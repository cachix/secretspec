use crate::deadline::instant_from_unix_ms;
use crate::error::{ErrorKind, RpcError};
use crate::frame::{AsyncFrameReader, write_frame};
use crate::jsonrpc::{Envelope, Notification, Request, RequestId, Response};
use crate::protocol::{
    CancelParams, EmptyParams, InitializeParams, InitializeResult, Limits, Product, rpc,
};
use crate::{ABSOLUTE_MAX_FRAME_BYTES, Error, Result};
use async_trait::async_trait;
use serde_json::{Value, json};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{Mutex, Semaphore, mpsc, oneshot};
use tokio::task::JoinSet;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

pub type RpcResult<T> = std::result::Result<T, RpcError>;
const MAX_ABANDONED_CALLBACKS: usize = crate::MAX_IN_FLIGHT * 4;

/// How long an out-of-band protocol response (an initialize reply, a shutdown
/// reply, or a value-free error) may wait for the writer to take it.
///
/// Deliberately not `ServerConfig::startup_timeout`: this bounds transport
/// backpressure on a response the session owes regardless of where it is in its
/// lifecycle, whereas `startup_timeout` bounds application startup work.
const COMMIT_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Clone)]
pub struct RequestContext {
    pub request_id: RequestId,
    pub deadline: Instant,
    pub cancellation: CancellationToken,
    /// Calls back to the client on this same session (0.20+). A handler uses it
    /// only for a method the client advertised; see [`Peer::supports`].
    pub peer: Peer,
}

/// The client, as seen from inside a handler.
///
/// Version 1 reverses direction for exactly one purpose: the endpoint that
/// discovers a value is missing is never the process that can ask a person for
/// it, and a stdio endpoint has no terminal to ask on. A callback is bounded by
/// the deadline and the cancellation of the request that raised it, so it can
/// neither outlive its caller nor keep an in-flight slot after the caller is
/// gone.
#[derive(Debug, Clone)]
pub struct Peer {
    inner: Arc<PeerInner>,
}

#[derive(Debug)]
struct PeerInner {
    /// Weak on purpose. The session ends by dropping its sender so the writer
    /// task sees the channel close and the process can exit; a strong clone
    /// here would keep that channel open and make every session linger until
    /// the shutdown timeout fired.
    writer: mpsc::WeakSender<WriterCommand>,
    calls: Mutex<PeerCalls>,
    next_id: AtomicU64,
    limit: AtomicUsize,
    capabilities: std::sync::RwLock<HashSet<String>>,
}

#[derive(Debug, Default)]
struct PeerCalls {
    pending: HashMap<RequestId, oneshot::Sender<Response>>,
    abandoned: HashSet<RequestId>,
}

impl Peer {
    fn new(writer: &mpsc::Sender<WriterCommand>) -> Self {
        Self {
            inner: Arc::new(PeerInner {
                writer: writer.downgrade(),
                calls: Mutex::new(PeerCalls::default()),
                next_id: AtomicU64::new(1),
                limit: AtomicUsize::new(ABSOLUTE_MAX_FRAME_BYTES),
                capabilities: std::sync::RwLock::new(HashSet::new()),
            }),
        }
    }

    /// A peer that is not attached to a session: it advertises nothing, so
    /// [`Self::supports`] is always false and no callback is ever attempted.
    ///
    /// This is what a handler exercised outside a live transport sees, and it
    /// is the same answer a real session gives for a client that advertised no
    /// callbacks, so a test never accidentally proves behavior a headless
    /// consumer would not get.
    pub fn detached() -> Self {
        let (writer, _) = mpsc::channel(1);
        Self::new(&writer)
    }

    /// Whether the client advertised one callback method. A handler MUST check
    /// this rather than calling and handling the failure: a client that cannot
    /// reach a person wants to be told so immediately, not after a deadline.
    pub fn supports(&self, method: &str) -> bool {
        self.inner
            .capabilities
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .contains(method)
    }

    /// Call one advertised method on the client and await its response.
    ///
    /// The deadline and cancellation come from the request being served, so an
    /// abandoned caller takes its callback down with it and no answer can
    /// arrive for a request that is already terminal.
    pub async fn call<P: serde::Serialize, R: serde::de::DeserializeOwned>(
        &self,
        method: &str,
        params: &P,
        context: &RequestContext,
    ) -> RpcResult<R> {
        if !self.supports(method) {
            return Err(RpcError::new(ErrorKind::CapabilityRequired));
        }
        let params =
            serde_json::to_value(params).map_err(|_| RpcError::new(ErrorKind::Internal))?;
        let deadline_unix_ms =
            crate::deadline::clamp_unix_ms(crate::deadline::unix_ms_from_instant(context.deadline));
        let id = RequestId::new(self.inner.next_id.fetch_add(1, Ordering::Relaxed))
            .map_err(|_| RpcError::new(ErrorKind::Internal))?;
        let request = Request::new(id, method, deadline_unix_ms, params)
            .map_err(|_| RpcError::new(ErrorKind::Internal))?
            .with_parent_request_id(context.request_id);
        let limit = self.inner.limit.load(Ordering::Acquire);
        let payload = Zeroizing::new(
            Envelope::Request(request)
                .to_vec()
                .map_err(|_| RpcError::new(ErrorKind::Internal))?,
        );
        if payload.is_empty() || payload.len() > limit {
            return Err(RpcError::new(ErrorKind::MessageTooLarge));
        }

        // The session drops its sender to close the transport. Failing to
        // upgrade means the session is already ending, so there is nothing left
        // to ask and nothing that could answer.
        let Some(writer) = self.inner.writer.upgrade() else {
            return Err(RpcError::new(ErrorKind::Unavailable));
        };
        let (sender, receiver) = oneshot::channel();
        self.inner.calls.lock().await.pending.insert(id, sender);
        let queued = writer
            .send(WriterCommand {
                payload,
                limit,
                committed: None,
            })
            .await;
        if queued.is_err() {
            self.inner.calls.lock().await.pending.remove(&id);
            return Err(RpcError::new(ErrorKind::Unavailable));
        }

        let response = tokio::select! {
            biased;
            _ = context.cancellation.cancelled() => {
                self.abandon_call(id).await;
                return Err(RpcError::new(ErrorKind::Cancelled));
            }
            response = tokio::time::timeout_at(context.deadline, receiver) => response,
        };
        match response {
            Ok(Ok(Response::Success(response))) => serde_json::from_value(response.result)
                .map_err(|_| RpcError::new(ErrorKind::OperationFailed)),
            Ok(Ok(Response::Error(response))) => Err(response.error),
            Ok(Err(_)) => Err(RpcError::new(ErrorKind::Unavailable)),
            Err(_) => {
                self.abandon_call(id).await;
                Err(RpcError::new(ErrorKind::DeadlineExceeded))
            }
        }
    }

    /// Deliver one inbound response, reporting whether it matched a call this
    /// side actually made. An unmatched response is a protocol violation.
    async fn deliver(&self, response: Response) -> bool {
        let Some(id) = response.id() else {
            return false;
        };
        let mut calls = self.inner.calls.lock().await;
        match calls.pending.remove(&id) {
            Some(sender) => {
                calls.abandoned.remove(&id);
                let _ = sender.send(response);
                true
            }
            None => calls.abandoned.remove(&id),
        }
    }

    async fn abandon_call(&self, id: RequestId) {
        // Record first, then remove from pending. `deliver` removes the marker
        // when a response wins the race while the sender is still present.
        let mut calls = self.inner.calls.lock().await;
        if calls.abandoned.len() < MAX_ABANDONED_CALLBACKS {
            calls.abandoned.insert(id);
        }
        calls.pending.remove(&id);
    }

    async fn fail_all(&self) {
        let mut calls = self.inner.calls.lock().await;
        calls.pending.clear();
        calls.abandoned.clear();
    }
}

/// Transport-independent application hook. Typed resolution and provider
/// adapters below this layer own application parameter validation.
#[async_trait]
pub trait ApplicationHandler: Send + Sync + 'static {
    fn protocol(&self) -> &'static str;
    fn versions(&self) -> &'static [u32] {
        &[1]
    }
    fn capabilities(&self) -> Vec<String>;

    fn validate_capabilities(&self, _capabilities: &[String]) -> RpcResult<()> {
        Ok(())
    }

    async fn initialize(&self, context: &RequestContext, application: Value) -> RpcResult<Value>;

    async fn call(&self, context: RequestContext, method: &str, params: Value) -> RpcResult<Value>;

    /// Reports whether the application's response became the terminal writer
    /// outcome. Handlers use an uncommitted outcome to release resources that
    /// were created while producing a response (for example resolver leases).
    async fn request_finished(&self, _request_id: RequestId, _committed: bool) {}

    async fn shutdown(&self) {}
}

#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub product: Product,
    pub limits: Limits,
    pub startup_timeout: Duration,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            product: Product {
                name: "secretspec-ipc".to_string(),
                version: env!("CARGO_PKG_VERSION").to_string(),
            },
            limits: Limits {
                max_frame_bytes: ABSOLUTE_MAX_FRAME_BYTES,
                max_in_flight: 8,
            },
            startup_timeout: Duration::from_secs(5),
        }
    }
}

/// One already-serialized frame for the single writer task.
///
/// The payload is built by the sender rather than the writer because the
/// too-large fallback has to inspect the encoded size before it can decide what
/// to enqueue, and because the writer now carries outbound callback requests as
/// well as responses.
struct WriterCommand {
    payload: Zeroizing<Vec<u8>>,
    limit: usize,
    committed: Option<oneshot::Sender<std::result::Result<(), ()>>>,
}

/// Serve exactly one initialized application session on a private byte stream.
pub async fn serve<R, W, H>(
    reader: R,
    mut writer: W,
    handler: Arc<H>,
    config: ServerConfig,
) -> Result<()>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
    H: ApplicationHandler,
{
    config.product.validate()?;
    config.limits.validate()?;
    let mut reader = AsyncFrameReader::new(reader);

    let (writer_tx, mut writer_rx) =
        mpsc::channel::<WriterCommand>(config.limits.max_in_flight + 2);
    let disconnected = CancellationToken::new();
    let writer_disconnected = disconnected.clone();
    let mut writer_task = tokio::spawn(async move {
        while let Some(command) = writer_rx.recv().await {
            let outcome = write_frame(&mut writer, &command.payload, command.limit)
                .await
                .map_err(|_| ());
            if let Some(committed) = command.committed {
                let _ = committed.send(outcome);
            }
            if outcome.is_err() {
                writer_disconnected.cancel();
                break;
            }
        }
        use tokio::io::AsyncWriteExt;
        let _ = writer.shutdown().await;
    });

    let peer = Peer::new(&writer_tx);
    let mut active_limit = ABSOLUTE_MAX_FRAME_BYTES;
    let mut initialized = false;
    let mut advertised_capabilities = HashSet::new();
    let mut last_seen_id: Option<RequestId> = None;
    let inflight: Arc<Mutex<HashMap<RequestId, CancellationToken>>> =
        Arc::new(Mutex::new(HashMap::new()));
    let mut tasks = JoinSet::new();
    // Replaced with the negotiated permit count during initialization; no
    // application call can be dispatched before that happens.
    let mut semaphore = Arc::new(Semaphore::new(1));
    let mut shutting_down = false;
    // A transport or protocol failure must still cancel in-flight work, join
    // its tasks, and run `handler.shutdown()`. Returning `?` straight out of
    // the loop would skip all of that, so the failure is carried out instead.
    let mut fatal: Option<Error> = None;

    loop {
        let frame = tokio::select! {
            _ = disconnected.cancelled() => break,
            frame = reader.read_frame(active_limit) => match frame {
                Ok(frame) => frame,
                Err(error) => {
                    fatal = Some(error);
                    break;
                }
            },
        };
        let Some(frame) = frame else {
            break;
        };

        let envelope = match Envelope::parse_classified(&frame) {
            Ok(envelope) => envelope,
            Err((_, kind)) => {
                // The strict parser intentionally does not recover an ID from a
                // malformed object. Emit one value-free error, then close. The
                // parser reports which layer rejected the frame, so there is no
                // need to re-parse it here to choose a kind.
                let error = Response::error(None, RpcError::new(kind));
                let _ = commit(&writer_tx, error, active_limit).await;
                break;
            }
        };

        match envelope {
            // Before this session reversed direction, any response was a
            // protocol violation. It still is unless it answers a callback this
            // side actually made: an unmatched or duplicate response means the
            // peer is tracking a different session state than we are.
            Envelope::Response(response) => {
                if !initialized || !peer.deliver(response).await {
                    break;
                }
            }
            Envelope::Notification(notification) => {
                handle_notification(notification, &inflight).await;
            }
            Envelope::Request(request) => {
                if last_seen_id.is_some_and(|last| request.id <= last) {
                    let response =
                        Response::error(Some(request.id), RpcError::new(ErrorKind::InvalidRequest));
                    let _ = commit(&writer_tx, response, active_limit).await;
                    break;
                }
                last_seen_id = Some(request.id);

                if !initialized {
                    if request.method != rpc::INITIALIZE {
                        let response = Response::error(
                            Some(request.id),
                            RpcError::new(ErrorKind::InvalidRequest),
                        );
                        let _ = commit(&writer_tx, response, active_limit).await;
                        break;
                    }
                    let selected =
                        match initialize(&request, handler.as_ref(), &config, &writer_tx, &peer)
                            .await
                        {
                            Ok(selected) => selected,
                            Err(error) => {
                                fatal = Some(error);
                                break;
                            }
                        };
                    let Some((limits, capabilities)) = selected else {
                        break;
                    };
                    peer.inner
                        .limit
                        .store(limits.max_frame_bytes, Ordering::Release);
                    active_limit = limits.max_frame_bytes;
                    semaphore = Arc::new(Semaphore::new(limits.max_in_flight));
                    advertised_capabilities = capabilities.into_iter().collect();
                    initialized = true;
                    continue;
                }

                if request.method == rpc::INITIALIZE {
                    let response =
                        Response::error(Some(request.id), RpcError::new(ErrorKind::InvalidRequest));
                    let _ = commit(&writer_tx, response, active_limit).await;
                    break;
                }

                if request.method == rpc::SHUTDOWN {
                    if shutdown(
                        request,
                        &inflight,
                        &mut tasks,
                        handler.as_ref(),
                        &writer_tx,
                        active_limit,
                    )
                    .await
                    .is_err()
                    {
                        break;
                    }
                    shutting_down = true;
                    break;
                }

                if shutting_down {
                    let response = Response::error(Some(request.id), RpcError::unavailable(None));
                    let _ = commit(&writer_tx, response, active_limit).await;
                    continue;
                }

                if !request.method.starts_with("resolver.")
                    && !request.method.starts_with("provider.")
                {
                    let response =
                        Response::error(Some(request.id), RpcError::new(ErrorKind::MethodNotFound));
                    let _ = commit(&writer_tx, response, active_limit).await;
                    continue;
                }
                if !advertised_capabilities.contains(&request.method) {
                    let response = Response::error(
                        Some(request.id),
                        RpcError::new(ErrorKind::CapabilityRequired),
                    );
                    let _ = commit(&writer_tx, response, active_limit).await;
                    continue;
                }

                let deadline = request_deadline(&request);
                if deadline <= Instant::now() {
                    let response = Response::error(
                        Some(request.id),
                        RpcError::new(ErrorKind::DeadlineExceeded),
                    );
                    let _ = commit(&writer_tx, response, active_limit).await;
                    continue;
                }

                let permit = match semaphore.clone().try_acquire_owned() {
                    Ok(permit) => permit,
                    Err(_) => {
                        let response =
                            Response::error(Some(request.id), RpcError::unavailable(None));
                        let _ = commit(&writer_tx, response, active_limit).await;
                        continue;
                    }
                };

                let cancellation = CancellationToken::new();
                inflight
                    .lock()
                    .await
                    .insert(request.id, cancellation.clone());
                let context = RequestContext {
                    request_id: request.id,
                    deadline,
                    cancellation: cancellation.clone(),
                    peer: peer.clone(),
                };
                let task_handler = handler.clone();
                let task_writer = writer_tx.clone();
                let task_inflight = inflight.clone();
                let task_disconnected = disconnected.clone();
                tasks.spawn(async move {
                    let _permit = permit;
                    run_call(
                        request,
                        context,
                        task_handler,
                        task_writer,
                        task_inflight,
                        task_disconnected,
                        active_limit,
                    )
                    .await;
                });
            }
        }
    }

    // Draining preserves accepted work. Only an expired shutdown deadline
    // turns this into cancellation; EOF remains the immediate-abort path.
    // A callback still waiting on a client that is gone would otherwise hold
    // its handler, and therefore its request, until the deadline.
    peer.fail_all().await;
    if !shutting_down {
        tasks.abort_all();
    }
    while tasks.join_next().await.is_some() {}
    if initialized && !shutting_down {
        let _ = tokio::time::timeout(config.startup_timeout, handler.shutdown()).await;
    }
    drop(writer_tx);
    if tokio::time::timeout(config.startup_timeout, &mut writer_task)
        .await
        .is_err()
    {
        writer_task.abort();
        let _ = writer_task.await;
    }
    match fatal {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

async fn initialize<H: ApplicationHandler>(
    request: &Request,
    handler: &H,
    config: &ServerConfig,
    writer: &mpsc::Sender<WriterCommand>,
    peer: &Peer,
) -> Result<Option<(Limits, Vec<String>)>> {
    let params: InitializeParams<Value> = match serde_json::from_value(request.params.clone()) {
        Ok(params) => params,
        Err(_) => {
            let response =
                Response::error(Some(request.id), RpcError::new(ErrorKind::InvalidParams));
            commit(writer, response, ABSOLUTE_MAX_FRAME_BYTES).await?;
            return Ok(None);
        }
    };
    if params.validate_common(handler.protocol()).is_err() {
        let response = Response::error(
            Some(request.id),
            RpcError::new(ErrorKind::UnsupportedVersion),
        );
        commit(writer, response, ABSOLUTE_MAX_FRAME_BYTES).await?;
        return Ok(None);
    }
    let Some(version) = params
        .versions
        .iter()
        .copied()
        .filter(|version| handler.versions().contains(version))
        .max()
    else {
        let response = Response::error(
            Some(request.id),
            RpcError::new(ErrorKind::UnsupportedVersion),
        );
        commit(writer, response, ABSOLUTE_MAX_FRAME_BYTES).await?;
        return Ok(None);
    };

    let capabilities = handler.capabilities();
    if crate::protocol::validate_capabilities(&capabilities).is_err() {
        let response = Response::error(Some(request.id), RpcError::new(ErrorKind::Internal));
        commit(writer, response, ABSOLUTE_MAX_FRAME_BYTES).await?;
        return Ok(None);
    }
    if let Err(error) = handler.validate_capabilities(&capabilities) {
        commit(
            writer,
            Response::error(Some(request.id), error),
            ABSOLUTE_MAX_FRAME_BYTES,
        )
        .await?;
        return Ok(None);
    }
    let limits = config.limits.select(params.limits)?;
    // Recorded before the application handler runs, so an initialize handler
    // that needs to ask the client something can already see what it answers.
    // Callbacks the client did not advertise are simply never sent.
    *peer
        .inner
        .capabilities
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) =
        params.client_methods.iter().cloned().collect();
    let cancellation = CancellationToken::new();
    let context = RequestContext {
        request_id: request.id,
        deadline: request_deadline(request).min(Instant::now() + config.startup_timeout),
        cancellation,
        peer: peer.clone(),
    };
    if context.deadline <= Instant::now() {
        commit(
            writer,
            Response::error(Some(request.id), RpcError::new(ErrorKind::DeadlineExceeded)),
            ABSOLUTE_MAX_FRAME_BYTES,
        )
        .await?;
        return Ok(None);
    }
    let application = match tokio::time::timeout_at(
        context.deadline,
        handler.initialize(&context, params.application),
    )
    .await
    {
        Ok(Ok(application)) => application,
        Ok(Err(error)) => {
            commit(
                writer,
                Response::error(Some(request.id), error),
                ABSOLUTE_MAX_FRAME_BYTES,
            )
            .await?;
            return Ok(None);
        }
        Err(_) => {
            context.cancellation.cancel();
            commit(
                writer,
                Response::error(Some(request.id), RpcError::new(ErrorKind::DeadlineExceeded)),
                ABSOLUTE_MAX_FRAME_BYTES,
            )
            .await?;
            return Ok(None);
        }
    };
    let result = InitializeResult {
        protocol: handler.protocol().to_string(),
        version,
        server: config.product.clone(),
        methods: capabilities.clone(),
        capabilities: Default::default(),
        limits,
        application,
    };
    let value =
        serde_json::to_value(result).map_err(|_| Error::Protocol("serialize initialize result"))?;
    commit(
        writer,
        Response::success(request.id, value),
        ABSOLUTE_MAX_FRAME_BYTES,
    )
    .await?;
    Ok(Some((limits, capabilities)))
}

async fn handle_notification(
    notification: Notification,
    inflight: &Arc<Mutex<HashMap<RequestId, CancellationToken>>>,
) {
    if notification.method != rpc::CANCEL {
        return;
    }
    let Ok(params) = serde_json::from_value::<CancelParams>(notification.params) else {
        return;
    };
    if let Some(cancellation) = inflight.lock().await.get(&params.id) {
        cancellation.cancel();
    }
}

async fn run_call<H: ApplicationHandler>(
    request: Request,
    context: RequestContext,
    handler: Arc<H>,
    writer: mpsc::Sender<WriterCommand>,
    inflight: Arc<Mutex<HashMap<RequestId, CancellationToken>>>,
    disconnected: CancellationToken,
    limit: usize,
) {
    let mut operation = Box::pin(handler.call(context.clone(), &request.method, request.params));
    let response = tokio::select! {
        biased;
        _ = tokio::time::sleep_until(context.deadline) => {
            context.cancellation.cancel();
            let response = Response::error(Some(request.id), RpcError::new(ErrorKind::DeadlineExceeded));
            let _ = send_terminal(&writer, response, limit).await;
            let _ = operation.await;
            handler.request_finished(request.id, false).await;
            inflight.lock().await.remove(&request.id);
            return;
        }
        _ = context.cancellation.cancelled() => {
            let response = Response::error(Some(request.id), RpcError::new(ErrorKind::Cancelled));
            let _ = send_terminal(&writer, response, limit).await;
            // Keep the semaphore permit until a non-cooperative handler really
            // exits. A late outcome is deliberately discarded.
            let _ = operation.await;
            handler.request_finished(request.id, false).await;
            inflight.lock().await.remove(&request.id);
            return;
        }
        result = &mut operation => response_from_result(request.id, result),
    };
    let committed = commit_application_before(
        &writer,
        response,
        limit,
        context.deadline,
        &context.cancellation,
        &disconnected,
    )
    .await;
    handler.request_finished(request.id, committed).await;
    inflight.lock().await.remove(&request.id);
}

/// Deadline and cancellation are themselves terminal outcomes. The channel is
/// sized above the negotiated in-flight count, so enqueueing one response per
/// accepted request remains bounded even when the transport is backpressured.
async fn send_terminal(
    writer: &mpsc::Sender<WriterCommand>,
    response: Response,
    limit: usize,
) -> Result<()> {
    let payload = encode_response(&response, limit)?;
    writer
        .send(WriterCommand {
            payload,
            limit,
            committed: None,
        })
        .await
        .map_err(|_| Error::Closed)
}

/// Serialize a response, substituting `message_too_large` for one that cannot
/// fit. A result carrying a secret must never be truncated onto the wire, and
/// the caller is owed exactly one terminal frame either way.
fn encode_response(response: &Response, limit: usize) -> Result<Zeroizing<Vec<u8>>> {
    let payload = serde_json::to_vec(response)
        .map_err(|_| Error::Protocol("failed to serialize response"))?;
    if !payload.is_empty() && payload.len() <= limit {
        return Ok(Zeroizing::new(payload));
    }
    drop(Zeroizing::new(payload));
    let replacement = Response::error(response.id(), RpcError::new(ErrorKind::MessageTooLarge));
    serde_json::to_vec(&replacement)
        .map(Zeroizing::new)
        .map_err(|_| Error::Protocol("failed to serialize response"))
}

fn response_from_result(id: RequestId, result: RpcResult<Value>) -> Response {
    match result {
        Ok(value) => Response::success(id, value),
        Err(error) => Response::error(Some(id), error),
    }
}

async fn commit_application_before(
    writer: &mpsc::Sender<WriterCommand>,
    response: Response,
    limit: usize,
    deadline: Instant,
    cancellation: &CancellationToken,
    disconnected: &CancellationToken,
) -> bool {
    let encoded = serde_json::to_vec(&response).map(Zeroizing::new).ok();
    let application_response = encoded
        .as_ref()
        .is_some_and(|payload| !payload.is_empty() && payload.len() <= limit);
    let request_id = response.id();
    let payload = match encoded.filter(|_| application_response) {
        Some(payload) => payload,
        None => {
            let replacement =
                Response::error(request_id, RpcError::new(ErrorKind::MessageTooLarge));
            match serde_json::to_vec(&replacement).map(Zeroizing::new) {
                Ok(payload) => payload,
                Err(_) => return false,
            }
        }
    };
    let (committed_tx, committed_rx) = oneshot::channel();
    let command = WriterCommand {
        payload,
        limit,
        committed: Some(committed_tx),
    };

    // Only cancellation/deadline that wins before enqueue may replace the
    // application response. Once the writer owns a frame, it is the sole
    // terminal outcome; a later write timeout closes the session instead of
    // queueing a second response.
    let enqueued = tokio::select! {
        biased;
        _ = tokio::time::sleep_until(deadline) => {
            cancellation.cancel();
            let response = Response::error(request_id, RpcError::new(ErrorKind::DeadlineExceeded));
            let _ = send_terminal(writer, response, limit).await;
            false
        }
        _ = cancellation.cancelled() => {
            let response = Response::error(request_id, RpcError::new(ErrorKind::Cancelled));
            let _ = send_terminal(writer, response, limit).await;
            false
        }
        result = writer.send(command) => result.is_ok(),
    };
    if !enqueued {
        return false;
    }

    match tokio::time::timeout_at(deadline, committed_rx).await {
        Ok(Ok(Ok(()))) => application_response,
        Ok(Ok(Err(()))) | Ok(Err(_)) | Err(_) => {
            disconnected.cancel();
            false
        }
    }
}

async fn commit(
    writer: &mpsc::Sender<WriterCommand>,
    response: Response,
    limit: usize,
) -> Result<()> {
    let payload = encode_response(&response, limit)?;
    tokio::time::timeout(COMMIT_TIMEOUT, async {
        let (committed_tx, committed_rx) = oneshot::channel();
        writer
            .send(WriterCommand {
                payload,
                limit,
                committed: Some(committed_tx),
            })
            .await
            .map_err(|_| Error::Closed)?;
        committed_rx
            .await
            .map_err(|_| Error::Closed)?
            .map_err(|_| Error::Closed)
    })
    .await
    .map_err(|_| Error::DeadlineExceeded)?
}

fn request_deadline(request: &Request) -> Instant {
    instant_from_unix_ms(request.deadline_unix_ms())
}

async fn shutdown<H: ApplicationHandler>(
    request: Request,
    inflight: &Arc<Mutex<HashMap<RequestId, CancellationToken>>>,
    tasks: &mut JoinSet<()>,
    handler: &H,
    writer: &mpsc::Sender<WriterCommand>,
    limit: usize,
) -> Result<()> {
    let deadline = request_deadline(&request);
    let _: EmptyParams = match serde_json::from_value(request.params) {
        Ok(params) => params,
        Err(_) => {
            commit(
                writer,
                Response::error(Some(request.id), RpcError::new(ErrorKind::InvalidParams)),
                limit,
            )
            .await?;
            return Err(Error::Protocol("invalid shutdown"));
        }
    };
    for cancellation in inflight.lock().await.values() {
        cancellation.cancel();
    }
    let drain = async {
        while tasks.join_next().await.is_some() {}
        handler.shutdown().await;
    };
    if tokio::time::timeout_at(deadline, drain).await.is_err() {
        for cancellation in inflight.lock().await.values() {
            cancellation.cancel();
        }
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
    }
    commit(writer, Response::success(request.id, json!({})), limit).await
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The session ends by dropping its sender so the writer task observes the
    /// close and the process can exit. Holding a strong clone in the peer made
    /// every session linger until the shutdown timeout instead, which showed up
    /// as an endpoint that never exited after EOF.
    #[tokio::test]
    async fn a_peer_does_not_keep_the_writer_channel_open() {
        let (writer_tx, mut writer_rx) = mpsc::channel::<WriterCommand>(1);
        let peer = Peer::new(&writer_tx);
        peer.inner
            .capabilities
            .write()
            .unwrap()
            .insert("client.prompt".to_string());
        drop(writer_tx);
        assert!(
            writer_rx.recv().await.is_none(),
            "the peer kept the writer channel open after the session dropped its sender"
        );

        // A callback attempted on a session that is already ending is reported
        // as unavailable rather than waiting for a writer that will never run.
        let context = RequestContext {
            request_id: RequestId::new(1).unwrap(),
            deadline: Instant::now() + Duration::from_secs(30),
            cancellation: CancellationToken::new(),
            peer: peer.clone(),
        };
        let error = peer
            .call::<_, Value>("client.prompt", &json!({}), &context)
            .await
            .unwrap_err();
        assert_eq!(error.data.kind, ErrorKind::Unavailable);
    }

    // Most dispatcher behavior is exercised through the black-box integration
    // tests; keep this module focused on wall-to-monotonic conversion.
    #[test]
    fn expired_deadline_is_not_started() {
        let request = Request::new(RequestId::new(1).unwrap(), "test.call", 1, json!({})).unwrap();
        assert!(request_deadline(&request) <= Instant::now());
    }

    #[tokio::test]
    async fn an_expired_callback_consumes_its_terminal_response() {
        let (writer_tx, mut writer_rx) = mpsc::channel::<WriterCommand>(1);
        let peer = Peer::new(&writer_tx);
        peer.inner
            .capabilities
            .write()
            .unwrap()
            .insert("client.prompt".to_string());

        // More than one in-flight window proves each consumed response retires
        // its abandoned marker instead of slowly filling the bounded set.
        for raw_id in 1..=64 {
            let context = RequestContext {
                request_id: RequestId::new(10).unwrap(),
                deadline: Instant::now(),
                cancellation: CancellationToken::new(),
                peer: peer.clone(),
            };
            let error = peer
                .call::<_, Value>("client.prompt", &json!({}), &context)
                .await
                .unwrap_err();
            assert_eq!(error.data.kind, ErrorKind::DeadlineExceeded);
            let _request = writer_rx.recv().await.unwrap();

            let id = RequestId::new(raw_id).unwrap();
            let terminal = Response::error(Some(id), RpcError::new(ErrorKind::DeadlineExceeded));
            assert!(peer.deliver(terminal.clone()).await);
            assert!(!peer.deliver(terminal).await, "duplicates remain invalid");
        }
        assert!(peer.inner.calls.lock().await.abandoned.is_empty());
    }

    #[tokio::test]
    async fn a_cancelled_callback_also_consumes_its_terminal_response() {
        let (writer_tx, mut writer_rx) = mpsc::channel::<WriterCommand>(1);
        let peer = Peer::new(&writer_tx);
        peer.inner
            .capabilities
            .write()
            .unwrap()
            .insert("client.prompt".to_string());
        let cancellation = CancellationToken::new();
        cancellation.cancel();
        let context = RequestContext {
            request_id: RequestId::new(10).unwrap(),
            deadline: Instant::now() + Duration::from_secs(1),
            cancellation,
            peer: peer.clone(),
        };

        let error = peer
            .call::<_, Value>("client.prompt", &json!({}), &context)
            .await
            .unwrap_err();
        assert_eq!(error.data.kind, ErrorKind::Cancelled);
        let _request = writer_rx.recv().await.unwrap();
        let terminal = Response::error(
            Some(RequestId::new(1).unwrap()),
            RpcError::new(ErrorKind::Cancelled),
        );
        assert!(peer.deliver(terminal).await);
        assert!(peer.inner.calls.lock().await.abandoned.is_empty());
    }
}
