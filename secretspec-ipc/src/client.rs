use crate::deadline::instant_from_unix_ms;
use crate::error::{ErrorKind, RpcError};
use crate::frame::{AsyncFrameReader, write_frame};
use crate::jsonrpc::{Envelope, Notification, Request, RequestId, Response};
use crate::protocol::{CancelParams, InitializeParams, InitializeResult, Limits, rpc};
use crate::{ABSOLUTE_MAX_FRAME_BYTES, Error, Result};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU8, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex, Weak};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{Mutex, Notify, RwLock, Semaphore, mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use zeroize::{Zeroize, Zeroizing};

const INITIALIZING: u8 = 0;
const READY: u8 = 1;
const CLOSING: u8 = 2;
const CLOSED: u8 = 3;
const MAX_ABANDONED_REQUESTS: usize = crate::MAX_IN_FLIGHT * 4;

enum WriterCommand {
    Frame {
        payload: Zeroizing<Vec<u8>>,
        limit: usize,
    },
    Close,
}

/// Answers the server's callbacks on this session (0.20+).
///
/// A client installs one only for the methods it advertised in
/// `client_methods`; a server never sends anything else. The returned
/// value is serialized as the callback's result, and an `RpcError` becomes its
/// error response, so declining is a normal outcome rather than a transport
/// failure.
#[async_trait::async_trait]
pub trait CallbackHandler: Send + Sync + 'static {
    async fn call(&self, method: &str, params: Value) -> std::result::Result<Value, RpcError>;
}

struct Inner {
    writer: mpsc::Sender<WriterCommand>,
    callbacks: Option<Arc<dyn CallbackHandler>>,
    /// The callbacks this client advertised. Fixed at initialization, so it
    /// needs no lock and cannot drift from what the server was told.
    advertised: HashSet<String>,
    inbound: StdMutex<InboundCallbacks>,
    pending: StdMutex<HashMap<RequestId, PendingRequest>>,
    abandoned: StdMutex<HashSet<RequestId>>,
    next_id: AtomicU64,
    max_frame_bytes: AtomicUsize,
    max_in_flight: AtomicUsize,
    limits: RwLock<Limits>,
    semaphore: RwLock<Arc<Semaphore>>,
    capabilities: RwLock<HashSet<String>>,
    state: AtomicU8,
    closed: Notify,
    reader_task: Mutex<Option<JoinHandle<()>>>,
    writer_task: Mutex<Option<JoinHandle<()>>>,
}

struct PendingRequest {
    sender: oneshot::Sender<Response>,
    deadline_unix_ms: u64,
    cancellation: CancellationToken,
}

#[derive(Default)]
struct InboundCallbacks {
    active: usize,
    last_seen_id: Option<RequestId>,
}

/// A multiplexed SecretSpec JSON-RPC session.
#[derive(Clone)]
pub struct Client {
    inner: Arc<Inner>,
}

impl Client {
    /// Initialize a session on an already-authenticated private transport.
    pub async fn connect<R, W, A, B>(
        reader: R,
        writer: W,
        initialize: InitializeParams<A>,
        startup_deadline_unix_ms: u64,
    ) -> Result<(Self, InitializeResult<B>)>
    where
        R: AsyncRead + Unpin + Send + 'static,
        W: AsyncWrite + Unpin + Send + 'static,
        A: Serialize,
        B: DeserializeOwned,
    {
        Self::connect_with_callbacks(reader, writer, initialize, startup_deadline_unix_ms, None)
            .await
    }

    /// As [`Self::connect`], installing a handler for the callbacks this
    /// client advertised in `client_methods` (0.20+).
    ///
    /// Passing `None` while advertising a callback would leave the server
    /// waiting out its deadline on a request nothing answers, so the two are
    /// checked against each other here rather than at the first callback.
    pub async fn connect_with_callbacks<R, W, A, B>(
        reader: R,
        mut writer: W,
        initialize: InitializeParams<A>,
        startup_deadline_unix_ms: u64,
        callbacks: Option<Arc<dyn CallbackHandler>>,
    ) -> Result<(Self, InitializeResult<B>)>
    where
        R: AsyncRead + Unpin + Send + 'static,
        W: AsyncWrite + Unpin + Send + 'static,
        A: Serialize,
        B: DeserializeOwned,
    {
        if callbacks.is_none() && !initialize.client_methods.is_empty() {
            return Err(Error::Protocol(
                "client advertised a callback with no handler to answer it",
            ));
        }
        let offered_protocol = initialize.protocol.clone();
        let offered_versions = initialize.versions.clone();
        let offered_limits = initialize.limits;
        let advertised: HashSet<String> = initialize.client_methods.iter().cloned().collect();
        // `offered_protocol` is a copy of `initialize.protocol`, so the protocol
        // comparison inside `validate_common` is trivially true here. The call
        // is kept for the checks that do bite locally: version list shape,
        // product strings, and limit ranges.
        initialize.validate_common(&offered_protocol)?;
        let initialize_id = RequestId::new(1)?;
        let initialize_params = serde_json::to_value(initialize)
            .map_err(|_| Error::Protocol("failed to serialize initialization"))?;
        let initialize_request = Request::new(
            initialize_id,
            rpc::INITIALIZE,
            startup_deadline_unix_ms,
            initialize_params,
        )?;

        let (writer_tx, mut writer_rx) =
            mpsc::channel::<WriterCommand>(offered_limits.max_in_flight.saturating_add(2));
        let mut reader = AsyncFrameReader::new(reader);
        let inner = Arc::new(Inner {
            writer: writer_tx,
            callbacks,
            advertised,
            inbound: StdMutex::new(InboundCallbacks::default()),
            pending: StdMutex::new(HashMap::new()),
            abandoned: StdMutex::new(HashSet::new()),
            next_id: AtomicU64::new(2),
            max_frame_bytes: AtomicUsize::new(ABSOLUTE_MAX_FRAME_BYTES),
            max_in_flight: AtomicUsize::new(1),
            limits: RwLock::new(Limits::PRE_NEGOTIATION),
            semaphore: RwLock::new(Arc::new(Semaphore::new(1))),
            capabilities: RwLock::new(HashSet::new()),
            state: AtomicU8::new(INITIALIZING),
            closed: Notify::new(),
            reader_task: Mutex::new(None),
            writer_task: Mutex::new(None),
        });

        let writer_inner = Arc::downgrade(&inner);
        let writer_task = tokio::spawn(async move {
            while let Some(command) = writer_rx.recv().await {
                match command {
                    WriterCommand::Frame { payload, limit } => {
                        if write_frame(&mut writer, &payload, limit).await.is_err() {
                            fail_session_weak(&writer_inner);
                            break;
                        }
                    }
                    WriterCommand::Close => break,
                }
            }
            use tokio::io::AsyncWriteExt;
            let _ = writer.shutdown().await;
        });
        *inner.writer_task.lock().await = Some(writer_task);

        let reader_inner = Arc::downgrade(&inner);
        let reader_task = tokio::spawn(async move {
            loop {
                let Some(inner) = reader_inner.upgrade() else {
                    break;
                };
                let limit = inner.max_frame_bytes.load(Ordering::Acquire);
                drop(inner);
                let frame = match reader.read_frame(limit).await {
                    Ok(Some(frame)) => frame,
                    Ok(None) | Err(_) => {
                        fail_session_weak(&reader_inner);
                        break;
                    }
                };
                let response = match Envelope::parse(&frame) {
                    Ok(Envelope::Response(response)) => response,
                    // A callback the client advertised. It is answered on its
                    // own task so this loop keeps reading: the same session
                    // still carries the responses this client is waiting for,
                    // and blocking here to ask a person would deadlock both
                    // sides until the deadline.
                    Ok(Envelope::Request(request)) => {
                        let Some(inner) = reader_inner.upgrade() else {
                            break;
                        };
                        let Some(handler) = inner.callbacks.clone() else {
                            fail_session(&inner);
                            break;
                        };
                        if !serve_callback(&inner, handler, request) {
                            fail_session(&inner);
                            break;
                        }
                        continue;
                    }
                    // Notifications have no response channel. Ignore unknown
                    // methods and malformed method-specific parameters after
                    // the strict envelope itself has parsed.
                    Ok(Envelope::Notification(_)) => continue,
                    _ => {
                        fail_session_weak(&reader_inner);
                        break;
                    }
                };
                let Some(id) = response.id() else {
                    fail_session_weak(&reader_inner);
                    break;
                };
                let Some(inner) = reader_inner.upgrade() else {
                    break;
                };
                let pending = lock_unpoisoned(&inner.pending).remove(&id);
                if let Some(pending) = pending {
                    // A deadline can race a response after marking this ID as
                    // abandoned but before removing it from `pending`.
                    lock_unpoisoned(&inner.abandoned).remove(&id);
                    pending.cancellation.cancel();
                    let _ = pending.sender.send(response);
                    continue;
                }
                if lock_unpoisoned(&inner.abandoned).remove(&id) {
                    continue;
                }
                // Unknown and duplicate terminal IDs are protocol violations.
                fail_session(&inner);
                break;
            }
        });
        *inner.reader_task.lock().await = Some(reader_task);

        let client = Self { inner };
        let response = match client
            .request_internal(initialize_request, ABSOLUTE_MAX_FRAME_BYTES)
            .await
        {
            Ok(response) => response,
            Err(error) => {
                client.abort_transport().await;
                return Err(error);
            }
        };
        let initialized = response_value(response)
            .and_then(|value| {
                serde_json::from_value::<InitializeResult<B>>(value)
                    .map_err(|error| Error::ProtocolOwned(error.to_string()))
            })
            .and_then(|initialized| {
                initialized.validate_common(
                    &offered_protocol,
                    &offered_versions,
                    offered_limits,
                )?;
                Ok(initialized)
            });
        let initialized = match initialized {
            Ok(initialized) => initialized,
            Err(error) => {
                client.abort_transport().await;
                return Err(error);
            }
        };
        client
            .inner
            .max_frame_bytes
            .store(initialized.limits.max_frame_bytes, Ordering::Release);
        client
            .inner
            .max_in_flight
            .store(initialized.limits.max_in_flight, Ordering::Release);
        *client.inner.limits.write().await = initialized.limits;
        *client.inner.semaphore.write().await =
            Arc::new(Semaphore::new(initialized.limits.max_in_flight));
        *client.inner.capabilities.write().await = initialized.methods.iter().cloned().collect();
        client.inner.state.store(READY, Ordering::Release);
        Ok((client, initialized))
    }

    pub async fn start<T: Serialize>(
        &self,
        method: &str,
        params: &T,
        deadline_unix_ms: u64,
    ) -> Result<Call> {
        if self.inner.state.load(Ordering::Acquire) != READY {
            return Err(Error::Closed);
        }
        if !self.inner.capabilities.read().await.contains(method) {
            return Err(Error::Protocol("method was not advertised"));
        }
        let params = serde_json::to_value(params)
            .map_err(|_| Error::Protocol("failed to serialize call params"))?;
        // Clamp once, then use the same value locally and on the wire so the
        // peer never enforces a longer deadline than this client waits for.
        let deadline_unix_ms = crate::deadline::clamp_unix_ms(deadline_unix_ms);
        let deadline = instant_from_unix_ms(deadline_unix_ms);
        if deadline <= Instant::now() {
            return Err(Error::DeadlineExceeded);
        }
        let semaphore = self.inner.semaphore.read().await.clone();
        let permit = semaphore
            .try_acquire_owned()
            .map_err(|_| Error::Unavailable)?;
        let id = self.next_id()?;
        let request = Request::new(id, method, deadline_unix_ms, params)?;
        let (sender, receiver) = oneshot::channel();
        lock_unpoisoned(&self.inner.pending).insert(
            id,
            PendingRequest {
                sender,
                deadline_unix_ms,
                cancellation: CancellationToken::new(),
            },
        );
        if let Err(error) = self.queue_request(request, deadline).await {
            remove_pending(&self.inner, id);
            return Err(error);
        }
        Ok(Call {
            id,
            deadline,
            receiver: Some(receiver),
            client: Arc::downgrade(&self.inner),
            _permit: Some(permit),
            terminal: false,
        })
    }

    pub async fn call<P: Serialize, R: DeserializeOwned>(
        &self,
        method: &str,
        params: &P,
        deadline_unix_ms: u64,
    ) -> Result<R> {
        let mut call = self.start(method, params, deadline_unix_ms).await?;
        let value = call.wait().await?;
        serde_json::from_value(value).map_err(|error| Error::ProtocolOwned(error.to_string()))
    }

    pub async fn limits(&self) -> Limits {
        *self.inner.limits.read().await
    }

    pub async fn capabilities(&self) -> HashSet<String> {
        self.inner.capabilities.read().await.clone()
    }

    pub fn is_closed(&self) -> bool {
        self.inner.state.load(Ordering::Acquire) == CLOSED
    }

    /// Close the protocol session. The process launcher separately enforces
    /// child termination and reaping after this wire shutdown completes.
    pub async fn close(&self, deadline_unix_ms: u64) -> Result<()> {
        let state =
            self.inner
                .state
                .compare_exchange(READY, CLOSING, Ordering::AcqRel, Ordering::Acquire);
        let outcome = match state {
            Ok(_) => {
                let id = self.next_id()?;
                let request = Request::new(id, rpc::SHUTDOWN, deadline_unix_ms, json!({}))?;
                self.request_internal(request, self.inner.max_frame_bytes.load(Ordering::Acquire))
                    .await
                    .and_then(|response| {
                        let value = response_value(response)?;
                        if value == json!({}) {
                            Ok(())
                        } else {
                            Err(Error::Protocol("shutdown result is not empty"))
                        }
                    })
            }
            Err(CLOSED) => Ok(()),
            Err(_) => return Err(Error::Closed),
        };

        let _ = self.inner.writer.try_send(WriterCommand::Close);
        let deadline = instant_from_unix_ms(deadline_unix_ms);
        if let Some(mut task) = self.inner.writer_task.lock().await.take()
            && tokio::time::timeout_at(deadline, &mut task).await.is_err()
        {
            task.abort();
            let _ = task.await;
        }
        if let Some(mut task) = self.inner.reader_task.lock().await.take()
            && tokio::time::timeout_at(deadline, &mut task).await.is_err()
        {
            task.abort();
            let _ = task.await;
        }
        fail_session(&self.inner);
        outcome
    }

    /// Mark a transport dead from a process watcher without exposing pending
    /// request data in an error.
    pub async fn abandon(&self) {
        fail_session(&self.inner);
    }

    /// Let the transport reader consume frames already buffered in the pipe
    /// before a process watcher declares the session dead. A child can write a
    /// terminal response and exit before the reader task is scheduled; failing
    /// the session immediately in that window would discard the valid reply.
    pub(crate) async fn abandon_after_process_exit(&self, grace: Duration) {
        if self.is_closed() {
            return;
        }
        let closed = self.inner.closed.notified();
        tokio::pin!(closed);
        closed.as_mut().enable();
        if self.is_closed() {
            return;
        }
        if tokio::time::timeout(grace, closed).await.is_err() && !self.is_closed() {
            fail_session(&self.inner);
        }
    }

    async fn abort_transport(&self) {
        fail_session(&self.inner);
        let _ = self.inner.writer.try_send(WriterCommand::Close);
        if let Some(task) = self.inner.writer_task.lock().await.take() {
            task.abort();
            let _ = task.await;
        }
        if let Some(task) = self.inner.reader_task.lock().await.take() {
            task.abort();
            let _ = task.await;
        }
    }

    fn next_id(&self) -> Result<RequestId> {
        let id = self.inner.next_id.fetch_add(1, Ordering::Relaxed);
        RequestId::new(id)
    }

    async fn queue_request(&self, request: Request, deadline: Instant) -> Result<()> {
        let envelope = Envelope::Request(request);
        let payload = Zeroizing::new(envelope.to_vec()?);
        let limit = self.inner.max_frame_bytes.load(Ordering::Acquire);
        if payload.len() > limit {
            return Err(Error::Protocol(
                "request exceeds the negotiated frame limit",
            ));
        }
        match tokio::time::timeout_at(
            deadline,
            self.inner
                .writer
                .send(WriterCommand::Frame { payload, limit }),
        )
        .await
        {
            Ok(Ok(())) => Ok(()),
            Ok(Err(_)) => Err(Error::Closed),
            Err(_) => Err(Error::DeadlineExceeded),
        }
    }

    async fn request_internal(&self, request: Request, limit: usize) -> Result<Response> {
        let id = request.id;
        let deadline_unix_ms = request.deadline_unix_ms();
        let deadline = instant_from_unix_ms(deadline_unix_ms);
        let (sender, receiver) = oneshot::channel();
        lock_unpoisoned(&self.inner.pending).insert(
            id,
            PendingRequest {
                sender,
                deadline_unix_ms,
                cancellation: CancellationToken::new(),
            },
        );
        let payload = match Envelope::Request(request).to_vec() {
            Ok(payload) => Zeroizing::new(payload),
            Err(error) => {
                remove_pending(&self.inner, id);
                return Err(error);
            }
        };
        if payload.len() > limit {
            remove_pending(&self.inner, id);
            return Err(Error::Protocol("request exceeds the active frame limit"));
        }
        match tokio::time::timeout_at(
            deadline,
            self.inner
                .writer
                .send(WriterCommand::Frame { payload, limit }),
        )
        .await
        {
            Ok(Ok(())) => {}
            Ok(Err(_)) => {
                remove_pending(&self.inner, id);
                return Err(Error::Closed);
            }
            Err(_) => {
                remove_pending(&self.inner, id);
                return Err(Error::DeadlineExceeded);
            }
        }
        match tokio::time::timeout_at(deadline, receiver).await {
            Ok(Ok(response)) => Ok(response),
            Ok(Err(_)) => Err(Error::Closed),
            Err(_) => {
                abandon_request(&self.inner, id);
                Err(Error::DeadlineExceeded)
            }
        }
    }
}

/// One in-flight call. Exactly one task may wait on a call; cancellation may
/// race that waiter through `cancel`.
pub struct Call {
    id: RequestId,
    deadline: Instant,
    receiver: Option<oneshot::Receiver<Response>>,
    client: Weak<Inner>,
    _permit: Option<tokio::sync::OwnedSemaphorePermit>,
    terminal: bool,
}

impl Call {
    pub const fn id(&self) -> RequestId {
        self.id
    }

    pub async fn cancel(&self) -> Result<()> {
        let Some(client) = self.client.upgrade() else {
            return Err(Error::Closed);
        };
        cancel_parent_callbacks(&client, self.id);
        match tokio::time::timeout_at(self.deadline, queue_cancel(&client, self.id)).await {
            Ok(result) => result,
            Err(_) => Err(Error::DeadlineExceeded),
        }
    }

    pub async fn wait(&mut self) -> Result<Value> {
        let receiver = self
            .receiver
            .take()
            .ok_or(Error::Protocol("call has already been waited"))?;
        let response = match tokio::time::timeout_at(self.deadline, receiver).await {
            Ok(Ok(response)) => response,
            Ok(Err(_)) => {
                self.terminal = true;
                self._permit.take();
                return Err(Error::Closed);
            }
            Err(_) => {
                if let Some(client) = self.client.upgrade() {
                    abandon_request(&client, self.id);
                    try_queue_cancel(&client, self.id);
                }
                self.terminal = true;
                self._permit.take();
                return Err(Error::DeadlineExceeded);
            }
        };
        self.terminal = true;
        self._permit.take();
        response_value(response)
    }
}

impl Drop for Call {
    fn drop(&mut self) {
        if self.terminal {
            return;
        }
        if let Some(client) = self.client.upgrade() {
            abandon_request(&client, self.id);
            try_queue_cancel(&client, self.id);
        }
    }
}

async fn queue_cancel(inner: &Arc<Inner>, id: RequestId) -> Result<()> {
    let notification = Notification::new(
        rpc::CANCEL,
        serde_json::to_value(CancelParams { id })
            .map_err(|_| Error::Protocol("failed to serialize cancellation"))?,
    )?;
    let payload = Zeroizing::new(Envelope::Notification(notification).to_vec()?);
    let limit = inner.max_frame_bytes.load(Ordering::Acquire);
    inner
        .writer
        .send(WriterCommand::Frame { payload, limit })
        .await
        .map_err(|_| Error::Closed)
}

fn try_queue_cancel(inner: &Arc<Inner>, id: RequestId) {
    let notification = serde_json::to_value(CancelParams { id })
        .ok()
        .and_then(|params| Notification::new(rpc::CANCEL, params).ok())
        .and_then(|notification| Envelope::Notification(notification).to_vec().ok())
        .map(Zeroizing::new);
    if let Some(payload) = notification {
        let limit = inner.max_frame_bytes.load(Ordering::Acquire);
        let _ = inner
            .writer
            .try_send(WriterCommand::Frame { payload, limit });
    }
}

/// Accept one inbound callback and answer it on its own task.
///
/// Returns `false` for a request this session must not accept at all: the
/// server reusing an inbound ID, naming a method the client never advertised,
/// or exceeding the negotiated active or bounded session-ID limits. Each means
/// the peer is not tracking the session state this side is, which is a protocol
/// violation rather than an application error.
///
/// Completed IDs remain in a bounded session set so reuse is still rejected
/// after a callback finishes. Active callbacks are bounded independently by
/// the negotiated in-flight limit.
fn serve_callback(inner: &Arc<Inner>, handler: Arc<dyn CallbackHandler>, request: Request) -> bool {
    if !inner.advertised.contains(&request.method) {
        return false;
    }
    let Some(parent_id) = request.meta.parent_request_id else {
        return false;
    };
    let parent_cancellation = {
        // Hold the parent table while reserving the inbound slot. A terminal
        // response cannot remove the parent between validation and attaching
        // the callback's cancellation state.
        let pending = lock_unpoisoned(&inner.pending);
        let Some(parent) = pending.get(&parent_id) else {
            return false;
        };
        if request.deadline_unix_ms() > parent.deadline_unix_ms {
            return false;
        }
        let mut inbound = lock_unpoisoned(&inner.inbound);
        let active_limit = inner.max_in_flight.load(Ordering::Acquire);
        if inbound.active >= active_limit
            || inbound.last_seen_id.is_some_and(|last| request.id <= last)
        {
            return false;
        }
        inbound.last_seen_id = Some(request.id);
        inbound.active += 1;
        parent.cancellation.clone()
    };
    let deadline = instant_from_unix_ms(request.deadline_unix_ms());
    let task_inner = Arc::downgrade(inner);
    tokio::spawn(async move {
        let mut outcome = tokio::select! {
            biased;
            _ = parent_cancellation.cancelled() => Err(RpcError::new(ErrorKind::Cancelled)),
            outcome = tokio::time::timeout_at(
                deadline,
                handler.call(&request.method, request.params),
            ) => outcome.unwrap_or_else(|_| Err(RpcError::new(ErrorKind::DeadlineExceeded))),
        };
        // A terminal parent may race a ready handler. Cancellation wins and
        // any returned secret is scrubbed before it can be serialized.
        if parent_cancellation.is_cancelled() {
            if let Ok(value) = &mut outcome {
                zeroize_json(value);
            }
            outcome = Err(RpcError::new(ErrorKind::Cancelled));
        }
        let mut response = match outcome {
            Ok(result) => Response::success(request.id, result),
            Err(error) => Response::error(Some(request.id), error),
        };
        let Some(inner) = task_inner.upgrade() else {
            zeroize_response(&mut response);
            return;
        };
        {
            let mut inbound = lock_unpoisoned(&inner.inbound);
            inbound.active = inbound.active.saturating_sub(1);
        }
        let limit = inner.max_frame_bytes.load(Ordering::Acquire);
        let encoded = serde_json::to_vec(&response).map(Zeroizing::new);
        zeroize_response(&mut response);
        let payload = match encoded {
            Ok(payload) if payload.len() <= limit => payload,
            // An answer that cannot fit still owes the server one terminal
            // frame, or its callback would hang until the deadline.
            _ => {
                let replacement =
                    Response::error(Some(request.id), RpcError::new(ErrorKind::MessageTooLarge));
                match Envelope::Response(replacement).to_vec().map(Zeroizing::new) {
                    Ok(payload) => payload,
                    Err(_) => return,
                }
            }
        };
        let send = inner.writer.send(WriterCommand::Frame { payload, limit });
        tokio::select! {
            biased;
            _ = parent_cancellation.cancelled() => {
                // Dropping the competing send zeroizes its serialized payload.
                // Only a value-free cancellation may be queued after the
                // parent has become terminal.
                let replacement =
                    Response::error(Some(request.id), RpcError::new(ErrorKind::Cancelled));
                if let Ok(payload) = Envelope::Response(replacement).to_vec().map(Zeroizing::new) {
                    let _ = inner
                        .writer
                        .send(WriterCommand::Frame { payload, limit })
                        .await;
                }
            }
            _ = send => {}
        }
    });
    true
}

fn response_value(response: Response) -> Result<Value> {
    match response {
        Response::Success(response) => Ok(response.result),
        Response::Error(response) => match response.error.data.kind {
            ErrorKind::Cancelled => Err(Error::Cancelled),
            ErrorKind::DeadlineExceeded => Err(Error::DeadlineExceeded),
            ErrorKind::Unavailable => Err(Error::Unavailable),
            _ => Err(Error::Remote(response.error)),
        },
    }
}

fn fail_session_weak(inner: &Weak<Inner>) {
    if let Some(inner) = inner.upgrade() {
        fail_session(&inner);
    }
}

fn fail_session(inner: &Arc<Inner>) {
    inner.state.store(CLOSED, Ordering::Release);
    for (_, pending) in lock_unpoisoned(&inner.pending).drain() {
        pending.cancellation.cancel();
    }
    lock_unpoisoned(&inner.abandoned).clear();
    inner.closed.notify_waiters();
}

fn abandon_request(inner: &Arc<Inner>, id: RequestId) {
    // Mark first, then remove from pending. The response reader removes the
    // marker if it wins the race while the pending sender still exists.
    let overflow = {
        let mut abandoned = lock_unpoisoned(&inner.abandoned);
        if abandoned.len() >= MAX_ABANDONED_REQUESTS {
            true
        } else {
            abandoned.insert(id);
            false
        }
    };
    remove_pending(inner, id);
    if overflow {
        // A peer that never terminates cancelled/timed-out requests cannot
        // grow client memory without bound. Close and reconnect instead.
        fail_session(inner);
    }
}

fn cancel_parent_callbacks(inner: &Arc<Inner>, id: RequestId) {
    if let Some(pending) = lock_unpoisoned(&inner.pending).get(&id) {
        pending.cancellation.cancel();
    }
}

fn remove_pending(inner: &Arc<Inner>, id: RequestId) {
    if let Some(pending) = lock_unpoisoned(&inner.pending).remove(&id) {
        pending.cancellation.cancel();
    }
}

fn zeroize_response(response: &mut Response) {
    if let Response::Success(response) = response {
        zeroize_json(&mut response.result);
    }
}

fn zeroize_json(value: &mut Value) {
    match value {
        Value::String(value) => value.zeroize(),
        Value::Array(values) => values.iter_mut().for_each(zeroize_json),
        Value::Object(values) => values.values_mut().for_each(zeroize_json),
        _ => {}
    }
}

fn lock_unpoisoned<T>(mutex: &StdMutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}
