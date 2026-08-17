use crate::deadline::instant_from_unix_ms;
use crate::error::{ErrorKind, RpcError};
use crate::frame::{read_frame, write_frame};
use crate::jsonrpc::{Envelope, Notification, Request, RequestId, Response};
use crate::protocol::{
    CancelParams, EmptyParams, InitializeParams, InitializeResult, Limits, Product, rpc,
};
use crate::{ABSOLUTE_MAX_FRAME_BYTES, Error, Result};
use async_trait::async_trait;
use serde_json::{Value, json};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{Mutex, Semaphore, mpsc, oneshot};
use tokio::task::JoinSet;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

pub type RpcResult<T> = std::result::Result<T, RpcError>;
const MAX_SESSION_REQUEST_IDS: usize = 65_536;

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
    /// were created while producing a response (for example broker leases).
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

struct WriterCommand {
    response: Response,
    limit: usize,
    committed: Option<oneshot::Sender<std::result::Result<(), ()>>>,
}

/// Serve exactly one initialized application session on a private byte stream.
pub async fn serve<R, W, H>(
    mut reader: R,
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

    let (writer_tx, mut writer_rx) =
        mpsc::channel::<WriterCommand>(config.limits.max_in_flight + 2);
    let disconnected = CancellationToken::new();
    let writer_disconnected = disconnected.clone();
    let mut writer_task = tokio::spawn(async move {
        while let Some(command) = writer_rx.recv().await {
            let outcome = match serde_json::to_vec(&command.response) {
                Ok(payload) => write_frame(&mut writer, &Zeroizing::new(payload), command.limit)
                    .await
                    .map_err(|_| ()),
                Err(_) => Err(()),
            };
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

    let mut active_limit = ABSOLUTE_MAX_FRAME_BYTES;
    let mut initialized = false;
    let mut advertised_capabilities = HashSet::new();
    let mut seen_ids = HashSet::new();
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
            frame = read_frame(&mut reader, active_limit) => match frame {
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
            Envelope::Response(_) => {
                break;
            }
            Envelope::Notification(notification) => {
                if handle_notification(notification, &inflight).await.is_err() {
                    break;
                }
            }
            Envelope::Request(request) => {
                if seen_ids.len() >= MAX_SESSION_REQUEST_IDS {
                    let response = Response::error(Some(request.id), RpcError::unavailable(None));
                    let _ = commit(&writer_tx, response, active_limit).await;
                    break;
                }
                if !seen_ids.insert(request.id) {
                    let response =
                        Response::error(Some(request.id), RpcError::new(ErrorKind::InvalidRequest));
                    let _ = commit(&writer_tx, response, active_limit).await;
                    break;
                }

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
                        match initialize(&request, handler.as_ref(), &config, &writer_tx).await {
                            Ok(selected) => selected,
                            Err(error) => {
                                fatal = Some(error);
                                break;
                            }
                        };
                    let Some((limits, capabilities)) = selected else {
                        break;
                    };
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

                if !request.method.starts_with("client.")
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

    for cancellation in inflight.lock().await.values() {
        cancellation.cancel();
    }
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
    let cancellation = CancellationToken::new();
    let context = RequestContext {
        request_id: request.id,
        deadline: request_deadline(request).min(Instant::now() + config.startup_timeout),
        cancellation,
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
        capabilities: capabilities.clone(),
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
) -> Result<()> {
    if notification.method != rpc::CANCEL {
        return Err(Error::Protocol("unknown notification"));
    }
    let params: CancelParams = serde_json::from_value(notification.params)
        .map_err(|_| Error::Protocol("malformed cancellation notification"))?;
    if let Some(cancellation) = inflight.lock().await.get(&params.id) {
        cancellation.cancel();
    }
    Ok(())
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
    let payload = serde_json::to_vec(&response)
        .map_err(|_| Error::Protocol("failed to serialize response"))?;
    let response = if payload.is_empty() || payload.len() > limit {
        Response::error(response.id(), RpcError::new(ErrorKind::MessageTooLarge))
    } else {
        response
    };
    writer
        .send(WriterCommand {
            response,
            limit,
            committed: None,
        })
        .await
        .map_err(|_| Error::Closed)
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
    let payload = serde_json::to_vec(&response).unwrap_or_default();
    let application_response = !payload.is_empty() && payload.len() <= limit;
    let response = if !application_response {
        let id = response.id();
        Response::error(id, RpcError::new(ErrorKind::MessageTooLarge))
    } else {
        response
    };
    let request_id = response.id();
    let (committed_tx, committed_rx) = oneshot::channel();
    let command = WriterCommand {
        response,
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
    tokio::time::timeout(COMMIT_TIMEOUT, async {
        let (committed_tx, committed_rx) = oneshot::channel();
        writer
            .send(WriterCommand {
                response,
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
    instant_from_unix_ms(request.deadline_unix_ms)
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
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
    }
    commit(writer, Response::success(request.id, json!({})), limit).await
}

#[cfg(test)]
mod tests {
    use super::*;

    // Most dispatcher behavior is exercised through the black-box integration
    // tests; keep this module focused on wall-to-monotonic conversion.
    #[test]
    fn expired_deadline_is_not_started() {
        let request = Request::new(RequestId::new(1).unwrap(), "test.call", 1, json!({})).unwrap();
        assert!(request_deadline(&request) <= Instant::now());
    }
}
