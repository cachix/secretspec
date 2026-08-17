use crate::deadline::instant_from_unix_ms;
use crate::error::ErrorKind;
use crate::frame::{read_frame, write_frame};
use crate::jsonrpc::{Envelope, Notification, Request, RequestId, Response};
use crate::protocol::{CancelParams, InitializeParams, InitializeResult, Limits, rpc};
use crate::{ABSOLUTE_MAX_FRAME_BYTES, Error, Result};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU8, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex, Weak};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{Mutex, RwLock, Semaphore, mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio::time::Instant;
use zeroize::Zeroizing;

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

struct Inner {
    writer: mpsc::Sender<WriterCommand>,
    pending: StdMutex<HashMap<RequestId, oneshot::Sender<Response>>>,
    abandoned: StdMutex<HashSet<RequestId>>,
    next_id: AtomicU64,
    max_frame_bytes: AtomicUsize,
    limits: RwLock<Limits>,
    semaphore: RwLock<Arc<Semaphore>>,
    capabilities: RwLock<HashSet<String>>,
    state: AtomicU8,
    reader_task: Mutex<Option<JoinHandle<()>>>,
    writer_task: Mutex<Option<JoinHandle<()>>>,
}

/// A multiplexed SecretSpec JSON-RPC session.
#[derive(Clone)]
pub struct Client {
    inner: Arc<Inner>,
}

impl Client {
    /// Initialize a session on an already-authenticated private transport.
    pub async fn connect<R, W, A, B>(
        mut reader: R,
        mut writer: W,
        initialize: InitializeParams<A>,
        startup_deadline_unix_ms: u64,
    ) -> Result<(Self, InitializeResult<B>)>
    where
        R: AsyncRead + Unpin + Send + 'static,
        W: AsyncWrite + Unpin + Send + 'static,
        A: Serialize,
        B: DeserializeOwned,
    {
        let offered_protocol = initialize.protocol.clone();
        let offered_versions = initialize.versions.clone();
        let offered_limits = initialize.limits;
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
        let inner = Arc::new(Inner {
            writer: writer_tx,
            pending: StdMutex::new(HashMap::new()),
            abandoned: StdMutex::new(HashSet::new()),
            next_id: AtomicU64::new(2),
            max_frame_bytes: AtomicUsize::new(ABSOLUTE_MAX_FRAME_BYTES),
            limits: RwLock::new(Limits::PRE_NEGOTIATION),
            semaphore: RwLock::new(Arc::new(Semaphore::new(1))),
            capabilities: RwLock::new(HashSet::new()),
            state: AtomicU8::new(INITIALIZING),
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
                let frame = match read_frame(&mut reader, limit).await {
                    Ok(Some(frame)) => frame,
                    Ok(None) | Err(_) => {
                        fail_session_weak(&reader_inner);
                        break;
                    }
                };
                let response = match Envelope::parse(&frame) {
                    Ok(Envelope::Response(response)) => response,
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
                let sender = lock_unpoisoned(&inner.pending).remove(&id);
                if let Some(sender) = sender {
                    // A deadline can race a response after marking this ID as
                    // abandoned but before removing it from `pending`.
                    lock_unpoisoned(&inner.abandoned).remove(&id);
                    let _ = sender.send(response);
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
        *client.inner.limits.write().await = initialized.limits;
        *client.inner.semaphore.write().await =
            Arc::new(Semaphore::new(initialized.limits.max_in_flight));
        *client.inner.capabilities.write().await =
            initialized.capabilities.iter().cloned().collect();
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
        lock_unpoisoned(&self.inner.pending).insert(id, sender);
        if let Err(error) = self.queue_request(request, deadline).await {
            lock_unpoisoned(&self.inner.pending).remove(&id);
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
        let deadline = instant_from_unix_ms(request.deadline_unix_ms);
        let (sender, receiver) = oneshot::channel();
        lock_unpoisoned(&self.inner.pending).insert(id, sender);
        let payload = Zeroizing::new(Envelope::Request(request).to_vec()?);
        if payload.len() > limit {
            lock_unpoisoned(&self.inner.pending).remove(&id);
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
                lock_unpoisoned(&self.inner.pending).remove(&id);
                return Err(Error::Closed);
            }
            Err(_) => {
                lock_unpoisoned(&self.inner.pending).remove(&id);
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
    lock_unpoisoned(&inner.pending).clear();
    lock_unpoisoned(&inner.abandoned).clear();
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
    lock_unpoisoned(&inner.pending).remove(&id);
    if overflow {
        // A peer that never terminates cancelled/timed-out requests cannot
        // grow client memory without bound. Close and reconnect instead.
        fail_session(inner);
    }
}

fn lock_unpoisoned<T>(mutex: &StdMutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}
