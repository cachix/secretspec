//! Synchronous `secretspec.resolver/1` sessions for callers without an async
//! runtime.
//!
//! [`crate::client::Client`] multiplexes concurrent calls over one transport,
//! which needs a reactor and therefore a Tokio dependency. A synchronous
//! consumer such as a build tool resolves one name at a time and needs neither.
//! This module keeps the canonical framing, envelopes, and validation and
//! trades only multiplexing for `std::process` and blocking pipe I/O, so a
//! program that has no runtime can speak the same wire protocol without
//! acquiring one.
//!
//! One call is in flight at a time, which is why no pending map, in-flight
//! permit, or cancellation arbitration appears here. Requests still carry their
//! wire deadline, and [`Watchdog`] enforces it locally.
//!
//! A session opened here advertises no callbacks (0.20+), so the endpoint never
//! sends one and an inbound request stays as fatal as any other envelope this
//! side did not ask for. That also means a `prompt = true` declaration with no
//! stored value resolves as missing rather than reaching a person, even though
//! a build tool on a terminal is exactly the consumer that could answer.
//! Servicing a callback between writing a request and reading its response
//! would fit this loop naturally, and is not implemented.

use crate::deadline::{clamp_unix_ms, duration_until_unix_ms};
use crate::error::ErrorKind;
use crate::frame::{FrameDecoder, encode};
use crate::jsonrpc::{Envelope, Request, RequestId, Response};
use crate::launch::{Environment, LaunchOptions};
use crate::protocol::resolver::{
    self as resolver_protocol, DeleteParams, DeleteResult, GetParams, GetResult,
    InitializeApplication, InitializedApplication, ReleaseParams, ReleaseResult, SetParams,
    SetResult,
};
use crate::protocol::{
    InitializeParams, InitializeResult, Limits, PROTOCOL_VERSION, Product, RESOLVER_PROTOCOL, rpc,
};
use crate::{ABSOLUTE_MAX_FRAME_BYTES, Error, Result};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use std::collections::{HashSet, VecDeque};
use std::io::{Read, Write};
use std::process::{Child, ChildStderr, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, SyncSender, sync_channel};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

/// Budget for reaping a child that had to be killed. Reaping is bounded local
/// work, so it is measured from the moment it starts rather than from a
/// caller's deadline, which a graceful wait has usually already spent.
const REAP_GRACE: Duration = Duration::from_secs(2);

/// Poll interval while waiting for a child to exit on its own. `Child::wait`
/// would block past the caller's deadline, so exit is polled instead.
const WAIT_POLL: Duration = Duration::from_millis(10);

/// Read size for the response pipe. Version 1 client frames are small, so this
/// buys full frames per syscall without reserving a frame-sized buffer.
const READ_CHUNK: usize = 8192;

/// An initialized `secretspec.resolver/1` session and the child process that owns
/// its private transport.
pub struct ResolverSession {
    transport: Transport,
    capabilities: HashSet<String>,
    initialized: InitializedApplication,
}

impl ResolverSession {
    /// Launch an endpoint, complete initialization, and return a ready session.
    ///
    /// The child is killed and reaped if any part of the handshake fails, so a
    /// rejected launch never leaves a process behind.
    pub fn launch(
        options: LaunchOptions,
        client: Product,
        limits: Limits,
        application: InitializeApplication,
        startup_deadline_unix_ms: u64,
    ) -> Result<Self> {
        application.validate()?;
        let initialize = InitializeParams {
            protocol: RESOLVER_PROTOCOL.to_string(),
            versions: vec![PROTOCOL_VERSION],
            client,
            limits,
            client_methods: Vec::new(),
            application,
        };
        // `initialize.protocol` is the constant compared against, so the
        // protocol check inside `validate_common` is trivially true here. The
        // call is kept for the checks that do bite locally: version list shape,
        // product strings, and limit ranges.
        initialize.validate_common(RESOLVER_PROTOCOL)?;

        let mut transport = Transport::spawn(&options)?;
        let handshake = transport.initialize(&initialize, startup_deadline_unix_ms);
        let initialized: InitializeResult<InitializedApplication> = match handshake {
            Ok(initialized) => initialized,
            Err(error) => {
                transport.terminate();
                return Err(error);
            }
        };

        let mut session = Self {
            transport,
            capabilities: initialized.methods.into_iter().collect(),
            initialized: initialized.application,
        };
        if let Err(error) = session.validate_endpoint() {
            session.transport.terminate();
            return Err(error);
        }
        Ok(session)
    }

    fn validate_endpoint(&self) -> Result<()> {
        self.initialized.validate()?;
        if !resolver_protocol::CAPABILITIES
            .iter()
            .all(|method| self.capabilities.contains(*method))
        {
            return Err(Error::Protocol(
                "resolution endpoint did not advertise all required methods",
            ));
        }
        Ok(())
    }

    /// Resolve one exact declared name on the session's fixed configuration.
    pub fn get(&mut self, params: &GetParams, deadline_unix_ms: u64) -> Result<GetResult> {
        params.validate()?;
        self.call(resolver_protocol::method::GET, params, deadline_unix_ms)
    }

    /// Store one exact declared name on the session's fixed configuration
    /// (0.20+).
    ///
    /// The value lands wherever a [`Self::get`] of the same name would read it
    /// from, so a consumer that stores and then resolves does not have to model
    /// the endpoint's routing. Endpoints advertise `resolver.set` only when they
    /// accept writes, and [`Self::call`] refuses to send an unadvertised method,
    /// so an older or read-only resolver fails here rather than on the wire.
    pub fn set(&mut self, params: &SetParams, deadline_unix_ms: u64) -> Result<SetResult> {
        params.validate()?;
        self.call(resolver_protocol::method::SET, params, deadline_unix_ms)
    }

    /// Remove one exact declared name's stored value (0.20+).
    ///
    /// Advertised as `resolver.delete` under the same rule as [`Self::set`]. A
    /// name the store never held reports `deleted: false` rather than failing.
    pub fn delete(&mut self, params: &DeleteParams, deadline_unix_ms: u64) -> Result<DeleteResult> {
        params.validate()?;
        self.call(resolver_protocol::method::DELETE, params, deadline_unix_ms)
    }

    /// Whether the endpoint advertised one method, such as
    /// [`resolver_protocol::method::SET`].
    ///
    /// A consumer that can explain a missing capability better than the
    /// protocol can checks it here before building a request.
    pub fn supports(&self, method: &str) -> bool {
        self.capabilities.contains(method)
    }

    /// Release path leases. Release is idempotent, so unknown IDs succeed.
    pub fn release(
        &mut self,
        params: &ReleaseParams,
        deadline_unix_ms: u64,
    ) -> Result<ReleaseResult> {
        params.validate()?;
        self.call(resolver_protocol::method::RELEASE, params, deadline_unix_ms)
    }

    pub fn capabilities(&self) -> &HashSet<String> {
        &self.capabilities
    }

    pub fn initialized(&self) -> &InitializedApplication {
        &self.initialized
    }

    pub fn is_closed(&self) -> bool {
        self.transport.closed
    }

    /// Shut the session down and reap the child.
    ///
    /// Path leases are released by disconnect, so a caller that only ever read
    /// inline values does not need an explicit release first.
    pub fn close(&mut self, deadline_unix_ms: u64) -> Result<()> {
        self.transport.close(deadline_unix_ms)
    }

    fn call<P: Serialize, R: DeserializeOwned>(
        &mut self,
        method: &str,
        params: &P,
        deadline_unix_ms: u64,
    ) -> Result<R> {
        if !self.capabilities.contains(method) {
            return Err(Error::Protocol("method was not advertised"));
        }
        self.transport.call(method, params, deadline_unix_ms)
    }
}

/// The child, its pipes, and the incremental decoder for its responses.
struct Transport {
    /// Shared so [`Watchdog`] can kill the child while this thread is parked in
    /// a blocking read. Nothing holds this lock across an I/O call.
    child: Arc<Mutex<Child>>,
    stdin: Option<ChildStdin>,
    stdout: Receiver<StdoutEvent>,
    decoder: FrameDecoder,
    frames: VecDeque<Zeroizing<Vec<u8>>>,
    next_id: u64,
    max_frame_bytes: usize,
    closed: bool,
}

impl Transport {
    fn spawn(options: &LaunchOptions) -> Result<Self> {
        options.validate()?;
        // Built before the spawn so nothing between here and the constructor
        // can fail while a live child has no owner to reap it.
        let decoder = FrameDecoder::new(ABSOLUTE_MAX_FRAME_BYTES)?;
        let mut command = Command::new(&options.executable);
        command
            .args(&options.arguments)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        match &options.environment {
            Environment::Inherit(overrides) => {
                command.envs(overrides);
            }
            Environment::Replace(environment) => {
                command.env_clear().envs(environment);
            }
        }

        let mut child = command.spawn()?;
        // Every pipe was requested above, so a missing one means the child is
        // unusable. Reap it here rather than dropping a live process on the
        // floor: nothing owns it yet, so no destructor would clean it up.
        let Some(((stdin, stdout), stderr)) = child
            .stdin
            .take()
            .zip(child.stdout.take())
            .zip(child.stderr.take())
        else {
            let _ = child.kill();
            let _ = child.wait();
            return Err(Error::Protocol("child pipes were not created"));
        };
        drain_stderr(stderr, options.max_stderr_bytes);
        let stdout = read_stdout(stdout);

        Ok(Self {
            child: Arc::new(Mutex::new(child)),
            stdin: Some(stdin),
            stdout,
            decoder,
            frames: VecDeque::new(),
            next_id: 1,
            max_frame_bytes: ABSOLUTE_MAX_FRAME_BYTES,
            closed: false,
        })
    }

    fn initialize<A: Serialize, B: DeserializeOwned>(
        &mut self,
        initialize: &InitializeParams<A>,
        deadline_unix_ms: u64,
    ) -> Result<InitializeResult<B>> {
        let params = serde_json::to_value(initialize)
            .map_err(|_| Error::Protocol("failed to serialize initialization"))?;
        let value = self.exchange(rpc::INITIALIZE, params, deadline_unix_ms)?;
        let initialized: InitializeResult<B> = serde_json::from_value(value)
            .map_err(|error| Error::ProtocolOwned(error.to_string()))?;
        initialized.validate_common(
            &initialize.protocol,
            &initialize.versions,
            initialize.limits,
        )?;
        // Both directions adopt the negotiated ceiling before the next call, so
        // an oversized response is rejected by length rather than allocated.
        self.max_frame_bytes = initialized.limits.max_frame_bytes;
        self.decoder.set_limit(self.max_frame_bytes)?;
        Ok(initialized)
    }

    fn call<P: Serialize, R: DeserializeOwned>(
        &mut self,
        method: &str,
        params: &P,
        deadline_unix_ms: u64,
    ) -> Result<R> {
        let params = serde_json::to_value(params)
            .map_err(|_| Error::Protocol("failed to serialize call params"))?;
        let value = self.exchange(method, params, deadline_unix_ms)?;
        serde_json::from_value(value).map_err(|error| Error::ProtocolOwned(error.to_string()))
    }

    /// Send one request and wait for its response under a local deadline.
    fn exchange(&mut self, method: &str, params: Value, deadline_unix_ms: u64) -> Result<Value> {
        if self.closed {
            return Err(Error::Closed);
        }
        // Clamp once, then use the same value locally and on the wire so the
        // peer never enforces a longer deadline than this client waits for.
        let deadline_unix_ms = clamp_unix_ms(deadline_unix_ms);
        let remaining = duration_until_unix_ms(deadline_unix_ms);
        if remaining.is_zero() {
            return Err(Error::DeadlineExceeded);
        }
        let id = self.next_id()?;
        let request = Request::new(id, method, deadline_unix_ms, params)?;
        let deadline = Instant::now() + remaining;

        let watchdog = Watchdog::arm(&self.child, remaining);
        let outcome = self.attempt(request, id, deadline);
        let read_timed_out = self.closed && matches!(&outcome, Err(Error::DeadlineExceeded));
        // A watchdog that fired killed the transport, so every failure it
        // produced downstream is really the deadline. A response that won the
        // race is still valid and is reported as success; the session is dead
        // either way and `close` reaps it.
        let watchdog_fired = watchdog.disarm();
        if read_timed_out && !watchdog_fired {
            self.stdin = None;
            self.kill_and_reap();
        }
        if watchdog_fired {
            self.closed = true;
            if outcome.is_err() {
                return Err(Error::DeadlineExceeded);
            }
        }
        outcome
    }

    fn attempt(&mut self, request: Request, id: RequestId, deadline: Instant) -> Result<Value> {
        let limit = self.max_frame_bytes;
        self.write_envelope(&Envelope::Request(request), limit)?;
        let response = self.read_response(deadline)?;
        if response.id() != Some(id) {
            // Strictly one call is in flight, so any other terminal ID is a
            // protocol violation rather than something to correlate later.
            self.closed = true;
            return Err(Error::Protocol("response ID does not match the request"));
        }
        response_value(response)
    }

    fn write_envelope(&mut self, envelope: &Envelope, limit: usize) -> Result<()> {
        let payload = Zeroizing::new(envelope.to_vec()?);
        let frame = Zeroizing::new(encode(&payload, limit)?);
        let Some(stdin) = self.stdin.as_mut() else {
            return Err(Error::Closed);
        };
        if let Err(error) = stdin.write_all(&frame).and_then(|()| stdin.flush()) {
            self.closed = true;
            return Err(Error::Io(error));
        }
        Ok(())
    }

    fn read_response(&mut self, deadline: Instant) -> Result<Response> {
        loop {
            if let Some(frame) = self.frames.pop_front() {
                return match Envelope::parse(&frame) {
                    Ok(Envelope::Response(response)) => Ok(response),
                    // Notifications have no response channel. Structurally
                    // valid notifications, including methods introduced by a
                    // later revision, are ignored.
                    Ok(Envelope::Notification(_)) => continue,
                    // This client advertises no callbacks, so an inbound
                    // request remains a protocol violation.
                    Ok(Envelope::Request(_)) => {
                        self.closed = true;
                        Err(Error::Protocol("peer sent an unexpected request"))
                    }
                    Err(error) => {
                        self.closed = true;
                        Err(error)
                    }
                };
            }

            let event = self
                .stdout
                .recv_timeout(deadline.saturating_duration_since(Instant::now()));
            let buffer = match event {
                Ok(StdoutEvent::Chunk(buffer)) => buffer,
                Ok(StdoutEvent::Error(error)) => {
                    self.closed = true;
                    return Err(Error::Io(error));
                }
                Ok(StdoutEvent::Eof) | Err(RecvTimeoutError::Disconnected) => {
                    self.closed = true;
                    // EOF between frames is a clean disconnect; a partial frame is
                    // a truncation the caller must not confuse with one.
                    self.decoder.finish_eof()?;
                    return Err(Error::Closed);
                }
                Err(RecvTimeoutError::Timeout) => {
                    self.closed = true;
                    return Err(Error::DeadlineExceeded);
                }
            };
            if buffer.is_empty() {
                self.closed = true;
                return Err(Error::Protocol("stdout reader returned an empty chunk"));
            }
            match self.decoder.push(&buffer) {
                Ok(frames) => self.frames.extend(frames),
                Err(error) => {
                    self.closed = true;
                    return Err(error);
                }
            }
        }
    }

    fn next_id(&mut self) -> Result<RequestId> {
        let id = RequestId::new(self.next_id)?;
        self.next_id += 1;
        Ok(id)
    }

    fn close(&mut self, deadline_unix_ms: u64) -> Result<()> {
        let outcome = if self.closed {
            Ok(())
        } else {
            self.exchange(rpc::SHUTDOWN, json!({}), deadline_unix_ms)
                .and_then(|value| {
                    if value == json!({}) {
                        Ok(())
                    } else {
                        Err(Error::Protocol("shutdown result is not empty"))
                    }
                })
        };
        self.closed = true;
        // Closing stdin is the disconnect signal an endpoint waits for, so it
        // must happen before the graceful wait rather than at drop time.
        self.stdin = None;

        let graceful = wait_until(&self.child, Instant::now() + REAP_GRACE);
        if !matches!(graceful, Ok(true)) {
            self.kill_and_reap();
        }
        graceful?;
        outcome
    }

    /// Kill the child and reap it, so a session that failed or overran never
    /// leaves a zombie behind.
    fn terminate(&mut self) {
        self.closed = true;
        self.stdin = None;
        self.kill_and_reap();
    }

    fn kill_and_reap(&mut self) {
        let mut child = lock_unpoisoned(&self.child);
        let _ = child.kill();
        drop(child);
        // A killed child exits promptly, but the wait stays bounded so a
        // grandchild holding the pipes cannot block the caller forever.
        let _ = wait_until(&self.child, Instant::now() + REAP_GRACE);
    }
}

impl Drop for Transport {
    fn drop(&mut self) {
        if self.stdin.is_none() && self.closed {
            return;
        }
        self.terminate();
    }
}

enum StdoutEvent {
    Chunk(Zeroizing<Vec<u8>>),
    Eof,
    Error(std::io::Error),
}

/// Read stdout on its own thread and bound the handoff to one chunk.
///
/// The receiver can enforce a request deadline even if a descendant inherited
/// the pipe and keeps this thread's blocking read alive after the direct child
/// is killed. Dropping the receiver makes the thread exit on its next read.
fn read_stdout(mut stdout: ChildStdout) -> Receiver<StdoutEvent> {
    let (sender, receiver) = sync_channel(1);
    std::thread::spawn(move || {
        loop {
            let mut buffer = Zeroizing::new(vec![0_u8; READ_CHUNK]);
            match stdout.read(&mut buffer) {
                Ok(0) => {
                    send_stdout_event(&sender, StdoutEvent::Eof);
                    break;
                }
                Ok(read) => {
                    buffer.truncate(read);
                    if sender.send(StdoutEvent::Chunk(buffer)).is_err() {
                        break;
                    }
                }
                Err(error) => {
                    send_stdout_event(&sender, StdoutEvent::Error(error));
                    break;
                }
            }
        }
    });
    receiver
}

fn send_stdout_event(sender: &SyncSender<StdoutEvent>, event: StdoutEvent) {
    let _ = sender.send(event);
}

/// Kills the direct child when a blocking call outlives its deadline.
///
/// Stdout is read on a dedicated thread and the caller's channel receive has
/// its own timeout, so an inherited pipe cannot strand the caller. The
/// watchdog remains necessary for writes, which can also block when a peer
/// stops consuming input, and to end the direct child once either side stalls.
struct Watchdog {
    finished: Arc<(Mutex<bool>, Condvar)>,
    fired: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Watchdog {
    fn arm(child: &Arc<Mutex<Child>>, timeout: Duration) -> Self {
        let finished = Arc::new((Mutex::new(false), Condvar::new()));
        let fired = Arc::new(AtomicBool::new(false));
        let thread = std::thread::spawn({
            let finished = Arc::clone(&finished);
            let fired = Arc::clone(&fired);
            let child = Arc::clone(child);
            move || {
                let (lock, condvar) = &*finished;
                let guard = lock_unpoisoned(lock);
                let (_guard, timeout_result) = condvar
                    .wait_timeout_while(guard, timeout, |finished| !*finished)
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                if !timeout_result.timed_out() {
                    return;
                }
                // Ordered before the kill so the call that observes a dead
                // transport always also observes the reason for it.
                fired.store(true, Ordering::Release);
                let _ = lock_unpoisoned(&child).kill();
            }
        });
        Self {
            finished,
            fired,
            thread: Some(thread),
        }
    }

    /// Stop the timer and report whether it had already fired.
    fn disarm(mut self) -> bool {
        let (lock, condvar) = &*self.finished;
        *lock_unpoisoned(lock) = true;
        condvar.notify_all();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
        self.fired.load(Ordering::Acquire)
    }
}

/// Drain the child's stderr on a detached thread.
///
/// Without a reader the child blocks once the pipe fills, which would deadlock
/// the session against a diagnostic it cannot finish writing. The retained
/// prefix is bounded by `max_stderr_bytes`; the remainder is read and dropped
/// so draining continues either way.
fn drain_stderr(mut stderr: ChildStderr, max_stderr_bytes: usize) {
    std::thread::spawn(move || {
        let mut retained = Zeroizing::new(Vec::with_capacity(max_stderr_bytes.min(READ_CHUNK)));
        let mut buffer = Zeroizing::new(vec![0_u8; READ_CHUNK]);
        loop {
            let read = match stderr.read(&mut buffer) {
                Ok(0) | Err(_) => break,
                Ok(read) => read,
            };
            let available = max_stderr_bytes.saturating_sub(retained.len());
            retained.extend_from_slice(&buffer[..read.min(available)]);
        }
    });
}

fn wait_until(child: &Arc<Mutex<Child>>, deadline: Instant) -> Result<bool> {
    loop {
        if lock_unpoisoned(child).try_wait()?.is_some() {
            return Ok(true);
        }
        if Instant::now() >= deadline {
            return Ok(false);
        }
        std::thread::sleep(WAIT_POLL);
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

fn lock_unpoisoned<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}
