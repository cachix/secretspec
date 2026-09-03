//! SecretSpec IPC version 1.
//!
//! The checked-in JSON schemas and protocol documents are canonical. This
//! crate is an independent Rust implementation of their wire, client, server,
//! resolution, and provider state machines.

pub mod deadline;
pub mod error;
pub mod frame;
pub mod jsonrpc;
pub mod launch;
pub mod protocol;

#[cfg(feature = "tokio")]
mod description;

#[cfg(feature = "blocking")]
pub mod blocking;

#[cfg(feature = "tokio")]
pub mod client;
#[cfg(feature = "tokio")]
pub mod lifecycle;
#[cfg(feature = "tokio")]
pub mod provider;
#[cfg(feature = "tokio")]
pub mod resolver;
#[cfg(feature = "tokio")]
pub mod server;

pub use deadline::unix_ms_after as deadline_unix_ms_after;
pub use error::{
    Error, ErrorData, ErrorKind, InteractionKind, InteractionReference, Result, RpcError,
};
pub use jsonrpc::{Envelope, Notification, Request, RequestId, Response};
pub use protocol::{Limits, Product};

/// Wire protocol major version implemented by this crate.
pub const WIRE_VERSION: u32 = 1;

/// Absolute pre-negotiation and version 1 frame ceiling.
pub const ABSOLUTE_MAX_FRAME_BYTES: usize = 1_048_576;

/// Smallest negotiable frame limit.
pub const MIN_FRAME_BYTES: usize = 4_096;

/// Version 1 in-flight ceiling.
pub const MAX_IN_FLIGHT: usize = 32;

/// Largest request ID that is exactly representable by JSON/JavaScript peers.
pub const MAX_REQUEST_ID: u64 = 9_007_199_254_740_991;
