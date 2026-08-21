use serde::{Deserialize, Serialize};
use std::fmt;
use thiserror::Error;

/// Stable machine-readable error kinds shared by both application protocols.
///
/// The set is closed for senders and open for receivers. An endpoint emits only
/// the kinds below, but a receiver decodes anything it does not recognize as
/// [`ErrorKind::Unrecognized`] instead of failing the frame. Without that, the
/// first kind a later protocol version adds would kill every session with an
/// older peer, and the set could never grow without a new protocol version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    ParseError,
    InvalidRequest,
    MethodNotFound,
    InvalidParams,
    Internal,
    UnsupportedVersion,
    CapabilityRequired,
    DeadlineExceeded,
    Cancelled,
    Unavailable,
    PermissionDenied,
    InteractionRequired,
    Conflict,
    OperationFailed,
    MessageTooLarge,
    RepresentationMismatch,
    /// A kind this implementation does not know, decoded from a peer that
    /// speaks a later revision of the protocol.
    ///
    /// Receiving one means the operation failed for a reason this side cannot
    /// name, so it is handled as a failure and never as a success. An endpoint
    /// MUST NOT construct it: doing so would put `"unrecognized"` on the wire
    /// as if it were a defined kind.
    Unrecognized,
}

impl ErrorKind {
    /// Stable wire spelling used for structured handling and redacted audit
    /// records.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ParseError => "parse_error",
            Self::InvalidRequest => "invalid_request",
            Self::MethodNotFound => "method_not_found",
            Self::InvalidParams => "invalid_params",
            Self::Internal => "internal",
            Self::UnsupportedVersion => "unsupported_version",
            Self::CapabilityRequired => "capability_required",
            Self::DeadlineExceeded => "deadline_exceeded",
            Self::Cancelled => "cancelled",
            Self::Unavailable => "unavailable",
            Self::PermissionDenied => "permission_denied",
            Self::InteractionRequired => "interaction_required",
            Self::Conflict => "conflict",
            Self::OperationFailed => "operation_failed",
            Self::MessageTooLarge => "message_too_large",
            Self::RepresentationMismatch => "representation_mismatch",
            Self::Unrecognized => "unrecognized",
        }
    }

    /// Decode a wire spelling, mapping anything unknown to
    /// [`Self::Unrecognized`] rather than refusing the frame.
    pub fn from_wire(kind: &str) -> Self {
        Self::DEFINED
            .iter()
            .copied()
            .find(|defined| defined.as_str() == kind)
            .unwrap_or(Self::Unrecognized)
    }

    /// The kind a defined code names, or `None` for a code this revision does
    /// not define. Used to keep a peer honest: a code this side knows must
    /// arrive with the kind that belongs to it, and only a code it does not
    /// know may carry a kind it does not know.
    pub fn from_code(code: i32) -> Option<Self> {
        Self::DEFINED
            .iter()
            .copied()
            .find(|defined| defined.code() == code)
    }

    /// Every kind this revision defines, in wire-code order. `Unrecognized` is
    /// deliberately absent: it is a decoding outcome, not a defined kind.
    pub const DEFINED: &'static [Self] = &[
        Self::ParseError,
        Self::InvalidRequest,
        Self::MethodNotFound,
        Self::InvalidParams,
        Self::Internal,
        Self::UnsupportedVersion,
        Self::CapabilityRequired,
        Self::DeadlineExceeded,
        Self::Cancelled,
        Self::Unavailable,
        Self::PermissionDenied,
        Self::InteractionRequired,
        Self::Conflict,
        Self::OperationFailed,
        Self::MessageTooLarge,
        Self::RepresentationMismatch,
    ];

    pub const fn code(self) -> i32 {
        match self {
            Self::ParseError => -32700,
            Self::InvalidRequest => -32600,
            Self::MethodNotFound => -32601,
            Self::InvalidParams => -32602,
            Self::Internal => -32603,
            Self::UnsupportedVersion => -32000,
            Self::CapabilityRequired => -32001,
            Self::DeadlineExceeded => -32002,
            Self::Cancelled => -32003,
            Self::Unavailable => -32004,
            Self::PermissionDenied => -32005,
            Self::InteractionRequired => -32006,
            Self::Conflict => -32007,
            Self::OperationFailed => -32008,
            Self::MessageTooLarge => -32009,
            Self::RepresentationMismatch => -32010,
            // Never sent, so it names no code of its own. The wire code that
            // arrived with it is carried by `RpcError::code`.
            Self::Unrecognized => 0,
        }
    }

    pub const fn message(self) -> &'static str {
        match self {
            Self::ParseError => "parse error",
            Self::InvalidRequest => "invalid request",
            Self::MethodNotFound => "method not found",
            Self::InvalidParams => "invalid params",
            Self::Internal => "internal error",
            Self::UnsupportedVersion => "unsupported version",
            Self::CapabilityRequired => "capability required",
            Self::DeadlineExceeded => "deadline exceeded",
            Self::Cancelled => "cancelled",
            Self::Unavailable => "unavailable",
            Self::PermissionDenied => "permission denied",
            Self::InteractionRequired => "interaction required",
            Self::Conflict => "conflict",
            Self::OperationFailed => "operation failed",
            Self::MessageTooLarge => "message too large",
            Self::RepresentationMismatch => "representation mismatch",
            Self::Unrecognized => "unrecognized error",
        }
    }

    pub const fn retryable_by_default(self) -> bool {
        matches!(self, Self::Unavailable)
    }
}

impl fmt::Display for ErrorKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message())
    }
}

impl Serialize for ErrorKind {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for ErrorKind {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        // Deliberately infallible for any string. Refusing an unknown kind here
        // would turn every later addition into a session-killing parse failure
        // against an older peer, which is exactly what the open receiver rule
        // exists to prevent. `RpcError::validate` still rejects an unknown kind
        // that arrived with a code this revision does define.
        Ok(Self::from_wire(&String::deserialize(deserializer)?))
    }
}

/// Closed JSON-RPC `error.data` payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ErrorData {
    pub kind: ErrorKind,
    pub retryable: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_after_ms: Option<u64>,
}

/// A stable, redacted JSON-RPC error.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RpcError {
    pub code: i32,
    pub message: String,
    pub data: ErrorData,
}

impl RpcError {
    pub fn new(kind: ErrorKind) -> Self {
        Self {
            code: kind.code(),
            message: kind.message().to_string(),
            data: ErrorData {
                kind,
                retryable: kind.retryable_by_default(),
                retry_after_ms: None,
            },
        }
    }

    pub fn unavailable(retry_after_ms: Option<u64>) -> Self {
        let mut error = Self::new(ErrorKind::Unavailable);
        error.data.retry_after_ms = retry_after_ms;
        error
    }

    pub fn validate(&self) -> std::result::Result<(), &'static str> {
        if self.data.kind == ErrorKind::Unrecognized {
            // A code this revision defines must arrive with the kind that
            // belongs to it. Only a code it has never heard of may carry a kind
            // it has never heard of, which is what a later revision sends.
            if ErrorKind::from_code(self.code).is_some() {
                return Err("defined error code arrived with an undefined kind");
            }
        } else if self.code != self.data.kind.code() {
            return Err("error code does not match error kind");
        }
        if self.message.is_empty() || self.message.len() > 256 {
            return Err("error message has an invalid byte length");
        }
        if let Some(retry_after_ms) = self.data.retry_after_ms {
            // Allowed alongside an unrecognized kind because a later revision
            // may define another retryable one, and refusing it here would make
            // that addition unreachable.
            if !matches!(
                self.data.kind,
                ErrorKind::Unavailable | ErrorKind::Unrecognized
            ) {
                return Err("retry_after_ms is only valid for unavailable");
            }
            if retry_after_ms == 0 {
                return Err("retry_after_ms must be positive");
            }
        }
        Ok(())
    }
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("I/O error")]
    Io(#[from] std::io::Error),
    #[error("protocol error: {0}")]
    Protocol(&'static str),
    #[error("protocol error: {0}")]
    ProtocolOwned(String),
    #[error("remote {0:?}")]
    Remote(RpcError),
    #[error("request cancelled")]
    Cancelled,
    #[error("request deadline exceeded")]
    DeadlineExceeded,
    #[error("endpoint unavailable")]
    Unavailable,
    #[error("session is closed")]
    Closed,
}

impl Error {
    /// The closed RPC kind when the failure came from an accepted request.
    /// Transport and local protocol failures have no remote application kind.
    pub const fn rpc_kind(&self) -> Option<ErrorKind> {
        match self {
            Self::Remote(error) => Some(error.data.kind),
            Self::Cancelled => Some(ErrorKind::Cancelled),
            Self::DeadlineExceeded => Some(ErrorKind::DeadlineExceeded),
            Self::Unavailable => Some(ErrorKind::Unavailable),
            Self::Io(_) | Self::Protocol(_) | Self::ProtocolOwned(_) | Self::Closed => None,
        }
    }

    /// A non-secret local description suitable for an FFI error object.
    pub const fn stable_message(&self) -> &'static str {
        match self {
            Self::Io(_) => "I/O error",
            Self::Protocol(_) | Self::ProtocolOwned(_) => "protocol error",
            Self::Remote(_) => "remote error",
            Self::Cancelled => "cancelled",
            Self::DeadlineExceeded => "deadline exceeded",
            Self::Unavailable => "unavailable",
            Self::Closed => "session closed",
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rpc_kind_preserves_closed_remote_semantics() {
        for kind in [
            ErrorKind::InteractionRequired,
            ErrorKind::PermissionDenied,
            ErrorKind::Conflict,
            ErrorKind::Unavailable,
        ] {
            let error = if kind == ErrorKind::Unavailable {
                Error::Unavailable
            } else {
                Error::Remote(RpcError::new(kind))
            };
            assert_eq!(error.rpc_kind(), Some(kind));
            assert_eq!(kind.to_string(), kind.message());
            assert!(!kind.as_str().contains(' '));
        }
        assert_eq!(Error::Closed.rpc_kind(), None);
        assert_eq!(Error::Protocol("bad frame").rpc_kind(), None);
    }

    /// The rule that keeps the error set growable. A later revision naming a
    /// kind this one has never heard of must be decodable, or the first
    /// addition breaks every deployed peer and the set is frozen for the life
    /// of the protocol version.
    #[test]
    fn an_undefined_kind_decodes_instead_of_failing_the_frame() {
        let later: RpcError = serde_json::from_str(
            r#"{"code":-32011,"message":"dynamic session required",
                "data":{"kind":"dynamic_session_required","retryable":false}}"#,
        )
        .unwrap();
        assert_eq!(later.data.kind, ErrorKind::Unrecognized);
        later.validate().unwrap();
        // It is a failure, never a success, and never silently retryable.
        assert!(!later.data.kind.retryable_by_default());

        // A code this revision defines must still arrive with its own kind. A
        // peer that disagrees there is broken, not merely newer.
        let mismatched: RpcError = serde_json::from_str(
            r#"{"code":-32005,"message":"permission denied",
                "data":{"kind":"something_else","retryable":false}}"#,
        )
        .unwrap();
        assert_eq!(mismatched.data.kind, ErrorKind::Unrecognized);
        assert!(mismatched.validate().is_err());

        // Every defined kind still round-trips through its wire spelling.
        for kind in ErrorKind::DEFINED {
            assert_eq!(ErrorKind::from_wire(kind.as_str()), *kind);
            assert_eq!(ErrorKind::from_code(kind.code()), Some(*kind));
        }
        assert_eq!(ErrorKind::from_code(-32011), None);
    }

    #[test]
    fn retry_after_must_be_positive() {
        assert!(RpcError::unavailable(Some(1)).validate().is_ok());
        assert!(RpcError::unavailable(Some(0)).validate().is_err());
    }
}
