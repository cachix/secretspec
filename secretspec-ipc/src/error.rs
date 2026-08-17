use serde::{Deserialize, Serialize};
use std::fmt;
use thiserror::Error;

/// Stable machine-readable error kinds shared by both application protocols.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
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
        }
    }

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
        if self.code != self.data.kind.code() {
            return Err("error code does not match error kind");
        }
        if self.message.is_empty() || self.message.len() > 256 {
            return Err("error message has an invalid byte length");
        }
        if let Some(retry_after_ms) = self.data.retry_after_ms {
            if self.data.kind != ErrorKind::Unavailable {
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

    #[test]
    fn retry_after_must_be_positive() {
        assert!(RpcError::unavailable(Some(1)).validate().is_ok());
        assert!(RpcError::unavailable(Some(0)).validate().is_err());
    }
}
