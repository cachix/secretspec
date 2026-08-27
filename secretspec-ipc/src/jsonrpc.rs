use crate::MAX_REQUEST_ID;
use crate::error::{Error, ErrorKind, Result, RpcError};
use serde::de::{DeserializeSeed, Error as _, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;
use std::collections::HashSet;
use std::fmt;

/// A positive, session-unique JSON request ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RequestId(u64);

impl RequestId {
    pub fn new(value: u64) -> Result<Self> {
        if value == 0 || value > MAX_REQUEST_ID {
            return Err(Error::Protocol("request ID is outside the version 1 range"));
        }
        Ok(Self(value))
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

impl Serialize for RequestId {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u64(self.0)
    }
}

impl<'de> Deserialize<'de> for RequestId {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = u64::deserialize(deserializer)?;
        if value == 0 || value > MAX_REQUEST_ID {
            return Err(D::Error::custom("invalid version 1 request ID"));
        }
        Ok(Self(value))
    }
}

/// The JSON-RPC version literal. A dedicated type prevents accepting another
/// string through otherwise valid derived structures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Version;

impl Serialize for Version {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str("2.0")
    }
}

impl<'de> Deserialize<'de> for Version {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        if value == "2.0" {
            Ok(Self)
        } else {
            Err(D::Error::custom("jsonrpc must be \"2.0\""))
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Meta {
    /// Mandatory absolute end-to-end deadline. Generic RPC metadata lives
    /// under this one reserved member instead of expanding the envelope.
    pub deadline_unix_ms: u64,
    /// A callback names the still-active request that caused it. Ordinary
    /// client-to-server requests omit this member.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_request_id: Option<RequestId>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub jsonrpc: Version,
    pub id: RequestId,
    pub method: String,
    #[serde(rename = "_meta")]
    pub meta: Meta,
    pub params: Value,
}

impl Request {
    pub fn new(
        id: RequestId,
        method: impl Into<String>,
        deadline_unix_ms: u64,
        params: Value,
    ) -> Result<Self> {
        let method = method.into();
        validate_method_and_params(&method, &params)?;
        Ok(Self {
            jsonrpc: Version,
            id,
            method,
            meta: Meta {
                deadline_unix_ms,
                parent_request_id: None,
            },
            params,
        })
    }

    pub const fn deadline_unix_ms(&self) -> u64 {
        self.meta.deadline_unix_ms
    }

    pub fn with_parent_request_id(mut self, parent_request_id: RequestId) -> Self {
        self.meta.parent_request_id = Some(parent_request_id);
        self
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Notification {
    pub jsonrpc: Version,
    pub method: String,
    pub params: Value,
}

impl Notification {
    pub fn new(method: impl Into<String>, params: Value) -> Result<Self> {
        let method = method.into();
        validate_method_and_params(&method, &params)?;
        Ok(Self {
            jsonrpc: Version,
            method,
            params,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SuccessResponse {
    pub jsonrpc: Version,
    pub id: RequestId,
    pub result: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ErrorResponse {
    pub jsonrpc: Version,
    #[serde(deserialize_with = "crate::protocol::deserialize_required_nullable")]
    pub id: Option<RequestId>,
    pub error: RpcError,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Response {
    Success(SuccessResponse),
    Error(ErrorResponse),
}

impl Response {
    pub fn success(id: RequestId, result: Value) -> Self {
        Self::Success(SuccessResponse {
            jsonrpc: Version,
            id,
            result,
        })
    }

    pub fn error(id: Option<RequestId>, error: RpcError) -> Self {
        Self::Error(ErrorResponse {
            jsonrpc: Version,
            id,
            error,
        })
    }

    pub const fn id(&self) -> Option<RequestId> {
        match self {
            Self::Success(response) => Some(response.id),
            Self::Error(response) => response.id,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(untagged)]
pub enum Envelope {
    Request(Request),
    Notification(Notification),
    Response(Response),
}

impl Envelope {
    /// Parse one strict JSON-RPC object, rejecting duplicate keys, non-objects,
    /// unknown envelope members, invalid IDs, and excessive nesting.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        Self::parse_classified(bytes).map_err(|(error, _)| error)
    }

    /// Parse, reporting the error kind the frame should be answered with.
    ///
    /// Malformed bytes yield `parse_error`; anything that parsed as JSON but
    /// broke a rule above it (duplicate keys, nesting depth, unknown members,
    /// invalid IDs, method and params shape) yields `invalid_request`. Callers
    /// that must answer with an error kind use this instead of re-parsing the
    /// frame with a laxer parser to guess which layer failed.
    pub fn parse_classified(bytes: &[u8]) -> std::result::Result<Self, (Error, ErrorKind)> {
        let value = parse_strict_value(bytes)?;
        Self::from_strict_value(value).map_err(|error| (error, ErrorKind::InvalidRequest))
    }

    fn from_strict_value(value: Value) -> Result<Self> {
        let object = value
            .as_object()
            .ok_or(Error::Protocol("JSON-RPC payload is not an object"))?;

        let envelope = if object.contains_key("method") && object.contains_key("id") {
            Self::Request(from_value(value)?)
        } else if object.contains_key("method") {
            Self::Notification(from_value(value)?)
        } else if object.contains_key("result") || object.contains_key("error") {
            let response: Response = from_value(value)?;
            if let Response::Error(error) = &response {
                error.error.validate().map_err(Error::Protocol)?;
            }
            Self::Response(response)
        } else {
            return Err(Error::Protocol("unrecognized JSON-RPC envelope"));
        };

        match &envelope {
            Self::Request(request) => {
                validate_method_and_params(&request.method, &request.params)?;
            }
            Self::Notification(notification) => {
                validate_method_and_params(&notification.method, &notification.params)?;
            }
            Self::Response(_) => {}
        }
        Ok(envelope)
    }

    pub fn to_vec(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(|error| Error::ProtocolOwned(error.to_string()))
    }
}

/// Borrows rather than consuming: parsing validates an already-built envelope,
/// and cloning `params` there duplicated the whole tree (up to a full frame,
/// including any secret it carries) only to be dropped again.
fn validate_method_and_params(method: &str, params: &Value) -> Result<()> {
    if method.is_empty() || method.len() > 256 {
        return Err(Error::Protocol("method has an invalid byte length"));
    }
    if !params.is_object() {
        return Err(Error::Protocol("params must be an object"));
    }
    Ok(())
}

fn from_value<T: for<'de> Deserialize<'de>>(value: Value) -> Result<T> {
    serde_json::from_value(value).map_err(|error| Error::ProtocolOwned(error.to_string()))
}

fn parse_strict_value(bytes: &[u8]) -> std::result::Result<Value, (Error, ErrorKind)> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let value = StrictValueSeed { depth: 0 }
        .deserialize(&mut deserializer)
        .map_err(classify_json_error)?;
    deserializer.end().map_err(classify_json_error)?;
    Ok(value)
}

/// Separates "this was not JSON" from "this was JSON we refuse".
///
/// `Syntax`/`Eof` mean the bytes are malformed, which is `parse_error`. `Data`
/// means the document parsed and one of the strict reader's own rules rejected
/// it (a duplicate key, or nesting past the limit); the peer sent well-formed
/// JSON, so that stays `invalid_request`. Reading the category off the existing
/// failure avoids re-parsing the frame just to tell the two apart.
fn classify_json_error(error: serde_json::Error) -> (Error, ErrorKind) {
    let kind = match error.classify() {
        serde_json::error::Category::Data => ErrorKind::InvalidRequest,
        _ => ErrorKind::ParseError,
    };
    (Error::ProtocolOwned(error.to_string()), kind)
}

const MAX_NESTING: usize = 64;

struct StrictValueSeed {
    depth: usize,
}

impl<'de> DeserializeSeed<'de> for StrictValueSeed {
    type Value = Value;

    fn deserialize<D>(self, deserializer: D) -> std::result::Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(StrictValueVisitor { depth: self.depth })
    }
}

struct StrictValueVisitor {
    depth: usize,
}

impl StrictValueVisitor {
    fn child<E: serde::de::Error>(&self) -> std::result::Result<StrictValueSeed, E> {
        if self.depth >= MAX_NESTING {
            Err(E::custom("JSON nesting exceeds 64 containers"))
        } else {
            Ok(StrictValueSeed {
                depth: self.depth + 1,
            })
        }
    }
}

impl<'de> Visitor<'de> for StrictValueVisitor {
    type Value = Value;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("an RFC 8259 JSON value without duplicate object keys")
    }

    fn visit_bool<E>(self, value: bool) -> std::result::Result<Self::Value, E> {
        Ok(Value::Bool(value))
    }

    fn visit_i64<E>(self, value: i64) -> std::result::Result<Self::Value, E> {
        Ok(Value::Number(value.into()))
    }

    fn visit_u64<E>(self, value: u64) -> std::result::Result<Self::Value, E> {
        Ok(Value::Number(value.into()))
    }

    fn visit_f64<E>(self, value: f64) -> std::result::Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        serde_json::Number::from_f64(value)
            .map(Value::Number)
            .ok_or_else(|| E::custom("non-finite JSON number"))
    }

    fn visit_str<E>(self, value: &str) -> std::result::Result<Self::Value, E> {
        Ok(Value::String(value.to_string()))
    }

    fn visit_string<E>(self, value: String) -> std::result::Result<Self::Value, E> {
        Ok(Value::String(value))
    }

    fn visit_none<E>(self) -> std::result::Result<Self::Value, E> {
        Ok(Value::Null)
    }

    fn visit_unit<E>(self) -> std::result::Result<Self::Value, E> {
        Ok(Value::Null)
    }

    fn visit_some<D>(self, deserializer: D) -> std::result::Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        StrictValueSeed { depth: self.depth }.deserialize(deserializer)
    }

    fn visit_seq<A>(self, mut sequence: A) -> std::result::Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element_seed(self.child()?)? {
            values.push(value);
        }
        Ok(Value::Array(values))
    }

    fn visit_map<A>(self, mut map: A) -> std::result::Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = serde_json::Map::new();
        let mut keys = HashSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if !keys.insert(key.clone()) {
                return Err(A::Error::custom("duplicate JSON object key"));
            }
            let value = map.next_value_seed(self.child()?)?;
            values.insert(key, value);
        }
        Ok(Value::Object(values))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejection_reports_the_layer_that_refused_the_frame() {
        // Only malformed bytes are `parse_error`. Everything that parsed as
        // JSON is `invalid_request`, however far up it was rejected. Pinned
        // because this is peer-visible and the classification is now read off
        // the parse failure rather than recovered by re-parsing the frame.
        for payload in [
            br#"{"jsonrpc":"2.0",}"#.as_slice(),
            br#"{"jsonrpc":"2.0""#.as_slice(),
            b"\xff\xfe".as_slice(),
        ] {
            let (_, kind) = Envelope::parse_classified(payload).unwrap_err();
            assert_eq!(kind, ErrorKind::ParseError, "{payload:?}");
        }

        let deep = format!("{}{}", "[".repeat(80), "]".repeat(80));
        for payload in [
            // Well-formed JSON the strict reader refuses on its own rules.
            br#"{"jsonrpc":"2.0","jsonrpc":"2.0"}"#.as_slice(),
            deep.as_bytes(),
            // A batch array parses as JSON; JSON-RPC 2.0 answers an array with
            // invalid_request rather than parse_error.
            br#"[]"#.as_slice(),
            // Envelope-layer rejections.
            br#"{"jsonrpc":"2.0","id":0,"method":"x","_meta":{"deadline_unix_ms":1},"params":{}}"#
                .as_slice(),
            br#"{"jsonrpc":"2.0","id":1,"method":"","_meta":{"deadline_unix_ms":1},"params":{}}"#
                .as_slice(),
            br#"{"jsonrpc":"2.0","id":1,"method":"x","_meta":{"deadline_unix_ms":1},"params":[]}"#
                .as_slice(),
            br#"{"jsonrpc":"2.0"}"#.as_slice(),
        ] {
            let (_, kind) = Envelope::parse_classified(payload).unwrap_err();
            assert_eq!(kind, ErrorKind::InvalidRequest, "{payload:?}");
        }
    }

    #[test]
    fn rejects_duplicate_keys_and_batches() {
        assert!(
            Envelope::parse(
                br#"{"jsonrpc":"2.0","jsonrpc":"2.0","id":1,"method":"x","_meta":{"deadline_unix_ms":1},"params":{}}"#
            )
            .is_err()
        );
        assert!(Envelope::parse(br#"[]"#).is_err());
    }

    #[test]
    fn request_ids_are_bounded_integers() {
        for id in ["0", "-1", "1.5", "\"1\"", "9007199254740992"] {
            let input = format!(
                r#"{{"jsonrpc":"2.0","id":{id},"method":"x","_meta":{{"deadline_unix_ms":1}},"params":{{}}}}"#
            );
            assert!(Envelope::parse(input.as_bytes()).is_err(), "accepted {id}");
        }
    }

    #[test]
    fn rejects_unknown_top_level_members() {
        assert!(
            Envelope::parse(
                br#"{"jsonrpc":"2.0","id":1,"method":"x","_meta":{"deadline_unix_ms":1},"params":{},"extra":true}"#
            )
                .is_err()
        );
        assert!(Envelope::parse(br#"{"jsonrpc":"2.0","id":1,"result":{},"extra":true}"#).is_err());
        assert!(
            Envelope::parse(
                br#"{"jsonrpc":"2.0","id":1,"result":{},"error":{"code":-32603,"message":"internal error","data":{"kind":"internal","retryable":false}}}"#
            )
            .is_err()
        );
    }

    #[test]
    fn request_deadline_is_required_and_round_trips() {
        assert!(Envelope::parse(br#"{"jsonrpc":"2.0","id":1,"method":"x","params":{}}"#).is_err());
        let parsed = Envelope::parse(
            br#"{"jsonrpc":"2.0","id":1,"method":"x","_meta":{"deadline_unix_ms":42},"params":{}}"#,
        )
        .unwrap();
        let Envelope::Request(request) = parsed else {
            panic!("expected request")
        };
        assert_eq!(request.deadline_unix_ms(), 42);
    }

    #[test]
    fn error_response_requires_an_explicit_nullable_id() {
        assert!(
            Envelope::parse(
                br#"{"jsonrpc":"2.0","error":{"code":-32700,"message":"parse error","data":{"kind":"parse_error","retryable":false}}}"#
            )
            .is_err()
        );
        assert!(
            Envelope::parse(
                br#"{"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"parse error","data":{"kind":"parse_error","retryable":false}}}"#
            )
            .is_ok()
        );
    }
}
