use crate::error::{Error, Result};
use crate::{ABSOLUTE_MAX_FRAME_BYTES, MAX_IN_FLIGHT, MIN_FRAME_BYTES};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub const RESOLVER_PROTOCOL: &str = "secretspec.resolver";
pub const PROVIDER_PROTOCOL: &str = "secretspec.provider";
pub const PROTOCOL_VERSION: u32 = 1;

pub mod rpc {
    pub const INITIALIZE: &str = "rpc.initialize";
    pub const CANCEL: &str = "rpc.cancel";
    pub const SHUTDOWN: &str = "rpc.shutdown";
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Product {
    pub name: String,
    pub version: String,
}

impl Product {
    pub fn validate(&self) -> Result<()> {
        validate_nonempty_bytes("product name", &self.name, 256)?;
        validate_nonempty_bytes("product version", &self.version, 256)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    pub max_frame_bytes: usize,
    pub max_in_flight: usize,
}

impl Limits {
    pub const PRE_NEGOTIATION: Self = Self {
        max_frame_bytes: ABSOLUTE_MAX_FRAME_BYTES,
        max_in_flight: 1,
    };

    pub fn validate(self) -> Result<()> {
        if !(MIN_FRAME_BYTES..=ABSOLUTE_MAX_FRAME_BYTES).contains(&self.max_frame_bytes) {
            return Err(Error::Protocol(
                "max_frame_bytes is outside the version 1 range",
            ));
        }
        if !(1..=MAX_IN_FLIGHT).contains(&self.max_in_flight) {
            return Err(Error::Protocol(
                "max_in_flight is outside the version 1 range",
            ));
        }
        Ok(())
    }

    pub fn select(self, peer: Self) -> Result<Self> {
        self.validate()?;
        peer.validate()?;
        Ok(Self {
            max_frame_bytes: self.max_frame_bytes.min(peer.max_frame_bytes),
            max_in_flight: self.max_in_flight.min(peer.max_in_flight),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InitializeParams<A> {
    pub protocol: String,
    pub versions: Vec<u32>,
    pub client: Product,
    pub limits: Limits,
    /// Methods this client can answer when the server calls back on the same
    /// session (0.20+). Empty, and omitted on the wire, for a client that
    /// answers none, which is every client before this field existed.
    ///
    /// The server's `methods` say what a client may ask for. These say
    /// what the server may ask of the client, and a server MUST NOT send a
    /// method that is not listed here. A consumer with no way to reach a person
    /// therefore advertises nothing and is told so immediately, rather than
    /// waiting out a deadline on an interaction that was never going to arrive.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub client_methods: Vec<String>,
    pub application: A,
}

impl<A> InitializeParams<A> {
    pub fn validate_common(&self, expected_protocol: &str) -> Result<()> {
        if self.protocol != expected_protocol {
            return Err(Error::Protocol(
                "initialization selected the wrong protocol",
            ));
        }
        if self.versions.is_empty()
            || self.versions.contains(&0)
            || self.versions.iter().collect::<BTreeSet<_>>().len() != self.versions.len()
        {
            return Err(Error::Protocol(
                "versions must be distinct positive integers",
            ));
        }
        self.client.validate()?;
        self.limits.validate()?;
        validate_capabilities(&self.client_methods)?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InitializeResult<A> {
    pub protocol: String,
    pub version: u32,
    pub server: Product,
    pub methods: Vec<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub capabilities: BTreeMap<String, bool>,
    pub limits: Limits,
    pub application: A,
}

impl<A> InitializeResult<A> {
    pub fn validate_common(
        &self,
        expected_protocol: &str,
        offered_versions: &[u32],
        offered_limits: Limits,
    ) -> Result<()> {
        if self.protocol != expected_protocol || !offered_versions.contains(&self.version) {
            return Err(Error::Protocol(
                "server selected an unsupported protocol version",
            ));
        }
        self.server.validate()?;
        validate_capabilities(&self.methods)?;
        validate_feature_capabilities(&self.capabilities)?;
        self.limits.validate()?;
        if self.limits.max_frame_bytes > offered_limits.max_frame_bytes
            || self.limits.max_in_flight > offered_limits.max_in_flight
        {
            return Err(Error::Protocol("server selected an unoffered limit"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CancelParams {
    pub id: crate::RequestId,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EmptyParams {}

/// Methods a server calls back on the client over the same session (0.20+).
///
/// This is the only direction reversal in version 1, and it exists because the
/// endpoint that knows a value is missing is never the process that can ask a
/// person for it. A stdio resolver has no terminal at all: its stdin and stdout
/// are the protocol. Prior art solves this the same way, from D-Bus Secret
/// Service returning a prompt object the client must drive, to the editor
/// protocols whose servers request input rather than drawing it.
///
/// A server MUST NOT send one of these unless the client advertised it in
/// [`InitializeParams::client_methods`].
pub mod callback {
    pub mod method {
        /// Ask the client to obtain one secret value from a person (0.20+).
        pub const PROMPT: &str = "client.prompt";

        pub const ALL: &[&str] = &[PROMPT];
    }

    use super::*;

    /// Everything the person answering needs, and nothing else.
    ///
    /// There is no free-form message: the text a client shows is built by the
    /// client from these fields, so a server cannot use the prompt to put
    /// arbitrary attacker-influenced text in front of a person. The declared
    /// name and the credential-free provider URI are already known to the
    /// session that asked.
    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct PromptParams {
        /// The declared name whose value is being asked for.
        pub name: String,
        /// The active profile, so a person answering can tell which one they
        /// are provisioning.
        pub profile: String,
        /// Credential-free display URI of the provider that will store the
        /// answer, or absent when the answer is not persisted.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub target_provider: Option<String>,
    }

    impl PromptParams {
        pub fn validate(&self) -> Result<()> {
            validate_nonempty_bytes("secret name has an invalid byte length", &self.name, 4096)?;
            validate_nonempty_bytes("profile has an invalid byte length", &self.profile, 4096)?;
            validate_optional_bytes(
                "target provider has an invalid byte length",
                self.target_provider.as_deref(),
                32768,
            )
        }
    }

    /// The answer carries a secret and is treated exactly like a resolved
    /// value: never logged, and dropped as soon as it is copied.
    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct PromptResult {
        pub value: String,
    }

    impl PromptResult {
        pub fn validate(&self) -> Result<()> {
            // An empty answer is refused for the same reason `resolver.set`
            // refuses an empty value: stores disagree about whether one means
            // absent or present-and-empty. A person who wants to decline
            // cancels instead.
            validate_nonempty_bytes(
                "prompt answer has an invalid byte length",
                &self.value,
                ABSOLUTE_MAX_FRAME_BYTES,
            )
        }
    }
}

pub(crate) fn validate_capabilities(capabilities: &[String]) -> Result<()> {
    if capabilities.iter().collect::<BTreeSet<_>>().len() != capabilities.len() {
        return Err(Error::Protocol("capabilities must be distinct"));
    }
    for capability in capabilities {
        validate_nonempty_bytes("capability", capability, 256)?;
    }
    Ok(())
}

pub(crate) fn validate_feature_capabilities(capabilities: &BTreeMap<String, bool>) -> Result<()> {
    for capability in capabilities.keys() {
        validate_nonempty_bytes("capability", capability, 256)?;
    }
    Ok(())
}

pub(crate) fn validate_nonempty_bytes(label: &'static str, value: &str, max: usize) -> Result<()> {
    if value.is_empty() || value.len() > max {
        Err(Error::Protocol(label))
    } else {
        Ok(())
    }
}

pub(crate) fn validate_optional_bytes(
    label: &'static str,
    value: Option<&str>,
    max: usize,
) -> Result<()> {
    if value.is_some_and(|value| value.len() > max) {
        Err(Error::Protocol(label))
    } else {
        Ok(())
    }
}

pub(crate) fn deserialize_required_nullable<'de, D, T>(
    deserializer: D,
) -> std::result::Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}

pub mod resolver {
    use super::*;

    pub mod method {
        pub const GET: &str = "resolver.get";
        pub const RELEASE: &str = "resolver.release";
        /// Report that a resolved value was refused by its consumer (0.20+).
        pub const REJECT: &str = "resolver.reject";
        /// Store one declared name (0.20+).
        pub const SET: &str = "resolver.set";
        /// Remove one declared name's stored value (0.20+).
        pub const DELETE: &str = "resolver.delete";

        /// Every method version 1 defines. What an endpoint advertises is a
        /// subset of this: see [`super::CAPABILITIES`] and
        /// [`super::MUTATION_CAPABILITIES`].
        pub const ALL: &[&str] = &[GET, RELEASE, REJECT, SET, DELETE];
    }

    /// Methods every version 1 endpoint answers. A client that negotiates a
    /// session without all of them is talking to something that is not a
    /// resolver, so it refuses the endpoint rather than degrading.
    ///
    /// `reject` is required rather than optional because it is how a cached
    /// value that was revoked before it expired gets discarded. An endpoint
    /// that cannot be told its cache is wrong serves the dead value until the
    /// entry ages out, and a read-only consumer has no other way to recover:
    /// that is exactly the case the method exists for.
    pub const CAPABILITIES: &[&str] = &[method::GET, method::RELEASE, method::REJECT];

    /// Methods that write to the store (0.20+).
    ///
    /// These are optional and separately advertised: resolution is the reason
    /// the protocol exists, while storage is authority a consumer usually does
    /// not need. An endpoint serving a read-only consumer, or one an operator
    /// started read-only, advertises none of them, and the client will not send
    /// a method that was not advertised.
    pub const MUTATION_CAPABILITIES: &[&str] = &[method::SET, method::DELETE];

    /// Rejects a capability list that no version 1 endpoint could honor.
    ///
    /// Only the base methods are required. Nothing here constrains the
    /// mutation methods against each other: an endpoint that can store but not
    /// remove is a store that only appends, which is a real backend and not a
    /// malformed advertisement.
    pub fn validate_capabilities(capabilities: &[String]) -> Result<()> {
        if !CAPABILITIES
            .iter()
            .all(|method| capabilities.iter().any(|item| item == method))
        {
            return Err(Error::Protocol(
                "resolver capability set omits a required method",
            ));
        }
        Ok(())
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
    pub enum Manifest {
        Path { path: String },
        Inline { toml: String, base_dir: String },
    }

    impl Manifest {
        pub fn validate(&self) -> Result<()> {
            match self {
                Self::Path { path } => validate_absolute_path(path),
                Self::Inline { toml, base_dir } => {
                    if toml.len() > ABSOLUTE_MAX_FRAME_BYTES {
                        return Err(Error::Protocol("inline manifest is too large"));
                    }
                    validate_absolute_path(base_dir)
                }
            }
        }

        pub const fn kind(&self) -> &'static str {
            match self {
                Self::Path { .. } => "path",
                Self::Inline { .. } => "inline",
            }
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct InitializeApplication {
        pub manifest: Manifest,
        #[serde(deserialize_with = "deserialize_required_nullable")]
        pub provider: Option<String>,
        #[serde(deserialize_with = "deserialize_required_nullable")]
        pub profile: Option<String>,
        #[serde(deserialize_with = "deserialize_required_nullable")]
        pub scope: Option<String>,
        #[serde(deserialize_with = "deserialize_required_nullable")]
        pub reason: Option<String>,
    }

    impl InitializeApplication {
        pub fn validate(&self) -> Result<()> {
            self.manifest.validate()?;
            validate_optional_bytes(
                "provider override is too long",
                self.provider.as_deref(),
                32768,
            )?;
            validate_optional_bytes("profile is too long", self.profile.as_deref(), 4096)?;
            validate_optional_bytes("scope is too long", self.scope.as_deref(), 4096)?;
            validate_optional_bytes("reason is too long", self.reason.as_deref(), 4096)
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct InitializedApplication {
        pub manifest_kind: String,
        pub supports_inline_manifest: bool,
    }

    impl InitializedApplication {
        pub fn validate(&self) -> Result<()> {
            if matches!(self.manifest_kind.as_str(), "path" | "inline") {
                Ok(())
            } else {
                Err(Error::Protocol("invalid initialized manifest kind"))
            }
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
    #[serde(rename_all = "snake_case")]
    /// Which shape of value the caller can accept.
    ///
    /// Both spellings describe what the returned string contains: the secret
    /// itself, or a location to read it from. The file the resolver writes for
    /// the `Path` form is how that location is produced, not something the
    /// caller selects, which is why it does not appear here.
    pub enum Representation {
        Auto,
        Value,
        Path,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Purpose {
        pub consumer: String,
        pub operation: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub host: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub path: Option<String>,
    }

    impl Purpose {
        pub fn validate(&self) -> Result<()> {
            validate_nonempty_bytes(
                "purpose consumer has an invalid byte length",
                &self.consumer,
                256,
            )?;
            validate_nonempty_bytes(
                "purpose operation has an invalid byte length",
                &self.operation,
                256,
            )?;
            validate_optional_bytes("purpose host is too long", self.host.as_deref(), 4096)?;
            validate_optional_bytes("purpose path is too long", self.path.as_deref(), 4096)
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct GetParams {
        pub name: String,
        pub representation: Representation,
        pub purpose: Purpose,
    }

    impl GetParams {
        pub fn validate(&self) -> Result<()> {
            validate_nonempty_bytes("secret name has an invalid byte length", &self.name, 4096)?;
            self.purpose.validate()
        }
    }

    /// Where a resolved value came from.
    ///
    /// Provenance, not an authorization input. The set is closed for the
    /// resolver and open for the client, under the same rule as
    /// [`crate::error::ErrorKind`]: a later revision naming a new origin, such
    /// as a dynamically issued credential, must not kill a session with an
    /// older client. A client that treats provenance as security-relevant reads
    /// [`Source::Unrecognized`] as "not one of the origins I can vouch for" and
    /// decides accordingly, which it could not do if the frame failed to parse.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum Source {
        Provider,
        Generated,
        Default,
        Composed,
        /// An origin this revision does not define. A resolver never sends it.
        Unrecognized,
    }

    impl Source {
        pub const fn as_str(self) -> &'static str {
            match self {
                Self::Provider => "provider",
                Self::Generated => "generated",
                Self::Default => "default",
                Self::Composed => "composed",
                Self::Unrecognized => "unrecognized",
            }
        }

        pub const DEFINED: &'static [Self] = &[
            Self::Provider,
            Self::Generated,
            Self::Default,
            Self::Composed,
        ];

        pub fn from_wire(source: &str) -> Self {
            Self::DEFINED
                .iter()
                .copied()
                .find(|defined| defined.as_str() == source)
                .unwrap_or(Self::Unrecognized)
        }
    }

    impl Serialize for Source {
        fn serialize<S: serde::Serializer>(
            &self,
            serializer: S,
        ) -> std::result::Result<S::Ok, S::Error> {
            serializer.serialize_str(self.as_str())
        }
    }

    impl<'de> Deserialize<'de> for Source {
        fn deserialize<D: serde::Deserializer<'de>>(
            deserializer: D,
        ) -> std::result::Result<Self, D::Error> {
            Ok(Self::from_wire(&String::deserialize(deserializer)?))
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct UndeclaredResult {
        pub status: UndeclaredStatus,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(rename_all = "snake_case")]
    pub enum UndeclaredStatus {
        Undeclared,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct MissingResult {
        pub status: MissingStatus,
        pub required: bool,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(rename_all = "snake_case")]
    pub enum MissingStatus {
        Missing,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct ResolvedValueResult {
        pub status: ResolvedStatus,
        pub representation: ValueRepresentation,
        pub value: String,
        pub source: Source,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub source_provider: Option<String>,
        #[serde(deserialize_with = "deserialize_required_nullable")]
        pub expires_at_unix_ms: Option<u64>,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct ResolvedPathResult {
        pub status: ResolvedStatus,
        pub representation: PathRepresentation,
        pub path: String,
        /// Releases the resolver-owned file behind [`Self::path`]. Named apart
        /// from a provider credential lease, which is an unrelated concept
        /// with its own issuance and revocation.
        pub path_lease_id: String,
        pub source: Source,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub source_provider: Option<String>,
        #[serde(deserialize_with = "deserialize_required_nullable")]
        pub expires_at_unix_ms: Option<u64>,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(rename_all = "snake_case")]
    pub enum ResolvedStatus {
        Resolved,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(rename_all = "snake_case")]
    pub enum ValueRepresentation {
        Value,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(rename_all = "snake_case")]
    pub enum PathRepresentation {
        Path,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(untagged)]
    pub enum GetResult {
        Undeclared(UndeclaredResult),
        Missing(MissingResult),
        Value(ResolvedValueResult),
        Path(ResolvedPathResult),
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct RejectParams {
        pub name: String,
        pub purpose: Purpose,
    }

    impl RejectParams {
        pub fn validate(&self) -> Result<()> {
            validate_nonempty_bytes("secret name has an invalid byte length", &self.name, 4096)?;
            self.purpose.validate()
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(rename_all = "snake_case")]
    pub enum RejectedStatus {
        Rejected,
    }

    /// Reject always succeeds. The caller is reporting what already happened to
    /// it, not asking for an operation that could be refused, and every reason
    /// there was nothing to discard — no cached copy, no cached route, a name
    /// this session cannot see — leaves the resolver in the state the caller
    /// wants. Reporting those apart would also make a scope disclose the names
    /// it hides, which is the same reason a hidden name reads as `undeclared`.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
    pub struct RejectResult {
        pub status: RejectedStatus,
        /// `true` when a cached copy was discarded. `false` means there was
        /// nothing to discard, which is also a success.
        pub invalidated: bool,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct SetParams {
        pub name: String,
        pub value: String,
        pub purpose: Purpose,
    }

    impl SetParams {
        pub fn validate(&self) -> Result<()> {
            validate_nonempty_bytes("secret name has an invalid byte length", &self.name, 4096)?;
            // An empty value means "no value" to some stores and "a value that
            // happens to be empty" to others, and the difference decides
            // whether a later read finds the secret. It never travels as a
            // write; a caller that wants the value gone sends `resolver.delete`.
            validate_nonempty_bytes(
                "secret value has an invalid byte length",
                &self.value,
                ABSOLUTE_MAX_FRAME_BYTES,
            )?;
            self.purpose.validate()
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(rename_all = "snake_case")]
    pub enum StoredStatus {
        Stored,
    }

    /// A write is either accepted or refused, so there is one shape here where
    /// a read has four. A name the manifest does not declare has no address to
    /// write to, and unlike an absent value it is not something the caller can
    /// route around, so it is an error rather than a status.
    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct SetResult {
        pub status: StoredStatus,
        /// Credential-free URI of the provider that took the write, for a
        /// consumer that reports the destination back to a human. Absent when
        /// the endpoint does not name it.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub target_provider: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct DeleteParams {
        pub name: String,
        pub purpose: Purpose,
    }

    impl DeleteParams {
        pub fn validate(&self) -> Result<()> {
            validate_nonempty_bytes("secret name has an invalid byte length", &self.name, 4096)?;
            self.purpose.validate()
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(rename_all = "snake_case")]
    pub enum DeletedStatus {
        Deleted,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct DeleteResult {
        pub status: DeletedStatus,
        /// `false` when the store held nothing for this name. Removal is
        /// idempotent, so that is a success and not an error.
        pub deleted: bool,
        /// Credential-free URI of the provider the removal was addressed to.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub target_provider: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct ReleaseParams {
        pub path_lease_ids: Vec<String>,
    }

    impl ReleaseParams {
        pub fn validate(&self) -> Result<()> {
            if self.path_lease_ids.len() > 256 {
                return Err(Error::Protocol("release contains more than 256 lease IDs"));
            }
            for lease in &self.path_lease_ids {
                validate_nonempty_bytes("lease ID has an invalid byte length", lease, 256)?;
            }
            Ok(())
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
    pub struct ReleaseResult {
        pub released: usize,
    }

    fn validate_absolute_path(path: &str) -> Result<()> {
        validate_nonempty_bytes("path has an invalid byte length", path, 32768)?;
        let path = std::path::Path::new(path);
        if !path.is_absolute()
            || path.components().any(|component| {
                matches!(
                    component,
                    std::path::Component::CurDir | std::path::Component::ParentDir
                )
            })
        {
            return Err(Error::Protocol(
                "manifest path must be absolute and lexically normalized",
            ));
        }
        Ok(())
    }
}

pub mod provider {
    use super::*;

    pub mod method {
        use super::*;
        use serde::de::DeserializeOwned;

        /// Associates one provider method with its wire parameter and result
        /// types so callers cannot accidentally deserialize a method into the
        /// wrong response shape.
        pub trait Method {
            const NAME: &'static str;
            type Params: Serialize;
            type Result: DeserializeOwned;
        }

        macro_rules! methods {
            ($(($type:ident, $constant:ident, $name:literal, $params:ty, $result:ty)),+ $(,)?) => {
                $(
                    pub const $constant: &str = $name;

                    #[derive(Debug, Clone, Copy)]
                    pub struct $type;

                    impl Method for $type {
                        const NAME: &'static str = $constant;
                        type Params = $params;
                        type Result = $result;
                    }
                )+

                pub const ALL: &[&str] = &[$($constant),+];
            };
        }

        methods!(
            (
                ResolveAddress,
                RESOLVE_ADDRESS,
                "provider.resolve_address",
                AddressParams,
                ResolveAddressResult
            ),
            (Get, GET, "provider.get", AddressParams, GetResult),
            (
                GetMany,
                GET_MANY,
                "provider.get_many",
                GetManyParams,
                GetManyResult
            ),
            (
                Exists,
                EXISTS,
                "provider.exists",
                AddressParams,
                ExistsResult
            ),
            (Set, SET, "provider.set", SetParams, StoredResult),
            (
                SetExpiring,
                SET_EXPIRING,
                "provider.set_expiring",
                SetExpiringParams,
                StoredResult
            ),
            (
                Delete,
                DELETE,
                "provider.delete",
                AddressParams,
                DeletedResult
            ),
            (Clear, CLEAR, "provider.clear", ClearParams, ClearResult),
            (
                CheckWritable,
                CHECK_WRITABLE,
                "provider.check_writable",
                AddressParams,
                EmptyResult
            ),
            (
                CheckDeletable,
                CHECK_DELETABLE,
                "provider.check_deletable",
                AddressParams,
                EmptyResult
            ),
            (
                DescribeWriteTarget,
                DESCRIBE_WRITE_TARGET,
                "provider.describe_write_target",
                AddressParams,
                DescribeWriteTargetResult
            ),
            (
                Reflect,
                REFLECT,
                "provider.reflect",
                ReflectParams,
                ReflectResult
            ),
        );
    }

    pub const CAPABILITIES: &[&str] = method::ALL;

    pub fn validate_capabilities(capabilities: &[String]) -> Result<()> {
        let has = |method: &str| capabilities.iter().any(|item| item == method);
        if !has(method::RESOLVE_ADDRESS)
            || ![method::GET, method::EXISTS, method::SET]
                .iter()
                .any(|method| has(method))
            || (has(method::GET_MANY) && !has(method::GET))
            || (has(method::SET_EXPIRING) && !has(method::SET))
        {
            return Err(Error::Protocol(
                "provider capability set violates version 1 dependencies",
            ));
        }
        Ok(())
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct InitializeApplication {
        pub scheme: String,
        pub uri: String,
        #[serde(deserialize_with = "deserialize_required_nullable")]
        pub base_dir: Option<String>,
        pub credentials: BTreeMap<String, String>,
        #[serde(deserialize_with = "deserialize_required_nullable")]
        pub reason: Option<String>,
    }

    impl InitializeApplication {
        pub fn validate(&self) -> Result<()> {
            validate_scheme(&self.scheme)?;
            validate_nonempty_bytes("provider URI has an invalid byte length", &self.uri, 32768)?;
            validate_optional_bytes(
                "provider base directory is too long",
                self.base_dir.as_deref(),
                32768,
            )?;
            validate_optional_bytes("provider reason is too long", self.reason.as_deref(), 4096)?;
            if let Some(base_dir) = &self.base_dir
                && !std::path::Path::new(base_dir).is_absolute()
            {
                return Err(Error::Protocol("provider base directory must be absolute"));
            }
            for name in self.credentials.keys() {
                validate_semantic_name(name)?;
            }
            let uri_scheme = self.uri.split_once(':').map(|(scheme, _)| scheme);
            if uri_scheme != Some(self.scheme.as_str()) {
                return Err(Error::Protocol(
                    "provider URI scheme does not match initialization scheme",
                ));
            }
            Ok(())
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
    #[serde(rename_all = "snake_case")]
    pub enum CoordinateName {
        Field,
        Vault,
        Section,
        Version,
    }

    impl CoordinateName {
        pub const fn as_str(self) -> &'static str {
            match self {
                Self::Field => "field",
                Self::Vault => "vault",
                Self::Section => "section",
                Self::Version => "version",
            }
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(rename_all = "snake_case")]
    pub enum Persistence {
        Persist,
        Ephemeral,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Metadata {
        pub name: String,
        pub display_uri: String,
        pub supported_coordinates: Vec<CoordinateName>,
        pub generated_value_persistence: Persistence,
        pub prompted_value_persistence: Persistence,
        pub storage_identity: String,
        pub entry_container_identity: String,
        #[serde(deserialize_with = "deserialize_required_nullable")]
        pub physical_store_path: Option<String>,
    }

    impl Metadata {
        pub fn validate(&self) -> Result<()> {
            validate_scheme(&self.name)?;
            for value in [
                &self.display_uri,
                &self.storage_identity,
                &self.entry_container_identity,
            ] {
                if value.len() > 32768 {
                    return Err(Error::Protocol("provider metadata is too long"));
                }
            }
            if self
                .supported_coordinates
                .iter()
                .collect::<BTreeSet<_>>()
                .len()
                != self.supported_coordinates.len()
            {
                return Err(Error::Protocol("supported coordinates must be distinct"));
            }
            if let Some(path) = &self.physical_store_path
                && !std::path::Path::new(path).is_absolute()
            {
                return Err(Error::Protocol("physical_store_path must be absolute"));
            }
            Ok(())
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct InitializedApplication {
        pub provider: Metadata,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Coordinates {
        pub item: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub field: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub vault: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub section: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub version: Option<String>,
    }

    impl Coordinates {
        pub fn validate(&self) -> Result<()> {
            validate_nonempty_bytes("item has an invalid byte length", &self.item, 4096)?;
            for value in [&self.field, &self.vault, &self.section, &self.version] {
                validate_optional_bytes("coordinate is too long", value.as_deref(), 4096)?;
            }
            Ok(())
        }

        pub fn unsupported(&self, supported: &[CoordinateName]) -> Option<CoordinateName> {
            [
                (CoordinateName::Field, self.field.is_some()),
                (CoordinateName::Vault, self.vault.is_some()),
                (CoordinateName::Section, self.section.is_some()),
                (CoordinateName::Version, self.version.is_some()),
            ]
            .into_iter()
            .find_map(|(name, present)| (present && !supported.contains(&name)).then_some(name))
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
    #[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
    pub enum Address {
        Convention {
            project: String,
            profile: String,
            key: String,
        },
        Native {
            coordinates: Coordinates,
        },
    }

    impl Address {
        pub fn validate(&self) -> Result<()> {
            match self {
                Self::Convention {
                    project,
                    profile,
                    key,
                } => {
                    for value in [project, profile, key] {
                        if value.len() > 4096 {
                            return Err(Error::Protocol(
                                "convention address component is too long",
                            ));
                        }
                    }
                    Ok(())
                }
                Self::Native { coordinates } => coordinates.validate(),
            }
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct AddressParams {
        pub address: Address,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct ResolveAddressResult {
        pub coordinates: Coordinates,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(tag = "status", rename_all = "snake_case")]
    pub enum GetResult {
        Found { value: String },
        Missing,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct NamedRequest {
        pub name: String,
        pub address: Address,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct GetManyParams {
        pub requests: Vec<NamedRequest>,
    }

    impl GetManyParams {
        pub fn validate(&self) -> Result<()> {
            if self.requests.len() > 1024 {
                return Err(Error::Protocol("get_many contains more than 1024 requests"));
            }
            let mut names = BTreeSet::new();
            for request in &self.requests {
                validate_nonempty_bytes(
                    "batch name has an invalid byte length",
                    &request.name,
                    4096,
                )?;
                if !names.insert(&request.name) {
                    return Err(Error::Protocol("batch names must be unique"));
                }
                request.address.validate()?;
            }
            Ok(())
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize)]
    pub struct NamedGetResult {
        pub name: String,
        #[serde(flatten)]
        pub outcome: GetResult,
    }

    impl<'de> Deserialize<'de> for NamedGetResult {
        fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            #[derive(Deserialize)]
            struct Found {
                name: String,
                status: FoundStatus,
                value: String,
            }

            #[derive(Deserialize)]
            struct Missing {
                name: String,
                status: MissingStatus,
            }

            #[derive(Deserialize)]
            #[serde(rename_all = "snake_case")]
            enum FoundStatus {
                Found,
            }

            #[derive(Deserialize)]
            #[serde(rename_all = "snake_case")]
            enum MissingStatus {
                Missing,
            }

            #[derive(Deserialize)]
            #[serde(untagged)]
            enum Repr {
                Found(Found),
                Missing(Missing),
            }

            match Repr::deserialize(deserializer)? {
                Repr::Found(Found {
                    name,
                    status: FoundStatus::Found,
                    value,
                }) => Ok(Self {
                    name,
                    outcome: GetResult::Found { value },
                }),
                Repr::Missing(Missing {
                    name,
                    status: MissingStatus::Missing,
                }) => Ok(Self {
                    name,
                    outcome: GetResult::Missing,
                }),
            }
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct GetManyResult {
        pub results: Vec<NamedGetResult>,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
    pub struct ExistsResult {
        pub exists: bool,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct SetParams {
        pub address: Address,
        pub value: String,
    }

    impl SetParams {
        pub fn validate(&self) -> Result<()> {
            self.address.validate()
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct SetExpiringParams {
        pub address: Address,
        pub value: String,
        pub ttl_ms: u64,
    }

    impl SetExpiringParams {
        pub fn validate(&self) -> Result<()> {
            self.address.validate()?;
            if self.ttl_ms == 0 {
                return Err(Error::Protocol("provider expiry must be positive"));
            }
            Ok(())
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
    pub struct StoredResult {
        pub stored: bool,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
    pub struct DeletedResult {
        pub deleted: bool,
    }

    #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
    pub struct EmptyResult {}

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
    pub enum ClearScope {
        All,
        Convention { project: String, profile: String },
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct ClearParams {
        pub scope: ClearScope,
    }

    impl ClearParams {
        pub fn validate(&self) -> Result<()> {
            match &self.scope {
                ClearScope::All => Ok(()),
                ClearScope::Convention { project, profile } => {
                    validate_optional_bytes("clear project is too long", Some(project), 4096)?;
                    validate_optional_bytes("clear profile is too long", Some(profile), 4096)
                }
            }
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
    pub struct ClearResult {
        pub cleared: usize,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct DescribeWriteTargetResult {
        pub description: String,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct ReflectParams {
        pub project: String,
        pub profile: String,
    }

    impl ReflectParams {
        pub fn validate(&self) -> Result<()> {
            validate_optional_bytes("reflection project is too long", Some(&self.project), 4096)?;
            validate_optional_bytes("reflection profile is too long", Some(&self.profile), 4096)
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct ReflectedDeclaration {
        pub description: String,
        pub required: bool,
        #[serde(rename = "ref")]
        pub reference: Coordinates,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct ReflectResult {
        pub schema_version: u32,
        pub declarations: BTreeMap<String, ReflectedDeclaration>,
    }

    impl ReflectResult {
        pub fn validate(&self) -> Result<()> {
            if self.schema_version != 1 {
                return Err(Error::Protocol("unsupported reflection schema version"));
            }
            for (name, declaration) in &self.declarations {
                validate_optional_bytes("reflected name is too long", Some(name), 4096)?;
                validate_optional_bytes(
                    "reflected description is too long",
                    Some(&declaration.description),
                    4096,
                )?;
                declaration.reference.validate()?;
            }
            Ok(())
        }
    }

    fn validate_scheme(scheme: &str) -> Result<()> {
        let mut chars = scheme.chars();
        let first = chars.next();
        if !matches!(first, Some('a'..='z'))
            || chars.any(|character| !matches!(character, 'a'..='z' | '0'..='9' | '-'))
        {
            return Err(Error::Protocol("invalid provider scheme"));
        }
        Ok(())
    }

    fn validate_semantic_name(name: &str) -> Result<()> {
        let mut chars = name.chars();
        if !matches!(chars.next(), Some('a'..='z'))
            || chars.any(|character| !matches!(character, 'a'..='z' | '0'..='9' | '_'))
            || name.len() > 256
        {
            return Err(Error::Protocol("invalid credential semantic name"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limit_selection_never_increases_an_offer() {
        let selected = Limits {
            max_frame_bytes: 32_768,
            max_in_flight: 16,
        }
        .select(Limits {
            max_frame_bytes: 8_192,
            max_in_flight: 4,
        })
        .unwrap();
        assert_eq!(selected.max_frame_bytes, 8_192);
        assert_eq!(selected.max_in_flight, 4);
    }

    #[test]
    fn provider_uri_scheme_must_match() {
        let application = provider::InitializeApplication {
            scheme: "factorseal".into(),
            uri: "other://default".into(),
            base_dir: None,
            credentials: BTreeMap::new(),
            reason: None,
        };
        assert!(application.validate().is_err());
    }

    #[test]
    fn named_provider_batch_results_are_flattened_and_closed() {
        let found = serde_json::from_value::<provider::NamedGetResult>(serde_json::json!({
            "name": "token",
            "status": "found",
            "value": "secret"
        }))
        .unwrap();
        assert_eq!(
            found,
            provider::NamedGetResult {
                name: "token".into(),
                outcome: provider::GetResult::Found {
                    value: "secret".into()
                }
            }
        );
        assert!(
            serde_json::from_value::<provider::NamedGetResult>(serde_json::json!({
                "name": "token",
                "status": "missing",
                "extra": true
            }))
            .is_ok()
        );
    }

    #[test]
    fn provider_empty_results_ignore_future_members() {
        assert!(serde_json::from_value::<provider::EmptyResult>(serde_json::json!({})).is_ok());
        assert!(
            serde_json::from_value::<provider::EmptyResult>(serde_json::json!({"stored": true}))
                .is_ok()
        );
    }

    #[test]
    fn schema_required_nullable_members_cannot_be_omitted() {
        assert!(
            serde_json::from_value::<resolver::InitializeApplication>(serde_json::json!({
                "manifest": {"kind": "path", "path": "/tmp/secretspec.toml"},
                "provider": null,
                "profile": null,
                "scope": null
            }))
            .is_err()
        );
        assert!(
            serde_json::from_value::<provider::InitializeApplication>(serde_json::json!({
                "scheme": "factorseal",
                "uri": "factorseal://default",
                "base_dir": null,
                "credentials": {}
            }))
            .is_err()
        );
    }
}
