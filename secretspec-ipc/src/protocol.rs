use crate::error::{Error, Result};
use crate::{ABSOLUTE_MAX_FRAME_BYTES, MAX_IN_FLIGHT, MIN_FRAME_BYTES};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub const CLIENT_PROTOCOL: &str = "secretspec.client";
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
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InitializeResult<A> {
    pub protocol: String,
    pub version: u32,
    pub server: Product,
    pub capabilities: Vec<String>,
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
        validate_capabilities(&self.capabilities)?;
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

pub(crate) fn validate_capabilities(capabilities: &[String]) -> Result<()> {
    if capabilities.iter().collect::<BTreeSet<_>>().len() != capabilities.len() {
        return Err(Error::Protocol("capabilities must be distinct"));
    }
    for capability in capabilities {
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

pub mod client {
    use super::*;

    pub mod method {
        pub const RESOLVE: &str = "client.resolve";
        pub const RELEASE: &str = "client.release";
    }

    pub const CAPABILITIES: &[&str] = &[method::RESOLVE, method::RELEASE];

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
    pub enum Representation {
        Auto,
        Value,
        File,
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
    pub struct ResolveParams {
        pub name: String,
        pub representation: Representation,
        pub purpose: Purpose,
    }

    impl ResolveParams {
        pub fn validate(&self) -> Result<()> {
            validate_nonempty_bytes("secret name has an invalid byte length", &self.name, 4096)?;
            self.purpose.validate()
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(rename_all = "snake_case")]
    pub enum Source {
        Provider,
        Generated,
        Default,
        Composed,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct UndeclaredResult {
        pub status: UndeclaredStatus,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(rename_all = "snake_case")]
    pub enum UndeclaredStatus {
        Undeclared,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
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
    #[serde(deny_unknown_fields)]
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
    #[serde(deny_unknown_fields)]
    pub struct ResolvedFileResult {
        pub status: ResolvedStatus,
        pub representation: FileRepresentation,
        pub path: String,
        pub lease_id: String,
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
    pub enum FileRepresentation {
        File,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(untagged)]
    pub enum ResolveResult {
        Undeclared(UndeclaredResult),
        Missing(MissingResult),
        Value(ResolvedValueResult),
        File(ResolvedFileResult),
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct ReleaseParams {
        pub lease_ids: Vec<String>,
    }

    impl ReleaseParams {
        pub fn validate(&self) -> Result<()> {
            if self.lease_ids.len() > 256 {
                return Err(Error::Protocol("release contains more than 256 lease IDs"));
            }
            for lease in &self.lease_ids {
                validate_nonempty_bytes("lease ID has an invalid byte length", lease, 256)?;
            }
            Ok(())
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
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
    #[serde(deny_unknown_fields)]
    pub struct ResolveAddressResult {
        pub coordinates: Coordinates,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
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
            #[serde(deny_unknown_fields)]
            struct Found {
                name: String,
                status: FoundStatus,
                value: String,
            }

            #[derive(Deserialize)]
            #[serde(deny_unknown_fields)]
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
    #[serde(deny_unknown_fields)]
    pub struct GetManyResult {
        pub results: Vec<NamedGetResult>,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
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
    #[serde(deny_unknown_fields)]
    pub struct StoredResult {
        pub stored: bool,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct DeletedResult {
        pub deleted: bool,
    }

    #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
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
    #[serde(deny_unknown_fields)]
    pub struct ClearResult {
        pub cleared: usize,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
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
    #[serde(deny_unknown_fields)]
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
            .is_err()
        );
    }

    #[test]
    fn provider_empty_results_reject_members() {
        assert!(serde_json::from_value::<provider::EmptyResult>(serde_json::json!({})).is_ok());
        assert!(
            serde_json::from_value::<provider::EmptyResult>(serde_json::json!({"stored": true}))
                .is_err()
        );
    }

    #[test]
    fn schema_required_nullable_members_cannot_be_omitted() {
        assert!(
            serde_json::from_value::<client::InitializeApplication>(serde_json::json!({
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
