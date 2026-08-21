use super::Provider;
use crate::config::NativeAddress;
use crate::{Result, SecretSpecError};
use std::borrow::Cow;

/// How a provider operation addresses a secret.
///
/// Every read and write names its secret one of two ways:
///
/// - [`Convention`](Address::Convention): SecretSpec's own naming scheme. The
///   provider maps `(project, profile, key)` into its namespace, by default
///   `{provider}/{project}/{profile}/{key}` or the provider's configured
///   format string.
/// - [`Native`](Address::Native): explicit coordinates from a secret's `ref`
///   field, naming one externally managed secret in the provider's own terms
///   (item, field, ...). The provider translates the coordinates and rejects
///   any it has no equivalent for.
///
/// Which stores are consulted is decided entirely by provider resolution
/// (chains, overrides, defaults); the address only supplies the name to look
/// up in one selected endpoint. SecretSpec may derive a different address for
/// another provider alias in the same logical route.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub enum Address<'a> {
    /// SecretSpec's `{project}/{profile}/{key}` naming convention.
    Convention {
        project: &'a str,
        profile: &'a str,
        key: &'a str,
    },
    /// Native coordinates of one externally managed secret (a `ref`).
    Native(&'a NativeAddress),
}

impl<'a> Address<'a> {
    /// Convention-scheme constructor, in the enum's own field order.
    pub fn convention(project: &'a str, profile: &'a str, key: &'a str) -> Self {
        Self::Convention {
            project,
            profile,
            key,
        }
    }
}

/// Owned counterpart to [`Address`], used by plans that must retain distinct
/// source and destination addresses before provider operations begin.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) enum OwnedAddress {
    Convention {
        project: String,
        profile: String,
        key: String,
    },
    Native(NativeAddress),
}

impl OwnedAddress {
    pub(crate) fn convention(project: &str, profile: &str, key: &str) -> Self {
        Self::Convention {
            project: project.to_string(),
            profile: profile.to_string(),
            key: key.to_string(),
        }
    }

    pub(crate) fn as_address(&self) -> Address<'_> {
        match self {
            Self::Convention {
                project,
                profile,
                key,
            } => Address::Convention {
                project,
                profile,
                key,
            },
            Self::Native(reference) => Address::Native(reference),
        }
    }

    pub(crate) fn native(&self) -> Option<&NativeAddress> {
        match self {
            Self::Native(reference) => Some(reference),
            Self::Convention { .. } => None,
        }
    }
}

/// Builds the shared diagnostic for a native-address coordinate a provider has
/// no equivalent for.
///
/// Enforced once for every address inside the default
/// [`resolve_coords`](Provider::resolve_coords), against the provider's
/// declared [`supported_coords`](Provider::supported_coords): a coordinate the
/// provider does not name produces an error that names the coordinate, the ref
/// it came from, and how to fix it, so a `ref` written for one store fails
/// loudly when routing points it at a store that cannot honor those
/// coordinates, instead of silently resolving something else.
///
/// Both remedies are offered because dropping the coordinate is only right when
/// every endpoint should share one address. When the coordinate is meaningful to
/// the store the ref was written for — a Bitwarden or 1Password item field, say —
/// and this store simply organizes the secret differently, the fix is a
/// per-provider address (0.19+), not a lossy edit to the ref.
#[allow(dead_code)]
pub(super) fn reject_unsupported_coords(
    provider: &str,
    addr: &NativeAddress,
    supported: &[&str],
) -> Result<()> {
    for (name, value) in addr.coordinates() {
        // `item` is the one coordinate every provider consumes.
        if name == "item" || value.is_none() {
            continue;
        }
        if !supported.contains(&name) {
            return Err(unsupported_coord_error(provider, addr, name));
        }
    }
    Ok(())
}

pub(super) fn unsupported_coord_error(
    provider: &str,
    addr: &NativeAddress,
    name: &str,
) -> SecretSpecError {
    SecretSpecError::ProviderOperationFailed(format!(
        "the {provider} provider does not support the `{name}` coordinate. \
         Drop `{name}` from the ref for `{item}`, or give this provider its \
         own address with `refs.<alias>` or an alias `ref` template (0.19+): \
         https://secretspec.dev/concepts/references/#different-coordinates-per-provider-019",
        item = addr.item
    ))
}

/// Resolves an address for flat stores whose secrets have no sub-components:
/// any address, convention or `ref`, names the entry via `item` alone, every
/// other coordinate having been rejected by the provider's empty
/// [`supported_coords`](Provider::supported_coords).
pub(crate) fn flat_item<'a, P: Provider + ?Sized>(
    provider: &P,
    addr: Address<'a>,
) -> Result<Cow<'a, str>> {
    match provider.resolve_coords(addr)? {
        Cow::Borrowed(native) => Ok(Cow::Borrowed(native.item.as_str())),
        Cow::Owned(native) => Ok(Cow::Owned(native.item)),
    }
}
