//! The resolution plan: a pure, I/O-free description of *what to do* for every
//! secret in a profile, computed once up front and then executed.
//!
//! Resolution used to interleave deciding (profile merge, alias resolution,
//! grouping, address derivation) with doing (spawning fetches, walking fallback
//! chains, applying defaults, generating). This module isolates the deciding
//! half: [`Secrets::build_plan`] turns the manifest plus provider-alias maps
//! into an immutable [`ResolutionPlan`] without touching any provider, so the
//! decisions are unit-testable on their own and the executor consumes a plan
//! instead of re-deriving per-secret facts across `get`, `set`, and batch
//! validation.
//!
//! Building a plan performs no I/O. Provider-alias resolution is a map lookup,
//! so the only error it can raise is an undefined alias
//! ([`SecretSpecError::ProviderNotFound`]); a plan never opens a store.

use crate::config::{NativeAddress, Profile, Secret};
use crate::error::Result;
use crate::provider::Address;
use crate::secrets::Secrets;
use std::collections::HashMap;

/// How a planned secret is named at whichever store resolves it.
///
/// Naming is orthogonal to routing: the same address is asked of whatever store
/// [`Route`] selects. A secret's `ref` supplies native coordinates; otherwise
/// SecretSpec's own `{project}/{profile}/{key}` convention applies, with the
/// project and profile carried once on the [`ResolutionPlan`].
#[derive(Debug)]
pub(crate) enum PlannedAddress {
    /// Native coordinates from the secret's `ref`.
    Native(NativeAddress),
    /// SecretSpec's naming convention; only the key varies per secret.
    Convention { key: String },
}

impl PlannedAddress {
    /// Borrow this owned address as the [`Address`] the provider trait consumes,
    /// supplying the plan-level `project`/`profile` for a convention address.
    pub(crate) fn as_address<'a>(&'a self, project: &'a str, profile: &'a str) -> Address<'a> {
        match self {
            PlannedAddress::Native(native) => Address::Native(native),
            PlannedAddress::Convention { key } => Address::convention(project, profile, key),
        }
    }
}

/// Where a planned secret reads and writes.
///
/// A `providers` chain is a fallback list tried in order. Only the **primary**
/// (the first entry — always tried first, the write target, and the grouping
/// key) is resolved to a URI up front; the rest are carried as raw specs and
/// resolved lazily, when and only when a read actually falls through to them.
/// That keeps the chain tried in order: an undefined alias further down never
/// fails an operation the primary satisfies, and never fails a write at all.
#[derive(Debug)]
pub(crate) enum Route {
    /// An explicit `--provider`/`SECRETSPEC_PROVIDER`/builder override: exactly
    /// one store, no fallback (the override collapses any per-secret chain).
    Override(String),
    /// The secret's `providers` chain. `primary` is the resolved first store;
    /// `fallback` holds the remaining specs (aliases or URIs) raw, tried in
    /// order — and resolved — only after the primary misses.
    Chain {
        primary: String,
        fallback: Vec<String>,
    },
    /// No routing configured for this secret: the default provider applies.
    Default,
}

impl Route {
    /// The store consulted first — the override, the chain's primary, or `None`
    /// for the default provider. This is the grouping key and the write target:
    /// secrets sharing a primary store are fetched together, and a write goes to
    /// the primary.
    pub(crate) fn primary(&self) -> Option<&str> {
        match self {
            Route::Override(uri) => Some(uri),
            Route::Chain { primary, .. } => Some(primary),
            Route::Default => None,
        }
    }

    /// The raw fallback specs a read walks after the primary misses: a chain's
    /// entries past the first, when there are any. `None` means the read may
    /// consult only one store — [`Route::primary`], with `None` meaning the
    /// default provider — so no other store could answer instead. The one
    /// definition of "has a fallback" shared by [`Route::has_fallback`] and
    /// the executor's fallback walk.
    pub(crate) fn fallback_specs(&self) -> Option<&[String]> {
        match self {
            Route::Chain { fallback, .. } if !fallback.is_empty() => Some(fallback),
            _ => None,
        }
    }

    /// Whether a read may consult more than one store: a chain with at least
    /// one fallback entry.
    pub(crate) fn has_fallback(&self) -> bool {
        self.fallback_specs().is_some()
    }

    /// The ordered provider specs a read walks — the primary followed by the raw
    /// fallback — or `None` for the default provider. Each entry is resolved only
    /// when the read reaches it, so the chain is genuinely tried in order.
    pub(crate) fn specs(&self) -> Option<Vec<String>> {
        match self {
            Route::Override(uri) => Some(vec![uri.clone()]),
            Route::Chain { primary, fallback } => {
                let mut specs = Vec::with_capacity(1 + fallback.len());
                specs.push(primary.clone());
                specs.extend(fallback.iter().cloned());
                Some(specs)
            }
            Route::Default => None,
        }
    }
}

/// Everything decided for one declared secret, ready to execute.
#[derive(Debug)]
pub(crate) struct PlannedSecret {
    /// The declared secret name (the manifest's `UPPER_SNAKE` key).
    pub name: String,
    /// The secret's effective config after the profile field-level merge.
    pub config: Secret,
    /// How the secret is named at whichever store resolves it.
    pub address: PlannedAddress,
    /// The resolved read/write route.
    pub route: Route,
}

impl PlannedSecret {
    /// The native `ref` coordinates the plan derived for this secret, if any.
    /// Reads the planned address, not the raw config, so audit attribution
    /// always reports the coordinates the plan actually addresses.
    pub(crate) fn reference(&self) -> Option<&NativeAddress> {
        match &self.address {
            PlannedAddress::Native(native) => Some(native),
            PlannedAddress::Convention { .. } => None,
        }
    }

    /// Whether the active profile requires this secret (required by default).
    pub(crate) fn required(&self) -> bool {
        self.config.required.unwrap_or(true)
    }

    /// Whether the value is materialized to a temp file and exposed as a path.
    pub(crate) fn as_path(&self) -> bool {
        self.config.as_path.unwrap_or(false)
    }
}

/// An immutable, fully-decided plan for resolving one profile.
#[derive(Debug)]
pub(crate) struct ResolutionPlan {
    /// The project name (supplies convention addressing).
    pub project: String,
    /// The resolved profile name.
    pub profile: String,
    /// The explicit provider override in force, if any. `Some` collapses every
    /// secret's route to that single store.
    pub override_uri: Option<String>,
    /// One entry per declared secret, sorted by name for deterministic output.
    pub secrets: Vec<PlannedSecret>,
    /// Primary-store groups in first-seen order: each maps a store URI (`None` =
    /// default provider) to the indices into [`ResolutionPlan::secrets`] fetched
    /// together. A pure function of each secret's [`Route::primary`], surfaced
    /// so the executor does not recompute it.
    pub groups: Vec<(Option<String>, Vec<usize>)>,
}

impl Secrets {
    /// Resolve a whole profile into an immutable [`ResolutionPlan`] without any
    /// I/O: merge the profile, compute each secret's effective config, derive
    /// its address and resolved route, and group secrets by their primary store.
    ///
    /// The explicit provider override (builder or `SECRETSPEC_PROVIDER`) is
    /// picked up via [`Secrets::resolve_provider_override`]. Production code
    /// resolves the profile itself and calls [`Secrets::build_plan_from_profile`]
    /// directly (it needs the profile for audit attribution too, and shouldn't
    /// merge it twice); this one-call form is for tests that don't.
    #[cfg(test)]
    pub(crate) fn build_plan(&self, profile: Option<&str>) -> Result<ResolutionPlan> {
        let profile_name = self.resolve_profile_name(profile);
        let profile_config = self.resolve_profile(Some(&profile_name))?;
        self.build_plan_from_profile(profile_name, profile_config)
    }

    /// As [`Secrets::build_plan`], but for a caller that has already resolved
    /// the profile for another purpose (e.g. attributing an audit event before
    /// planning can fail) and would otherwise redo that merge a second time.
    pub(crate) fn build_plan_from_profile(
        &self,
        profile_name: String,
        profile_config: Profile,
    ) -> Result<ResolutionPlan> {
        // Sorted names make planning deterministic (grouping order, missing
        // lists) rather than inheriting the profile's HashMap iteration order.
        let names = profile_config.sorted_secret_names();

        let override_uri = self.resolve_provider_override(None);

        let mut secrets = Vec::with_capacity(names.len());
        for name in &names {
            let config = self
                .resolve_secret_config(name, Some(&profile_name))
                .expect("secret resolved from the merged profile always has a config");
            secrets.push(self.plan_one_secret(name.clone(), config, &override_uri)?);
        }

        // Group by primary store, preserving first-seen order so grouping is
        // deterministic and independent of hashing.
        let mut groups: Vec<(Option<String>, Vec<usize>)> = Vec::new();
        let mut group_index: HashMap<Option<&str>, usize> = HashMap::new();
        for (i, secret) in secrets.iter().enumerate() {
            let primary = secret.route.primary();
            match group_index.get(&primary) {
                Some(&idx) => groups[idx].1.push(i),
                None => {
                    group_index.insert(primary, groups.len());
                    groups.push((primary.map(String::from), vec![i]));
                }
            }
        }

        Ok(ResolutionPlan {
            project: self.config().project.name.clone(),
            profile: profile_name,
            override_uri,
            secrets,
            groups,
        })
    }

    /// Plan a single secret the CLI's `get`/`set` operate on, reusing the exact
    /// per-secret decisions batch resolution makes. Returns `Ok(None)` when the
    /// secret is not declared in the (merged) profile, mirroring
    /// [`Secrets::resolve_secret_config`], so the caller can raise its own
    /// "not found" error and audit it.
    ///
    /// `override_arg` is the caller's explicit provider (the `--provider`
    /// flag); like [`Secrets::build_plan`] it also picks up the builder and
    /// `SECRETSPEC_PROVIDER` via [`Secrets::resolve_provider_override`], and
    /// profile resolution follows the same precedence.
    pub(crate) fn plan_secret(
        &self,
        name: &str,
        profile: Option<&str>,
        override_arg: Option<&str>,
    ) -> Result<Option<PlannedSecret>> {
        let profile_name = self.resolve_profile_name(profile);
        let Some(config) = self.resolve_secret_config(name, Some(&profile_name)) else {
            return Ok(None);
        };
        let override_uri = self.resolve_provider_override(override_arg);
        Ok(Some(self.plan_one_secret(
            name.to_string(),
            config,
            &override_uri,
        )?))
    }

    /// Derive one [`PlannedSecret`] from its effective config and the resolved
    /// override. The single place per-secret decisions are made, shared by the
    /// whole-profile [`Secrets::build_plan`] and the single-secret
    /// [`Secrets::plan_secret`], so `get`, `set`, and batch validation cannot
    /// drift.
    fn plan_one_secret(
        &self,
        name: String,
        config: Secret,
        override_uri: &Option<String>,
    ) -> Result<PlannedSecret> {
        // A `ref` supplies naming only; convention naming otherwise. The address
        // applies to whichever store the route selects.
        let address = match &config.reference {
            Some(native) => PlannedAddress::Native(native.clone()),
            None => PlannedAddress::Convention { key: name.clone() },
        };

        let route = self.route_for(&config, override_uri)?;

        Ok(PlannedSecret {
            name,
            config,
            address,
            route,
        })
    }

    /// Resolve a secret's [`Route`] from its config and the active override.
    ///
    /// An explicit override collapses to a single store. Otherwise only the
    /// primary of the `providers` chain is resolved (it is always tried first
    /// and is the write/grouping target, so an undefined primary is a hard error
    /// here); the fallback specs are carried raw and resolved lazily on a miss,
    /// so the chain stays tried in order. An empty or absent chain is the default
    /// provider. This is the one routing deriver behind the plan, `get`, `set`,
    /// and generation.
    pub(crate) fn route_for(
        &self,
        config: &Secret,
        override_uri: &Option<String>,
    ) -> Result<Route> {
        if let Some(uri) = override_uri {
            return Ok(Route::Override(uri.clone()));
        }
        match config.providers.as_deref() {
            Some([first, fallback @ ..]) => Ok(Route::Chain {
                primary: self.resolve_one_provider(first)?,
                fallback: fallback.to_vec(),
            }),
            _ => Ok(Route::Default),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::SecretSpecError;
    use crate::tests::{global_config_with_aliases, scrub_resolution_env};
    use std::collections::HashMap;

    /// Build a secret with a description and optional per-secret provider chain.
    fn secret(providers: Option<Vec<&str>>) -> Secret {
        Secret {
            description: Some("a secret".to_string()),
            providers: providers.map(|p| p.into_iter().map(String::from).collect()),
            ..Default::default()
        }
    }

    /// A `Secrets` over a single `default` profile holding `secrets`, with an
    /// optional builder provider and global alias map.
    fn spec(
        secrets: HashMap<String, Secret>,
        provider: Option<&str>,
        aliases: &[(&str, &str)],
    ) -> Secrets {
        let config = crate::tests::resolve_test_config(secrets);
        let global_config = (!aliases.is_empty()).then(|| global_config_with_aliases(aliases));
        Secrets::new(config, global_config, provider.map(String::from), None)
    }

    fn plan(spec: &Secrets) -> ResolutionPlan {
        spec.build_plan(None).unwrap()
    }

    fn find<'a>(plan: &'a ResolutionPlan, name: &str) -> &'a PlannedSecret {
        plan.secrets
            .iter()
            .find(|s| s.name == name)
            .expect("secret in plan")
    }

    #[test]
    fn no_routing_plans_the_default_store() {
        let _env = scrub_resolution_env();
        let secrets = HashMap::from([("DATABASE_URL".to_string(), secret(None))]);
        let plan = plan(&spec(secrets, None, &[]));

        let planned = find(&plan, "DATABASE_URL");
        assert!(matches!(planned.route, Route::Default));
        assert_eq!(planned.route.primary(), None);
        assert_eq!(plan.groups, vec![(None, vec![0])]);
    }

    #[test]
    fn override_collapses_the_chain_to_one_store() {
        let _env = scrub_resolution_env();
        let secrets = HashMap::from([(
            "API_KEY".to_string(),
            secret(Some(vec!["onepassword://Production", "keyring://"])),
        )]);
        // An explicit override wins over the per-secret chain.
        let mut spec = spec(secrets, None, &[]);
        spec.set_provider("dotenv://.env.mock");
        let plan = plan(&spec);

        let planned = find(&plan, "API_KEY");
        assert!(matches!(&planned.route, Route::Override(uri) if uri == "dotenv://.env.mock"));
        assert_eq!(planned.route.primary(), Some("dotenv://.env.mock"));
        assert_eq!(plan.override_uri, Some("dotenv://.env.mock".to_string()));
    }

    #[test]
    fn providers_chain_resolves_the_primary_and_carries_the_fallback_raw() {
        let _env = scrub_resolution_env();
        let secrets = HashMap::from([("API_KEY".to_string(), secret(Some(vec!["shared", "kr"])))]);
        let plan = plan(&spec(
            secrets,
            None,
            &[("shared", "onepassword://Shared"), ("kr", "keyring://")],
        ));

        let planned = find(&plan, "API_KEY");
        match &planned.route {
            // The primary is resolved to its URI; the fallback stays as the raw
            // alias, resolved only if the primary misses at read time.
            Route::Chain { primary, fallback } => {
                assert_eq!(primary, "onepassword://Shared");
                assert_eq!(fallback, &vec!["kr".to_string()]);
            }
            other => panic!("expected a chain, got {other:?}"),
        }
        assert_eq!(planned.route.primary(), Some("onepassword://Shared"));
    }

    #[test]
    fn an_undefined_fallback_alias_does_not_fail_the_plan() {
        let _env = scrub_resolution_env();
        // The chain is tried in order: a broken link after the primary must not
        // fail planning, since a live primary may never reach it.
        let secrets = HashMap::from([("API_KEY".to_string(), secret(Some(vec!["kr", "ghost"])))]);
        let plan = plan(&spec(secrets, None, &[("kr", "keyring://")]));

        let planned = find(&plan, "API_KEY");
        match &planned.route {
            Route::Chain { primary, fallback } => {
                assert_eq!(primary, "keyring://");
                // The undefined alias is carried raw, not resolved (which would error).
                assert_eq!(fallback, &vec!["ghost".to_string()]);
            }
            other => panic!("expected a chain, got {other:?}"),
        }
    }

    #[test]
    fn inline_uri_in_chain_passes_through_without_an_alias() {
        let _env = scrub_resolution_env();
        let secrets = HashMap::from([(
            "API_KEY".to_string(),
            secret(Some(vec!["onepassword://Production"])),
        )]);
        let plan = plan(&spec(secrets, None, &[]));

        let planned = find(&plan, "API_KEY");
        assert_eq!(planned.route.primary(), Some("onepassword://Production"));
    }

    #[test]
    fn undefined_alias_fails_the_plan() {
        let _env = scrub_resolution_env();
        let secrets = HashMap::from([("API_KEY".to_string(), secret(Some(vec!["nope"])))]);
        let spec = spec(secrets, None, &[]);
        let err = spec.build_plan(None).unwrap_err();
        assert!(matches!(err, SecretSpecError::ProviderNotFound(_)));
    }

    #[test]
    fn bare_provider_name_in_chain_passes_through() {
        let _env = scrub_resolution_env();
        // A chain entry that names a registered provider (no alias, no `://`)
        // is a valid spec, exactly as `--provider keyring` is: the plan carries
        // it through for `build_provider` to construct.
        let secrets = HashMap::from([("API_KEY".to_string(), secret(Some(vec!["keyring"])))]);
        let plan = plan(&spec(secrets, None, &[]));

        assert_eq!(find(&plan, "API_KEY").route.primary(), Some("keyring"));
    }

    #[test]
    fn a_ref_plans_a_native_address_convention_otherwise() {
        let _env = scrub_resolution_env();
        let mut referenced = secret(None);
        referenced.reference = Some(NativeAddress {
            item: "db".to_string(),
            field: Some("password".to_string()),
            ..Default::default()
        });
        let secrets = HashMap::from([
            ("REFERENCED".to_string(), referenced),
            ("PLAIN".to_string(), secret(None)),
        ]);
        let plan = plan(&spec(secrets, None, &[]));

        match &find(&plan, "REFERENCED").address {
            PlannedAddress::Native(native) => {
                assert_eq!(native.item, "db");
                assert_eq!(native.field.as_deref(), Some("password"));
            }
            PlannedAddress::Convention { .. } => panic!("a ref should plan a native address"),
        }
        match &find(&plan, "PLAIN").address {
            PlannedAddress::Convention { key } => assert_eq!(key, "PLAIN"),
            PlannedAddress::Native(_) => panic!("no ref should plan a convention address"),
        }
    }

    #[test]
    fn secrets_are_sorted_and_grouped_by_primary_store() {
        let _env = scrub_resolution_env();
        let secrets = HashMap::from([
            ("B".to_string(), secret(Some(vec!["keyring://"]))),
            ("A".to_string(), secret(None)),
            ("C".to_string(), secret(Some(vec!["keyring://"]))),
        ]);
        let plan = plan(&spec(secrets, None, &[]));

        // Deterministic, name-sorted ordering regardless of map hashing.
        let names: Vec<&str> = plan.secrets.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(names, vec!["A", "B", "C"]);

        // A goes to the default group; B and C share the keyring group.
        assert_eq!(
            plan.groups,
            vec![
                (None, vec![0]),
                (Some("keyring://".to_string()), vec![1, 2]),
            ]
        );
    }

    #[test]
    fn plan_secret_is_none_for_an_undeclared_secret() {
        let _env = scrub_resolution_env();
        let secrets = HashMap::from([("DECLARED".to_string(), secret(None))]);
        let spec = spec(secrets, None, &[]);
        assert!(
            spec.plan_secret("NOPE", None, None).unwrap().is_none(),
            "an undeclared secret must not plan"
        );
    }

    #[test]
    fn plan_secret_matches_the_batch_plan_for_a_declared_secret() {
        let _env = scrub_resolution_env();
        // `get`/`set` plan one secret; the decision must match `build_plan`.
        let secrets = HashMap::from([(
            "API_KEY".to_string(),
            secret(Some(vec!["onepassword://Production", "keyring://"])),
        )]);
        let spec = spec(secrets, None, &[]);

        let one = spec.plan_secret("API_KEY", None, None).unwrap().unwrap();
        assert_eq!(one.route.primary(), Some("onepassword://Production"));
        match &one.route {
            Route::Chain { primary, fallback } => {
                assert_eq!(primary, "onepassword://Production");
                assert_eq!(fallback, &vec!["keyring://".to_string()]);
            }
            other => panic!("expected a chain, got {other:?}"),
        }

        // Same route the whole-profile plan derives.
        let batch = plan(&spec);
        assert_eq!(one.route.primary(), find(&batch, "API_KEY").route.primary());
    }
}
