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
//! Building a plan performs no I/O. Provider-spec resolution is a map lookup
//! plus a registry check, so the only errors it can raise are a routing spec
//! that names neither an alias nor a provider
//! ([`SecretSpecError::ProviderNotFound`]) and the corrected `1password`
//! misspelling; a plan never opens a store.

use crate::config::{NativeAddress, Secret};
use crate::error::Result;
use crate::provider::Address;
use crate::secrets::Secrets;
use std::collections::HashMap;

/// Where a planned secret reads and writes.
///
/// A `providers` chain is a fallback list tried in order. Only the primary
/// (always tried first, the write target, and the grouping key) is resolved to
/// a URI up front; the rest are carried as raw specs and resolved lazily, when
/// and only when a read actually falls through to them. That keeps the chain
/// tried in order: an undefined alias further down never fails an operation
/// the primary satisfies, and never fails a write at all.
///
/// An explicit `--provider`/`SECRETSPEC_PROVIDER`/builder override collapses
/// any chain to just that store: it becomes the primary with no fallback.
#[derive(Debug)]
pub(crate) struct Route {
    /// The store consulted first — the resolved chain head or the explicit
    /// override — or `None` for the default provider.
    pub primary: Option<String>,
    /// The chain's remaining specs (aliases or URIs), raw, tried in order —
    /// and resolved — only after the primary misses.
    pub fallback: Vec<String>,
}

impl Route {
    /// The store consulted first, `None` meaning the default provider. This is
    /// the grouping key and the write target: secrets sharing a primary store
    /// are fetched together, and a write goes to the primary.
    pub(crate) fn primary(&self) -> Option<&str> {
        self.primary.as_deref()
    }

    /// The raw fallback specs a read walks after the primary misses, when
    /// there are any. `None` means the read may consult only one store —
    /// [`Route::primary`], with `None` meaning the default provider — so no
    /// other store could answer instead.
    pub(crate) fn fallback_specs(&self) -> Option<&[String]> {
        (!self.fallback.is_empty()).then_some(self.fallback.as_slice())
    }

    /// The ordered provider specs a read walks — the primary followed by the raw
    /// fallback — or `None` for the default provider. Each entry is resolved only
    /// when the read reaches it, so the chain is genuinely tried in order.
    pub(crate) fn specs(&self) -> Option<Vec<String>> {
        self.primary.as_ref().map(|primary| {
            let mut specs = Vec::with_capacity(1 + self.fallback.len());
            specs.push(primary.clone());
            specs.extend(self.fallback.iter().cloned());
            specs
        })
    }
}

/// Everything decided for one declared secret, ready to execute.
#[derive(Debug)]
pub(crate) struct PlannedSecret {
    /// The declared secret name (the manifest's `UPPER_SNAKE` key).
    pub name: String,
    /// The secret's effective config after the profile field-level merge.
    pub config: Secret,
    /// The resolved read/write route.
    pub route: Route,
}

impl PlannedSecret {
    /// The provider [`Address`] this secret's operations resolve: its native
    /// `ref` coordinates when it has them, otherwise SecretSpec's own
    /// `{project}/{profile}/{key}` naming convention. Naming is orthogonal to
    /// routing: the same address is asked of whichever store [`Route`] selects.
    pub(crate) fn as_address<'a>(&'a self, project: &'a str, profile: &'a str) -> Address<'a> {
        match &self.config.reference {
            Some(native) => Address::Native(native),
            None => Address::convention(project, profile, &self.name),
        }
    }

    /// The native `ref` coordinates this secret addresses, if any.
    pub(crate) fn reference(&self) -> Option<&NativeAddress> {
        self.config.reference.as_ref()
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
    /// The resolved profile name.
    pub profile: String,
    /// The explicit provider override in force, if any. `Some` collapses every
    /// secret's route to that single store.
    pub override_uri: Option<String>,
    /// One entry per declared secret, sorted by name for deterministic output.
    pub secrets: Vec<PlannedSecret>,
}

impl ResolutionPlan {
    /// Primary-store groups in first-seen order: each pairs a store URI
    /// (`None` = default provider) with the planned secrets fetched together.
    /// Derived from each secret's [`Route::primary`] on demand, so grouping
    /// can never drift from the routes.
    pub(crate) fn groups(&self) -> Vec<(Option<&str>, Vec<&PlannedSecret>)> {
        let mut groups: Vec<(Option<&str>, Vec<&PlannedSecret>)> = Vec::new();
        let mut group_index: HashMap<Option<&str>, usize> = HashMap::new();
        for secret in &self.secrets {
            let primary = secret.route.primary();
            match group_index.get(&primary) {
                Some(&idx) => groups[idx].1.push(secret),
                None => {
                    group_index.insert(primary, groups.len());
                    groups.push((primary, vec![secret]));
                }
            }
        }
        groups
    }
}

impl Secrets {
    /// Resolve a whole profile into an immutable [`ResolutionPlan`] without any
    /// I/O: merge the profile, compute each secret's effective config, and
    /// derive its resolved route.
    ///
    /// The explicit provider override (builder or `SECRETSPEC_PROVIDER`) is
    /// picked up via [`Secrets::resolve_provider_override`]. Production code
    /// resolves the profile itself and calls [`Secrets::build_plan_from_names`]
    /// directly (it needs the sorted names for audit attribution too, and
    /// shouldn't merge and sort twice); this one-call form is for tests that
    /// don't.
    #[cfg(test)]
    pub(crate) fn build_plan(&self, profile: Option<&str>) -> Result<ResolutionPlan> {
        let profile_name = self.resolve_profile_name(profile);
        let names = self
            .resolve_profile(Some(&profile_name))?
            .sorted_secret_names();
        self.build_plan_from_names(profile_name, names)
    }

    /// As [`Secrets::build_plan`], but for a caller that has already resolved
    /// the profile and its sorted secret names for another purpose (e.g.
    /// attributing an audit event before planning can fail) and would otherwise
    /// redo that work a second time. Sorted names keep planning deterministic
    /// (grouping order, missing lists) rather than inheriting the profile's
    /// `HashMap` iteration order.
    pub(crate) fn build_plan_from_names(
        &self,
        profile_name: String,
        names: Vec<String>,
    ) -> Result<ResolutionPlan> {
        let override_uri = self.resolve_provider_override(None);

        let mut secrets = Vec::with_capacity(names.len());
        for name in names {
            let config = self
                .resolve_secret_config(&name, Some(&profile_name))
                .expect("secret resolved from the merged profile always has a config");
            secrets.push(self.plan_one_secret(name, config, &override_uri)?);
        }

        Ok(ResolutionPlan {
            profile: profile_name,
            override_uri,
            secrets,
        })
    }

    /// Plan a single secret the CLI's `get`/`set` operate on, reusing the exact
    /// per-secret decisions batch resolution makes. Returns `Ok(None)` when the
    /// secret is not declared in the (merged) profile, mirroring
    /// [`Secrets::resolve_secret_config`], so the caller can raise its own
    /// "not found" error and audit it.
    ///
    /// `profile_name` is the already-resolved profile. `override_arg` is the
    /// caller's explicit provider (the `--provider` flag); like
    /// [`Secrets::build_plan`] it also picks up the builder and
    /// `SECRETSPEC_PROVIDER` via [`Secrets::resolve_provider_override`].
    pub(crate) fn plan_secret(
        &self,
        name: &str,
        profile_name: &str,
        override_arg: Option<&str>,
    ) -> Result<Option<PlannedSecret>> {
        let Some(config) = self.resolve_secret_config(name, Some(profile_name)) else {
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
    /// whole-profile [`Secrets::build_plan_from_names`] and the single-secret
    /// [`Secrets::plan_secret`], so `get`, `set`, and batch validation cannot
    /// drift.
    fn plan_one_secret(
        &self,
        name: String,
        config: Secret,
        override_uri: &Option<String>,
    ) -> Result<PlannedSecret> {
        let route = self.route_for(&config, override_uri)?;
        Ok(PlannedSecret {
            name,
            config,
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
            return Ok(Route {
                primary: Some(uri.clone()),
                fallback: Vec::new(),
            });
        }
        match config.providers.as_deref() {
            Some([first, fallback @ ..]) => Ok(Route {
                primary: Some(self.resolve_one_provider(first)?),
                fallback: fallback.to_vec(),
            }),
            _ => Ok(Route {
                primary: None,
                fallback: Vec::new(),
            }),
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

    /// The plan's groups as (primary store, secret names) for easy assertion.
    fn group_names<'a>(plan: &'a ResolutionPlan) -> Vec<(Option<&'a str>, Vec<&'a str>)> {
        plan.groups()
            .into_iter()
            .map(|(uri, group)| (uri, group.iter().map(|s| s.name.as_str()).collect()))
            .collect()
    }

    #[test]
    fn no_routing_plans_the_default_store() {
        let _env = scrub_resolution_env();
        let secrets = HashMap::from([("DATABASE_URL".to_string(), secret(None))]);
        let plan = plan(&spec(secrets, None, &[]));

        let planned = find(&plan, "DATABASE_URL");
        assert_eq!(planned.route.primary(), None);
        assert!(planned.route.fallback.is_empty());
        assert_eq!(group_names(&plan), vec![(None, vec!["DATABASE_URL"])]);
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
        assert_eq!(planned.route.primary(), Some("dotenv://.env.mock"));
        assert!(
            planned.route.fallback.is_empty(),
            "the override must collapse the chain: no fallback survives"
        );
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

        // The primary is resolved to its URI; the fallback stays as the raw
        // alias, resolved only if the primary misses at read time.
        let planned = find(&plan, "API_KEY");
        assert_eq!(planned.route.primary(), Some("onepassword://Shared"));
        assert_eq!(planned.route.fallback, vec!["kr".to_string()]);
    }

    #[test]
    fn an_undefined_fallback_alias_does_not_fail_the_plan() {
        let _env = scrub_resolution_env();
        // The chain is tried in order: a broken link after the primary must not
        // fail planning, since a live primary may never reach it.
        let secrets = HashMap::from([("API_KEY".to_string(), secret(Some(vec!["kr", "ghost"])))]);
        let plan = plan(&spec(secrets, None, &[("kr", "keyring://")]));

        let planned = find(&plan, "API_KEY");
        assert_eq!(planned.route.primary(), Some("keyring://"));
        // The undefined alias is carried raw, not resolved (which would error).
        assert_eq!(planned.route.fallback, vec!["ghost".to_string()]);
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
    fn a_ref_addresses_native_coordinates_convention_otherwise() {
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

        match find(&plan, "REFERENCED").as_address("proj", "default") {
            Address::Native(native) => {
                assert_eq!(native.item, "db");
                assert_eq!(native.field.as_deref(), Some("password"));
            }
            Address::Convention { .. } => panic!("a ref should address native coordinates"),
        }
        match find(&plan, "PLAIN").as_address("proj", "default") {
            Address::Convention { key, .. } => assert_eq!(key, "PLAIN"),
            Address::Native(_) => panic!("no ref should address the naming convention"),
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
            group_names(&plan),
            vec![(None, vec!["A"]), (Some("keyring://"), vec!["B", "C"])]
        );
    }

    #[test]
    fn plan_secret_is_none_for_an_undeclared_secret() {
        let _env = scrub_resolution_env();
        let secrets = HashMap::from([("DECLARED".to_string(), secret(None))]);
        let spec = spec(secrets, None, &[]);
        assert!(
            spec.plan_secret("NOPE", "default", None).unwrap().is_none(),
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

        let one = spec
            .plan_secret("API_KEY", "default", None)
            .unwrap()
            .unwrap();
        assert_eq!(one.route.primary(), Some("onepassword://Production"));
        assert_eq!(one.route.fallback, vec!["keyring://".to_string()]);

        // Same route the whole-profile plan derives.
        let batch = plan(&spec);
        assert_eq!(one.route.primary(), find(&batch, "API_KEY").route.primary());
    }
}
