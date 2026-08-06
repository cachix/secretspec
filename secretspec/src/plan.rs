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
//! Building a plan performs no store I/O. Provider-spec resolution is a map
//! lookup plus provider configuration parsing; cached routes also reconstruct
//! canonical provider URIs so equivalent spellings cannot disguise a cache as
//! its own authoritative store. A plan never reads or writes a secret.

use crate::composition::Template;
use crate::config::{NativeAddress, Secret, SecretEncoding, SecretExtract};
use crate::error::{Result, SecretSpecError};
use crate::manifest::CompiledSecret;
use crate::provider::OwnedAddress;
use crate::secrets::Secrets;
use std::collections::HashMap;

/// The resolved primary store: the raw spec used to build it, plus its resolved
/// URI for display.
///
/// Construction and grouping key on [`spec`](Self::spec) rather than the URI so
/// that an alias's `credentials` map is still reachable when the provider is
/// built (a resolved URI is not an alias and has lost it), and so two aliases
/// that happen to share a URI but declare different credentials never merge into
/// one group.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ResolvedPrimary {
    /// The raw primary chain entry: an alias name, a bare provider name, or a
    /// URI. The build key.
    pub spec: String,
    /// The resolved, credential-free URI, for display and the resolution report.
    pub uri: String,
}

/// The leaf store and freshness policy for a cached provider route.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ResolvedCache {
    /// Raw provider spec, retained so alias credentials remain available.
    pub spec: String,
    /// Credential-free resolved URI, used for diagnostics and provenance.
    pub uri: String,
    /// Freshness window in seconds.
    pub max_age_secs: u64,
    /// Stable fingerprint of the expanded authoritative provider route.
    pub route_fingerprint: String,
}

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
    pub primary: Option<ResolvedPrimary>,
    /// The chain's remaining specs (aliases or URIs), raw, tried in order —
    /// and resolved — only after the primary misses.
    pub fallback: Vec<String>,
    /// Local cache consulted before the authoritative route, when configured.
    pub cache: Option<ResolvedCache>,
}

impl Route {
    /// The resolved, credential-free URI of the store consulted first, `None`
    /// meaning the default provider. Used for display and the resolution report,
    /// never as the grouping/build key — see [`Route::group_key`].
    pub(crate) fn primary(&self) -> Option<&str> {
        self.primary.as_ref().map(|primary| primary.uri.as_str())
    }

    /// The raw primary spec that groups secrets and builds the store, `None`
    /// meaning the default provider. Distinct from [`Route::primary`] (the
    /// resolved URI): secrets sharing a primary store are fetched together and a
    /// write goes to the primary, and keying on the spec keeps an alias's
    /// `credentials` reachable at build time.
    pub(crate) fn group_key(&self) -> Option<&str> {
        self.primary.as_ref().map(|primary| primary.spec.as_str())
    }

    /// The raw fallback specs a read walks after the primary misses, when
    /// there are any. `None` means the read may consult only one store —
    /// [`Route::primary`], with `None` meaning the default provider — so no
    /// other store could answer instead.
    pub(crate) fn fallback_specs(&self) -> Option<&[String]> {
        (!self.fallback.is_empty()).then_some(self.fallback.as_slice())
    }

    /// The ordered provider specs a read walks — the primary spec followed by
    /// the raw fallback — or `None` for the default provider. Each entry is
    /// resolved (and credential-backed) only when the read reaches it, so the chain
    /// is genuinely tried in order.
    pub(crate) fn specs(&self) -> Option<Vec<String>> {
        self.primary.as_ref().map(|primary| {
            let mut specs = Vec::with_capacity(1 + self.fallback.len());
            specs.push(primary.spec.clone());
            specs.extend(self.fallback.iter().cloned());
            specs
        })
    }

    /// Cache policy for this route, if its provider alias enables caching.
    pub(crate) fn cache(&self) -> Option<&ResolvedCache> {
        self.cache.as_ref()
    }
}

/// Everything decided for one declared secret, ready to execute.
#[derive(Debug)]
pub(crate) struct PlannedSecret {
    /// The declared secret name (the manifest's `UPPER_SNAKE` key).
    pub name: String,
    /// The compiled effective secret: its merged config, missing-value policy,
    /// required marker, and parsed composition travel together so they cannot
    /// fall out of sync.
    pub secret: CompiledSecret,
    /// The resolved read/write route, or `None` for a composed secret: its
    /// value is derived from other secrets, so there is no store to consult
    /// and consumers must decide what a routeless secret means for them.
    pub route: Option<Route>,
}

impl PlannedSecret {
    /// The secret's effective config after the profile field-level merge.
    pub(crate) fn config(&self) -> &Secret {
        &self.secret.config
    }

    /// The native `ref` coordinates this secret addresses, if any.
    pub(crate) fn reference(&self) -> Option<&NativeAddress> {
        self.secret.config.reference.as_ref()
    }

    /// Fingerprint stored in this secret's cache entry, over everything that
    /// decides what the authoritative route would answer: the project and
    /// profile, the expanded route, the secret's name, and its native
    /// coordinates. A change to any of them invalidates the entry. Project and
    /// profile are included even though they are also passed in the cache
    /// address, because flat stores such as dotenv discard that namespace.
    pub(crate) fn cache_fingerprint(
        &self,
        cache: &ResolvedCache,
        project: &str,
        profile: &str,
    ) -> String {
        let address = if let Some(reference) = self.reference() {
            coordinate_fingerprint("legacy-ref", reference.coordinates())
        } else if let Some(references) = &self.config().refs {
            let mut entries = references.iter().collect::<Vec<_>>();
            entries.sort_by_key(|(alias, _)| alias.as_str());
            let mut fingerprints = vec!["scoped-refs".to_string()];
            fingerprints.extend(entries.into_iter().map(|(alias, reference)| {
                let coordinates = coordinate_fingerprint("native-ref", reference.coordinates());
                stable_fingerprint(["scoped-ref", alias.as_str(), coordinates.as_str()])
            }));
            stable_fingerprint(fingerprints.iter().map(String::as_str))
        } else {
            "convention".to_string()
        };
        stable_fingerprint([
            project,
            profile,
            cache.route_fingerprint.as_str(),
            self.name.as_str(),
            address.as_str(),
        ])
    }

    /// Whether the active profile treats this secret as required: its compiled
    /// `required` marker (an omitted `required` counts as required unless the
    /// secret carries a default).
    pub(crate) fn required(&self) -> bool {
        self.secret.declared_required
    }

    /// Whether the value is materialized to a temp file and exposed as a path.
    pub(crate) fn as_path(&self) -> bool {
        self.secret.config.as_path.unwrap_or(false)
    }

    /// Optional encoding applied at the storage boundary.
    pub(crate) fn encoding(&self) -> Option<SecretEncoding> {
        self.secret.config.encoding
    }

    /// Optional structured extraction applied at the storage boundary.
    pub(crate) fn extract(&self) -> Option<&SecretExtract> {
        self.secret.config.extract.as_ref()
    }

    pub(crate) fn is_composed(&self) -> bool {
        self.secret.composition.is_some()
    }

    /// The parsed derived-value template, for composed secrets.
    pub(crate) fn composition(&self) -> Option<&Template> {
        self.secret.composition.as_ref()
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
    /// Primary-store groups in first-seen order: each pairs a primary spec
    /// (`None` = default provider) with the planned secrets fetched together.
    /// Derived from each secret's [`Route::group_key`] on demand, so grouping
    /// can never drift from the routes. Keying on the spec (not the resolved
    /// URI) keeps an alias's `credentials` reachable at build time and keeps
    /// two aliases that share a URI but differ in credentials in separate groups.
    pub(crate) fn groups(&self) -> Vec<(Option<&str>, Vec<&PlannedSecret>)> {
        let mut groups: Vec<(Option<&str>, Vec<&PlannedSecret>)> = Vec::new();
        let mut group_index: HashMap<Option<&str>, usize> = HashMap::new();
        for secret in &self.secrets {
            // Composed secrets have no route, so nothing fetches them.
            let Some(route) = &secret.route else {
                continue;
            };
            let primary = route.group_key();
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
    /// Resolve one secret's address for one concrete provider endpoint.
    ///
    /// Legacy `ref` remains route-wide. The 0.19+ scoped model is deliberately
    /// different: a concrete `refs.<alias>` wins for that alias, then the
    /// alias's ref template, then the provider's ordinary convention address.
    /// Literal provider specs have no alias identity and therefore use
    /// convention naming. `ref` and `refs` are rejected together by config
    /// validation, so these two modes never merge implicitly.
    pub(crate) fn address_for_spec(
        &self,
        planned: &PlannedSecret,
        provider_spec: Option<&str>,
        project: &str,
        profile: &str,
    ) -> Result<OwnedAddress> {
        if let Some(reference) = planned.reference() {
            return Ok(OwnedAddress::Native(reference.clone()));
        }

        let effective_spec = provider_spec
            .map(str::to_string)
            .or_else(|| self.configured_default_provider_spec());
        if let Some(spec) = effective_spec.as_deref()
            && let Some(alias) = self.lookup_provider_alias_entry(spec)
            && !alias.is_cached()
        {
            if let Some(reference) = planned
                .config()
                .refs
                .as_ref()
                .and_then(|refs| refs.get(spec))
            {
                return Ok(OwnedAddress::Native(reference.clone()));
            }
            if let Some(template) = alias.reference_template() {
                let reference = template.expand(project, profile, &planned.name).map_err(|error| {
                    SecretSpecError::ProviderOperationFailed(format!(
                        "provider alias '{spec}' could not expand its ref template for '{}': {error}",
                        planned.name
                    ))
                })?;
                return Ok(OwnedAddress::Native(reference));
            }
        }

        Ok(OwnedAddress::convention(project, profile, &planned.name))
    }

    /// Validate all provider-scoped refs on a secret, including source-only
    /// aliases used later by `import`. Validation belongs in planning because
    /// user-global aliases are unavailable to the standalone `Config` parser.
    fn validate_scoped_refs(&self, name: &str, secret: &Secret) -> Result<()> {
        let Some(references) = &secret.refs else {
            return Ok(());
        };
        for alias_name in references.keys() {
            let Some(alias) = self.lookup_provider_alias_entry(alias_name) else {
                return Err(SecretSpecError::ProviderNotFound(format!(
                    "Secret '{name}' defines `refs.{alias_name}`, but provider alias '{alias_name}' is not defined"
                )));
            };
            if alias.is_cached() {
                return Err(SecretSpecError::ProviderOperationFailed(format!(
                    "Secret '{name}' defines `refs.{alias_name}`, but '{alias_name}' is a cached route; scoped refs must name leaf provider aliases"
                )));
            }
        }
        Ok(())
    }

    /// Resolve a whole profile into an immutable [`ResolutionPlan`] without any
    /// I/O: merge the profile, compute each secret's effective config, and
    /// derive its resolved route.
    ///
    /// The explicit provider override (builder or `SECRETSPEC_PROVIDER`) is
    /// picked up via [`Secrets::explicit_provider_spec`]. Production code
    /// resolves the profile itself and calls [`Secrets::build_plan_from_names`]
    /// directly (it needs the sorted names for audit attribution too, and
    /// shouldn't merge and sort twice); this one-call form is for tests that
    /// don't.
    #[cfg(test)]
    pub(crate) fn build_plan(&self, profile: Option<&str>) -> Result<ResolutionPlan> {
        let profile_name = self.resolve_profile_name(profile);
        let names = self.resolve_profile_secret_names(Some(&profile_name))?;
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
        // Routes carry the raw override spec (it may be an alias whose provider
        // `env` must stay reachable at build time); the plan's `override_uri`
        // field is the resolved form, for display and the resolution report.
        let override_spec = self.explicit_provider_spec(None);

        let mut secrets = Vec::with_capacity(names.len());
        let profile = self
            .manifest
            .profile(&profile_name)
            .expect("profile names are validated before planning");
        for name in names {
            let secret = profile
                .secrets
                .get(&name)
                .expect("planned names come from the compiled profile");
            secrets.push(self.plan_one_secret(name, secret, &override_spec)?);
        }

        let override_uri = override_spec
            .as_deref()
            .map(|spec| self.override_display_uri(spec))
            .transpose()?;

        Ok(ResolutionPlan {
            profile: profile_name,
            override_uri,
            secrets,
        })
    }

    /// Plan a single secret the CLI's `get`/`set`/`delete` operate on, reusing the exact
    /// per-secret decisions batch resolution makes. Returns `Ok(None)` when the
    /// secret is not declared in the (merged) profile, mirroring
    /// [`Secrets::resolve_secret_config`], so the caller can raise its own
    /// "not found" error and audit it.
    ///
    /// `profile_name` is the already-resolved profile. `override_arg` is the
    /// caller's explicit provider (the `--provider` flag); like
    /// [`Secrets::build_plan`] it also picks up the builder and
    /// `SECRETSPEC_PROVIDER` via [`Secrets::explicit_provider_spec`].
    pub(crate) fn plan_secret(
        &self,
        name: &str,
        profile_name: &str,
        override_arg: Option<&str>,
    ) -> Result<Option<PlannedSecret>> {
        let override_spec = self.explicit_provider_spec(override_arg);
        self.plan_one(name, profile_name, &override_spec)
    }

    /// As [`Secrets::plan_secret`], but ignoring every provider override —
    /// `--provider`, the builder, and `SECRETSPEC_PROVIDER`.
    ///
    /// Cache maintenance needs the route the manifest *declares*, not the one an
    /// override redirected this command to: an override collapses the route to a
    /// single store and drops its cache, so planning with one would leave the
    /// entry that override bypassed in place.
    pub(crate) fn plan_declared_secret(
        &self,
        name: &str,
        profile_name: &str,
    ) -> Result<Option<PlannedSecret>> {
        self.plan_one(name, profile_name, &None)
    }

    /// Plan one declared secret against an already-decided override spec.
    /// `Ok(None)` when the secret is not declared in the (merged) profile.
    fn plan_one(
        &self,
        name: &str,
        profile_name: &str,
        override_spec: &Option<String>,
    ) -> Result<Option<PlannedSecret>> {
        let Some(secret) = self
            .manifest
            .profile(profile_name)
            .and_then(|profile| profile.secrets.get(name))
        else {
            return Ok(None);
        };
        Ok(Some(self.plan_one_secret(
            name.to_string(),
            secret,
            override_spec,
        )?))
    }

    /// Derive one [`PlannedSecret`] from its effective config and the raw
    /// override spec. The single place per-secret decisions are made, shared by
    /// the whole-profile [`Secrets::build_plan_from_names`] and the
    /// single-secret [`Secrets::plan_secret`], so `get`, `set`, and batch
    /// validation cannot drift.
    fn plan_one_secret(
        &self,
        name: String,
        secret: &CompiledSecret,
        override_spec: &Option<String>,
    ) -> Result<PlannedSecret> {
        self.validate_scoped_refs(&name, &secret.config)?;
        // A composed secret's value is derived by the executor, so it routes
        // to no store, including an explicit `--provider` override.
        let route = if secret.composition.is_some() {
            None
        } else {
            Some(self.route_for(&secret.config, override_spec)?)
        };
        Ok(PlannedSecret {
            name,
            secret: secret.clone(),
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
        override_spec: &Option<String>,
    ) -> Result<Route> {
        // Either arm keeps the raw spec as the build key (the spec may be an
        // alias whose `credentials` must stay reachable when the store is
        // constructed — a resolved URI has lost it), resolves the URI for
        // display, and validates any `credentials` (unknown source, one-hop)
        // up front — all pure map lookups.
        if let Some(spec) = override_spec {
            if let Some(alias) = self.cached_alias(spec) {
                return self.cached_route(spec, alias);
            }
            self.validate_credential_sources(spec)?;
            return Ok(Route {
                primary: Some(ResolvedPrimary {
                    spec: spec.clone(),
                    uri: self.resolve_provider_spec(spec.clone()),
                }),
                fallback: Vec::new(),
                cache: None,
            });
        }
        match config.providers.as_deref() {
            Some([first, fallback @ ..]) => {
                // A cached alias expands into a whole route — sources, order,
                // and cache — so it cannot also be one link of a chain, in any
                // position. Were a later position accepted, the chain walk would
                // fail to resolve it, warn, and silently continue without the
                // cache or its sources, and writes would go to the wrong store.
                if let Some(spec) = std::iter::once(first)
                    .chain(fallback)
                    .find(|spec| self.cached_alias(spec).is_some())
                {
                    if !fallback.is_empty() {
                        return Err(SecretSpecError::ProviderOperationFailed(format!(
                            "cached provider alias '{spec}' is a complete route and cannot be \
                             combined with additional entries in a secret's providers list"
                        )));
                    }
                    let alias = self
                        .cached_alias(spec)
                        .expect("the spec was just found to be a cached alias");
                    return self.cached_route(spec, alias);
                }
                // Unlike an override, an undefined alias as chain primary is a
                // hard error here (`resolve_one_provider` fails fast).
                let uri = self.resolve_one_provider(first)?;
                self.validate_credential_sources(first)?;
                Ok(Route {
                    primary: Some(ResolvedPrimary {
                        spec: first.clone(),
                        uri,
                    }),
                    fallback: fallback.to_vec(),
                    cache: None,
                })
            }
            _ => {
                if let Some(spec) = self.configured_default_provider_spec()
                    && let Some(alias) = self.cached_alias(&spec)
                {
                    return self.cached_route(&spec, alias);
                }
                Ok(Route {
                    primary: None,
                    fallback: Vec::new(),
                    cache: None,
                })
            }
        }
    }

    /// Expand a cached alias into its authoritative route plus cache policy.
    ///
    /// Cached aliases deliberately cannot be nested: every fallback and the
    /// cache provider must be a leaf provider spec. This keeps the read/write
    /// target and cache invalidation semantics obvious and prevents cycles.
    ///
    /// Shape validation (a non-empty source list, a parseable `max_age`) lives
    /// in [`crate::config::ProviderAlias::cached`] and
    /// [`crate::config::ProviderCache::new`]. Their validated fields are
    /// immutable after construction; expansion here resolves specs and rejects
    /// what needs the whole config to see: nesting, and a cache sharing a store
    /// with its own sources.
    fn cached_route(&self, name: &str, alias: &crate::config::ProviderAlias) -> Result<Route> {
        let cache = alias.cache().ok_or_else(|| {
            SecretSpecError::ProviderOperationFailed(format!(
                "provider alias '{name}' does not declare a cache policy"
            ))
        })?;

        if alias.authoritative_uri().is_some() && !alias.fallback().is_empty() {
            return Err(SecretSpecError::ProviderOperationFailed(format!(
                "cached provider alias '{name}' cannot declare both uri and fallback"
            )));
        }

        // A cache provider is always a leaf. Explicit fallback entries are too;
        // the inline form names its own leaf URI and is handled below without
        // treating the alias as nested inside itself.
        for spec in alias
            .fallback()
            .iter()
            .map(String::as_str)
            .chain(std::iter::once(cache.provider()))
        {
            if self.cached_alias(spec).is_some() {
                return Err(SecretSpecError::ProviderOperationFailed(format!(
                    "cached provider alias '{name}' cannot use cached alias '{spec}' as a \
                     fallback or cache provider; cached aliases may contain only leaf providers"
                )));
            }
        }

        // The inline form builds under the alias name itself, so the alias's
        // credentials apply; its label in errors is the authoritative URI.
        let (source_specs, source_uris) = if let Some(uri) = alias.authoritative_uri() {
            self.validate_credential_sources(name)?;
            (
                vec![name.to_string()],
                vec![self.resolve_one_provider(uri)?],
            )
        } else {
            let mut source_uris = Vec::with_capacity(alias.fallback().len());
            for spec in alias.fallback() {
                source_uris.push(self.resolve_one_provider(spec)?);
                self.validate_credential_sources(spec)?;
            }
            (alias.fallback().to_vec(), source_uris)
        };
        let cache_uri = self.resolve_one_provider(cache.provider())?;
        self.validate_credential_sources(cache.provider())?;

        let source_identities = source_uris
            .iter()
            .map(|uri| self.canonical_storage_identity(uri))
            .collect::<Result<Vec<_>>>()?;
        let source_route_uris = source_uris
            .iter()
            .map(|uri| self.canonical_provider_uri(uri))
            .collect::<Result<Vec<_>>>()?;
        let source_route_fingerprints = alias
            .fallback()
            .iter()
            .zip(&source_route_uris)
            .map(|(spec, uri)| {
                let template = self
                    .lookup_provider_alias_entry(spec)
                    .and_then(|alias| alias.reference_template())
                    .map(|template| coordinate_fingerprint("ref-template", template.coordinates()))
                    .unwrap_or_else(|| "convention".to_string());
                stable_fingerprint(["source-route", spec, uri, template.as_str()])
            })
            .collect::<Vec<_>>();
        let cache_identity = self.canonical_storage_identity(&cache_uri)?;

        // The cache entry lives at the same logical address the authoritative
        // read asks for, so a cache pointed at one of its own sources would
        // overwrite the secret with the cache envelope the first time it
        // refreshed, and then serve that envelope back as the value. Compare
        // provider-reconstructed storage identities after applying the project
        // base directory:
        // raw specs such as `dotenv:.env` and `dotenv://.env` are different
        // strings but identify the same store. Public provider attribution is
        // deliberately not used: two auth methods, or Vault and OpenBao, can
        // address the same physical store through different public URIs.
        if let Some(shared) = source_identities
            .iter()
            .position(|identity| *identity == cache_identity)
        {
            return Err(SecretSpecError::ProviderOperationFailed(format!(
                "cached provider alias '{name}' caches into '{uri}', which is also its \
                 authoritative source '{source}'. A cache must be a distinct store, otherwise \
                 refreshing it overwrites the secret it caches.",
                uri = crate::audit::redact_uri_strict(&cache_uri),
                source = crate::audit::redact_uri_strict(
                    alias
                        .authoritative_uri()
                        .unwrap_or_else(|| alias.fallback()[shared].as_str()),
                ),
            )));
        }

        // Every way a cached value stops being correct ends in deleting the
        // entry: `cache clear`, a refresh that failed, a write that bypassed the
        // route. A store that cannot delete gives an uninvalidatable cache, so
        // require the capability here rather than discovering it the first time
        // a stale value needs dropping.
        if !crate::provider::spec_provider_deletes(&cache_uri) {
            return Err(SecretSpecError::ProviderOperationFailed(format!(
                "cached provider alias '{name}' caches into '{uri}', which cannot delete secrets, \
                 so its entries could never be invalidated. Cache into one of: {supported}.",
                uri = crate::audit::redact_uri_strict(&cache_uri),
                supported = crate::provider::deleting_provider_names().join(", "),
            )));
        }

        let mut specs = source_specs.into_iter();
        let first = specs.next().ok_or_else(|| {
            SecretSpecError::ProviderOperationFailed(format!(
                "cached provider alias '{name}' requires at least one authoritative source"
            ))
        })?;
        Ok(Route {
            primary: Some(ResolvedPrimary {
                spec: first,
                uri: source_uris[0].clone(),
            }),
            fallback: specs.collect(),
            cache: Some(ResolvedCache {
                spec: cache.provider().to_string(),
                uri: cache_uri,
                max_age_secs: cache.max_age_secs(),
                route_fingerprint: stable_fingerprint(
                    source_route_fingerprints.iter().map(String::as_str),
                ),
            }),
        })
    }

    /// Reconstruct a provider's public canonical URI without resolving its
    /// credentials or touching the store. Unlike its storage identity, this URI
    /// retains configuration that can change what the authoritative route
    /// answers and must therefore invalidate cached values.
    fn canonical_provider_uri(&self, uri: &str) -> Result<String> {
        let mut provider =
            crate::provider::provider_from_spec(uri, crate::provider::ProviderCredentials::new())?;
        provider.with_base_dir(&self.config_dir);
        Ok(provider.uri())
    }

    /// Reconstruct a provider's physical storage identity without resolving its
    /// credentials or touching the store. Provider implementations normalize
    /// shorthand, defaults, percent encoding, relative filesystem paths, and
    /// compatible public provider spellings in this identity.
    fn canonical_storage_identity(&self, uri: &str) -> Result<String> {
        let mut provider =
            crate::provider::provider_from_spec(uri, crate::provider::ProviderCredentials::new())?;
        provider.with_base_dir(&self.config_dir);
        Ok(provider.storage_identity())
    }

    /// The URI to report for an explicit provider override.
    ///
    /// A cached alias is a route, not a store, so it has no URI of its own: name
    /// the store a read consults first. This is what lands in the resolution
    /// report, `--json`, and the SDK `provider` field, so it must never be a
    /// bare alias name.
    pub(crate) fn override_display_uri(&self, spec: &str) -> Result<String> {
        match self.cached_alias(spec) {
            Some(alias) => {
                if let Some(uri) = alias.authoritative_uri() {
                    return self.resolve_one_provider(uri);
                }
                let first = alias.fallback().first().ok_or_else(|| {
                    SecretSpecError::ProviderOperationFailed(format!(
                        "cached provider alias '{spec}' requires at least one authoritative source"
                    ))
                })?;
                self.resolve_one_provider(first)
            }
            None => Ok(self.resolve_provider_spec(spec.to_string())),
        }
    }
}

/// Deterministic, dependency-free fingerprint used only for cache invalidation.
fn stable_fingerprint<'a>(parts: impl IntoIterator<Item = &'a str>) -> String {
    let mut hash = 0xcbf29ce484222325_u64;
    for part in parts {
        for byte in part.len().to_le_bytes().iter().chain(part.as_bytes()) {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(0x100000001b3);
        }
    }
    format!("v1-{hash:016x}")
}

/// Fingerprint native coordinates without routing them through their
/// human-readable rendering. Each coordinate name, presence marker, and value
/// is a separately length-delimited hash part, so delimiter-like text inside an
/// item cannot collide with a real adjacent coordinate.
fn coordinate_fingerprint<'a>(
    kind: &'static str,
    coordinates: impl IntoIterator<Item = (&'static str, Option<&'a str>)>,
) -> String {
    let mut parts = vec![kind];
    for (name, value) in coordinates {
        parts.push(name);
        match value {
            Some(value) => {
                parts.push("present");
                parts.push(value);
            }
            None => parts.push("absent"),
        }
    }
    stable_fingerprint(parts)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{NativeAddressTemplate, ProviderAlias, ProviderCache};
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

    /// The provider route a non-composed planned secret must carry.
    fn route(planned: &PlannedSecret) -> &Route {
        planned.route.as_ref().expect("a provider route")
    }

    /// The plan's groups as (primary store, secret names) for easy assertion.
    fn group_names(plan: &ResolutionPlan) -> Vec<(Option<&str>, Vec<&str>)> {
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
        assert_eq!(route(planned).primary(), None);
        assert!(route(planned).fallback.is_empty());
        assert_eq!(group_names(&plan), vec![(None, vec!["DATABASE_URL"])]);
    }

    #[test]
    fn composed_secrets_have_no_provider_route_or_fetch_group() {
        let _env = scrub_resolution_env();
        let secrets = HashMap::from([
            ("PART".to_string(), secret(None)),
            (
                "RESULT".to_string(),
                Secret {
                    description: Some("derived".to_string()),
                    composed: Some("prefix-${PART}".to_string()),
                    ..Default::default()
                },
            ),
        ]);
        let plan = plan(&spec(secrets, Some("dotenv://.env.mock"), &[]));

        assert!(find(&plan, "RESULT").is_composed());
        assert!(find(&plan, "RESULT").route.is_none());
        assert_eq!(
            group_names(&plan),
            vec![(Some("dotenv://.env.mock"), vec!["PART"])]
        );
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
        assert_eq!(route(planned).primary(), Some("dotenv://.env.mock"));
        assert!(
            route(planned).fallback.is_empty(),
            "the override must collapse the chain: no fallback survives"
        );
        assert_eq!(plan.override_uri, Some("dotenv://.env.mock".to_string()));
    }

    #[test]
    fn override_alias_keeps_the_raw_spec_as_build_key() {
        let _env = scrub_resolution_env();
        let secrets = HashMap::from([("API_KEY".to_string(), secret(None))]);
        // `--provider mock` names an alias: the route keeps the raw spec so the
        // alias's `credentials` stays reachable at build time, and resolves
        // the URI for display and the report.
        let spec = spec(secrets, Some("mock"), &[("mock", "dotenv://.env.mock")]);
        let plan = plan(&spec);

        let planned = find(&plan, "API_KEY");
        assert_eq!(route(planned).group_key(), Some("mock"));
        assert_eq!(route(planned).primary(), Some("dotenv://.env.mock"));
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
        assert_eq!(route(planned).primary(), Some("onepassword://Shared"));
        assert_eq!(route(planned).fallback, vec!["kr".to_string()]);
    }

    #[test]
    fn an_undefined_fallback_alias_does_not_fail_the_plan() {
        let _env = scrub_resolution_env();
        // The chain is tried in order: a broken link after the primary must not
        // fail planning, since a live primary may never reach it.
        let secrets = HashMap::from([("API_KEY".to_string(), secret(Some(vec!["kr", "ghost"])))]);
        let plan = plan(&spec(secrets, None, &[("kr", "keyring://")]));

        let planned = find(&plan, "API_KEY");
        assert_eq!(route(planned).primary(), Some("keyring://"));
        // The undefined alias is carried raw, not resolved (which would error).
        assert_eq!(route(planned).fallback, vec!["ghost".to_string()]);
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
        assert_eq!(route(planned).primary(), Some("onepassword://Production"));
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

        assert_eq!(route(find(&plan, "API_KEY")).primary(), Some("keyring"));
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
        let spec = spec(secrets, None, &[]);
        let plan = plan(&spec);
        let referenced = find(&plan, "REFERENCED");
        let referenced_address = spec
            .address_for_spec(
                referenced,
                referenced.route.as_ref().and_then(Route::group_key),
                "proj",
                "default",
            )
            .unwrap();
        match referenced_address {
            OwnedAddress::Native(native) => {
                assert_eq!(native.item, "db");
                assert_eq!(native.field.as_deref(), Some("password"));
            }
            OwnedAddress::Convention { .. } => {
                panic!("a ref should address native coordinates")
            }
        }
        let plain = find(&plan, "PLAIN");
        let plain_address = spec
            .address_for_spec(
                plain,
                plain.route.as_ref().and_then(Route::group_key),
                "proj",
                "default",
            )
            .unwrap();
        match plain_address {
            OwnedAddress::Convention { key, .. } => assert_eq!(key, "PLAIN"),
            OwnedAddress::Native(_) => panic!("no ref should address the naming convention"),
        }
    }

    #[test]
    fn endpoint_address_prefers_scoped_ref_then_alias_template_then_convention() {
        let _env = scrub_resolution_env();
        let mut configured = secret(Some(vec!["local"]));
        configured.refs = Some(HashMap::from([(
            "remote".to_string(),
            NativeAddress {
                item: "legacy-source".to_string(),
                field: Some("token".to_string()),
                ..Default::default()
            },
        )]));
        let mut config =
            crate::tests::resolve_test_config(HashMap::from([("API_KEY".to_string(), configured)]));
        config.providers = Some(HashMap::from([
            (
                "remote".to_string(),
                ProviderAlias::from("onepassword://Production"),
            ),
            (
                "local".to_string(),
                ProviderAlias::from("dotenv://.env")
                    .with_reference_template(NativeAddressTemplate {
                        item: "{project}_{profile}_{key}".to_string(),
                        ..Default::default()
                    })
                    .unwrap(),
            ),
        ]));
        let spec = Secrets::new(config, None, None, None);

        let plan = spec.build_plan(None).unwrap();
        let planned = find(&plan, "API_KEY");
        assert_eq!(
            spec.address_for_spec(planned, Some("remote"), "app", "prod")
                .unwrap(),
            OwnedAddress::Native(NativeAddress {
                item: "legacy-source".to_string(),
                field: Some("token".to_string()),
                ..Default::default()
            })
        );
        assert_eq!(
            spec.address_for_spec(planned, Some("local"), "app", "prod")
                .unwrap(),
            OwnedAddress::Native(NativeAddress {
                item: "app_prod_API_KEY".to_string(),
                ..Default::default()
            })
        );
        assert_eq!(
            spec.address_for_spec(planned, Some("dotenv://other.env"), "app", "prod")
                .unwrap(),
            OwnedAddress::convention("app", "prod", "API_KEY")
        );
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
    fn distinct_aliases_sharing_a_uri_do_not_merge() {
        let _env = scrub_resolution_env();
        let secrets = HashMap::from([
            ("A".to_string(), secret(Some(vec!["one"]))),
            ("B".to_string(), secret(Some(vec!["two"]))),
        ]);
        // Two aliases, same URI, different names: grouping keys on the spec, so
        // they stay in separate groups (they could carry different provider
        // credentials, which the resolved URI has lost).
        let plan = plan(&spec(
            secrets,
            None,
            &[("one", "keyring://"), ("two", "keyring://")],
        ));
        assert_eq!(
            group_names(&plan),
            vec![(Some("one"), vec!["A"]), (Some("two"), vec!["B"])]
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
        // `get`/`set`/`delete` plan one secret; the decision must match `build_plan`.
        let secrets = HashMap::from([(
            "API_KEY".to_string(),
            secret(Some(vec!["onepassword://Production", "keyring://"])),
        )]);
        let spec = spec(secrets, None, &[]);

        let one = spec
            .plan_secret("API_KEY", "default", None)
            .unwrap()
            .unwrap();
        assert_eq!(route(&one).primary(), Some("onepassword://Production"));
        assert_eq!(route(&one).fallback, vec!["keyring://".to_string()]);

        // Same route the whole-profile plan derives.
        let batch = plan(&spec);
        assert_eq!(
            route(&one).primary(),
            route(find(&batch, "API_KEY")).primary()
        );
    }

    /// A cached route alias over the given sources, cached in `cache_spec`.
    fn cached_alias(sources: &[&str], cache_spec: &str, max_age: &str) -> ProviderAlias {
        ProviderAlias::cached(
            sources.iter().map(|s| s.to_string()).collect(),
            ProviderCache::new(cache_spec, max_age).unwrap(),
        )
        .unwrap()
    }

    fn cached_aliases() -> HashMap<String, ProviderAlias> {
        HashMap::from([
            ("azure".to_string(), ProviderAlias::from("akv://team-vault")),
            ("env".to_string(), ProviderAlias::from("env://")),
            ("local".to_string(), ProviderAlias::from("keyring://")),
            (
                "myprovider".to_string(),
                cached_alias(&["azure", "env"], "local", "8h"),
            ),
        ])
    }

    /// A `Secrets` over one `API_KEY` and the cached alias map, with `aliases`
    /// merged in (later entries replacing the defaults).
    fn cached_spec_with(secret_providers: Vec<&str>, aliases: &[(&str, ProviderAlias)]) -> Secrets {
        let mut config = crate::tests::resolve_test_config(HashMap::from([(
            "API_KEY".to_string(),
            secret(Some(secret_providers)),
        )]));
        let mut providers = cached_aliases();
        for (name, alias) in aliases {
            providers.insert(name.to_string(), alias.clone());
        }
        config.providers = Some(providers);
        Secrets::new(config, None, None, None)
    }

    fn cached_spec(secret_providers: Vec<&str>) -> Secrets {
        cached_spec_with(secret_providers, &[])
    }

    #[test]
    fn cached_alias_expands_into_authoritative_route_and_cache() {
        let _env = scrub_resolution_env();
        let plan = plan(&cached_spec(vec!["myprovider"]));
        let route = route(find(&plan, "API_KEY"));

        assert_eq!(route.group_key(), Some("azure"));
        assert_eq!(route.primary(), Some("akv://team-vault"));
        assert_eq!(route.fallback, ["env"]);
        let cache = route.cache().expect("cached route");
        assert_eq!(cache.spec, "local");
        assert_eq!(cache.uri, "keyring://");
        assert_eq!(cache.max_age_secs, 8 * 60 * 60);
    }

    #[test]
    fn inline_cached_uri_keeps_alias_as_the_authoritative_build_key() {
        let _env = scrub_resolution_env();
        let inline = ProviderAlias::from("akv://team-vault")
            .with_cache(ProviderCache::new("local", "5m").expect("valid cache policy"));
        let spec = cached_spec_with(vec!["inline"], &[("inline", inline)]);
        let plan = plan(&spec);
        let route = route(find(&plan, "API_KEY"));

        // The alias remains the build key so inline provider credentials are
        // available when the authoritative provider is constructed.
        assert_eq!(route.group_key(), Some("inline"));
        assert_eq!(route.primary(), Some("akv://team-vault"));
        assert!(route.fallback.is_empty());
        let cache = route.cache().expect("cached route");
        assert_eq!(cache.spec, "local");
        assert_eq!(cache.max_age_secs, 5 * 60);
    }

    #[test]
    fn cached_alias_is_a_complete_route_not_a_chain_link() {
        let _env = scrub_resolution_env();
        // A cached alias is a whole route, so it cannot be a link in a chain in
        // *any* position. Accepting it after the head would silently drop the
        // cache and its sources at read time and point writes at the wrong store.
        for chain in [
            vec!["myprovider", "env"],
            vec!["env", "myprovider"],
            vec!["env", "azure", "myprovider"],
        ] {
            let error = cached_spec(chain.clone()).build_plan(None).unwrap_err();
            assert!(
                error.to_string().contains("complete route"),
                "{chain:?}: {error}"
            );
        }
    }

    #[test]
    fn a_cache_may_not_share_a_store_with_its_authoritative_sources() {
        let _env = scrub_resolution_env();
        // `local` and `mirror` name the same store, and the cache envelope is
        // written at the same address the authoritative read uses, so allowing
        // this would overwrite the real secret with the envelope on the first
        // refresh — and serve the envelope back as the value once it expired.
        let spec = cached_spec_with(
            vec!["myprovider"],
            &[
                ("mirror", ProviderAlias::from("keyring://")),
                (
                    "myprovider",
                    cached_alias(&["azure", "mirror"], "local", "8h"),
                ),
            ],
        );

        let error = spec.build_plan(None).unwrap_err();
        let message = error.to_string();
        assert!(message.contains("distinct store"), "{message}");
        assert!(message.contains("mirror"), "{message}");
    }

    #[test]
    fn same_store_error_redacts_inline_authoritative_credentials() {
        let _env = scrub_resolution_env();
        let source = "vault://team-user:super-sensitive-password@127.0.0.1:8200/secret?tls=false";
        let inline = ProviderAlias::from(source)
            .with_cache(ProviderCache::new(source, "8h").expect("valid cache policy"));
        let spec = cached_spec_with(vec!["route"], &[("route", inline)]);

        let message = spec.build_plan(None).unwrap_err().to_string();
        assert!(message.contains("distinct store"), "{message}");
        assert!(
            message.contains("vault://127.0.0.1:8200/secret"),
            "{message}"
        );
        assert!(!message.contains("team-user"), "{message}");
        assert!(!message.contains("super-sensitive-password"), "{message}");
    }

    #[test]
    fn equivalent_provider_spellings_cannot_bypass_cache_separation() {
        let _env = scrub_resolution_env();
        // Both dotenv spellings resolve to the same project-relative file.
        // Comparing the unresolved strings would let the cache interpret and
        // delete the authoritative plaintext as a malformed envelope.
        let spec = cached_spec_with(
            vec!["myprovider"],
            &[(
                "myprovider",
                cached_alias(&["dotenv:.env"], "dotenv://.env", "8h"),
            )],
        );

        let message = spec.build_plan(None).unwrap_err().to_string();
        assert!(message.contains("distinct store"), "{message}");
        assert!(message.contains("dotenv:.env"), "{message}");
    }

    #[test]
    fn vault_compatible_spelling_and_auth_cannot_bypass_cache_separation() {
        let _env = scrub_resolution_env();
        for (source, cache) in [
            (
                "vault://127.0.0.1:8200/secret?tls=false",
                "openbao://127.0.0.1:8200/secret?tls=false",
            ),
            (
                "vault://127.0.0.1:8200/secret?tls=false&auth=token",
                "vault://127.0.0.1:8200/secret?tls=false&auth=approle",
            ),
            (
                "openbao://127.0.0.1:8200/secret?tls=false&auth=jwt&role=read&audience=one",
                "openbao://127.0.0.1:8200/secret?tls=false&auth=jwt&role=deploy&audience=two",
            ),
            (
                "vault://127.0.0.1:8200/secret?tls=false&kv=1",
                "openbao://127.0.0.1:8200/secret?tls=false&kv=2",
            ),
        ] {
            let spec = cached_spec_with(
                vec!["route"],
                &[("route", cached_alias(&[source], cache, "8h"))],
            );

            let message = spec.build_plan(None).unwrap_err().to_string();
            assert!(
                message.contains("distinct store"),
                "{source} / {cache}: {message}"
            );
            assert!(
                message.contains(&crate::audit::redact_uri_strict(source)),
                "{source} / {cache}: {message}"
            );
        }
    }

    #[test]
    fn compatible_providers_may_cache_into_a_different_location() {
        let _env = scrub_resolution_env();
        for (source, cache) in [
            (
                "vault://team-a@bao.example.com:8200/secret",
                "openbao://team-b@bao.example.com:8200/secret",
            ),
            (
                "vault://team-a@bao.example.com:8200/secret",
                "openbao://team-a@bao.example.com:8200/cache",
            ),
            (
                "vault://team-a@bao.example.com:8200/secret",
                "openbao://team-a@other.example.com:8200/secret",
            ),
        ] {
            let spec = cached_spec_with(
                vec!["route"],
                &[("route", cached_alias(&[source], cache, "8h"))],
            );

            assert!(
                spec.build_plan(None).is_ok(),
                "{source} and {cache} are different stores"
            );
        }
    }

    /// The cache fingerprint of a route reading from `source`.
    fn fingerprint(source: &str) -> String {
        let spec = cached_spec_with(
            vec!["route"],
            &[("route", cached_alias(&[source], "keyring://", "8h"))],
        );
        let plan = plan(&spec);
        route(find(&plan, "API_KEY"))
            .cache()
            .expect("cached route")
            .route_fingerprint
            .clone()
    }

    #[test]
    fn vault_compatible_route_configuration_changes_invalidate_the_cache() {
        let _env = scrub_resolution_env();

        let baseline = fingerprint("vault://bao.example.com:8200/secret");
        for changed in [
            "openbao://bao.example.com:8200/secret",
            "vault://bao.example.com:8200/secret?auth=approle",
            "vault://bao.example.com:8200/secret?auth=jwt&role=ci&audience=deploy",
            "vault://bao.example.com:8200/secret?kv=1",
        ] {
            assert_ne!(
                baseline,
                fingerprint(changed),
                "route configuration change must invalidate the cache: {changed}"
            );
        }

        assert_ne!(
            fingerprint("vault://bao.example.com:8200/secret?auth=jwt&role=read"),
            fingerprint("vault://bao.example.com:8200/secret?auth=jwt&role=deploy"),
            "changing the JWT role must invalidate the cache"
        );
    }

    /// The fingerprint is built from each source's `uri()`, so a provider that
    /// reports less than its whole configuration reports two different routes
    /// as one, and the cache keeps serving the value the old route fetched.
    #[test]
    fn lastpass_item_template_changes_invalidate_the_cache() {
        let _env = scrub_resolution_env();

        assert_ne!(
            fingerprint("lastpass://Work/TeamA/{project}/{profile}/{key}"),
            fingerprint("lastpass://Work/TeamB/{project}/{profile}/{key}"),
            "changing the item template must invalidate the cache"
        );
    }

    fn template_fingerprint(template: NativeAddressTemplate) -> String {
        let source = ProviderAlias::from("env://")
            .with_reference_template(template)
            .unwrap();
        let spec = cached_spec_with(
            vec!["route"],
            &[
                ("source", source),
                ("route", cached_alias(&["source"], "keyring://", "8h")),
            ],
        );
        let plan = plan(&spec);
        route(find(&plan, "API_KEY"))
            .cache()
            .expect("cached route")
            .route_fingerprint
            .clone()
    }

    #[test]
    fn coordinate_boundaries_distinguish_alias_template_fingerprints() {
        let _env = scrub_resolution_env();
        let embedded_field = NativeAddressTemplate {
            item: "foo field={key}".to_string(),
            ..Default::default()
        };
        let separate_field = NativeAddressTemplate {
            item: "foo".to_string(),
            field: Some("{key}".to_string()),
            ..Default::default()
        };

        assert_ne!(
            template_fingerprint(embedded_field),
            template_fingerprint(separate_field),
            "different template coordinates must not collide through display rendering"
        );
    }

    fn scoped_ref_cache_fingerprint(reference: NativeAddress) -> String {
        let mut configured = secret(Some(vec!["route"]));
        configured.refs = Some(HashMap::from([("source".to_string(), reference)]));
        let mut config =
            crate::tests::resolve_test_config(HashMap::from([("API_KEY".to_string(), configured)]));
        config.providers = Some(HashMap::from([
            ("source".to_string(), ProviderAlias::from("env://")),
            ("local".to_string(), ProviderAlias::from("keyring://")),
            (
                "route".to_string(),
                cached_alias(&["source"], "local", "8h"),
            ),
        ]));
        let spec = Secrets::new(config, None, None, None);
        let plan = plan(&spec);
        let planned = find(&plan, "API_KEY");
        planned.cache_fingerprint(
            route(planned).cache().expect("cached route"),
            &spec.config().project.name,
            "default",
        )
    }

    #[test]
    fn coordinate_boundaries_distinguish_scoped_ref_fingerprints() {
        let _env = scrub_resolution_env();
        let embedded_field = NativeAddress {
            item: "foo field=API_KEY".to_string(),
            ..Default::default()
        };
        let separate_field = NativeAddress {
            item: "foo".to_string(),
            field: Some("API_KEY".to_string()),
            ..Default::default()
        };

        assert_ne!(
            scoped_ref_cache_fingerprint(embedded_field),
            scoped_ref_cache_fingerprint(separate_field),
            "different scoped-ref coordinates must not collide through display rendering"
        );
    }

    #[test]
    fn a_cache_must_be_a_store_that_can_delete() {
        let _env = scrub_resolution_env();
        // Every way a cached value stops being correct ends in deleting the
        // entry, so a store that cannot delete would give a cache nothing could
        // ever invalidate.
        let spec = cached_spec_with(
            vec!["myprovider"],
            &[("myprovider", cached_alias(&["azure"], "env://", "8h"))],
        );

        let message = spec.build_plan(None).unwrap_err().to_string();
        assert!(message.contains("cannot delete secrets"), "{message}");
        assert!(message.contains("keyring"), "{message}");
    }

    #[test]
    fn a_cache_may_share_a_store_kind_with_a_different_address() {
        let _env = scrub_resolution_env();
        // Same provider, different store: only an identical store is a conflict.
        let spec = cached_spec_with(
            vec!["myprovider"],
            &[
                (
                    "sibling",
                    ProviderAlias::from("keyring://secretspec/source/{project}/{profile}/{key}"),
                ),
                ("myprovider", cached_alias(&["sibling"], "local", "8h")),
            ],
        );

        let plan = plan(&spec);
        assert!(route(find(&plan, "API_KEY")).cache().is_some());
    }

    #[test]
    fn a_cached_override_reports_its_first_authoritative_store() {
        let _env = scrub_resolution_env();
        // The alias itself is not a store, so the report must name the store a
        // read consults first — including when no secret planned a route and
        // there is none to borrow.
        for secrets in [
            HashMap::new(),
            HashMap::from([("API_KEY".to_string(), secret(None))]),
        ] {
            let mut config = crate::tests::resolve_test_config(secrets);
            config.providers = Some(cached_aliases());
            let mut spec = Secrets::new(config, None, None, None);
            spec.set_provider("myprovider");

            assert_eq!(
                plan(&spec).override_uri,
                Some("akv://team-vault".to_string())
            );
        }
    }

    #[test]
    fn cached_alias_can_be_the_global_default_provider() {
        let _env = scrub_resolution_env();
        let mut config = crate::tests::resolve_test_config(HashMap::from([(
            "API_KEY".to_string(),
            secret(None),
        )]));
        config.providers = Some(cached_aliases());
        let mut global = global_config_with_aliases(&[]);
        global.defaults.provider = Some("myprovider".to_string());
        let spec = Secrets::new(config, Some(global), None, None);

        let plan = plan(&spec);
        let route = route(find(&plan, "API_KEY"));
        assert_eq!(route.group_key(), Some("azure"));
        assert!(route.cache().is_some());
    }

    #[test]
    fn cached_alias_can_be_an_explicit_provider_override() {
        let _env = scrub_resolution_env();
        let spec = cached_spec(vec!["env"]);
        let planned = spec
            .plan_secret("API_KEY", "default", Some("myprovider"))
            .unwrap()
            .unwrap();
        let route = route(&planned);

        assert_eq!(route.group_key(), Some("azure"));
        assert!(route.cache().is_some());
    }

    #[test]
    fn cached_aliases_cannot_be_nested() {
        let _env = scrub_resolution_env();
        let spec = cached_spec_with(
            vec!["outer"],
            &[("outer", cached_alias(&["myprovider"], "local", "1h"))],
        );

        let error = spec.build_plan(None).unwrap_err();
        assert!(
            error.to_string().contains("cannot use cached alias"),
            "{error}"
        );
    }
}
