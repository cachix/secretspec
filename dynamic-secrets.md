# SPEC: Dynamic secrets for SecretSpec

> Status: draft / working specification.
>
> This document describes the simplified north-star design and a phased
> implementation. It is not user documentation. Before any part is published,
> choose its target SecretSpec release and label every unreleased provider
> capability, configuration field, CLI behavior, SDK API, example, provider
> listing, and generated summary with that version.

## 1. Summary

A dynamic secret is issued on demand, has a backend-bounded lifetime, and may be
renewable or revocable. It is a live resource rather than a durable value
retrieved from storage.

SecretSpec models dynamic issuance as a capability of a provider alias:

- a dynamic-capable provider alias describes one kind of issuance;
- authentication establishes a provider-attested principal before issuance;
- one alias produces one lease per SecretSpec session;
- one lease may contain several named outputs;
- profile secrets project those outputs onto SecretSpec names;
- the session keeps the lease alive and performs best-effort cleanup.

The initial lifecycle owner is `secretspec run`. It issues only the dynamic
aliases referenced by the active profile and scope, injects their outputs into
one child environment, renews leases whose output bytes remain unchanged, and
revokes them when the command exits.

Stateful Rust and polyglot sessions follow later. Stateless value-carrying
operations never silently issue dynamic credentials.

Dynamic providers reuse the existing `[providers]` alias and credential system.
They do not use the existing storage `Provider` trait internally: storage
providers perform CRUD on durable addresses, while dynamic providers issue,
renew, and revoke leases. The two provider kinds share configuration,
registration, credentials, provenance, and planning, but retain different
operation traits.

## 2. First principles

The design follows six rules.

### 2.1 Acquisition mode is explicit

A caller must be able to tell from a secret declaration whether resolving it
requires a live session. Dynamic behavior is therefore not inferred merely from
the current implementation behind a `providers` route.

### 2.2 Provider configuration is not duplicated

Endpoint configuration, authentication selection, credential routes, alias
inheritance, and per-user aliases already belong to `[providers]`. Dynamic
issuance reuses those concepts rather than introducing parallel `[dynamic]` and
`[authentication]` maps.

### 2.3 The lease is the lifecycle unit

One backend issuance may return a credential set. SecretSpec manages that set as
one lease even when several SecretSpec variables expose its outputs.

### 2.4 Scope is the session boundary

A session fixes its project, profile, and optional SecretSpec scope at open
time. It owns the complete accessed set for that scope, including hidden
composition dependencies. A second arbitrary name-selection or snapshot
language is unnecessary.

### 2.5 Ship renewal before replacement

In-place renewal preserves output bytes and works with a process environment.
Replacement issuance changes output bytes and requires a separate delivery and
consumer-adoption contract. The first public release supports renewal and
begins bounded consumer shutdown when replacement would be required.

### 2.6 The provider attests identity

Project, profile, provider alias, access reason, local user name, and an
agent-detection heuristic are request context. They are not authenticated
identity. A dynamic provider establishes identity only after its configured
authentication mechanism succeeds and reports the principal attested by that
provider.

SecretSpec does not derive the authenticated principal by decoding an input
JWT, trusting local environment labels, or combining project metadata. It
accepts the provider's validated identity result, qualifies it by the
provider's trust domain, and pins it for the session. Reauthentication may
replace authentication artifacts, but it must not silently change the pinned
principal.

## 3. Goals and non-goals

### 3.1 Goals

- Issue short-lived credentials only for an explicit lifecycle-owned operation.
- Represent one issuance with several named outputs.
- Share one issuance across every binding to the same provider alias in a
  session.
- Derive a conservative expiration from the backend's returned TTL or absolute
  expiration and honor its renewable/revocable facts.
- Renew in place while output bytes remain unchanged.
- Revoke on normal close when the backend supports revocation.
- Roll back known leases when opening a session fails partway through.
- Reuse existing provider aliases and provider credentials.
- Record the provider-attested principal and authentication assurance without
  treating self-asserted request context as identity.
- Report residual bootstrap authority after authentication so a short-lived
  session token does not hide a reusable JWT, SecretID, request token, or
  supplied parent token.
- Preserve enough value-free correlation to join a SecretSpec issuance with
  the provider's audit record.
- Remove inherited authentication environment inputs from a `run` child.
- Respect profiles, scopes, composed-secret dependencies, reason policy, and
  audit behavior.
- Keep issued values, authentication values, backend lease identifiers, and
  opaque backend state out of logs and reports.
- Preserve one Rust lifecycle implementation for the CLI and all later SDKs.

### 3.2 Non-goals for the first public release

- Replacement issuance or consumer restart.
- Dynamic file delivery.
- Cross-run credential reuse or a secret-bearing persistent lease ledger.
- A public command issuer, arbitrary plugin protocol, or dynamically loaded
  issuer.
- A second project-level authentication-plan routing system; the operator trust
  ceiling constrains the existing provider configuration instead.
- Authentication-session sharing between static and dynamic providers.
- First-use fingerprint approvals or a dynamic-only policy language.
- Stateful language SDKs; `run` is the first public lifecycle owner.
- Guaranteeing cleanup after `SIGKILL`, process abort, kernel failure, power
  loss, or host compromise.
- Guaranteeing that backend revocation terminates an already-established
  database, TLS, or application session.
- Proving which process used a copied bearer credential after issuance.
- Implementing user-on-behalf-of-agent delegation or sender-constrained
  credentials in the first public release.
- Isolating mutually untrusted processes running as the same OS user.

## 4. Terminology

- **Storage provider**: a provider implementing durable value operations such as
  get, set, and delete.
- **Dynamic provider**: a provider implementing issue, renew, and revoke
  operations for one configured credential kind.
- **Provider trust domain**: the provider-owned boundary within which a
  principal identifier is meaningful, such as product, Vault/OpenBao cluster,
  and namespace. A configured endpoint is routing information and is not by
  itself a stable identity namespace.
- **Provider principal**: the authenticated identity attested by the provider,
  qualified by its trust domain. It may identify a workload, user, shared role,
  or another provider-native subject; SecretSpec does not relabel every
  principal as an agent.
- **Authentication session**: the provider-owned or user-supplied authority
  used for issue and lifecycle operations, together with its principal,
  ownership, token class, lifetime, use budget, and cleanup containment.
- **Issued principal**: the downstream identity created for a lease, such as a
  database username. It is distinct from the provider principal that requested
  issuance.
- **Provider alias**: a named entry in `[providers]` or
  `[defaults.providers]`, for either provider kind.
- **Dynamic binding**: a profile secret's projection from one dynamic provider
  alias and one named output.
- **Lease**: SecretSpec's in-memory record of one successful issuance, including
  its outputs, conservative expiration, capabilities, and sensitive backend
  state.
- **Partial lease**: cleanup-capable state for a backend resource that was
  created but could not be accepted as a publishable lease. It has no usable
  outputs and may not have a validated expiration.
- **Lease expiration**: a conservative local deadline derived from the
  backend's returned absolute expiration or TTL. It must never be later than
  the provider's best estimate of backend expiration.
- **Renewal increment**: an optional provider-specific duration requested
  during renewal. It is advisory; the backend-returned expiration remains
  authoritative.
- **Renewal**: extending the same lease without changing output values.
- **Replacement**: issuing a new lease whose output values may differ.
- **Session**: the lifecycle owner for the resolved static values, dynamic
  leases, renewal worker, optional supervised consumer, and cleanup.
- **Visible set**: the secrets selected by the active profile and optional
  SecretSpec scope.
- **Accessed set**: the visible set plus transitive composed-secret
  dependencies.
- **Outcome uncertainty**: a failed mutating request may have been applied by
  the backend even though SecretSpec did not receive a successful response.

The user-facing feature name is `dynamic`. Internally, `Lease` and
`LeaseProvider` are the appropriate lifecycle names.

## 5. Configuration model

### 5.1 Manifest revision

Dynamic syntax requires manifest revision `1.1`:

```toml
[project]
name = "my-app"
revision = "1.1"
```

Revision `1.0` rejects:

- a secret's `dynamic` field;
- a dynamic-provider URI or alias used as a dynamic binding;
- any future dynamic delivery setting.

Every document in an `extends` graph is parsed according to its own revision.
Revisions are monotonic across an edge: a `1.1` document may extend `1.0`; a
`1.0` document may not extend `1.1`. The root revision must therefore cover
every feature in the effective graph.

Previous released CLIs and proc macros must reject revision `1.1`. Reading a
small revision envelope before the full document is not required for
correctness as long as:

- unsupported revisions fail before validation, planning, or I/O;
- an older binary cannot ignore the dynamic field and continue;
- compatibility tests cover both the CLI loader and derive macro.

New dynamic fields and provider-specific URI options reject unknown values.
This feature does not require replacing the complete manifest parser with
revision-specific duplicate Rust structures.

### 5.2 Dynamic provider aliases

Dynamic providers use the existing provider alias table:

```toml
[providers.db]
uri = "vault+database://vault.example.com/database?role=my-app"
credentials = { token = "keyring" }
```

The exact Vault URI spelling is finalized with its implementation. This
specification uses `vault+database` to make the acquisition kind unambiguous:

- `vault://...` continues to mean the durable Vault KV storage provider;
- `vault+database://...` means a Vault database credential lease provider;
- `openbao://...` continues to mean OpenBao KV;
- `openbao+database://...` means an OpenBao database credential lease provider.

A dynamic alias may use the same two existing leaf forms:

```toml
[providers]
db = "vault+database://vault.example.com/database?role=my-app"
```

or:

```toml
[providers.db]
uri = "vault+database://vault.example.com/database?role=my-app&auth=approle"

[providers.db.credentials]
role_id = { provider = "onepassword", ref = { vault = "Infra", item = "db-approle", field = "role_id" } }
secret_id = { provider = "onepassword", ref = { vault = "Infra", item = "db-approle", field = "secret_id" } }
```

Dynamic aliases are leaf aliases:

- they cannot use `{ fallback, cache }`;
- they cannot appear inside a cached provider route;
- they do not persist issued values through another provider;
- credential sources remain limited to the existing one-hop rule;
- every credential source must resolve to a storage provider, never another
  dynamic provider.

Project aliases take precedence over user-global aliases exactly as they do for
storage providers. A profile may reference an alias defined only in user config,
although a project alias is preferable when endpoint and role configuration
should be shared by a team.

#### Operator trust ceiling

Alias precedence does not make a checked-in project an authority over where
ambient or stored authentication may be sent. Before resolving authentication
values, an operator-owned policy constrains the effective dynamic plan:

- provider product, allowed endpoint origins, and approved reverse-proxy or
  load-balancer topology;
- trusted CA roots or certificate/public-key pins;
- namespace, secrets-engine mount, auth mount, and allowed roles;
- authentication mechanisms and whether direct user-owned tokens are allowed;
- OIDC mint origins and audiences;
- allowed credential-source providers and ambient fallback classes;
- maximum session-authentication and residual-bootstrap lifetimes, lease
  lifetime, and immutable credential age;
- redirect origins, outbound proxy policy, and whether plaintext transport is
  allowed.

For mutating dynamic-secret paths, the approved topology must not cache or
independently retry requests merely because their HTTP method is conventionally
idempotent. This matters for Vault/OpenBao database issuance, which creates a
credential through HTTP `GET`.

Project configuration can narrow or select within this ceiling but cannot
broaden it. In particular, a repository cannot redirect an ambient Vault token,
AppRole SecretID, JWT, CI OIDC request token, or credential-provider result to
an arbitrary endpoint. Plaintext HTTP is rejected except for loopback unless
the operator policy explicitly permits a narrower development case.

The provider HTTP client uses an explicit proxy policy rather than silently
inheriting `HTTP_PROXY`, `HTTPS_PROXY`, or future library-level system-proxy
behavior. An operator may authorize a particular outbound proxy, but a project
cannot select it or add its trust root.

The coordinator freezes the effective provider and credential-source plan and
computes a value-free digest before reading authentication values or contacting
an issuer. Audit intent records that digest. Later phases use the frozen plan;
changes to project or user configuration require a new session rather than
silently changing the active trust path.

The exact operator-policy syntax is finalized before Phase 1. It belongs to
user or centrally managed configuration, not to the project manifest that it
constrains.

### 5.3 Provider capabilities

Provider registrations declare their acquisition capability:

```rust
enum ProviderCapability {
    Stored,
    Dynamic {
        outputs: &'static [&'static str],
    },
}
```

The representation may differ in implementation, but planning can determine
without I/O whether a provider spec is storage-capable or dynamic-capable and
which output names a dynamic provider exposes.

Each registration contains the factory matching its capability. A dynamic
registration cannot accidentally carry a storage factory, and one URI scheme
does not change capability at runtime. Provider families that support both
operations register distinct schemes. Dynamic output schemas must be non-empty,
unique, and use the selector output-name grammar.

Initial output schemas are fixed by the provider and credential kind:

- Vault/OpenBao database password roles: `username`, `password`;
- AWS STS, later: `access_key_id`, `secret_access_key`, `session_token`;
- GitHub App, later: `value`.

The manifest does not repeat an `outputs` list. A provider is the authority for
its output schema, and a binding to an unknown output fails during
runtime structural validation.

The first Vault/OpenBao provider accepts only roles configured with
`credential_type=password`. Backend role definitions may support other
credential types, but those are not alternate runtime schemas of the same
registration. Structural validation does not require permission to read a role
definition. Issue validates the returned credential shape; if the backend
created a lease but returned a credential kind this registration cannot
publish, the provider returns an applied issue failure with partial-lease
cleanup state. Future credential kinds use distinct registered schemes unless
a later specification introduces variant schemas.

Provider listings and reference tables distinguish stored and dynamic
capabilities without presenting them as unrelated authentication systems.

### 5.4 Dynamic bindings

A profile secret binds one provider alias output:

```toml
[profiles.production]
DB_USER = {
  description = "Ephemeral database username",
  dynamic = "db.username"
}
DB_PASSWORD = {
  description = "Ephemeral database password",
  dynamic = "db.password"
}
```

`db.username` means:

1. resolve provider alias `db` through the existing project-then-user alias
   lookup;
2. require that it resolves to a dynamic provider;
3. project its `username` output onto the declared SecretSpec name.

The alias, not the SecretSpec variable, is the lease identity. Both bindings
above share one issuance.

Bindings use only the string form in the first release. There is no expanded
table form and no inline source form. A single-output provider still uses an
explicit output:

```toml
GITHUB_TOKEN = {
  description = "GitHub App installation token",
  dynamic = "github.value"
}
```

This keeps selectors stable if a provider adds another output later.

### 5.5 Selector grammar

Dynamic selectors are intentionally narrow:

- split at the final period;
- the non-empty part before it must exactly match an existing provider alias;
- the non-empty part after it is an output name;
- output names match `[a-z][a-z0-9_]*`;
- comparison is case-sensitive;
- existing alias names are not given a second, dynamic-only identifier grammar.

Examples:

```toml
dynamic = "database.password"       # valid
dynamic = "aws-prod.session_token"  # valid
dynamic = "database"                # invalid: output missing
dynamic = ".password"               # invalid: alias missing
dynamic = "database.Password"       # invalid: output name
dynamic = "database.eu.password"    # valid only if "database.eu" is an alias
dynamic = "vault://host.password"   # invalid unless that exact alias exists
```

Requiring an alias gives every lease a stable local identity and ensures two
bindings can share it without comparing or canonicalizing arbitrary inline
URIs. Splitting at the final period preserves every alias name the existing
provider map already accepts.

### 5.6 Source conflicts

One effective secret has one acquisition kind:

- stored provider resolution;
- a dynamic binding;
- composition.

As today, a declaration with neither `dynamic` nor `composed` uses stored
provider resolution.

A raw declaration that writes `dynamic` beside a stored acquisition field or
`composed` is invalid. Stored acquisition fields are:

- `providers`;
- `ref`;
- `default`;
- `type`;
- `generate`.

`composed` independently selects composition. Raw validation classifies
`dynamic`, `composed`, and the set of stored fields as three mutually exclusive
acquisition selectors and reports every selector present when more than one is
declared.

For example:

```toml
[profiles.production]
TOKEN = {
  description = "API token",
  dynamic = "github.value",
  providers = ["keyring"]
}
```

SecretSpec reports both conflicting fields rather than choosing one.

`required`, required-group membership, `description`, and `as_path` are
metadata or presence/delivery policy. They do not independently choose an
acquisition kind.

Profile-level stored acquisition defaults (`default` and `providers`) do not
apply to a dynamic binding. Profile-level `required` still does.

### 5.7 Profile inheritance

Acquisition kind is selected atomically, while metadata continues to inherit
field by field.

Classify the current profile entry and its inherited `default` entry
independently as stored, dynamic, composition, metadata-only, or absent after
raw conflict validation. Then:

1. A current dynamic declaration selects the complete dynamic acquisition.
2. A current `composed` declaration selects the complete composition
   acquisition.
3. A current stored declaration selects stored acquisition. Existing
   field-level inheritance among stored fields applies only when the inherited
   entry is also stored.
4. A metadata-only current entry inherits the complete acquisition from the
   default entry.
5. An absent current entry inherits the complete default entry.

If neither entry selects an acquisition after these steps, the result uses
implicit stored provider resolution, preserving today's behavior for
metadata-only declarations.

After this choice, profile `required` defaults may fill metadata. Profile
`default` and `providers` defaults fill only a stored acquisition. Acquisition
fields never cross a stored, dynamic, or composition boundary.

This makes both directions explicit without `dynamic = false`:

```toml
[profiles.default]
TOKEN = {
  description = "API token",
  providers = ["keyring"]
}

[profiles.production]
TOKEN = { dynamic = "github.value" }
```

and:

```toml
[profiles.default]
TOKEN = {
  description = "API token",
  dynamic = "github.value"
}

[profiles.test]
TOKEN = { providers = ["env"] }
```

When a more-specific stored declaration selects the stored acquisition kind,
the existing field-level rules among stored fields continue to apply. When it
switches between stored, dynamic, and composed acquisition, fields belonging to
the previous kind do not leak across the boundary.

An author who wants to return to stored resolution must name a stored provider
or other stored acquisition field. The first release does not add a
polymorphic boolean solely to mean "use the ambient default provider."

### 5.8 `extends`

Top-level `[providers]` maps retain their existing `extends` behavior: a later
alias replaces an earlier alias of the same name as one unit. The URI,
credentials, and provider kind never merge piecemeal across documents.

Cross-file secret definitions also retain the existing whole-entry overlay
behavior. Dynamic support changes only the default-profile-to-specific-profile
acquisition rule described above.

Every document is parsed and revision-gated before it is added to the overlay
graph. Existing whole-entry overlay semantics may replace a parent declaration.
The final merged document and every effective profile are then validated after
alias resolution and compilation.

The initial dynamic provider configurations contain no relative file paths, so
the feature does not require a new located-field provenance system. If a future
dynamic provider accepts relative paths, it must use the same declaring-file
origin rules as file-backed storage providers.

### 5.9 Scopes

Scopes need no dynamic-specific syntax.

Session planning first computes:

```text
visible = effective profile ∩ selected scope
accessed = visible ∪ transitive composition dependencies
```

Only dynamic aliases referenced by `accessed` are issued. Outputs needed solely
for an out-of-scope composition dependency remain hidden from the returned
value set and child environment.

An unused provider alias is never authenticated or issued.

### 5.10 Validation

Validation has two pure stages:

- Manifest and derive-time validation checks the revision, selector grammar,
  acquisition conflicts, inheritance, composition graph, and generated Rust
  shape. The proc macro does not read per-user provider aliases.
- Runtime structural validation resolves project aliases first and user-global
  aliases second, then checks provider capability, output schema, credentials,
  and provider-specific configuration.

This preserves the existing ability to keep a machine-specific alias in user
config. Generated types can compile on a machine that does not define that
alias; opening or checking the affected runtime profile cannot.
Alias-dependent runtime checks apply to the active profile and accessed set, so
an unavailable machine-specific alias in an inactive profile does not block an
unrelated operation.

Across those stages, SecretSpec rejects:

- dynamic syntax under revision `1.0`;
- a malformed selector;
- an undefined alias;
- an alias resolving to a storage provider rather than a dynamic provider;
- an output not declared by the dynamic provider registration;
- a dynamic alias using fallback or cache;
- a dynamic provider inside a stored fallback or cached route;
- unsupported provider credentials;
- an effective endpoint, trust root, namespace, mount, role, auth mechanism,
  audience, redirect, transport, credential source, or ambient fallback outside
  the operator trust ceiling;
- a provider credential source requiring another credential hop;
- a provider credential source resolving to a dynamic provider;
- raw or effective acquisition conflicts;
- `as_path = true` on a dynamic binding or on a composition transitively
  depending on one in the first release;
- provider-specific invalid URI options, durations, roles, mounts, endpoints,
  or authentication settings.

Validation never authenticates, contacts the backend, or issues a lease.

Expected diagnostics include:

```text
invalid dynamic selector "db": expected "<provider-alias>.<output>"

dynamic selector "vault://host.password" must name a provider alias, not a URI

secret DB_PASSWORD declares both dynamic and providers in profile production

dynamic binding DB_PASSWORD references storage provider alias "vault_kv"; use a dynamic-capable provider

dynamic provider "db" has outputs username, password; output "token" does not exist

dynamic provider alias "db" cannot use fallback or cache

secret DB_PASSWORD sets as_path = true; dynamic file delivery is not available until SecretSpec <target release>
```

## 6. Compiled model and planning

### 6.1 Acquisition

Compilation makes acquisition explicit:

```rust
enum Acquisition {
    Stored(StoredSource),
    Dynamic(DynamicProjection),
    Composition(Template),
}

struct DynamicProjection {
    provider_alias: String,
    output: String,
}

struct CompiledSecret {
    config: Secret,
    acquisition: Acquisition,
    missing: MissingPolicy,
    declared_required: bool,
}
```

`MissingPolicy` governs stored acquisition and composition. Dynamic issuance
does not return ordinary "not found":

- a successful issue must contain every declared output;
- authentication, authorization, network, or issuance failure is an operation
  error;
- `required = false` does not convert an issuer outage into an omitted value.

Optionality and required groups still affect the profile's presence contract,
but once a selected dynamic binding participates in a session, its provider
must issue successfully.

### 6.2 Dynamic groups

The resolution plan derives dynamic groups from planned secrets in the same way
it derives storage-provider groups:

```rust
struct DynamicGroup {
    alias: String,
    bindings: Vec<(SecretName, OutputName)>,
}
```

The provider entry is resolved from the alias when the group is constructed;
the compiled binding does not retain a second copy of its URI. Groups key on
the raw alias name, not only the canonical URI:

- every binding to the same alias shares one lease;
- two different aliases create independent leases even if their URIs match;
- alias credentials remain reachable at provider construction time;
- changing an alias through overlay changes the complete issuance config.

Dynamic groups are sorted by alias for deterministic issue and cleanup ordering.
The first implementation issues them sequentially. Concurrency may be added
after rollback behavior is exercised and measured.

### 6.3 Composition

A composed secret may depend on dynamic bindings:

```toml
DATABASE_URL = {
  description = "Database URL",
  composed = "postgres://${DB_USER}:${DB_PASSWORD}@db.example.com/app"
}
```

The first release supports environment-value delivery only, so a dynamic
dependency's delivered representation is its logical value. Existing
composition syntax and behavior remain unchanged.

No special `lifetime_sources` or `generation_sources` sets are compiled:

- the session already owns the whole accessed set;
- the existing composition graph already records dependencies;
- in-place renewal does not change any value bytes;
- when replacement is added later, the coordinator can re-render affected
  compositions—or the complete DAG—before atomically replacing the resolved
  session map.

A composition may depend on more than one dynamic alias. The first release
never replaces output bytes, so it does not need a cross-source replacement
snapshot rule. A later replacement design must promise only a locally
consistent SecretSpec snapshot, not a transaction across independent backends.

## 7. Dynamic provider model

### 7.1 Separate operation trait, shared provider infrastructure

The existing storage `Provider` trait remains focused on durable addresses and
CRUD. Dynamic providers implement a separate trait:

```rust
trait LeaseProvider: Send {
    fn authenticate(
        &mut self,
        request: OperationRequest<'_>,
    ) -> Result<AuthSession, LeaseError>;

    fn issue(
        &mut self,
        request: IssueRequest<'_>,
    ) -> Result<Lease, IssueFailure>;

    fn renew(
        &mut self,
        lease: &Lease,
        request: OperationRequest<'_>,
    ) -> Result<Renewal, LeaseError>;

    fn revoke(
        &mut self,
        lease: &LeaseCleanup,
        request: OperationRequest<'_>,
    ) -> Result<RevokeOutcome, LeaseError>;

    fn close(
        &mut self,
        request: OperationRequest<'_>,
    ) -> Result<ProviderCloseOutcome, LeaseError>;

    fn name(&self) -> &'static str;
    fn uri(&self) -> String;
}
```

The exact Rust signatures may evolve during implementation. The important
boundary is:

- provider alias parsing and credential resolution are shared;
- storage and lease operations are not forced into one trait;
- one constructed `LeaseProvider` instance owns or borrows one authenticated
  client state for one alias and one SecretSpec session;
- `authenticate` returns provider-attested identity and authority facts before
  `issue` may create a downstream resource;
- explicit idempotent `close` releases provider-owned authentication resources
  even if issue never succeeds.

The authentication result contains no bearer token or provider credential:

```rust
struct ProviderTrustDomain {
    provider: &'static str,
    id: String,
    namespace: Option<String>,
}

enum PrincipalKind {
    Workload,
    User,
    SharedRole,
    Other,
}

struct ProviderPrincipal {
    trust_domain: ProviderTrustDomain,
    id: String,
    kind: PrincipalKind,
    auth_method: String,
    auth_mount: Option<String>,
}

struct ProviderIdentity {
    subject: ProviderPrincipal,
    actor: Option<ProviderPrincipal>,
}

enum AuthOwnership {
    ProviderOwned,
    UserSupplied,
}

enum AuthArtifactKind {
    Service,
    Batch,
    Opaque,
}

enum UseBudget {
    Unlimited,
    Remaining(u64),
    Unknown,
}

enum CleanupContainment {
    SessionLeases,
    ExpiryOnly,
    None,
}

struct AuthSession {
    identity: ProviderIdentity,
    ownership: AuthOwnership,
    artifact_kind: AuthArtifactKind,
    expires_at: SystemTime,
    renewable: bool,
    use_budget: UseBudget,
    cleanup_containment: CleanupContainment,
    residual_bootstrap: Vec<ResidualBootstrapAuthority>,
}

struct ResidualBootstrapAuthority {
    kind: String,
    expires_at: Option<SystemTime>,
    use_budget: UseBudget,
    audience_bound: Option<bool>,
    revocable_by_session: bool,
}
```

The representation may differ, but these distinctions are mandatory:

- a principal ID is meaningful only inside its provider trust domain;
- the subject is the identity whose authority is being exercised;
- an optional actor is populated only when the provider validates a delegation
  chain; project metadata never synthesizes one;
- `SharedRole` is honest attribution for mechanisms such as a shared AppRole;
- authentication ownership determines whether SecretSpec may close authority;
- artifact kind and use budget constrain which lifecycle operations remain
  possible;
- cleanup containment states whether closing owned authentication can contain
  leases whose individual backend identifiers were never received;
- residual bootstrap facts describe authorities that can authenticate again
  after this session closes, without retaining or reporting their values.

The first release does not collapse these facts into one self-asserted
"assurance level." Operator policy evaluates the structured identity,
ownership, containment, and bootstrap facts and reports which named claims the
session satisfies.

The first Vault/OpenBao implementation leaves `actor` absent. Keeping the slot
prevents a later user-on-behalf-of-agent flow from overloading one principal
string or changing the session ownership model.

Issue has a richer failure type because a backend may create a resource before
the provider can validate a publishable lease:

```rust
enum IssueFailure {
    NotApplied(LeaseError),
    Applied {
        partial: PartialLease,
        error: LeaseError,
    },
    Unknown(LeaseError),
}
```

`Applied` means the provider knows issuance occurred and has enough opaque state
to attempt cleanup. It is not returned without a `PartialLease`. A successful
backend response that proves creation but lacks enough identity for cleanup is
`Unknown`, with orphan risk, rather than a cleanup-capable applied failure.
The failure variant and the enclosed error's completion classification must
agree.

Constructing a `LeaseProvider` parses configuration and accepts already-resolved
credentials but performs no backend mutation. The core installs its close guard
before `authenticate()`, and any login that mints provider-owned state happens
behind that guard. Authentication that can mint an artifact is itself a
mutating operation: only a retryable, definitely-not-applied failure may be
retried generically. An applied or unknown login failure enters provider close
and relies on the backend lifetime for any artifact whose identifier was lost.

After authentication, the coordinator pins `ProviderIdentity`. Every later
provider login or refresh must return the same trust domain, subject, and actor.
An identity change is a fatal lifecycle error: it never silently continues a
lease under different authority.

There is no separate public `DynamicIssuerFactory` and `IssuerSession`
abstraction in the first implementation. The provider factory constructs the
session-owned `LeaseProvider` directly. If two native integrations later
demonstrate a need to share one authenticated client across several aliases,
that optimization can introduce an internal authentication-session cache
without changing manifest syntax.

### 7.2 Lease

A cleanup handle contains only the state needed to correlate and revoke a
backend resource. A partial lease is deliberately not publishable:

```rust
struct LeaseCleanup {
    local_id: LeaseId,
    backend_state: SecretState,
}

struct PartialLease {
    cleanup: LeaseCleanup,
    expires_at: Option<SystemTime>,
}
```

A successful lease adds a complete output schema and mandatory lifecycle
facts:

```rust
struct Lease {
    cleanup: LeaseCleanup,
    outputs: BTreeMap<String, SecretString>,
    issued_principal: Option<IssuedPrincipal>,
    issued_at: SystemTime,
    rotation_due_at: SystemTime,
    expires_at: SystemTime,
    renewable: bool,
    revocable: bool,
}

struct IssuedPrincipal {
    kind: String,
    output: String,
}
```

- `cleanup.local_id` is random, value-free correlation generated by
  SecretSpec.
- `cleanup.backend_state` contains sensitive lease IDs, tokens, or other opaque
  data needed for renewal and revocation.
- a partial lease is used only for rollback and audit correlation; its outputs
  are unavailable and its expiration may be unknown;
- `outputs` contains exactly the provider's registered schema.
- `issued_principal` identifies which output names the downstream principal,
  without copying its value; the Vault/OpenBao database provider points to the
  `username` output.
- `issued_at` is set to request start, so it cannot be later than backend
  issuance, and never changes;
- `rotation_due_at` applies the operator's maximum age to the unchanged output
  bytes and never moves during renewal;
- `expires_at` is mandatory and conservative.
- `renewable` and `revocable` are effective capabilities derived from the
  backend response and validity chain.

The backend lease identifier is never the local audit identifier.

When a backend returns a TTL rather than an absolute timestamp, the provider
derives `expires_at` from the local request start, not response receipt. Network
time therefore consumes the TTL instead of extending it. A backend absolute
timestamp is preserved with the configured clock-skew reserve applied later by
the session coordinator.

The provider reports one effective lifecycle bound. If expiration or revocation
of an authentication token would invalidate the issued credential,
`expires_at` is no later than the earliest such dependency. `renewable = true`
means the provider can extend the complete validity chain in place without
changing output bytes. The coordinator therefore needs no second
authentication-deadline model.

The first release does not model `reissuable`: replacement is unsupported
regardless of whether the backend could issue another credential.

Lease renewal can extend validity without rotating a bearer password. The
usable boundary is therefore the earlier of `rotation_due_at` and
`expires_at`. A role or provider maximum TTL may impose an earlier bound, but a
large backend maximum does not override the operator's maximum credential age.

### 7.3 Renewal

Renewal is valid only when it preserves output bytes:

```rust
struct Renewal {
    expires_at: SystemTime,
    renewable: bool,
    revocable: bool,
    backend_state: SecretState,
}
```

The provider receives the current lease read-only and returns the complete
lifecycle update. The coordinator applies that update atomically only after
success. The provider does not return new outputs. A backend operation that
would change credential bytes is replacement, not renewal, and is unsupported
in the first release.

### 7.4 Revocation

Revocation returns an honest outcome:

```rust
enum RevokeOutcome {
    Confirmed,
    AlreadyInactive,
    AcceptedAsync,
    ExpiresOnly,
    Unsupported,
}
```

Unsupported revocation is not treated as successful revocation. Backend
expiration remains the fundamental bound. `ExpiresOnly` means the provider
knows a finite backend expiration but cannot explicitly revoke this artifact;
`Unsupported` means it cannot make that stronger statement. `Confirmed` is
reserved for a backend result that confirms invalidation of the underlying
credential, not merely removal of a local handle or acceptance into a queue.

Provider close reports authority shutdown and descendant-lease containment
separately:

```rust
enum CleanupOutcome {
    NotNeeded,
    Confirmed,
    AcceptedAsync,
    ExpiresOnly,
    Unsupported,
}

struct ProviderCloseOutcome {
    authority: CleanupOutcome,
    descendant_leases: CleanupOutcome,
}
```

For Vault/OpenBao, successful revocation of a provider-owned service token can
confirm that the token no longer authorizes new requests while descendant
dynamic leases are only accepted for asynchronous expiration-manager cleanup.
It does not prove that the database account has already been removed. A batch
token cannot be manually revoked, and a user-supplied token is not closed by
SecretSpec.

A failed or uncertain close returns `LeaseError`; local close still completes
after its bounded deadline. Force-removing a provider lease record while
backend cleanup failed is never reported as `Confirmed` because it may leave
the downstream credential active.

### 7.5 Requests and attribution

Authentication, issue, and later lifecycle operations receive:

- project;
- profile;
- provider alias;
- normalized access reason;
- SecretSpec audit session correlation;
- a value-free operation correlation stable across attempts of that logical
  operation;
- a bounded local operation deadline.

SecretSpec allocates the value-free local lease ID before issue and includes it
in `IssueRequest`, so successful, failed, and uncertain attempts share one audit
correlation.

Issue and renewal also receive a cancellation signal tied to session shutdown.
Revocation and provider close during normal session close receive their own
bounded cleanup contexts; they are not immediately canceled merely because the
session entered `Closing`.

Providers propagate non-secret attribution to backend request metadata where
the backend supports it. Secret values, authentication inputs, session handles,
and sensitive backend state are never used as labels.

The wire correlation value is an opaque random identifier. It does not encode
project, key names, local user names, reasons, or other potentially sensitive
metadata. The provider sends it on authentication, issue, renewal, revocation,
and close requests using a backend-supported header such as
`X-Correlation-ID`. Retries of one definitely-not-applied logical operation use
the same value; distinct logical operations use distinct values.

Providers also return non-secret provider request IDs, when available, for the
audit event associated with that phase. Provider request IDs are correlation
evidence, not lease cleanup handles, and never replace `cleanup.backend_state`.
If a response is lost and no provider request ID is available, the outbound
correlation value is the join key for the provider audit log.

### 7.6 Errors and retries

Mutating backend calls must distinguish whether retry is known safe:

```rust
enum Completion {
    NotApplied,
    Applied,
    Unknown,
}

struct LeaseError {
    kind: LeaseErrorKind,
    completion: Completion,
    retryable: bool,
}
```

This is deliberately smaller than a general retry framework. `Applied` means
the backend mutation is known to have happened but no valid operation result
was produced. `Unknown` means SecretSpec cannot determine whether it happened.
Neither is retried by the generic coordinator. `retryable` has an effect only
when `completion` is `NotApplied`.

Retry and deadline rules are operation-specific:

- authentication retries only a retryable `NotApplied` error; an applied or
  unknown login may have minted provider-owned authority whose identifier was
  not received, so it is not exchanged again blindly;
- issue retries only a retryable `NotApplied` error within its bounded issue
  deadline; any eventual success still has to pass the minimum-useful-lifetime
  check;
- renewal retries only a retryable `NotApplied` error while the old lease's
  existing `renew-by` deadline leaves it safe;
- revoke retries only a retryable `NotApplied` error within its bounded cleanup
  deadline;
- provider close retries only a retryable `NotApplied` error within its bounded
  close deadline.

These guarantees include the complete request path. A provider cannot claim
`NotApplied` retry safety if an SDK, Vault Agent/Proxy, HTTP intermediary, or
load balancer may independently retry the request. This is especially
important for Vault/OpenBao database issuance, whose credential-creation API is
a mutating HTTP `GET`.

Applied and uncertain outcomes are handled by operation:

- applied issue: install the supplied partial-lease guard, publish nothing,
  attempt its revocation, close the provider, and fail session open;
- uncertain issue: publish nothing, start no consumer, close the provider,
  record the authority and descendant-lease containment outcomes, and record
  residual orphan risk until backend cleanup or expiration;
- applied or uncertain renewal: retain the old expiration and schedule
  shutdown from its existing deadlines;
- applied or uncertain revoke: close local state, report that revocation lacked
  a confirmed outcome, and rely on backend expiration;
- applied or uncertain provider close: close local state and report that
  authentication cleanup lacked a confirmed outcome.

A provider may later implement explicitly idempotent recovery for `Applied` or
`Unknown`, but that is provider-specific behavior, not a generic blind retry.

Vault/OpenBao response wrapping is not issue recovery. The dynamic lease exists
before Vault serializes the response into a wrapping token; losing the wrapped
response or the one-use unwrap response can still lose the only exact lease
identifier. Wrapping may serve a separate recipient-handoff confidentiality
protocol, but the first SecretSpec provider does not enable it for dynamic
issuance or treat wrapping-token expiration as downstream credential
revocation.

A response-wrapped AppRole SecretID is a different, bootstrap-delivery use case.
It is not part of the first vertical slice. If added, its one-use unwrap belongs
to the authentication transaction, needs its own completion classification and
audit intent, and still does not make a later database issuance recoverable.

The first release does not need public operation IDs, attempt counters, or a
generic idempotency protocol. A provider that later supports idempotent recovery
may extend the internal request context without changing the manifest.

## 8. Authentication

### 8.1 Existing provider credentials

Dynamic aliases use the existing `credentials` map:

```toml
[providers.db]
uri = "vault+database://vault.example.com/database?role=my-app&auth=approle"

[providers.db.credentials]
role_id = { provider = "onepassword", ref = { vault = "Infra", item = "approle", field = "role_id" } }
secret_id = { provider = "onepassword", ref = { vault = "Infra", item = "approle", field = "secret_id" } }
```

The existing rules remain:

- credential names are provider-specific and validated before reading;
- configured credentials outrank provider ambient fallbacks;
- a credential source may use convention addressing or `ref`;
- credential chains are limited to one hop;
- a credential source must be a storage provider;
- credential values are passed in memory and never exported to the child.

`secretspec config provider login` can store credentials declared by a dynamic
alias without a dynamic-specific login command. It is a compatibility workflow,
not the preferred workload-identity path: persisting a reusable token or
AppRole SecretID retains bootstrap bearer authority even when the issued
credential is short-lived.

### 8.2 Provider-native mechanisms

Authentication mechanism remains provider configuration:

- Vault/OpenBao: configured or ambient token, token file, AppRole, and JWT
  login using an already-issued or CI-minted OIDC JWT;
- AWS STS, later: native AWS credential-provider chain or provider-specific
  configured role source;
- GitHub App, later: provider credential for the private key plus non-secret app
  and installation identifiers.

There is no top-level `[authentication]` map in this design.

`auth=jwt` is the non-interactive JWT login endpoint. It does not implement
Vault's browser-based OIDC authorization flow. When SecretSpec calls a CI OIDC
mint endpoint, that endpoint and its audience are a separate trust boundary;
the audience is explicit and operator-bounded rather than inferred from a
project-controlled Vault address.

Different profiles may select different aliases when local development and CI
need different mechanisms:

```toml
[providers.db_local]
uri = "vault+database://vault.example.com/database?role=my-app"

[providers.db_ci]
uri = "vault+database://vault.example.com/database?role=my-app&auth=approle"
credentials = { role_id = "env", secret_id = "env" }

[profiles.default]
DB_USER = { description = "DB user", dynamic = "db_local.username" }
DB_PASSWORD = { description = "DB password", dynamic = "db_local.password" }

[profiles.ci]
DB_USER = { dynamic = "db_ci.username" }
DB_PASSWORD = { dynamic = "db_ci.password" }
```

### 8.3 Provider-attested identity and assurance

Authentication must produce `AuthSession` before issue. For Vault/OpenBao:

- AppRole and JWT login responses, supplemented by
  `auth/token/lookup-self` when needed, supply the provider entity ID, token
  type, lease duration, renewability, and use count;
- direct token authentication uses `auth/token/lookup-self` to obtain the same
  provider facts rather than treating possession of an opaque token as an
  identity assertion;
- the trust-domain identifier includes the provider product, provider-native
  cluster identity, and namespace; auth mount and method remain provenance;
- an empty entity ID, root or unbounded token, unknown expiration, or identity
  lookup that cannot be completed fails the provider-attested,
  lifecycle-contained contract before dynamic issue.

Identity granularity is reported honestly. Vault AppRole's default identity
alias is its RoleID and is normally `SharedRole`, even when many agent instances
use different SecretIDs. A JWT-authenticated entity is not automatically
called a workload: it remains `Other` unless an operator-owned provider binding
establishes whether the validated subject represents a workload or user.

A lifecycle-contained session and a uniquely identified workload are separate
claims. The first requires provider-owned, revocable authority over the issued
lease tree. The second additionally requires `PrincipalKind::Workload` from an
operator-controlled identity binding and acceptable bootstrap issuer,
audience, lifetime, and use facts. A shared AppRole can satisfy lifecycle
containment without identifying one agent instance. A reusable or
unknown-lifetime bootstrap credential prevents a short-lived-bootstrap claim
even when the exchanged Vault token is short-lived.

The first public Vault/OpenBao lifecycle-contained path requires a finite-lived
service token for provider-owned authentication. Batch tokens are rejected
because they cannot be manually revoked and do not provide the required
unknown-issue containment. Direct user-supplied tokens are accepted only under
an explicit operator-owned compatibility policy; project configuration cannot
relax this policy. Such a session is reported as degraded because SecretSpec
will not revoke its parent authority and an issue with unknown completion can
only rely on expiration.

Vault recommends batch tokens for many high-scale AppRole deployments. This
spec deliberately chooses a service token for the lifecycle-contained profile,
because that profile values explicit authority revocation and descendant-lease
containment over batch-token scalability. Deployments that require batch
tokens cannot be labeled as satisfying that profile.

A later mode may create a dedicated child service token from a supplied token.
That requires explicit `auth/token/create` authority and a defined policy/TTL
attenuation contract; it is never attempted implicitly.

Token use count is part of admission and scheduling. Identity lookup consumes
an authenticated request, as do issue, token/lease renewal, revoke, and close.
A provider must reject a use budget that cannot safely reach the next lifecycle
boundary. In particular, a token whose final use would create a leased secret
cannot yield a publishable lease, and a renewable long-running session cannot
pretend an exhausted token can be replaced without preserving the old lease's
parent dependency.

The first successful authentication pins the complete provider identity.
Reauthentication must produce the same trust domain, subject, and optional
actor. A mismatch stops issue or renewal and enters bounded cleanup.

### 8.4 Consumer environment scrubbing

Authentication material used by a dynamic provider must not be inherited by
the consumer merely because it came from SecretSpec's parent environment.

Session open accumulates the names of parent-environment inputs consumed
anywhere in the dynamic authentication chain:

- environment-backed credential values;
- ambient authentication used by a storage provider that supplies a credential;
- ambient authentication used by the dynamic provider itself.

The corresponding credential-resolution and provider-operation paths report
names, never values. Authentication choice is completed and frozen before child
spawn. A provider may reuse or refresh that selected mechanism later, but it
must not lazily switch to an unreported environment fallback after the child
has inherited its environment.

For the first Vault/OpenBao implementation this includes, as applicable:

- token variables;
- token-path variables;
- AppRole variables;
- JWT variables;
- CI OIDC request variables used to mint a JWT.

Values are never reported. Verbose output and reports may list scrubbed variable
names.

`run` first removes the union of scope-excluded names and consumed
authentication names from the inherited environment, then overlays the visible
SecretSpec values. An explicitly declared visible secret with the same name is
therefore a separate, auditable export decision; inheritance alone never
exports the issuer's authority.

The first release has no `expose_to_consumer` exception. A consumer that needs a
different credential should receive it under a separately declared SecretSpec
name rather than inherit the issuer's authority.

### 8.5 Authentication lifetime

The constructed lease provider owns whatever authenticated client or scoped
token it creates for issue, renewal, and revocation. A token supplied by the
user or a credential source remains user-owned and is never revoked by
SecretSpec. A token minted by AppRole, JWT, or an equivalent login is
provider-owned: it must have a future backend expiration, and explicit provider
close releases it when supported. A login returning unbounded provider-owned
authority aborts issue and immediately enters cleanup.

The provider guard is installed immediately after construction, before
authentication. It therefore closes known owned authentication state when
authentication, issue, composition, or spawn later fails. Lease revocation runs
before provider close. On Vault/OpenBao, successfully revoking an owned service
token confirms that the authority is closed and queues its descendant leases
for cleanup; it does not confirm that their downstream database users have
already been removed.

In-place lease renewal also maintains any authentication dependency required to
keep that lease valid. Reauthentication counts only if the backend preserves
the existing lease under the new authentication state; issuing a new parent
token does not by itself extend a lease tied to the old one. If the complete
chain cannot be extended in place, the effective lease is non-renewable and
consumer shutdown follows its conservative deadline.

Closing the provider token does not consume or revoke its bootstrap credential.
An input JWT, AppRole SecretID, CI OIDC request token, or stored credential may
remain usable according to its own issuer. Authentication reports that residual
bootstrap authority and its known or unknown expiration, use, and audience
bounds. Removing it from the consumer environment prevents accidental
inheritance but is not described as revocation.

Sharing authentication with a storage provider or another dynamic alias is an
optimization, not part of the first correctness contract.

## 9. Session lifecycle

### 9.1 Open transaction

Opening the first `run` session performs:

1. resolve profile and optional scope;
2. compute visible and accessed secret sets;
3. build and validate the complete resolution plan without I/O;
4. apply the operator trust ceiling, freeze the effective dynamic plan, and
   compute its value-free digest;
5. enforce the existing reason policy;
6. durably record the session/open audit intent;
7. resolve stored values and ordinary missing-value behavior;
8. resolve dynamic provider credentials;
9. construct dynamic providers and immediately install provider-close guards;
10. authenticate each referenced provider, validate identity and lifecycle
    policy plus use budget, and pin its provider-attested identity;
11. issue each referenced dynamic alias once, in alias order;
12. install each successful lease guard before continuing; if issue returns an
   applied failure, install its partial-lease guard before entering rollback;
13. project outputs onto SecretSpec names;
14. render compositions and evaluate required groups;
15. remove scope-excluded and consumed-authentication names from the inherited
    environment, then overlay the visible SecretSpec values;
16. recheck every authentication and lease deadline;
17. spawn the consumer;
18. renew or initiate shutdown according to the lease deadlines;
19. on exit, stop renewal work, revoke known leases, close providers, and drop
    local state.

Stored provider reads may be concurrent as they are today. Initial dynamic
issuance is deterministic and sequential.

The provider extracts cleanup state before validating publishable outputs,
expiration, or capabilities. If alias B returns an applied failure after alias
A issued, B's partial lease and A's complete lease are both revoked before open
returns. If composition, constraint validation, environment construction, or
child spawn fails after issuance, every known complete or partial lease is
cleaned up. Every constructed provider is explicitly closed on each rollback
path.

An issue whose completion is unknown has no locally usable cleanup handle or
lease. SecretSpec does not issue a replacement blindly and does not start the
consumer. It closes the alias's authentication session. A dedicated owned
service token can stop further authority and queue all descendant leases for
cleanup without knowing the missing lease ID; a batch or user-owned token
cannot provide that containment. Neither path claims the downstream database
account has already been removed.

### 9.2 Optional bindings

A referenced dynamic provider either issues its complete registered output set
or the session fails. An optional binding does not suppress:

- authentication failure;
- authorization failure;
- endpoint unavailability;
- malformed backend response;
- an expected output missing from a successful response.

This differs from a storage provider returning `None`: issuance is an explicit
resource-creation operation, not a lookup for a possibly absent value.

If no binding to an alias appears in the accessed set, the alias is unused and
no error from its unavailable authentication can affect the session.

Required groups remain presence constraints, not issuer fallback or selection.
Every accessed member is resolved independently. In particular, declaring
several dynamic members in one group may issue several leases, and
`exactly_one` fails if more than one resolves.

### 9.3 Deadline derivation

The conservative backend-returned lease expiration controls the lifecycle.
For a backend TTL, elapsed request time is already subtracted because expiration
was derived from request start. Vault/OpenBao initial database issuance has no
client-requested TTL; its role and backend configuration determine the initial
duration.

For each lease, SecretSpec derives:

```text
renew-by
    < graceful-stop
    < force-stop
    < unsafe-at
    < usable-until
    <= lease-expiration
    <= estimated-backend-expiration
```

Where:

- `usable-until` is the earlier of immutable credential rotation due and the
  conservative lease expiration;
- `unsafe-at` reserves clock skew before `usable-until`;
- `force-stop` reserves cleanup time before `unsafe-at`;
- `graceful-stop` reserves the configured child shutdown grace;
- `renew-by` reserves one bounded renewal operation before shutdown begins.

A lease whose remaining lifetime cannot cover startup and these reserves is
rejected before the consumer starts.

Session health is the conjunction of every referenced lease. Because one child
environment is published as a unit, any lease entering shutdown drives the
whole session; SecretSpec never continues with a partially valid environment.

The exact skew, operation timeout, shutdown grace, cleanup reserve, and minimum
useful lifetime are finalized before the public release and may be
provider-bounded.

### 9.4 Clocks and suspension

Across each issue or renewal request, SecretSpec records:

- the conservative wall-clock expiration;
- the request-start and response-receipt wall times;
- a conservative monotonic remaining-time budget.

Scheduling never extends the lease because the local wall clock moves backward.
Before publication, spawn, renewal, and consumer status decisions, the owner
uses the earlier of:

- the original monotonic budget;
- the remaining wall-clock budget.

After any wakeup, the wall clock is rechecked. A host suspension may prevent
SecretSpec from running cleanup on time; backend expiration remains the
fundamental bound. The first release documents this limitation rather than
introducing public clock-guarantee tiers.

### 9.5 Renewal

When `renewable` is true, the owner attempts renewal before `renew-by`.
When a provider URI specifies a renewal increment, the provider may send it as
an advisory renewal request. Only the returned expiration and capabilities are
accepted as lifecycle facts.

On success:

- outputs remain byte-for-byte unchanged;
- `issued_at` and `rotation_due_at` remain unchanged;
- expiration and opaque state are updated;
- all deadlines are recalculated conservatively.

On a safely retryable, definitely-not-applied error, the owner may retry with
bounded backoff while the old lease remains safe.

On an uncertain, fatal, or exhausted renewal failure, the owner schedules
graceful and force-termination attempts at the old lease's existing deadlines.

### 9.6 Non-renewable leases

The first public release does not issue a replacement. A non-renewable lease
therefore sets the maximum session duration:

- the consumer may exit naturally before its shutdown deadline;
- otherwise `run` begins graceful termination;
- it sends force-termination early enough to leave reserve before `unsafe-at`;
- it then performs best-effort revocation and local cleanup.

Failure to observe the boundary terminate cannot extend or pause the lease.
SecretSpec reports that loss of supervision; backend expiration remains the
ultimate validity bound.

This behavior supports bounded commands and renewable Vault/OpenBao leases. AWS
STS and other replacement-oriented providers may be added for bounded commands
later, but long-running transparent replacement requires a separate delivery
design.

### 9.7 Consumer supervision

`run` controls the strongest process boundary implemented for the platform
without claiming complete containment:

- on POSIX, the first implementation should create and signal a dedicated
  process group;
- on Windows, a Job Object is preferred when implemented;
- otherwise only the direct child is controlled and the limitation is reported.

Signals handled by SecretSpec are forwarded to the observed boundary. After
the documented grace period, SecretSpec sends the platform's force-termination
operation and observes whether the boundary exits.

A cooperative child may detach from a process group, and privileged processes
may escape stronger boundaries. Descendants outside the observed boundary can
retain copied environment values until backend expiration or successful
revocation. The specification does not call process-group control full process
containment.

### 9.8 Close and cleanup

Cleanup order is:

1. stop scheduling new renewal work;
2. finish or cancel the current bounded provider operation;
3. stop the consumer boundary when close is owner-initiated;
4. revoke every partial lease and every complete lease reported revocable;
5. explicitly close every provider and its owned authentication state;
6. discard output and authentication values;
7. remove the session from any process-local registry.

Normal child exit triggers explicit cleanup before `run` returns. `Drop` is a
best-effort fallback, not the primary mechanism.

Lease-revocation or provider-close failure is reported but cannot keep local
state open indefinitely. Backend expiration remains the upper bound when
cleanup is unsupported, unavailable, or uncertain.

No persistent secret-bearing orphan ledger is written in the initial releases.
The audit sink may retain an incomplete write-ahead intent and provider
correlation, but it cannot resume lease management because it contains no
backend lease ID, authentication token, or other cleanup capability.

### 9.9 Exit behavior

`run` returns:

- the child's exit status when the child exits normally;
- a dedicated documented exit code when SecretSpec stops it for lease safety;
- an ordinary SecretSpec error when the session cannot open or the child cannot
  start;
- conventional signal-derived behavior for an operator-initiated signal.

Revocation uncertainty after the child has stopped is a warning and audited
cleanup failure; it does not replace an otherwise meaningful child exit status.
The exact dedicated code is chosen before release.

## 10. Delivery

### 10.1 First-release environment delivery

Dynamic outputs are copied into the child environment under their declared
SecretSpec names:

```text
DB_USER=<lease username>
DB_PASSWORD=<lease password>
```

The existing `as_path` default remains `false`. Until dynamic file delivery
ships, `as_path = true` is rejected both on a dynamic binding and on any
composition whose transitive dependency closure contains a dynamic binding.

Environment delivery has explicit limitations:

- values cannot be changed in an already-running child;
- descendants inherit them unless they scrub them;
- debuggers, crash tooling, and sufficiently privileged processes may inspect
  them;
- SecretSpec cannot recall a value copied by the consumer.

In-place renewal is compatible because it changes expiration without changing
the environment bytes. Replacement is not compatible and is therefore not
performed.

If one dynamic alias feeds several environment variables, they all come from
one lease response and are inserted into the child environment as one completed
map before spawn.

### 10.2 Deferred replacement delivery

Replacement delivery is a separate specification because it must define:

- complete generation publication;
- multi-output consistency;
- environment restart or re-exec;
- stable file paths and atomic file generation switches;
- consumer acknowledgment or another adoption contract;
- overlap between old and new leases;
- when the old lease may be revoked;
- SDK behavior for previously copied values.

No first-release internal `DeliveryPlan` should pretend those choices are
already implemented. The current boolean environment delivery is sufficient.

## 11. CLI behavior

### 11.1 Operation matrix

| Operation                              | Dynamic behavior                                                                                 |
| -------------------------------------- | ------------------------------------------------------------------------------------------------ |
| `run`                                  | Opens a lifecycle session, issues referenced aliases, renews, revokes, and supervises the child. |
| `check`                                | Validates structure and reports `dynamic_unchecked`; never authenticates or issues.              |
| `check --json` / `--explain`           | Reports dynamic provenance without values or backend contact.                                    |
| `get`                                  | Returns `DynamicSessionRequired` when the target or its dependency closure is dynamic.           |
| `export`                               | Returns `DynamicSessionRequired` when the visible/accessed set is dynamic.                       |
| `validate` / one-shot SDK resolve      | Returns `DynamicSessionRequired` for a dynamic accessed set.                                     |
| `resolve_without_values` / report mode | Does not issue; returns dynamic provenance without value or expiration.                          |
| `set`                                  | Rejects a dynamic target; `--provider` cannot downgrade it.                                      |
| `import`                               | Rejects dynamic targets before performing writes to the import set.                              |
| `config provider login`                | Resolves and stores the dynamic alias's declared provider credentials normally.                  |
| cache commands                         | Reject dynamic providers; leases are never provider-cache entries.                               |

A least-access `get` of a static secret may still succeed in a profile that
contains unrelated dynamic bindings. Only the target and its dependency closure
matter.

An ordinary `--provider` override applies to stored routes only. It cannot turn
an explicit dynamic binding into a static read or replace its dynamic alias.
Supplying a dynamic-capable provider to `--provider` for a stored route is also
an error. Changing acquisition mode belongs in profile configuration.

### 11.2 Check and reporting

`check` never resolves dynamic authentication or contacts a dynamic backend.
A valid binding reports:

```text
DB_PASSWORD  dynamic_unchecked  provider db  output password
```

`dynamic_unchecked` means:

- the alias exists;
- it is dynamic-capable;
- its URI and credential routes are structurally valid;
- the output exists;
- no current authentication, authorization, endpoint, role, or issuance was
  exercised.

It satisfies the default required-secret gate because the declaration is
structurally capable of supplying the value. The distinct status prevents
`check` from claiming it actually resolved.

The first release has no `check --dynamic-preflight`. A generic non-issuing
preflight cannot reliably prove permission to issue, and authentication itself
may mint workload-identity tokens. Real authentication and issuance occur
transactionally at `run` open.

### 11.3 Reports and resolve responses

Value-free reports add dynamic provenance:

- provider alias;
- canonical credential-free provider URI;
- selected output;
- `dynamic_unchecked` status;
- effective delivery (`environment` in the first release).

They omit expiration and capabilities because no lease exists.

A stateful value-carrying response later adds:

- `source = "dynamic"`;
- dynamic provider alias;
- output name;
- provider trust domain, provider principal ID, principal kind, and optional
  provider-attested actor;
- authentication ownership, artifact kind, cleanup containment, and residual
  bootstrap-authority facts;
- issued-principal kind and output name, without its value;
- conservative lease expiration;
- renewable and revocable flags.

It never adds backend lease identifiers or opaque state.

When one result uses several providers, the existing top-level `provider`
summary may be empty or a documented mixed-provider marker. Per-secret
provenance is authoritative.

## 12. Audit and accountability

Dynamic lifecycle adds:

- `dynamic_authenticate`;
- `dynamic_issue`;
- `dynamic_renew`;
- `dynamic_revoke`;
- `dynamic_provider_close`.

Authentication and provider close are separate actions because they may mint or
invalidate authority independently of a lease. Their events share the session
and operation hierarchy with the issue or cleanup that triggered them.

Every mutating lifecycle operation emits a write-ahead intent before sending
the request and a completion event afterward. An intent contains the outbound
opaque operation correlation but no provider request ID yet. Its completion
adds any provider request IDs and the honest completion/cleanup outcomes. A
process crash can therefore leave an explicit incomplete intent instead of no
record of whether a mutation was attempted.

Dynamic mutation is fail-closed if its intent cannot be appended atomically to
the configured audit sink. This is stronger than the existing policy for
ordinary reads and is required because an issuance can create an external
resource. The sink must serialize concurrent writers and must not silently
truncate an event. This write-ahead audit is not a persistent lease ledger and
does not contain enough secret state to renew or revoke a lease after restart.

Events contain:

- existing audit session correlation;
- operation correlation and operation phase;
- provider request IDs returned for that phase;
- local lease ID for issue/renew/revoke correlation;
- project and profile;
- provider alias and credential-free canonical URI;
- bound SecretSpec key names and output names;
- non-secret provider-specific lifecycle request fields, such as renewal
  increment, where applicable;
- conservative lease expiration on successful issue or renewal;
- provider trust domain, provider principal ID, principal kind, optional actor,
  auth method/mount, ownership, artifact kind, and bounded lifetime/use facts;
- residual bootstrap kinds and their known or unknown lifetime, use, audience,
  and session-revocation facts;
- issued-principal kind and output name without the output value;
- normalized reason;
- outcome and redacted error kind;
- completion classification for a failed mutating result;
- whether lease revocation was unsupported or unconfirmed;
- whether provider-owned authentication cleanup was needed and confirmed;
- separate authority-shutdown and descendant-lease containment outcomes.

Events never contain:

- issued output values;
- provider credential values;
- ambient authentication values;
- backend lease IDs;
- opaque backend state;
- stateful FFI session handles.

Vault/OpenBao requests use a random `X-Correlation-ID`, which Vault audits by
default. SecretSpec records the same opaque value locally. It also records the
provider's response request ID when one is received. It never places a reason,
project name, secret name, local user, or other identifying text into the raw
header.

For database credentials, the provider principal identifies who requested
issuance and the issued `username` identifies the downstream database
principal. Vault/OpenBao may HMAC that username in provider audit logs; an
operator can correlate a username observed in database logs using the
provider's audit-hash facility. SecretSpec does not log the username merely to
make that join easier.

This is issuance attribution, not proof of use. A process may copy a bearer
credential and another process may present it. End-to-end use attribution
therefore also requires downstream database/service audit logs, and stronger
proof would require a future sender-constrained credential design.

The existing reason policy is enforced before provider credentials or ambient
authentication values are resolved.

Dynamic issuance does not introduce a separate first-use approval store. The
operator is responsible for enabling and retaining provider audit devices; a
sent correlation header proves only that SecretSpec supplied a join key, not
that an external audit sink retained it.

## 13. Native API and stateful FFI

Stateful APIs follow after `run` has exercised the lifecycle. Their design is
included here to preserve one ownership model without committing to per-field
accessors.

### 13.1 Rust session

`Secrets::report()` remains value-free and non-issuing.

`Secrets::validate()` and existing generated `load()` retain their static
snapshot contract. They return `DynamicSessionRequired` when their accessed set
contains a dynamic binding.

Dynamic resolution is explicit:

```rust
let session = secrets.open(options)?;
let current = session.resolve()?;
use_values(&current);
session.close()?;
```

`SecretSession` owns:

- the immutable project/profile/scope plan;
- resolved stored values needed by the plan;
- dynamic provider instances and live leases;
- the current complete resolved map;
- renewal coordination and health;
- explicit idempotent close state.

`resolve()` returns the complete visible scope from one local session-state
read. It does not accept an arbitrary list of names.

A convenience `get(name)` may exist in Rust or SDK wrappers, but it indexes a
complete current response and is not a separate FFI lifecycle operation.

A stateful API has no consumer process to terminate. When a lease can no longer
be kept safe, its background owner marks the session unhealthy, refuses new
`resolve()` or `refresh()` responses before `unsafe-at`, and performs cleanup.
It cannot invalidate values the caller copied from an earlier response; status
and expiration make that limit explicit.

### 13.2 Generated Rust types

Generated types remain ordinary value shapes:

```rust
pub struct ResolvedSession<T> {
    pub secrets: T,
    pub provider: String,
    pub profile: String,
    session: SecretSession,
}

impl<T> ResolvedSession<T> {
    pub fn refresh(&mut self) -> Result<&T>;
    pub fn status(&self) -> SessionStatus;
    pub fn close(&mut self) -> Result<()>;
}
```

`refresh()` obtains the current complete scoped response and replaces the whole
typed value shape. Dynamic fields do not become hidden per-field accessors.

This is an honest contract:

- a caller may copy a plaintext `String`;
- SecretSpec cannot recall or zeroize that copy;
- the session keeps the backend lease alive while retained;
- status and expiration say whether a newly requested snapshot is safe;
- future replacement refreshes the complete object rather than mutating
  individual fields independently.

With in-place renewal, `refresh()` returns the same value bytes and `status()`
exposes current health and expiration. Replacement semantics are specified
before any SDK can receive changed values.

### 13.3 FFI surface

The existing one-shot function remains:

```c
char *secretspec_resolve(const char *request_json);
```

It continues to support static value resolution and value-free dynamic reports.
Value-carrying one-shot dynamic resolution returns
`dynamic_session_required`.

Stateful support adds four functions that accept a NUL-terminated UTF-8 JSON
request and return the existing JSON envelope:

```c
char *secretspec_session_open(const char *request_json);
char *secretspec_session_resolve(const char *request_json);
char *secretspec_session_status(const char *request_json);
char *secretspec_session_close(const char *request_json);
```

The resolve, status, and close requests contain the process-local handle:

```json
{
  "session_id": "<unguessable session capability>"
}
```

Using request objects keeps the input contract consistent with
`secretspec_resolve` and permits future optional fields without changing the C
ABI. There is no C-level per-secret getter and no snapshot request that accepts
an arbitrary list of names. The open request already selects the profile and
optional SecretSpec scope. `session_resolve` returns the current complete
visible scope atomically.

`session_open` returns the new session ID and the initial complete scoped
response in one envelope. If recoverable response construction or handle
registration fails, the just-opened session is closed before returning an
error. Callers therefore do not need an issue-prone
open-then-first-resolve handshake.

SDK wrappers may expose:

- `session.secrets` as their current typed or map snapshot;
- `session.refresh()` to replace that whole snapshot;
- local `get(name)` convenience;
- `status()` and structured close.

### 13.4 FFI handle rules

Session IDs are random, unguessable process-local capabilities. They are not
logged.

Every FFI entry point:

- catches panics before crossing the ABI;
- validates UTF-8 and JSON against that function's request schema;
- uses the existing `{ "ok", "response" | "error" }` envelope;
- rejects malformed, unknown, or closed IDs;
- does not hold the global registry lock during provider I/O;
- checks that the current process is the process that opened the session.

Sessions are invalid after `fork` and must be opened in the child. The exact
at-fork synchronization implementation is finalized with the FFI work rather
than pre-designed in the first `run` release.

The Rust session's `close()` is idempotent while its object exists. Once a C
handle is removed from the registry, a second close receives a closed/unknown
handle error; no tombstone cache is required.

### 13.5 Resolver IPC

Resolver mode is the third consumer of this lifecycle, alongside `run` and the
stateful FFI. It is not part of any phase here, but `secretspec.resolver/1` has
already reserved room for it, so dynamic issuance lands as capabilities on the
existing protocol version rather than as a version 2. The reservation is
recorded in the shipped specification under
`docs/src/content/docs/reference/ipc-architecture.md`, and its rules in
`ipc-wire.md`.

What the wire protocol already provides:

- **The session is the lifecycle unit.** An IPC session is one connection to one
  `secretspec serve` child, with profile, scope, and reason fixed at
  initialization. That is the same boundary §2.4 and §9 assume, and disconnect
  is already the release path for every session-owned resource, which is what a
  lease needs.
- **Growable enumerations.** Both clients decode an unknown `source` value and
  an unknown error kind rather than failing the frame, so `source = "dynamic"`
  and a `dynamic_session_required` error can be added without breaking a
  deployed peer. The error code range below `-32011` is reserved.
- **A callback direction.** The endpoint can already send a request to its
  client and receive an answer, gated on what the client advertised. That is the
  mechanism §10.2 needs for replacement adoption, and the one §13.1 needs to
  report a session that has become unhealthy.
- **Capability-gated members.** New result members such as `renewable`,
  `revocable`, and lease expiry are sent only to a client that advertised
  understanding them, so an older client never sees a field it would reject.

What is still open, and belongs to the replacement and stateful-session work
rather than here:

- Atomic multi-output resolution. `resolver.get` resolves one name; one lease
  feeding several declared names has to be read as one consistent set, which is
  a new capability-gated method bounded by the session's existing profile and
  scope.
- Whether an IPC session may own leases at all, or whether resolver mode stays
  static-only until the stateful Rust session exists. The reservation does not
  decide this; it only ensures the decision does not cost a protocol version.
- Naming. `resolver.get` returns a `path_lease_id`, a handle over a
  resolver-owned file that is unrelated to a credential lease. That field was
  deliberately named for the path it releases so dynamic work can use "lease"
  for the credential meaning without collision.

## 14. Built-in providers

### 14.1 Vault/OpenBao database credentials

Vault and OpenBao database credentials are the first dynamic providers because
they exercise:

- multi-output issuance;
- backend-reported lease duration;
- in-place lease renewal;
- revocation;
- opaque backend lease state;
- configured/ambient token, token-file, AppRole, and JWT authentication;
- provider-attested identity and authentication containment;
- reason and audit correlation.

The intended URI shape is:

```text
vault+database://[namespace@]host[:port][/mount]?role=DB_ROLE[&auth=METHOD][&auth_role=AUTH_ROLE][&renew_increment=DURATION]
openbao+database://[namespace@]host[:port][/mount]?role=DB_ROLE[&auth=METHOD][&auth_role=AUTH_ROLE][&renew_increment=DURATION]
```

Provider-specific parsing strictly validates:

- endpoint and TLS selection;
- namespace;
- database engine mount;
- database role;
- optional renewal increment;
- authentication method, optional authentication role, and supported credential
  names;
- unknown query parameters.

The first provider registration supports roles configured with
`credential_type=password` and has the fixed outputs:

```text
username
password
```

Issue maps a compatible backend response to one `Lease`. It does not require a
preflight read of the backend role definition because callers may have
permission to generate credentials without permission to inspect the role.
Instead it validates that the issue response contains the fixed password-role
shape. If a response represents another credential type after creating a
backend lease, issue returns an applied failure with a `PartialLease` and the
coordinator revokes it before failing open.

Initial lease duration comes exclusively from the backend role and mount
configuration and the issue response; the generate-credentials request has no
TTL input. `renew_increment`, when present, is an advisory input only to the
lease renewal API. Returned lease duration and renewable facts are
authoritative. Renewal never changes the username or password. Revocation uses
the backend lease revoke API.

The provider reports the Vault/OpenBao entity as the provider principal and
marks `username` as the issued-principal output. It captures the provider
request ID from every response that supplies one. Requests send only the opaque
SecretSpec operation correlation to provider audit; project, profile, key names,
and reason remain in the local audit event.

An owned AppRole or JWT login must return a finite-lived service token. Its
successful close invalidates that authority but maps descendant lease cleanup
to `AcceptedAsync`. A batch login is rejected. A direct user token follows the
operator-owned degraded compatibility policy from section 8.3 and is never
revoked by SecretSpec.

#### Direct API lifecycle ownership

The first provider owns the complete lifecycle itself. It sends
`X-Vault-Request: true` and a random `X-Correlation-ID` on every request. It
does not enable response wrapping for dynamic issuance and does not use a
generic HTTP retry layer. It disables environment-derived and library-default
proxy discovery. Automatic redirects are disabled; if redirect support is
required for an approved Vault/OpenBao topology, SecretSpec follows it
explicitly only after validating the destination against the operator-owned
trust binding and never replays a request whose completion is not definitely
unapplied.

Vault Agent and Vault Proxy can cache dynamic-secret responses, return the same
lease for a repeated request, independently renew cached leases, retry selected
upstream failures, and inject or forcibly substitute an auto-auth token. Those
behaviors create a second lifecycle owner, can change the provider principal
and authentication ownership seen by Vault/OpenBao, and can violate the
coordinator's completion classification for the mutating
`GET /database/creds/:role` request.

The lifecycle-contained first-release profile therefore accepts an Agent/Proxy
address only when an operator-owned topology declaration attests all of the
following:

- no `cache` stanza for this listener, because even an empty stanza enables
  caching;
- upstream request retries are disabled, including `num_retries = -1` and
  consistency retry modes;
- auto-auth token injection and forced substitution are disabled; and
- Agent/Proxy does not renew or revoke SecretSpec's tokens or leases.

If SecretSpec cannot verify or rely on an operator attestation of those facts,
the lifecycle-contained session is rejected. Changing correlation headers to
force a cache miss is not a substitute: it may create another credential after
an ambiguous failure. Delegating authentication, renewal, or recovery to
Agent/Proxy requires a later, separate lifecycle-owner mode.

### 14.2 AWS STS

AWS STS is deferred until after the first Vault/OpenBao release.

Its provider outputs are:

```text
access_key_id
secret_access_key
session_token
```

AWS STS credentials are non-renewable. AWS can deny temporary sessions through
IAM or resource policy changes, but that is not a lease-style close operation
SecretSpec should perform automatically. The initial provider therefore reports
`revocable = false`. Under the first lifecycle it can support a bounded command
that ends before the shutdown deadline, but not a transparent long-running
session.

A later replacement-delivery specification should prefer an AWS-native adapter,
such as a session-owned `credential_process`, over trying to update a running
process environment.

### 14.3 GitHub App tokens

GitHub App installation tokens are also deferred. They use a named provider
alias like every other dynamic provider:

```toml
[providers.github]
uri = "github+app://api.github.com?app_id=12345&installation_id=67890"
credentials = { private_key = "keyring" }

[profiles.production]
GITHUB_TOKEN = {
  description = "GitHub App installation token",
  dynamic = "github.value"
}
```

There is no inline-source exception.

### 14.4 External issuers

The initial manifest has no `type = "command"` dynamic provider and no public
executable protocol.

An external issuer contract would need:

- versioned fail-closed messages;
- mandatory future expiration;
- statically declared outputs;
- bounded I/O and execution;
- explicit authentication transfer;
- opaque sensitive state;
- renewal and revocation semantics;
- outcome uncertainty;
- executable trust and policy;
- subprocess-tree cleanup.

At least two native dynamic providers should exercise the internal lease
contract before an external protocol is considered. An unknown dynamic provider
scheme never falls back to executing a command.

## 15. Security invariants

- Dynamic syntax requires a revision older clients reject.
- A dynamic binding explicitly names one dynamic provider alias and output.
- A dynamic provider is never used as a storage fallback or cache.
- A dynamic provider is never used as a provider credential source.
- An issued value never calls a storage provider's `set()` or enters a provider
  cache.
- Only lifecycle-owned operations issue leases.
- Stateless value-carrying operations never silently issue.
- Only aliases referenced by the scoped accessed set authenticate or issue.
- Project, profile, alias, reason, local user, and agent detection are never
  treated as authenticated identity.
- Authentication must return a provider-attested identity qualified by its
  trust domain before issue.
- Provider subject and optional actor are distinct and remain pinned across
  reauthentication.
- Lifecycle containment is never presented as proof of a unique workload;
  workload identity requires an operator-bound `Workload` principal and
  acceptable bootstrap facts.
- Residual bootstrap authority is reported even though its value is scrubbed,
  and scrubbing is never presented as revocation.
- The operator trust ceiling is applied and the plan is frozen before any
  authentication value is read or sent.
- One alias issues at most one lease per session across the complete request
  path, including SDKs, proxies, and intermediaries.
- Policy and reason checks happen before authentication values are resolved.
- Environment inputs consumed anywhere in the dynamic authentication chain are
  reported before spawn and removed from inherited child state.
- The selected authentication mechanism is frozen before spawn and cannot
  switch to an unreported environment fallback.
- Backend-returned lifetime and capabilities are authoritative inputs; local
  deadlines may only shorten them.
- A lease's effective expiration includes authentication dependencies whose
  expiry would invalidate its outputs.
- Renewal never moves immutable `issued_at` or `rotation_due_at`.
- Renewal never changes output bytes.
- Replacement does not occur until a delivery/adoption contract is specified.
- Generic retries are operation-specific and occur only for retryable,
  definitely-not-applied errors within that operation's deadline.
- An operation with applied or unknown completion is never retried as
  definitely unapplied.
- Every mutating authentication or lease operation has a durable value-free
  audit intent before its request is sent.
- One opaque operation correlation joins local and provider audit; raw
  correlation headers never contain user, project, reason, or secret metadata.
- Unsupported revocation is represented honestly.
- Authority shutdown, descendant-lease containment, and downstream credential
  invalidation are reported as separate facts.
- Every known partial-open lease has a cleanup guard.
- An applied issue failure transfers cleanup-capable partial state before
  rollback begins and never publishes its outputs.
- Every constructed dynamic provider has a close guard before authentication.
- Dynamic provider construction performs no backend mutation before that guard
  exists.
- SecretSpec closes authentication artifacts it minted but never revokes a
  credential supplied by the user or a credential source.
- Provider-owned authentication artifacts require a future backend expiration.
- The lifecycle-contained Vault/OpenBao path uses provider-owned service
  tokens; batch tokens are rejected and direct user tokens require an
  operator-owned degraded compatibility policy.
- Response wrapping is never treated as transactional issuance or orphan
  recovery.
- Provider HTTP clients do not inherit ambient proxy routing or automatically
  forward authentication across redirects.
- Vault Agent/Proxy caching, independent retries, auto-auth token substitution,
  or external lifecycle management is not combined with SecretSpec lifecycle
  ownership in the lifecycle-contained first-release profile.
- Issued values, authentication inputs, backend lease IDs, opaque backend
  state, and FFI handles never enter logs or value-free reports.
- A process environment is not described as isolated or refreshable.
- Process supervision is described according to the boundary actually
  controlled.
- Backend expiration remains the bound after host suspension, abrupt process
  death, or cleanup failure.

`SecretString` reduces accidental copies in the Rust core. It does not provide
end-to-end zeroization: child environments, FFI strings, host-language strings,
kernel buffers, HTTP clients, and consumer memory may retain copies outside
SecretSpec's control.

## 16. Implementation fit

The current architecture already provides most of the non-lifecycle machinery:

- `ProviderAlias` stores URI configuration and one-hop credentials.
- Project and user aliases already have defined precedence.
- `ConfigGraphLoader` visits every inherited document before overlay.
- Provider registrations already expose credential names and factories.
- `CompiledManifest` and `MissingPolicy` separate parsed and effective config.
- `ResolutionPlan` groups secrets by raw provider spec.
- Scope planning already computes visible names and transitive composition
  dependencies.
- `Materialize::None` distinguishes value-free reporting from side effects.
- `run_command` already keeps temporary-resource ownership alive until child
  exit.
- The workspace `reqwest` dependency disables default features and does not
  enable system-proxy discovery; the dynamic client must preserve that property
  and explicitly disable automatic redirects.
- The FFI already uses versioned JSON envelopes and panic containment.

Required structural work for the first release:

- support manifest revision `1.1` and monotonic `extends` checks;
- add the secret `dynamic` selector and atomic acquisition inheritance;
- register provider acquisition capability and dynamic output schemas;
- allow provider alias and credential lookup for dynamic registrations;
- add operator-owned trust ceilings and frozen value-free plan digests;
- reject dynamic providers in stored routes, caches, and credential sources;
- report environment use through credential resolution and dynamic provider
  operations without reporting values;
- compile `Acquisition::Dynamic` and derive alias groups;
- add `ProviderTrustDomain`, `ProviderIdentity`, `AuthSession`, `LeaseProvider`,
  `Lease`, `PartialLease`, applied issue-failure, renewal, revocation,
  multi-axis provider close, and operation-specific completion/retry models;
- add durable write-ahead lifecycle audit with operation correlation and
  provider request IDs;
- add scoped session open, rollback, deadline, health, and cleanup state;
- add a fake dynamic provider and clock for fault injection;
- extend reports and resolve provenance;
- add dynamic audit actions;
- extend `run` with whole-chain authentication scrubbing, renewal scheduling,
  signal handling, and bounded termination attempts;
- implement Vault/OpenBao database issue, renew, and revoke.

The first release does not require:

- a top-level dynamic-source map;
- a top-level authentication map;
- inline-source parsing;
- `dynamic = false`;
- source fingerprints or approval storage;
- located dynamic field provenance;
- authentication-scope grouping;
- lifetime/generation dependency sets;
- file publication;
- replacement/adoption;
- stateful FFI or generated accessors.

## 17. Delivery plan

### Phase 0: internal configuration and lifecycle foundation

- Add revision `1.1` feature gating and compatibility tests.
- Add dynamic provider capability metadata and strict output validation.
- Add `dynamic = "alias.output"` parsing and atomic acquisition inheritance.
- Exercise every stored/dynamic/composition inheritance pairing plus
  metadata-only and absent entries.
- Reject dynamic credential sources and transitive dynamic `as_path`.
- Compile scoped dynamic groups by alias.
- Implement a fake lease provider with issue, renewal, revocation, short TTLs,
  malformed post-creation responses, applied partial failures, and uncertain
  outcomes.
- Give the fake provider configurable provider-attested subjects, actors,
  authentication ownership, token classes, use budgets, and cleanup
  containment plus residual bootstrap authority.
- Compile an operator trust ceiling into an immutable effective provider plan
  and digest before reading authentication values or contacting a backend.
- Implement transactional open and cleanup guards.
- Exercise provider-owned authentication cleanup before and after issue.
- Implement conservative wall/monotonic deadlines and fail-closed health.
- Test authentication dependencies that expire before the issued credential.
- Add value-free `dynamic_unchecked` reporting.
- Define operation errors for every CLI and one-shot SDK surface.
- Add durable write-ahead lifecycle audit intent and completion events without
  values or backend cleanup identifiers.

This phase is internal and receives no public target version.

### Phase 1: internal Vault/OpenBao vertical slice

- Add strict `vault+database` and `openbao+database` provider configurations.
- Reuse existing provider credential-source resolution, but authenticate
  explicitly and require Vault/OpenBao to attest the provider principal.
- Pin provider trust domain, subject, and optional actor for the session.
- For the lifecycle-contained path, accept only provider-owned, finite-lived
  service tokens; reject batch tokens and identityless, root, or unbounded
  sessions. Non-renewable tokens bound the session lifetime.
- If a direct user-supplied token compatibility path ships, require an explicit
  operator opt-in and report degraded cleanup containment.
- Issue one username/password lease per referenced alias for a role configured
  with `credential_type=password`.
- Validate conservative expiration and output schema before publication; turn
  incompatible post-creation responses into cleanup-capable applied failures.
- Set immutable issuance and rotation deadlines independently of renewable
  lease expiration.
- Renew unchanged credentials using the backend lease API.
- Revoke on normal close and every known partial failure.
- Close SecretSpec-minted Vault/OpenBao authentication tokens without revoking
  user-supplied tokens.
- Report authority shutdown separately from asynchronous descendant-lease
  cleanup; never treat a queued token-tree revocation as confirmed database
  account removal.
- Use an opaque operation correlation ID on every provider mutation, retain
  provider request IDs when returned, and write audit intent before dispatch.
- Use the Vault/OpenBao API directly. If an Agent or Proxy endpoint is allowed,
  require an operator topology declaration and disable its dynamic-secret
  cache, automatic retries, auto-auth token injection, and lifecycle renewal.
- Accumulate and scrub environment inputs consumed across the complete dynamic
  authentication chain.
- Extend `run` with bounded renewal, signals, consumer termination attempts,
  and cleanup.
- Exercise scope and composition behavior.

Exit gates prove:

- a previous released CLI and proc macro reject the manifest;
- a project cannot widen the operator trust ceiling or redirect authentication
  to a different origin, namespace, role, audience, or ambient credential
  route;
- an unused alias performs no authentication or issuance;
- authentication returns a provider-qualified principal before issuance, and
  subject or actor changes during reauthentication fail the session;
- a shared AppRole is reported as a shared role rather than a unique workload;
- the provider-attested, lifecycle-contained path rejects batch, root,
  identityless, unbounded, and unknown-expiry authentication artifacts;
- only an operator-bound `Workload` principal with acceptable bootstrap issuer,
  audience, lifetime, and use facts is described as workload identity;
- reusable or unknown-bound JWTs, SecretIDs, request tokens, and supplied
  tokens remain visible as residual bootstrap authority after exchange;
- two bindings to one alias issue once;
- two aliases with matching URIs issue independently;
- a scoped-out alias is not issued;
- composition dependencies issue but remain hidden when out of scope;
- issue or spawn failure cleans every known lease;
- an applied issue failure installs and revokes its partial lease without
  publishing outputs;
- issue or spawn failure closes every constructed provider and its owned
  authentication state;
- an uncertain authentication or issue is not retried and never starts a
  consumer;
- authenticate, issue, renew, revoke, and close retries obey their distinct
  deadlines and never generically retry applied or unknown outcomes;
- no SDK, Vault Agent, Vault Proxy, or intermediary performs an independent
  retry of a mutating dynamic-secret request;
- an Agent/Proxy cannot inject or substitute its own token, change the pinned
  provider principal, or become the token/lease lifecycle owner;
- the Vault/OpenBao HTTP client inherits no ambient proxy and follows no
  automatic redirect; any explicit redirect path remains inside the
  operator-bound topology;
- an unknown issue closes a provider-owned service-token authority and reports
  descendant cleanup as asynchronous without claiming confirmed database
  removal;
- a batch or supplied user token cannot satisfy the lifecycle-contained
  unknown-issue contract;
- response wrapping does not make an unknown issuance recoverable;
- renewal never changes output bytes;
- renewal never advances the immutable credential-age rotation deadline;
- effective expiration never outlives a parent authentication dependency;
- clocks moving backward never extend a local deadline;
- every provider mutation has a durable audit intent before dispatch and a
  completion event afterward when a result is known;
- opaque correlation IDs and provider request IDs permit a value-free join to
  provider audit records;
- values, provider credentials, issued usernames, lease IDs, and backend
  cleanup handles never enter diagnostics or audit;
- reports distinguish the provider principal from the issued database
  principal, and issuance attribution from downstream credential use;
- inherited authentication variables consumed anywhere in the dynamic
  credential chain do not reach the child;
- a non-renewable or failed-renewal lease triggers graceful and force
  termination before its unsafe boundary, and loss of supervision is reported.

### Phase 2: first public dynamic-secrets release

- Publish the Vault/OpenBao database workflow.
- Keep `run` as the only value-carrying lifecycle owner.
- Support environment delivery, issue, in-place renewal, and revocation.
- Document lifecycle containment and workload-identity assurance as separate
  claims, and label any supplied-token compatibility path as degraded.
- Document that the database username is an issued principal, not the
  authenticating provider principal, and that downstream database audit is
  required to attribute actual use.
- Document the direct-API requirement and the unsupported Agent/Proxy cache,
  retry, auto-auth token, and lifecycle configurations.
- Report `dynamic_unchecked` from `check`.
- Reject dynamic file delivery, replacement, cache, stateless resolution, and
  writes with versioned diagnostics.
- Document process-boundary and abrupt-exit limitations.
- Assign the target SecretSpec release and add its version at every provider
  list, selector example, reference section, landing page, README, and generated
  summary where the unreleased capability appears.

### Phase 3: stateful Rust and polyglot sessions

- Add `Secrets::open()` and full-scope `SecretSession::resolve()`.
- Add generated `ResolvedSession<T>` with whole-object `refresh()`.
- Add FFI open/resolve/status/close.
- Return the initial full-scope response with the FFI open handle.
- Add creator-process enforcement and host-language structured close.
- Keep the response scoped at open; do not add arbitrary name snapshots.

This phase still supports only in-place renewal unless the replacement
specification has landed.

### Phase 4: replacement and delivery

Write and approve a separate specification before implementing:

- reissue and complete-generation state;
- file delivery and stable paths;
- restart/re-exec adoption;
- old/new lease overlap;
- SDK replacement snapshots;
- AWS-native delivery;
- GitHub App replacement;
- optional persistent management.

Only after those semantics stabilize should SecretSpec add AWS STS for
long-running consumers, dynamic files, restart-on-reissue, or an external issuer
protocol.

## 18. Decisions and remaining questions

### 18.1 Resolved decisions

- Dynamic configuration uses manifest revision `1.1`.
- `[providers]` is the single user-facing alias and authentication-routing
  system.
- Storage and dynamic providers share registration/configuration but implement
  separate operation traits.
- Provider configuration and request context are not identity. A dynamic
  provider authenticates first and attests a trust-domain-qualified subject
  plus an optional actor.
- The provider principal is distinct from the principal issued by a downstream
  secret engine, such as a database username. Reports and audit retain that
  distinction.
- Subject and actor are pinned for the authentication session; a change during
  reauthentication is fatal.
- Lifecycle containment and workload-identity assurance are separate claims.
  A service token with descendant cleanup can still represent a shared role;
  a workload label additionally requires an operator-controlled identity and
  bootstrap binding.
- Authentication reports residual bootstrap authorities with value-free,
  possibly unknown lifetime, use, audience, and session-revocation facts.
- The first Vault/OpenBao implementation does not infer an actor. AppRole is
  reported as a shared role unless an operator-controlled binding provides
  stronger semantics.
- An operator trust ceiling constrains origins, TLS trust, network topology and
  replay guarantees, namespaces, mounts, roles, authentication methods,
  audiences, credential routes, and lifetime maxima. Project configuration can
  only narrow it.
- The effective provider plan and its digest are frozen before authentication
  values are read or a backend is contacted.
- A dynamic binding is `dynamic = "<provider-alias>.<output>"`.
- The binding must name an alias, not an inline URI.
- Selectors split at the final period and otherwise preserve existing alias
  names.
- The first release has no inline or expanded binding form.
- Provider registrations declare output names; manifests do not repeat them.
- The first Vault/OpenBao database registration supports only roles configured
  with `credential_type=password`; incompatible post-creation responses are
  rolled back as partial leases without requiring permission to preflight-read
  the role.
- Derive-time validation does not read user-global aliases; runtime structural
  validation completes alias, capability, output, and credential checks.
- One provider alias is one lease per session.
- Different aliases are independent even when their URIs match.
- Dynamic aliases cannot use fallback or cache.
- Dynamic aliases cannot be storage routes or provider credential sources.
- Acquisition kind overrides atomically across profile inheritance.
- An explicit stored acquisition replaces inherited dynamic acquisition
  without `dynamic = false`.
- Scopes select the session's visible set; composition adds hidden accessed
  dependencies.
- A selected dynamic issuance failure is an operation error, not optional
  absence.
- The first public owner is `run`.
- The first release delivers through the environment only.
- The first release supports issue, in-place renewal, and revoke, but not
  replacement.
- Authentication is an explicit provider operation before issue. Its result
  records principal, ownership, token class, expiration, renewability, use
  budget, and cleanup containment without exposing the bearer token.
- The lifecycle-contained Vault/OpenBao path uses a provider-owned,
  finite-lived service token. Batch tokens are rejected because they cannot be
  manually revoked; a direct supplied token, if supported, is an
  operator-enabled compatibility path with degraded containment.
- Issue failure distinguishes definitely-not-applied, applied with
  cleanup-capable partial state, and unknown completion. Applied partial state
  is guarded before rollback and never published.
- Authenticate, issue, renew, revoke, and provider close use distinct retry
  deadlines; the generic coordinator never retries an applied or unknown
  outcome blindly.
- Completion guarantees cover the entire network path. Independent SDK,
  proxy, or intermediary retries are incompatible with a
  definitely-not-applied classification.
- The Vault/OpenBao HTTP client disables implicit proxy discovery and automatic
  redirects. Any explicitly supported redirect is revalidated against the
  operator trust binding before authentication can be forwarded.
- Response wrapping is transport protection, not unknown-issuance recovery,
  and is not enabled for database credential issuance by the first
  Vault/OpenBao implementation.
- Vault/OpenBao initial database credential lifetime is backend-controlled;
  only an optional advisory renewal increment is configurable.
- Credential age is anchored when issuance begins. Renewal can extend a lease
  but never advances the immutable rotation deadline or changes outputs.
- Each provider reports one effective expiration and renewability bound across
  the credential and any authentication dependency that can invalidate it.
- Provider-owned authentication is created only after a close guard exists and
  is explicitly closed; user-supplied authentication is never revoked.
- Closing a provider reports authority invalidation separately from descendant
  lease cleanup. Vault/OpenBao token revocation may confirm the first while
  only queuing the second; that is not confirmed database account removal.
- A bootstrap JWT, AppRole SecretID, or supplied token has its own lifecycle and
  is not revoked merely because the exchanged session token is closed or an
  environment variable is scrubbed.
- SecretSpec owns the Vault/OpenBao dynamic lifecycle directly. Agent or Proxy
  endpoints require an operator-owned topology declaration and are compatible
  only when caching, independent retries, auto-auth token injection, and
  external token/lease management are disabled.
- Non-renewable or failed-renewal sessions trigger bounded shutdown before the
  lease becomes unsafe without claiming that an OS process can always be
  terminated.
- Existing provider credentials and provider-native auth mechanisms are reused.
- Parent environment inputs consumed anywhere in a dynamic provider's
  credential chain are removed from inherited child state before declared
  SecretSpec values are overlaid.
- Dynamic bindings and compositions that transitively depend on them cannot use
  `as_path` initially.
- There is no dynamic-specific first-use approval store.
- `check` is structural and reports `dynamic_unchecked`; there is no initial
  dynamic preflight mode.
- Every provider mutation requires a durable, value-free audit intent before
  dispatch and a completion event afterward when its result is known.
- An opaque operation correlation ID is sent to the provider, provider request
  IDs are captured when returned, and neither contains request context or
  secret material.
- Provider audit can attribute issuance to an authenticated principal, but
  attributing actual credential use requires audit from the downstream system.
- Stateful APIs operate on the complete immutable scope, not arbitrary name
  snapshots.
- Generated SDK refresh replaces the complete typed value set rather than
  introducing per-field session accessors.
- No persistent secret-bearing lease ledger or command issuer ships initially.
  The audit sink can retain incomplete mutation intent and correlation data,
  but it is not a recovery ledger.

### 18.2 Questions to close before Phase 1

- Define the operator trust-policy syntax, managed-policy precedence, and the
  trust-domain identifier used for a Vault/OpenBao cluster and namespace.
- Decide whether the first public release includes direct supplied-token
  compatibility and, if so, define its exact operator opt-in and degraded
  diagnostics.
- Define the operator-controlled bindings, if any, that may classify a
  provider subject as a workload or user rather than `Other` or `SharedRole`.
- Define which residual bootstrap kinds are allowed for each assurance profile
  and whether unknown issuer, audience, lifetime, or use facts degrade or reject
  a session.
- Choose maximum session-authentication lifetime, residual-bootstrap lifetime,
  backend lease lifetime, and immutable credential-age defaults.
- Specify use-budget admission: the number of token uses reserved for identity
  lookup, issue, renew, revoke, and provider close.
- Decide whether response-wrapped AppRole SecretID delivery is in scope and, if
  so, define one-use unwrap completion and residual-authority reporting.
- Finalize the Vault/OpenBao dynamic URI schemes and strict parameter grammar.
- Choose the minimum and maximum accepted renewal increment and whether
  omission leaves the parameter out or sends the backend-default zero value.
- Choose clock-skew, operation-timeout, shutdown-grace, cleanup-reserve, and
  minimum-useful-lifetime defaults.
- Define the exact dedicated exit code for lease-safety termination.
- Define the minimum process boundary implemented on every supported platform.
- Enumerate the exact ambient inputs reported by each Vault/OpenBao
  authentication path and by supported storage credential-source paths.
- Version the resolution-report and resolve-response schema changes.
- Decide how mixed-provider top-level report attribution is rendered while
  keeping per-secret provenance authoritative.
- Define the durable audit sink format, append/locking and durability contract,
  failure behavior, and correlation/request-ID report schema.
- Confirm the minimum supported Vault/OpenBao versions and which authentication,
  renewal, revoke, and token-close responses map to each outcome, including
  asynchronous, already-revoked, and expiry-only behavior.
- Define how an Agent or Proxy endpoint and its operator attestation are
  represented, verified, and invalidated when dynamic cache, retry, auto-auth
  token, or lifecycle settings change.

These include security-policy, compatibility, and ownership choices. They must
be resolved before Phase 1 can claim the provider-attested identity and cleanup
contract described here.

## 19. Research basis

- exe.dev's agent workload identity flow illustrates a provider-issued OIDC
  identity being exchanged for short-lived cloud access without placing a
  long-lived cloud credential in the workload:
  <https://blog.exe.dev/oauth-for-agents>
- OAuth token exchange distinguishes the authenticated subject from an
  optional acting party, which is the model used here for provider-attested
  subject and actor:
  <https://www.rfc-editor.org/rfc/rfc8693.html>
- OAuth resource indicators show why a minted token's audience or target
  resource must be explicit and operator-bounded:
  <https://www.rfc-editor.org/rfc/rfc8707.html>
- Vault Identity defines entities and aliases as the provider-side identity
  model; authentication mounts and aliases are part of interpreting an entity:
  <https://developer.hashicorp.com/vault/docs/concepts/identity>
- Vault's Identity mapping identifies AppRole aliases by RoleID and JWT/OIDC
  aliases by an operator-selected claim, supporting the distinction between a
  shared role and a uniquely bound workload:
  <https://developer.hashicorp.com/vault/docs/concepts/identity#mount-bound-aliases>
- Vault's health response exposes `cluster_id`; the exact stable trust-domain
  binding and replication behavior remain a Phase 1 design choice:
  <https://developer.hashicorp.com/vault/api-docs/system/health>
- Vault recommends batch tokens for many AppRole deployments, while documenting
  that the AppRole may cover a machine, user, or service. The
  lifecycle-contained profile's service-token requirement is therefore an
  explicit SecretSpec tradeoff:
  <https://developer.hashicorp.com/vault/docs/auth/approle>
- Vault's AppRole guidance recommends response wrapping for SecretID delivery;
  that bootstrap use is distinct from wrapping a dynamic-secret response:
  <https://developer.hashicorp.com/vault/docs/auth/approle/approle-pattern>
- Vault token concepts distinguish service, batch, and root tokens, including
  batch-token revocation and lease-tracking limitations:
  <https://developer.hashicorp.com/vault/docs/concepts/tokens>
- Vault's token API exposes self lookup, token metadata, use counts, and token
  revocation operations used by the authentication-session contract:
  <https://developer.hashicorp.com/vault/api-docs/auth/token>
- Vault leases distinguish backend-reported TTL, renewal, and revocation:
  <https://developer.hashicorp.com/vault/docs/concepts/lease>
- Vault's database generate-credentials endpoint takes a role but no requested
  TTL, and database roles define TTL and supported credential types:
  <https://developer.hashicorp.com/vault/api-docs/secret/databases>
- OpenBao's corresponding database endpoints use the same role-controlled
  issuance and lease lifecycle:
  <https://openbao.org/api-docs/secret/databases/>
- Vault response wrapping protects response transport but does not undo the
  secret-engine mutation that produced the wrapped response:
  <https://developer.hashicorp.com/vault/docs/concepts/response-wrapping>
- Vault Agent and Vault Proxy can cache dynamic-secret responses and manage
  leases, making them another lifecycle owner unless those behaviors are
  disabled:
  <https://developer.hashicorp.com/vault/docs/agent-and-proxy/proxy/caching>
- Vault Proxy's upstream retry default is twelve attempts unless explicitly
  disabled with `num_retries = -1`, and its API proxy can attach an auto-auth
  token:
  <https://developer.hashicorp.com/vault/docs/agent-and-proxy/proxy>
- Vault Agent's API proxy can forcibly replace a caller's token with its
  auto-auth token, so endpoint topology is part of authentication ownership:
  <https://developer.hashicorp.com/vault/docs/agent-and-proxy/agent/apiproxy>
- Vault audit records expose request IDs and the audit schema carries configured
  request headers:
  <https://developer.hashicorp.com/vault/docs/audit/schema>
- Vault records `Correlation-Id` and `X-Correlation-Id` request headers by
  default when audit devices are enabled; arbitrary additional headers require
  audit configuration:
  <https://developer.hashicorp.com/vault/docs/audit>
- Vault's audit-hash endpoint supports value-safe joins against HMAC-protected
  audit fields when a backend audit record must be correlated:
  <https://developer.hashicorp.com/vault/api-docs/system/audit-hash>
- Vault documents irrevocable leases and forced lease-record removal as
  operational repair, not confirmation that the external credential was
  invalidated:
  <https://developer.hashicorp.com/vault/tutorials/monitoring/troubleshoot-irrevocable-leases>
- Vault's token-tree revocation implementation invalidates the token first and
  schedules descendant lease revocation asynchronously, which motivates the
  separate authority and descendant-cleanup outcomes:
  <https://github.com/hashicorp/vault/blob/1661e8c80e741bf4ceac56c129cf6483cf44ba1f/vault/expiration.go#L1188-L1210>
- HashiCorp's AI-agent identity pattern likewise separates agent authentication,
  policy-bound identity, and short-lived downstream credentials:
  <https://developer.hashicorp.com/validated-patterns/vault/ai-agent-identity-with-hashicorp-vault>
- Vault Agent distinguishes renewing a lease from fetching replacement values:
  <https://developer.hashicorp.com/vault/docs/agent-and-proxy/agent/template>
- AWS temporary credentials expire; disabling them requires IAM or resource
  policy changes rather than a lease-style close:
  <https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp_control-access_disable-perms.html>
- AWS supports `credential_process` as a native replacement-delivery boundary:
  <https://docs.aws.amazon.com/sdkref/latest/guide/feature-process-credentials.html>
- Rust does not specify whether `Instant` includes system suspension:
  <https://doc.rust-lang.org/std/time/struct.Instant.html>
- Linux distinguishes monotonic time from suspend-aware boot time:
  <https://www.man7.org/linux/man-pages/man2/clock_gettime.2.html>
- POSIX process groups are cooperative rather than complete containment:
  <https://man7.org/linux/man-pages/man2/setsid.2.html>
- Windows Job Objects provide process grouping and lifetime controls:
  <https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects>
