# NixOS integration plan

> **Status:** design proposal for SecretSpec 0.17. The integration described
> here is not available in the current SecretSpec 0.16 release. The target
> version must be reconfirmed before implementation, and every user-facing
> reference must retain a `0.17+` compatibility label until 0.17 is released.

## Outcome

SecretSpec should integrate with NixOS as a resolver and reconciliation layer,
not as another encrypted-file format and not primarily as a service wrapper.

The primary SecretSpec 0.17+ workflow should:

1. resolve an explicit allowlist of logical secrets from their authoritative
   SecretSpec providers;
2. reconcile those values into declared deployment destinations;
3. commit each declared reconciliation set atomically where the destination
   supports it;
4. restart or reload only consumers whose delivered values changed.

For NixOS, the first destination should be a persistent, host-bound systemd
encrypted-credential generation. Services consume it through ordinary
`LoadCredentialEncrypted=` entries. SecretSpec 0.17 targets resolution on the
NixOS host. SecretSpec 0.18+ adds controller-side resolution, using the same
value-free deployment plan and target-side installer.

An atomic `/run/secretspec` file destination should be provided for programs
that cannot consume systemd credentials. These compatibility destinations and
live credential sockets are follow-up SecretSpec 0.18+ work, unavailable in
SecretSpec 0.16 and outside the initial 0.17 scope.

This gives SecretSpec a different role from agenix and sops-nix:

| Project | Source and distribution model | Runtime delivery |
| --- | --- | --- |
| agenix | Age-encrypted files travel in the Nix closure and are decrypted with a host identity. | Files under `/run/agenix`. |
| sops-nix | SOPS-encrypted files travel in the Nix closure and are decrypted with an age, SSH, GPG, or KMS identity. | Atomic file generations, rendered templates, and service restart/reload coordination. |
| SecretSpec 0.17+ | Selected values are resolved from any SecretSpec provider on the target and reconciled into deployment destinations. Controller-side resolution follows in 0.18+. | Prefer persistent systemd encrypted credentials; managed runtime files and live sockets follow in 0.18+. |

SecretSpec should not reimplement age or SOPS. Users who want encrypted files in
Git and offline target-side decryption should continue to use agenix or
sops-nix.

## Terminology

- **Logical secret:** a named output declared in `secretspec.toml`.
- **Source:** the authoritative provider chain, composition, default, or
  generator from which a logical secret resolves.
- **Binding:** a deployment declaration connecting one logical secret to one
  destination item and its consumers.
- **Reconciliation set:** the bindings that resolve, stage, commit, and fail as
  one transaction. Sets form failure boundaries; unrelated services should not
  share one accidentally.
- **Destination:** a stateful delivery backend that can inspect, stage, commit,
  and optionally remove replicas. A destination is not automatically an
  authoritative SecretSpec provider.
- **Reconciliation:** a one-way operation that makes declared destination
  replicas match their authoritative sources.
- **Generation:** a complete staged set of destination items switched live as a
  unit.
- **Target pull:** source resolution runs on the NixOS host.
- **Controller push (0.18+):** source resolution runs on an operator or CI
  controller; selected values are streamed to a target-side installer.

## Design principles

### Keep resolution, replication, and delivery separate

Providers answer “where does this value come from?” Reconciliation answers “what
replicas should exist?” NixOS delivery answers “how does this service consume
this replica?”

The existing `Provider::get()`/`set()` abstraction is sufficient for simple
secret stores, but it is not the whole destination interface. A safe NixOS
destination also needs staging, multi-item commit, rollback, deletion policy,
change reporting, and consumer coordination.

### Resolve an explicit allowlist

Every binding must name the logical secret it consumes. Enabling the NixOS
module must not resolve the entire active profile. This avoids unrelated
provider access, unnecessary audit events, and the “flood the zone” problem
described in issue #65.

Composed dependencies are resolved transitively, but only selected outputs are
sent to a destination.

### Reconcile in one direction

The source is authoritative and destinations are replicas. SecretSpec 0.17+
must not implement bidirectional synchronization, timestamp-based conflict
resolution, or implicit write-through caching.

The existing commands retain distinct meanings:

| Operation | Contract |
| --- | --- |
| `export` | Resolve values and write them to stdout. |
| `import` | One-time adoption; copy a missing value into a configured provider without overwriting an existing one. |
| `reconcile` (0.17+) | Compare declared source outputs with declared destination replicas and converge them according to explicit policy. |
| Mirror or dual-write mode | A separate, unscheduled feature outside this NixOS integration plan. |

### Keep plaintext out of the Nix store and persistent files

Nix evaluation and builds may operate only on:

- `secretspec.toml` and non-secret provider addresses;
- selected logical secret names;
- destination identifiers and non-secret addresses;
- service names, credential identifiers, paths, permissions, and policy;
- value-free generation metadata.

They must never contact providers or embed resolved values. Configuration
defaults and provider URIs containing credentials remain unsafe because the
manifest itself may enter the world-readable Nix store.

Target-side staging must keep plaintext in memory or pipes. Only encrypted
systemd credential blobs may be persisted for the encrypted-credential
destination. The managed runtime-file destination writes plaintext only below a
RAM-backed `/run` hierarchy.

### Make the trust boundary explicit

Target-pull and controller-push are different security models. The module must
not silently choose between them.

- **Target pull:** the host receives a provider identity and resolves secrets
  during reconciliation. This works well with narrowly scoped workload or
  machine identities, but a compromised host may use that identity for
  additional provider reads.
- **Controller push (0.18+):** an operator or CI resolver holds the provider
  identity and sends only selected values to the host. This reduces the
  target's provider-side blast radius and supports self-hosted providers that
  cannot bootstrap themselves, but rotation requires another reconciliation.

Protecting a provider token with `LoadCredentialEncrypted=` protects it at rest;
it does not reduce the permissions granted by the remote provider.

## Architecture

The NixOS module evaluates to a value-free deployment plan:

```text
logical secret + source profile
    -> reconciliation set
    -> destination item and credential identifier
    -> consuming units
    -> failure, freshness, deletion, and restart policy
```

The same plan is executable in two locations:

```text
target pull
    SecretSpec provider -> resolver on target -> local destination installer

controller push (0.18+)
    SecretSpec provider -> resolver on controller
        -> authenticated SSH stream -> same destination installer on target
```

The target installer owns destination inspection, plaintext comparison,
host-bound encryption, staging, commit, rollback, and local service
coordination. The controller never attempts to create host-bound ciphertext
itself.

### Destination capabilities

The initial internal destination contract should cover:

1. `inspect` — validate the destination and describe existing items without
   returning values to the deployment controller;
2. `prepare` — create an owner-only staging generation;
3. `put` — accept one selected value and stage its destination representation;
4. `remove` — stage an authorized removal;
5. `commit` — atomically make the complete generation live;
6. `abort` — discard staging and retain the current generation;
7. `changed` — return only value-free change information for consumer
   coordination.

Destinations that cannot provide atomic multi-item commit must declare that
capability. The first NixOS release should not weaken atomicity merely to make
arbitrary `Provider::set()` implementations look like transactional
destinations.

Atomicity is per reconciliation set, not global across a host. A set should
contain values that a consumer needs consistently, such as cloudflared's
certificate and tunnel credential. Unrelated consumers use separate sets so
one provider failure does not block them. The module may default a binding's set
from its sole consumer unit, but multi-unit and shared-secret cases must be
explicit.

## Phase 1: selective canonical resolution (SecretSpec 0.17+)

Extend the library resolver and `secretspec export` with a reusable selective
operation.

The proposed SecretSpec 0.17+ CLI is:

```console
# Proposed 0.17+ syntax; unavailable in SecretSpec 0.16.
# Exact UTF-8 bytes for one selected SecretSpec string; no trailing newline.
secretspec export --key CLOUDFLARE_CREDJSON --format raw

# Proposed 0.17+ syntax; unavailable in SecretSpec 0.16.
# A selected subset in a structured format.
secretspec export --key DB_URL --key REDIS_URL --format json

# Existing SecretSpec 0.16 behavior remains the whole active profile.
secretspec export --format shell
```

Required behavior:

- `--key` is repeatable for every non-raw format.
- `--format raw` requires exactly one key.
- Raw output uses an exact byte write and adds no newline.
- SecretSpec's current value model is a UTF-8 string. Systemd can carry
  arbitrary binary credentials, but SecretSpec 0.17+ does not claim arbitrary
  binary input until its provider and value interfaces support it.
- A selected operation plans only requested outputs and their transitive
  composed dependencies.
- Only requested outputs leave the resolver; dependency values remain internal.
- Composition operates on canonical values, before any `as_path` delivery
  transformation.
- Raw export returns the canonical value even when the selected secret declares
  `as_path = true`.
- An explicitly selected but unresolved optional secret fails in `export`. An
  empty string is a valid value and cannot also represent absence.
- The reconciliation engine may instead apply an explicit destination policy
  to a missing optional output; it must not inherit that behavior accidentally
  from `export`.
- Export never prompts.
- A manifest generator remains a source-side operation: if selected resolution
  invokes it, generation and any configured source-provider write must finish
  before destination staging begins and must be audited separately.
- Secret bytes go only to stdout; diagnostics go only to stderr.
- Audit events record the selected output, its dependency closure, all
  credential-free provider provenance, profile, outcome, and supplied reason.

The library API should return canonical selected values plus value-free
resolution metadata. It must not expose dependency values or materialize
`as_path` files unless the caller explicitly requests that delivery
transformation.

## Phase 2: reconciliation engine (SecretSpec 0.17+)

Add a one-shot reconciliation engine. Scheduling belongs to NixOS/systemd
rather than to a permanent SecretSpec daemon in the first implementation.

Illustrative SecretSpec 0.17+ commands:

```console
# Proposed 0.17+ syntax; unavailable in SecretSpec 0.16.
secretspec reconcile --deployment /nix/store/...-secretspec-deployment.json

# Proposed 0.17+ syntax; value-free preview.
secretspec reconcile --deployment /nix/store/...-secretspec-deployment.json \
  --check
```

The final command and deployment-schema names remain provisional.

### Reconciliation transaction

For one reconciliation set and destination generation, the engine must:

1. Parse and validate the value-free deployment plan.
2. Resolve profile, reason policy, sources, and destination before reading any
   value.
3. Preflight every requested source and destination capability.
4. Resolve all selected required outputs and the dependency closure.
5. Apply explicit missing-optional and removal policy.
6. Inspect current destination items locally.
7. Compare current and desired plaintext in memory without logging either.
8. Construct a complete staged generation: carry unchanged retained items
   forward, replace changed items, add new items, and omit only authorized
   removals.
9. Abort the entire generation on any resolution, comparison, encryption, or
   installation failure.
10. Atomically switch the complete staged generation.
11. Record value-free per-item and transaction audit events.
12. Restart or reload only consumers associated with changed items.

No consumer coordination occurs before a successful commit.

### Idempotency

Reconciliation means “ensure desired state,” not “rewrite every item.”
`systemd-creds encrypt` uses authenticated encryption and may produce different
ciphertext for unchanged plaintext. Ciphertext equality therefore cannot drive
change detection.

For the encrypted-credential destination, comparison happens on the target:
decrypt the current item into protected memory, compare it with the incoming
canonical value, and erase intermediate buffers as far as the platform permits.
Do not persist an unkeyed value hash; low-entropy secrets could be guessed
offline from it. Generation metadata may contain item names, timestamps, source
identifiers, and plan digests, but no plaintext or reusable value digest.

A change to the credential identifier, encryption policy, destination address,
or rendered representation requires a new destination item even when the
canonical plaintext is unchanged.

Freshness is the age of the last successful source verification, not the age of
the ciphertext. An unchanged reconciliation atomically advances separate
value-free verification metadata without re-encrypting the credential or
restarting consumers.

### Default policy

Defaults should preserve data and avoid surprising service changes:

| Condition | Default SecretSpec 0.17+ behavior |
| --- | --- |
| Destination already matches | Do not rewrite or restart. |
| Any staging or commit failure | Commit nothing; retain the previous complete generation. |
| Provider error with an existing acceptable generation | Retain it and report degraded reconciliation. |
| Provider error with no existing generation | Fail dependent consumers. |
| Healthy source reports a required value missing | Fail reconciliation; do not silently treat the old value as current. |
| Optional source value is missing | Keep the destination item unless `onMissingOptional = "delete"` is explicit. |
| Binding is removed from configuration | Keep the destination item unless pruning is explicit. |
| Reconciliation contains no changes | Do not restart or reload consumers. |

The deployment plan must expose:

- `onSourceFailure = "fail" | "keep"`;
- `maxStaleness = null | <duration>`;
- `onMissingOptional = "keep" | "delete" | "fail"`;
- `pruneRemoved = false | true`;
- `stopUnitsOnStale = false | true`;
- per-binding `restartUnits` and `reloadUnits`.

An existing generation retained after provider failure is stale, not
successfully refreshed. Status and audit output must say so. If its age exceeds
`maxStaleness`, it is not acceptable for satisfying a dependent service start.
An already-running consumer keeps its mounted credential when freshness later
expires. SecretSpec reports that condition but stops the unit only when
`stopUnitsOnStale = true` is explicit.

### Audit concurrency

NixOS may start or reconcile several destinations concurrently. SecretSpec's
current size-bounded JSONL audit file assumes a single writer. Before the NixOS
integration ships, auditing must gain cross-process synchronization or a
multi-writer-safe sink. Audit requirements are not satisfied by accepting
interleaved or lost helper events.

## Phase 3: systemd encrypted-credential destination (SecretSpec 0.17+)

The first destination should install persistent encrypted credentials on the
target and let PID 1 perform final decryption for each consumer.

### Generation layout

An illustrative layout is:

```text
/etc/secretspec/credentials/
    sets/
        cloudflared/
            generations/
                <generation-id>/
                    cert.pem.cred
                    credentials.json.cred
                    metadata.json
            current -> generations/<generation-id>
            status.json
        my-service/
            generations/
                <generation-id>/
                    database-password.cred
                    metadata.json
            current -> generations/<generation-id>
            status.json
```

The target installer must:

- create staging and generation directories as root with mode `0700`;
- write only encrypted credential blobs and value-free metadata to persistent
  storage;
- encrypt each item on the target with the exact systemd credential identifier
  supplied as `systemd-creds --name`;
- use host-bound TPM2 and/or host-secret protection according to explicit
  destination policy;
- switch each reconciliation set's `current` with an atomic rename;
- update value-free last-verification status atomically without changing
  ciphertext;
- retain previous generations according to policy so an operator can roll back;
- prune older ciphertext generations according to explicit retention policy;
- defend against symlink traversal and unsafe destination names.

A successful credential-generation commit is not automatically rolled back
because a consumer later fails to restart: that failure may be unrelated to the
credential. The service-coordination result must be reported separately, and an
operator may explicitly reactivate a retained generation.

Generated services consume absolute paths such as:

```ini
LoadCredentialEncrypted=database-password:/etc/secretspec/credentials/sets/my-service/current/database-password.cred
```

Systemd imposes an accumulated credential-size limit per unit. The module must
document the supported systemd limit, validate credential identifiers, detect
duplicate identifiers within a unit, and test failures at the limit.

### Illustrative NixOS module

```nix
# Proposed SecretSpec 0.17+ syntax; unavailable in SecretSpec 0.16.
services.secretspec = {
  enable = true;
  mode = "target-pull"; # Never selected implicitly.

  source = {
    file = ./secretspec.toml;
    profile = "production";
  };

  destinations.system-credentials = {
    type = "systemd-credentials";
    path = "/etc/secretspec/credentials";
  };

  reconciliationSets.my-service = {
    destination = "system-credentials";
    onSourceFailure = "keep";
    maxStaleness = "24h";

    bindings.database-password = {
      secret = "DATABASE_PASSWORD";
      credential = "database-password";
      units = [ "my-service.service" ];
      attach = true;
    };
  };
};

systemd.services.my-service.environment.DATABASE_PASSWORD_FILE =
  "%d/database-password";
```

The module should create a one-shot reconciliation unit per reconciliation set,
ordered before that set's dependent consumers. When policy accepts an existing
stale generation after a source outage, the unit may allow those consumers to
start but must report the degraded result. With no acceptable generation, only
that set's dependent consumers fail; unrelated sets, services, and the rest of
boot continue.

Remote-provider network ordering and authentication must be explicit.
Target-pull bindings may request `network-online.target`, but enabling
SecretSpec must not globally block `multi-user.target` on all providers.

### Source-manifest placement

`file = ./secretspec.toml` places the manifest in the Nix store. This is safe
only when the manifest itself contains no values or credential-bearing URIs.
It also does not automatically make relative `extends` targets or relative
provider paths available with the same layout.

The module must choose and document one of:

- require a self-contained manifest with no relative runtime dependencies;
- accept an explicit sanitized source root plus a relative manifest path; or
- build a validated value-free manifest closure.

Target services must not silently depend on root's mutable
`~/.config/secretspec/config.toml`. Profile, aliases, default provider,
provider-credential inputs, reason, and audit destination must be explicit or
deliberately inherited through documented module options.

### Existing NixOS modules

Raw `systemd.services` can consume attached
`LoadCredentialEncrypted=` bindings directly.

The current NixOS cloudflared module turns `certificateFile` and
`credentialsFile` into plaintext `LoadCredential=` entries. It cannot consume
an encrypted blob merely by receiving its path. Until that module exposes an
encrypted-credential option, users need an explicit service override or a
SecretSpec-aware adapter that replaces the relevant `LoadCredential=` entries
with `LoadCredentialEncrypted=`.

The NixOS VM proof of concept must exercise the current released cloudflared
module's working form first, document the override, and treat an upstream
cloudflared option improvement as a separate compatibility task. It must not
claim that an encrypted path is directly interchangeable with the module's
current plaintext path option.

## Phase 4: controller-push reconciliation (SecretSpec 0.18+)

Controller push is targeted for SecretSpec 0.18 and is unavailable in
SecretSpec 0.16 and 0.17. It reuses the Phase 2 plan and Phase 3 target
installer.

Illustrative future command:

```console
# Proposed SecretSpec 0.18+ syntax; unavailable in SecretSpec 0.16 and 0.17.
secretspec nixos reconcile \
  --flake .#rpi5 \
  --target-host root@rpi5
```

The workflow should:

1. Evaluate a value-free deployment plan from the selected NixOS
   configuration.
2. Resolve only named logical secrets on the controller.
3. Authenticate the SSH host and target-side installer.
4. Verify that the target's installed deployment-plan digest matches the plan
   being reconciled, or install and authorize the new plan as part of the same
   deployment transaction.
5. Stream a framed set of selected values over SSH without controller-side
   plaintext files or command-line arguments.
6. Compare existing plaintext only inside the target installer.
7. Invoke host-local systemd credential encryption for changed items.
8. Atomically commit each complete ciphertext reconciliation set.
9. Restart or reload only changed consumers.

Interrupted SSH transfer, authentication failure, target-side encryption
failure, or any malformed frame must abort staging and retain the previous
generation for the affected set. Sets already committed by the same command
remain committed; cross-set host-wide atomicity is not promised, and the final
report must identify every committed, unchanged, failed, and unattempted set.

This formalizes the working script reported in issue #65 and supports:

- machines that must boot without the authoritative provider;
- self-hosted providers that cannot bootstrap themselves;
- targets that should receive values but not a reusable provider identity.

Controller reconciliation is not `secretspec export`: it mutates remote state
and must have a command name, audit action, and confirmation policy that make
those side effects clear.

## Phase 5: managed runtime-file destination (SecretSpec 0.18+)

Some daemons and NixOS modules read a configured path directly and cannot use
systemd credentials. For them, reuse the reconciliation engine with an
explicit RAM-backed file destination. This destination is targeted for
SecretSpec 0.18 and is unavailable in SecretSpec 0.16 and 0.17.

Illustrative syntax:

```nix
# Proposed SecretSpec 0.18+ syntax; unavailable in SecretSpec 0.16 and 0.17.
services.secretspec = {
  destinations.runtime-files = {
    type = "runtime-files";
    path = "/run/secretspec";
  };

  reconciliationSets.application = {
    destination = "runtime-files";

    bindings.application-config = {
      secret = "APPLICATION_CONFIG";
      path = "application/config.json";
      owner = "application";
      group = "application";
      mode = "0400";
      restartUnits = [ "application.service" ];
    };
  };
};
```

The destination must:

1. Restrict managed paths to its owned hierarchy.
2. Resolve every selected required output before changing the live generation.
3. Write a new owner-only generation on tmpfs or ramfs.
4. Apply owner, group, and mode without exposing a permissive intermediate.
5. Compare old and new contents without logging them.
6. Atomically switch one common live-generation symlink.
7. Leave the previous generation active if resolution or installation fails.
8. Apply missing-optional and pruning policy explicitly.
9. Restart or reload only affected units after commit.
10. Prune old in-memory generations according to explicit retention policy.

Rollback under `/run` survives only within the current boot. If the host must
boot offline, it needs the persistent encrypted-credential destination or
another persistent encrypted source.

`as_path` remains a process/SDK delivery transformation and must not be reused
as the managed-file implementation.

## Optional SecretSpec 0.18+ mode: live systemd credential sockets

Live sockets are useful when a service must resolve the latest authoritative
value at every start or, on systemd 260+, every credential refresh. They have a
different availability and failure model from reconciliation and should not be
the default. They are targeted for SecretSpec 0.18 and are unavailable in
SecretSpec 0.16 and 0.17.

Systemd supports `LoadCredential=ID:/absolute/path` where the path is an
AF_UNIX stream socket. PID 1 connects while starting the consumer and copies
the byte stream into the private credential directory.

A safe SecretSpec implementation requires more than directing
`secretspec export` to an activated socket:

- PID 1 observes the byte stream, not the helper's exit code.
- A helper that fails and closes normally without writing may be
  indistinguishable from a successful empty credential.
- Empty strings are valid SecretSpec values.

Therefore a dedicated helper must resolve fully before writing and must cause a
connection error, rather than clean zero-byte EOF, on every failure. The design
must prove this behavior against supported kernels and systemd versions before
shipping. If it cannot do so reliably, live sockets must not be offered.

Each binding needs its own root-owned socket path with `SocketMode=0600`,
`DirectoryMode=0700`, `Accept=yes`, explicit `Requires=`/`After=` dependencies,
bounded activation time, and a short path safe for AF_UNIX limits. The helper
should run with the least privilege its provider permits rather than as root by
default.

A minimal read-only provider for `$CREDENTIALS_DIRECTORY` must ship with this
mode if remote-provider tokens are supplied through
`LoadCredentialEncrypted=`. Passing decrypted tokens through environment
variables is not an acceptable bootstrap mechanism.

For systemd 260+, `RefreshOnReload=credentials` may reacquire socket-backed
credentials. It is useful only when the daemon rereads the credential file;
otherwise the module must restart it. The module must version-gate the option.

## Systemd credentials as SecretSpec sources

A minimal read-only service-credential source is required for SecretSpec 0.17
target pull and is unavailable in SecretSpec 0.16. It reads only the
reconciliation unit's `$CREDENTIALS_DIRECTORY`, allowing PID 1 to decrypt a
provider token with `LoadCredentialEncrypted=` without placing that token in an
environment variable.

Illustrative SecretSpec 0.17+ configuration:

```toml
# Proposed SecretSpec 0.17+ provider; unavailable in SecretSpec 0.16.
[providers]
bootstrap = "systemd-credential://"

vault_prod = {
  uri = "vault://secret/myapp"
  credentials = {
    token = {
      provider = "bootstrap"
      ref = { item = "vault-token" }
    }
  }
}
```

The URI is provisional. The NixOS module must attach `vault-token` to the
reconciliation unit and must not copy its contents into an `Environment=`
setting.

The following roles must not be conflated:

- **Destination:** reconcile canonical values into host-bound encrypted blobs
  for consumers. This is the initial NixOS feature.
- **Service-credential source (0.17+):** read a credential already exposed
  through `$CREDENTIALS_DIRECTORY`, primarily to bootstrap another provider.
  This is the narrow, read-only provider required by target pull.
- **Persistent encrypted-store source (0.18+):** decrypt an item outside its
  consumer service. This is unavailable in SecretSpec 0.16 and 0.17, grants
  broader machine-level capability, and needs a separate security review.

The destination does not need to become a general SecretSpec provider. An
offline consumer can use its encrypted blob directly through systemd without
routing the value back through SecretSpec.

Any future systemd-credential provider must reject traversal, validate
credential identifiers, preserve only the exact bytes supported by
SecretSpec's value model, distinguish service credentials from persistent
stores, and make read/write/decrypt privileges explicit.

## Rotation and failure behavior

### Persistent encrypted credentials

- A reconciliation updates changed values and leaves unchanged ciphertext
  untouched.
- Provider failure never creates an empty or partial new generation.
- An acceptable previous generation may remain usable according to explicit
  source-failure and staleness policy.
- Rotation occurs on activation, a timer, an operator command, or a controller
  run; the trigger must be visible in configuration.
- Consumers restart or reload only after a successful changed commit.

### Managed runtime files

- Required-resolution failure keeps the previous complete in-memory generation
  live during the current boot.
- Missing optional values and removed bindings follow explicit deletion policy.
- Change detection requests only configured restarts or reloads.
- Reboot removes the previous generation.

### Live sockets

- Each service start resolves the latest value.
- A verified transport-level helper failure prevents only that consumer from
  starting.
- There is no offline fallback unless a separate destination/cache policy is
  explicitly designed.
- A later restart retries resolution.

## Security requirements

- Never resolve secrets during Nix evaluation or a Nix build.
- Never place plaintext in a derivation, store path, unit file, command line,
  environment variable, journal message, or value-free deployment manifest.
- Use exact UTF-8 byte streams for SecretSpec's current string value model; do
  not append newlines or apply shell quoting.
- Keep persistent plaintext out of controller and target files.
- Authenticate SSH hosts and target installers in controller-push mode.
- Make target-pull provider identities explicit and least-privileged.
- Give resolver and installer processes only the network, executable,
  filesystem, decryption, and provider capabilities they require.
- Do not wrap consumers with `secretspec run`; it injects a process environment
  and currently supervises a spawned child rather than replacing it.
- Record value-free audit events for every source resolution, destination
  comparison, staging result, commit, rollback, removal, provisioning action,
  and stale-generation decision.
- Treat provider credentials as a separate, potentially broader capability
  than destination replicas.
- Test that failures, previews, dry activation, Nix evaluation, and systemd
  status output never reveal values.
- Zeroize or minimize plaintext buffers where practical, without claiming
  guarantees Rust strings and third-party provider SDKs cannot provide.

## Module distribution

The canonical module should initially live and be tested in the SecretSpec
repository, exported as `nixosModules.default` from an upstream flake. The
module, deployment schema, resolver, and target installer can then evolve in
lockstep.

The module must expose an explicit `package` option and assert that the selected
SecretSpec package implements the required deployment-schema version. Shipping
the module and package from one flake does not guarantee compatibility after a
user overrides the package.

A nixpkgs module should follow only after selective resolution, deployment
schema, destination transaction, and service-coordination interfaces are
stable.

Home Manager, nix-darwin, early-user password secrets, initrd delivery,
templates, bidirectional synchronization, a permanent broker, and generic
multi-provider transactional replication are out of the initial scope.

## Validation plan

### Selective resolution

- raw output with no trailing newline;
- empty-string success distinct from missing output;
- selected optional output missing;
- composed output with only its dependency closure accessed;
- dependencies excluded from returned output;
- `as_path` output and dependency handling use canonical values;
- source generation and writes finish before destination staging;
- complete provider provenance and value-free auditing.

### Reconciliation engine

- unchanged, changed, added, missing, and explicitly removed items;
- atomic grouping and failure isolation between reconciliation sets;
- no destination writes or consumer restarts for an unchanged value;
- unchanged source verification advances freshness without rewriting
  ciphertext;
- rollback on failure at every staging and commit boundary;
- optional deletion and explicit pruning;
- first provisioning versus an existing generation;
- provider error, healthy required-missing result, and max-staleness expiry;
- concurrent reconciliation with lossless audit records;
- no persistent plaintext or unkeyed reusable value digest.

### NixOS systemd destination

- host-bound encryption with TPM2 and TPM-less host-secret modes;
- exact credential names and path validation;
- atomic multi-item generation switch;
- interrupted encryption and disk-full rollback;
- ordinary and `DynamicUser=` consumers;
- remote-provider credentials supplied to the reconciliation unit with
  `LoadCredentialEncrypted=` and read through the 0.17+ service-credential
  source;
- boot, `nixos-rebuild switch`, timer refresh, manual refresh, restart, and
  reload behavior;
- max-staleness behavior for stopped and already-running consumers;
- provider failure affects only dependent consumers;
- accumulated systemd credential-size failure;
- current cloudflared module integration using its released working form and
  documented override;
- no plaintext in the Nix store, generated units, process arguments, audit
  records, or logs.

### Controller push

- deployment-plan digest mismatch;
- SSH host and installer authentication failure;
- interrupted and malformed framed transfer;
- target-side encryption failure;
- first provisioning, rotation, deletion, and no-op runs;
- offline boot from the last committed generation;
- no controller-side plaintext files.

### Optional live sockets

- successful non-empty and empty credentials;
- provider error and missing optional output both fail consumer acquisition;
- root-only socket and directory permissions;
- activation timeout and helper crash;
- repeated and concurrent connections;
- provider credentials supplied with `LoadCredentialEncrypted=`;
- systemd 260+ refresh behavior when available.

## Delivery milestones

1. **Selective canonical resolution:** implement selected output planning,
   canonical values, dependency closure, raw export, provenance, audit, and
   tests.
2. **Reconciliation core:** add the value-free deployment schema, policy
   engine, destination capability interface, transaction report, preview, and
   multi-process-safe auditing.
3. **Service-credential bootstrap source:** read provider credentials supplied
   to a reconciliation unit through `LoadCredentialEncrypted=` without
   environment-variable injection.
4. **Encrypted-destination proof of concept:** compare, encrypt, stage, and
   atomically commit a local systemd credential generation without plaintext
   files.
5. **Upstream NixOS target-pull module:** add bindings, ordering, package/schema
   assertions, scheduling, documentation, and VM tests.
6. **Controller push (0.18+):** evaluate the same deployment plan, stream selected
   values to the target installer, and coordinate changed consumers.
7. **Runtime-file destination (0.18+):** add atomic `/run` generations, permissions,
   deletion policy, and service coordination.
8. **Optional live sockets (0.18+):** proceed only after the empty-value versus
   failure proof and bootstrap design pass security review.
9. **Nixpkgs proposal:** submit the stabilized module and compatible SecretSpec
   package together.

Each milestone that ships in 0.17 must be documented as `(0.17+)` everywhere it
appears until the release is published. Features deferred past 0.17 must use
their actual later target version rather than inheriting the 0.17 label.

## References

- SecretSpec issue #65, NixOS integration:
  <https://github.com/cachix/secretspec/issues/65>
- SecretSpec issue #41, systemd credentials:
  <https://github.com/cachix/secretspec/issues/41>
- Systemd credentials:
  <https://systemd.io/CREDENTIALS/>
- Systemd `LoadCredential=` socket semantics:
  <https://github.com/systemd/systemd/blob/main/man/systemd.exec.xml>
- Systemd socket activation:
  <https://github.com/systemd/systemd/blob/main/man/systemd.socket.xml>
- Current NixOS cloudflared module:
  <https://github.com/NixOS/nixpkgs/blob/master/nixos/modules/services/networking/cloudflared.nix>
- Agenix module:
  <https://github.com/ryantm/agenix/blob/main/modules/age.nix>
- Sops-nix module and installer:
  <https://github.com/Mic92/sops-nix/tree/master/modules/sops>
