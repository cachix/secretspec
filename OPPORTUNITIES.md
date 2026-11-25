# SecretSpec: Opportunity Landscape

This document captures opportunities unlocked by SecretSpec's architecture. It was produced by reading the codebase (manifest/config types, the `Secrets` resolver, the provider trait + URI registry, the `secretspec-derive` compile-time macro, the generator, and the CLI), then running a multi-lens ideation pass (241 raw ideas + 18 gap-fillers, 259 total) deduped and clustered into what follows.

## The core leverage (why these are possible)

SecretSpec splits secret **declaration** (a committed, value-free, machine-readable `secretspec.toml`) from **storage** (pluggable providers). That gives it three chokepoints no competing tool holds all of at once:

1. **The compile-time macro** knows the full secret contract at *build time*.
2. **The `run`/`get`/`get_batch` path** knows the exact resolved values at exactly one moment.
3. **The uniform provider trait + URI registry** speaks every backend through one interface.

Almost everything below falls on one of two axes: **(A) turn the value-free contract into superpowers** (diff, lint, policy, inventory, attestation, docs, SBOM, IDE intelligence) or **(B) exploit the storage abstraction** (provider middleware, keyless CI, migration, lifecycle/rotation, agent sandboxing).

Effort/impact tags use `[effort, impact]` where effort is S/M/L/XL and impact is low/medium/high/transformative.

---

## 1. Onboarding, DX and live editor intelligence

- **`secretspec doctor`**: force every provider preflight, classify each failure (unreachable vs unauthenticated vs missing vs read only), print a per-secret fix. `[M, high]`
- **`check --explain` / `--json`**: expose the resolution waterfall `validate()` already computes (which chain link hit, profile inheritance, default, generation) as a trace and a machine-readable status feed, never values. `[S, high]`
- **Editor LSP for `secretspec.toml`**: completion from the live provider registry + type enum, hover docs, inline validation using the real `Secret::validate` messages, live found/missing squiggles, code actions to set or generate. `[L, high]`
- **Richer derive compile errors**: a missing/typo'd secret becomes a Rust compile error carrying the description and a copy-pasteable `secretspec set` command. `[M, high]`
- **`secretspec list` + contextual `--help`**: `run --help` inside a project appends the actual declared secrets for the active profile (metadata only). `[S, medium]`
- **Auto-generated `ONBOARDING.md` / runbook**: render the manifest into a never-stale per-profile table (every secret, description, where to get it, the exact fix command); injectable between README markers in CI. `[S, medium]`
- **`init --from-code`**: bootstrap a manifest by statically scanning source for env reads (`process.env.X`, `os.environ`, `std::env::var`), complementing today's dotenv-only reflection. `[L, high]`
- **Shell hook + direnv integration**: on `cd`, validate the dev profile and export resolved secrets into the shell (unset on leave). A vault-backed, never-to-disk replacement for direnv's plaintext dotenv. `[M, high]`
- **Devcontainer/Codespaces bootstrap + onboarding wizard**: a first-run flow that auto-generates ephemeral dev secrets, pulls platform env secrets, and prompts only the truly human-supplied ones so a fresh Codespace boots green. `[M, high]`
- **Pre-commit hooks**: fail on invalid manifest or an unresolvable new required secret, and lint for env reads not declared in the manifest (and declared-but-unused). `[M, medium]`
- **Accessible / i18n output**: `NO_COLOR` + `--plain`, status by words not color (WCAG), translatable strings and localizable descriptions. `[S, medium]`

## 2. Manifest-as-contract: diff, lint, policy, inventory

- **Org-wide secret inventory** by crawling git for every `secretspec.toml` into one CMDB-grade view, sliceable by provider/type/required-in-prod, with zero per-app integration. `[L, transformative]`
- **Service catalog + cross-service dependency graph** (extends-aware): which services need which secret, blast radius of rotating a shared key, DOT/Mermaid output, Backstage plugin. `[L, high]`
- **Semantic contract diff + semver breaking-change detector**: classify added/removed secrets, required/optional flips, provider repointing as BREAKING vs additive; PR gate that says "this adds 2 required secrets". `[M, high]`
- **Policy-as-code over the manifest** (OPA/conftest-style): "no prod secret may resolve to dotenv", "`*_KEY` must be required in production", "`rsa_private_key` must use `as_path`". Enforces *how* a secret is sourced. `[M, high]`
- **Diff-aware review bot for PRs**: posts a risk-tagged contract changelog instead of raw TOML, can require security approval when a secret is added or its provider alias changes. `[M, high]`
- **`secretspec drift`**: use `reflect()`/`get_batch` to diff declared vs what the provider actually holds across profiles (declared-but-missing, orphan/shadow secrets, prod-required-but-dev-defaulted). `[M, high]`
- **Unused/orphaned secret detection**: join declared names against source env references and against reflect-capable providers. `[M, high]`
- **SecretBOM export**: CycloneDX-style value-free JSON answering "what secrets does this service use and where are they stored?", ingestible by existing SBOM tooling. `[M, transformative]`
- **JSON Schema for `secretspec.toml` + `secretspec fmt`**: free editor autocomplete/validation everywhere, plus a canonical formatter (Prettier/dprint plugin) so manifest diffs are clean. `[S, high]`
- **Ownership/classification/rotation metadata fields** (`owner`, `classification=pii`, `rotate_after`) + audits that enforce "every PII secret has an owner". `[M, high]`
- **Default-value classifier**: flag committed `default = "..."` values that look like real credentials (JWT/PEM/connection-string shapes), closing the one hole in the no-values-in-git invariant. `[S, medium]`
- **Per-profile constants matrix + parity linter**: an item-by-profile dashboard that flags "required in prod but absent in staging" drift teams build spreadsheets for. `[S, high]`
- **Transitive secret contracts**: let libraries ship their own `secretspec.toml` (Stripe SDK declares `STRIPE_KEY`); `secretspec collect` merges the dependency tree into one effective contract with provenance. `[L, transformative]`

## 3. Security, audit, attestation, compliance

- **Build-bound SecretBOM / provenance attestation** (in-toto/SLSA): the macro bakes the manifest hash into the binary; `verify-deploy` checks the running contract matches what was compiled. `[L, transformative]`
- **Cryptographically signed manifests**: cosign/minisign over the canonicalized manifest + extends closure; `run`/codegen refuse unverified manifests, stopping a malicious `prod_vault` to `dotenv://attacker` repoint. `[M, high]`
- **Compile-time typed taint**: derive wraps secret fields in a `Redacted<String>` newtype whose Debug/Serialize are redacted by default, making leaks a type-level impossibility. `[L, high]`
- **`run --redact`**: scrub the child's stdout/stderr of resolved secret values (precise, value-based, because `run` already holds the exact set). `[M, high]`
- **Tamper-evident hash-chained usage audit log**: `run --audit-log` records manifest hash, profile, injected secret *names*, source provider, identity, exit code. `[M, high]`
- **Compliance evidence pack**: `secretspec evidence --profile production` emits a signed, timestamped, value-free SOC2/ISO control snapshot bound to a git SHA. `[M, high]`
- **Access-attestation matrix + recertification**: join each secret's resolved provider URI with provider ACLs into a "who can read prod secrets?" grid; recurring approve/revoke campaigns. `[XL, transformative]`
- **Honeytoken/canary secrets**: declare per-profile canaries (via `type=command` minting a tracked token) injected like any env var; a trip pinpoints which environment/agent leaked. `[M, high]`
- **`scan-rules`**: generate tuned gitleaks/trufflehog/GitHub detector configs *from* the manifest (PEM headers, hex length, uuid regex) and allowlist safe defaults, near-zero false positives. `[M, high]`
- **Incident-response playbook compiler**: `secretspec incident <SECRET>` computes every profile/provider/service holding it, the rotation command, the revoke hook, a downtime-minimizing checklist. `[M, high]`
- **Data-residency/sovereignty enforcement**: a `residency=eu` field + a gate asserting the resolved endpoint's region is permitted (GDPR/Schrems II evidence). `[M, high]`
- **`as_path` materialization audit + zeroization hardening**: log temp-file lifecycle, optionally force tmpfs/memfd, scrub the intermediate plain-String map `run_command` builds. `[M, medium]`
- **Cross-provider consistency / quorum audit**: find the same logical secret diverging across chain backends (stale prod value in keyring), or require N-of-M agreement for break-glass roots. `[M, medium]`

## 4. CI/CD, deployment and runtime injection

- **`oidc://` keyless provider**: exchange the ambient CI OIDC token for short-lived cloud/Vault creds at run time, so the same manifest uses keyring locally and zero-static-credential auth in CI. `[L, transformative]`
- **Manifest-driven GitHub Action / GitLab template**: discovers secret names from the committed manifest (no parallel `secrets.*` YAML to drift), masks logs, runs under `run --`. `[M, high]`
- **Pre-deploy contract gate**: `check --no-prompt --profile production` as a required CI status that turns a 2am missing-env page into a red check. `[S, high]`
- **Kubernetes injection**: compile the manifest into an init-container running `run --` (secrets only in process env, never etcd) or a generated External Secrets `ExternalSecret`; `as_path` secrets become mounted files; profiles map to namespaces. `[L, high]`
- **Lambda/serverless extension + `secretspec serve` daemon**: cold-start `get_batch` one round trip, fail fast; a UDS daemon holds refreshable secrets so many processes fetch by name without re-authing. `[L, high]`
- **systemd `LoadCredential`/`SetCredentialEncrypted` generator**: kernel-managed credentials instead of world-readable `EnvironmentFile=`; strong NixOS fit. `[M, medium]`
- **Docker/BuildKit secret-mount + `as_path` cred broker**: feed `RUN --mount=type=secret` (no ARG/ENV leaking into layers); materialize file-shaped secrets into pods. `[M, medium]`
- **Bootstrap-on-deploy + per-PR ephemeral envs**: generate-if-absent self-seeds JWT keys and passwords into a fresh env; synthesize a transient profile + scoped provider prefix per PR, teardown on close. `[M, high]`
- **Graceful-degradation chains + `--strict`**: `providers=[cloud_vault, env]` degrades to a CI break-glass on a vault outage without an emergency commit; strict mode hard-fails prod and logs when a fallback fired. `[S, medium]`
- **Pre-merge GitHub App**: value-blind, confirms via `reflect()` that a newly added secret is actually provisioned in the target provider before allowing merge. `[M, high]`

## 5. Lifecycle: generation, rotation, expiry, leasing

- **`type=lease` dynamic secrets**: mint short-lived DB users/STS tokens per run, revoke on exit via `run_command`'s drop-before-exit guarantee. Vault-style dynamic secrets on any backend. `[L, transformative]`
- **`secretspec rotate`**: re-run a secret's own `generate` config to mint a fresh value through the write path; `--overlap`/`--finalize` uses the fallback chain for zero-downtime blue/green rotation. `[S, high]`
- **`rotate --propagate`**: walk the extends graph to write a rotated shared secret into every downstream project; `--dry-run` shows blast radius. Solves "update everything that uses it". `[XL, transformative]`
- **TTL/staleness policy + `check --stale` gate**: `ttl`/`rotate_every`/`last_rotated` fields, age-vs-policy reporting, owner ping, CI fail on expired credentials. `[M, high]`
- **`snapshot`/`rollback` + DR restore**: capture the closed key set into a versioned/age-encrypted bundle, rehydrate into any provider. Versioning + DR on backends that have neither. `[M, high]`
- **Native version pinning + history**: a version selector in the URI (`vault://...#3`) and `secretspec history <SECRET>` via an optional `get_version`/`list_versions` trait method. `[L, high]`
- **`secretspec revoke`**: a per-secret `revoke=command` that kills the key at the issuer (deactivate at Stripe/GitHub) *and* deletes the stored value; pairs with generate for true single-use creds. `[M, high]`
- **Deterministic derived secrets (no storage)**: compute a value from a root-seed reference + namespace salt at run time, so per-PR envs get consistent-yet-isolated creds with nothing persisted and nothing to tear down. `[M, high]`
- **Time-windowed availability**: `available_when` (business-hours, on-call window, date range) so a high-blast-radius prod credential simply does not resolve outside its window. Least-privilege over time. `[M, high]`
- **`secretspec bootstrap`**: fully populate a brand-new vault in one shot (generate, run command, or prompt) reusing `ensure_secrets`; `revision` bumps trigger a re-bootstrap diff. `[M, high]`

## 6. Provider system: composable middleware and new backends

- **Composable provider middleware via URI wrapping**: `cache://`, `audit://`, `encrypt://age@...`, `policy://`, `metrics://`, `readonly://` wrap an inner provider and add behavior. PreflightGuard already proves the decorator pattern. `[M, transformative]`
- **Read-through + stale-while-revalidate cache provider**: cut the 50 to 300ms `run` re-fetch cost; serve last-known-good during an outage with auditable staleness. `[M, high]`
- **Audit/telemetry wrapper providers**: structured value-redacted event per get/set, Prometheus/OTEL metrics labeled by secret name and provider, across all backends. `[M, high]`
- **Multi-write fan-out / mirror provider**: `mirror://primary+secondary` writes to all, reads from first; a reversible dual-write window that turns a risky vault migration into a one-line git diff cutover. `[M, high]`
- **Envelope-encryption-at-rest wrapper + sops-in-git provider**: `encrypt://` so weak backends store only ciphertext (safely commit `.env.enc`); a `sopsdir://` provider with `reflect()` over a git-committed tree. `[M, high]`
- **First-class `mock://` provider**: promote the test-internal `MockProvider` to a shipped, seedable scheme so any app/test exercises the full resolution path with no keyring/network/files. `[S, high]`
- **New backends**: `k8s://`, plus native `doppler://`, `infisical://`, `azurekv://`, `akeyless://`, personal `bitwarden://`, `keepass://`. Each widens the migration matrix. `[L, high]`
- **Capability-negotiating registry**: capability flags (`supports_reflect`, `writable`, `encrypted_at_rest`) surfaced in `config init` and a portability report; the macro errors at compile time if a manifest uses `as_path`/`generate` with an incapable backend. `[M, high]`
- **TPM / Secure Enclave / passkey-sealed local provider**: hardware-sealed unlock (Touch ID, Windows Hello), gained by changing one URI. `[XL, high]`
- **Cross-platform keyring portability shim**: detect when teammates' keyring backends differ (Keychain vs Credential Manager vs Secret Service vs headless WSL) and recommend a portable fallback chain. `[M, medium]`
- **Signed plugin distribution**: out-of-tree providers as separate signed crates/binaries with capability/permission manifests; `provider verify` before a provider is trusted with plaintext. `[XL, high]`

## 7. Multi-language SDKs, codegen and a portable contract

- **`secretspec resolve --json`**: the universal SDK FFI boundary. Run the full resolver and emit `{provider, profile, secrets:{NAME:{value|path, source_provider, generated}}, missing_required}` so any-language SDK is ~100 lines yet inherits all providers, chains, generation, and `as_path`. `[M, transformative]`
- **`secretspec codegen --lang ts|py|go|java`**: refactor the Rust codegen into a shared IR, emit idiomatic typed accessors (TS interface + Zod, Python Pydantic, Go struct, JVM record). Static langs get real compile failures on missing/typo'd secrets. `[L, transformative]`
- **First-party native runtime SDKs** (Node/Python/Ruby) with `as_path` returning a `Path`/`pathlib.Path` cleaned via each language's finalizer, and `set_as_env` mirroring the Rust path. `[L, high]`
- **WASM build of the resolver** for edge/Workers/Deno/in-process Node, plus manifest-driven feature pruning for mobile/embedded. `[XL, high]`
- **Framework adapters**: Next.js/Vite/Django/Rails/Spring/FastAPI; the Next.js plugin can structurally refuse to expose a server-only secret to the client unless marked `client_safe`. `[L, high]`
- **Polyglot conformance suite + test fixtures**: one fixture manifest + golden `resolve --json` asserts every SDK produces identical typed objects, optionality, and missing-required errors. `[M, high]`
- **Build-bound rotation runbook + shell completions codegen**: derive emits typed `rotate_*()` methods, a `SECRETSPEC_CONTRACT` const the binary self-reports, and completion candidates from declared names. `[M, medium]`
- **Formal manifest specification + conformance vectors**: publish `secretspec.toml` as an independently-implementable normative spec so vendors (1Password, Doppler, clouds) can self-certify. What legitimizes it as "package.json for secrets". `[L, transformative]`

## 8. Interop, migration and anti-lock-in

- **Bidirectional `reflect()` for every provider**: the single change that turns `init --from <provider>` and full vault-to-vault migration from dotenv-only into universal. `[L, high]`
- **`import --to` + continuous `mirror` + migration-as-rotation**: any URI to any URI, months-long risk-free cutovers, and generate-then-mirror that rotates secrets into the new backend rather than copying possibly-exposed old values (the secure way to leave a breached vendor). `[M, high]`
- **Format exporters**: `export --format dotenv|k8s|tfvars|compose|json|helm-values`, with `as_path` file references and a `--no-secrets` config-only mode. Be the source of truth feeding tools that only ingest files. `[M, high]`
- **`secretspec diff <A> <B>` / verify-import**: value-blind three-column status (A-only, B-only, differ, identical) using salted hashes; the verification step `import` lacks. `[S, high]`
- **Fallback chain as zero-downtime migration switch + coverage**: `providers=[new_vault, old_vault]` plus a coverage report telling you exactly when the legacy backend can be dropped. `[M, high]`
- **Value-free migration lockfile + round-trip fidelity harness**: a committable `secretspec.migration.lock` reviewed via git diff, plus a `set` to `reflect` to `import` to `get` conformance test ("migration-certified" badge). `[M, high]`
- **Adopt-without-migrating env-shim**: point an alias at wherever secrets already live, then later re-point an entire fleet by changing one alias in a shared `extends` baseline. Removes both the adoption cliff and the migration cliff. `[S, high]`
- **Two-way sync conflict policy engine**: bidirectional sync with declared per-secret conflict policy (source-wins, newest-wins, manual) so two teams keep a shared set consistent without one capitulating. `[XL, high]`

## 9. Ecosystem integrations (Nix/devenv, IaC, task runners, registry)

- **First-class devenv module**: read the manifest to wire required secrets into `config.env`, map `secretspec.profile` to devenv environments, and auto-wrap every `processes.*`/`tasks.*` under `run --`. Highest-affinity integration since Cachix owns devenv. `[M, high]`
- **Nix-native generation + flake checks**: generate-if-absent at `enterShell`/activation (recipe pinned in git), `nix flake check` runs `check --no-prompt`, `mock://`-backed hermetic offline dev shell. `[M, high]`
- **Terraform/OpenTofu/Pulumi**: an external data source where the manifest is the input schema (no plaintext in `.tfvars`), plus `provision --emit terraform` that creates backend entries at the deterministic path scheme. `[L, high]`
- **Ansible lookup plugin + check module**: `lookup('secretspec', 'DATABASE_URL', profile='production')` through the chain; replaces ansible-vault sprawl. `[M, medium]`
- **Task-runner recipe generation + `secretspec render`**: emit just/Task/make stubs wrapped in `run --`, and substitute resolved values into config-file templates (honoring `as_path` for file references) for tools that read config files not env vars. `[M, high]`
- **`secretspec watch`**: re-resolve on provider change and SIGHUP/re-exec the child, rewriting `as_path` temp files in place so nginx/envoy pick up rotated certs without a restart. `[L, medium]`
- **Manifest registry: remote, versioned, signed `extends`**: `extends = ['org-baseline@2.3.0']` resolved from git/registry with a checksummed lockfile, distributable via the Nix store/Cachix. The "npm for secret contracts". `[XL, transformative]`

## 10. Team/org governance and least-privilege

- **Path-to-IAM/RBAC policy generator + auditor**: walk declared secrets, compute their exact provider paths, emit least-privilege Vault HCL / AWS IAM / GCP bindings per profile, then diff against live ACLs for over/under-grants. `[M, high]`
- **Split ownership: mandated baseline + sealed aliases**: a platform-owned baseline every app extends, with a lint that fails CI when an app weakens an inherited `required` flag, and org-governed alias names a project may not redefine (inverting project-wins for locked aliases). `[M, high]`
- **Approval-gated promotion**: `promote --from staging --to production` per declared key, only after a recorded/signed approval, bounded by each profile's key set. `[M, high]`
- **Break-glass / JIT access through the chain**: `providers=[jit_vault, prod_vault]` where jit is a short-TTL approval-gated backend; `break-glass --ttl 30m` provisions, normal runs fall through, access auto-expires with an audit hook. `[L, high]`
- **Tenant fan-out**: template the project name (`SECRETSPEC_PROJECT=acme`) so one manifest resolves N customer namespaces; `tenants check` proves every tenant has the complete identical secret set. `[M, high]`
- **CI runner least-privilege presets + onboarding scorecard**: CI uses `providers=[env]` (read-only, can't write back) while devs use keyring; an org-wide check rollup shows exactly which grants each person/runner still needs. `[S, medium]`

## 11. AI agents, MCP and sandboxing

- **`secretspec-mcp`**: an MCP server exposing `list_secrets` (name + description, value-free), `check_status`, and `run_with_secrets(cmd)` that injects into a child the model never sees. The agent reasons about *what* exists but `expose_secret()` is never wired to a tool. Impossible without a values-free self-describing manifest. `[L, transformative]`
- **Broker mode**: a local UDS daemon where an agent requests a capability by name; the broker performs the privileged action itself and returns only the result, logging every grant. A compromised agent gets an audited "do this" API, not the credential. `[XL, transformative]`
- **`run --scrub-env`**: build the child env from only the resolved secrets plus an explicit allowlist (PATH, HOME) instead of cloning `env::vars()`, so an agent subprocess can't inherit unrelated `AWS_*`/`OPENAI_API_KEY`. The manifest is the allowlist. A concrete shippable PR. `[M, high]`
- **Context redaction filter for LLM transcripts**: replace exact resolved values (and `as_path` file contents) with `[REDACTED:NAME]` in model input/output and tool stdout, precise because the manifest enumerates the complete set. `[M, high]`
- **Per-agent least-privilege scopes via `[profiles.agent_*]`**: each profile lists only the secrets a role may touch; the MCP server/`run` is pinned to one profile so the agent literally cannot resolve outside it. Plus an exfil-risk linter on high-blast-radius agent profiles. `[S, high]`
- **Ephemeral / single-use agent credentials**: `type=command` short-lived leases or generate+revoke single-use-per-tool-call, bundled into devenv-based reproducible agent sandboxes. `[M, high]`

## 12. Adjacent domains and commercial model (for Cachix)

- **SecretSpec Cloud: a managed provider behind a URI** (`secretspec://team.acme.cloud/project`): teams add one alias and everything works unchanged; self-hosted Enterprise is the identical code at a different URI. The paid thing is purely storage while the open contract stays vendor-neutral. The revenue engine. `[XL, transformative]`
- **`sensitive=false`: one manifest for secrets AND plain config**: non-secret config (`LOG_LEVEL`, `S3_BUCKET`, base URLs) flows through the same declaration/provider/profile machinery but may be printed, committed, and typed as plain `String`. Eliminates the second config tool that always drifts. `[M, transformative]`
- **Feature-flag / service-discovery / typed-value providers**: `flag://`, `discover://` (DNS SRV/Consul/k8s with offline fallback), plus extending `type` to value types (`int`/`bool`/`enum`/`url`/`port`) the library validates and the macro emits as native types. `[L, high]`
- **Manifest-as-publishable setup contract**: `schema --json` that PaaS/IDPs (Render, Railway, Fly) consume to auto-generate a perfect "set these variables" form, and that SaaS vendors ship as a canonical fragment `secretspec add-vendor` pulls. `[M, high]`
- **Open-core freemium boundary**: free forever = CLI, derive, all local/self-hosted providers; paid Team = Cloud + access control + audit + drift dashboard; paid Enterprise = managed rotation, compliance export, SSO/SCIM, white-glove migration, plus a FinOps "cloud-secret-manager API cost + orphaned-secret waste" insights add-on (a non-security buyer). `[M, high]`
- **Provider marketplace + drift/coverage audit SaaS + private contract registry**: a paid "Certified Provider" program over the `#[provider]` registry, a hosted drift dashboard, and a private "npm for secret contracts" registry enforcing inherited baselines. `[XL, transformative]`
- **`as_path` reframed as the universal file-shaped config primitive**: lean into `KUBECONFIG`, `GOOGLE_APPLICATION_CREDENTIALS`, `CA_BUNDLE`, `.npmrc` getting an auto-cleaned ephemeral file; plus `explain --with-provenance` reporting each item's origin. `[M, medium]`

---

## If you were prioritizing

**Quick wins** (low effort, high value, mostly surfacing data `validate()` already computes):
`check --explain/--json`, JSON Schema + `fmt`, pre-deploy `check -n` gate, ship `mock://` publicly, adopt-without-migrating env-shim, `diff`/verify-import, `run --dry-run`, provider conformance test-kit, per-profile parity matrix, agent least-privilege profiles, `secretspec rotate`, CI least-privilege presets, default-value classifier, contextual `list`/`--help`.

**Strategic bets** (the highest-leverage commitments):
`resolve --json` (universal SDK boundary), polyglot `codegen`, composable provider middleware, `oidc://` keyless CI, bidirectional `reflect()`, semantic contract diff, policy-as-code, the devenv module, contract snapshot/lockfile + drift, `sensitive=false`, the LSP, mirror provider, GitHub Action, the open-core boundary.

**Moonshots** (transformative):
SecretSpec Cloud, agent broker mode, build-bound SLSA attestation, `type=lease` dynamic secrets, `rotate --propagate` across the extends graph, a formal manifest spec/standard, remote signed `extends` registry, access-attestation matrix, transitive secret contracts (libraries declare their needs), provider marketplace, WASM resolver, org-wide git-crawl inventory.

**Most genuinely novel:**
`secretspec-mcp`, honeytoken/canary secrets, deterministic derived secrets (no storage), migration lockfile, time-windowed availability, compile-time redacted newtypes, `--scrub-env` sandbox, `scan-rules` generated from the manifest, publishable vendor setup fragments, quorum/split-knowledge audit, migration-as-rotation.

---

## The single most consequential observation

The **`resolve --json` boundary plus polyglot codegen** is both the README's explicit ask and the unlock for most of the rest (every SDK, framework adapter, and integration becomes a thin client over one authoritative resolver), while **SecretSpec Cloud as just-another-provider-URI** is the honest monetization path that never compromises the vendor-neutral contract.
