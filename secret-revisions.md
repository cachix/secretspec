# Proposal: secret revision metadata over IPC

Status: focused implementation now in the working tree; SDK migration and moon
integration remain proposals. The implementation shares one validated `Revision`
type across core and IPC, with domain-separated provider/selection/logical tokens.
Investigated against local HEAD `93e27205`
and the existing uncommitted IPC work on 2026-09-13. Proposed target: 0.21,
subject to the release scope. This is a design note, not published feature documentation.

Issue: [#440](https://github.com/cachix/secretspec/issues/440).
Related lifecycle work: [#11](https://github.com/cachix/secretspec/issues/11).

## Recommendation

Extend existing value-returning provider and resolver operations with optional
revision metadata. Preserve it with the value through caching and projection.
Start with AWS Secrets Manager and the IPC client API. Do not require dynamic
issuance, renewal, change notifications, or a new metadata-only operation.

The feature identifies the effective value observed by a resolution. It does
not guarantee an immediate observation of remote rotation or that a task's
outputs are otherwise safe to cache.

## Findings in this checkout

| Location | Finding and proposed change |
| --- | --- |
| `secretspec/src/provider/traits.rs` | `ProviderValue` has bytes and expiry. Add an optional provider revision. Preserve the existing constructor with revision defaulting to unknown. |
| `secretspec/src/provider/traits.rs` | `get_many_with_metadata` wraps `get_many` with unknown metadata. Providers must override both metadata methods; overriding only the single read is insufficient. |
| `secretspec-ipc/src/provider.rs` | The endpoint's value wrapper and `into_parts` carry expiry only. Extend these as well as wire types. |
| `secretspec-ipc/src/protocol.rs` | Add revision to provider found results, batch found results, resolver inline results, and resolver path results. |
| `secretspec/src/provider/external.rs` | Preserve revisions through both single and batch adapters. |
| `secretspec/src/cache.rs` | The v4 envelope stores bytes and secret expiry, but no revision. Add an optional provider revision with a missing-field default. |
| `secretspec/src/secrets.rs`, `validation.rs` | Carry revisions through authoritative reads, cache hits, fallback, extraction, decoding, and owned named resolution. |
| `secretspec/src/serve.rs` | Return the effective revision with the exact value/path returned. |
| `secretspec/src/resolve.rs` | Public `ResolvedSecret` has no expiry, freshness, or revision. The owned-to-embedded conversion currently discards the clocks. SDK exposure needs an explicit follow-up. |

Cache-hit `source_provider` names the serving cache store. Consequently it
cannot namespace a backend version correctly. The cache must preserve a
self-contained revision from the authoritative read, independently of display
provenance. The existing route fingerprint identifies routing configuration,
not the identity and generation of the secret that answered.

## Revision contract

Introduce distinct Rust newtypes `ProviderRevision` and `SecretRevision`.
Both serialize as opaque strings; neither grants access or supports ordering.
A provider revision identifies the exact bytes returned by that provider,
including any provider-side field selection. A secret revision identifies the
logical bytes after SecretSpec's extraction and decoding.

For supported values, equal revisions imply equal bytes under the documented
provider identity and projection rules, subject to ordinary cryptographic
collision assumptions. Different revisions may identify equal bytes: updating
an unrelated field or writing the same value again may conservatively invalidate
a task. Consumers must not interpret revisions as counters or require monotonicity.

Revisions must be stable across independent clients using the same algorithm
and observing the same backend identity, generation, and projection. A session
ID, local random number, path lease, cache write time, or secret digest does not
satisfy this contract. Neither does an unscoped provider version number.

Providers may derive tokens from explicitly non-secret identity/version metadata
using a domain-separated SHA-256 hash with length-prefixed fields. They must not
hash secret bytes, credentials, renewal/revocation handles, or arbitrary response
metadata. Hashing is not a way to sanitize sensitive input. External endpoints
are responsible for honoring the same contract; the resolver cannot prove that
an opaque token is safe merely by validating its syntax.

Use a versioned token format and a bounded ASCII representation (proposed maximum
256 bytes). Reject malformed non-null tokens without including them in errors.
Absent and null both mean unknown. Unknown is never an equality token on which
to base a cache hit.

At the resolver, derive `SecretRevision` from the provider token and a canonical
description of SecretSpec's extraction/decoding operations. Do not incorporate
credentials, cache times, temporary paths, or the whole configuration. Updating
projection semantics requires updating the algorithm discriminator. Preserve the
provider token in the cache so the current projection can be applied on each read.
`resolve_provider_backed_values` writes the provider bytes to the cache before
`insert_resolved` applies the stored-to-logical conversion. Derive the effective
token alongside that conversion, after it succeeds, on both direct and cached
reads. Keep the cached token at the provider boundary to avoid applying a
projection twice.

Initially, generated, defaulted, and composed results return unknown. Do not
hash a default value or composition literals to manufacture a revision. Later
composition support needs all dependency revisions and an explicit treatment of
literal content, expression identity, and unknown dependencies.

## Wire and SDK changes

Proposed additions to existing found/resolved result objects:

```json
{
  "revision": "ssr1:opaque-token",
  "expires_at_unix_ms": null,
  "refresh_at_unix_ms": null
}
```

This is a metadata fragment, not a complete response. Provider results carry
their provider token and expiry; only resolver results carry cache freshness.
Retain the two existing clocks rather than adding `validUntil`. Expiry is a
known credential-validity bound; freshness determines when a cached copy is
re-read. Neither promises unchanged provider state until that time.

The current IPC wire rules allow unknown result fields. Keep both protocol `/1`
identifiers, make `revision` optional in schemas, and use a Serde missing-field
default rather than `deserialize_required_nullable`. New clients accept old
results and old clients ignore the addition. Per-result nullability is sufficient;
a provider-wide support flag would not prove that a particular result is known.

Update canonical and packaged schemas/OpenRPC assets, discovery output, fixtures,
typed endpoint/client wrappers, and C/Rust conformance coverage together. New
request fields or methods would require capability negotiation; this result-only
addition does not.

The embedded JSON/FFI response is a different contract: its schema closes
`resolvedSecret` with `additionalProperties: false` and uses schema version 2.
Do not assume IPC's additive compatibility applies there. Follow IPC delivery
with a deliberate schema-version migration (proposed version 3) and coordinated
SDK decoder changes exposing revision and both clocks. Adding fields to public
Rust structs also requires a source-compatibility audit of struct literals.
Keep `check --json` as a preflight report, not a promise of an execution snapshot.

## Cache and write behavior

Store value, provider revision, and expiry together in the existing envelope.
Existing v4 and older cache entries decode with unknown revision. New optional
v4 metadata can be ignored by old readers; an old writer may lose it, which
correctly produces unknown rather than a false cache hit.

An authoritative read populates the envelope with its own revision. A cache read
never supplements an old value with freshly fetched provider metadata. A write
must drop any old revision. Since current set operations do not return a
value-bound revision, cache refresh after a write stores unknown until a later
authoritative read; never retain the pre-write revision or invent a generation.
Delete follows the existing invalidation path. Fallback carries the revision of
the provider that actually supplied the returned bytes.

## First provider: AWS Secrets Manager

Use a domain-separated digest of the returned full ARN, returned `VersionId`,
and optional JSON field selector. Both single reads and batch entries contain
ARN/version metadata. Preserve this alongside bytes in the batch's name/ARN
index, then derive each selected field's token. Missing identity/version metadata
means unknown, not an extra metadata lookup.

This choice has a stronger documented identity foundation than an incrementing
counter: [GetSecretValue](https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html)
returns the value and version together;
[PutSecretValue](https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_PutSecretValue.html)
does not allow an existing version's value to be changed; and
[CreateSecret](https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_CreateSecret.html)
documents a different ARN when a deleted secret's name is reused.
[Batch entries](https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_SecretValueEntry.html)
also include ARN and version ID. Region-specific replicas can conservatively
have different revisions. A moved `AWSCURRENT` label must use the returned
version ID, not the label as the revision.

AWS permits callers to choose version IDs through `ClientRequestToken`; providers
must document the assumption that writers use it as non-secret metadata, as AWS
intends. Do not promise safety for deliberately secret-derived version IDs.

Defer Parameter Store and Vault/OpenBao KV v2 until their full identity contracts
are established. [Parameter Store](https://docs.aws.amazon.com/systems-manager/latest/userguide/sysman-paramstore-versions.html)
starts newly created parameters at version 1.
[Vault KV v2](https://developer.hashicorp.com/vault/api-docs/secret/kv/kv-v2)
supports deleting all versions and metadata. A bare version is therefore
insufficient; adding a modification timestamp needs an explicit uniqueness and
recreation argument rather than assuming a timestamp is a generation ID.

## moon integration contract

[moon hashes before execution and persists hash inputs for debugging](https://moonrepo.dev/docs/concepts/cache).
The integration should resolve selected secrets once before fingerprinting, retain
the exact values privately, and add only sorted `(name, revision)` pairs to its
fingerprint inputs. Ordinary task/configuration inputs remain necessary.

On a cache miss, inject those retained values into the child after the normal
hash-input capture, without putting secret values in task configuration snapshots
or diagnostic manifests. On a hit, discard them. Keep path leases alive through
execution and release them on hit, completion, or cancellation. A temporary path
is not an input revision. The integration must verify moon's actual injection
hook; this investigation verified documented caching behavior, not an existing
SecretSpec plugin implementation.

If a selected resolved secret has unknown revision, bypass task-cache reads and
writes for that invocation. Missing optional values need an explicit absent marker;
required missing values and provider failures remain errors. Recheck known expiry
before launching a delayed task; if re-resolution is needed, rebuild its fingerprint.
Expiry is not automatically an expiration time for already-produced task outputs.

Do not fingerprint one read and launch a separate `secretspec run` that reads again.
No new snapshot protocol is required when the client retains the returned values.
This still does not provide atomic multi-secret provider issuance: correlated dynamic
credentials need the separate resource/batch design in #11.

Normal cache policy means upstream rotation may remain unobserved until refresh.
Document that limit. Integrations requiring a fresh backend observation must use
routes without SecretSpec caching initially, accounting for provider-side caching
as well. A future capability-gated revalidation policy must preserve routing,
fallback, and authorization; merely selecting a different leaf provider is not equivalent.

## Delivery and acceptance tests

First change: revision types, provider/IPC/cache propagation, AWS Secrets Manager
single and batch support, and IPC documentation marked with the selected target
version at each use. Include one user-facing unreleased changelog entry when
committing the Rust change. Second change: embedded SDK schema migration and
moon integration. Metadata-only reads, conditional resolution, composition, and
dynamic lifecycle capabilities remain separate proposals.

Required behavioral coverage for the first change:

- Repeated independent reads agree; changed generation differs; same bytes in a
  new generation may differ; rollback to an old generation remains valid.
- Same version string under different ARNs differs; delete/recreate differs;
  moving `AWSCURRENT` follows the version actually returned.
- Single/batch parity, duplicate addresses, JSON fields, binary values, and
  extraction/encoding changes preserve or transform metadata correctly.
- Cache hits return the stored value/revision pair even after remote rotation;
  expiry/refresh, old envelopes, writes, deletion, and fallback never pair an old
  value with a new revision or vice versa.
- Unknown/null/absent revisions remain unknown; malformed tokens fail without
  leaking them; old/new IPC peers interoperate in both directions.
- A simulated task retains value A after fingerprinting A while the provider
  rotates to B; path cleanup and expiry-triggered re-resolution behave correctly.
- Conformance canaries never reach task hash manifests, logs, or error output.

Run focused provider/cache/resolver tests, `cargo test -p secretspec-ipc --test fixtures`,
the IPC conformance checks and affected client/provider matrices, then
the repository's required formatting and test checks. The original investigation did not change runtime code; the subsequent focused
implementation adds provider, cache, resolver, schema, and conformance tests.
