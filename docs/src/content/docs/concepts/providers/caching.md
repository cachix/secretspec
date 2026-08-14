---
title: Provider caching
description: Cache slow provider routes in a local secret store
---

:::caution[Version compatibility]
Provider caching and `monosecret cache clear` are available starting with
Monosecret 0.2.
:::

## The problem

A remote secret read can include authentication, external-process startup,
DNS, TCP and TLS setup, and one or more network requests. Those fixed costs can
dominate a command that resolves only a few secrets. Separate Monosecret CLI
invocations may pay them again even when the values rarely change.

Latency can also scale with the number of distinct secret addresses. Monosecret
groups compatible reads and providers can batch or parallelize them, but the
remote service, proxy, or provider CLI still determines the cost of each read.

## Cache one provider (0.2+)

Provider caching places a faster local secret store in front of an
authoritative provider. A fresh cache entry returns without constructing or
contacting the remote provider; a miss reads the remote value and stores it
locally for later Monosecret invocations.

:::caution[Version compatibility]
Attaching `cache` directly to a provider URI is available starting with
Monosecret 0.2. Use a cached fallback alias on Monosecret 0.2 and 0.2.
:::

Add `cache` to the remote provider alias and select that same alias normally:

```toml title="monosecret.toml"
[providers]
local = "keyring://monosecret/cache/{project}/{profile}/{key}"
azure = {
  uri = "akv://team-vault",
  credentials = { client_secret = "keyring" },
  cache = { provider = "local", max_age = "8h" }
}

[profiles.development.defaults]
providers = ["azure"]
```

The alias remains the authoritative provider, so its [provider credentials](/concepts/providers/#provider-credentials) stay next to `uri` and
`cache`.

## Cache a fallback route (0.2+)

When more than one provider can authoritatively answer, use a route alias.
`fallback` lists its providers in read order and `cache.provider` selects the
local leaf provider:

```toml title="monosecret.toml"
[providers]
azure = "akv://team-vault?auth=cli"
env = "env://"
local = "keyring://monosecret/cache/{project}/{profile}/{key}"

remote = {
  fallback = ["azure", "env"],
  cache = { provider = "local", max_age = "8h" }
}

[profiles.development.defaults]
providers = ["remote"]
```

## Read behavior

Monosecret reads a cached route in this order:

1. returns a fresh cache entry without constructing or contacting an
   authoritative provider;
2. on a miss, unusable entry, or cache error, reads the provider URI or tries
   each `fallback` entry in order;
3. caches the value returned by the authoritative provider that answers.

Cache failures produce warnings but never block the authoritative route.
Monosecret never returns an expired value when all fallbacks fail. It deletes
expired, malformed, and route-mismatched entries when found so stale copies do
not remain indefinitely in stores without native expiry.

Value-free resolutions such as `check --json`, `check --explain`, and SDK
`no_values` requests may read or discard an existing entry, but never populate
or refresh one.

## Writes

Writes and generated values go to the provider URI or the first fallback, then
refresh the cache. If the refresh fails, the authoritative write still succeeds
and Monosecret deletes the old cache entry. If deletion also fails, the warning
identifies the `cache clear` command to run.

For a cached fallback route, select a leaf provider to bypass the cache for one
command:

```bash
$ monosecret check --provider azure
```

In the fallback example, a direct write such as
`monosecret set API_KEY --provider azure` invalidates the corresponding cache
entry.

## Freshness and invalidation

`max_age` requires a unit: `s`, `m`, `h`, `d`, or `w`; compound durations such
as `1h30m` are accepted.

Entries use Monosecret's logical `{project}/{profile}/{secret}` address, even
when the authoritative secret has a provider-native `ref`. Each entry contains
the value, absolute expiration time, originating `max_age`, format version, and
a fingerprint of the fallback route and secret reference. Changing the route,
reference, or `max_age` invalidates it.

The cache must use a distinct store from every authoritative provider;
otherwise, a refresh could overwrite the authoritative secret. Monosecret
rejects such routes during planning. The examples use a separate keyring
namespace for `local`.

The cache provider must also support deletion: keyring, pass, gopass, dotenv,
or a Vault/OpenBao KV v2 mount. Other providers are rejected during planning.

Clear one entry or every cached entry in the active profile:

```bash
$ monosecret cache clear API_KEY          # Monosecret 0.2+

$ monosecret cache clear --profile production
```

## Store-side expiry

Monosecret requests native expiry where supported, using `max_age`.
[Vault](/providers/vault/#provider-caching-017) and
[OpenBao](/providers/openbao/#provider-caching) set KV v2
`delete_version_after` metadata. This removes the copy on time even if
Monosecret never runs again.

The entry's absolute expiration time remains the source of truth for freshness
on every store; a read at or after that time deletes the entry. Machines sharing
a cache should keep their system clocks synchronized. If native expiry cannot
be configured, for example because a Vault token lacks metadata access or the
mount uses KV v1, Monosecret refuses the cache write and uses the authoritative
route.

## Ownership

Each cache entry records a marker, project, and profile. Because addresses can
collide in flat stores such as dotenv, Monosecret changes only entries whose
ownership it can verify.

Unmarked entries and unexpired entries owned by another project or profile are
bypassed, not overwritten or deleted.
[`cache clear`](/reference/cli/#cache-clear-017) reports them. Any expired
Monosecret entry can be deleted by the project that encounters it because its
stored lifetime has ended. A marked but unreadable entry, such as a partial
write, can be identified as Monosecret's and replaced.

If clearing reports a foreign entry, two configurations are addressing the same
place. Give each project a separate store or path, such as the
`{project}/{profile}/{key}` path used by `local` above.

## Where cached aliases can be used

An inline cached provider alias or cached fallback alias works anywhere a
complete route is selected:

- a secret or profile-default `providers` list;
- the user-global default provider;
- `MONOSECRET_PROVIDER`;
- `--provider`.

Because a cached alias defines a complete route, it must be the only entry in a
`providers` list. Fallback entries and the cache provider may be aliases,
provider names, or URIs, but must resolve to leaf providers; cached aliases
cannot be nested.

An inline cached alias can declare credentials next to its `uri`. For a cached
fallback route, credentials belong on its leaf aliases rather than on the route
alias.

## Security

The cache contains the secret value, not just metadata. Use an encrypted
provider such as keyring, pass, or gopass when values must be encrypted at rest.
Dotenv stores entries as plaintext. Native expiry limits how long a copy exists
without another Monosecret run.

## Reference

- See [`cache clear`](/reference/cli/#cache-clear-017) in the CLI reference.
- Review the [inline cache fields](/reference/configuration/#monosecret-019-inline-provider-cache)
  (0.2+) or [cached fallback fields](/reference/configuration/#monosecret-017-cached-fallback-alias-values)
  in the configuration reference.
- Review [Provider fallback](/concepts/providers/fallback/) for authoritative
  route and write semantics.

## Diagnose and improve provider performance

Use these checks when the first cache fill is too slow, the route cannot be
cached, or you need to understand a platform-specific difference.

### Establish a baseline

Benchmark the same command, profile, and set of secrets each time. `check`
resolves values without printing them:

```bash
$ time monosecret get SECRET_NAME >/dev/null

$ time monosecret check --no-prompt
```

The redirected `get` prevents the value from appearing in the terminal. Compare
it with the complete profile: similar times suggest a fixed authentication or
connection cost, while time that grows with the number of secrets points to
per-secret round trips, provider grouping, or concurrency.

If you have [hyperfine](https://github.com/sharkdp/hyperfine), compare repeated
runs:

```bash
$ hyperfine --warmup 1 'monosecret check --no-prompt'
```

Record the first run separately. A warmup can hide cold authentication or an
external CLI's startup cost, while repeated one-shot Monosecret commands still
pay that cost in normal use.

### Isolate authentication and network cost

When a provider uses an external CLI, time a harmless authentication command
without printing its token. For Azure CLI, for example:

```bash
$ time az account get-access-token \
  --scope https://vault.azure.net/.default \
  --output none
```

If this takes most of a cache miss, consider another supported authentication
mode. External CLI sessions are convenient for local development, but direct
service-principal, managed-identity, workload-identity, token, or SDK
authentication can avoid the process boundary where appropriate.

For example, the [Azure Key Vault provider](/providers/akv/#authentication)
supports Azure CLI sessions as well as service principals, managed identity,
and workload identity. Prefer the identity mode that matches the environment;
do not replace short-lived or workload-bound credentials with long-lived
credentials solely to reduce latency.

To distinguish connection setup from the secret API itself, probe the remote
endpoint without requesting a real secret. This Azure Key Vault example is
expected to return an authorization error, but still reports DNS, TCP, TLS, and
time to first byte:

```bash
$ curl --silent --show-error --output /dev/null \
  --write-out 'dns=%{time_namelookup} connect=%{time_connect} tls=%{time_appconnect} ttfb=%{time_starttransfer} total=%{time_total}\n' \
  'https://VAULT.vault.azure.net/secrets/__probe__?api-version=7.5'
```

Run the same probe from the host and from WSL or a container to expose a
platform-specific DNS, VPN, proxy, or TLS delay.

### Keep related secrets on one route

Secrets that use the same store and authentication configuration should select
the same provider alias. Monosecret groups those reads into one provider
operation, deduplicates identical references, and lets providers use a bulk API
or bounded parallel reads where supported.

Do not merge aliases that intentionally use different identities, endpoints,
namespaces, or other security settings. Those are distinct routes even if they
use the same provider type.

### Tune per-address concurrency (0.2+)

Providers using Monosecret's default per-address fetch path read up to eight
unique addresses concurrently. Test a few caps when latency grows with the
number of secrets:

```bash
$ MONOSECRET_PROVIDER_CONCURRENCY=1 monosecret check --no-prompt

$ MONOSECRET_PROVIDER_CONCURRENCY=4 monosecret check --no-prompt

$ MONOSECRET_PROVIDER_CONCURRENCY=16 monosecret check --no-prompt
```

More concurrency is not always faster. It can increase rate limiting, overload
a reverse proxy, or create more simultaneous connections. The setting does not
remove a provider's cold authentication floor, and providers with a true bulk
API may not use it for their batched reads.

### Check WSL and container overhead

If the same manifest is slower under WSL or in a container:

- use the Linux build of each provider CLI instead of invoking a Windows
  executable through interoperability;
- keep the project and provider CLI's configuration and credential cache on
  the Linux filesystem rather than under `/mnt/c`;
- compare the endpoint probe with and without `curl -4` to identify an
  address-family or VPN routing delay before changing system-wide networking;
- check whether a proxy, VPN, antivirus product, or certificate helper is only
  active on one side of the host boundary;
- remember that short-lived containers repeat process startup, authentication,
  DNS, and TLS setup on every invocation.

### Interpret the results

| Observation                                              | Likely cost                                                 | First thing to try                                                          |
| -------------------------------------------------------- | ----------------------------------------------------------- | --------------------------------------------------------------------------- |
| One secret and the full profile take about the same time | Authentication or process startup                           | Use direct authentication where appropriate, or cache the route             |
| Every Monosecret invocation has the same fixed delay     | External CLI or cold connection setup                       | Time the auth command and endpoint probe separately                         |
| Time grows with the number of secrets                    | Per-secret network reads                                    | Consolidate equivalent routes and benchmark concurrency                     |
| A warm run is much faster than the first                 | Provider CLI, token, DNS, or connection cache               | Preserve the relevant cache and benchmark cold runs separately              |
| Only WSL or a container is slower                        | Filesystem, DNS, VPN, proxy, or executable interoperability | Compare the host/container probes and move hot files off mounted host paths |
