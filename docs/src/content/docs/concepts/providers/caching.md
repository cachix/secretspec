---
title: Provider caching
description: Cache slow provider routes in a local secret store
---

:::caution[Version compatibility]
Provider caching and `secretspec cache clear` are available starting with
SecretSpec 0.17.
:::

Remote providers add network, authentication, or external-CLI latency to every
read, even when values rarely change. Provider caching stores a time-limited
copy in a faster local store. Fresh entries return immediately; misses and
expired entries use the authoritative providers and refill the cache.

Configure caching with a cached alias. `fallback` lists the authoritative
providers in read order, and `cache.provider` selects the local leaf provider:

```toml title="secretspec.toml"
[providers]
azure = { uri = "akv://team-vault", credentials = { client_secret = "keyring" } }
env = "env://"
local = "keyring://secretspec/cache/{project}/{profile}/{key}"

myprovider = {
  fallback = ["azure", "env"],
  cache = { provider = "local", max_age = "8h" }
}

[profiles.development.defaults]
providers = ["myprovider"]
```

## Read behavior

SecretSpec reads a cached route in this order:

1. returns a fresh cache entry without constructing or contacting `azure` or
   `env`;
2. on a miss, unusable entry, or cache error, tries `azure` and then `env`;
3. caches the value returned by whichever fallback answers.

Cache failures produce warnings but never block the authoritative route.
SecretSpec never returns an expired value when all fallbacks fail. It deletes
expired, malformed, and route-mismatched entries when found so stale copies do
not remain indefinitely in stores without native expiry.

Value-free resolutions such as `check --json`, `check --explain`, and SDK
`no_values` requests may read or discard an existing entry, but never populate
or refresh one.

## Writes

Writes and generated values go to the first fallback (`azure` above), then
refresh the cache. If the refresh fails, the authoritative write still
succeeds and SecretSpec deletes the old cache entry. If deletion also fails,
the warning identifies the `cache clear` command to run.

Select a leaf provider to bypass the cache for one command:

```bash
$ secretspec check --provider azure
```

A direct write, such as `secretspec set API_KEY --provider azure`, invalidates
the corresponding cache entry.

## Freshness and invalidation

`max_age` requires a unit: `s`, `m`, `h`, `d`, or `w`; compound durations such
as `1h30m` are accepted.

Entries use SecretSpec's logical `{project}/{profile}/{secret}` address, even
when the authoritative secret has a provider-native `ref`. Each entry contains
the value, absolute expiration time, originating `max_age`, format version, and
a fingerprint of the fallback route and secret reference. Changing the route,
reference, or `max_age` invalidates it.

The cache must use a distinct store from every provider in `fallback`;
otherwise, a refresh could overwrite the authoritative secret. SecretSpec
rejects such routes during planning. The example uses a separate keyring
namespace for `local`.

The cache provider must also support deletion: keyring, pass, gopass, dotenv,
or a Vault/OpenBao KV v2 mount. Other providers are rejected during planning.

Clear one entry or every cached entry in the active profile:

```bash
$ secretspec cache clear API_KEY          # SecretSpec 0.17+
$ secretspec cache clear --profile production
```

## Store-side expiry

SecretSpec requests native expiry where supported, using `max_age`.
[Vault](/providers/vault/#provider-caching-017) and
[OpenBao](/providers/openbao/#provider-caching) set KV v2
`delete_version_after` metadata. This removes the copy on time even if
SecretSpec never runs again.

The entry's absolute expiration time remains the source of truth for freshness
on every store; a read at or after that time deletes the entry. Machines sharing
a cache should keep their system clocks synchronized. If native expiry cannot
be configured, for example because a Vault token lacks metadata access or the
mount uses KV v1, SecretSpec refuses the cache write and uses the authoritative
route.

## Ownership

Each cache entry records a marker, project, and profile. Because addresses can
collide in flat stores such as dotenv, SecretSpec changes only entries whose
ownership it can verify.

Unmarked entries and unexpired entries owned by another project or profile are
bypassed, not overwritten or deleted.
[`cache clear`](/reference/cli/#cache-clear-017) reports them. Any expired
SecretSpec entry can be deleted by the project that encounters it because its
stored lifetime has ended. A marked but unreadable entry, such as a partial
write, can be identified as SecretSpec's and replaced.

If clearing reports a foreign entry, two configurations are addressing the same
place. Give each project a separate store or path, such as the
`{project}/{profile}/{key}` path used by `local` above.

## Where cached aliases can be used

A cached alias works anywhere a complete route is selected:

- a secret or profile-default `providers` list;
- the user-global default provider;
- `SECRETSPEC_PROVIDER`;
- `--provider`.

Because a cached alias defines a complete route, it must be the only entry in a
`providers` list. Its fallback entries and cache provider may be aliases,
provider names, or URIs, but must resolve to leaf providers; cached aliases
cannot be nested.

Credentials belong on leaf aliases, such as `azure` above, rather than on
`myprovider`.

## Security

The cache contains the secret value, not just metadata. Use an encrypted
provider such as keyring, pass, or gopass when values must be encrypted at rest.
Dotenv stores entries as plaintext. Native expiry limits how long a copy exists
without another SecretSpec run.

## Next steps

- Review [Provider fallback](/concepts/providers/fallback/) for authoritative
  route and write semantics.
- See [`cache clear`](/reference/cli/#cache-clear-017) in the CLI reference.
- Review the [cached alias fields](/reference/configuration/#secretspec-017-cached-alias-values)
  in the configuration reference.
