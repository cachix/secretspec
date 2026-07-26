---
title: Provider caching
description: Cache slow provider routes in a local secret store
---

:::caution[Version compatibility]
Provider caching and `secretspec cache clear` are available starting with
SecretSpec 0.17.
:::

A cached alias is a complete provider route: `fallback` contains the
authoritative providers in read order, while `cache.provider` names the local
leaf provider used to accelerate reads.

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

On a read, SecretSpec:

1. returns a fresh cache entry without constructing or contacting `azure` or
   `env`;
2. on a miss, expired entry, malformed entry, or cache error, tries `azure` and
   then `env`;
3. caches the value returned by whichever fallback answers.

Expired values are not returned when every fallback fails. A cache read or
write failure produces a warning but does not prevent the authoritative route
from answering.

An entry no read can serve — expired, malformed, or written for a different
authoritative route — is deleted when it is found, not merely skipped. Most cache
stores cannot expire a value themselves, and a refresh only overwrites an entry
when the authoritative read succeeds, so without this an expired value would keep
its plaintext in the store indefinitely: a `secretspec run` that resolves once
and then runs for a week leaves an entry nothing revisits until the next command.

Value-free resolution such as `check --json`, `check --explain`, and SDK
`no_values` requests may read an existing cache and drop an unusable entry, but
never populate or refresh one.

## Writes

Writes and generated values go to the first fallback (`azure` above), then
refresh the cache. A cache write failure does not hide a successful
authoritative write.

A cached value never outlives the write that superseded it. If the refresh
fails, the entry is dropped rather than left to be served until it expires, and
if it cannot even be dropped the warning names the `cache clear` to run.

Select a leaf directly to bypass the cached route for one command:

```bash
$ secretspec check --provider azure
```

A write through such a bypass (`secretspec set API_KEY --provider azure`) also
invalidates the cache entry, so the next read sees the value that was just
written rather than the one it replaced.

## Freshness and invalidation

`max_age` requires a unit: `s`, `m`, `h`, `d`, or `w`; compound durations such
as `1h30m` are accepted.

The cache entry is stored at SecretSpec's logical
`{project}/{profile}/{secret}` address even when the authoritative secret uses
a provider-native `ref`. It contains the value, write time, format version, and
a fingerprint of the fallback route and secret reference. Changing the route
or reference therefore invalidates an existing entry.

Because the entry is stored at that same logical address, the cache must be a
*distinct* store from every provider in `fallback`. A cache that resolves to one
of its own authoritative sources is rejected when the route is planned: refreshing
it would overwrite the secret with the cache entry. The `local` alias above keeps
the cache in its own keyring namespace for exactly this reason.

Clear one entry or every cached entry in the active profile:

```bash
$ secretspec cache clear API_KEY          # SecretSpec 0.17+
$ secretspec cache clear --profile production
```

Invalidation is what keeps a cached value from outliving its authoritative one,
so the cache provider must be a store SecretSpec can delete from: keyring, pass,
gopass, dotenv, or a Vault/OpenBao KV v2 mount. A cache pointed at any other
provider is rejected when the route is planned, rather than leaving entries
nothing could ever clear.

## Store-side expiry

Where the store can expire a value on its own, SecretSpec asks it to, using the
same `max_age`. [Vault](/providers/vault/#provider-caching-017) and
[OpenBao](/providers/openbao/#provider-caching) do this through the KV v2 path's
`delete_version_after` metadata. The cached copy then stops existing at that age
even if SecretSpec is never run again, which matters because the entry is a copy
of a secret another store owns.

The envelope's own write time stays the authority on freshness: it is what makes
`max_age` hold for stores that cannot expire anything, and a read that finds an
entry past that age drops it. What store-side expiry adds is a bound that does not
need SecretSpec to run at all — the difference between "removed the next time a
command touches this secret" and "gone at 8h". A provider that
*can* expire but cannot arrange it — a token without access to Vault's metadata
path, a KV v1 mount — refuses the write instead of storing a copy that would
never expire; the read falls through to the authoritative route as with any
other cache failure.

## Ownership

Every entry SecretSpec writes carries a marker, the owning project, and the
profile it was resolved under. A cache address is not proof of ownership: a flat
store such as dotenv gives every project the same key for a given secret name,
and a store may hold values SecretSpec never wrote.

So SecretSpec changes only what it can show is its own. A value with no marker,
or an entry naming another project or profile, is left alone — reads fall through
to the authoritative route, refreshes decline to overwrite it, and
[`cache clear`](/reference/cli/#cache-clear-017) reports it instead of deleting
it. An entry that carries the marker but cannot be read, such as a partially
written one, is unmistakably SecretSpec's own and is replaced.

If clearing reports a foreign entry, two configurations are addressing the same
place. Give each project's cache a store or path of its own — the `local` alias
above uses a `{project}/{profile}/{key}` path for exactly this reason.

## Where cached aliases can be used

A cached alias works anywhere a complete route is selected:

- a secret or profile-default `providers` list;
- the user-global default provider;
- `SECRETSPEC_PROVIDER`;
- `--provider`.

It must be the only entry in a `providers` list because its own `fallback`
already defines the complete route; a cached alias listed alongside other
entries, in any position, is rejected. Its fallback entries and cache provider
may be aliases, provider names, or URIs, but must resolve to leaf providers;
cached aliases cannot be nested.

Credentials belong on leaf aliases, such as `azure` above, rather than on
`myprovider`.

## Security

The cache provider stores the secret value, not merely metadata. Choose an
encrypted provider such as keyring, pass, or gopass when cached values must be
encrypted at rest. Dotenv is useful for testing but stores cache entries as
plaintext. A store with server-side expiry additionally bounds how long the copy
exists without SecretSpec's involvement.

## Next steps

- Review [Provider fallback](/concepts/providers/fallback/) for authoritative
  route and write semantics.
- See [`cache clear`](/reference/cli/#cache-clear-017) in the CLI reference.
- Review the [cached alias fields](/reference/configuration/#secretspec-017-cached-alias-values)
  in the configuration reference.
