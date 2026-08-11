# Bundler 4 Linux platform reproduction

This reproduces the Linux packaging behavior of the published
`secretspec` 0.19.0 gems with Ruby and Bundler 4.

## Run

Docker is the only prerequisite:

```console
./run.sh
```

The repository's full SDK integration runner, `scripts/ci-sdks.sh`, invokes
this script as part of its Ruby test section as well.

The script uses Ruby 4.0.6 images and verifies that Bundler 4 is active. It
runs three isolated cases:

1. The Debian/glibc control installs the generic `${arch}-linux` gem and loads
   it.
2. Alpine/musl resolves and installs that same generic Linux gem, but loading
   its extension fails because the bundled Rust archive was built for glibc.
3. `BUNDLE_FORCE_RUBY_PLATFORM=true` fails resolution because 0.19.0 has no
   `ruby` platform gem to use as a source-build fallback.

The script treats the latter two failures as successful reproductions, so it
exits zero only when all three behaviors are observed.

## Why the generic Linux gem is selected

The [RubyGems platform guide](https://guides.rubygems.org/platforms/#linux-and-musl)
states that a bare platform such as `x86_64-linux` matches both glibc and musl.
It is therefore not rejected by Bundler 4 as a deprecated platform. Instead,
Bundler considers the current generic gem compatible with Alpine even though
the native archive inside it is not.

Publishing distinct `*-linux-gnu` and `*-linux-musl` gems prevents that unsafe
match. Publishing a `ruby` variant would separately provide the fallback that
`force_ruby_platform` requests, but such a gem would need enough source to
build the Rust library locally; the current gem only builds its C glue locally
and links a prebuilt Rust archive.
