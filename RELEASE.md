# Releasing the language SDKs

Each SDK is a thin client over the Rust core (the `secretspec-ffi` cdylib, a
pyo3 extension for Python, or the napi-rs addon for Node). A release builds
the native artifact per platform and publishes it through that ecosystem's
registry, so users install with no native build. The per-platform build
workflows are drafted under `.github/workflows/`; the Python build (wheel
build + install) has been verified running end to end in CI, but the actual
publish steps below have not (they need the one-time external Trusted
Publisher / secret setup described per language first).

Version tags are `vX.Y.Z`; the publish jobs trigger on them.

## Before your first release

Trusted Publishing works differently per registry. PyPI and RubyGems let you
register a **pending publisher** before anything is published — the first
tagged release creates the project/gem automatically, no manual publish step.
npm has no such mechanism: the package must already exist before you can
attach a Trusted Publisher to it, so the very first version has to go up with
a temporary token. Do each of these once; every release after it needs no
secrets (except Hackage, which has no Trusted Publishing at all yet).

### crates.io — already done

`secretspec` and `secretspec-derive` already exist on crates.io and Trusted
Publishing is already wired up in `publish.yml` (this predates the SDK work
that added the other languages). Nothing to do, beyond confirming the linked
GitHub repo is still correct at
https://crates.io/crates/secretspec/settings if this repo is ever renamed or
transferred.

### PyPI — pending publisher configured, done

The `pypi` GitHub Environment exists and a pending publisher is configured on
PyPI (project `secretspec`, owner `cachix`, repo `secretspec`, workflow
`python-wheels.yml`, environment `pypi`). Nothing left to do — the first
`vX.Y.Z` tag's OIDC-authenticated publish will create the `secretspec` project
on PyPI automatically and convert the pending publisher into a normal one.
⚠️ if someone else registers the `secretspec` name on PyPI before that first
tag, the pending publisher is invalidated and the project would need a
different name.

### RubyGems — pending publisher configured, done

A pending trusted publisher is configured on rubygems.org (gem `secretspec`,
repository owner `cachix`, repository name `secretspec`, workflow filename
`ruby-gems.yml`, environment `release`). Nothing left to do — the first
`vX.Y.Z` tag's push creates the gem and makes the publishing workflow its
owner automatically.

### npm — already done

npm has no pending-publisher mechanism, so this needed a manual first publish
for the main `secretspec` package **and every platform sub-package**
(`secretspec-linux-x64-gnu`, `secretspec-linux-arm64-gnu`,
`secretspec-darwin-arm64`, `secretspec-win32-x64-msvc`) — 5 packages that each
had to exist before a Trusted Publisher could be attached. This has been done:
all 5 packages are published (bootstrap-published once with a temporary
granular access token, "All Packages" / "Read and write" scope — narrower
"select packages" scopes 404 on brand-new package names, since that picker
can't reference a package that doesn't exist yet), each has a Trusted
Publisher configured (GitHub Actions, repo `cachix/secretspec`, workflow
`node-addon.yml`, no environment), and the bootstrap token has been revoked.
Nothing left to do — every release from here publishes via OIDC.

### Hackage — token set, done

Hackage doesn't support OIDC yet (tracked upstream:
[haskell/hackage-server#1443](https://github.com/haskell/hackage-server/issues/1443),
open as of this writing), so this stays a long-lived token rather than a
one-time setup step. The `HACKAGE_TOKEN` repo secret is set. Nothing left to
do — the first `vX.Y.Z` tag's `haskell-build.yml` publish job uploads with it.

### Go — nothing to set up

No registry involved. `go get` reads the tag directly from git; `go-embed.yml`
just attaches per-platform cdylibs to the GitHub Release for the optional
self-contained build.

### Packagist (PHP) — not yet set up

Packagist has no OIDC/Trusted-Publishing mechanism; it reads a git repo and its
root `composer.json` directly. This repo publishes the PHP package straight from
the monorepo — the manifest lives at the repository root (`/composer.json`, with
`vendor-dir` pointed into `secretspec-php/` and autoload sourcing
`secretspec-php/src/`), so no split/mirror repo is needed. One-time setup:

1. Submit `https://github.com/cachix/secretspec` on
   [packagist.org](https://packagist.org) as package `cachix/secretspec`.
2. Enable the GitHub auto-update hook (the Packagist GitHub app), so each
   `vX.Y.Z` tag becomes a Composer version automatically.

No CI workflow or token is involved — Packagist pulls from the tag on push.

### NuGet (.NET) — not yet set up

The `Cachix.SecretSpec` package is built by `dotnet-package.yml`. Before its
first release, reserve the package ID on nuget.org and add an
`NUGET_API_KEY` secret to the repository's `nuget` environment, scoped to push
only `Cachix.SecretSpec`. Version tags then build all native runtime assets,
pack them into one `.nupkg`, and publish it automatically.

## Python (PyPI) — `python-wheels.yml`

- **Build:** the Rust resolver is statically linked into a pyo3 extension
  (`secretspec._native`, built from the `secretspec-py-native` crate via
  maturin) — there is no separate cdylib bundled. The extension targets
  pyo3's `abi3-py39` feature, so one `cp39-abi3-<platform>` wheel per platform
  serves all CPython >= 3.9. Linux wheels are built via `PyO3/maturin-action`
  inside a `manylinux_2_28` container (old glibc); maturin vendors the
  extension's dynamic system dependencies itself (notably `libdbus`, pulled in
  by the keyring provider), no separate `auditwheel` step needed. macOS builds
  natively; a Windows wheel is a follow-up.
- **Publish:** `pypa/gh-action-pypi-publish` via **PyPI Trusted Publishing**
  (OIDC); no token needed. One-time setup already done — see "Before your
  first release" above.

## Ruby (RubyGems) — `ruby-gems.yml`

- **Build:** a platform gem (`Gem::Platform::CURRENT`) bundling the
  `secretspec-ffi` staticlib in `vendor/`. At `gem install`, mkmf compiles a tiny
  C glue and statically links that archive, so the resolver is embedded in the
  extension and one platform gem serves every Ruby ABI (install needs a C
  compiler + Ruby headers, plus `libdbus-1-dev` for the keyring provider).
- **Publish:** `gem push` for each platform gem, authenticated via **RubyGems
  Trusted Publishing** (OIDC) through `rubygems/configure-rubygems-credentials`
  — no token stored in CI. One-time setup already done — see "Before your
  first release" above.
- **Gap:** the Linux gem currently links the runner's glibc; for a portable gem,
  build the staticlib on an old-glibc baseline (e.g. a `manylinux` container, as
  the Python job does, or `rake-compiler-dock`) and bundle that. Tracked
  follow-up.

## Go (system library) — `go-embed.yml`

Go has no binary registry, and the module proxy (`proxy.golang.org`) builds
module zips from raw git objects — it does **not** run git-LFS smudge filters, so
LFS-tracked files reach consumers as ~130-byte pointer text, not libraries.
`go:embed` over LFS therefore cannot ship a working library through `go get`.
(Committing the ~34 MB-per-platform libs to *plain* git would work but bloats
history permanently and ships every platform's lib in the module zip.)

So the Go SDK follows the purego norm: the cdylib is provided at runtime, not
shipped through the module. Consumers either set `SECRETSPEC_FFI_LIB` to an
installed/built `libsecretspec_ffi`, or build with `-tags embed_lib` after
staging the per-platform library into `secretspec-go/lib/` themselves (a
self-contained, vendored build — not a module-proxy install).

- **Build:** `go-embed.yml` builds the per-platform libs, uploads them as
  artifacts, and smoke-tests an `-tags embed_lib` build with a staged lib.
- **Release:** nothing to publish to a registry. Attach the per-platform cdylibs
  to the GitHub release so users who want a self-contained build can download and
  stage them. Do **not** commit binaries to the repo (plain git or LFS).

> The loader rejects an embedded git-LFS pointer with a clear error, so a botched
> LFS-based build fails loudly instead of feeding pointer text to `dlopen`.

## Haskell (Hackage) — `haskell-build.yml`

- **Build:** statically links the `secretspec-ffi` archive at build time via
  the GHC FFI, so the Rust resolver is embedded in the binary with no runtime
  loader path.
- **Publish:** `cabal upload --publish` with the `HACKAGE_TOKEN` secret — see
  "Before your first release" above. Hackage has no Trusted Publishing yet
  ([haskell/hackage-server#1443](https://github.com/haskell/hackage-server/issues/1443)),
  so this stays a long-lived token.
- **Note:** Hackage's own build bots cannot compile this package (it statically
  links a Rust archive Hackage doesn't build); the upload still succeeds, it
  just won't show as "buildable" in Hackage's UI. The README documents the
  link requirement for anyone installing from source.

## Node.js (npm) — `node-addon.yml`

- **Build:** `node-addon.yml` builds the napi-rs addon (`secretspec.node`) per
  platform via `@napi-rs/cli` (`scripts/build-addon.sh` wraps `napi build`) and
  runs the SDK tests against it.
- **Publish:** multi-platform npm distribution uses per-platform optional
  packages (`secretspec-<platform>`, e.g. `secretspec-linux-x64-gnu`) that the
  main `secretspec` package references via `optionalDependencies` and loads at
  runtime — the layout `@napi-rs/cli` automates (`napi create-npm-dirs` /
  `napi pre-publish`). Authenticated via **npm Trusted Publishing** (OIDC); no
  token stored in CI.
- **One-time setup:** already done — see "Before your first release" above.

## PHP (Packagist + extension) — `php-ext.yml`

The PHP SDK ships as two artifacts, because PHP delivers native code as an
*extension* (provisioned at the image/php.ini level, like `ext-redis`), not
through Composer.

- **Client → Packagist.** The pure-PHP client (`cachix/secretspec`) is published
  straight from the monorepo: the Composer manifest is the repository-root
  `/composer.json` (autoload sources `secretspec-php/src/`; `vendor-dir` points
  into `secretspec-php/` so the tooling stays there), which Packagist reads
  directly — no split/mirror repo, no CI, no token. Packagist auto-updates from
  each `vX.Y.Z` tag. No version-sync is needed — Composer takes the version from
  the git tag (like Go), so `sync-sdk-versions.sh` does not touch it. One-time
  setup: see "Packagist (PHP)" above.
- **Extension → GitHub Release (`php-ext.yml`).** The `secretspec-php-native`
  extension (an ext-php-rs cdylib embedding the resolver) is built as a prebuilt
  shared object per PHP minor (8.2–8.4, NTS) × platform, smoke-tested, and
  attached to the release. Users install it by dropping the `.so` in and
  `extension=` / `docker-php-ext-enable`, or by building from source with cargo.
- **ext-ffi fallback library.** For the no-extension path, `ffi-build.yml`
  attaches the per-target `secretspec-ffi` library (with a `.sha256`) to the
  release; the client's `vendor/bin/secretspec-install-lib` command downloads the
  right one on demand. It is a deliberate opt-in command, not a Composer
  post-install hook (a dependency's install scripts do not run in the consumer
  project, and a secrets tool should not silently fetch a binary during
  `composer install`).
- **Gaps (follow-up, unvalidated cross-platform):** the extension matrix is
  Linux + macOS, NTS-only (no ZTS), and links the runner's glibc/system libs
  (same portability caveat as the Ruby/Python jobs — a baseline/manylinux build
  is the fix). A **Windows** extension build is deferred (ext-php-rs on Windows
  needs the PHP SDK dev pack + `rust-lld`; Windows users can use the ext-ffi
  backend, whose cdylib `ffi-build.yml` does build for Windows). A one-command
  PIE install is not wired (PIE builds non-Windows extensions from source via
  phpize, which does not fit a Cargo extension); and the release-asset uploads
  race cargo-dist's release creation, so they wait-then-`--clobber`.

### First PHP release — checklist

Everything through the CI is green, but the live Packagist + release-asset paths
can only be exercised for real once the package is registered and a tag exists.
In order:

1. **Merge to `main`** so the repo-root `composer.json` is on the default branch.
2. **Register on Packagist** — the one-time "Packagist (PHP)" setup above.
3. **Smoke-test off `main` before tagging.** In a scratch project, confirm the
   manifest resolves:

   ```bash
   composer require cachix/secretspec:dev-main
   ```

4. **Cut the `vX.Y.Z` tag.** Packagist ingests the tag as a version, and
   `php-ext.yml` / `ffi-build.yml` attach the extension + cdylib binaries to the
   GitHub Release.
5. **Verify against the live release** (the one path CI cannot cover): in a clean
   project, `composer require cachix/secretspec`, then exercise **both** backends —
   `vendor/bin/secretspec-install-lib` for the ext-ffi path, and a downloaded
   `secretspec-php-native` `.so` (`extension=…`) for the extension path — and
   confirm a resolve works under each.

## .NET (NuGet) — `dotnet-package.yml`

- **Client:** a .NET 8 assembly with no managed package dependencies. It invokes
  the stable JSON C ABI through P/Invoke and exposes the same builder, resolved
  value, report, and typed-error vocabulary as the other SDKs.
- **Native assets:** one NuGet package carries `secretspec-ffi` under the
  standard `runtimes/<rid>/native/` layout for `linux-x64`, `linux-arm64`,
  `osx-arm64`, and `win-x64`. Linux builds use a manylinux 2.28 baseline and
  the resolver's vendored-dbus feature.
- **Publish:** `dotnet-package.yml` tests every native asset on its target,
  assembles `Cachix.SecretSpec.<version>.nupkg`, and pushes it with the
  `NUGET_API_KEY` stored in the `nuget` GitHub environment. One-time setup is
  described above.
