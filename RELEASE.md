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
