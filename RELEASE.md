# Releasing the language SDKs

Each SDK is a thin client over the Rust core (the `secretspec-ffi` cdylib, or the
napi-rs addon for Node). A release builds the native artifact per platform and
publishes it through that ecosystem's registry, so users install with no native
build. The per-platform build workflows are drafted under `.github/workflows/`;
they have **not been run end to end** and need a CI iteration plus the secrets
below.

Version tags are `vX.Y.Z`; the publish jobs trigger on them.

## Python (PyPI) — `python-wheels.yml`

- **Build:** Linux wheels are built inside a `manylinux_2_28` container (old
  glibc) and repaired with `auditwheel`, which vendors the cdylib's system
  dependencies (notably `libdbus`, pulled in by the keyring provider) and retags
  to `manylinux`. macOS/Windows build natively. The wheel is `py3-none-<platform>`
  and bundles the cdylib in `secretspec/_lib/`.
- **Publish:** `pypa/gh-action-pypi-publish` via **PyPI Trusted Publishing**
  (OIDC). Configure a trusted publisher for this repo + a `pypi` environment; no
  token needed.

## Ruby (RubyGems) — `ruby-gems.yml`

- **Build:** a platform gem (`Gem::Platform::CURRENT`) bundling the cdylib in
  `vendor/`.
- **Publish:** `gem push` for each platform gem.
- **Secret:** `RUBYGEMS_API_KEY` (or configure RubyGems Trusted Publishing).
- **Gap:** the Linux gem currently links the runner's glibc; for a portable gem,
  build the cdylib on an old-glibc baseline (e.g. a `manylinux` container, as the
  Python job does, or `rake-compiler-dock`) and bundle that. Tracked follow-up.

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

## Node.js (npm) — `node-addon.yml`

- **Build:** `node-addon.yml` builds the napi-rs addon (`secretspec.node`) per
  platform and uploads it as an artifact.
- **Publish gap:** multi-platform npm distribution uses per-platform optional
  packages (`@secretspec/<os>-<arch>`) that the main package `optionalDependencies`
  and loads at runtime. This is the pattern `@napi-rs/cli` automates. Adopting
  the `@napi-rs/cli` project layout (so `napi build` / `napi prepublish` emit and
  publish those packages) is the remaining follow-up; the current addon build is
  what such a setup would publish.
- **Secret:** `NPM_TOKEN`.
