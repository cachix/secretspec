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

## Go (git-LFS) — `go-embed.yml`

Go has no binary registry, so the per-platform cdylibs are committed into the
module and embedded via `go:embed` (behind the `embed_lib` build tag).

- **Build:** `go-embed.yml` builds the per-platform libs and uploads them as
  artifacts.
- **Release (manual):** stage all platforms' libs into `secretspec-go/lib/`
  (from the CI artifacts), un-ignore them, `git lfs track` is already set via
  `secretspec-go/.gitattributes`, commit them with LFS, and flip embedding on by
  default (drop the `embed_lib` gate or document `-tags embed_lib`). The libs are
  ~34 MB each, so plain git is unsuitable; **git-LFS must be enabled** for the
  repo.

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
