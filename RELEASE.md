# Releasing the language SDKs

Each SDK is a thin client over the Rust core (the `libsecretspec` C ABI, a
pyo3 extension for Python, or the napi-rs addon for Node). A release builds the
native artifact per platform and publishes it through that ecosystem's
registry or as a checksummed SwiftPM binary, so users install with no native
build.

Version tags are `vX.Y.Z`; the publish jobs trigger on them. After the Go
release build succeeds, CI also creates the submodule tag
`secretspec-go/vX.Y.Z`, which is the version the Go module proxy resolves.

## SecretSpec 0.20 native-library rename

SecretSpec 0.20 renames the embedded native library from `secretspec-ffi` /
`secretspec_ffi` to `libsecretspec` without renaming its exported C symbols.
Before tagging 0.20:

1. Run the SDK workflow and every platform packaging workflow from the release
   commit, including the Windows native assets.
2. Verify Go purego, .NET, and PHP FFI discover the pre-0.20 shared-library
   filenames for legacy operations. Static-link SDKs must use the matching 0.20
   archive because their source references the new `secretspec_call` symbol.
3. Verify newly packaged artifacts contain only the new public filename and
   that `SECRETSPEC_FFI_LIB` can explicitly select either compatible library.
4. Test one clean install per SDK without a source checkout or Cargo `target/`
   directory present, so development fallback discovery cannot hide a missing
   packaged asset.
5. Keep `libsecretspec` and each SDK at the same release version. Filename
   fallback preserves loading, not newer request fields or behavior in an old
   library.

The detailed compatibility matrix is maintained in
[`libsecretspec/README.md`](libsecretspec/README.md).

## After every release

Once the release artifacts are available, update the `secretspec` package in
Nixpkgs. From a Nixpkgs checkout, let `nix-update` update the crate source and
Cargo dependency hashes and verify that the package builds:

```bash
nix-update --version=X.Y.Z --build secretspec
```

Commit the generated package change as `secretspec: OLD -> X.Y.Z`, include the
GitHub release URL in the commit body, and submit it to Nixpkgs.

## One-time registry setup

External registry status was last verified on 2026-08-31. Recheck every item
still marked pending before tagging a release.

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

### PyPI — trusted publishing active, done

The `pypi` GitHub Environment and PyPI Trusted Publisher are active for project
`secretspec` (owner `cachix`, repo `secretspec`, workflow
`python-wheels.yml`, environment `pypi`). OIDC-authenticated releases have
published through 0.19.1; no token or additional setup is needed.

### RubyGems — trusted publishing active, done

The RubyGems Trusted Publisher is active for gem `secretspec` (repository owner
`cachix`, repository name `secretspec`, workflow filename `ruby-gems.yml`,
environment `release`). OIDC-authenticated releases have published through
0.19.1; no token or additional setup is needed.

### npm — trusted publishing active, done

npm has no pending-publisher mechanism, so this needed a manual first publish
for the main `secretspec` package **and every platform sub-package**
(`secretspec-linux-x64-gnu`, `secretspec-linux-arm64-gnu`,
`secretspec-linux-x64-musl`, `secretspec-linux-arm64-musl`,
`secretspec-darwin-arm64`, `secretspec-win32-x64-msvc`) — 7 packages that each
had to exist before a Trusted Publisher could be attached. This has been done:
all 7 packages are published (bootstrap-published once with a temporary
granular access token, "All Packages" / "Read and write" scope — narrower
"select packages" scopes 404 on brand-new package names, since that picker
can't reference a package that doesn't exist yet), each has a Trusted
Publisher configured (GitHub Actions, repo `cachix/secretspec`, workflow
`node-addon.yml`, no environment). Revoke every temporary bootstrap token
immediately after setup; release automation does not use or store one. Every
release from here publishes via OIDC. `napi pre-publish` skips a platform
package version that is already present, so the manually bootstrapped 0.20
musl packages do not make the tag workflow fail.

### Hackage — token set, done

Hackage doesn't support OIDC yet (tracked upstream:
[haskell/hackage-server#1443](https://github.com/haskell/hackage-server/issues/1443),
open as of this writing), so this stays a long-lived token rather than a
one-time setup step. The `HACKAGE_TOKEN` repo secret is set. Nothing left to
do — each `vX.Y.Z` tag's `haskell-build.yml` publish job uploads with it.

### Go — nothing to set up

No registry involved. `go get` reads the `secretspec-go/vX.Y.Z` submodule tag
directly from git. `go-embed.yml` creates that tag after its full platform
matrix succeeds and attaches the per-platform cdylibs to the GitHub Release for
the optional self-contained build.

### Packagist (PHP) — configured, done

Packagist has no OIDC/Trusted-Publishing mechanism; it reads a git repo and its
root `composer.json` directly. This repo publishes the PHP package straight from
the monorepo — the manifest lives at the repository root (`/composer.json`, with
`vendor-dir` pointed into `secretspec-php/` and autoload sourcing
`secretspec-php/src/`), so no split/mirror repo is needed.

The [`cachix/secretspec`](https://packagist.org/packages/cachix/secretspec)
package and its GitHub auto-update integration are active; Packagist has
ingested releases through 0.19.1. No split/mirror repository, CI workflow, or
token is needed. Packagist pulls each `vX.Y.Z` tag automatically.

For recovery after a missed update, ask Packagist to refresh the package or
reconnect its GitHub hook.

### NuGet (.NET) — trusted publishing set up, done

`Cachix.SecretSpec` publishes via NuGet Trusted Publishing (OIDC), so no
long-lived API key is stored. The nuget.org policy is configured (repository
owner `cachix`, repository `secretspec`, workflow file `dotnet-package.yml`,
environment `nuget`), and the repository's `nuget` GitHub environment holds
`NUGET_USER` — the nuget.org profile name that owns the policy. The first
publish (0.15.0, a manual `dotnet-package.yml` run with `publish: true`)
claimed the package ID and permanently activated the policy. It is an
unsupported bootstrap artifact rather than the C# SDK release; the first
supported package is 0.16.0, whose publish job also unlists 0.15.0. Nothing
else is needed — version tags build all native runtime assets, pack them into
one `.nupkg`, run clean-package and NativeAOT consumers on every RID, and
publish with a short-lived OIDC-issued API key (`--skip-duplicate` makes
re-runs of an already-published version harmless).

### SwiftPM (0.18+) — no registry setup

The root `Package.swift` makes this repository a Swift package and downloads
`CSecretSpec.xcframework.zip` from the matching GitHub Release. SwiftPM requires
that remote binary's SHA-256 checksum to already be present in `Package.swift`,
so Swift has one required release-preparation step after the workspace version
is bumped and before the version tag is created:

1. Run `swift-package.yml` on the release branch with `publish: false`.
2. Download its `swift-xcframework` artifact and run:

   ```bash
   swift package compute-checksum CSecretSpec.xcframework.zip
   ```

3. Replace `secretSpecBinaryChecksum` in `/Package.swift` with that value,
   commit it, and rerun the workflow.
4. Create the version tag only after the rerun passes. The tag workflow rebuilds
   the deterministic archive, refuses to publish if its checksum differs, and
   attaches the ZIP to the existing GitHub Release.

`scripts/sync-sdk-versions.sh` updates the version in the XCFramework URL but
intentionally leaves the checksum alone, making a missing checksum refresh
visible during release review. There is no Swift registry credential or
separate repository.

### Maven Central (JVM, 0.20+) — setup pending

The JVM workflow builds and tests the multi-platform JAR on version tags, but
does not publish it automatically yet. Before the first Maven Central release:

1. Register and verify the `org.cachix` namespace with Maven Central.
2. Create a GPG signing key and add `MAVEN_CENTRAL_SIGNING_KEY` and
   `MAVEN_CENTRAL_SIGNING_PASSPHRASE` as GitHub Actions secrets.
3. Create a Maven Central publisher token and add
   `MAVEN_CENTRAL_TOKEN_USERNAME` and `MAVEN_CENTRAL_TOKEN_PASSWORD` as GitHub
   Actions secrets.
4. Manually dispatch `jvm-package.yml` from the release tag with
   `publish: true`. Do not enable tag-triggered publication until this path has
   successfully published and a clean consumer resolves the package from Maven
   Central.

### WinGet — bootstrap merged; token access must be confirmed

[`winget-releaser`](https://github.com/vedantmgoyal9/winget-releaser)
requires one package version in the WinGet Community Repository before it can
derive future manifests. The manual `Cachix.SecretSpec` 0.18.0 bootstrap was
merged in
[microsoft/winget-pkgs#413776](https://github.com/microsoft/winget-pkgs/pull/413776)
on 2026-08-18.

Before relying on automatic publication, confirm that this repository can
access a `WINGET_TOKEN` secret. No repository-level secret was visible when
this status was last verified; an organization-level secret could not be
verified. If it is not already available, create a classic GitHub personal
access token for `domenkozar` with only the `public_repo` scope and store it as
`WINGET_TOKEN`. The action does not support fine-grained tokens and uses the
`domenkozar/winget-pkgs` fork created for the bootstrap submission.

After this one-time setup, `winget.yml` runs after each successful stable
`Release` workflow and submits the matching
`secretspec-x86_64-pc-windows-msvc.zip`. Manual dispatch accepts an existing
published release tag for recovery or retry. Prerelease tags are skipped.

## Python (PyPI) — `python-wheels.yml`

- **Build:** the Rust resolver is statically linked into a pyo3 extension
  (`secretspec._native`, built from the `secretspec-py-native` crate via
  maturin) — there is no separate cdylib bundled. The extension targets
  pyo3's `abi3-py39` feature, so one `cp39-abi3-<platform>` wheel per platform
  serves all CPython >= 3.9. Linux wheels are built via `PyO3/maturin-action`
  inside a `manylinux_2_28` container (old glibc); maturin repairs the wheel,
  so no separate `auditwheel` step is needed. macOS builds natively; a Windows
  wheel is a follow-up.
- **Publish:** `pypa/gh-action-pypi-publish` via **PyPI Trusted Publishing**
  (OIDC); no token needed. One-time setup is complete; see "One-time registry
  setup" above.

## Ruby (RubyGems) — `ruby-gems.yml`

- **Build:** a platform gem (`Gem::Platform::CURRENT`) bundling the
  `libsecretspec` staticlib in `vendor/`. At `gem install`, mkmf compiles a tiny
  C glue and statically links that archive, so the resolver is embedded in the
  extension and one platform gem serves every Ruby ABI (install needs a C
  compiler and Ruby headers).
- **Publish:** `gem push` for each platform gem, authenticated via **RubyGems
  Trusted Publishing** (OIDC) through `rubygems/configure-rubygems-credentials`
  — no token stored in CI. One-time setup is complete; see "One-time registry
  setup" above.
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
installed/built `libsecretspec`, or build with `-tags embed_lib` after
staging the per-platform library into `secretspec-go/lib/` themselves (a
self-contained, vendored build — not a module-proxy install).

- **Build:** `go-embed.yml` builds the per-platform libs, uploads them as
  artifacts, and smoke-tests an `-tags embed_lib` build with a staged lib.
- **Release:** nothing is pushed to a registry. On a `vX.Y.Z` release,
  `go-embed.yml` attaches the per-platform cdylibs to the GitHub Release and
  creates `secretspec-go/vX.Y.Z` at the same commit for `go get`.
  `go-static.yml` attaches its musl static SDK bundle separately. Do **not**
  commit binaries to the repo (plain git or LFS).

> The loader rejects an embedded git-LFS pointer with a clear error, so a botched
> LFS-based build fails loudly instead of feeding pointer text to `dlopen`.

## Haskell (Hackage) — `haskell-build.yml`

- **Build:** statically links the `libsecretspec` archive at build time via
  the GHC FFI, so the Rust resolver is embedded in the binary with no runtime
  loader path.
- **Publish:** `cabal upload --publish` with the `HACKAGE_TOKEN` secret — see
  "One-time registry setup" above. Hackage has no Trusted Publishing yet
  ([haskell/hackage-server#1443](https://github.com/haskell/hackage-server/issues/1443)),
  so this stays a long-lived token.
- **Note:** Hackage's own build bots cannot compile this package (it statically
  links a Rust archive Hackage doesn't build); the upload still succeeds, it
  just won't show as "buildable" in Hackage's UI. The README documents the
  link requirement for anyone installing from source.

## Swift (0.18+, SwiftPM + XCFramework) — `swift-package.yml`

- **Build:** native Intel and Apple-silicon macOS runners build the
  `libsecretspec` cdylib with a macOS 12 deployment target.
  `scripts/build-swift-xcframework.sh` gives each dylib an `@rpath` install
  name, combines the slices into a universal dylib, adds the public header and
  Clang module map, and wraps it with `xcodebuild -create-xcframework`.
- **Test:** the Swift package selects the local XCFramework when staged under
  `secretspec-swift/Artifacts/`; its unit and cross-language conformance tests
  run against the final two-architecture artifact.
- **Publish:** the workflow normalizes archive metadata, verifies the
  precommitted SwiftPM checksum, and attaches
  `CSecretSpec.xcframework.zip` to the version's GitHub Release. Follow the
  pre-tag checksum procedure above.
- **Platforms:** macOS 12+ on Intel and Apple silicon. Mobile Apple platforms
  are intentionally unsupported because SecretSpec's development-workflow
  providers rely on desktop files, processes, CLIs, and credential stores.

## Node.js (npm) — `node-addon.yml`

- **Build:** `node-addon.yml` builds the napi-rs addon (`secretspec.node`) per
  platform via `@napi-rs/cli` (`scripts/build-addon.sh` wraps `napi build`) and
  runs the SDK tests against it.
- **Publish:** multi-platform npm distribution uses per-platform optional
  packages (`secretspec-<platform>`, e.g. `secretspec-linux-x64-gnu`) that the
  main `secretspec` package references via `optionalDependencies` and loads at
  runtime — the layout `@napi-rs/cli` automates (`napi create-npm-dirs` /
  `napi pre-publish`). Authenticated via **npm Trusted Publishing** (OIDC); no
  token stored in CI. `napi.targets` in `secretspec-node/package.json` is the
  source of truth for the platform list; `napi pre-publish` derives
  `optionalDependencies` from it at publish time.
- **One-time setup:** done for the four glibc, macOS, and Windows packages. The
  two musl packages added in 0.20 still need it — see "One-time registry
  setup" above.

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
  attaches the per-target `libsecretspec` library (with a `.sha256`) to the
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

### PHP release verification

The first-release Packagist registration is complete. For each release:

1. **Smoke-test off the release commit before tagging.** In a scratch project,
   confirm the manifest resolves:

   ```bash
   composer require cachix/secretspec:dev-main
   ```

2. **Cut the `vX.Y.Z` tag.** Packagist ingests the tag as a version, and
   `php-ext.yml` / `ffi-build.yml` attach the extension + cdylib binaries to the
   GitHub Release.
3. **Verify against the live release** (the one path CI cannot cover): in a clean
   project, `composer require cachix/secretspec`, then exercise **both** backends —
   `vendor/bin/secretspec-install-lib` for the ext-ffi path, and a downloaded
   `secretspec-php-native` `.so` (`extension=…`) for the extension path — and
   confirm a resolve works under each.

## .NET (NuGet) — `dotnet-package.yml`

- **Client:** a trimming-safe, NativeAOT-compatible .NET 8 assembly with no
  managed package dependencies. It invokes the stable JSON C ABI through
  source-generated P/Invoke and exposes the same builder, resolved value,
  report, and typed-error vocabulary as the other SDKs.
- **Native assets:** one NuGet package carries `libsecretspec` under the
  standard `runtimes/<rid>/native/` layout for glibc and musl Linux x64/Arm64,
  macOS x64/Arm64, and Windows x64/Arm64. Glibc builds use a manylinux 2.28
  baseline, and Windows builds statically link the MSVC runtime.
- **Publish:** `dotnet-package.yml` tests every native asset on its target,
  assembles `Cachix.SecretSpec.<version>.nupkg`, then installs that exact
  package in isolated framework-dependent and NativeAOT consumers on all eight
  RIDs before pushing it with a short-lived API key from NuGet Trusted
  Publishing (OIDC), running in the `nuget` GitHub environment. One-time setup
  is described above.
