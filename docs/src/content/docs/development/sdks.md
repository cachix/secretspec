---
title: SDK Development
description: How the language SDKs are built, packaged, and released, and which platforms each one supports
---

SecretSpec ships SDKs for Rust, Python, Go, Ruby, Node.js/TypeScript, Haskell,
PHP, and C#. This page is for contributors: how the SDKs are put together, how
each one is packaged and released, which platforms each artifact covers, and
what to update when adding a platform or a new SDK. For the user-facing
architecture and API, see the [SDK overview](/sdk/overview).

## One resolver, many packages

All resolution logic lives in the `secretspec` Rust crate. The SDKs reach it
two ways:

- **Through the C ABI** (`secretspec-ffi`, which builds a `cdylib` for dynamic
  loading and a `staticlib` for embedding): Ruby (mkmf extension statically
  links the archive), Go (purego `dlopen` of the cdylib, or cgo against the
  archive with `-tags static`), Haskell (GHC FFI against the archive), C#
  (P/Invoke against per-runtime cdylibs in the NuGet package), and PHP's
  `ext-ffi` fallback (runtime `dlopen` of the cdylib).
- **As an embedded extension**: Python ([pyo3](https://pyo3.rs/)), Node.js
  ([napi-rs](https://napi.rs/)), and PHP's preferred backend
  ([ext-php-rs](https://github.com/davidcole1340/ext-php-rs)) compile the
  resolver directly into a language-native extension module.

Every SDK exchanges the same JSON request/response with the core, and the
cross-language conformance suite (`conformance/`, run by
`.github/workflows/sdks.yml` on every PR) asserts they all reduce the same
inputs to the same result.

Package versions for the non-Rust SDKs are not hand-edited: release workflows
run `scripts/sync-sdk-versions.sh`, which stamps the Cargo workspace version
into every package manifest.

## Packaging workflows

Each SDK has a dedicated distribution workflow that builds artifacts per
platform and publishes on a version tag:

| SDK | Package | Workflow |
| --- | --- | --- |
| Rust | `secretspec` on crates.io (source) | `publish.yml` |
| Python | `secretspec` wheels on PyPI | `python-wheels.yml` |
| Node.js | `secretspec` + per-platform packages on npm | `node-addon.yml` |
| Go | Go module (source) + `secretspec-ffi` release assets | `go-embed.yml`, `go-static.yml`, `ffi-build.yml` |
| Ruby | `secretspec` platform gems on RubyGems | `ruby-gems.yml` |
| C# | `Cachix.SecretSpec` on NuGet | `dotnet-package.yml` |
| PHP | Composer package (source) + prebuilt extension binaries and `secretspec-ffi` release assets | `php-ext.yml`, `ffi-build.yml` |
| Haskell | `secretspec` on Hackage (source) | `haskell-build.yml` |

## Platform support

Platforms each released artifact covers. Windows support for the Python wheel,
the Ruby gem, and the PHP extension binaries targets SecretSpec 0.17 and is not
available in the current release.

| SDK | Linux x64 | Linux arm64 | macOS Intel | macOS Apple silicon | Windows x64 | Windows arm64 |
| --- | --- | --- | --- | --- | --- | --- |
| Rust (source crate) | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| Python | ✓ | ✓ | — | ✓ | ✓ (0.17+) | — |
| Node.js | ✓ | ✓ | — | ✓ | ✓ | — |
| Go | ✓ | ✓ | — | ✓ | ✓ | — |
| Ruby | ✓ | ✓ | — | ✓ | ✓ (0.17+) | — |
| C# | ✓ (glibc and musl) | ✓ (glibc and musl) | ✓ | ✓ | ✓ | ✓ |
| PHP | ✓ | ✓ | — | ✓ | ✓ (0.17+) | — |
| Haskell (source) | ✓ (CI-covered) | — | — | — | ✓ (CI-covered, 0.17+) | — |

Notes:

- Most Linux binary artifacts build inside manylinux_2_28 containers so they
  run on any distro with glibc >= 2.28 (the Ruby Linux gem still links the
  build runner's glibc; a baseline toolchain there is a tracked follow-up).
  On Linux the keyring provider's libdbus is either compiled in
  (`vendored-dbus`) or required at runtime, per artifact — each workflow's
  header comment states which.
- Hackage distributes source only; the Haskell column records which platforms
  CI builds and tests, since users link `secretspec-ffi` themselves.
- The fully-static Go binary (`-tags static`, musl) is Linux x64 only.

## Windows toolchains

Windows artifacts split across two Rust targets, and the split is load-bearing:

- **MSVC (`x86_64-pc-windows-msvc`)** for artifacts loaded by MSVC-built
  hosts: the CLI, the FFI cdylib, the Python wheel, the Node addon, the NuGet
  natives, and the PHP extension. PHP is the special case: PHP's Windows ABI
  uses the vectorcall calling convention, which stable Rust does not expose,
  so `php-ext.yml` builds that one artifact on nightly Rust (the same setup
  ext-php-rs's own CI uses). ext-php-rs downloads the PHP development pack
  matching the installed `php.exe` during the build.
- **MinGW (`x86_64-pc-windows-gnu`, declared in `rust-toolchain.toml`)** for
  artifacts linked by MinGW toolchains, which cannot consume MSVC `.lib`
  archives: the staticlib bundled in the Ruby gem (RubyInstaller's devkit) and
  the one the Haskell CI job links (GHC's bundled toolchain). Building it
  needs a MinGW C compiler for the archive's C dependencies (aws-lc-sys,
  SQLite, zstd) and NASM for aws-lc's assembly.

A `staticlib` does not carry its native link-time dependencies; consumers
capture them from `cargo rustc ... -- --print native-static-libs`. On
`windows-gnu` that list names import libraries that ship inside cargo registry
crates (`libwindows.*.a` from `windows_x86_64_gnu`, `libwinapi_*.a` from
`winapi-x86_64-pc-windows-gnu`) and exist in no MinGW distribution.
`scripts/copy-mingw-import-libs.sh` stages exactly the referenced ones next to
the archive — the Ruby gem bundles them in `vendor/`, the Haskell job points
GHC's linker at them.

## Adding a platform to an SDK

1. Add the platform to the SDK's distribution workflow matrix, and make the
   publish job consume the new artifact.
2. Build natively on a runner of that platform where possible; the workflows
   deliberately avoid cross-compiling because the crate links system
   libraries.
3. Keep the artifact self-contained: vendor or statically link anything an end
   user's machine will not have (see the manylinux/dbus and MinGW import
   library notes above).
4. Smoke test in the same workflow: install or load the built artifact and
   call one function through it.
5. Update the platform table above, the [SDK overview](/sdk/overview) platform
   section, and label the platform with its target release (for example
   `(0.17+)`) until that release ships.
6. Add a user-facing CHANGELOG entry.

## Adding a new SDK

1. Create the binding crate/package as a workspace sibling
   (`secretspec-<lang>/`), thin: marshal the JSON envelope, expose the
   builder/resolve API mirroring the existing SDKs' vocabulary.
2. Wire the package manifest into `scripts/sync-sdk-versions.sh` so its
   version tracks the workspace.
3. Add the SDK to the conformance suite and to `.github/workflows/sdks.yml`.
4. Create a distribution workflow following an existing one
   (`ruby-gems.yml` and `python-wheels.yml` are the smallest), including
   publish-on-tag with trusted publishing where the registry supports it.
5. Document it: `docs/src/content/docs/sdk/<lang>.md`, the sidebar in
   `docs/astro.config.ts`, the [SDK overview](/sdk/overview), and the platform
   tables on this page and the overview.
6. Follow the same release-visibility rules as providers: label everything
   with the target version until the release ships (see
   [Adding Providers](/development/adding-providers)).
