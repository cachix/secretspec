---
title: SDK Development
description: How the language SDKs are built, packaged, and released, and which platforms each one supports
---

Monosecret ships SDKs for Rust, Python, Go, Ruby, Node.js/TypeScript, Haskell,
PHP, C#, and Swift (0.2+). This page is for contributors: how the SDKs are put
together, how each one is packaged and released, which platforms each artifact
covers, and what to update when adding a platform or a new SDK. For the
user-facing architecture and API, see the [SDK overview](/sdk/overview).

## One resolver, many packages

All resolution logic lives in the `monosecret` Rust crate. The SDKs reach it
two ways:

- **Through the C ABI** (`monosecret_ffi`, which builds a `cdylib` for dynamic
  loading and a `staticlib` for embedding): Ruby (mkmf extension statically
  links the archive), Go (purego `dlopen` of the cdylib, or cgo against the
  archive with `-tags static`), Haskell (GHC FFI against the archive), C#
  (P/Invoke against per-runtime cdylibs in the NuGet package), Swift (0.2+;
  Clang C import from an XCFramework), and PHP's `ext-ffi` fallback (runtime
  `dlopen` of the cdylib).
- **As an embedded extension**: Python ([pyo3](https://pyo3.rs/)), Node.js
  ([napi-rs](https://napi.rs/)), and PHP's preferred backend
  ([ext-php-rs](https://github.com/davidcole1340/ext-php-rs)) compile the
  resolver directly into a language-native extension module.

Every SDK exchanges the same JSON request/response with the core, and the
cross-language conformance suite (`conformance/`, run by
`.github/workflows/sdks.yml` on every PR) asserts they all reduce the same
inputs to the same result.

Package versions for the new C# and Swift SDKs are tracked as versioned files
in `monochange.toml`, alongside the existing SDK manifests.

## Packaging workflows

Established SDKs use the distribution workflows below. PHP, C#, and Swift
currently have local package-readiness checks only; their registry and native
artifact publication is deferred until Monosecret 0.2+.

| SDK                  | Package                                              | Workflow                                         |
| -------------------- | ---------------------------------------------------- | ------------------------------------------------ |
| Rust                 | `monosecret` on crates.io (source)                   | `publish.yml`                                    |
| Python               | `monosecret` wheels on PyPI                          | `python-wheels.yml`                              |
| Node.js              | `monosecret` + per-platform packages on npm          | `node-addon.yml`                                 |
| Go                   | Go module (source) + `monosecret_ffi` release assets | `go-embed.yml`, `go-static.yml`, `ffi-build.yml` |
| Ruby                 | `monosecret` platform gems on RubyGems               | `ruby-gems.yml`                                  |
| C# (planned 0.2+)    | `Monosecret` on NuGet                                | Deferred; local `dotnet pack` readiness check    |
| Swift (planned 0.2+) | SwiftPM source package + XCFramework release asset   | Deferred; local manifest/XCFramework tests       |
| PHP (planned 0.2+)   | Composer package + native backends                   | Deferred; local Composer and extension tests     |
| Haskell              | `monosecret` on Hackage (source)                     | `haskell-build.yml`                              |

## Platform support

Platforms each released artifact covers. Windows support for the Python wheel,
the Ruby gem, and the PHP extension binaries is added in Monosecret 0.2.

| SDK                 | Linux x64          | Linux arm64        | macOS Intel | macOS Apple silicon | Windows x64          | Windows arm64 |
| ------------------- | ------------------ | ------------------ | ----------- | ------------------- | -------------------- | ------------- |
| Rust (source crate) | ✓                  | ✓                  | ✓           | ✓                   | ✓                    | ✓             |
| Python              | ✓                  | ✓                  | —           | ✓                   | ✓ (0.2+)             | —             |
| Node.js             | ✓                  | ✓                  | —           | ✓                   | ✓                    | —             |
| Go                  | ✓                  | ✓                  | —           | ✓                   | ✓                    | —             |
| Ruby                | ✓                  | ✓                  | —           | ✓                   | ✓ (0.2+)             | —             |
| C#                  | ✓ (glibc and musl) | ✓ (glibc and musl) | ✓           | ✓                   | ✓                    | ✓             |
| Swift (0.2+)        | —                  | —                  | ✓           | ✓                   | —                    | —             |
| PHP                 | ✓                  | ✓                  | —           | ✓                   | ✓ (0.2+)             | —             |
| Haskell (source)    | ✓ (CI-covered)     | —                  | —           | —                   | ✓ (CI-covered, 0.2+) | —             |

Notes:

- Most Linux binary artifacts build inside manylinux_2_28 containers so they
  run on any distro with glibc >= 2.28 (the Ruby Linux gem still links the
  build runner's glibc; a baseline toolchain there is a tracked follow-up).
  The keyring provider uses a Rust-native D-Bus transport on Linux and does not
  require system libdbus.
- Hackage distributes source only; the Haskell column records which platforms
  CI builds and tests, since users link `monosecret_ffi` themselves.
- The Swift package targets macOS 12+ only. Its XCFramework contains native
  Intel and Apple-silicon slices; mobile Apple platforms are intentionally out
  of scope for a development-workflow resolver that launches provider CLIs and
  reads desktop files and credential stores.
- The fully-static Go binary (`-tags static`, musl) is Linux x64 only.

## Why Swift uses the C ABI

Swift interoperates with C directly through Clang modules, and SwiftPM
distributes native Apple binaries as XCFramework binary targets. That fits the
existing `monosecret_ffi` boundary exactly: three ownership-audited C functions
carry one already-versioned JSON contract.

[UniFFI](https://mozilla.github.io/uniffi-rs/latest/) is a good default for a
new object-rich Rust API that needs generated Swift and Kotlin bindings. It
would be the wrong layer here: Monosecret already has a deliberately narrow ABI
shared by several SDKs, and introducing UniFFI would create a second exported
ABI, generated Rust scaffolding, and another schema to version. The hand-written
Swift layer is limited to `Codable` request/response models and idiomatic errors;
resolution remains entirely in Rust.

`swift/monosecret_swift/scripts/stage-local-xcframework.sh` stages the current
`libmonosecret_ffi.dylib`, C header, and module map as a local XCFramework for
Swift tests. A future 0.2+ release workflow must build both macOS architectures,
archive the XCFramework, and replace the all-zero checksum in `Package.swift`
before publication.

## Windows toolchains

Windows artifacts split across two Rust targets, and the split is load-bearing:

- **MSVC (`x86_64-pc-windows-msvc`)** for artifacts loaded by MSVC-built
  hosts: the CLI, the FFI cdylib, the Python wheel, the Node addon, the NuGet
  natives, and the PHP extension. PHP is the special case: PHP's Windows ABI
  uses the vectorcall calling convention, which stable Rust does not expose,
  so future Windows extension packaging must use nightly Rust (the same setup
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

## Linking through pkg-config (0.2+)

`monosecret_ffi/scripts/cinstall.sh PREFIX static|shared` uses
[cargo-c](https://github.com/lu-zero/cargo-c) to install one library type, the
header, and a `monosecret_ffi.pc` carrying its full link line. This lets
pkg-config consumers skip the `native-static-libs` capture above. Use separate
prefixes for the two modes: both metadata files use `-lmonosecret_ffi`, and the
linker prefers a shared library when both forms are present.

## Adding a platform to an SDK

1. Add the platform to the SDK's distribution workflow matrix, and make the
   publish job consume the new artifact.
2. Build natively on a runner of that platform where possible; the workflows
   deliberately avoid cross-compiling because the crate links system
   libraries.
3. Keep the artifact self-contained: vendor or statically link anything an end
   user's machine will not have (see the manylinux and MinGW import library
   notes above).
4. Smoke test in the same workflow: install or load the built artifact and
   call one function through it.
5. Update the platform table above, the [SDK overview](/sdk/overview) platform
   section, and label the platform with its target release (for example
   `(0.2+)`) until that release ships.
6. Add a user-facing CHANGELOG entry.

## Adding a new SDK

1. Create the binding crate/package as a workspace sibling
   (`monosecret-<lang>/`), thin: marshal the JSON envelope, expose the
   builder/resolve API mirroring the existing SDKs' vocabulary.
2. Register the package manifest in `monochange.toml` so its version tracks
   the workspace.
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
