---
"rust:monosecret": feat
"rust:monosecret_derive": none
"dart": feat
"dart:monosecret_builder": major
"@monosecret/cli": none
"@monosecret/client": none
"@monosecret/skill": none
"@monosecret/cli-darwin-arm64": none
"@monosecret/cli-darwin-x64": none
"@monosecret/cli-linux-arm64-gnu": none
"@monosecret/cli-linux-arm64-musl": none
"@monosecret/cli-linux-x64-gnu": none
"@monosecret/cli-linux-x64-musl": none
"@monosecret/cli-win32-arm64-msvc": none
"@monosecret/cli-win32-x64-msvc": none
---

Add a secret-value-free manifest command for SDK code generation, introduce a build_runner-based Dart typed SDK generator, reorganize source by ecosystem into `crates/`, `npm/`, and `dart/`, and wire Rust, Dart, and npm coverage reports with package-level Codecov flags.
