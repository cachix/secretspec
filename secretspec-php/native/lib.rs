//! ext-php-rs extension for the PHP SDK.
//!
//! A thin wrapper over [`secretspec::resolve_json`], the same JSON-in/JSON-out
//! boundary the C ABI uses, so this binding shares one envelope contract with
//! every other language. The pure-PHP layer (`src/*.php`) marshals the
//! request/response and exposes the builder API; it prefers this extension when
//! it is loaded and falls back to `ext-ffi` dlopening the cdylib otherwise.
//!
//! Building a native PHP extension (rather than dlopening the cdylib via
//! `ext-ffi`) means the resolver is embedded in a normal PHP extension: it needs
//! no `ffi.enable`, and it works in FPM/web the same way `ext-redis` or
//! `ext-pdo` do — the deployment model Laravel and Symfony users already manage.

use ext_php_rs::prelude::*;

/// Resolve secrets from a JSON request string, returning the JSON response
/// envelope (`{"ok": true, "response": ...}` or `{"ok": false, "error": ...}`).
///
/// Exposed to PHP as the global function `secretspec_native_resolve()`.
#[php_function]
pub fn secretspec_native_resolve(request_json: String) -> String {
    secretspec::resolve_json(&request_json)
}

/// The extension's version (tracks the crate version). Exposed to PHP as
/// `secretspec_native_abi_version()`.
#[php_function]
pub fn secretspec_native_abi_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

#[php_module]
pub fn get_module(module: ModuleBuilder) -> ModuleBuilder {
    module
}
