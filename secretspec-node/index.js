'use strict';

// Node.js SDK for SecretSpec, a declarative secrets manager.
//
// A thin client over the secretspec-ffi C ABI, loaded at runtime via koffi
// (dlopen). Resolution happens entirely in the Rust core, so the SDK inherits
// every provider with no JS-side logic. Mirrors the Rust derive crate's
// vocabulary.

const fs = require('fs');
const path = require('path');
const koffi = require('koffi');

class SecretSpecError extends Error {
  constructor(kind, message) {
    super(`${message} (kind: ${kind})`);
    this.name = 'SecretSpecError';
    this.kind = kind;
  }
}

class MissingRequiredError extends SecretSpecError {
  constructor(missing) {
    super('missing_required', `missing required secret(s): ${missing.join(', ')}`);
    this.name = 'MissingRequiredError';
    this.missing = missing;
  }
}

function libNames() {
  if (process.platform === 'darwin') return ['libsecretspec_ffi.dylib'];
  if (process.platform === 'win32') return ['secretspec_ffi.dll'];
  return ['libsecretspec_ffi.so'];
}

function findLibrary() {
  const override = process.env.SECRETSPEC_FFI_LIB;
  if (override) return override;

  let dir = process.cwd();
  for (;;) {
    for (const profile of ['release', 'debug']) {
      for (const name of libNames()) {
        const candidate = path.join(dir, 'target', profile, name);
        if (fs.existsSync(candidate)) return candidate;
      }
    }
    const parent = path.dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  throw new SecretSpecError(
    'load',
    'could not locate the secretspec-ffi library; set SECRETSPEC_FFI_LIB',
  );
}

let _lib = null;

function lib() {
  if (_lib) return _lib;
  const handle = koffi.load(findLibrary());
  _lib = {
    // void* return so we own the pointer and can free it after decoding.
    resolve: handle.func('void *secretspec_resolve(const char *)'),
    free: handle.func('void secretspec_free(void *)'),
    // const char* return is a static string; koffi decodes it directly.
    abi: handle.func('const char *secretspec_abi_version()'),
  };
  return _lib;
}

function resolveRaw(request) {
  const l = lib();
  const ptr = l.resolve(JSON.stringify(request));
  if (!ptr) {
    throw new SecretSpecError('ffi', 'secretspec_resolve returned null');
  }
  try {
    return koffi.decode(ptr, 'char', -1); // NUL-terminated C string
  } finally {
    l.free(ptr);
  }
}

class ResolvedSecret {
  constructor(entry) {
    this.value = entry.value ?? null;
    this.path = entry.path ?? null;
    this.asPath = entry.as_path ?? false;
    this.source = entry.source;
    this.sourceProvider = entry.source_provider ?? null;
  }

  /** The usable string: the file path for as_path secrets, else the value. */
  get() {
    return this.asPath ? this.path : this.value;
  }
}

class Resolved {
  constructor(response) {
    this.provider = response.provider;
    this.profile = response.profile;
    this.secrets = {};
    for (const [name, entry] of Object.entries(response.secrets || {})) {
      this.secrets[name] = new ResolvedSecret(entry);
    }
    this.missingOptional = response.missing_optional || [];
  }

  /** Export each resolved secret into process.env by its declared name. */
  setAsEnv() {
    for (const [name, secret] of Object.entries(this.secrets)) {
      process.env[name] = secret.get();
    }
  }
}

class Builder {
  constructor() {
    this._request = {};
  }

  withPath(p) { if (p != null) this._request.path = p; return this; }
  withProvider(p) { if (p != null) this._request.provider = p; return this; }
  withProfile(p) { if (p != null) this._request.profile = p; return this; }
  withReason(r) { if (r != null) this._request.reason = r; return this; }

  /**
   * Resolve the secrets. Throws MissingRequiredError if a required secret is
   * missing, and SecretSpecError for any other failure.
   */
  load() {
    const envelope = JSON.parse(resolveRaw(this._request));
    if (!envelope.ok) {
      const err = envelope.error || {};
      throw new SecretSpecError(err.kind || 'unknown', err.message || '');
    }
    const response = envelope.response;
    const missing = response.missing_required || [];
    if (missing.length) {
      throw new MissingRequiredError(missing);
    }
    return new Resolved(response);
  }
}

const SecretSpec = {
  builder() {
    return new Builder();
  },
};

function abiVersion() {
  return lib().abi();
}

module.exports = {
  SecretSpec,
  Builder,
  Resolved,
  ResolvedSecret,
  SecretSpecError,
  MissingRequiredError,
  abiVersion,
};
