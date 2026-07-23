'use strict';

const fs = require('node:fs');

// Node.js SDK for SecretSpec, a declarative secrets manager.
//
// A thin wrapper over the native napi-rs addon (secretspec.node), which embeds
// the resolver and shares the same JSON envelope contract as every other
// language binding. Resolution (providers, chains, profiles, generation,
// as_path) happens entirely in the Rust core; this layer marshals JSON and
// exposes the builder API. TypeScript declarations ship in index.d.ts.

// Maps process.platform-process.arch to the optionalDependency package that
// carries the addon for that platform (see napi.targets in package.json and
// the generated npm/<platform>/ package dirs).
const PLATFORM_PACKAGES = {
  'linux-x64': 'secretspec-linux-x64-gnu',
  'linux-arm64': 'secretspec-linux-arm64-gnu',
  'darwin-arm64': 'secretspec-darwin-arm64',
  'win32-x64': 'secretspec-win32-x64-msvc',
};

function loadNative() {
  try {
    // A source checkout's own build, from scripts/build-addon.sh.
    return require('./secretspec.node');
  } catch (localErr) {
    // Installed from npm: the addon lives in a platform-specific
    // optionalDependency package instead of being bundled here.
    const key = `${process.platform}-${process.arch}`;
    const pkg = PLATFORM_PACKAGES[key];
    if (!pkg) {
      throw new Error(`secretspec: unsupported platform ${key}`);
    }
    try {
      return require(pkg);
    } catch (pkgErr) {
      throw new Error(
        `failed to load the secretspec native addon for ${key} (tried ./secretspec.node ` +
          `and the '${pkg}' package). Underlying error: ${pkgErr.message}`,
      );
    }
  }
}

const native = loadNative();

// Response wire-format version this SDK understands. Tracks secretspec-ffi's
// RESOLVE_SCHEMA_VERSION; a mismatch means the native addon is out of sync.
const RESOLVE_SCHEMA_VERSION = 2;

// Wire-format version of the value-free report. Tracks secretspec's
// RESOLUTION_REPORT_SCHEMA_VERSION.
const REPORT_SCHEMA_VERSION = 1;

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

  /**
   * Export each resolved secret into process.env by its declared name. Secrets
   * with no usable value (e.g. under no_values) are skipped rather than coerced
   * to the string "null".
   */
  setAsEnv() {
    for (const [name, secret] of Object.entries(this.secrets)) {
      const value = secret.get();
      if (value != null) {
        process.env[name] = value;
      }
    }
  }

  /** Flat { SECRET_NAME: value } object (the file path for as_path secrets). */
  fields() {
    const out = {};
    for (const [name, secret] of Object.entries(this.secrets)) {
      out[name] = secret.get();
    }
    return out;
  }

  /**
   * fields() as a JSON string, the input for a quicktype-generated deserializer
   * (e.g. Convert.toSecretSpec). See `secretspec schema`.
   */
  fieldsJson() {
    return JSON.stringify(this.fields());
  }

  /**
   * Remove the temp files backing any as_path secrets in this result. The
   * resolver persists those files (mode 0400) so their paths stay valid after
   * resolve returns; the caller owns their lifetime. Call dispose() when done
   * (or use `using resolved = builder.load()` for automatic disposal) so secret
   * files do not accumulate in the temp dir. A file already gone is not an error.
   */
  dispose() {
    for (const secret of Object.values(this.secrets)) {
      if (secret.asPath && secret.path != null) {
        try {
          fs.unlinkSync(secret.path);
        } catch (err) {
          if (err.code !== 'ENOENT') throw err;
        }
      }
    }
  }

  [Symbol.dispose]() {
    this.dispose();
  }
}

class SecretReport {
  constructor(entry) {
    this.name = entry.name;
    this.status = entry.status;
    this.required = entry.required ?? false;
    this.sourceProvider = entry.source_provider ?? null;
    this.defaultApplied = entry.default_applied ?? false;
    this.generated = entry.generated ?? false;
    this.asPath = entry.as_path ?? false;
  }
}

class Report {
  constructor(response) {
    this.provider = response.provider;
    this.profile = response.profile;
    this.secrets = (response.secrets || []).map((s) => new SecretReport(s));
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
  withNoValues(v = true) { this._request.no_values = v; return this; }

  /**
   * Resolve the secrets. Throws MissingRequiredError if a required secret is
   * missing, and SecretSpecError for any other failure.
   *
   * Synchronous: the native resolve runs on the Node main thread. Prefer
   * loadAsync() when a provider may do network I/O (1Password, LastPass).
   */
  load() {
    return this._parse(native.resolve(JSON.stringify(this._request)));
  }

  /**
   * Like load(), but resolves on the libuv threadpool so a provider doing
   * network I/O does not block the Node event loop. Returns a Promise<Resolved>
   * and rejects with the same error types load() throws.
   */
  async loadAsync() {
    if (typeof native.resolveAsync !== 'function') {
      throw new SecretSpecError(
        'addon',
        'the loaded native addon predates resolveAsync; rebuild it with scripts/build-addon.sh',
      );
    }
    return this._parse(await native.resolveAsync(JSON.stringify(this._request)));
  }

  /**
   * Validate a JSON response envelope string and return its `response` (or
   * throw). `kind` is "resolve" or "report"; it selects the schema version to
   * enforce and labels the version-mismatch message.
   */
  _parseEnvelope(raw, kind, expectedSchemaVersion) {
    const envelope = JSON.parse(raw);
    if (!envelope.ok) {
      const err = envelope.error || {};
      throw new SecretSpecError(err.kind || 'unknown', err.message || '');
    }
    const response = envelope.response;
    if (response == null) {
      throw new SecretSpecError('ffi', 'secretspec_resolve reported ok with no response');
    }
    if (response.schema_version !== expectedSchemaVersion) {
      throw new SecretSpecError(
        'version',
        `unsupported ${kind} schema version ${response.schema_version} (expected ` +
          `${expectedSchemaVersion}); the native addon and this SDK are out of sync`,
      );
    }
    return response;
  }

  /** Parse a JSON response envelope string into a Resolved (or throw). */
  _parse(raw) {
    const response = this._parseEnvelope(raw, 'resolve', RESOLVE_SCHEMA_VERSION);
    const missing = response.missing_required || [];
    if (missing.length) {
      throw new MissingRequiredError(missing);
    }
    return new Resolved(response);
  }

  /**
   * Resolve a value-free Report (the inventory/preflight view, the same one the
   * CLI exposes as `check --json`). Unlike load(), never throws
   * MissingRequiredError: a missing required secret appears as a SecretReport
   * with status "missing_required". Synchronous; prefer reportAsync() for
   * network-backed providers.
   */
  report() {
    return this._parseReport(
      native.resolve(JSON.stringify({ ...this._request, mode: 'report' })),
    );
  }

  /** Like report(), but resolves on the libuv threadpool. */
  async reportAsync() {
    if (typeof native.resolveAsync !== 'function') {
      throw new SecretSpecError(
        'addon',
        'the loaded native addon predates resolveAsync; rebuild it with scripts/build-addon.sh',
      );
    }
    return this._parseReport(
      await native.resolveAsync(JSON.stringify({ ...this._request, mode: 'report' })),
    );
  }

  /** Parse a JSON report envelope string into a Report (or throw). */
  _parseReport(raw) {
    return new Report(this._parseEnvelope(raw, 'report', REPORT_SCHEMA_VERSION));
  }
}

const SecretSpec = {
  builder() {
    return new Builder();
  },
};

function abiVersion() {
  return native.abiVersion();
}

module.exports = {
  SecretSpec,
  Builder,
  Resolved,
  ResolvedSecret,
  Report,
  SecretReport,
  SecretSpecError,
  MissingRequiredError,
  abiVersion,
};
