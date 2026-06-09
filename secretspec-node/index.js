'use strict';

// Node.js SDK for SecretSpec, a declarative secrets manager.
//
// A thin wrapper over the native napi-rs addon (secretspec.node), which embeds
// the resolver and shares the same JSON envelope contract as every other
// language binding. Resolution (providers, chains, profiles, generation,
// as_path) happens entirely in the Rust core; this layer marshals JSON and
// exposes the builder API. TypeScript declarations ship in index.d.ts.

let native;
try {
  // The prebuilt addon for this platform. napi-rs publishes it per platform;
  // in a source checkout, build it with scripts/build-addon.sh.
  native = require('./secretspec.node');
} catch (err) {
  throw new Error(
    'failed to load the secretspec native addon (secretspec.node); build it ' +
      `with scripts/build-addon.sh. Underlying error: ${err.message}`,
  );
}

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

  /** Export each resolved secret into process.env by its declared name. */
  setAsEnv() {
    for (const [name, secret] of Object.entries(this.secrets)) {
      process.env[name] = secret.get();
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
    const envelope = JSON.parse(native.resolve(JSON.stringify(this._request)));
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
  return native.abiVersion();
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
