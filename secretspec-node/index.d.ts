// Type definitions for the SecretSpec Node.js SDK.

export class SecretSpecError extends Error {
  kind: string;
}

export class MissingRequiredError extends SecretSpecError {
  missing: string[];
}

export class ResolvedSecret {
  value: string | null;
  path: string | null;
  asPath: boolean;
  source: string;
  sourceProvider: string | null;
  /** The usable string: the file path for as_path secrets, else the value. */
  get(): string | null;
}

export class Resolved {
  provider: string;
  profile: string;
  secrets: Record<string, ResolvedSecret>;
  missingOptional: string[];
  /** Export each resolved secret into process.env by its declared name. */
  setAsEnv(): void;
  /**
   * Flat { SECRET_NAME: value } object (the file path for as_path secrets). A
   * secret with no usable value (e.g. under no_values) maps to null, matching
   * the other SDKs.
   */
  fields(): Record<string, string | null>;
  /** fields() as a JSON string, the input for a quicktype-generated deserializer. */
  fieldsJson(): string;
  /**
   * Remove the temp files backing any as_path secrets in this result. Call when
   * done (or use `using` for automatic disposal) so secret files do not
   * accumulate in the temp dir.
   */
  dispose(): void;
  [Symbol.dispose](): void;
}

export class SecretReport {
  name: string;
  /** "resolved" | "missing_required" | "missing_optional" */
  status: string;
  required: boolean;
  sourceProvider: string | null;
  defaultApplied: boolean;
  generated: boolean;
  asPath: boolean;
}

export class Report {
  provider: string;
  profile: string;
  secrets: SecretReport[];
}

export class Builder {
  withPath(path: string): this;
  withProvider(provider: string): this;
  withProfile(profile: string): this;
  withReason(reason: string): this;
  /** Omit secret values, returning only structure and provenance. */
  withNoValues(noValues?: boolean): this;
  /**
   * Resolve the secrets. Throws MissingRequiredError if a required secret is
   * missing, and SecretSpecError for any other failure. Synchronous: runs on the
   * Node main thread.
   */
  load(): Resolved;
  /**
   * Like load(), but resolves on the libuv threadpool so a provider doing
   * network I/O does not block the Node event loop. Rejects with the same error
   * types load() throws.
   */
  loadAsync(): Promise<Resolved>;
  /**
   * Resolve a value-free Report (the inventory/preflight view). Unlike load(),
   * never throws MissingRequiredError: a missing required secret appears as a
   * SecretReport with status "missing_required".
   */
  report(): Report;
  /** Like report(), but resolves on the libuv threadpool. */
  reportAsync(): Promise<Report>;
}

export const SecretSpec: {
  builder(): Builder;
};

export function abiVersion(): string;
