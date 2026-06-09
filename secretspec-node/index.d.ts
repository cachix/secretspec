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
  /** Flat { SECRET_NAME: value } object (the file path for as_path secrets). */
  fields(): Record<string, string>;
  /** fields() as a JSON string, the input for a quicktype-generated deserializer. */
  fieldsJson(): string;
}

export class Builder {
  withPath(path: string): this;
  withProvider(provider: string): this;
  withProfile(profile: string): this;
  withReason(reason: string): this;
  /**
   * Resolve the secrets. Throws MissingRequiredError if a required secret is
   * missing, and SecretSpecError for any other failure.
   */
  load(): Resolved;
}

export const SecretSpec: {
  builder(): Builder;
};

export function abiVersion(): string;
