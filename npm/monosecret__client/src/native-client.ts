import { createRequire } from "node:module";
import { unlinkSync } from "node:fs";

const RESOLVE_SCHEMA_VERSION = 2;
const REPORT_SCHEMA_VERSION = 1;

const platformPackages: Readonly<Record<string, string>> = {
  "darwin-arm64": "@monosecret/client-darwin-arm64",
  "linux-arm64": "@monosecret/client-linux-arm64-gnu",
  "linux-x64": "@monosecret/client-linux-x64-gnu",
  "win32-x64": "@monosecret/client-win32-x64-msvc",
};

interface NativeBinding {
  abiVersion(): string;
  resolve(request: string): string;
  resolveAsync(request: string): Promise<string>;
}

let nativeBinding: NativeBinding | undefined;

function native(): NativeBinding {
  if (nativeBinding !== undefined) {
    return nativeBinding;
  }

  const require = createRequire(import.meta.url);

  try {
    nativeBinding = require("../monosecret-client.node") as NativeBinding;
    return nativeBinding;
  } catch (localError) {
    const platform = `${process.platform}-${process.arch}`;
    const packageName = platformPackages[platform];

    if (packageName === undefined) {
      throw new MonosecretError("addon", `unsupported native platform ${platform}`);
    }

    try {
      nativeBinding = require(packageName) as NativeBinding;
      return nativeBinding;
    } catch (packageError) {
      const detail = packageError instanceof Error ? packageError.message : String(packageError);
      const localDetail = localError instanceof Error ? localError.message : String(localError);
      throw new MonosecretError(
        "addon",
        `failed to load the native resolver for ${platform}; install ${packageName} or build ` +
          `monosecret-client.node locally. Package error: ${detail}. Local error: ${localDetail}`,
      );
    }
  }
}

export class MonosecretError extends Error {
  readonly kind: string;

  constructor(kind: string, message: string) {
    super(`${message} (kind: ${kind})`);
    this.name = "MonosecretError";
    this.kind = kind;
  }
}

export class MissingRequiredError extends MonosecretError {
  readonly missing: readonly string[];

  constructor(missing: readonly string[]) {
    super("missing_required", `missing required secret(s): ${missing.join(", ")}`);
    this.name = "MissingRequiredError";
    this.missing = missing;
  }
}

interface SecretEntry {
  value?: string | null;
  path?: string | null;
  as_path?: boolean;
  source: string;
  source_provider?: string | null;
}

export class ResolvedSecret {
  readonly value: string | null;
  readonly path: string | null;
  readonly asPath: boolean;
  readonly source: string;
  readonly sourceProvider: string | null;

  constructor(entry: SecretEntry) {
    this.value = entry.value ?? null;
    this.path = entry.path ?? null;
    this.asPath = entry.as_path ?? false;
    this.source = entry.source;
    this.sourceProvider = entry.source_provider ?? null;
  }

  get(): string | null {
    return this.asPath ? this.path : this.value;
  }
}

interface ResolveResponse {
  schema_version: number;
  provider: string;
  profile: string;
  scope?: string | null;
  secrets?: Record<string, SecretEntry>;
  missing_required?: string[];
  missing_optional?: string[];
}

export class Resolved implements Disposable {
  readonly provider: string;
  readonly profile: string;
  readonly scope: string | null;
  readonly secrets: Readonly<Record<string, ResolvedSecret>>;
  readonly missingOptional: readonly string[];

  constructor(response: ResolveResponse) {
    this.provider = response.provider;
    this.profile = response.profile;
    this.scope = response.scope ?? null;
    this.secrets = Object.fromEntries(
      Object.entries(response.secrets ?? {}).map(([name, entry]) => [
        name,
        new ResolvedSecret(entry),
      ]),
    );
    this.missingOptional = response.missing_optional ?? [];
  }

  setAsEnv(): void {
    for (const [name, secret] of Object.entries(this.secrets)) {
      const value = secret.get();
      if (value !== null) process.env[name] = value;
    }
  }

  fields(): Record<string, string | null> {
    return Object.fromEntries(
      Object.entries(this.secrets).map(([name, secret]) => [name, secret.get()]),
    );
  }

  fieldsJson(): string {
    return JSON.stringify(this.fields());
  }

  dispose(): void {
    for (const secret of Object.values(this.secrets)) {
      if (secret.asPath && secret.path !== null) {
        try {
          unlinkSync(secret.path);
        } catch (error) {
          if (!(error instanceof Error && "code" in error && error.code === "ENOENT")) throw error;
        }
      }
    }
  }

  [Symbol.dispose](): void {
    this.dispose();
  }
}

interface SecretReportEntry {
  name: string;
  status: string;
  required?: boolean;
  source_provider?: string | null;
  default_applied?: boolean;
  generated?: boolean;
  as_path?: boolean;
}

export class SecretReport {
  readonly name: string;
  readonly status: string;
  readonly required: boolean;
  readonly sourceProvider: string | null;
  readonly defaultApplied: boolean;
  readonly generated: boolean;
  readonly asPath: boolean;

  constructor(entry: SecretReportEntry) {
    this.name = entry.name;
    this.status = entry.status;
    this.required = entry.required ?? false;
    this.sourceProvider = entry.source_provider ?? null;
    this.defaultApplied = entry.default_applied ?? false;
    this.generated = entry.generated ?? false;
    this.asPath = entry.as_path ?? false;
  }
}

export type ConstraintViolationKind = "at_least_one" | "exactly_one";

interface ConstraintViolationEntry {
  kind: ConstraintViolationKind;
  group: string;
  secrets: string[];
  present: string[];
}

export class ConstraintViolation {
  readonly kind: ConstraintViolationKind;
  readonly group: string;
  readonly secrets: readonly string[];
  readonly present: readonly string[];

  constructor(entry: ConstraintViolationEntry) {
    this.kind = entry.kind;
    this.group = entry.group;
    this.secrets = [...entry.secrets];
    this.present = [...entry.present];
  }
}

interface ReportResponse {
  schema_version: number;
  provider: string;
  profile: string;
  scope?: string | null;
  secrets?: SecretReportEntry[];
  constraint_violations?: ConstraintViolationEntry[];
}

export class Report {
  readonly provider: string;
  readonly profile: string;
  readonly scope: string | null;
  readonly secrets: readonly SecretReport[];
  readonly constraintViolations: readonly ConstraintViolation[];

  constructor(response: ReportResponse) {
    this.provider = response.provider;
    this.profile = response.profile;
    this.scope = response.scope ?? null;
    this.secrets = (response.secrets ?? []).map((entry) => new SecretReport(entry));
    this.constraintViolations = (response.constraint_violations ?? []).map(
      (entry) => new ConstraintViolation(entry),
    );
  }
}

interface ResolveEnvelope<T> {
  ok: boolean;
  response?: T;
  error?: { kind?: string; message?: string };
}

function checkedResponse<T extends { schema_version: number }>(
  raw: string,
  kind: string,
  expectedVersion: number,
): T {
  const envelope = JSON.parse(raw) as ResolveEnvelope<T>;

  if (!envelope.ok) {
    throw new MonosecretError(
      envelope.error?.kind ?? "unknown",
      envelope.error?.message ?? "native resolution failed",
    );
  }
  if (envelope.response === undefined) {
    throw new MonosecretError("ffi", "monosecret_resolve reported success without a response");
  }
  if (envelope.response.schema_version !== expectedVersion) {
    throw new MonosecretError(
      "version",
      `unsupported ${kind} schema version ${envelope.response.schema_version}; expected ${expectedVersion}`,
    );
  }

  return envelope.response;
}

export class Builder {
  private readonly request: Record<string, unknown> = {};

  withPath(path: string | null | undefined): this {
    if (path != null) this.request.path = path;
    return this;
  }

  withProvider(provider: string | null | undefined): this {
    if (provider != null) this.request.provider = provider;
    return this;
  }

  withProfile(profile: string | null | undefined): this {
    if (profile != null) this.request.profile = profile;
    return this;
  }

  withScope(scope: string | null | undefined): this {
    if (scope != null) this.request.scope = scope;
    return this;
  }

  withInclude(include: readonly string[]): this {
    this.request.include = [...include];
    return this;
  }

  withGroups(groups: readonly string[]): this {
    this.request.groups = [...groups];
    return this;
  }

  withReason(reason: string | null | undefined): this {
    if (reason != null) this.request.reason = reason;
    return this;
  }

  withNoValues(noValues = true): this {
    this.request.no_values = noValues;
    return this;
  }

  load(): Resolved {
    return this.parseResolved(native().resolve(JSON.stringify(this.request)));
  }

  async loadAsync(): Promise<Resolved> {
    return this.parseResolved(await native().resolveAsync(JSON.stringify(this.request)));
  }

  report(): Report {
    return this.parseReport(native().resolve(JSON.stringify({ ...this.request, mode: "report" })));
  }

  async reportAsync(): Promise<Report> {
    return this.parseReport(
      await native().resolveAsync(JSON.stringify({ ...this.request, mode: "report" })),
    );
  }

  private parseResolved(raw: string): Resolved {
    const response = checkedResponse<ResolveResponse>(raw, "resolve", RESOLVE_SCHEMA_VERSION);
    const missing = response.missing_required ?? [];
    if (missing.length > 0) throw new MissingRequiredError(missing);
    return new Resolved(response);
  }

  private parseReport(raw: string): Report {
    return new Report(checkedResponse<ReportResponse>(raw, "report", REPORT_SCHEMA_VERSION));
  }
}

export const Monosecret = {
  builder(): Builder {
    return new Builder();
  },
};

export function abiVersion(): string {
  return native().abiVersion();
}
