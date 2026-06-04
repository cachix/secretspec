import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);

export interface MonosecretClientOptions {
  /** Path or command name for the Monosecret CLI. */
  executable?: string;

  /** Extra arguments inserted before every Monosecret command. Useful for tests and wrappers. */
  executableArgs?: readonly string[];

  /** Working directory used when invoking the CLI. */
  workingDirectory?: string | URL;

  /** Environment variables merged into the child process environment. */
  environment?: NodeJS.ProcessEnv;
}

export interface SecretSelectorOptions {
  profile?: string;
  provider?: string;
  file?: string;
}

export interface CheckOptions extends SecretSelectorOptions {
  /** Pass `--no-prompt` to the CLI. Defaults to true for client-safe non-interactive checks. */
  noPrompt?: boolean;
}

export interface LoadEnvironmentOptions extends SecretSelectorOptions {
  include?: readonly string[];
  groups?: readonly string[];
}

export interface MonosecretProcessOutput {
  stdout: string;
  stderr: string;
}

/** TypeScript client for the `monosecret` CLI. */
export class MonosecretClient {
  readonly executable: string;
  readonly executableArgs: readonly string[];
  readonly workingDirectory?: string | URL;
  readonly environment: NodeJS.ProcessEnv;

  constructor(options: MonosecretClientOptions = {}) {
    this.executable = options.executable ?? 'monosecret';
    this.executableArgs = options.executableArgs ?? [];
    this.environment = options.environment ?? {};

    if (options.workingDirectory !== undefined) {
      this.workingDirectory = options.workingDirectory;
    }
  }

  async get(name: string, options: SecretSelectorOptions = {}): Promise<string> {
    const result = await this.run([
      'get',
      name,
      ...selectorArgs(options),
    ]);

    return trimRight(result.stdout);
  }

  async check(options: CheckOptions = {}): Promise<void> {
    await this.run([
      'check',
      ...(options.noPrompt ?? true ? ['--no-prompt'] : []),
      ...selectorArgs(options),
    ]);
  }

  async loadEnvironment(options: LoadEnvironmentOptions = {}): Promise<Record<string, string>> {
    const result = await this.run([
      'run',
      ...selectorArgs(options),
      ...repeatedArgs('--include', options.include),
      ...repeatedArgs('--group', options.groups),
      '--',
      ...environmentPrinterCommand(),
    ]);

    return parseEnvironment(result.stdout);
  }

  async run(args: readonly string[]): Promise<MonosecretProcessOutput> {
    const commandArgs = [...this.executableArgs, ...args];

    try {
      const result = await execFileAsync(this.executable, commandArgs, {
        cwd: this.workingDirectory,
        env: { ...process.env, ...this.environment },
        encoding: 'utf8',
        maxBuffer: 10 * 1024 * 1024,
      });

      return {
        stdout: result.stdout,
        stderr: result.stderr,
      };
    } catch (error) {
      if (isExecFileError(error)) {
        throw new MonosecretException({
          args,
          executable: this.executable,
          exitCode: typeof error.code === 'number' ? error.code : 1,
          stderr: error.stderr ?? '',
          stdout: error.stdout ?? '',
        });
      }

      throw error;
    }
  }
}

export class MonosecretException extends Error {
  readonly args: readonly string[];
  readonly executable: string;
  readonly exitCode: number;
  readonly stdout: string;
  readonly stderr: string;

  constructor(options: {
    args: readonly string[];
    executable: string;
    exitCode: number;
    stdout: string;
    stderr: string;
  }) {
    super(`${options.executable} ${options.args.join(' ')} failed with exit code ${options.exitCode}: ${options.stderr}`);
    this.name = 'MonosecretException';
    this.args = options.args;
    this.executable = options.executable;
    this.exitCode = options.exitCode;
    this.stdout = options.stdout;
    this.stderr = options.stderr;
  }
}

export function parseEnvironment(stdout: string): Record<string, string> {
  const environment: Record<string, string> = {};

  for (const line of stdout.split(/\r?\n/)) {
    const separator = line.indexOf('=');

    if (separator < 0) {
      continue;
    }

    environment[line.slice(0, separator)] = line.slice(separator + 1);
  }

  return environment;
}

function selectorArgs(options: SecretSelectorOptions): string[] {
  return [
    ...(options.profile !== undefined ? ['--profile', options.profile] : []),
    ...(options.provider !== undefined ? ['--provider', options.provider] : []),
    ...(options.file !== undefined ? ['--file', options.file] : []),
  ];
}

function repeatedArgs(flag: string, values: readonly string[] | undefined): string[] {
  return values?.flatMap((value) => [flag, value]) ?? [];
}

function environmentPrinterCommand(): string[] {
  return process.platform === 'win32' ? ['cmd', '/c', 'set'] : ['env'];
}

function trimRight(value: string): string {
  return value.replace(/\s+$/u, '');
}

function isExecFileError(error: unknown): error is Error & {
  code?: number | string;
  stderr?: string;
  stdout?: string;
} {
  return error instanceof Error && ('stdout' in error || 'stderr' in error || 'code' in error);
}
