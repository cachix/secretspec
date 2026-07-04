import { mkdtemp, readFile, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import { MonosecretClient, MonosecretException, parseEnvironment } from "../src/index.js";

const tempDirs: string[] = [];

const nodeClient = (
  script: string,
  options: Omit<
    ConstructorParameters<typeof MonosecretClient>[0],
    "executable" | "executableArgs"
  > = {},
) =>
  new MonosecretClient({
    ...options,
    executable: process.execPath,
    executableArgs: [script],
  });

describe("MonosecretClient.get", () => {
  it("returns stdout with trailing CLI whitespace removed", async () => {
    const cli = await fakeCli({ stdout: "secret-value  \n\n" });
    const client = nodeClient(cli);

    await expect(client.get("API_KEY")).resolves.toBe("secret-value");
  });

  it("passes secret name and optional profile/provider/file flags", async () => {
    const argsFile = await tempFile("args.json");
    const cli = await fakeCli({ argsFile, stdout: "value\n" });
    const client = nodeClient(cli);

    await client.get("DATABASE_URL", {
      file: "monosecret.production.toml",
      profile: "production",
      provider: "op",
    });

    await expect(readRecordedArgs(argsFile)).resolves.toEqual([
      "get",
      "DATABASE_URL",
      "--profile",
      "production",
      "--provider",
      "op",
      "--file",
      "monosecret.production.toml",
    ]);
  });
});

describe("MonosecretClient.check", () => {
  it("uses --no-prompt by default and forwards selectors", async () => {
    const argsFile = await tempFile("args.json");
    const cli = await fakeCli({ argsFile });
    const client = nodeClient(cli);

    await client.check({
      file: "monosecret.ci.toml",
      profile: "ci",
      provider: "env",
    });

    await expect(readRecordedArgs(argsFile)).resolves.toEqual([
      "check",
      "--no-prompt",
      "--profile",
      "ci",
      "--provider",
      "env",
      "--file",
      "monosecret.ci.toml",
    ]);
  });

  it("omits --no-prompt when disabled", async () => {
    const argsFile = await tempFile("args.json");
    const cli = await fakeCli({ argsFile });
    const client = nodeClient(cli);

    await client.check({ noPrompt: false });

    await expect(readRecordedArgs(argsFile)).resolves.toEqual(["check"]);
  });
});

describe("MonosecretClient.loadEnvironment", () => {
  it("passes include/group selectors and returns injected environment", async () => {
    const argsFile = await tempFile("args.json");
    const cli = await environmentCli({
      argsFile,
      injectedEnvironment: {
        API_KEY: "abc123",
        DATABASE_URL: "postgres://localhost/app",
      },
    });
    const client = nodeClient(cli);

    const environment = await client.loadEnvironment({
      file: "monosecret.toml",
      groups: ["backend", "workers"],
      include: ["DATABASE_URL", "API_KEY"],
      profile: "development",
      provider: "dotenv",
    });

    expect(environment).toMatchObject({
      API_KEY: "abc123",
      DATABASE_URL: "postgres://localhost/app",
    });
    await expect(readRecordedArgs(argsFile)).resolves.toEqual([
      "run",
      "--profile",
      "development",
      "--provider",
      "dotenv",
      "--file",
      "monosecret.toml",
      "--include",
      "DATABASE_URL",
      "--include",
      "API_KEY",
      "--group",
      "backend",
      "--group",
      "workers",
      "--",
      ...(process.platform === "win32" ? ["cmd", "/c", "set"] : ["env"]),
    ]);
  });

  it("parses environment lines and preserves equals signs in values", () => {
    expect(
      parseEnvironment(
        "DATABASE_URL=postgres://localhost/app\nTOKEN=value=with=equals\nIGNORED_LINE\n",
      ),
    ).toEqual({
      DATABASE_URL: "postgres://localhost/app",
      TOKEN: "value=with=equals",
    });
  });
});

describe("process configuration", () => {
  it("passes custom environment to the CLI process", async () => {
    const cli = await fakeCli({ stdoutEnvironmentVariable: "MONOSECRET_TEST_TOKEN" });
    const client = nodeClient(cli, {
      environment: { MONOSECRET_TEST_TOKEN: "from-client-env" },
    });

    await expect(client.get("TOKEN")).resolves.toBe("from-client-env");
  });

  it("runs the CLI from the configured working directory", async () => {
    const dir = await tempDir();
    const cli = await fakeCli({ stdoutWorkingDirectory: true });
    const client = nodeClient(cli, { workingDirectory: dir });

    await expect(client.get("PWD")).resolves.toBe(await realpath(dir));
  });
});

describe("MonosecretException", () => {
  it("captures command, exit code, stdout, stderr, and message", async () => {
    const cli = await fakeCli({ exitCode: 7, stderr: "boom\n", stdout: "partial output\n" });
    const client = nodeClient(cli);

    await expect(client.check({ profile: "ci" })).rejects.toMatchObject({
      args: ["check", "--no-prompt", "--profile", "ci"],
      exitCode: 7,
      name: "MonosecretException",
      stderr: "boom\n",
      stdout: "partial output\n",
    } satisfies Partial<MonosecretException>);
    await expect(client.check({ profile: "ci" })).rejects.toThrow(
      `${process.execPath} check --no-prompt --profile ci failed with exit code 7: boom`,
    );
  });
});

afterEach(async () => {
  await Promise.all(tempDirs.splice(0).map((dir) => rm(dir, { force: true, recursive: true })));
});

async function fakeCli(
  options: {
    argsFile?: string;
    exitCode?: number;
    stderr?: string;
    stdout?: string;
    stdoutEnvironmentVariable?: string;
    stdoutWorkingDirectory?: boolean;
  } = {},
): Promise<string> {
  return writeCli(`
    import { writeFileSync } from 'node:fs';

    const args = process.argv.slice(2);
    ${options.argsFile === undefined ? "" : `writeFileSync(${JSON.stringify(options.argsFile)}, JSON.stringify(args));`}
    ${options.stdoutWorkingDirectory === true ? "process.stdout.write(process.cwd());" : ""}
    ${options.stdoutEnvironmentVariable === undefined ? "" : `process.stdout.write(process.env[${JSON.stringify(options.stdoutEnvironmentVariable)}] ?? '');`}
    ${options.stdout === undefined ? "" : `process.stdout.write(${JSON.stringify(options.stdout)});`}
    ${options.stderr === undefined ? "" : `process.stderr.write(${JSON.stringify(options.stderr)});`}
    process.exit(${options.exitCode ?? 0});
  `);
}

async function environmentCli(options: {
  argsFile: string;
  injectedEnvironment: Record<string, string>;
}): Promise<string> {
  const stdout = Object.entries(options.injectedEnvironment)
    .map(([key, value]) => `${key}=${value}`)
    .join("\n");

  return fakeCli({
    argsFile: options.argsFile,
    stdout: `${stdout}\n`,
  });
}

async function writeCli(source: string): Promise<string> {
  const file = await tempFile("monosecret.mjs");
  await writeFile(file, source);
  return file;
}

async function readRecordedArgs(file: string): Promise<string[]> {
  return JSON.parse(await readFile(file, "utf8")) as string[];
}

async function tempFile(name: string): Promise<string> {
  return join(await tempDir(), name);
}

async function tempDir(): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), "monosecret_ts_test_"));
  tempDirs.push(dir);
  return dir;
}
