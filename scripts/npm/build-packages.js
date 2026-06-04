#!/usr/bin/env node

import { spawnSync as nodeSpawnSync } from "node:child_process";
import { chmodSync, copyFileSync, existsSync, mkdirSync, readdirSync, rmSync } from "node:fs";
import { basename, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(__dirname, "../..");

let spawnSync = nodeSpawnSync;

export const platforms = [
  {
    archiveExt: "tar.gz",
    binaryName: "monosecret",
    cpu: "arm64",
    label: "Linux arm64 (glibc)",
    libc: "glibc",
    os: "linux",
    packageName: "@monosecret/cli-linux-arm64-gnu",
    target: "aarch64-unknown-linux-gnu",
  },
  {
    archiveExt: "tar.gz",
    binaryName: "monosecret",
    cpu: "arm64",
    label: "Linux arm64 (musl)",
    libc: "musl",
    os: "linux",
    packageName: "@monosecret/cli-linux-arm64-musl",
    target: "aarch64-unknown-linux-musl",
  },
  {
    archiveExt: "tar.gz",
    binaryName: "monosecret",
    cpu: "arm64",
    label: "macOS arm64",
    os: "darwin",
    packageName: "@monosecret/cli-darwin-arm64",
    target: "aarch64-apple-darwin",
  },
  {
    archiveExt: "tar.gz",
    binaryName: "monosecret",
    cpu: "x64",
    label: "Linux x64 (glibc)",
    libc: "glibc",
    os: "linux",
    packageName: "@monosecret/cli-linux-x64-gnu",
    target: "x86_64-unknown-linux-gnu",
  },
  {
    archiveExt: "tar.gz",
    binaryName: "monosecret",
    cpu: "x64",
    label: "Linux x64 (musl)",
    libc: "musl",
    os: "linux",
    packageName: "@monosecret/cli-linux-x64-musl",
    target: "x86_64-unknown-linux-musl",
  },
  {
    archiveExt: "tar.gz",
    binaryName: "monosecret",
    cpu: "x64",
    label: "macOS x64",
    os: "darwin",
    packageName: "@monosecret/cli-darwin-x64",
    target: "x86_64-apple-darwin",
  },
  {
    archiveExt: "zip",
    binaryName: "monosecret.exe",
    cpu: "arm64",
    label: "Windows arm64",
    os: "win32",
    packageName: "@monosecret/cli-win32-arm64-msvc",
    target: "aarch64-pc-windows-msvc",
  },
  {
    archiveExt: "zip",
    binaryName: "monosecret.exe",
    cpu: "x64",
    label: "Windows x64",
    os: "win32",
    packageName: "@monosecret/cli-win32-x64-msvc",
    target: "x86_64-pc-windows-msvc",
  },
];

export function parseArgs(argv) {
  const args = {};
  for (let index = 0; index < argv.length; index += 1) {
    const key = argv[index];
    const value = argv[index + 1];
    if (!key.startsWith("--") || value === undefined) {
      continue;
    }
    args[key.slice(2)] = value;
    index += 1;
  }
  return args;
}

export function run(command, args, options = {}) {
  const result = spawnSync(command, args, {
    encoding: "utf8",
    stdio: options.stdio ?? "pipe",
    cwd: options.cwd,
  });
  if (result.status !== 0) {
    const detail = result.stderr || result.stdout || `exit code ${result.status ?? "unknown"}`;
    throw new Error(`${command} ${args.join(" ")} failed: ${detail}`);
  }
  return result;
}

export function ensureDirectory(path) {
  mkdirSync(path, { recursive: true });
}

export function findArchive(assetsDir, target, releaseTag, archiveExt) {
  const archiveName = `monosecret-${target}-${releaseTag}.${archiveExt}`;
  const archivePath = join(assetsDir, archiveName);
  if (!existsSync(archivePath)) {
    throw new Error(`missing release asset: ${archiveName}`);
  }
  return archivePath;
}

export function* walk(dir) {
  const entries = readdirSync(dir, { withFileTypes: true });
  for (const entry of entries) {
    const entryPath = join(dir, entry.name);
    if (entry.isDirectory()) {
      yield* walk(entryPath);
    } else {
      yield entryPath;
    }
  }
}

export function extractArchive(archivePath, destinationDir) {
  rmSync(destinationDir, { recursive: true, force: true });
  ensureDirectory(destinationDir);
  if (archivePath.endsWith(".zip")) {
    run("unzip", ["-q", archivePath, "-d", destinationDir]);
    return;
  }
  if (archivePath.endsWith(".tar.gz")) {
    run("tar", ["-xzf", archivePath, "-C", destinationDir]);
    return;
  }
  throw new Error(`unsupported archive: ${basename(archivePath)}`);
}

export function findBinary(extractedDir, binaryName) {
  for (const filePath of walk(extractedDir)) {
    if (basename(filePath) === binaryName) {
      return filePath;
    }
  }
  throw new Error(`could not find ${binaryName} in ${extractedDir}`);
}

export function packageNameToDirName(packageName) {
  return packageName.replace("@", "").replace("/", "__");
}

export function populatePlatformPackage({ packagesDir, spec, releaseTag, assetsDir, tmpDir }) {
  const archivePath = findArchive(assetsDir, spec.target, releaseTag, spec.archiveExt);
  const extractedDir = join(tmpDir, spec.target);
  const packageDir = join(packagesDir, packageNameToDirName(spec.packageName));
  const binDir = join(packageDir, "bin");

  extractArchive(archivePath, extractedDir);
  const binaryPath = findBinary(extractedDir, spec.binaryName);

  rmSync(binDir, { recursive: true, force: true });
  ensureDirectory(binDir);
  copyFileSync(binaryPath, join(binDir, spec.binaryName));
  if (spec.binaryName === "monosecret") {
    chmodSync(join(binDir, spec.binaryName), 0o755);
  }
}

export function main(argv = process.argv.slice(2)) {
  const args = parseArgs(argv);
  const releaseTag = args["release-tag"];
  const assetsDir = resolve(args["assets-dir"] ?? "");

  if (!releaseTag || !args["assets-dir"]) {
    throw new Error("usage: build-packages.js --release-tag <vX.Y.Z> --assets-dir <dir>");
  }

  const packagesDir = join(repoRoot, "packages");
  const tmpDir = join(packagesDir, ".tmp");

  for (const spec of platforms) {
    populatePlatformPackage({ packagesDir, spec, releaseTag, assetsDir, tmpDir });
  }

  console.log(`Populated platform binaries in ${packagesDir} for ${releaseTag}`);
}

if (process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url))) {
  main();
}
