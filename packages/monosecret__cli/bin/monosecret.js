#!/usr/bin/env node
"use strict";

import { existsSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";

const require = createRequire(import.meta.url);

const PLATFORM_PACKAGES = {
  darwin: {
    arm64: ["@monosecret/cli-darwin-arm64"],
    x64: ["@monosecret/cli-darwin-x64"],
  },
  linux: {
    arm64: ["@monosecret/cli-linux-arm64-gnu", "@monosecret/cli-linux-arm64-musl"],
    x64: ["@monosecret/cli-linux-x64-gnu", "@monosecret/cli-linux-x64-musl"],
  },
  win32: {
    arm64: ["@monosecret/cli-win32-arm64-msvc"],
    x64: ["@monosecret/cli-win32-x64-msvc"],
  },
};

function getCandidatePackages() {
  return PLATFORM_PACKAGES[process.platform]?.[process.arch] ?? [];
}

function resolveBinary(pkgName) {
  try {
    const packageJsonPath = require.resolve(`${pkgName}/package.json`);
    const packageDir = dirname(packageJsonPath);
    const binaryName = process.platform === "win32" ? "monosecret.exe" : "monosecret";
    const binaryPath = join(packageDir, "bin", binaryName);
    if (existsSync(binaryPath)) {
      return binaryPath;
    }
  } catch {
    // Ignore missing optional dependencies and continue trying candidates.
  }

  return null;
}

function shouldTryNextPackage(result) {
  if (result.error) {
    return true;
  }

  if (result.status !== 127) {
    return false;
  }

  const stderr = result.stderr ?? "";
  return /not found|no such file or directory|exec format error/i.test(stderr);
}

function forwardOutput(result) {
  if (result.stdout) {
    process.stdout.write(result.stdout);
  }
  if (result.stderr) {
    process.stderr.write(result.stderr);
  }
}

function resolveDevelopmentBinary() {
  const here = dirname(fileURLToPath(import.meta.url));
  const repoBinary = resolve(here, "../../../target/release/monosecret");
  if (existsSync(repoBinary)) {
    return repoBinary;
  }
  return null;
}

function main() {
  const developmentBinary = process.env.MONOSECRET_BIN ?? resolveDevelopmentBinary();
  if (developmentBinary) {
    const result = spawnSync(developmentBinary, process.argv.slice(2), { stdio: "inherit" });
    if (result.error) {
      console.error(result.error.message);
      process.exit(1);
    }
    process.exit(result.status ?? 0);
  }

  const candidates = getCandidatePackages();
  if (candidates.length === 0) {
    console.error(
      `Monosecret does not currently publish npm binaries for ${process.platform}/${process.arch}. ` +
        "Install from GitHub releases or with `cargo install monosecret` instead.",
    );
    process.exit(1);
  }

  const failures = [];
  for (const pkgName of candidates) {
    const binaryPath = resolveBinary(pkgName);
    if (!binaryPath) {
      continue;
    }

    const result = spawnSync(binaryPath, process.argv.slice(2), {
      encoding: "utf8",
      stdio: ["inherit", "pipe", "pipe"],
      windowsHide: false,
    });

    if (shouldTryNextPackage(result)) {
      const detail = result.error?.message ?? result.stderr?.trim() ?? "failed to launch";
      failures.push(`${pkgName}: ${detail}`);
      continue;
    }

    forwardOutput(result);
    process.exit(result.status ?? 0);
  }

  console.error("Unable to find a compatible Monosecret binary in the installed npm packages.");
  console.error(`Tried: ${candidates.join(", ")}`);
  if (failures.length > 0) {
    console.error(failures.join("\n"));
  }
  console.error(
    "Reinstall with `npm install -g @monosecret/cli`, download a binary from GitHub releases, or use `cargo install monosecret`.",
  );
  process.exit(1);
}

main();
