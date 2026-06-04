#!/usr/bin/env node

import { spawnSync as nodeSpawnSync } from "node:child_process";
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

export const PLATFORM_PACKAGE_DIRS = [
  "monosecret__cli-darwin-arm64",
  "monosecret__cli-darwin-x64",
  "monosecret__cli-linux-arm64-gnu",
  "monosecret__cli-linux-arm64-musl",
  "monosecret__cli-linux-x64-gnu",
  "monosecret__cli-linux-x64-musl",
  "monosecret__cli-win32-arm64-msvc",
  "monosecret__cli-win32-x64-msvc",
];

export const CLI_PACKAGE_DIR = "monosecret__cli";
export const TRUSTED_PUBLISHING_REPOSITORY = "ifiokjr/monosecret";
export const TRUSTED_PUBLISHING_WORKFLOW = "publish.yml";
export const FORBIDDEN_NPM_TOKEN_ENV_KEYS = [
  "NODE_AUTH_TOKEN",
  "NPM_TOKEN",
  "NPM_AUTH_TOKEN",
  "NPM_CONFIG_TOKEN",
  "NPM_CONFIG__AUTH_TOKEN",
  "npm_config_token",
  "npm_config__authToken",
];

let spawnSync = nodeSpawnSync;

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

export function packageMetadata(dir) {
  return JSON.parse(readFileSync(join(dir, "package.json"), "utf8"));
}

export function hasBinary(dir) {
  const binDir = join(dir, "bin");
  if (!existsSync(binDir)) {
    return false;
  }
  const entries = readdirSync(binDir);
  return entries.some((entry) => entry.startsWith("monosecret"));
}

export function assertTrustedPublishingContext(env = process.env) {
  const configuredTokenKeys = FORBIDDEN_NPM_TOKEN_ENV_KEYS.filter((key) => env[key]);
  if (configuredTokenKeys.length > 0) {
    throw new Error(
      `Refusing to publish npm packages with long-lived npm token environment variables: ${configuredTokenKeys.join(", ")}. ` +
        "Remove npm token credentials so npm trusted publishing can use GitHub OIDC.",
    );
  }

  const workflowRef = env.GITHUB_WORKFLOW_REF ?? "";
  const expectedWorkflowPath = `${TRUSTED_PUBLISHING_REPOSITORY}/.github/workflows/${TRUSTED_PUBLISHING_WORKFLOW}@`;
  const missing = [];

  if (env.GITHUB_ACTIONS !== "true") {
    missing.push("GITHUB_ACTIONS=true");
  }
  if (env.GITHUB_REPOSITORY !== TRUSTED_PUBLISHING_REPOSITORY) {
    missing.push(`GITHUB_REPOSITORY=${TRUSTED_PUBLISHING_REPOSITORY}`);
  }
  if (!workflowRef.startsWith(expectedWorkflowPath)) {
    missing.push(`GITHUB_WORKFLOW_REF=${expectedWorkflowPath}<ref>`);
  }
  if (!env.ACTIONS_ID_TOKEN_REQUEST_URL) {
    missing.push("ACTIONS_ID_TOKEN_REQUEST_URL");
  }
  if (!env.ACTIONS_ID_TOKEN_REQUEST_TOKEN) {
    missing.push("ACTIONS_ID_TOKEN_REQUEST_TOKEN");
  }

  if (missing.length > 0) {
    throw new Error(
      "Cannot publish npm packages without the trusted-publishing GitHub Actions context. " +
        `Expected repository ${TRUSTED_PUBLISHING_REPOSITORY}, workflow ${TRUSTED_PUBLISHING_WORKFLOW}, environment publisher, and OIDC token permissions. ` +
        `Missing or mismatched: ${missing.join(", ")}.`,
    );
  }
}

export function main(argv = process.argv.slice(2)) {
  const args = parseArgs(argv);
  if (!args["packages-dir"]) {
    throw new Error("usage: populate-packages.js --packages-dir <dir>");
  }

  const packagesDir = resolve(args["packages-dir"]);

  for (const dirName of PLATFORM_PACKAGE_DIRS) {
    const dir = join(packagesDir, dirName);
    const pkg = packageMetadata(dir);
    if (hasBinary(dir) === false) {
      throw new Error(
        `Cannot populate ${pkg.name}@${pkg.version}: no binary found in ${join(dir, "bin")}. ` +
          "Run build-packages.js first to populate platform binaries.",
      );
    }
    console.log(`Populated ${pkg.name}@${pkg.version}`);
  }

  const cliDir = join(packagesDir, CLI_PACKAGE_DIR);
  const cliPkg = packageMetadata(cliDir);
  console.log(`Populated ${cliPkg.name}@${cliPkg.version}`);
}

if (process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url))) {
  main();
}
