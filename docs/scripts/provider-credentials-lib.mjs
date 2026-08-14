import fs from "node:fs";
import path from "node:path";

const PROVIDER_NAME = /^[a-z][a-z0-9-]*$/;
const CREDENTIAL_NAME = /^[a-z][a-z0-9_]*$/;
const ENVIRONMENT_NAME = /^[A-Z][A-Z0-9_]*$/;
const VERSION = /^\d+\.\d+$/;

function fail(errors) {
  if (errors.length > 0) {
    throw new Error(errors.join("\n"));
  }
}

export function validateCatalog(catalog) {
  const errors = [];
  if (!Array.isArray(catalog)) {
    throw new Error("provider credential catalog must be an array");
  }

  const providers = new Set();
  let previousProvider = "";
  for (const entry of catalog) {
    if (!entry || typeof entry !== "object") {
      errors.push("every catalog entry must be an object");
      continue;
    }
    if (!PROVIDER_NAME.test(entry.provider ?? "")) {
      errors.push(`invalid provider name: ${JSON.stringify(entry.provider)}`);
    }
    if (providers.has(entry.provider)) {
      errors.push(`duplicate provider entry: ${entry.provider}`);
    }
    providers.add(entry.provider);
    if (previousProvider && entry.provider.localeCompare(previousProvider) <= 0) {
      errors.push("provider catalog entries must be sorted by provider name");
    }
    previousProvider = entry.provider;

    if (!Array.isArray(entry.implementationSources) || entry.implementationSources.length === 0) {
      errors.push(`${entry.provider}: implementationSources must be a non-empty array`);
    }
    if (!Array.isArray(entry.credentials) || entry.credentials.length === 0) {
      errors.push(`${entry.provider}: credentials must be a non-empty array`);
      continue;
    }

    const names = new Set();
    for (const credential of entry.credentials) {
      if (!CREDENTIAL_NAME.test(credential.name ?? "")) {
        errors.push(
          `${entry.provider}: invalid credential name ${JSON.stringify(credential.name)}`,
        );
      }
      if (names.has(credential.name)) {
        errors.push(`${entry.provider}: duplicate credential ${credential.name}`);
      }
      names.add(credential.name);
      if (!VERSION.test(credential.since ?? "")) {
        errors.push(`${entry.provider}.${credential.name}: since must be MAJOR.MINOR`);
      }
      if (!Array.isArray(credential.environmentFallbacks)) {
        errors.push(`${entry.provider}.${credential.name}: environmentFallbacks must be an array`);
        continue;
      }
      const environments = new Set();
      for (const environment of credential.environmentFallbacks) {
        if (!ENVIRONMENT_NAME.test(environment)) {
          errors.push(
            `${entry.provider}.${credential.name}: invalid environment fallback ${JSON.stringify(environment)}`,
          );
        }
        if (environments.has(environment)) {
          errors.push(
            `${entry.provider}.${credential.name}: duplicate environment fallback ${environment}`,
          );
        }
        environments.add(environment);
      }
    }
  }

  fail(errors);
  return new Map(catalog.map((entry) => [entry.provider, entry]));
}

function findClosingDelimiter(source, openingIndex, opening, closing) {
  let depth = 0;
  let state = "code";
  for (let index = openingIndex; index < source.length; index += 1) {
    const character = source[index];
    const next = source[index + 1];
    if (state === "line-comment") {
      if (character === "\n") state = "code";
      continue;
    }
    if (state === "block-comment") {
      if (character === "*" && next === "/") {
        state = "code";
        index += 1;
      }
      continue;
    }
    if (state === "string") {
      if (character === "\\") {
        index += 1;
      } else if (character === '"') {
        state = "code";
      }
      continue;
    }
    if (character === "/" && next === "/") {
      state = "line-comment";
      index += 1;
      continue;
    }
    if (character === "/" && next === "*") {
      state = "block-comment";
      index += 1;
      continue;
    }
    if (character === '"') {
      state = "string";
      continue;
    }
    if (character === opening) depth += 1;
    if (character === closing) {
      depth -= 1;
      if (depth === 0) return index;
    }
  }
  throw new Error(`unclosed ${opening} delimiter`);
}

function extractConstantsFromSource(source) {
  const constants = new Map();
  const pattern = /\b(?:pub\(crate\)\s+)?const\s+([A-Z][A-Z0-9_]*)\s*:\s*&str\s*=\s*"([^"]*)"\s*;/g;
  for (const match of source.matchAll(pattern)) {
    constants.set(match[1], match[2]);
  }
  return constants;
}

function extractGlobalConstants(sources) {
  const constants = new Map();
  for (const source of sources.values()) {
    for (const [name, value] of extractConstantsFromSource(source)) {
      const values = constants.get(name) ?? new Set();
      values.add(value);
      constants.set(name, values);
    }
  }
  return constants;
}

function resolveCredentialToken(token, localConstants, globalConstants) {
  if (/^"[^"]*"$/.test(token)) return JSON.parse(token);
  if (!/^[A-Z][A-Z0-9_]*$/.test(token)) {
    throw new Error(`unsupported credential_names token: ${token}`);
  }
  if (localConstants.has(token)) return localConstants.get(token);
  const values = globalConstants.get(token);
  if (!values || values.size === 0) {
    throw new Error(`could not resolve credential_names constant: ${token}`);
  }
  if (values.size > 1) {
    throw new Error(
      `credential_names constant ${token} has conflicting values: ${[...values].join(", ")}`,
    );
  }
  return [...values][0];
}

export function extractRegisteredCredentials(sources) {
  const globalConstants = extractGlobalConstants(sources);
  const providers = new Map();
  for (const [filename, source] of sources) {
    if (filename.endsWith("/macros.rs") || filename.endsWith("/tests.rs")) continue;
    const localConstants = extractConstantsFromSource(source);
    let searchFrom = 0;
    const marker = "crate::register_provider!";
    while (true) {
      const markerIndex = source.indexOf(marker, searchFrom);
      if (markerIndex === -1) break;
      const opening = source.indexOf("{", markerIndex + marker.length);
      if (opening === -1) throw new Error(`${filename}: register_provider! has no body`);
      const closing = findClosingDelimiter(source, opening, "{", "}");
      const body = source.slice(opening + 1, closing);
      searchFrom = closing + 1;

      const providerMatch = body.match(/\bname\s*:\s*"([^"]+)"/);
      if (!providerMatch) throw new Error(`${filename}: register_provider! has no literal name`);
      const fieldMatch = /\bcredential_names\s*:\s*\[/.exec(body);
      if (!fieldMatch) continue;
      const arrayOpening = body.indexOf("[", fieldMatch.index);
      const arrayClosing = findClosingDelimiter(body, arrayOpening, "[", "]");
      const tokens = body
        .slice(arrayOpening + 1, arrayClosing)
        .split(",")
        .map((token) => token.trim())
        .filter(Boolean);
      const names = tokens.map((token) =>
        resolveCredentialToken(token, localConstants, globalConstants),
      );
      if (providers.has(providerMatch[1])) {
        throw new Error(`duplicate registered provider: ${providerMatch[1]}`);
      }
      providers.set(providerMatch[1], names);
    }
  }
  return providers;
}

export function compareCatalogToRust(catalogByProvider, registeredProviders) {
  const errors = [];
  for (const [provider, names] of registeredProviders) {
    const entry = catalogByProvider.get(provider);
    if (!entry) {
      errors.push(`${provider}: registered credential provider is missing from the docs catalog`);
      continue;
    }
    const documented = entry.credentials.map((credential) => credential.name);
    if (JSON.stringify(documented) !== JSON.stringify(names)) {
      errors.push(
        `${provider}: Rust credentials [${names.join(", ")}] do not match catalog credentials [${documented.join(", ")}]`,
      );
    }
  }
  for (const provider of catalogByProvider.keys()) {
    if (!registeredProviders.has(provider)) {
      errors.push(`${provider}: docs catalog entry has no registered credential_names declaration`);
    }
  }
  fail(errors);
}

function quotedArrayPattern(names) {
  const escaped = names.map((name) => name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"));
  return new RegExp(`\\[\\s*"${escaped.join('"\\s*,\\s*"')}"\\s*,?\\s*\\]`);
}

export function validateImplementationBacklinks(catalog, sourceLoader) {
  const errors = [];
  for (const entry of catalog) {
    let implementation = "";
    for (const filename of entry.implementationSources) {
      try {
        implementation += `\n${sourceLoader(filename)}`;
      } catch (error) {
        errors.push(
          `${entry.provider}: cannot read implementation source ${filename}: ${error.message}`,
        );
      }
    }
    for (const credential of entry.credentials) {
      for (const environment of credential.environmentFallbacks) {
        if (!implementation.includes(`"${environment}"`)) {
          errors.push(
            `${entry.provider}.${credential.name}: environment fallback ${environment} is absent from its implementation sources`,
          );
        }
      }
      if (
        credential.environmentFallbacks.length > 1 &&
        !quotedArrayPattern(credential.environmentFallbacks).test(implementation)
      ) {
        errors.push(
          `${entry.provider}.${credential.name}: ordered environment fallback sequence is absent from its implementation sources`,
        );
      }
    }
  }
  fail(errors);
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

export function validateProviderPage(provider, content) {
  const errors = [];
  if (
    !/^import ProviderCredentials from ['"][^'"]*ProviderCredentials\.astro['"];?$/m.test(content)
  ) {
    errors.push(`${provider}: provider page does not import ProviderCredentials`);
  }
  const headings = [...content.matchAll(/^## Provider credentials\s*$/gm)];
  if (headings.length !== 1) {
    errors.push(
      `${provider}: provider page must have exactly one \"## Provider credentials\" heading`,
    );
  }
  const component = new RegExp(
    `<ProviderCredentials\\s+provider=["']${escapeRegExp(provider)}["']\\s*/>`,
  );
  if (!component.test(content)) {
    errors.push(`${provider}: provider page does not render its ProviderCredentials entry`);
  }
  if (headings.length === 1) {
    const section = content.slice(
      headings[0].index,
      content.indexOf("\n## ", headings[0].index + 3) === -1
        ? undefined
        : content.indexOf("\n## ", headings[0].index + 3),
    );
    if (!component.test(section)) {
      errors.push(
        `${provider}: ProviderCredentials component must be inside its credential section`,
      );
    }
  }
  fail(errors);
}

export function validateReferencePage(content) {
  const errors = [];
  if (
    !/^import ProviderCredentials from ['"][^'"]*ProviderCredentials\.astro['"];?$/m.test(content)
  ) {
    errors.push("provider credential reference does not import ProviderCredentials");
  }
  if (!/<ProviderCredentials\s*\/>/.test(content)) {
    errors.push("provider credential reference does not render the complete credential catalog");
  }
  fail(errors);
}

export function validateConceptPage(content) {
  if (!content.includes("/reference/provider-credentials/")) {
    throw new Error("provider credential concept guide must link to the credential reference");
  }
}

export function validateComponentBacklink(content) {
  if (!content.includes("/reference/provider-credentials/")) {
    throw new Error(
      "ProviderCredentials component must backlink to the provider credential reference",
    );
  }
}

export function collectRustSources(providerDirectory) {
  const sources = new Map();
  function visit(directory) {
    for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
      const filename = path.join(directory, entry.name);
      if (entry.isDirectory()) visit(filename);
      else if (entry.isFile() && filename.endsWith(".rs")) {
        sources.set(filename.replaceAll(path.sep, "/"), fs.readFileSync(filename, "utf8"));
      }
    }
  }
  visit(providerDirectory);
  return sources;
}
