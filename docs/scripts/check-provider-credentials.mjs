import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  collectRustSources,
  compareCatalogToRust,
  extractRegisteredCredentials,
  validateCatalog,
  validateConceptPage,
  validateComponentBacklink,
  validateImplementationBacklinks,
  validateProviderPage,
  validateReferencePage,
} from "./provider-credentials-lib.mjs";

const scriptsDirectory = path.dirname(fileURLToPath(import.meta.url));
const docsDirectory = path.resolve(scriptsDirectory, "..");
const repositoryDirectory = path.resolve(docsDirectory, "..");
const catalogPath = path.join(docsDirectory, "src/data/provider-credentials.json");
const catalog = JSON.parse(fs.readFileSync(catalogPath, "utf8"));
const catalogByProvider = validateCatalog(catalog);

const rustSources = collectRustSources(
  path.join(repositoryDirectory, "crates/monosecret/src/provider"),
);
const registeredProviders = extractRegisteredCredentials(rustSources);
compareCatalogToRust(catalogByProvider, registeredProviders);

validateImplementationBacklinks(catalog, (filename) =>
  fs.readFileSync(path.join(repositoryDirectory, filename), "utf8"),
);

for (const entry of catalog) {
  const markdownPath = path.join(docsDirectory, `src/content/docs/providers/${entry.provider}.md`);
  if (fs.existsSync(markdownPath)) {
    throw new Error(
      `${entry.provider}: rename the credential-aware provider page from .md to .mdx`,
    );
  }
  const pagePath = path.join(docsDirectory, `src/content/docs/providers/${entry.provider}.mdx`);
  validateProviderPage(entry.provider, fs.readFileSync(pagePath, "utf8"));
}

const oldCentralPath = path.join(docsDirectory, "src/content/docs/concepts/providers.md");
if (fs.existsSync(oldCentralPath)) {
  throw new Error("rename the central provider guide from providers.md to providers.mdx");
}
validateConceptPage(
  fs.readFileSync(path.join(docsDirectory, "src/content/docs/concepts/providers.mdx"), "utf8"),
);
validateReferencePage(
  fs.readFileSync(
    path.join(docsDirectory, "src/content/docs/reference/provider-credentials.mdx"),
    "utf8",
  ),
);

const component = fs.readFileSync(
  path.join(docsDirectory, "src/components/ProviderCredentials.astro"),
  "utf8",
);
validateComponentBacklink(component);

const credentialCount = catalog.reduce((count, entry) => count + entry.credentials.length, 0);
console.log(
  `Provider credential documentation is synchronized (${catalog.length} providers, ${credentialCount} credentials).`,
);
