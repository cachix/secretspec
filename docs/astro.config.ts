import type {PluginOption} from "vite";
import { readFileSync } from "node:fs";
import { defineConfig } from "astro/config";
import starlight from "@astrojs/starlight";
import starlightLlmsTxt from "starlight-llms-txt";
import starlightBlog from "starlight-blog";
import { preserveHeadingIdPlugin } from "./src/lib/preserve-heading-id.mjs";
import { terminalCopyPlugin } from "./src/lib/terminal-copy.mjs";

const rustSdkBasicExample = readFileSync(
  new URL("../secretspec-derive/examples/basic.rs", import.meta.url),
  "utf8",
).trim();

// Dev-only: `astro dev` (what `devenv up` runs) does not execute worker.js, so
// /api/github would 404 and the release/star pills would stay hidden locally.
// Mirror the worker's GitHub proxy here so both populate during development.
// Production is unaffected — it is served by worker.js.
const devGitHubApi: PluginOption = {
  name: "dev-github-api",
  apply: "serve",
  enforce: "pre",
  configureServer(server) {
    server.middlewares.use("/api/github", async (_req, res) => {
      let stars = null;
      let release = null;
      try {
        const headers = { "User-Agent": "secretspec-docs" };
        const [repoResponse, releaseResponse] = await Promise.all([
          fetch("https://api.github.com/repos/cachix/secretspec", { headers }),
          fetch("https://api.github.com/repos/cachix/secretspec/releases/latest", { headers }),
        ]);
        if (repoResponse.ok) {
          const data = await repoResponse.json();
          if (typeof data.stargazers_count === "number") stars = data.stargazers_count;
        }
        if (releaseResponse.ok) {
          const data = await releaseResponse.json();
          if (typeof data.tag_name === "string") release = data.tag_name;
        }
      } catch {
        // Degrade to null values — the corresponding pills stay hidden.
      }
      res.setHeader("Content-Type", "application/json");
      res.end(JSON.stringify({ stars, release }));
    });
  },
};

// https://astro.build/config
export default defineConfig({
  site: "https://secretspec.dev/",
  markdown: {
    remarkPlugins: [preserveHeadingIdPlugin],
  },
  redirects: {
    "/reference/adding-providers": "/development/adding-providers",
    "/ci": "/ci/github-actions",
  },
  vite: {
    plugins: [devGitHubApi],
  },
  integrations: [
    starlight({
      expressiveCode: {
        plugins: [terminalCopyPlugin()],
      },
      plugins: [
        starlightBlog({
          title: "Blog",
          authors: {
            domen: {
              name: "Domen Kožar",
              url: "https://github.com/domenkozar",
            },
          },
        }),
        starlightLlmsTxt({
          description: `SecretSpec is a declarative secrets manager for development workflows. It separates secret **declaration** from secret **storage**: commit a \`secretspec.toml\` that declares what secrets your application needs, while the actual values live in a secure provider (system keyring, 1Password, Vault, etc.).

SecretSpec answers three questions for every project:

- **WHAT** secrets does the application need?
- **HOW** do requirements change per environment (via profiles)?
- **WHERE** are the actual values stored (via providers)?

## Quick Start

1. Initialize: \`secretspec init --from .env\` or create \`secretspec.toml\` manually
2. Set secrets: \`secretspec set DATABASE_URL\`
3. Check status: \`secretspec check\`
4. Run commands with secrets: \`secretspec run -- npm start\`

## Configuration Example

\`\`\`toml
[project]
name = "my-app"
revision = "1.0"

[profiles.default]
DATABASE_URL = { description = "PostgreSQL connection string", required = true }
REDIS_URL    = { description = "Redis cache" }
TLS_CERT     = { description = "TLS cert", as_path = true }
DB_PASSWORD  = { description = "DB password", type = "password", generate = true }

[profiles.development]
DATABASE_URL = { default = "postgresql://localhost/dev" }
\`\`\`

## Composed Secrets (0.16+)

\`composed\` derives a read-only value from other declared secrets with strict,
order-independent \`\${UPPERCASE_NAME}\` references. Names must match
\`[A-Z][A-Z0-9_]*\`; it does not perform dotenv, shell, ambient-environment, or
recursive expansion.

## Type-safe Rust SDK

\`\`\`rust
${rustSdkBasicExample}
\`\`\`

## Migration

Move every secret between providers without changing application code:

\`\`\`bash
$ secretspec import dotenv://.env.production
\`\`\`

## Providers

Values can be resolved from: keyring (default), KeePass KDBX (0.17+), dotenv files, plaintext file directories (0.19+), EJSON files (0.20+, read-only), environment variables, systemd service credentials (0.17+), 1Password, Gopass (0.15+), LastPass, Dashlane (0.18+, read-only), Pass, Proton Pass, Passbolt (0.19+), Keeper Secrets Manager (0.18+), Google Cloud Secret Manager, AWS Secrets Manager, AWS Systems Manager Parameter Store (0.18+), Scaleway Secret Manager (0.17+), HashiCorp Vault, OpenBao (0.17+), Bitwarden Password Manager (0.18+), Bitwarden Secrets Manager, Azure Key Vault, Azure App Configuration (0.20+), Infisical (0.16+), age (0.17+), SOPS (0.17+), or Kubernetes (0.20+). Fly.io application secrets and Cloudflare Secrets Store entries can be published through the write-only fly and cloudflare providers (0.20+). The null provider (0.19+) uses manifest defaults, ephemeral generation, or ephemeral run prompts without storage.`,
        }),
      ],
      title: "SecretSpec",
      head: [
        {
          tag: "meta",
          attrs: {
            property: "og:image",
            content: "https://secretspec.dev/social-card.png",
          },
        },
        {
          tag: "meta",
          attrs: {
            property: "og:image:alt",
            content: "SecretSpec — A declarative interface for every secret provider.",
          },
        },
        {
          tag: "meta",
          attrs: { property: "og:image:width", content: "1200" },
        },
        {
          tag: "meta",
          attrs: { property: "og:image:height", content: "630" },
        },
        {
          tag: "meta",
          attrs: { property: "og:image:type", content: "image/png" },
        },
        {
          tag: "meta",
          attrs: {
            name: "twitter:image",
            content: "https://secretspec.dev/social-card.png",
          },
        },
        {
          tag: "meta",
          attrs: {
            name: "twitter:image:alt",
            content: "SecretSpec — A declarative interface for every secret provider.",
          },
        },
      ],
      components: {
        Hero: "./src/overrides/Hero.astro",
        SocialIcons: "./src/overrides/SocialIcons.astro",
      },
      logo: {
        light: "./src/assets/logo.svg",
        dark: "./src/assets/logo-dark.svg",
        replacesTitle: true,
      },
      tagline: "A declarative interface for every secret provider.",
      social: [
        {
          icon: "github",
          label: "GitHub",
          href: "https://github.com/cachix/secretspec",
        },
        {
          icon: "discord",
          label: "Discord",
          href: "https://discord.gg/naMgvexb6q",
        },
      ],
      customCss: ["./src/styles/custom.css", "./src/styles/landing.css"],
      sidebar: [
        {
          label: "Getting Started",
          items: [
            { label: "Quick Start", slug: "quick-start" },
            { label: "Basic Usage", slug: "basic-usage" },
            { label: "Migration", slug: "migration" },
          ],
        },
        {
          label: "Concepts",
          items: [
            { label: "Overview", slug: "concepts/overview" },
            { label: "Comparison", slug: "comparison" },
            {
              label: "secretspec.toml",
              slug: "concepts/declarative",
            },
            {
              label: "secretspec.toml Inheritance",
              slug: "concepts/inheritance",
            },
            { label: "Profiles", slug: "concepts/profiles" },
            {
              label: "Scopes",
              slug: "concepts/scopes",
              badge: { text: "0.17+", variant: "note" },
            },
            {
              label: "Secret Generation",
              slug: "concepts/generation",
              badge: { text: "0.7+", variant: "note" },
            },
            {
              label: "Composed Secrets",
              slug: "concepts/composed-secrets",
              badge: { text: "0.16+", variant: "note" },
            },
            {
              label: "Secret References",
              slug: "concepts/references",
              badge: { text: "0.14+", variant: "note" },
            },
            {
              label: "Audit Logging",
              slug: "concepts/audit",
              badge: { text: "0.12+", variant: "note" },
            },
            {
              label: "Providers",
              items: [
                { label: "Providers", slug: "concepts/providers" },
                {
                  label: "Provider fallback",
                  slug: "concepts/providers/fallback",
                },
                {
                  label: "Provider caching",
                  slug: "concepts/providers/caching",
                  badge: { text: "0.17+", variant: "note" },
                },
              ],
            },
          ],
        },
        {
          label: "Providers",
          items: [
            { label: "Keyring", slug: "providers/keyring" },
            {
              label: "KeePass KDBX",
              slug: "providers/kdbx",
              badge: { text: "0.17+", variant: "note" },
            },
            { label: "Dotenv", slug: "providers/dotenv" },
            {
              label: "Files",
              slug: "providers/file",
              badge: { text: "0.19+", variant: "note" },
            },
            { label: "Environment Variables", slug: "providers/env" },
            {
              label: "EJSON",
              slug: "providers/ejson",
              badge: { text: "0.20+", variant: "note" },
            },
            {
              label: "Null",
              slug: "providers/null",
              badge: { text: "0.19+", variant: "note" },
            },
            {
              label: "systemd Credentials",
              slug: "providers/systemd-credential",
              badge: { text: "0.17+", variant: "note" },
            },
            {
              label: "Fly.io Secrets",
              slug: "providers/fly",
              badge: { text: "0.20+", variant: "note" },
            },
            {
              label: "Cloudflare Secrets Store",
              slug: "providers/cloudflare",
              badge: { text: "0.20+", variant: "note" },
            },
            { label: "Pass", slug: "providers/pass" },
            { label: "Proton Pass", slug: "providers/protonpass" },
            {
              label: "Passbolt",
              slug: "providers/passbolt",
              badge: { text: "0.19+", variant: "note" },
            },
            { label: "LastPass", slug: "providers/lastpass" },
            {
              label: "Dashlane",
              slug: "providers/dashlane",
              badge: { text: "0.18+", variant: "note" },
            },
            { label: "1Password", slug: "providers/onepassword" },
            {
              label: "Keeper Secrets Manager",
              slug: "providers/keeper",
              badge: { text: "0.18+", variant: "note" },
            },
            {
              label: "Gopass",
              slug: "providers/gopass",
              badge: { text: "0.15+", variant: "note" },
            },
            {
              label: "Google Cloud Secret Manager",
              slug: "providers/gcsm",
            },
            {
              label: "AWS Secrets Manager",
              slug: "providers/awssm",
            },
            {
              label: "AWS Parameter Store",
              slug: "providers/awsps",
              badge: { text: "0.18+", variant: "note" },
            },
            {
              label: "Scaleway Secret Manager",
              slug: "providers/scaleway",
              badge: { text: "0.17+", variant: "note" },
            },
            {
              label: "Vault",
              slug: "providers/vault",
            },
            {
              label: "Bitwarden Password Manager",
              slug: "providers/bw",
              badge: { text: "0.18+", variant: "note" },
            },
            {
              label: "OpenBao",
              slug: "providers/openbao",
              badge: { text: "0.17+", variant: "note" },
            },
            {
              label: "Bitwarden Secrets Manager",
              slug: "providers/bws",
            },
            {
              label: "Azure Key Vault",
              slug: "providers/akv",
              badge: { text: "0.15+", variant: "note" },
            },
            {
              label: "Azure App Configuration",
              slug: "providers/aac",
              badge: { text: "0.20+", variant: "note" },
            },
            {
              label: "Infisical",
              slug: "providers/infisical",
              badge: { text: "0.16+", variant: "note" },
            },
            {
              label: "age",
              slug: "providers/age",
              badge: { text: "0.17+", variant: "note" },
            },
            {
              label: "SOPS",
              slug: "providers/sops",
              badge: { text: "0.17+", variant: "note" },
            },
            {
              label: "Kubernetes",
              slug: "providers/kubernetes",
              badge: { text: "0.20+", variant: "note" },
            },
          ],
        },
        {
          label: "Integrations",
          items: [
            {
              label: "Git credentials",
              slug: "integrations/git",
              badge: { text: "0.20+", variant: "note" },
            },
            {
              label: "Docker credentials",
              slug: "integrations/docker",
              badge: { text: "0.20+", variant: "note" },
            },
            {
              label: "Claude Code",
              slug: "integrations/claude-code",
              badge: { text: "0.21+", variant: "note" },
            },
          ],
        },
        {
          label: "SDK",
          items: [
            {
              label: "Overview",
              slug: "sdk/overview",
            },
            { label: "Rust", slug: "sdk/rust" },
            {
              label: "Python",
              slug: "sdk/python",
              badge: { text: "0.13+", variant: "note" },
            },
            {
              label: "Go",
              slug: "sdk/go",
              badge: { text: "0.13+", variant: "note" },
            },
            {
              label: "Ruby",
              slug: "sdk/ruby",
              badge: { text: "0.13+", variant: "note" },
            },
            {
              label: "Node.js",
              slug: "sdk/nodejs",
              badge: { text: "0.13+", variant: "note" },
            },
            {
              label: "Haskell",
              slug: "sdk/haskell",
              badge: { text: "0.13+", variant: "note" },
            },
            {
              label: "PHP",
              slug: "sdk/php",
              badge: { text: "0.15+", variant: "note" },
            },
            {
              label: "C#",
              slug: "sdk/csharp",
              badge: { text: "0.16+", variant: "note" },
            },
            {
              label: "Swift",
              slug: "sdk/swift",
              badge: { text: "0.18+", variant: "note" },
            },
            {
              label: "JVM",
              slug: "sdk/jvm",
              badge: { text: "0.20+", variant: "note" },
            },
          ],
        },
        {
          label: "CI",
          items: [
            { label: "GitHub Actions", slug: "ci/github-actions" },
          ],
        },
        {
          label: "Reference",
          items: [
            { label: "Configuration", slug: "reference/configuration" },
            { label: "CLI Commands", slug: "reference/cli" },
            { label: "Providers", slug: "reference/providers" },
            {
              label: "Provider credentials",
              slug: "reference/provider-credentials",
              badge: { text: "0.15+", variant: "note" },
            },
          ],
        },
        {
          label: "Development",
          items: [
            {
              label: "Adding a Provider",
              slug: "development/adding-providers",
            },
            {
              label: "Adding an SDK",
              slug: "development/sdks",
            },
          ],
        },
      ],
    }),
  ],
});
