import type {PluginOption} from "vite";
import { defineConfig } from "astro/config";
import starlight from "@astrojs/starlight";
import starlightLlmsTxt from "starlight-llms-txt";
import starlightBlog from "starlight-blog";

// Dev-only: `astro dev` (what `devenv up` runs) does not execute worker.js, so
// /api/stars would 404 and the star pill would stay hidden locally. Mirror the
// worker's GitHub proxy here so the pill populates during local development.
// Production is unaffected — it is served by worker.js.
const devStarsApi: PluginOption = {
  name: "dev-stars-api",
  apply: "serve",
  enforce: "pre",
  configureServer(server) {
    server.middlewares.use("/api/stars", async (_req, res) => {
      let stars = null;
      try {
        const r = await fetch("https://api.github.com/repos/cachix/secretspec", {
          headers: { "User-Agent": "secretspec-docs" },
        });
        if (r.ok) {
          const data = await r.json();
          if (typeof data.stargazers_count === "number") stars = data.stargazers_count;
        }
      } catch {
        // Degrade to { stars: null } — the pill simply stays hidden.
      }
      res.setHeader("Content-Type", "application/json");
      res.end(JSON.stringify({ stars }));
    });
  },
};

// https://astro.build/config
export default defineConfig({
  site: "https://secretspec.dev/",
  redirects: {
    "/reference/adding-providers": "/development/adding-providers",
  },
  vite: {
    plugins: [devStarsApi],
  },
  integrations: [
    starlight({
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
secretspec_derive::declare_secrets!("secretspec.toml");

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let secrets = Secrets::builder()
        .with_provider("keyring")
        .with_profile(Profile::Production)
        .load()?;
    println!("{}", secrets.secrets.database_url);
    secrets.secrets.set_as_env_vars();
    Ok(())
}
\`\`\`

## Migration

Move every secret between providers without changing application code:

\`\`\`bash
$ secretspec import dotenv://.env.production
\`\`\`

## Providers

Secrets can be stored in: keyring (default), dotenv files, environment variables, 1Password, Gopass (0.15+), LastPass, Pass, Proton Pass, Google Cloud Secret Manager, AWS Secrets Manager, HashiCorp Vault / OpenBao, Bitwarden Secrets Manager, Azure Key Vault, or Infisical (0.16+).`,
        }),
      ],
      title: "SecretSpec",
      components: {
        Hero: "./src/overrides/Hero.astro",
        SocialIcons: "./src/overrides/SocialIcons.astro",
      },
      logo: {
        light: "./src/assets/logo.png",
        dark: "./src/assets/logo-dark.png",
        replacesTitle: true,
      },
      tagline: "Declarative secrets for development workflows",
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
          items: [{ label: "Quick Start", slug: "quick-start" }],
        },
        {
          label: "Concepts",
          items: [
            { label: "Overview", slug: "concepts/overview" },
            {
              label: "Declarative Configuration",
              slug: "concepts/declarative",
            },
            { label: "Profiles", slug: "concepts/profiles" },
            { label: "Providers", slug: "concepts/providers" },
            {
              label: "Configuration Inheritance",
              slug: "concepts/inheritance",
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
          ],
        },
        {
          label: "Providers",
          items: [
            { label: "Keyring", slug: "providers/keyring" },
            { label: "Dotenv", slug: "providers/dotenv" },
            { label: "Environment Variables", slug: "providers/env" },
            { label: "Pass", slug: "providers/pass" },
            { label: "Proton Pass", slug: "providers/protonpass" },
            { label: "LastPass", slug: "providers/lastpass" },
            { label: "1Password", slug: "providers/onepassword" },
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
              label: "Vault / OpenBao",
              slug: "providers/vault",
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
              label: "Infisical",
              slug: "providers/infisical",
              badge: { text: "0.16+", variant: "note" },
            },
          ],
        },
        {
          label: "SDK",
          items: [
            {
              label: "Overview",
              slug: "sdk/overview",
              badge: { text: "0.13+", variant: "note" },
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
          ],
        },
        {
          label: "Reference",
          items: [
            { label: "Configuration", slug: "reference/configuration" },
            { label: "CLI Commands", slug: "reference/cli" },
            { label: "Providers", slug: "reference/providers" },
          ],
        },
        {
          label: "Development",
          items: [
            {
              label: "Adding Providers",
              slug: "development/adding-providers",
            },
            {
              label: "SDK Development",
              slug: "development/sdks",
            },
          ],
        },
      ],
    }),
  ],
});
