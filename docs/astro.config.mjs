// @ts-check
import { defineConfig } from "astro/config";
import starlight from "@astrojs/starlight";
import starlightLlmsTxt from "starlight-llms-txt";

// https://astro.build/config
export default defineConfig({
  site: "https://secretspec.dev/",
  integrations: [
    starlight({
      plugins: [
        starlightLlmsTxt({
          description: `SecretSpec is a declarative secrets manager for development workflows. Define secrets in \`secretspec.toml\`, then use the CLI to manage them.

## Quick Start

1. Initialize: \`secretspec init --from .env\` or create \`secretspec.toml\` manually
2. Set secrets: \`secretspec set DATABASE_URL\`
3. Check status: \`secretspec check\`
4. Run commands with secrets: \`secretspec run -- npm start\`

## Configuration Example

\`\`\`toml
[profiles.default]
DATABASE_URL = { description = "PostgreSQL connection string" }
API_KEY = { description = "External API key" }
\`\`\`

## Providers

Secrets can be stored in: keyring (default), dotenv files, environment variables, 1Password, LastPass, Pass, Google Cloud Secret Manager, AWS Secrets Manager, or HashiCorp Vault / OpenBao.`,
        }),
      ],
      title: "SecretSpec",
      logo: {
        src: "./src/assets/logo.png",
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
      customCss: ["./src/styles/custom.css"],
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
            { label: "Secret Generation", slug: "concepts/generation" },
          ],
        },
        {
          label: "Providers",
          items: [
            { label: "Keyring", slug: "providers/keyring" },
            { label: "Dotenv", slug: "providers/dotenv" },
            { label: "Environment Variables", slug: "providers/env" },
            { label: "Pass", slug: "providers/pass" },
            { label: "LastPass", slug: "providers/lastpass" },
            { label: "1Password", slug: "providers/onepassword" },
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
          ],
        },
        {
          label: "SDK",
          items: [{ label: "Rust SDK", slug: "sdk/rust" }],
        },
        {
          label: "Reference",
          items: [
            { label: "Configuration", slug: "reference/configuration" },
            { label: "CLI Commands", slug: "reference/cli" },
            { label: "Providers", slug: "reference/providers" },
            { label: "Adding Providers", slug: "reference/adding-providers" },
          ],
        },
      ],
    }),
  ],
});
