// @ts-check
import { defineConfig } from "astro/config";
import starlight from "@astrojs/starlight";

// https://astro.build/config
export default defineConfig({
  integrations: [
    starlight({
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
            {
              label: "Declarative Configuration",
              slug: "concepts/declarative",
            },
            { label: "Profiles", slug: "concepts/profiles" },
            { label: "Providers", slug: "concepts/providers" },
          ],
        },
        {
          label: "Providers",
          items: [
            { label: "Keyring", slug: "providers/keyring" },
            { label: "Dotenv", slug: "providers/dotenv" },
            { label: "Environment Variables", slug: "providers/env" },
            { label: "Infisical", slug: "providers/infisical" },
            { label: "LastPass", slug: "providers/lastpass" },
            { label: "1Password", slug: "providers/onepassword" },
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
