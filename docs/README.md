# Monosecret documentation

This directory contains the Astro + Starlight documentation site for Monosecret.

## Local development

From the repository root:

```bash
pnpm install
pnpm --filter docs run dev
```

Or with the project development environment:

```bash
devenv shell build:docs
```

## Build

```bash
pnpm --filter docs run build
```

The production site is emitted to `docs/dist`.

## Deployment

`.github/workflows/docs.yml` builds this site and deploys `docs/dist` to GitHub Pages
on pushes to `main`. Pull requests run the same build without deploying.
