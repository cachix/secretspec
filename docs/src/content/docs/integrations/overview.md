---
title: Integrations
description: Connect SecretSpec to SSH, CI systems, development environments, containers, and deployment workflows
---

Integrations connect SecretSpec's resolved secrets to the tools that use them.
They are different from [providers](/concepts/providers/), which decide where
values are stored, and [SDKs](/sdk/overview/), which load secrets directly into
application code.

## Integration guides

| Integration | Use it for | Guide |
|-------------|------------|-------|
| SSH / OpenSSH (0.19+) | Give SSH and Git access to provider-backed private keys without writing key files | [SSH agent (0.19+)](/integrations/ssh-agent/) |
| GitHub Actions and Forgejo Actions | Resolve, mask, and export a profile for later workflow steps | [GitHub Actions](/integrations/github-actions/) |
| devenv and Nix | Resolve a selected provider and profile into development shells, services, and processes | [devenv integration](https://devenv.sh/integrations/secretspec/) |

## Command and export interoperability

Tools without a dedicated integration can use one of SecretSpec's general
handoff boundaries:

- [`secretspec run`](/reference/cli/#run) gives one child process a resolved
  environment and removes scope-excluded secret variables inherited from the
  parent.
- [`secretspec export`](/reference/cli/#export) emits shell, dotenv, JSON, or
  GitHub Actions output for tools that cannot be wrapped directly.
- [`secretspec ssh-agent` (0.19+)](/integrations/ssh-agent/) exposes typed SSH
  keys through the agent protocol instead of environment variables or files.

For Docker, pass selected host variables explicitly into the container:

```bash
$ secretspec run -- docker run --rm --env DATABASE_URL --env API_KEY my-app
```

For Docker Compose, declare the variables under a service's `environment`
section, then run Compose through SecretSpec:

```yaml title="compose.yaml"
services:
  app:
    image: my-app
    environment:
      DATABASE_URL:
      API_KEY:
```

```bash
$ secretspec run -- docker compose up
```

For Kubernetes, transform a structured
[`secretspec export --format json`](/reference/cli/#export) stream into a
`Secret` manifest and send it directly to `kubectl`. SecretSpec does not create
Kubernetes objects itself:

```bash
$ secretspec export --profile production --format json | \
    jq '{apiVersion: "v1", kind: "Secret", metadata: {name: "my-app"}, type: "Opaque", stringData: .}' | \
    kubectl apply -f -
```

Keep transformations in the pipe rather than writing plaintext intermediate
files. Avoid putting secret values directly in command-line arguments, where
process listings and shell history can expose them.

## Choose the right extension point

- Add or configure a **provider** when SecretSpec needs to read or write a
  storage backend.
- Use an **SDK** when application code should receive a typed SecretSpec
  configuration directly.
- Use an **integration** when an external tool, shell, CI runner, or deployment
  workflow needs SecretSpec-managed values or signing capabilities.
