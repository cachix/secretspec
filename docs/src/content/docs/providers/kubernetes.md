---
title: Kubernetes Provider
description: Kubernetes ConfigMap & Secerts
---

The [Kubernetes](https://kubernetes.io/) provider reads from and writes to
Kubernetes ConfigMaps or Secrets.

:::caution[Version compatibility]
The `kubernetes` provider is added in SecretSpec 0.20.
:::

# At a glance
| | |
| --- | --- |
| Provider | `kubernetes` |
| URI | `k8s+<configmap\|secret>://NAME[@NAMESPACE]` |
| Access | Read and write |
| Best for | Accessing values stores in Kubernetes |
| Authentication | Current cluster set in kubectl configuration |
| Default storage | `secretspec--{project}--{profile}--{key}` |

## Quick start

```bash
# Set a secret
$ secretspec set DATABASE_URL --provider k8s+secret://secret-name
Enter value for DATABASE_URL: postgresql://localhost/mydb
✓ Secret DATABASE_URL saved to kubernetes

# Get a secret
$ secretspec get DATABASE_URL --provider k8s+secret://secret-name
postgresql://localhost/mydb

# Run with secrets
$ secretspec run --provider k8s+secret://secret-name -- npm start
```

## Setup

### Prerequisites

- A Kubernetes cluster
- Cluster connection configured in `$KUBECONFIG` (or `$HOME/.kube/config` as
  fallback)
- Build with `--features kubernetes`

### Authentication

Uses whatever authentication method is configured in the cluster configuration
used by kubectl.

## Configuration

### URI format

```
k8s+KIND://NAME[@NAMESPACE]
```

- `NAME`: Name of the Kubernetes object
- `KIND`: Kind of the Kubernetes object. Only supports `configmap` or `secret`.
- `NAMESPACE`: Optional namespace where the Kubernetes object exists in. If
  omitted, will use the cluster's default namespace.

### URI examples

```
k8s+configmap://db-config@db-postgres
k8s+configmap://db-config
k8s+secret://db-credentials@db-postgres
```

### Project configuration

```toml title="secretspec.toml"
[providers]
kube = "k8s+configmap://db-config@db-postgres"

[profiles.default]
DATABASE_URL = { description = "Database URL", providers = ["kube"] }
```

## Storage model

Each secret is stored as a key in the Kubernetes ConfigMap or Secret. Each
secret is stored as `secretspec--{project}--{profile}--{key}` under `.data`. A
key cannot exceed 253 characters. Each component can only contain alphanumeric
characters, underscores, periods, and internal hyphens. SecretSpec joins the
project, profile, and key with validated `--` boundaries. Distinct logical
addresses therefore cannot collapse onto one GCSM secret when a project or
profile contains a single internal hyphen. As a consequence, a component cannot
start or end with `-` or contain `--`, because those forms could overlap a
boundary.

## Use existing secrets

A secret's [`ref`](/reference/configuration/#secret-references) field names an
existing secret instead: `item` is the secret name stored in `.data.item` of
the Kubernetes object. Reads and writes target that entry in place.

```toml
[profiles.default]
API_TOKEN = { description = "Token", ref = { item = "com.example.app" }, providers = ["k8s+secret://app-config"] }
```
