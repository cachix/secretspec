---
title: Adding an Integration
description: Choose a mechanism for making an external tool read secrets from SecretSpec, then build it
---

An integration lets a tool that is not SecretSpec read its secrets from a
SecretSpec provider, instead of keeping a second copy in that tool's own store.
[Git credentials](/integrations/git/) is the first one SecretSpec ships.

There is no single way to build one. Which mechanism fits depends on how the
tool takes input, whether you can change its source, and whether it needs a
value once at startup or repeatedly while it runs. Pick from the table, then
read the matching section.

## Choose a mechanism

| Mechanism | Use when | You write | Ships in |
| --- | --- | --- | --- |
| [Environment injection](#environment-injection) | The tool reads environment variables or a file path | Nothing | Available today |
| [An SDK](#link-an-sdk) | You control the tool's source and can link a library | Calls into the SDK | Available today |
| [IPC](#resolve-over-ipc) | A separate program needs on-demand resolution, prompting, or write-back, and must not link SecretSpec | A protocol client | 0.20+ |
| [An in-tree integration](#ship-an-integration-inside-secretspec) | The tool speaks its own credential or helper protocol, and the integration should ship with SecretSpec | A module and a shim binary | 0.20+ |

Work down the list. Environment injection costs nothing and covers most tools,
so reach past it only when something concrete rules it out: the tool needs a
value it did not have at startup, it must not hold the value in its
environment for its whole lifetime, or it has a credential protocol of its own
that expects to be asked.

## Environment injection

The shortest path. `secretspec run` resolves the profile and executes the tool
with the values in its environment:

```bash
$ secretspec run -- terraform apply
```

Narrow what the tool receives with a [scope](/concepts/scopes/), so a single
manifest can serve several tools without handing each one everything:

```bash
$ secretspec run --scope deploy -- terraform apply
```

For a tool that wants a file rather than a variable, declare the secret with
`as_path = true` and it receives a path to a resolver-owned temporary file.

This mechanism resolves once, before the tool starts. It cannot re-resolve a
rotated value, ask a person for input mid-run, or write a value back. When one
of those matters, keep reading.

## Link an SDK

If you own the tool's source, link SecretSpec directly rather than wrapping it.
The SDK resolves on demand inside the process, with no subprocess and no
protocol to implement. See the [SDK overview](/sdk/overview/) for the available
languages and how each one ships.

This is the right answer for your own applications. It is the wrong answer for
a third-party tool you do not control, and for any consumer that must not take
on SecretSpec's dependency closure.

## Resolve over IPC

:::caution[Version compatibility]
`secretspec serve`, the IPC libraries, and protocol version 1 are available
starting with SecretSpec 0.20.
:::

IPC covers the case the other two cannot: a separate, long-lived program that
resolves names while it runs, without linking SecretSpec or any provider SDK.

The consumer launches [`secretspec serve`](/reference/cli/#serve-020) as a
child process and speaks the
[Secret Resolution Protocol](/reference/resolver-protocol/) over its standard
input and output. A session is bound at initialization to one manifest,
provider, profile, scope, and access reason, and from then on resolves one
exact declared name at a time. That bound scope is what makes IPC safe to hand
to a consumer you would not hand a whole profile.

Beyond resolution, a session can:

- return a resolver-owned file path under an explicit lease, for a value that
  should not pass through an environment variable;
- ask the launching process for a value through the `client.prompt` callback,
  since the resolver has no terminal of its own;
- store or remove one declared name with `resolver.set` and `resolver.delete`,
  for a tool such as `cargo login` that authenticates and then wants to keep
  the result;
- report a rejected value with `resolver.reject`, so a credential revoked at
  its issuer is dropped from the cache instead of served until it expires.

Each of those beyond plain resolution is advertised as a capability, so a
client can tell an older endpoint apart from one that refused a particular
request. Launch with `secretspec serve --read-only` when the consumer must
never cause a write.

You have three ways to write the client:

| Client | Language | Notes |
| --- | --- | --- |
| `secretspec-ipc` | Rust | Async by default; its `blocking` feature gives a synchronous session for a program with no async runtime |
| `libsecretspec-resolver` | C11 | Portable source plus static and shared libraries, with no Rust in its dependency closure |
| Your own | Any | Implement the [wire protocol](/reference/ipc-wire/) directly |

Read the [IPC architecture](/reference/ipc-architecture/) first for the trust
boundaries, then the protocol pages for the contract.

:::note[Integrating a secret store, not a consumer]
If the thing you are connecting *holds* secrets rather than consuming them, you
want the [Secret Provider Protocol](/reference/provider-protocol/) or a native
[provider](/development/adding-providers/), not an integration. The distinction
is direction: a provider answers SecretSpec, an integration asks it.
:::

## Ship an integration inside SecretSpec

:::caution[Version compatibility]
The integration module layout described here is available starting with
SecretSpec 0.20.
:::

Some tools already define how they ask for a credential. Git invokes a helper
binary and exchanges attributes with it on stdin and stdout; other tools have
their own equivalents. For those, the integration belongs inside SecretSpec, so
a user installs one thing and configures it with `secretspec`.

Integrations live in `secretspec/src/integration/`. Read
`integration/git.rs` alongside this section: it is the worked example, and it
is the only one so far.

### 1. Embed a manifest

An integration must not depend on the current working directory. A user running
`git push` from any directory expects the same credential, so the integration
carries its own manifest rather than discovering one:

```rust
const EMBEDDED_MANIFEST: &str = include_str!("git-credentials.toml");
```

Keep it small. The Git manifest declares exactly two secrets, a required
`PASSWORD` and an optional `USERNAME`, and sets `require_reason = false`
because the tool invoking the helper cannot supply a reason.

### 2. Derive a stable identity

One embedded manifest usually has to serve many targets: several Git hosts,
several accounts on one host. Derive an identity from the canonical attributes
of the target and use it to isolate values.

Rewrite the project name *and* suffix the key names:

```rust
config.project.name = format!("git-credential-{identity}");
let password_secret = format!("{EMBEDDED_PASSWORD}_{identity}");
```

Both are necessary. Some providers flatten a convention address to the logical
key and ignore project and profile entirely, so an identity carried only in the
project name would collapse every target onto one value in those stores.

Canonicalize before hashing, so that equivalent spellings of the same target
select the same credential and genuinely different targets never collide.

### 3. Add the shim binary

Register the binary the tool will invoke in `secretspec/Cargo.toml`:

```toml
[[bin]]
name = "git-credential-secretspec"
path = "src/bin/git-credential-secretspec.rs"
required-features = ["cli"]
```

Keep it a thin entry point that delegates into the integration module, and
match the primary CLI's behavior for the environment it runs in. The Git shim
restores default `SIGPIPE` handling so it exits quietly when its output pipe
closes.

### 4. Add CLI subcommands

The shim serves the tool. A `secretspec <tool>` subcommand group serves the
person, and should cover the whole lifecycle:

```bash
$ secretspec git configure --url https://github.com --username YOUR_USERNAME
$ secretspec git login https://github.com
$ secretspec git logout https://github.com
$ secretspec git unconfigure --url https://github.com
```

Where the integration writes into the tool's own configuration, treat that file
as shared. Register alongside existing entries rather than replacing them,
write durably, preserve symlinks, and leave recoverable state when removal
fails partway.

### 5. Document it

Add `docs/src/content/docs/integrations/<tool>.md`, then add it to the
`Integrations` group in `docs/astro.config.ts`. State what the integration does
not cover: the Git page says up front that it does not manage SSH keys or
inject secrets into repositories, which saves a reader from discovering that
later.

Mark every new command, field, and page with its target version, as described
in the [release visibility checklist](/development/adding-providers/#documentation-and-release-visibility).
