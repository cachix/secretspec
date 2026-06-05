---
title: "SecretSpec 0.12: audit logs and coding agents"
description: Require a human-readable reason whenever a coding agent reaches for your secrets.
date: 2026-06-08
authors:
  - domen
---

A coding agent reaches for the same secrets you do, but on its own initiative and
many times a session: a read looks identical whether it came from you running a
deploy or an agent exploring the codebase.

[SecretSpec 0.12](https://github.com/cachix/secretspec/releases/tag/v0.12.0 "SecretSpec 0.12 release")
makes that access accountable. It ships three things:

- **Audit log** — every secret read and write is appended to a local,
  per-user JSONL log. On by default. Values are never recorded.
- **Reason-on-access** — secret access can require a human-readable reason,
  enforced for coding agents by default.
- **`secretspec audit` command** — filter and summarize the log, or pipe raw
  JSON Lines to `jq`.

:::caution[Behavior change in 0.12]
If you run SecretSpec inside a coding agent, secret access now **fails** until a
reason is supplied. This is the new default (`require_reason = "agents"`). Opt
out with `require_reason = false` in the `[project]` table. Existing providers
and library callers keep working unchanged. See [Upgrading](#upgrading).
:::

## The audit log

Every secret read and write, from the CLI and the Rust SDK, is appended to a
local log as [JSON Lines](https://jsonlines.org/), one event per line. Secret
**values are never written**, only metadata: the secret name, the profile, the
provider that served it (with any embedded credentials redacted), the outcome,
the reason, and who was asking, including the detected coding agent.

```json
{
  "v": 1,
  "ts": "2026-06-04T17:04:00.893Z",
  "action": "get",
  "project": "my-app",
  "profile": "production",
  "key": "DATABASE_URL",
  "provider": "keyring://",
  "outcome": "found",
  "reason": "deploy web frontend",
  "actor": { "user": "alice", "agent": "claude-code", "is_agent": true },
  "version": "0.12.0"
}
```

The log lives in your per-user state directory
(`~/.local/state/secretspec/audit.log`) and is created readable only by you. Read
it with any tool, or use the new `secretspec audit` command for filtering and a
readable summary:

```bash
# Last 20 entries, formatted
secretspec audit -n 20

# Only `run` events for one project
secretspec audit --project my-app --action run

# Raw JSON Lines, piped to jq
secretspec audit --json | jq 'select(.outcome == "missing")'
```

It is configured in your **user-global config**
(`~/.config/secretspec/config.toml`), not the project's `secretspec.toml`, so a
repository you clone can't quietly turn off or redirect your audit log. The log is
a single file capped at 1 MiB, a size-bounded recent record rather than permanent
compliance history; forward it to a central system if you need that. To turn it
off entirely:

```toml
# ~/.config/secretspec/config.toml
[audit]
enabled = false
```

See [Audit Logging](/concepts/audit/) for the full record schema and options.

## Supplying a reason

When a coding agent like Claude Code reaches for a secret without a reason, the
access is refused and the agent is told exactly what to do next:

```text
$ secretspec run -- npm test
Error: Accessing secrets requires a reason. Provide one with --reason
"<why you are accessing these secrets>", the SECRETSPEC_REASON environment
variable, or Secrets::with_reason() in the SDK. (Policy: require_reason in
[project] of secretspec.toml — defaults to "agents"; set it to false to
disable.)
```

Claude Code reads that message, states why it needs the secret, and retries:

```bash
secretspec run --reason "run the test suite before opening a PR" -- npm test
```

Both the refusal and the successful retry land in the audit log, so the reason
is tied to the access. There are three ways to supply a reason:

| Source | Scope | Precedence |
|---|---|---|
| `--reason` flag | CLI | highest |
| `Secrets::with_reason()` | SDK | overrides env |
| `SECRETSPEC_REASON` | CLI + SDK + derive | lowest |

```bash
# CLI: the most explicit option, overrides the others
secretspec run --reason "deploying release 0.12" -- ./deploy.sh
```

```rust
// SDK: the programmatic equivalent of --reason
let secrets = Secrets::load(/* ... */)?.with_reason("nightly backup job");
```

```bash
# Env: lowest precedence, but honored everywhere
export SECRETSPEC_REASON="nightly backup job"
```

`SECRETSPEC_REASON` is resolved by `Secrets::load` / `load_from`, which means
`secretspec-derive`-generated code and other library callers satisfy the policy
and supply an audit reason **without any code changes**.

Whichever path you use, blank or whitespace-only reasons are ignored, so they
can't quietly satisfy the policy. Under the hood this is backed by a new
`Provider::set_reason` trait method (a no-op by default), so existing providers
keep working unchanged.

## Configuring when a reason is required

The new `require_reason` policy in the `[project]` table controls when a reason
is mandatory:

```toml
[project]
name = "my-app"
require_reason = "agents"  # require it from agents (default), or true / false
```

- `"agents"` (the default): require a reason only when a coding agent is detected.
- `true`: require it from every caller.
- `false`: never require it.

Because the policy lives in `secretspec.toml` and is enforced by SecretSpec, it
applies to everyone and every CI runner, and is inherited through `extends`.
Coding agents are spotted by the
[`detect-coding-agent`](https://crates.io/crates/detect-coding-agent) crate
(Claude Code, Cursor, Codex, Gemini CLI, Copilot, and more); set
`SECRETSPEC_AGENT` for a harness it doesn't recognize.

## Upgrading

```bash
cargo install secretspec
```

Remember the new default: agents must pass a reason: set `require_reason = false`
to opt out.

Questions or feedback? Join us on [Discord](https://discord.gg/naMgvexb6q).
