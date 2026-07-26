---
title: Audit Logging
description: A local, append-only record of every secret access for after-the-fact review
---

secretspec records every secret access to a local audit log so you can review,
after the fact, **what** secret was accessed, **when**, by **whom**, with what
**reason**, and what the **outcome** was. Auditing is **on by default**.

Secret values are never written to the log. Only metadata is recorded, and any
credentials embedded in a provider URI are redacted.

## Where the log lives

By default the log is written to the per-user state directory, one entry per line
in [JSON Lines](https://jsonlines.org/) format:

| Platform | Default path |
|----------|--------------|
| Linux | `~/.local/state/secretspec/audit.log` |
| macOS | `~/.local/state/secretspec/audit.log` |

(secretspec follows the XDG state-directory convention on macOS too, matching
where it keeps its config, so the path is the same as on Linux. Set `[audit]
path` to override it.)

The file is created with owner-only permissions (`0600` on Unix), inside an
owner-only directory (`0700`). The first time
secretspec writes to it, it prints a one-time note telling you where the log is
and how to turn it off.

## What a record looks like

```json
{
  "v": 1,
  "id": "386987e6-291f-4e8f-a08b-73db9d80897b",
  "ts": "2026-06-04T17:04:00.893Z",
  "session_id": "d59e0f0f-ed2f-456f-a2b6-be25a24b7ec7",
  "seq": 0,
  "action": "get",
  "project": "my-app",
  "profile": "production",
  "key": "DATABASE_URL",
  "provider": "keyring://",
  "outcome": "found",
  "reason": "deploy web frontend",
  "actor": { "user": "alice", "agent": "claude-code", "is_agent": true },
  "version": "0.11.0"
}
```

| Field | Meaning |
|-------|---------|
| `v` | Schema version of the record |
| `id` | Unique id for this event |
| `ts` | RFC 3339 UTC timestamp |
| `session_id` | Shared by every event from one `secretspec` invocation |
| `seq` | Monotonic sequence within that invocation |
| `action` | The operation: `get`, `set`, `check`, `run`, `import`, or `export` |
| `project` / `profile` | The project and profile in effect |
| `scope` | The named scope for a scoped `check`, `run`, or `export`; omitted otherwise (SecretSpec 0.17+) |
| `key` | The secret name for single-secret actions (`get`/`set`); never its value |
| `keys` | The set of secret names for bulk actions (`check`/`run`/`import`/`export`) |
| `command` | For `run`, the executed program (argv[0] only — never its arguments, which may contain secrets) |
| `provider` | The provider URI that served the access, with credentials redacted |
| `outcome` | `found`, `missing`, `default`, `written`, `started` (a `run` launched its command), or `error` |
| `error_kind` | A non-sensitive tag when `outcome` is `error` |
| `reason` | The reason supplied via `--reason` / `SECRETSPEC_REASON` / the SDK, if any |
| `actor` | The OS user, the detected coding agent (if any), and whether this is an agent session |

This pairs naturally with the [`require_reason`](/reference/configuration/#requiring-a-reason-for-secret-access)
policy: the policy makes callers state *why* they need a secret, and the audit
log records that reason alongside the access.

## Reading the log

The log is plain JSON Lines, so any tool works (`cat`, `tail -f`, `jq`). The
[`secretspec audit`](/reference/cli/#audit) command reads it for you with filters
and a readable summary:

```bash
# Last 20 entries, formatted
secretspec audit -n 20

# Only `run` events for one project
secretspec audit --project my-app --action run

# Raw JSON Lines, piped to jq
secretspec audit --json | jq 'select(.outcome == "missing")'
```

## Size cap

The log is a single file capped at **1 MiB** by default. When it reaches the cap
it is truncated and started fresh, so disk usage stays bounded without any log
rotation to manage. This makes the log a size-bounded recent record rather than a
complete, permanent history — it is not intended to satisfy long-term compliance
retention on its own. Forward it to a central system if you need that.

## Reliability

Auditing never blocks secret access. If the log cannot be written (for example, a
read-only filesystem), secretspec prints a `warning:` to stderr and continues —
your `get`, `set`, and `run` still work.

## Configuration

Auditing is a per-machine concern, so it is configured in your **user-global
config** (`~/.config/secretspec/config.toml`) under the top-level `[audit]` table —
not in the project's `secretspec.toml`. This means a repository you clone cannot
turn off or redirect your audit log. See the
[configuration reference](/reference/configuration/#audit-logging) for all options.
To turn it off:

```toml title="~/.config/secretspec/config.toml"
[audit]
enabled = false
```
