---
"rust:monosecret": feat
---

# Sync upstream secretspec 0.12.2: pass store_dir and the audit CLI command

Merge upstream/main through 0.12.2.

- Restore the `monosecret audit` CLI command (`show_audit_log`,
  `filter_audit_entries`, `sanitize_field`, `format_audit_line`) that was
  dropped during the rebrand merge, plus the `audit` field on `GlobalConfig`
  so the log path can be resolved from the user-global `[audit]` config.
- port the `pass` provider `store_dir` query parameter
  (`PASSWORD_STORE_DIR` scoped per invocation) and the shared
  `query_value` / `encode_query` / `QUERY_ENCODE_SET` helpers so query
  values round-trip through form-urlencoded parsing (awssm `prefix` too).
