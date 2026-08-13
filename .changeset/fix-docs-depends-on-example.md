---
"rust:monosecret": docs
---

# Fix the `depends_on` docs example and validate docs snippets

The `depends_on` example in the configuration reference used a
`service_token = { secret = "..." }` shape that did not deserialize into
`ProviderDependency`, so anyone copying it hit a parse error. Use the correct
`secret = "..."` form, make the example a complete copy-pasteable config, and
document the optional `as` field for injecting a dependency under a different
env-var name.

Add an integration test (`docs_snippets`) that scans the docs for TOML snippets
marked with an invisible `<!-- monosecret-test: ... -->` marker and parses /
validates them against the `Config`, `GlobalConfig`, and `Project` schemas, so
reference examples can't silently drift from the schema again. The harness is
opt-in (no false positives on partial snippets) and a no-op when the docs tree
isn't present.
