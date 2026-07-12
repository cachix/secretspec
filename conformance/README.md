# Cross-language conformance suite

Every native-backed Monosecret SDK uses the same Rust resolver contract. Dart,
Go, Ruby, and Haskell call the `monosecret_ffi` C ABI; Python's pyo3 extension
and the Node.js napi-rs addon call the Rust resolver directly. This suite proves
they agree: each SDK resolves the same fixtures and must produce the identical
**canonical** result.

## Fixtures

Each directory under `fixtures/` is one case:

- `monosecret.toml` — the manifest
- `.env` — backing values (resolved via the `dotenv` provider)
- `expected.json` — the canonical value-carrying result
- `expected_no_values.json` — the value-free resolve result
- `expected_report.json` — the canonical resolution report

Fixtures only cover successful resolutions; per-SDK test suites cover error
behavior (missing-required, invalid input).

## Canonical form

Environmental details (the absolute `dotenv://` path, `as_path` temp-file paths)
are not comparable across runs, so each SDK projects its resolved result to a
canonical shape before comparing:

```json
{
  "profile": "<active profile>",
  "secrets": {
    "<NAME>": {
      "value": "<value, or file contents for as_path>",
      "source": "provider|generated|default",
      "as_path": false
    }
  },
  "missing_required": [],
  "missing_optional": ["<sorted names>"]
}
```

For `as_path` secrets, `value` is the **contents** of the materialized file, so
the comparison is deterministic and meaningful across languages.

## Running

Run everything with the aggregate runner (inside the project devenv shell). It
builds `monosecret_ffi`, points Go at the cdylib via `MONOSECRET_FFI_LIB`,
stages the staticlib for Ruby and Haskell, builds the Python and Node.js native
extensions, runs each language's conformance suite, and prints a combined
PASS/FAIL/SKIP summary (exiting non-zero if any language fails):

```sh
devenv shell -- bash conformance/run.sh
```

Or run a single language in its own native runner, reading this directory
relative to the repo root:

- Dart: `melos exec --scope monosecret -- dart test test/conformance_test.dart`
- Python: `cd python/monosecret_py && pytest`
- Go: `cd go/monosecret_go && go test ./...`
- Ruby: `cd ruby/monosecret_rb && ruby test/test_resolve.rb`
- Node: `pnpm --filter @monosecret/client run build:native && pnpm --filter @monosecret/client test`
- Haskell: `cd haskell/monosecret_hs && cabal test` (needs the `monosecret_ffi`
  staticlib staged on `--extra-lib-dirs`; see the Haskell SDK build steps)
