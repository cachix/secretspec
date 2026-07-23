# Cross-language conformance suite

Every SecretSpec SDK (Python, Go, Ruby, Node.js, Haskell, C#, and PHP) is a thin
client over the same resolver contract. This suite proves they agree: each SDK
resolves the same fixtures and must produce the identical **canonical** result.

## Fixtures

Each directory under `fixtures/` is one case:

- `secretspec.toml` — the manifest
- `.env` — backing values (resolved via the `dotenv` provider)
- `expected.json` — the canonical result every SDK must produce

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
    "<NAME>": { "value": "<value, or file contents for as_path>",
                "source": "provider|generated|default",
                "as_path": false }
  },
  "missing_required": [],
  "missing_optional": ["<sorted names>"]
}
```

For `as_path` secrets, `value` is the **contents** of the materialized file, so
the comparison is deterministic and meaningful across languages.

## Running

Run everything with the aggregate runner (inside the project devenv shell). It
builds the `secretspec-ffi` library once, points the runtime-loading SDKs at the
cdylib via `SECRETSPEC_FFI_LIB` and stages the staticlib for the SDKs that link
it (Haskell), runs each language's conformance suite, and prints a combined
PASS/FAIL/SKIP summary (exiting non-zero if any language fails):

```sh
devenv shell -- bash conformance/run.sh
```

Or run a single language in its own native runner, reading this directory
relative to the repo root:

- Python: `cd secretspec-py && pytest`
- Go: `cd secretspec-go && go test ./...`
- Ruby: `cd secretspec-rb && ruby test/test_resolve.rb`
- Node: `cd secretspec-node && node --test`
- Haskell: `cd secretspec-hs && cabal test` (needs the `secretspec-ffi`
  staticlib staged on `--extra-lib-dirs`; see the Haskell SDK build steps)
- C#: `cd secretspec-dotnet && dotnet run --project tests/SecretSpec.Tests`
- PHP: `cd secretspec-php && ./vendor/bin/phpunit tests/ConformanceTest.php`
