---
title: Haskell SDK
description: Resolve SecretSpec secrets from Haskell
---

The Haskell SDK (`secretspec-hs`) is a thin client over the `secretspec-ffi` C
ABI, linked at build time via the Haskell FFI. Resolution happens in the Rust
core, so the SDK inherits every provider with no Haskell-side logic.

## Quick start

```haskell
import qualified SecretSpec as S
import qualified Data.Map.Strict as Map
import Data.Function ((&))

main :: IO ()
main = do
  resolved <-
    S.load
      ( S.builder
          & S.withProvider "keyring://"
          & S.withProfile "production"
          & S.withReason "boot web app"
      )

  print (S.resolvedProvider resolved, S.resolvedProfile resolved)
  case Map.lookup "DATABASE_URL" (S.resolvedSecrets resolved) of
    Just db -> print (S.get db) -- the value, or the file path for as_path secrets
    Nothing -> pure ()
  S.setAsEnv resolved           -- export everything into the process environment
```

A missing required secret throws `MissingRequiredError`; any other failure
throws `SecretSpecError` (with a stable `errorKind`).

`as_path` secrets are materialized to temp files that outlive the call; call
`S.close resolved` when done so they do not accumulate in the temp dir.

## Value-free report

`S.report` returns the inventory/preflight view: per-secret status and
provenance, never a value. Unlike `load`, it does not throw when a required
secret is missing — that secret appears as a `SecretReport` with `srStatus`
`"missing_required"`.

```haskell
rep <- S.report (S.builder & S.withProfile "production")
mapM_ (\s -> print (S.srName s, S.srStatus s, S.srRequired s)) (S.reportSecrets rep)
```

## Typed access (codegen)

Generate a typed record with `secretspec schema` plus
[quicktype](https://quicktype.io), then decode `S.fieldsJson resolved`:

```bash
secretspec schema | quicktype -s schema --top-level SecretSpec --lang haskell -o Secrets.hs
```

## Building

The `secretspec-ffi` archive is statically linked at build time, so the resolver
is embedded in the binary and there is no `cdylib` or `LD_LIBRARY_PATH` at
runtime. Stage the `.a` in a directory of its own — so `-lsecretspec_ffi`
resolves to the archive and not the co-located `.so` in `target/debug` — and pass
the archive's transitive native dependencies through to the linker:

```bash
cargo build -p secretspec-ffi
TARGET="$(cargo metadata --no-deps --format-version 1 \
  | grep -o '"target_directory":"[^"]*"' | head -1 | sed 's/.*:"\(.*\)"/\1/')"

# Stage the staticlib alone, and capture its native-static-libs for the linker.
LIBDIR="$(mktemp -d)"
cp "$TARGET/debug/libsecretspec_ffi.a" "$LIBDIR/"
NATIVE_LIBS="$(cargo rustc -q -p secretspec-ffi --crate-type staticlib -- \
  --print native-static-libs 2>&1 | sed -n 's/^note: native-static-libs: //p' | tail -1)"
OPTL=(); for l in $NATIVE_LIBS; do OPTL+=("--ghc-options=-optl$l"); done

cabal build --extra-lib-dirs="$LIBDIR" "${OPTL[@]}"
cabal test  --extra-lib-dirs="$LIBDIR" "${OPTL[@]}"
```
