# secretspec (Haskell SDK)

Haskell bindings for [SecretSpec](https://secretspec.dev/), a declarative secrets
manager. A thin client over the `secretspec-ffi` C ABI, linked at build time via
the Haskell FFI. Resolution happens in the Rust core, so the SDK inherits every
provider with no Haskell-side logic.

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

## Scopes (0.17+)

Use `withScope "api"` to resolve only a named `[scopes.api]` subset. Both
`resolvedScope` and `reportScope` return the selected scope:

```haskell
resolved <- S.load (S.builder & S.withScope "api")
```

## Cleanup

`as_path` secrets are materialized to temp files that outlive the call. Call
`SecretSpec.close resolved` when done so the secret files do not accumulate in
the temp dir.

## Value-free report

`SecretSpec.report` returns the inventory/preflight view: per-secret status and
provenance, never a value. Unlike `load`, it does not throw when a required
secret is missing — it appears as a `SecretReport` with `srStatus`
`"missing_required"`.

```haskell
rep <- S.report (S.builder & S.withProfile "production")
mapM_ (\s -> print (S.srName s, S.srStatus s, S.srRequired s)) (S.reportSecrets rep)
```

## Typed access (codegen)

Generate a typed record with `secretspec schema` plus
[quicktype](https://quicktype.io), then decode `SecretSpec.fieldsJson resolved`:

```bash
secretspec schema | quicktype -s schema --top-level SecretSpec --lang haskell -o Secrets.hs
```

## Building

The build links the `secretspec-ffi` archive statically. Stage the `.a` in a
directory of its own (so the linker picks the archive, not the co-located
`.so`) and pass its native dependencies to the linker:

```bash
cargo build -p secretspec-ffi
TARGET="$(cargo metadata --no-deps --format-version 1 \
  | grep -o '"target_directory":"[^"]*"' | head -1 | sed 's/.*:"\(.*\)"/\1/')"

LIBDIR="$(mktemp -d)"
cp "$TARGET/debug/libsecretspec_ffi.a" "$LIBDIR/"
NATIVE_LIBS="$(cargo rustc -q -p secretspec-ffi --crate-type staticlib -- \
  --print native-static-libs 2>&1 | sed -n 's/^note: native-static-libs: //p' | tail -1)"
OPTL=(); for l in $NATIVE_LIBS; do OPTL+=("--ghc-options=-optl$l"); done

cabal build --extra-lib-dirs="$LIBDIR" "${OPTL[@]}"
cabal test  --extra-lib-dirs="$LIBDIR" "${OPTL[@]}"
```

### pkg-config (0.19+)

Install the library with [cargo-c](https://github.com/lu-zero/cargo-c) and
build with the `use-pkg-config` flag instead of the flags above:

```bash
cargo cinstall -p secretspec-ffi --library-type staticlib --prefix "$PREFIX"
cd secretspec-hs
PKG_CONFIG_PATH="$PREFIX/lib/pkgconfig" cabal build -f use-pkg-config
PKG_CONFIG_PATH="$PREFIX/lib/pkgconfig" cabal test  -f use-pkg-config
```

### Dynamic linking (0.19+)

Drop `--library-type staticlib` from the install and the build links the shared
library instead.
