# IPC resolver fuzzing

`resolver_wire` feeds byte streams to the real `secretspec.resolver/1` server
through in-memory streams. It covers frame decoding, strict JSON-RPC parsing,
session sequencing, initialization, capability checks, and typed resolver
request validation. Its handler is intentionally side-effect free, so fuzzing
does not load manifests, read providers, or create secret files.

The target has one checked-in seed containing initialization followed by a
`resolver.get` request. Inputs beginning with a NUL byte are used verbatim as
the transport stream; all other inputs are converted to UTF-8 frames, with a
blank line separating frames. This gives mutations direct access to both the
wire framing and resolver-message layers.

`resolve_apis` differentially fuzzes the Rust `secretspec::resolve_json` API
and the C `secretspec_resolve` / `secretspec_free` ABI. It pins each valid
object to a temporary `null://` manifest, so fuzzed fields cannot select a
provider or read an arbitrary manifest. The target then requires both API
responses to be identical valid JSON envelopes; arbitrary NUL-free bytes also
exercise the C ABI's invalid-UTF-8 path.

The development environment supplies `cargo-fuzz` and dedicated commands for
the separate nightly toolchain. Install it once, then run from the repository
root:

```bash
devenv shell install-fuzz-nightly
devenv shell fuzz-resolver

# Fuzz the Rust and C resolver APIs instead.
devenv shell fuzz-resolve-apis
```

Pass libFuzzer options after `--`:

```bash
devenv shell fuzz-resolver -- -runs=1000
devenv shell fuzz-resolve-apis -- -runs=1000
```

The underlying command is:

```bash
rustup run nightly cargo fuzz run resolver_wire
```

To replay a crash artifact:

```bash
devenv shell fuzz-resolver -- fuzz/artifacts/resolver_wire/<artifact>
```
