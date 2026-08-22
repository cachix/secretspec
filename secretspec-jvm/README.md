# SecretSpec for the Java Virtual Machine

> Supported starting with SecretSpec 0.20.

`org.cachix.SecretSpec` is the Java SDK for
[SecretSpec](https://secretspec.dev/), the declarative secrets manager. It is a
thin client over the shared Rust resolver, so every provider, fallback chain,
profile, generator, and `as_path` secret behaves exactly like the CLI and the
other language SDKs.


```java
import org.cachix.secretspec.SecretSpec;

public class MyApplication {

  public static void main() {
    var resolved = SecretSpec.builder()
      .withProvider("keyring://")
      .withProfile("production")
      .withReason("boot web app")
      .load();

    var secrets = resolved.getSecrets():
    System.out.println(secrets.get("DATABASE_URL").get());
    resolved.setAsSystemProperties();
  }
}
```

A missing required secret throws `MissingRequiredException`, whose `missing`
property contains the names. Other failures throw `SecretSpecException`, with a
stable `kind`.

## Scopes (0.17+)

Use `withScope("api")` to resolve only a named `[scopes.api]` subset. Both
`Resolved.getScope()` and `ResolutionReport.getScope()` return the selected scope:

```java
var resolved = SecretSpec.builder().withScope("api").load();
```

## Value-free reports

`report()` returns the same inventory/preflight view as
`secretspec check --json`. It never exposes values, and a missing required
secret is an entry with `getStatus() == "missing_required"` rather than an exception.

```java
var report = SecretSpec.builder()
    .withProfile("production")
    .withReason("deployment preflight")
    .report();

for (var secret : report.getSecrets())
    System.out.println("%s: %s".formatted(secret.getName(), secret.getStatus()));
```

## Typed access

Generate a Java type from the manifest, then deserialize `fieldsJson()`:

```bash
secretspec schema |
  quicktype -s schema --top-level AppSecrets --lang java -o AppSecrets.java
```

```java
var secrets = io.quicktype.Converter.fromJson(resolved.fieldsJson());
```

## Files and cleanup

An `as_path` secret is materialized as a mode-0400 temporary file, and `get()`
returns its path. `Resolved` implements `AutoCloseable`; keep the result in a
`try-with-resources` declaration or call `close()` to remove those files when finished.

## Native resolver

The JAR file carries the resolver for glibc and musl Linux x64/Arm64,
macOS x64/Arm64, and Windows x64/Arm64. Windows builds include the C runtime,
so users do not need to install the Visual C++ Redistributable.

During local SDK development, `SECRETSPEC_FFI_LIB` can point to an explicit
`libsecretspec_ffi` build; the SDK also discovers a Cargo `target` directory
when used from a SecretSpec source checkout.
