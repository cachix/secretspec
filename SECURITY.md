# Security Policy

Monosecret handles sensitive data and sits between applications and secret
providers. Vulnerabilities that could disclose secret values, bypass configured
controls, impersonate providers, or compromise release artifacts are treated
seriously.

## Supported versions

The latest stable Monosecret release is supported. Older releases,
pre-releases, development snapshots, forks, and modified builds may be asked to
upgrade before a report is investigated or fixed.

Published advisories will identify affected versions, the minimum fixed
version, and any available mitigations.

## Reporting a vulnerability

Do not include vulnerability details, credentials, secret values, or customer
data in a public issue, discussion, or pull request.

1. Visit the repository's [Security page](https://github.com/ifiokjr/monosecret/security)
   and use **Report a vulnerability** when private vulnerability reporting is
   available.
2. If that option is unavailable, open a
   [minimal issue](https://github.com/ifiokjr/monosecret/issues/new) requesting a
   private security contact. Include no technical details beyond the affected
   Monosecret component and your preferred contact method. A maintainer will
   arrange a private channel.

Use synthetic values in reproductions. A useful report includes:

- the affected Monosecret component, package, provider, and version;
- the operating system and relevant configuration, with sensitive values removed;
- the security impact and conditions required to exploit the issue;
- minimal reproduction steps or a proof of concept;
- whether the issue is already public or known to other parties; and
- your preferred name or handle for credit, if desired.

## Scope

Security reports are welcome for:

- the Monosecret CLI and Rust crates;
- bundled secret-provider implementations;
- the C FFI and official language SDKs;
- configuration parsing, inheritance, provider routing, secret generation, and
  secret materialization;
- audit-event redaction and access-control enforcement; and
- official build, packaging, release workflows, and artifacts.

Examples of relevant impact include secret or credential disclosure, policy
bypass, command or path injection, cross-secret access, memory-safety issues at
native boundaries, and substituted or unauthenticated release artifacts.

## Product boundaries

Monosecret is a policy and delivery layer around external secret stores. The
selected provider remains responsible for authorization, encryption at rest,
availability, rotation, and provider-side audit records.

Some operations intentionally expose plaintext to the caller. For example,
`get` and `export` return secret values, `run` places values in a child process
environment, and plaintext providers use process or filesystem interfaces. A
report should demonstrate behavior beyond the operation the user requested or
a failure of a documented protection.

Reports about third-party providers, operating systems, registries, or services
should be sent to those maintainers unless the vulnerability arises from
Monosecret's integration with them.
