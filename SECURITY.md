# Security Policy

SecretSpec handles sensitive data and sits between applications and secret
providers. We take vulnerabilities that could disclose secret values, bypass
configured controls, impersonate providers, or compromise release artifacts
seriously.

## Supported versions

SecretSpec releases frequently, so support is defined by release age rather
than by a fixed number of version lines.

| Release | Security support |
|---|---|
| Latest stable release | Fully supported; security fixes are always published here |
| Stable releases published within the previous 90 days | Supported for impact assessment; critical and high-severity fixes are backported when a safe backport is practical |
| Stable releases older than 90 days | Unsupported |
| Pre-releases, development snapshots, forks, and modified builds | Unsupported |

For a supported older release, remediation may require upgrading when a
backport would be unsafe or disproportionately complex. Published advisories
will identify the affected versions, the minimum fixed version, and any
available mitigation.

The 90-day window is measured from the release date shown on the
[GitHub Releases page](https://github.com/cachix/secretspec/releases). The
latest stable release remains supported even if more than 90 days pass before
the next release. Support eligibility is assessed when a report is received; a
report does not fall out of scope merely because remediation continues beyond
the affected release's 90-day window.

## Reporting a vulnerability

Do not open a public GitHub issue, discussion, or pull request for a suspected
vulnerability.

Email reports privately to [security@cachix.org](mailto:security@cachix.org).
Encrypt sensitive supporting material before sending it, or ask for a secure
transfer method in your initial message.

Include as much of the following as possible:

- the affected SecretSpec component, package, provider, and version;
- the operating system and relevant configuration, with all credentials and
  secret values removed;
- a description of the issue and its security impact;
- the conditions required to exploit it;
- minimal reproduction steps or a proof of concept;
- whether the issue is already public or known to other parties;
- your preferred contact details and name or handle for credit, if desired.

Never include real secret values, provider credentials, access tokens, or
customer data in a report. Use synthetic values in reproductions.

We will acknowledge a report within five business days and aim to resolve
confirmed vulnerabilities within 90 days, depending on severity, complexity,
release coordination, and upstream dependencies. We will provide status updates
when the assessment or remediation timeline changes materially.

## What to expect

After receiving a report, the maintainers will:

1. assign a primary contact and confirm receipt;
2. reproduce and assess the issue, affected versions, and severity;
3. investigate related code paths and packages;
4. prepare and test a fix and any required mitigations;
5. coordinate release and downstream notifications;
6. publish an advisory and request a CVE when appropriate;
7. coordinate disclosure timing and credit with the reporter.

Please allow a reasonable remediation window before public disclosure. If the
issue is already being exploited or disclosure is imminent, state that clearly
in the initial report so an accelerated response can be considered.

## Scope

Security reports are welcome for:

- the SecretSpec CLI and Rust library;
- bundled secret-provider implementations;
- `secretspec-derive`;
- the C FFI and official Go, Haskell, Node.js, PHP, Python, and Ruby bindings;
- parsers, configuration inheritance, provider routing, secret generation, and
  secret materialization;
- audit-event redaction and access-control enforcement;
- official installation, build, packaging, and release workflows and artifacts;
- documentation or examples that directly cause users to expose secrets or
  disable an intended security control.

Examples of relevant impact include:

- exposing secret values or provider credentials through logs, errors, audit
  events, process arguments, temporary files, SDK responses, or generated code;
- bypassing a documented policy or security boundary;
- command, path, configuration, or provider-URI injection;
- retrieving or modifying a different secret than the one requested;
- memory-safety issues at Rust `unsafe`, native-extension, or FFI boundaries;
- accepting substituted, unauthenticated, or malicious release artifacts;
- vulnerabilities in SecretSpec's use of a dependency that are exploitable in
  a supported SecretSpec configuration.

## Product boundaries

SecretSpec is a policy and delivery layer around external secret stores. The
selected provider remains responsible for primary authorization, encryption at
rest, availability, rotation, and provider-side audit records.

Some supported operations deliberately expose plaintext to the caller. For
example, `get` and `export` return secret values, `run` places values in a child
process environment, file materialization writes a value to a temporary file,
and the dotenv and environment providers use plaintext process or filesystem
interfaces. A report must demonstrate behavior beyond the operation the user
explicitly requested or a failure of a documented protection.

The current local audit log is user-controlled, size-bounded, and designed to
fail open. It is not an authoritative, tamper-proof enterprise audit trail.
Reports that only restate this limitation are not vulnerabilities.

SecretSpec does not currently provide SOC 2, ISO/IEC 27001, CMMC, FedRAMP, or
FIPS 140-3 certification or validation. Security reports should concern a
concrete vulnerability rather than the absence of a compliance claim.

## Out of scope

The following are normally outside this policy unless they demonstrate a
concrete vulnerability in a supported SecretSpec release:

- vulnerabilities in a third-party secret provider, provider CLI, package
  registry, operating system, or cloud service that do not arise from
  SecretSpec's integration;
- attacks that require an already-compromised host, malicious administrator,
  debugger access, or unrestricted access to the victim process;
- secrets deliberately committed as configuration defaults or written to a
  deliberately selected plaintext provider;
- unsupported versions, forks, and modified builds;
- dependency-version reports without an exploitable SecretSpec code path;
- automated scanner output without manual validation and impact analysis;
- denial of service based only on traffic volume or resource exhaustion;
- social engineering, phishing, physical attacks, or attacks against
  maintainers and infrastructure providers;
- best-practice suggestions without a demonstrated security impact.

Report vulnerabilities in third-party components to their maintainers as well.
If SecretSpec needs a mitigation or dependency update, include that impact in
the SecretSpec report.

## Research guidelines and safe harbor

When investigating SecretSpec:

- use only systems, repositories, provider accounts, and secret values that you
  own or have explicit permission to test;
- stop immediately if you encounter another person's data and report what
  happened without retaining or accessing more data;
- do not exfiltrate data, establish persistence, degrade services, or perform
  large-scale automated scanning;
- minimize access to sensitive data and securely delete research copies when
  they are no longer needed;
- comply with applicable law and give the maintainers a reasonable opportunity
  to remediate before disclosure.

If you make a good-faith effort to follow this policy, Cachix will consider the
research authorized and will not pursue or support legal action related to that
research. This safe harbor cannot waive the rights of third parties.

If you are uncertain whether planned research is permitted, contact
[security@cachix.org](mailto:security@cachix.org) before proceeding.

## Bug bounty

SecretSpec does not currently operate a paid bug-bounty program. Reports that
lead to a substantive fix may be credited publicly with the reporter's consent.
