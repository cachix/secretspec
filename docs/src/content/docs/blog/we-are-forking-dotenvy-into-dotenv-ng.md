---
title: "We Are Forking dotenvy into dotenv-ng"
description: A modern Rust dotenv implementation with literal dollars, round-trip rendering, and structured parse errors.
date: 2026-08-15
authors:
  - domen
---

We have released [`dotenv-ng`](https://github.com/cachix/dotenv-ng) 1.0, a
modern Rust implementation for loading and rendering `.env` files. It began as
a fork of [`dotenvy`](https://github.com/allan2/dotenvy) after its parser
changed a secret while reading it.

That may sound contradictory. SecretSpec is still on a mission to [eliminate
environment variables as a secrets
interface](/blog/secrets-dont-belong-in-config/), and we have written about
[where `.env` went wrong](/blog/where-env-went-wrong/). It should not be the
final home of a secret. But migrating away from `.env` starts with reading it
correctly.

## Why fork dotenvy?

The immediate failure was [SecretSpec issue
#73](https://github.com/cachix/secretspec/issues/73). A dotenv file contained a
value with bcrypt fragments:

```dotenv
TEST="foo:$2a$10$TWoviNHS27HJMw1PKe4tBeIMlms6tWdYS9hKoHANKCQhluDlEt/gu"
```

The file was intact. Reading it through the dotenv provider returned a
different value because `dotenvy` treated the dollar-prefixed fragments as
variable substitutions. The failure appeared later as an authentication error,
not a parse error.

An upstream request to make substitution configurable had been [open since
2024](https://github.com/allan2/dotenvy/issues/113). A [pull
request](https://github.com/allan2/dotenvy/pull/167) arrived in 2026 but
targeted an unreleased API. A migration tool cannot require users to recognize
and escape parser syntax inside their secrets.

## The maintenance gap

The original Rust `dotenv` crate stopped releasing in 2020 and was eventually
marked [unmaintained by
RustSec](https://rustsec.org/advisories/RUSTSEC-2021-0141.html), which listed
dotenvy as an alternative.

Dotenvy's description still calls it “a well-maintained fork.” Its latest
published version, [0.15.7, was released on March 22,
2023](https://github.com/allan2/dotenvy/releases/tag/v0.15.7). A [Rust forum
discussion](https://users.rust-lang.org/t/recommended-crate-for-storing-keys-for-web-site-database/133305/11)
noted the two-year release gap in 2025. By the time the bcrypt bug blocked
SecretSpec, it was more than three years.

There is an uncomfortable irony in a maintained fork repeating its upstream's
release problem. Its maintainers do not owe us a release, but SecretSpec needed
breaking fixes on a schedule we control.

## What does dotenv-ng improve upon?

We first considered a small patch. Auditing the parser uncovered more problems
around JSON, Windows paths, Unicode names, precedence, and partial environment
mutation.

`dotenv-ng` therefore starts from dotenvy 0.15.7 but deliberately breaks
compatibility where correctness requires it. Version 1.0 adds:

- a source-aware parser with structured errors;
- literal dollar signs by default, with substitution available only when a
  caller explicitly enables it;
- a broader key grammar that supports dashes, leading digits, leading dots,
  and Unicode;
- a renderer that adds only the quoting and escaping needed to parse a value
  back unchanged;
- validation before process-environment mutation; and
- an explicit `unsafe` boundary around that mutation.

Property tests exercise arbitrary Unicode and syntax-heavy values, check that
quoting is used only when necessary, and round-trip complete documents. The
parser and renderer, the core of the rewrite, both have 100% line coverage.

The complete compatibility and API changes are recorded in the [`dotenv-ng`
1.0 changelog](https://github.com/cachix/dotenv-ng/blob/v1.0.0/CHANGELOG.md).

## Try dotenv-ng 1.0

The package is available on [crates.io](https://crates.io/crates/dotenv-ng).
Applications can keep the familiar `dotenv` crate name with a dependency
alias:

```toml
[dependencies]
dotenv = { package = "dotenv-ng", version = "1" }
```

Starting in SecretSpec 0.20+, dotenv-ng powers dotenv parsing and rendering
throughout SecretSpec.
