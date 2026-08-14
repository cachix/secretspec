{
  pkgs,
  lib,
  config,
  inputs,
  ...
}:

let
  currentDir = dirOf __curPos.file;
  custom = inputs.ifiokjr-nixpkgs.packages.${pkgs.stdenv.system};
  dartPkgs = import inputs.dart-nixpkgs { system = pkgs.stdenv.system; };
  phpWithFfi = pkgs.php.buildEnv {
    extensions =
      { enabled, all }:
      enabled ++ [ all.ffi ];
    extraConfig = ''
      ffi.enable = true
    '';
  };
in
{
  # The C# SDK (`dotnet/monosecret_dotnet`) loads the Monosecret C ABI through
  # P/Invoke. Release packaging remains deferred; local conformance tests use the
  # native library prepared by `scripts/ci-sdks.sh`.
  languages.dotnet.enable = true;

  # The PHP SDK (`php/monosecret_php`) supports both an ext-php-rs extension that
  # embeds the resolver and an ext-ffi fallback that loads the Monosecret C ABI.
  # Composer comes from the devenv PHP module; the FFI extension is enabled only
  # for development and conformance testing.
  languages.php = {
    enable = true;
    package = phpWithFfi;
  };

  packages =
    with pkgs;
    [
      cargo-c
      cargo-insta
      custom.monochange
      custom.op
      rustup
      nodejs_24
      pnpm
      dartPkgs.dart
      go
      (python3.withPackages (pythonPackages: [ pythonPackages.pytest ]))
      maturin
      ruby
      ghc
      cabal-install
      dbus
      pkg-config
      # Provider integration and documentation tooling.
      bitwarden-cli
      sops
      lychee
      # Building `monosecret_php_native` needs php-config, PHP headers, and
      # bindgen's Clang environment in addition to the PHP runtime above.
      (lib.lowPrio php.unwrapped.dev)
      rustPlatform.bindgenHook
      # Client only: the Vaultwarden harness uses the developer's existing
      # Docker-compatible runtime (Docker Desktop, Colima, or Podman).
      (docker_29.override { clientOnly = true; })
      actionlint
      dprint
      gitleaks
      jq
      nixfmt-rfc-style
      shfmt
      taplo
      zizmor
      gh
      git
      unzip
      zip
    ]
    ++ lib.optionals stdenv.isLinux [
      cargo-llvm-cov
    ]
    ++ lib.optionals stdenv.isDarwin [
      coreutils
    ];

  # Fully static musl builds of the Go SDK need a target-scoped C linker. Keep
  # these Linux-only and reference the cross toolchain by store path rather than
  # adding it to `packages`, which would pollute host linker flags.
  env = lib.optionalAttrs pkgs.stdenv.isLinux (
    let
      muslcc = "${pkgs.pkgsCross.musl64.stdenv.cc}/bin/x86_64-unknown-linux-musl-gcc";
    in
    {
      CC_x86_64_unknown_linux_musl = muslcc;
      CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER = muslcc;
      MUSL_CC = muslcc;
      MUSL_STATIC_LDFLAGS = "-L${pkgs.pkgsStatic.libunwind}/lib";
    }
  );

  enterShell = ''
    set -euo pipefail
    export PATH="$DEVENV_PROFILE/bin:$PATH"
    dartfmt:hash
  '';

  dotenv.disableHint = true;

  git-hooks = {
    hooks = {
      "secrets:commit" = {
        enable = true;
        name = "secrets:commit";
        description = "Scan staged changes for leaked secrets with gitleaks.";
        entry = "${pkgs.gitleaks}/bin/gitleaks protect --staged --verbose --redact";
        pass_filenames = false;
        stages = [ "pre-commit" ];
      };
      "lint:commit" = {
        enable = true;
        name = "lint:commit";
        description = "Run formatting checks on every commit.";
        entry = "${config.env.DEVENV_PROFILE}/bin/lint:format";
        pass_filenames = false;
        always_run = true;
        stages = [ "pre-commit" ];
      };
      "lint:push" = {
        enable = true;
        name = "lint:push";
        description = "Run the full lint suite before push.";
        entry = "${config.env.DEVENV_PROFILE}/bin/lint:push";
        pass_filenames = false;
        always_run = true;
        stages = [ "pre-push" ];
      };
    };
  };

  enterTest = ''
    test:all
  '';

  scripts = {
    "dartfmt" = {
      exec = ''
        set -euo pipefail
        file="$1"
        shift || true
        dir="$(dirname "$file")"
        base="$(basename "$file")"
        (
          cd "$dir"
          dart format -o show "$base" "$@" | sed '$d'
        )
      '';
      description = "The dart format executable for formatting the workspace.";
      binary = "bash";
    };
    "dartfmt:hash" = {
      exec = ''
        set -euo pipefail
        cd "''${DEVENV_ROOT:-${currentDir}}"

        find . \( -name pubspec.yaml -o -name analysis_options.yaml -o -name pubspec.lock \) \
          | sort \
          | ${pkgs.findutils}/bin/xargs ${pkgs.coreutils}/bin/sha256sum \
          | ${pkgs.coreutils}/bin/sha256sum \
          | cut -d' ' -f1 > .dartfmt.txt
      '';
      description = "Write .dartfmt.txt from pubspec, analysis options, and lockfile contents.";
      binary = "bash";
    };

    "install:all" = {
      exec = ''
        set -euo pipefail
        install:node
        install:dart
      '';
      description = "Install all workspace dependencies.";
      binary = "bash";
    };
    "install:node" = {
      exec = ''
        set -euo pipefail
        if [ -f pnpm-lock.yaml ]; then
          pnpm install --frozen-lockfile
        else
          pnpm install --no-frozen-lockfile
        fi
      '';
      description = "Install pnpm workspace dependencies.";
      binary = "bash";
    };
    "install:dart" = {
      exec = ''
        set -euo pipefail
        dart pub get
      '';
      description = "Install Dart workspace dependencies.";
      binary = "bash";
    };
    "melos" = {
      exec = ''
        set -euo pipefail
        dart run melos "$@"
      '';
      description = "Run the melos CLI for the Dart workspace.";
      binary = "bash";
    };
    "update:deps" = {
      exec = ''
        set -euo pipefail
        cargo update
        pnpm update --latest
        dart pub upgrade
        devenv update
      '';
      description = "Update Rust, pnpm, Dart, and devenv dependencies.";
      binary = "bash";
    };

    "build:all" = {
      exec = ''
        set -euo pipefail
        export PATH="$DEVENV_PROFILE/bin:$PATH"
        cargo build --workspace --all-features --locked
        build:node
      '';
      description = "Build Rust crates and npm packages.";
      binary = "bash";
    };
    "build:dist" = {
      exec = ''
        set -euo pipefail
        cargo build --workspace --all-features --locked --release
      '';
      description = "Build release binaries.";
      binary = "bash";
    };
    "build:node" = {
      exec = ''
        set -euo pipefail
        pnpm --filter @monosecret/cli --filter @monosecret/client run build
      '';
      description = "Build npm package entry points and TypeScript client.";
      binary = "bash";
    };
    "build:docs" = {
      exec = ''
        set -euo pipefail
        pnpm --filter docs run build
      '';
      description = "Build the Astro/Starlight documentation site.";
      binary = "bash";
    };

    "test:all" = {
      exec = ''
        set -euo pipefail
        export PATH="$DEVENV_PROFILE/bin:$PATH"
        test:rust
        test:node
        test:dart
        test:sdks
      '';
      description = "Run all Rust, npm, and Dart tests.";
      binary = "bash";
    };
    "test:rust" = {
      exec = ''
        set -euo pipefail
        cargo test --all --all-features --locked
      '';
      description = "Run Rust workspace tests.";
      binary = "bash";
    };
    "test:dart" = {
      exec = ''
        set -euo pipefail
        install:dart
        cargo build -p monosecret_ffi
        melos exec --fail-fast -- dart test
      '';
      description = "Run Dart SDK tests.";
      binary = "bash";
    };
    "test:node" = {
      exec = ''
        set -euo pipefail
        pnpm --filter @monosecret/client run test
      '';
      description = "Run npm package tests.";
      binary = "bash";
    };
    "test:ffi" = {
      exec = ''
        set -euo pipefail
        cargo test -p monosecret_ffi
      '';
      description = "Run the Monosecret C ABI tests.";
      binary = "bash";
    };
    "test:python" = {
      exec = ''
        set -euo pipefail
        (cd python/monosecret_py && python -m pytest -q)
      '';
      description = "Run the Python SDK tests.";
      binary = "bash";
    };
    "test:go" = {
      exec = ''
        set -euo pipefail
        (cd go/monosecret_go && go test ./...)
      '';
      description = "Run the Go SDK tests.";
      binary = "bash";
    };
    "test:ruby" = {
      exec = ''
        set -euo pipefail
        bash ruby/monosecret_rb/scripts/build-ext.sh
        (cd ruby/monosecret_rb && ruby -Ilib -e 'Dir["test/test_*.rb"].sort.each { |file| require File.expand_path(file) }')
      '';
      description = "Run the Ruby SDK tests.";
      binary = "bash";
    };
    "test:haskell" = {
      exec = ''
        set -euo pipefail
        bash scripts/ci-sdks.sh
      '';
      description = "Run the complete native SDK conformance suite, including Haskell.";
      binary = "bash";
    };
    "test:sdks" = {
      exec = ''
        set -euo pipefail
        bash scripts/ci-sdks.sh
      '';
      description = "Run all native language SDK and conformance tests.";
      binary = "bash";
    };
    "test-cli-integration" = {
      exec = ''
        set -euo pipefail
        cargo build --release --bin monosecret
        export PATH="$PWD/target/release:$PATH"
        bash tests/cli-integration.sh
      '';
      description = "Build the CLI and run shell-based integration tests.";
      binary = "bash";
    };

    "coverage:all" = {
      exec = ''
        set -euo pipefail
        export PATH="$DEVENV_PROFILE/bin:$PATH"
        coverage:rust
        coverage:dart
        coverage:node
      '';
      description = "Generate Rust, Dart, and npm LCOV reports.";
      binary = "bash";
    };
    "coverage:rust" = {
      exec = ''
        set -euo pipefail
        mkdir -p coverage
        rustup run nightly cargo llvm-cov clean --workspace
        rustup run nightly cargo llvm-cov --all-features --workspace --lcov --output-path coverage/rust.lcov
      '';
      description = "Generate Rust coverage at coverage/rust.lcov with cargo-llvm-cov.";
      binary = "bash";
    };
    "coverage:dart" = {
      exec = ''
        set -euo pipefail
        install:dart
        cargo build -p monosecret_ffi
        rm -rf coverage/dart
        mkdir -p coverage/dart
        melos exec --fail-fast -- dart test --coverage=coverage
        for package in dart/monosecret dart/monosecret_builder; do
          (
            cd "$package"
            dart run coverage:format_coverage \
              --lcov \
              --in=coverage \
              --out=coverage/lcov.info \
              --package=. \
              --report-on=lib
          )
        done
      '';
      description = "Generate Dart SDK and builder LCOV reports.";
      binary = "bash";
    };
    "coverage:node" = {
      exec = ''
        set -euo pipefail
        pnpm --filter @monosecret/client run coverage
      '';
      description = "Generate TypeScript client LCOV report.";
      binary = "bash";
    };

    "package:check" = {
      exec = ''
        set -euo pipefail
        export PATH="$DEVENV_PROFILE/bin:$PATH"
        package:rust:check
        package:node:check
        package:dart:check
        package:sdks:check
      '';
      description = "Validate publish metadata and deferred SDK package readiness without publishing.";
      binary = "bash";
    };
    "package:rust:check" = {
      exec = ''
        set -euo pipefail
        cargo package -p monosecret -p monosecret_derive --allow-dirty --locked
      '';
      description = "Run cargo package for publishable Rust crates.";
      binary = "bash";
    };
    "package:node:check" = {
      exec = ''
        set -euo pipefail
        for package in npm/monosecret__cli npm/monosecret__client npm/monosecret__skill npm/monosecret__cli-* npm/monosecret__client-*; do
          (cd "$package" && npm pack --dry-run)
        done
      '';
      description = "Dry-run npm package tarballs.";
      binary = "bash";
    };
    "package:dart:check" = {
      exec = ''
        set -euo pipefail
        for package in dart/monosecret dart/monosecret_builder; do
          (cd "$package" && dart pub publish --dry-run --skip-validation)
        done
      '';
      description = "Dry-run Dart package packaging (local validation without server contact).";
      binary = "bash";
    };
    "package:ruby:source-check" = {
      exec = ''
        set -euo pipefail
        bash ruby/monosecret_rb/scripts/check-source-gem.sh
      '';
      description = "Validate deferred Ruby source-gem metadata without claiming native installability.";
      binary = "bash";
    };
    "package:sdks:check" = {
      exec = ''
        set -euo pipefail
        maturin build --manifest-path python/monosecret_py/Cargo.toml --out target/wheels
        package:ruby:source-check
        (cd haskell/monosecret_hs && cabal check && cabal sdist)
        (cd go/monosecret_go && go list ./...)
        composer validate --strict --no-check-publish
        dotnet pack dotnet/monosecret_dotnet/src/Monosecret/Monosecret.csproj --output target/dotnet-pack
        # The devenv Nix SDK (DEVELOPER_DIR/SDKROOT) is built with an older Swift
        # than the system toolchain, which breaks manifest compilation. Unset it
        # so `swift package` uses the system SDK. The Swift SDK is deferred, so a
        # toolchain crash (e.g. stack smashing on some Linux runners) is a warning,
        # not a packaging failure.
        if env -u SDKROOT -u SDK_NAME -u NIX_SDKROOT -u DEVELOPER_DIR swift package dump-package >/dev/null 2>&1; then
          :
        else
          echo "warning: swift manifest check skipped (toolchain unavailable or crashing on this runner)"
        fi
      '';
      description = "Check staged SDK packages, including deferred PHP, C#, and Swift package metadata, without publishing.";
      binary = "bash";
    };

    "lint:all" = {
      exec = ''
        set -euo pipefail
        export PATH="$DEVENV_PROFILE/bin:$PATH"
        lint:format
        lint:clippy
        lint:node
        lint:dart
        lint:monochange
        lint:workflows
        package:check
      '';
      description = "Run all lint and publish-readiness checks: formatting, Rust, npm, Dart, monochange, workflows, and package metadata.";
      binary = "bash";
    };
    "lint:push" = {
      exec = ''
        set -euo pipefail

        run_step() {
          local name="$1"
          shift
          echo "Currently running: $name"
          "$@"
        }

        run_step "gitleaks detect" ${pkgs.gitleaks}/bin/gitleaks detect --verbose --redact
        export PATH="${currentDir}/.devenv/profile/bin:$PATH"
        run_step "lint:format"
        run_step "lint:clippy"
        run_step "lint:node"
        run_step "lint:dart"
        run_step "lint:monochange"
        run_step "lint:workflows"
        run_step "package:check"
      '';
      description = "Run all lint and publish-readiness checks: formatting, Rust, npm, Dart, monochange, workflows, and package metadata.";
      binary = "bash";
    };
    "lint:format" = {
      exec = ''
        set -euo pipefail

        export PATH="${currentDir}/.devenv/profile/bin:$PATH"
        dprint check --allow-no-files --config "$DEVENV_ROOT/dprint.json" -L debug
      '';
      description = "Check dprint, TOML, rustfmt, Dart, and Nix formatting.";
      binary = "bash";
    };
    "lint:clippy" = {
      exec = ''
        set -euo pipefail
        cargo clippy --all-targets --all-features --locked
      '';
      description = "Run Clippy across all Rust targets and features.";
      binary = "bash";
    };
    "lint:dart" = {
      exec = ''
        set -euo pipefail
        install:dart
        dart analyze .
      '';
      description = "Run Dart static analysis for the SDK.";
      binary = "bash";
    };
    "lint:node" = {
      exec = ''
        set -euo pipefail
        pnpm --filter @monosecret/client run check
      '';
      description = "Run TypeScript static analysis for npm packages.";
      binary = "bash";
    };
    "lint:monochange" = {
      exec = ''
        set -euo pipefail
        monochange check
      '';
      description = "Validate monochange release metadata.";
      binary = "bash";
    };
    "lint:actionlint" = {
      exec = ''
        set -euo pipefail
        actionlint .github/workflows/*.yml
      '';
      description = "Lint GitHub Actions workflow syntax with actionlint.";
      binary = "bash";
    };
    "lint:workflows" = {
      exec = ''
        set -euo pipefail
        lint:actionlint
        zizmor .github/workflows/ .github/actions/
      '';
      description = "Lint GitHub Actions syntax with actionlint and scan workflow security with zizmor.";
      binary = "bash";
    };
    "lint:secrets" = {
      exec = ''
        set -euo pipefail
        gitleaks detect --verbose --redact
      '';
      description = "Scan repository history for leaked secrets.";
      binary = "bash";
    };
    "fix:all" = {
      exec = ''
        set -euo pipefail
        fix:clippy
        fix:dart
        fix:format
        fix:monochange
        fix:workflows
      '';
      description = "Fix all autofixable issues: Clippy, Dart, formatting, monochange metadata, workflow security, and actionlint validation.";
      binary = "bash";
    };
    "fix:format" = {
      exec = ''
        set -euo pipefail
        dprint fmt --config "$DEVENV_ROOT/dprint.json" -L debug
      '';
      description = "Fix formatting for entire project.";
      binary = "bash";
    };
    "fix:clippy" = {
      exec = ''
        set -euo pipefail
        cargo clippy --workspace --fix --allow-dirty --allow-staged --all-features --all-targets
      '';
      description = "Apply Clippy fixes where possible.";
      binary = "bash";
    };
    "fix:dart" = {
      exec = ''
        set -euo pipefail
        install:dart
        for package in dart/monosecret dart/monosecret_builder; do
          (cd "$package" && dart fix --apply)
        done
      '';
      description = "Apply Dart analyzer fixes where possible.";
      binary = "bash";
    };
    "fix:monochange" = {
      exec = ''
        set -euo pipefail
        monochange check --fix
      '';
      description = "Validate monochange metadata after other fixes.";
      binary = "bash";
    };
    "fix:workflows" = {
      exec = ''
        set -euo pipefail
        zizmor --fix .github/workflows/ .github/actions/ || true
        lint:actionlint
      '';
      description = "Auto-fix zizmor findings where possible, then validate workflow syntax with actionlint.";
      binary = "bash";
    };

    "snapshot:review" = {
      exec = ''
        set -euo pipefail
        cargo insta test --all-features --workspace --accept-unseen
        cargo insta review --workspace
      '';
      description = "Run snapshot tests and review any pending changes with cargo-insta.";
      binary = "bash";
    };
    "snapshot:accept" = {
      exec = ''
        set -euo pipefail
        cargo insta accept --workspace
      '';
      description = "Accept all pending insta snapshots without interactive review.";
      binary = "bash";
    };
  };

  processes.docs.exec = ''
    cd docs && npm run dev
  '';
}
