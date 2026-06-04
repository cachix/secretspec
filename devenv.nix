{
  pkgs,
  lib,
  config,
  inputs,
  ...
}:

let
  custom = inputs.ifiokjr-nixpkgs.packages.${pkgs.stdenv.hostPlatform.system};
in
{
  languages.rust.enable = true;
  languages.javascript = {
    enable = true;
    npm = {
      enable = true;
      install.enable = false;
    };
  };

  packages =
    with pkgs;
    [
      # Rust and release tooling
      cargo-dist
      custom.monochange
      rustup

      # Node/npm workspace tooling
      nodejs_22
      pnpm

      # Dart SDK tooling
      dart

      # keyring/libdbus dependencies
      dbus
      pkg-config

      # formatting and linting
      actionlint
      dprint
      gitleaks
      jq
      nixfmt-rfc-style
      shfmt
      taplo
      zizmor

      # release/archive helpers
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

  enterShell = ''
    set -euo pipefail
    export PATH="$DEVENV_PROFILE/bin:$PATH"
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
        entry = "${config.env.DEVENV_PROFILE}/bin/lint:all";
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
      description = "Format a Dart file for dprint's exec plugin.";
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
        pnpm --filter @monosecret/cli run build
      '';
      description = "Build npm package entry points.";
      binary = "bash";
    };

    "test:all" = {
      exec = ''
        set -euo pipefail
        export PATH="$DEVENV_PROFILE/bin:$PATH"
        test:rust
        test:dart
      '';
      description = "Run all Rust and Dart tests.";
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
        melos exec --fail-fast -- dart test
      '';
      description = "Run Dart SDK tests.";
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
      '';
      description = "Generate Rust and Dart LCOV reports.";
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
        cd packages/monosecret
        dart test --coverage=coverage
        dart run coverage:format_coverage \
          --lcov \
          --in=coverage \
          --out=coverage/lcov.info \
          --package=. \
          --report-on=lib
      '';
      description = "Generate Dart SDK coverage at packages/monosecret/coverage/lcov.info.";
      binary = "bash";
    };

    "package:check" = {
      exec = ''
        set -euo pipefail
        export PATH="$DEVENV_PROFILE/bin:$PATH"
        package:rust:check
        package:node:check
        package:dart:check
      '';
      description = "Validate Rust, npm, and Dart package publish metadata.";
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
        for package in packages/monosecret__cli packages/monosecret__skill packages/monosecret__cli-*; do
          npm --prefix "$package" pack --dry-run
        done
      '';
      description = "Dry-run npm package tarballs.";
      binary = "bash";
    };
    "package:dart:check" = {
      exec = ''
        set -euo pipefail
        cd packages/monosecret
        dart pub publish --dry-run
      '';
      description = "Dry-run Dart package publishing.";
      binary = "bash";
    };

    "lint:all" = {
      exec = ''
        set -euo pipefail
        export PATH="$DEVENV_PROFILE/bin:$PATH"
        lint:format
        lint:clippy
        lint:dart
        lint:monochange
        lint:workflows
        package:check
      '';
      description = "Run all lint and publish-readiness checks: formatting, Rust, Dart, monochange, workflows, and package metadata.";
      binary = "bash";
    };
    "lint:format" = {
      exec = ''
        set -euo pipefail
        dprint check --allow-no-files
        git ls-files -z '*.toml' | xargs -0 taplo fmt --check
        rustup run nightly cargo fmt --all -- --check
        dart format --output=none --set-exit-if-changed packages/monosecret
        nixfmt --check devenv.nix
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
    "lint:monochange" = {
      exec = ''
        set -euo pipefail
        monochange step:validate
      '';
      description = "Validate monochange release metadata.";
      binary = "bash";
    };
    "lint:workflows" = {
      exec = ''
        set -euo pipefail
        actionlint .github/workflows/*.yml
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
        export PATH="$DEVENV_PROFILE/bin:$PATH"
        fix:clippy
        fix:dart
        fix:format
        fix:monochange
        fix:workflows
      '';
      description = "Fix all autofixable issues: Clippy, Dart, formatting, monochange metadata, and workflow security.";
      binary = "bash";
    };
    "fix:format" = {
      exec = ''
        set -euo pipefail
        dprint fmt --allow-no-files
        git ls-files -z '*.toml' | xargs -0 taplo fmt
        rustup run nightly cargo fmt --all
        dart format packages/monosecret
        nixfmt devenv.nix
      '';
      description = "Format dprint-managed files, TOML, Rust, Dart, and Nix.";
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
        cd packages/monosecret
        dart fix --apply
      '';
      description = "Apply Dart analyzer fixes where possible.";
      binary = "bash";
    };
    "fix:monochange" = {
      exec = ''
        set -euo pipefail
        monochange step:validate
      '';
      description = "Validate monochange metadata after other fixes.";
      binary = "bash";
    };
    "fix:workflows" = {
      exec = ''
        set -euo pipefail
        zizmor --fix .github/workflows/ .github/actions/ || true
        actionlint .github/workflows/*.yml
      '';
      description = "Auto-fix zizmor findings where possible, then validate workflow syntax.";
      binary = "bash";
    };
  };

  processes.docs.exec = ''
    cd docs && npm run dev
  '';
}
