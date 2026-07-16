---
description: release secretspec crates
---

- next version is #$ARGUMENTS
- create a release branch: `git checkout -b release-X.X.X`
- update /Cargo.toml: bump `workspace.package` version and the `secretspec` / `secretspec-derive` entries in `workspace.dependencies`; also bump the `secretspec` dependency pin in secretspec-derive/Cargo.toml (all member crates inherit `version.workspace = true`)
- bump the SDK packaging files: secretspec-node/package.json, secretspec-py/pyproject.toml, secretspec-hs/secretspec.cabal, secretspec-rb/secretspec.gemspec (composer.json has no version field, Packagist reads git tags)
- update CHANGELOG.md: retitle `## [Unreleased]` to the new version with the current date, and cross-check the section against `git log --oneline vX.X.X..HEAD` for missing user facing entries
- cargo build (verifies the workspace and updates Cargo.lock)
- commit as `Release X.X.X` and push the branch
- open a PR with `gh pr create`
- wait for the PR to be merged (do not tag before merge)
- after merge: `git checkout main && git pull`, then `git tag vX.X.X && git push origin vX.X.X`
