---
main: fix
---

Fix release PR formatting and CI packaging failures so auto-generated release
PRs always pass checks. Run `fix:format` before committing in the release PR
workflow, use `dart pub publish --dry-run --skip-validation` in CI to avoid
server-side validation errors, and call `build:dist` directly in the publish
workflow instead of nesting devenv shells.
