---
description: release secretspec crates
---

- next version is #$ARGUMENTS
- update /Cargo.toml files with the new version and all members
- update CHANGELOG.md with current date and version, using `git log --oneline vX.X.X..HEAD`
- cargo build
- commit
- add a git tag
- git push && git push origin vX.X.X
