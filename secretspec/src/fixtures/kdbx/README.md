# KDBX 4.0 regression fixtures

These password-protected databases are copied unchanged from
[keepass-rs tests/resources](https://github.com/sseemayer/keepass-rs/tree/5fb4f30bbe1403b0bc4218d91dab3bc90216615d/tests/resources).
They use the test password `demopass` and exercise Argon2d and Argon2id.
The upstream MIT license is included in `LICENSE`.

They reproduce issue #445 without modifying authenticated header bytes or
requiring an installed KeePass client. Tests verify that writing upgrades the
format to KDBX 4.1 and preserves the database's security settings and entries.
