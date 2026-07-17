//! Deterministic coverage that a typed loader ignores an ambient
//! `SECRETSPEC_SCOPE` while the untyped path honors it.
//!
//! Setting `SECRETSPEC_SCOPE` in-process would race the parallel unit suite —
//! every resolving test reads the scope env fallback — so this drives real
//! library resolution in a **child process** that owns its own environment. The
//! parent re-execs this same test binary in two modes and compares the resolved
//! secret sets the child writes back. The child is made hermetic (its own
//! `HOME`/`XDG_CONFIG_HOME`, an explicit provider) so it never touches the real
//! user config or audit log.

use std::fs;
use std::path::Path;
use std::process::Command;

/// Set on the child so it runs the resolution branch instead of the parent
/// orchestration; its value ("typed" or "untyped") selects the loader behavior.
const MODE: &str = "SECRETSPEC_TYPED_SCOPE_TEST_MODE";
/// File the child writes its sorted resolved secret names to.
const OUT: &str = "SECRETSPEC_TYPED_SCOPE_TEST_OUT";

const MANIFEST: &str = r#"
[project]
name = "typed-scope-env"
revision = "1.0"
require_reason = false

[profiles.default]
DATABASE_URL = { description = "DB", required = true }
API_KEY = { description = "API key", required = true }
QUEUE_TOKEN = { description = "Queue token", required = true }

[scopes.api]
secrets = ["DATABASE_URL", "API_KEY"]
"#;

const ENV_FILE: &str = "DATABASE_URL=db\nAPI_KEY=key\nQUEUE_TOKEN=tok\n";

/// The child entry point: load from the project (its cwd) under an ambient
/// `SECRETSPEC_SCOPE=api`, optionally suppress the ambient scope exactly as the
/// `secretspec-derive` typed loader does, resolve, and write the sorted resolved
/// names for the parent to assert. Runs only when `MODE` is set, so the ordinary
/// `cargo test` pass (no mode) skips it.
#[test]
fn typed_scope_env_child() {
    let Ok(mode) = std::env::var(MODE) else {
        return;
    };
    let out = std::env::var(OUT).expect("child needs an output path");

    let mut spec = secretspec::Secrets::load().expect("load secretspec.toml from cwd");
    if mode == "typed" {
        // What the generated typed loader calls, so an ambient SECRETSPEC_SCOPE
        // cannot narrow the full generated shape.
        spec.set_ignore_ambient_scope(true);
    }
    let response = spec.resolve().expect("resolve secrets");
    let mut names: Vec<String> = response.secrets.keys().cloned().collect();
    names.sort();
    fs::write(out, names.join(",")).expect("write resolved names");
}

/// Re-exec this test binary as the child in `mode`, returning the sorted
/// resolved names it produced.
fn resolved_names(exe: &Path, project: &Path, mode: &str) -> String {
    let out = project.join(format!("out-{mode}"));
    let status = Command::new(exe)
        .args(["typed_scope_env_child", "--exact", "--nocapture"])
        .current_dir(project)
        .env(MODE, mode)
        .env(OUT, &out)
        // Resolve against the project's `.env`, under the ambient scope the typed
        // path must ignore.
        .env(
            "SECRETSPEC_PROVIDER",
            format!("dotenv://{}", project.join(".env").display()),
        )
        .env("SECRETSPEC_SCOPE", "api")
        // Keep the child hermetic: no inherited profile, and its own config home
        // so it never reads the real user config or writes the real audit log.
        .env_remove("SECRETSPEC_PROFILE")
        .env("HOME", project)
        .env("XDG_CONFIG_HOME", project)
        .status()
        .expect("spawn child test binary");
    assert!(status.success(), "child ({mode}) exited with failure");
    fs::read_to_string(&out).expect("child wrote resolved names")
}

#[test]
fn typed_load_ignores_ambient_scope_while_untyped_honors_it() {
    // Only the parent (no mode set) sets up the project and re-execs the child.
    if std::env::var(MODE).is_ok() {
        return;
    }

    let project =
        std::env::temp_dir().join(format!("secretspec-typed-scope-{}", std::process::id()));
    fs::create_dir_all(&project).unwrap();
    fs::write(project.join("secretspec.toml"), MANIFEST).unwrap();
    fs::write(project.join(".env"), ENV_FILE).unwrap();

    let exe = std::env::current_exe().expect("current test binary");
    let untyped = resolved_names(&exe, &project, "untyped");
    let typed = resolved_names(&exe, &project, "typed");

    // Untyped resolution honors the ambient scope: only the `api` subset resolves.
    assert_eq!(
        untyped, "API_KEY,DATABASE_URL",
        "untyped resolution honors SECRETSPEC_SCOPE"
    );
    // A typed loader suppresses the ambient scope: the whole profile resolves.
    assert_eq!(
        typed, "API_KEY,DATABASE_URL,QUEUE_TOKEN",
        "a typed loader ignores an ambient SECRETSPEC_SCOPE and sees the full profile"
    );

    let _ = fs::remove_dir_all(&project);
}
