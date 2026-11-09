#![cfg(all(feature = "cli", any(target_os = "linux", target_os = "macos")))]

use std::{
    process::Command,
    time::{Duration, Instant},
};

#[test]
fn installed_cli_hosts_a_lease_without_an_application_helper_hook() {
    let mut owner = Command::new("sleep").arg("60").spawn().unwrap();
    let lease = secretspec::FileLease::new(owner.id())
        .with_keeper_executable(env!("CARGO_BIN_EXE_secretspec"));
    let path = lease.materialize(b"public-cli-fixture", None).unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), b"public-cli-fixture");
    lease.handoff().unwrap();
    drop(lease);
    assert_eq!(std::fs::read(&path).unwrap(), b"public-cli-fixture");
    owner.kill().unwrap();
    owner.wait().unwrap();
    let deadline = Instant::now() + Duration::from_secs(15);
    while path.exists() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(!path.exists(), "CLI keeper outlived its consumer");
}

#[test]
fn published_lease_adapter_preserves_suffixes_and_io_errors() {
    let lease = secretspec::FileLease::new(std::process::id())
        .with_keeper_executable(env!("CARGO_BIN_EXE_secretspec"));
    let error = lease
        .materialize(b"invalid-suffix", Some("../escape"))
        .unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);

    let payload = b"binary\0fixture\n";
    let path = lease.materialize(payload, Some(".pem")).unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), payload);
    #[cfg(target_os = "macos")]
    assert_eq!(path.extension().unwrap(), "pem");
    drop(lease);
    assert!(!path.exists());
}

#[test]
fn closed_standard_descriptors_child() {
    let Ok(mask) = std::env::var("SECRETSPEC_TEST_CLOSED_STDIO") else {
        return;
    };
    let mask: u8 = mask.parse().unwrap();
    for descriptor in 0..3 {
        if mask & (1 << descriptor) != 0 {
            assert_eq!(unsafe { libc::close(descriptor) }, 0);
        }
    }
    let lease = secretspec::FileLease::new(std::process::id())
        .with_keeper_executable(env!("CARGO_BIN_EXE_secretspec"));
    let path = lease.materialize(b"closed-stdio-fixture", None).unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), b"closed-stdio-fixture");
    drop(lease);
    assert!(!path.exists());
    // The test harness cannot report through intentionally closed descriptors.
    std::process::exit(0);
}

#[test]
fn installed_cli_works_with_closed_standard_descriptors() {
    for mask in 1..8 {
        let status = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "closed_standard_descriptors_child",
                "--nocapture",
            ])
            .env("SECRETSPEC_TEST_CLOSED_STDIO", mask.to_string())
            .status()
            .unwrap();
        assert!(status.success(), "closed descriptor mask {mask} failed");
    }
}

#[test]
fn validated_and_cloned_values_retain_the_lease() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("secretspec.toml"), "[project]\nname='file-lease-test'\nrevision='1.0'\nrequire_reason=false\n[profiles.default]\nKEY={description='key',as_path=true}\n").unwrap();
    std::fs::write(root.path().join(".env"), "KEY=public-test-key\n").unwrap();
    let mut spec = secretspec::Secrets::load_from(&root.path().join("secretspec.toml")).unwrap();
    spec.set_file_storage(secretspec::FileStorageMode::FileLease);
    spec.set_provider("dotenv:.env");
    let validated = spec.validate().unwrap().unwrap();
    let path = std::path::PathBuf::from(
        std::str::from_utf8(validated.resolved.secrets["KEY"].expose_secret()).unwrap(),
    );
    let cloned = validated.resolved.clone();
    drop(validated);
    drop(spec);
    assert_eq!(std::fs::read(&path).unwrap(), b"public-test-key");
    drop(cloned);
    let deadline = Instant::now() + Duration::from_secs(15);
    while path.exists() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(!path.exists());
}

fn cli_project() -> tempfile::TempDir {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("secretspec.toml"), "[project]\nname='default-file-lease'\nrevision='1.0'\nrequire_reason=false\n[profiles.default]\nKEY={description='key',default='public-fixture',as_path=true}\nARGS={description='args',composed='key=${KEY}'}\n[scopes.app]\nsecrets=['ARGS']\n").unwrap();
    std::fs::create_dir(root.path().join("tmp")).unwrap();
    root
}

fn shell(root: &std::path::Path, script: &str) -> Command {
    let mut command = Command::new("sh");
    command.args(["-c", script]);
    configure(&mut command, root);
    command
}

fn configure(command: &mut Command, root: &std::path::Path) {
    command
        .current_dir(root)
        .env("CLI", env!("CARGO_BIN_EXE_secretspec"))
        .env("SECRETSPEC_FILE_STORAGE", "file-lease")
        .env("HOME", root)
        .env("XDG_CONFIG_HOME", root.join("config"))
        .env("XDG_STATE_HOME", root.join("state"))
        .env("TMPDIR", root.join("tmp"))
        .env_remove("SECRETSPEC_PROVIDER")
        .env_remove("SECRETSPEC_PROFILE")
        .env_remove("SECRETSPEC_SCOPE")
        .env_remove("SECRETSPEC_REASON");
}

fn wait_for_cleanup(root: &std::path::Path, path: &std::path::Path) {
    let metadata = root.join("Library/Application Support/file-lease");
    let pending = || std::fs::read_dir(&metadata).is_ok_and(|mut entries| entries.next().is_some());
    let deadline = Instant::now() + Duration::from_secs(15);
    while (path.exists() || pending()) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(!path.exists());
    assert!(
        !pending(),
        "macOS cleanup must finish before removing the fixture home"
    );
}

#[test]
fn get_and_export_paths_survive_command_substitution_until_the_shell_exits() {
    for script in [
        r#"KEY=$("$CLI" get KEY --provider env) || exit; printf '%s\n' "$KEY"; cat "$KEY""#,
        r#"ARGS=$("$CLI" get ARGS --provider env) || exit; KEY=${ARGS#key=}; printf '%s\n' "$KEY"; cat "$KEY""#,
        r#"eval "$("$CLI" export --provider env)"; printf '%s\n' "$KEY"; cat "$KEY""#,
        r#"eval "$("$CLI" export --provider env --scope app)"; KEY=${ARGS#key=}; printf '%s\n' "$KEY"; cat "$KEY""#,
    ] {
        let root = cli_project();
        let output = shell(root.path(), script).output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8(output.stdout).unwrap();
        let (path, value) = stdout.split_once('\n').unwrap();
        assert_eq!(value, "public-fixture");
        wait_for_cleanup(root.path(), std::path::Path::new(path));
        assert_eq!(
            std::fs::read_dir(root.path().join("tmp")).unwrap().count(),
            0
        );
    }
}

#[test]
fn exported_paths_are_revoked_after_shell_sigkill() {
    use std::io::BufRead;
    use std::process::Stdio;
    let root = cli_project();
    let mut owner = shell(
        root.path(),
        r#"KEY=$("$CLI" get KEY --provider env) || exit; printf '%s\n' "$KEY"; read hold"#,
    )
    .stdin(Stdio::piped())
    .stdout(Stdio::piped())
    .spawn()
    .unwrap();
    let mut path = String::new();
    std::io::BufReader::new(owner.stdout.take().unwrap())
        .read_line(&mut path)
        .unwrap();
    let path = std::path::Path::new(path.trim());
    assert_eq!(std::fs::read(path).unwrap(), b"public-fixture");
    owner.kill().unwrap();
    owner.wait().unwrap();
    wait_for_cleanup(root.path(), path);
}

#[test]
fn run_files_follow_the_consumer_after_launcher_sigkill() {
    use std::io::BufRead;
    use std::process::Stdio;
    let root = cli_project();
    let mut command = Command::new(env!("CARGO_BIN_EXE_secretspec"));
    configure(&mut command, root.path());
    let mut launcher = command
        .args([
            "run",
            "--provider",
            "env",
            "--",
            "sh",
            "-c",
            r#"printf '%s\n%s\n' "$$" "$KEY"; read hold"#,
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    // Receiving output proves the redaction pump started after ownership handoff.
    // Keep stdin's writer alive across Child::wait, which otherwise closes it.
    let _input = launcher.stdin.take().unwrap();
    let mut output = std::io::BufReader::new(launcher.stdout.take().unwrap());
    let mut pid = String::new();
    let mut path = String::new();
    output.read_line(&mut pid).unwrap();
    output.read_line(&mut path).unwrap();
    let consumer = pid.trim().parse::<i32>().unwrap();
    let path = std::path::Path::new(path.trim());
    launcher.kill().unwrap();
    launcher.wait().unwrap();
    let readable = std::fs::read(path);
    assert_eq!(unsafe { libc::kill(consumer, libc::SIGKILL) }, 0);
    assert_eq!(readable.unwrap(), b"public-fixture");
    wait_for_cleanup(root.path(), path);
}

#[test]
fn native_release_revokes_hidden_dependencies_and_is_idempotent() {
    let root = cli_project();
    let mut spec = secretspec::Secrets::load_from(&root.path().join("secretspec.toml")).unwrap();
    spec.set_file_storage(secretspec::FileStorageMode::FileLease);
    spec.set_provider("env");
    spec.set_scope("app");
    let resolved = spec.resolve().unwrap();
    assert!(!resolved.secrets.contains_key("KEY"));
    let path = std::path::Path::new(
        resolved.secrets["ARGS"]
            .value
            .as_ref()
            .unwrap()
            .strip_prefix("key=")
            .unwrap(),
    );
    assert_eq!(std::fs::read(path).unwrap(), b"public-fixture");
    let request = serde_json::json!({"request_version": 1, "operation": "release_files",
        "source": {"lease_id": resolved.file_lease_id.as_ref().unwrap()}});
    let response: serde_json::Value =
        serde_json::from_str(&secretspec::call_json(&request.to_string())).unwrap();
    assert_eq!(response["ok"], true);
    assert_eq!(response["response"]["released"], 1);
    assert!(!path.exists());
    resolved.close().unwrap();
    let unrelated = root.path().join("unrelated");
    std::fs::write(&unrelated, "keep").unwrap();
    let response = secretspec::call_json(
        &serde_json::json!({"request_version":1,"operation":"release_files",
        "source":{"lease_id":unrelated.to_str().unwrap()}})
        .to_string(),
    );
    assert!(response.contains("\"ok\":true"));
    assert_eq!(std::fs::read(unrelated).unwrap(), b"keep");
}

#[test]
fn separate_results_share_storage_but_release_independently() {
    let root = cli_project();
    let mut spec = secretspec::Secrets::load_from(&root.path().join("secretspec.toml")).unwrap();
    spec.set_file_storage(secretspec::FileStorageMode::FileLease);
    spec.set_provider("env");
    let first = spec.resolve().unwrap();
    let second = spec.resolve().unwrap();
    let one = std::path::Path::new(first.secrets["KEY"].path.as_ref().unwrap());
    let two = std::path::Path::new(second.secrets["KEY"].path.as_ref().unwrap());
    assert_eq!(one.parent(), two.parent());
    assert_ne!(one, two);
    first.close().unwrap();
    assert!(!one.exists());
    assert_eq!(std::fs::read(two).unwrap(), b"public-fixture");
    second.close().unwrap();
    assert!(!two.exists());
}

#[test]
fn native_reader_requires_a_live_result_and_its_exact_path() {
    let root = cli_project();
    let mut spec = secretspec::Secrets::load_from(&root.path().join("secretspec.toml")).unwrap();
    spec.set_file_storage(secretspec::FileStorageMode::FileLease);
    spec.set_provider("env");
    let first = spec.resolve().unwrap();
    let second = spec.resolve().unwrap();
    let path = first.secrets["KEY"].path.as_ref().unwrap();
    let unrelated = root.path().join("unrelated");
    std::fs::write(&unrelated, "private-unrelated-data").unwrap();
    let read = |id: &str, path: &std::path::Path| -> serde_json::Value {
        serde_json::from_str(&secretspec::call_json(
            &serde_json::json!({
                "request_version": 1, "operation": "read_file",
                "source": {"lease_id": id, "path": path}
            })
            .to_string(),
        ))
        .unwrap()
    };
    let id = first.file_lease_id.as_ref().unwrap();
    let response = read(id, path.as_ref());
    assert_eq!(response["ok"], true);
    assert_eq!(
        data_encoding::BASE64
            .decode(response["response"]["base64"].as_str().unwrap().as_bytes())
            .unwrap(),
        b"public-fixture"
    );
    for denied in [
        read("unknown-token", path.as_ref()),
        read(second.file_lease_id.as_ref().unwrap(), path.as_ref()),
        read(id, &unrelated),
    ] {
        assert_eq!(denied["ok"], false);
        assert!(!denied.to_string().contains("private-unrelated-data"));
    }
    first.close().unwrap();
    assert_eq!(read(id, path.as_ref())["ok"], false);
    second.close().unwrap();
}

#[test]
#[cfg(target_os = "linux")]
fn exhausted_descriptor_namespace_rotates_storage_child() {
    if std::env::var_os("SECRETSPEC_TEST_LOW_FDS").is_none() {
        return;
    }
    let limit = libc::rlimit {
        rlim_cur: 64,
        rlim_max: 64,
    };
    assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limit) }, 0);
    let root = cli_project();
    let mut spec = secretspec::Secrets::load_from(&root.path().join("secretspec.toml")).unwrap();
    spec.set_file_storage(secretspec::FileStorageMode::FileLease);
    spec.set_provider("env");
    let anchor = spec.validate().unwrap().unwrap();
    let path = anchor.resolved.secrets["KEY"].try_as_utf8().unwrap();
    for _ in 0..100 {
        let result = spec.validate().unwrap().unwrap();
        assert_eq!(
            std::fs::read(result.resolved.secrets["KEY"].try_as_utf8().unwrap()).unwrap(),
            b"public-fixture"
        );
        assert_eq!(std::fs::read(path).unwrap(), b"public-fixture");
    }
    drop(anchor);
}

#[test]
#[cfg(target_os = "linux")]
fn descriptor_namespace_rotation_preserves_live_readers() {
    assert!(
        Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "exhausted_descriptor_namespace_rotates_storage_child",
                "--nocapture"
            ])
            .env("SECRETSPEC_TEST_LOW_FDS", "1")
            .status()
            .unwrap()
            .success()
    );
}
