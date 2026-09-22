#![cfg(all(feature = "cli", unix))]

use secretspec_ipc::connection::{FilesystemAccess, SshOptions};
use secretspec_ipc::lifecycle::ResolverSession;
use secretspec_ipc::protocol::resolver::{
    GetParams, GetResult, InitializeApplication, Manifest, Purpose, Representation, SetParams,
};
use secretspec_ipc::{ErrorKind, Limits, Product, deadline_unix_ms_after};
use std::os::unix::fs::{PermissionsExt, symlink};
use std::time::Duration;

fn deadline() -> u64 {
    deadline_unix_ms_after(Duration::from_secs(10))
}

fn product() -> Product {
    Product {
        name: "ssh-integration-test".into(),
        version: "1".into(),
    }
}

fn limits() -> Limits {
    Limits {
        max_frame_bytes: 32768,
        max_in_flight: 4,
    }
}

fn purpose() -> Purpose {
    Purpose {
        consumer: "ssh-test".into(),
        operation: "resolve".into(),
        host: None,
        path: None,
    }
}

/// Emulate SSH's remote-shell command execution, using the real resolver CLI.
/// No SSH daemon, enrolled keys, or network is required by this test.
fn fixture() -> (tempfile::TempDir, SshOptions, InitializeApplication) {
    let directory = tempfile::tempdir().unwrap();
    let remote = directory.path().join("resolver 'quoted' $(false)");
    symlink(env!("CARGO_BIN_EXE_secretspec"), &remote).unwrap();
    let ssh = directory.path().join("ssh");
    let log = directory.path().join("arguments");
    std::fs::write(&ssh, format!(
        "#!/bin/sh\nfor argument do printf '%s\\n' \"$argument\"; done > '{}'\nfor argument do command=$argument; done\nexec sh -c \"$command\"\n",
        log.display()
    )).unwrap();
    std::fs::set_permissions(&ssh, std::fs::Permissions::from_mode(0o700)).unwrap();
    let dotenv = directory.path().join("values.env");
    std::fs::write(&dotenv, "TOKEN=remote-value\nCERT=certificate\n").unwrap();
    let mut options = SshOptions::new("developer");
    options.executable = ssh;
    options.remote_executable = remote.to_string_lossy().into_owned();
    let application = InitializeApplication {
        manifest: Manifest::Inline {
            toml: "[project]\nname = 'ssh-test'\nrevision = '1.0'\nrequire_reason = false\n[profiles.default]\nTOKEN = { description = 'token' }\nCERT = { description = 'certificate', as_path = true }\n".into(),
            base_dir: directory.path().to_string_lossy().into_owned(),
        },
        provider: Some(format!("dotenv:{}", dotenv.display())),
        profile: Some("default".into()),
        scope: None,
        reason: None,
        requested_authorization_duration_ms: None,
    };
    (directory, options, application)
}

#[test]
fn blocking_ssh_uses_the_same_filesystem_policy() {
    let (_directory, options, application) = fixture();
    let mut session = secretspec_ipc::blocking::ResolverSession::launch_ssh(
        options,
        product(),
        limits(),
        application,
        deadline(),
    )
    .unwrap();
    let result = session
        .get(
            &GetParams {
                name: "TOKEN".into(),
                representation: Representation::Auto,
                purpose: purpose(),
            },
            deadline(),
        )
        .unwrap();
    assert!(matches!(result, GetResult::Value(_)));
    let error = session
        .get(
            &GetParams {
                name: "CERT".into(),
                representation: Representation::Auto,
                purpose: purpose(),
            },
            deadline(),
        )
        .unwrap_err();
    assert_eq!(error.rpc_kind(), Some(ErrorKind::RepresentationMismatch));
    assert!(
        session
            .get(
                &GetParams {
                    name: "CERT".into(),
                    representation: Representation::Path,
                    purpose: purpose()
                },
                deadline()
            )
            .is_err()
    );
    session.close(deadline()).unwrap();
}

#[tokio::test]
async fn ssh_launch_quotes_remote_executable_and_enforces_remote_read_only_defaults() {
    let (directory, options, application) = fixture();
    let session = ResolverSession::launch_ssh(
        options.clone(),
        product(),
        limits(),
        application.clone(),
        deadline(),
    )
    .await
    .unwrap();
    assert!(!session.supports("resolver.set"));
    let result = session
        .get(
            &GetParams {
                name: "TOKEN".into(),
                representation: Representation::Auto,
                purpose: purpose(),
            },
            deadline(),
        )
        .await
        .unwrap();
    let GetResult::Value(result) = result else {
        panic!("expected inline value")
    };
    assert_eq!(result.value, "remote-value");
    let error = session
        .get(
            &GetParams {
                name: "CERT".into(),
                representation: Representation::Auto,
                purpose: purpose(),
            },
            deadline(),
        )
        .await
        .unwrap_err();
    assert_eq!(error.rpc_kind(), Some(ErrorKind::RepresentationMismatch));
    session.close(deadline()).await.unwrap();

    let arguments = std::fs::read_to_string(directory.path().join("arguments")).unwrap();
    for option in [
        "-T",
        "-oBatchMode=yes",
        "-oStrictHostKeyChecking=yes",
        "-oForwardAgent=no",
        "-oClearAllForwardings=yes",
    ] {
        assert!(arguments.lines().any(|argument| argument == option));
    }
    assert!(arguments.ends_with(" serve --read-only\n"));

    // Opting into shared paths and writes preserves ordinary resolver behavior.
    let mut options = options;
    options.filesystem = FilesystemAccess::Shared;
    options.read_only = false;
    let session =
        ResolverSession::launch_ssh(options, product(), limits(), application, deadline())
            .await
            .unwrap();
    assert!(session.supports("resolver.set"));
    session
        .set(
            &SetParams {
                name: "TOKEN".into(),
                value: "updated".into(),
                purpose: purpose(),
            },
            deadline(),
        )
        .await
        .unwrap();
    let GetResult::Path(result) = session
        .get(
            &GetParams {
                name: "CERT".into(),
                representation: Representation::Auto,
                purpose: purpose(),
            },
            deadline(),
        )
        .await
        .unwrap()
    else {
        panic!("expected path")
    };
    assert_eq!(
        std::fs::read_to_string(&result.path).unwrap(),
        "certificate"
    );
    session.close(deadline()).await.unwrap();
    assert!(!std::path::Path::new(&result.path).exists());
}
