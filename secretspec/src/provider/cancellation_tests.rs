//! Exercise registered CLI reads in isolated processes, without changing the
//! environment of concurrently running tests or invoking installed providers.
use super::{Address, ProviderCredentials};
use crate::{CancellationHandle, NativeAddress, SecretBytes};
use std::time::Duration;

const FIXTURE: &str = "provider::cancellation_tests::cli_fixture";

#[test]
fn registered_cli_reads_cancel_after_start() {
    let cases = [
        ("lastpass", "lpass"),
        ("pass", "pass"),
        ("gopass", "gopass"),
        ("dashlane", "dcli"),
        ("passbolt", "passbolt"),
        ("onepassword", "op"),
        ("onepassword+token", "op"),
        ("protonpass", "pass-cli"),
        #[cfg(feature = "bw")]
        ("bw", "bw"),
        #[cfg(feature = "bws")]
        ("bws", "bws"),
        #[cfg(feature = "sops")]
        ("sops", "sops"),
    ];
    for (scheme, binary) in cases {
        for phase in ["first", "read", "serial"] {
            if phase == "serial" && scheme != "protonpass" {
                continue;
            }
            let dir = tempfile::tempdir().unwrap();
            let cli = dir.path().join(binary);
            crate::fake_executable::install(
                &cli,
                r#"#!/bin/sh
if [ "$PHASE" != first ]; then
  case "$PROVIDER:$*" in
    lastpass:status) printf 'Logged in'; exit 0 ;;
    dashlane:status) printf 'Logged in: yes\nLocked: no\n'; exit 0 ;;
    onepassword:'vault list --format json') printf '[]'; exit 0 ;;
    protonpass:info) printf '{}'; exit 0 ;;
    protonpass:'item list '*)
      printf '%s' '{"items":[{"id":"one","share_id":"share","content":{"title":"11111111-1111-4111-8111-111111111111"}},{"id":"two","share_id":"share","content":{"title":"22222222-2222-4222-8222-222222222222"}}]}'
      exit 0 ;;
    passbolt:'list resource '*) printf '[]'; exit 0 ;;
  esac
fi
if [ "$PROVIDER" = sops ]; then
  [ "$SOPS_AGE_KEY" = fixture-age ] && [ "$AWS_SECRET_ACCESS_KEY" = fixture-aws ] || exit 4
fi
printf '%s' "$*" > "$READY/$$"
# Exercise both a blocked pipe and child-group cleanup.
sleep 60 &
wait
"#,
            );
            let ready = dir.path().join("ready");
            std::fs::create_dir(&ready).unwrap();
            let file = dir.path().join("encrypted.yaml");
            std::fs::write(&file, "sops: {}\n").unwrap();
            let spec = match scheme {
                "sops" => format!("sops://{}", file.display()),
                "bws" => "bws://11111111-1111-4111-8111-111111111111".into(),
                _ => format!("{scheme}://"),
            };
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", FIXTURE, "--nocapture"])
                .env_clear()
                .env("PATH", format!("{}:/usr/bin:/bin", dir.path().display()))
                .env("HOME", dir.path())
                .env("READY", &ready)
                .env(
                    "PROVIDER",
                    if matches!(scheme, "op" | "onepassword+token") {
                        "onepassword"
                    } else {
                        scheme
                    },
                )
                .env("PHASE", phase)
                .env(
                    "SECRETSPEC_PROVIDER_CONCURRENCY",
                    if phase == "serial" { "1" } else { "8" },
                )
                .env("SECRETSPEC_CANCELLATION_FIXTURE", &spec)
                .env("SECRETSPEC_OPCLI_PATH", &cli)
                .env("SECRETSPEC_PROTONPASS_CLI_PATH", &cli)
                .env("SECRETSPEC_PASSBOLT_CLI_PATH", &cli)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{scheme}/{phase}: {}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }
}

#[tokio::test]
async fn cli_fixture() {
    let Ok(spec) = std::env::var("SECRETSPEC_CANCELLATION_FIXTURE") else {
        return;
    };
    let ready = std::path::PathBuf::from(std::env::var_os("READY").unwrap());
    let handle = CancellationHandle::new();
    let cancel = handle.clone();
    let task = tokio::spawn(async move {
        crate::request::run(&handle, move |request| {
            let credentials = ProviderCredentials::from([
                ("access_token".into(), SecretBytes::from_utf8("fixture-bws")),
                ("age_key".into(), SecretBytes::from_utf8("fixture-age")),
                (
                    "aws_secret_access_key".into(),
                    SecretBytes::from_utf8("fixture-aws"),
                ),
            ]);
            let provider = super::managed_read::from_spec(&spec, credentials, &request)?;
            let one = NativeAddress {
                item: "11111111-1111-4111-8111-111111111111".into(),
                ..Default::default()
            };
            let two = NativeAddress {
                item: "22222222-2222-4222-8222-222222222222".into(),
                ..Default::default()
            };
            provider.get_many_with_metadata(&[
                ("ONE", Address::Native(&one)),
                ("TWO", Address::Native(&two)),
            ])
        })
        .await
    });
    let started = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if std::fs::read_dir(&ready).unwrap().next().is_some() {
                break true;
            }
            if task.is_finished() {
                break false;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await;
    cancel.cancel();
    let result = tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .unwrap()
        .unwrap();
    assert!(
        started.unwrap_or(false),
        "provider did not start the CLI: {:?}",
        result.as_ref().err()
    );
    let error = result.err().unwrap();
    assert_eq!(error.kind(), "cancelled", "{error}");
    if std::env::var("PHASE").as_deref() == Ok("serial") {
        assert_eq!(
            std::fs::read_dir(&ready).unwrap().count(),
            1,
            "a queued item started before the preceding read finished"
        );
    }
    for entry in std::fs::read_dir(ready).unwrap() {
        let pid: i32 = entry
            .unwrap()
            .file_name()
            .to_str()
            .unwrap()
            .parse()
            .unwrap();
        assert_eq!(
            unsafe { libc::kill(pid, 0) },
            -1,
            "child {pid} was not reaped"
        );
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::ESRCH)
        );
    }
}
