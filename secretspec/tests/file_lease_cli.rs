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
