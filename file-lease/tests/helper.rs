#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::{
    process::Command,
    time::{Duration, Instant},
};

#[test]
fn standalone_helper_hosts_a_lease() {
    let mut owner = Command::new("sleep").arg("60").spawn().unwrap();
    let lease = file_lease::FileLease::new(owner.id())
        .with_keeper_executable(env!("CARGO_BIN_EXE_file-lease"));
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
fn closed_standard_descriptors_child() {
    let Ok(mask) = std::env::var("FILE_LEASE_TEST_CLOSED_STDIO") else {
        return;
    };
    let mask: u8 = mask.parse().unwrap();
    for descriptor in 0..3 {
        if mask & (1 << descriptor) != 0 {
            assert_eq!(unsafe { libc::close(descriptor) }, 0);
        }
    }
    let lease = file_lease::FileLease::new(std::process::id())
        .with_keeper_executable(env!("CARGO_BIN_EXE_file-lease"));
    let path = lease.materialize(b"closed-stdio-fixture", None).unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), b"closed-stdio-fixture");
    drop(lease);
    assert!(!path.exists());
    // The test harness cannot report through intentionally closed descriptors.
    std::process::exit(0);
}

#[test]
fn standalone_helper_works_with_closed_standard_descriptors() {
    for mask in 1..8 {
        let status = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "closed_standard_descriptors_child",
                "--nocapture",
            ])
            .env("FILE_LEASE_TEST_CLOSED_STDIO", mask.to_string())
            .status()
            .unwrap();
        assert!(status.success(), "closed descriptor mask {mask} failed");
    }
}
