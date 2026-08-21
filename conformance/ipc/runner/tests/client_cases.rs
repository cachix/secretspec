use std::collections::BTreeSet;
use std::process::Command;

fn run_client_cases(target: &str, implementation: &str) {
    let output = Command::new(env!("CARGO_BIN_EXE_secretspec-ipc-conformance"))
        .args([
            "run",
            target,
            env!("CARGO_BIN_EXE_ipc-client-conformance-driver"),
            "--implementation",
            implementation,
            "--peer",
            env!("CARGO_BIN_EXE_ipc-fake-peer-rust"),
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{implementation} driver failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    assert!(output.stderr.is_empty(), "driver wrote to stderr");
    let completed = String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .map(str::to_string)
        .collect::<BTreeSet<_>>();
    assert_eq!(
        completed,
        BTreeSet::from([
            "ok client.lifecycle".to_string(),
            "ok wire.fragmented-frame".to_string(),
            "ok wire.strict-rejections".to_string(),
        ])
    );
}

#[test]
fn checked_in_client_cases_run_against_the_c_client() {
    run_client_cases("c-client", "c");
}

#[test]
fn checked_in_client_cases_run_against_the_rust_client() {
    run_client_cases("rust-client", "rust");
}
