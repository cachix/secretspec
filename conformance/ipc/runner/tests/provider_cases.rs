use std::collections::BTreeSet;
use std::process::Command;

fn run_provider_cases(target: &str, implementation: &str, expected: &[&str]) {
    let output = Command::new(env!("CARGO_BIN_EXE_secretspec-ipc-conformance"))
        .args([
            "run",
            target,
            env!("CARGO_BIN_EXE_ipc-provider-conformance-driver"),
            "--implementation",
            implementation,
            "--endpoint",
            env!("CARGO_BIN_EXE_ipc-provider-endpoint-rust"),
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{implementation} provider suite failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    assert!(output.stderr.is_empty(), "provider suite wrote to stderr");
    let completed = String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .map(str::to_string)
        .collect::<BTreeSet<_>>();
    assert_eq!(
        completed,
        expected
            .iter()
            .map(|case| format!("ok {case}"))
            .collect::<BTreeSet<_>>()
    );
}

#[test]
fn checked_in_provider_cases_run_against_the_rust_endpoint() {
    run_provider_cases(
        "provider-endpoint",
        "endpoint",
        &[
            "provider.errors",
            "provider.lifecycle",
            "provider.operations",
            "wire.fragmented-frame",
            "wire.initialization-state",
            "wire.lifecycle",
            "wire.notifications",
            "wire.strict-rejections",
        ],
    );
}

#[test]
fn checked_in_provider_cases_run_through_the_external_adapter() {
    run_provider_cases(
        "external-adapter",
        "adapter",
        &[
            "provider.errors",
            "provider.operations",
            "provider.reconnect",
            "provider.session-isolation",
            "wire.fragmented-frame",
            "wire.strict-rejections",
        ],
    );
}

#[test]
fn transport_only_profile_runs_wire_cases_and_reports_semantic_cases() {
    let profile = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../profiles/transport-only.example.json");
    let output = Command::new(env!("CARGO_BIN_EXE_secretspec-ipc-conformance"))
        .args([
            "run",
            "provider-endpoint",
            env!("CARGO_BIN_EXE_ipc-provider-conformance-driver"),
            "--implementation",
            "endpoint",
            "--endpoint",
            env!("CARGO_BIN_EXE_ipc-provider-endpoint-rust"),
            "--profile",
        ])
        .arg(profile)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "transport-only suite failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    assert!(output.stderr.is_empty());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("ok wire.fragmented-frame"));
    assert!(stdout.contains("ok wire.initialization-state"));
    assert!(stdout.contains("ok wire.lifecycle"));
    assert!(stdout.contains("ok wire.notifications"));
    assert!(stdout.contains("ok wire.strict-rejections"));
    assert!(stdout.contains("not applicable provider.operations:"));
    assert!(stdout.contains("not applicable provider.lifecycle:"));
    assert!(stdout.contains("not applicable provider.errors:"));
}
