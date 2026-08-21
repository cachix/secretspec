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
