use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeSet;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const CANARY: &str = "SECRETSPEC_IPC_CANARY_DO_NOT_LOG";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Case {
    schema_version: u32,
    id: String,
    targets: Vec<String>,
    timeout_ms: u64,
    actions: Vec<Value>,
    required_events: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Transcript {
    case: String,
    events: Vec<Value>,
}

fn main() {
    if let Err(error) = execute() {
        eprintln!("conformance: {error}");
        std::process::exit(1);
    }
}

fn execute() -> Result<(), String> {
    let mut arguments = std::env::args_os().skip(1);
    let action = arguments
        .next()
        .and_then(|value| value.into_string().ok())
        .unwrap_or_else(|| "check".to_string());
    let cases = load_cases(&case_root())?;
    match action.as_str() {
        "check" => {
            check_schema_assets()?;
            println!("validated {} IPC conformance cases", cases.len());
            Ok(())
        }
        "run" => {
            let target = arguments
                .next()
                .and_then(|value| value.into_string().ok())
                .ok_or_else(|| "run requires a target name".to_string())?;
            let command = arguments
                .next()
                .ok_or_else(|| "run requires a driver executable".to_string())?;
            let command_arguments = arguments.collect::<Vec<_>>();
            let selected = cases
                .iter()
                .filter(|case| {
                    case.targets
                        .iter()
                        .any(|candidate| candidate == "common" || candidate == &target)
                })
                .collect::<Vec<_>>();
            if selected.is_empty() {
                return Err(format!("no cases select target {target}"));
            }
            for case in selected {
                run_case(case, &command, &command_arguments)?;
            }
            Ok(())
        }
        _ => Err("usage: secretspec-ipc-conformance [check | run TARGET COMMAND [ARGS...]]".into()),
    }
}

fn case_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../cases")
}

fn schema_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../schema/ipc/v1")
}

fn load_cases(directory: &Path) -> Result<Vec<Case>, String> {
    let mut paths = std::fs::read_dir(directory)
        .map_err(|error| error.to_string())?
        .map(|entry| {
            entry
                .map(|entry| entry.path())
                .map_err(|error| error.to_string())
        })
        .collect::<Result<Vec<_>, _>>()?;
    paths.sort();
    let mut cases = Vec::new();
    let mut ids = BTreeSet::new();
    for path in paths {
        if path.extension().and_then(|value| value.to_str()) != Some("json") {
            continue;
        }
        let bytes = std::fs::read(&path).map_err(|error| error.to_string())?;
        let case: Case = serde_json::from_slice(&bytes)
            .map_err(|error| format!("{}: {error}", path.display()))?;
        validate_case(&case)?;
        if !ids.insert(case.id.clone()) {
            return Err(format!("duplicate case ID {}", case.id));
        }
        cases.push(case);
    }
    if cases.is_empty() {
        return Err("the conformance case set is empty".into());
    }
    Ok(cases)
}

fn validate_case(case: &Case) -> Result<(), String> {
    if case.schema_version != 1
        || case.id.is_empty()
        || case.targets.is_empty()
        || case.timeout_ms == 0
        || case.timeout_ms > 60_000
        || case.actions.is_empty()
        || case.required_events.is_empty()
    {
        return Err(format!("case {} violates the version 1 bounds", case.id));
    }
    if case.targets.iter().collect::<BTreeSet<_>>().len() != case.targets.len()
        || case.required_events.iter().collect::<BTreeSet<_>>().len() != case.required_events.len()
    {
        return Err(format!("case {} contains duplicates", case.id));
    }
    Ok(())
}

fn check_schema_assets() -> Result<(), String> {
    for name in [
        "common.schema.json",
        "resolver.schema.json",
        "provider.schema.json",
        "resolver.openrpc.json",
        "provider.openrpc.json",
    ] {
        let path = schema_root().join(name);
        let bytes = std::fs::read(&path).map_err(|error| error.to_string())?;
        let value: Value = serde_json::from_slice(&bytes)
            .map_err(|error| format!("{}: {error}", path.display()))?;
        if !value.is_object() {
            return Err(format!("{} is not a JSON object", path.display()));
        }
    }
    Ok(())
}

fn run_case(
    case: &Case,
    executable: &std::ffi::OsStr,
    arguments: &[std::ffi::OsString],
) -> Result<(), String> {
    let mut child = Command::new(executable)
        .args(arguments)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("{}: launch failed: {error}", case.id))?;
    let mut input = serde_json::to_vec(case).map_err(|error| error.to_string())?;
    input.push(b'\n');
    child
        .stdin
        .take()
        .ok_or_else(|| "driver stdin was not piped".to_string())?
        .write_all(&input)
        .map_err(|error| error.to_string())?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| "driver stdout was not piped".to_string())?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| "driver stderr was not piped".to_string())?;
    let stdout_reader = std::thread::spawn(move || read_bounded(stdout));
    let stderr_reader = std::thread::spawn(move || read_bounded(stderr));
    let deadline = Instant::now() + Duration::from_millis(case.timeout_ms);
    let status = loop {
        if let Some(status) = child.try_wait().map_err(|error| error.to_string())? {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(format!("{}: driver timed out", case.id));
        }
        std::thread::sleep(Duration::from_millis(5));
    };
    let stdout = stdout_reader
        .join()
        .map_err(|_| "driver stdout reader panicked".to_string())??;
    let stderr = stderr_reader
        .join()
        .map_err(|_| "driver stderr reader panicked".to_string())??;
    if contains_canary(&stdout) || contains_canary(&stderr) {
        return Err(format!("{}: canary appeared in driver output", case.id));
    }
    if !status.success() {
        // Report what the driver said, not just that it died. The canary check
        // above already ran, so this cannot echo a secret into a CI log.
        let detail = String::from_utf8_lossy(&stderr);
        let detail = detail.trim();
        return Err(if detail.is_empty() {
            format!(
                "{}: driver exited with {status} without writing stderr",
                case.id
            )
        } else {
            format!("{}: driver exited with {status}: {detail}", case.id)
        });
    }
    let transcript: Transcript = serde_json::from_slice(&stdout)
        .map_err(|error| format!("{}: invalid transcript: {error}", case.id))?;
    if transcript.case != case.id {
        return Err(format!("{}: transcript case mismatch", case.id));
    }
    let event_kinds = transcript
        .events
        .iter()
        .filter_map(|event| event.get("kind").and_then(Value::as_str))
        .collect::<BTreeSet<_>>();
    for required in &case.required_events {
        if !event_kinds.contains(required.as_str()) {
            return Err(format!("{}: missing event {required}", case.id));
        }
    }
    println!("ok {}", case.id);
    Ok(())
}

fn read_bounded(mut reader: impl Read) -> Result<Vec<u8>, String> {
    const RETAIN: usize = 1024 * 1024;
    let mut retained = Vec::new();
    let mut buffer = [0_u8; 8192];
    loop {
        let read = reader
            .read(&mut buffer)
            .map_err(|error| error.to_string())?;
        if read == 0 {
            return Ok(retained);
        }
        let available = RETAIN.saturating_sub(retained.len());
        retained.extend_from_slice(&buffer[..read.min(available)]);
    }
}

fn contains_canary(bytes: &[u8]) -> bool {
    bytes
        .windows(CANARY.len())
        .any(|window| window == CANARY.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checked_in_cases_and_schemas_validate() {
        assert!(!load_cases(&case_root()).unwrap().is_empty());
        check_schema_assets().unwrap();
    }
}
