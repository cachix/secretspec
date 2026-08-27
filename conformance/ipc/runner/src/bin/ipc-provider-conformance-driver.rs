use secrecy::{ExposeSecret, SecretString};
use secretspec::{
    Address as CoreAddress, DiscoveryContext, ExternalProvider, Provider, ProviderEndpoint,
    SecretSpecError,
};
use secretspec_ipc::lifecycle::{Environment, LaunchOptions, ProviderSession};
use secretspec_ipc::protocol::provider::{
    self as wire, Address, AddressParams, ApplicationContext, ClearParams, ClearScope,
    GetManyParams, GetManyResult, GetResult, InitializeApplication, NamedRequest, ReflectParams,
    ReflectResult, ResolveAddressResult, SetExpiringParams, SetParams,
};
use secretspec_ipc::protocol::{
    InitializeParams, Limits, PROTOCOL_VERSION, PROVIDER_PROTOCOL, Product,
};
use secretspec_ipc::{Error, ErrorKind};
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const CANARY: &str = "SECRETSPEC_IPC_CANARY_DO_NOT_LOG";
const MAX_CASE_BYTES: u64 = 1024 * 1024;
const MAX_FRAME_BYTES: usize = 1024 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Case {
    schema_version: u32,
    id: String,
    targets: Vec<String>,
    timeout_ms: u64,
    actions: Vec<Value>,
    required_events: Vec<String>,
}

#[derive(Clone, Copy)]
enum Implementation {
    Endpoint,
    Adapter,
}

fn main() {
    if let Err(error) = execute() {
        eprintln!("provider conformance driver: {error}");
        std::process::exit(1);
    }
}

/// Copy the endpoint into a directory whose ACL the external adapter trusts.
///
/// On Windows the adapter validates the endpoint executable and its parent
/// against a trust domain. A build directory is not a deployment location and
/// carries whatever ACL it inherited, so the endpoint is staged elsewhere and
/// that directory's ACL is set explicitly. Relying on what a temporary
/// directory inherits is not enough: on a CI runner that inheritance is
/// outside our control, and it has changed underneath this suite before.
/// Other platforms run the endpoint where it was built.
#[cfg(windows)]
fn stage_endpoint(endpoint: &Path) -> Result<Option<(tempfile::TempDir, PathBuf)>, String> {
    let directory = tempfile::tempdir().map_err(|error| error.to_string())?;
    secretspec::windows_security::make_path_private(directory.path())
        .map_err(|error| format!("failed to secure the staging directory: {error}"))?;
    let name = endpoint
        .file_name()
        .ok_or_else(|| "endpoint path has no file name".to_string())?;
    let staged = directory.path().join(name);
    std::fs::copy(endpoint, &staged).map_err(|error| error.to_string())?;
    Ok(Some((directory, staged)))
}

#[cfg(not(windows))]
fn stage_endpoint(_endpoint: &Path) -> Result<Option<(tempfile::TempDir, PathBuf)>, String> {
    Ok(None)
}
fn execute() -> Result<(), String> {
    let (implementation, endpoint) = arguments()?;
    let staged = stage_endpoint(&endpoint)?;
    let endpoint = match &staged {
        Some((_directory, path)) => path.clone(),
        None => endpoint,
    };
    let mut input = Vec::new();
    io::stdin()
        .take(MAX_CASE_BYTES + 1)
        .read_to_end(&mut input)
        .map_err(|error| error.to_string())?;
    if input.len() as u64 > MAX_CASE_BYTES {
        return Err("conformance case exceeds 1 MiB".into());
    }
    let case: Case = serde_json::from_slice(&input).map_err(|error| error.to_string())?;
    validate_case(&case)?;
    let events = match case.id.as_str() {
        "wire.fragmented-frame" => match implementation {
            Implementation::Endpoint => run_fragmented_server(&endpoint, &case)?,
            Implementation::Adapter => run_fragmented_adapter(&endpoint, &case)?,
        },
        "wire.strict-rejections" => match implementation {
            Implementation::Endpoint => run_strict_server_rejections(&endpoint, &case)?,
            Implementation::Adapter => run_strict_adapter_rejections(&endpoint, &case)?,
        },
        "provider.operations" => {
            require_methods(
                &case,
                &[
                    "provider.resolve_address",
                    "provider.get",
                    "provider.get_many",
                    "provider.exists",
                    "provider.set",
                    "provider.set_expiring",
                    "provider.delete",
                    "provider.clear",
                    "provider.check_writable",
                    "provider.check_deletable",
                    "provider.describe_write_target",
                    "provider.reflect",
                ],
            )?;
            match implementation {
                Implementation::Endpoint => run_async(run_endpoint_operations(&endpoint))?,
                Implementation::Adapter => run_adapter_operations(&endpoint)?,
            }
        }
        "provider.lifecycle" if matches!(implementation, Implementation::Endpoint) => {
            require_action(&case.actions, "cancel")?;
            require_action(&case.actions, "deadline")?;
            run_async(run_endpoint_lifecycle(&endpoint))?
        }
        "provider.reconnect" if matches!(implementation, Implementation::Adapter) => {
            require_action(&case.actions, "crash")?;
            require_action(&case.actions, "reconnect")?;
            run_adapter_reconnect(&endpoint)?
        }
        "provider.errors" => {
            require_action(&case.actions, "explicit_retry")?;
            match implementation {
                Implementation::Endpoint => run_async(run_endpoint_errors(&endpoint))?,
                Implementation::Adapter => run_adapter_errors(&endpoint)?,
            }
        }
        "provider.session-isolation" if matches!(implementation, Implementation::Adapter) => {
            require_action(&case.actions, "change_reason")?;
            run_adapter_session_isolation(&endpoint)?
        }
        other => return Err(format!("unsupported provider conformance case {other}")),
    };
    serde_json::to_writer(
        io::stdout().lock(),
        &json!({"case": case.id, "events": events}),
    )
    .map_err(|error| error.to_string())?;
    Ok(())
}

fn arguments() -> Result<(Implementation, PathBuf), String> {
    let mut arguments = std::env::args_os().skip(1);
    if arguments.next().as_deref() != Some(std::ffi::OsStr::new("--implementation")) {
        return Err("expected --implementation endpoint|adapter --endpoint PATH".into());
    }
    let implementation = match arguments.next().and_then(|value| value.into_string().ok()) {
        Some(value) if value == "endpoint" => Implementation::Endpoint,
        Some(value) if value == "adapter" => Implementation::Adapter,
        _ => return Err("implementation must be endpoint or adapter".into()),
    };
    if arguments.next().as_deref() != Some(std::ffi::OsStr::new("--endpoint")) {
        return Err("expected --endpoint PATH".into());
    }
    let endpoint = arguments
        .next()
        .map(PathBuf::from)
        .ok_or_else(|| "missing endpoint path".to_string())?;
    if arguments.next().is_some() {
        return Err("unexpected driver argument".into());
    }
    Ok((implementation, endpoint))
}

fn validate_case(case: &Case) -> Result<(), String> {
    if case.schema_version != 1
        || case.targets.is_empty()
        || case.timeout_ms == 0
        || case.actions.is_empty()
        || case.required_events.is_empty()
    {
        return Err("invalid conformance case envelope".into());
    }
    Ok(())
}

fn require_action<'a>(actions: &'a [Value], kind: &str) -> Result<&'a Value, String> {
    actions
        .iter()
        .find(|action| action.get("kind").and_then(Value::as_str) == Some(kind))
        .ok_or_else(|| format!("case has no {kind} action"))
}

fn require_methods(case: &Case, methods: &[&str]) -> Result<(), String> {
    let present = case
        .actions
        .iter()
        .filter(|action| action.get("kind").and_then(Value::as_str) == Some("call"))
        .filter_map(|action| action.get("method").and_then(Value::as_str))
        .collect::<BTreeSet<_>>();
    if let Some(missing) = methods.iter().find(|method| !present.contains(**method)) {
        return Err(format!("case has no call for {missing}"));
    }
    Ok(())
}

fn event(kind: &str) -> Value {
    json!({"kind": kind})
}

fn events(kinds: &[&str]) -> Vec<Value> {
    kinds.iter().map(|kind| event(kind)).collect()
}

fn deadline_after(duration: Duration) -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .saturating_add(duration.as_millis())
        .min(u64::MAX as u128) as u64
}

fn initialize_params() -> InitializeParams<InitializeApplication> {
    InitializeParams {
        protocol: PROVIDER_PROTOCOL.into(),
        versions: vec![PROTOCOL_VERSION],
        client: Product {
            name: "provider-conformance".into(),
            version: "1".into(),
        },
        limits: Limits {
            max_frame_bytes: 32 * 1024,
            max_in_flight: 8,
        },
        client_methods: Vec::new(),
        application: InitializeApplication {
            scheme: "memory".into(),
            uri: "memory://conformance".into(),
            context: ApplicationContext {
                project: Some("conformance".into()),
                profile: Some("default".into()),
                base_dir: None,
                reason: Some("conformance".into()),
            },
            credentials: BTreeMap::new(),
        },
    }
}

fn launch_options(endpoint: &Path, arguments: &[String]) -> LaunchOptions {
    LaunchOptions {
        executable: endpoint.to_path_buf(),
        arguments: arguments.iter().map(Into::into).collect(),
        environment: Environment::Replace(BTreeMap::new()),
        allow_path_discovery: false,
        max_stderr_bytes: 4096,
    }
}

async fn open_endpoint(endpoint: &Path, arguments: &[String]) -> Result<ProviderSession, String> {
    let initialize = initialize_params();
    let session = ProviderSession::launch(
        launch_options(endpoint, arguments),
        initialize.client,
        initialize.limits,
        initialize.application,
        deadline_after(Duration::from_secs(2)),
    )
    .await
    .map_err(stable)?;
    if session.metadata().name != "memory" {
        return Err("provider endpoint returned the wrong identity".into());
    }
    Ok(session)
}

fn wire_address(key: &str) -> Address {
    Address::Convention {
        project: "payments".into(),
        profile: "production".into(),
        key: key.into(),
    }
}

fn wire_other_address(key: &str) -> Address {
    Address::Convention {
        project: "payments".into(),
        profile: "development".into(),
        key: key.into(),
    }
}

async fn run_endpoint_operations(endpoint: &Path) -> Result<Vec<Value>, String> {
    let session = open_endpoint(endpoint, &[]).await?;
    let client = &session;
    let resolved: ResolveAddressResult = client
        .call(
            "provider.resolve_address",
            &AddressParams {
                address: wire_address("TOKEN"),
            },
            deadline_after(Duration::from_secs(2)),
        )
        .await
        .map_err(stable)?;
    if resolved.coordinates.item != "payments/production/TOKEN" {
        return Err("provider resolved the wrong convention address".into());
    }

    assert_missing(
        client
            .call(
                "provider.get",
                &AddressParams {
                    address: wire_address("TOKEN"),
                },
                deadline_after(Duration::from_secs(2)),
            )
            .await
            .map_err(stable)?,
    )?;
    call_empty(client, "provider.check_writable", wire_address("TOKEN")).await?;
    call_empty(client, "provider.check_deletable", wire_address("TOKEN")).await?;
    let described: wire::DescribeWriteTargetResult = client
        .call(
            "provider.describe_write_target",
            &AddressParams {
                address: wire_address("TOKEN"),
            },
            deadline_after(Duration::from_secs(2)),
        )
        .await
        .map_err(stable)?;
    if described.description.contains(CANARY) || described.description.is_empty() {
        return Err("provider returned an unsafe write description".into());
    }

    set_wire(client, wire_address("TOKEN"), CANARY).await?;
    let found: GetResult = client
        .call(
            "provider.get",
            &AddressParams {
                address: wire_address("TOKEN"),
            },
            deadline_after(Duration::from_secs(2)),
        )
        .await
        .map_err(stable)?;
    if found
        != (GetResult::Found {
            value: CANARY.into(),
            expires_at_unix_ms: None,
        })
    {
        return Err("provider did not return the stored value".into());
    }
    set_wire(client, wire_address("SECRET_EXPIRY"), CANARY).await?;
    let validity_bounded: GetResult = client
        .call(
            "provider.get",
            &AddressParams {
                address: wire_address("SECRET_EXPIRY"),
            },
            deadline_after(Duration::from_secs(2)),
        )
        .await
        .map_err(stable)?;
    if !matches!(
        validity_bounded,
        GetResult::Found {
            expires_at_unix_ms: Some(_),
            ..
        }
    ) {
        return Err("provider did not report the secret expiry".into());
    }
    let removed_validity_fixture: wire::DeletedResult = client
        .call(
            "provider.delete",
            &AddressParams {
                address: wire_address("SECRET_EXPIRY"),
            },
            deadline_after(Duration::from_secs(2)),
        )
        .await
        .map_err(stable)?;
    if !removed_validity_fixture.deleted {
        return Err("provider could not remove the validity fixture".into());
    }
    let batch: GetManyResult = client
        .call(
            "provider.get_many",
            &GetManyParams {
                requests: vec![
                    NamedRequest {
                        name: "token".into(),
                        address: wire_address("TOKEN"),
                    },
                    NamedRequest {
                        name: "missing".into(),
                        address: wire_address("MISSING"),
                    },
                ],
            },
            deadline_after(Duration::from_secs(2)),
        )
        .await
        .map_err(stable)?;
    if batch.results.len() != 2
        || batch.results[0].name != "token"
        || batch.results[1].name != "missing"
    {
        return Err("provider batch result did not preserve request order".into());
    }
    let exists: wire::ExistsResult = client
        .call(
            "provider.exists",
            &AddressParams {
                address: wire_address("TOKEN"),
            },
            deadline_after(Duration::from_secs(2)),
        )
        .await
        .map_err(stable)?;
    if !exists.exists {
        return Err("provider presence check missed a stored value".into());
    }

    let stored: wire::StoredResult = client
        .call(
            "provider.set_expiring",
            &SetExpiringParams {
                address: wire_address("TOKEN"),
                value: CANARY.into(),
                ttl_ms: 250,
            },
            deadline_after(Duration::from_secs(2)),
        )
        .await
        .map_err(stable)?;
    if !stored.stored {
        return Err("provider did not confirm the expiring write".into());
    }
    let retained: GetResult = client
        .call(
            "provider.get",
            &AddressParams {
                address: wire_address("TOKEN"),
            },
            deadline_after(Duration::from_secs(2)),
        )
        .await
        .map_err(stable)?;
    if !matches!(retained, GetResult::Found { .. }) {
        return Err("provider did not retain the expiring store entry".into());
    }
    tokio::time::sleep(Duration::from_millis(350)).await;
    let expired: GetResult = client
        .call(
            "provider.get",
            &AddressParams {
                address: wire_address("TOKEN"),
            },
            deadline_after(Duration::from_secs(2)),
        )
        .await
        .map_err(stable)?;
    assert_missing(expired)?;

    set_wire(client, wire_address("A"), CANARY).await?;
    set_wire(client, wire_address("B"), CANARY).await?;
    set_wire(client, wire_other_address("OTHER"), CANARY).await?;
    let cleared: wire::ClearResult = client
        .call(
            "provider.clear",
            &ClearParams {
                scope: ClearScope::Convention {
                    project: "payments".into(),
                    profile: "production".into(),
                },
            },
            deadline_after(Duration::from_secs(2)),
        )
        .await
        .map_err(stable)?;
    if cleared.cleared != 2 {
        return Err("provider clear escaped or under-cleared its namespace".into());
    }
    let other_exists: wire::ExistsResult = client
        .call(
            "provider.exists",
            &AddressParams {
                address: wire_other_address("OTHER"),
            },
            deadline_after(Duration::from_secs(2)),
        )
        .await
        .map_err(stable)?;
    if !other_exists.exists {
        return Err("provider clear escaped the selected namespace".into());
    }

    set_wire(client, wire_address("DELETE"), CANARY).await?;
    let first: wire::DeletedResult = client
        .call(
            "provider.delete",
            &AddressParams {
                address: wire_address("DELETE"),
            },
            deadline_after(Duration::from_secs(2)),
        )
        .await
        .map_err(stable)?;
    let second: wire::DeletedResult = client
        .call(
            "provider.delete",
            &AddressParams {
                address: wire_address("DELETE"),
            },
            deadline_after(Duration::from_secs(2)),
        )
        .await
        .map_err(stable)?;
    if !first.deleted || second.deleted {
        return Err("provider delete is not idempotent".into());
    }
    let reflected: ReflectResult = client
        .call(
            "provider.reflect",
            &ReflectParams {
                project: "payments".into(),
                profile: "production".into(),
            },
            deadline_after(Duration::from_secs(2)),
        )
        .await
        .map_err(stable)?;
    if reflected.declarations.len() != 1 {
        return Err("provider reflection returned the wrong declarations".into());
    }
    session
        .close(deadline_after(Duration::from_secs(2)))
        .await
        .map_err(stable)?;
    Ok(operation_events())
}

async fn call_empty(
    client: &ProviderSession,
    method: &str,
    address: Address,
) -> Result<(), String> {
    let value: Value = client
        .call(
            method,
            &AddressParams { address },
            deadline_after(Duration::from_secs(2)),
        )
        .await
        .map_err(stable)?;
    if value != json!({}) {
        return Err(format!("{method} returned a non-empty result"));
    }
    Ok(())
}

async fn set_wire(client: &ProviderSession, address: Address, value: &str) -> Result<(), String> {
    let stored: wire::StoredResult = client
        .call(
            "provider.set",
            &SetParams {
                address,
                value: value.into(),
            },
            deadline_after(Duration::from_secs(2)),
        )
        .await
        .map_err(stable)?;
    if stored.stored {
        Ok(())
    } else {
        Err("provider did not confirm the write".into())
    }
}

fn assert_missing(result: GetResult) -> Result<(), String> {
    if result == GetResult::Missing {
        Ok(())
    } else {
        Err("provider returned a value for a missing or expired entry".into())
    }
}

fn core_address(key: &str) -> CoreAddress<'_> {
    CoreAddress::Convention {
        project: "payments",
        profile: "production",
        key,
    }
}

fn core_other_address(key: &str) -> CoreAddress<'_> {
    CoreAddress::Convention {
        project: "payments",
        profile: "development",
        key,
    }
}

fn external_provider(endpoint: &Path, arguments: Vec<String>) -> Result<ExternalProvider, String> {
    external_provider_with_uri(endpoint, arguments, "memory://conformance")
}

fn external_provider_with_uri(
    endpoint: &Path,
    arguments: Vec<String>,
    uri: &str,
) -> Result<ExternalProvider, String> {
    ExternalProvider::new(
        ProviderEndpoint {
            schema_version: 1,
            scheme: "memory".into(),
            executable: endpoint.to_path_buf(),
            arguments,
            credential_names: Vec::new(),
        },
        uri,
    )
    .map_err(|error| error.to_string())
}

fn run_adapter_operations(endpoint: &Path) -> Result<Vec<Value>, String> {
    let provider = external_provider(endpoint, Vec::new())?;
    let resolved = provider
        .convention_address("payments", "production", "TOKEN")
        .map_err(|error| error.to_string())?;
    if resolved.render() != "item=payments/production/TOKEN" {
        return Err("external adapter resolved the wrong convention address".into());
    }
    if provider
        .get(core_address("TOKEN"))
        .map_err(|error| error.to_string())?
        .is_some()
    {
        return Err("external adapter found a missing value".into());
    }
    provider
        .check_writable(core_address("TOKEN"))
        .map_err(|error| error.to_string())?;
    provider
        .check_deletable(core_address("TOKEN"))
        .map_err(|error| error.to_string())?;
    let description = provider
        .describe_write_target(core_address("TOKEN"))
        .map_err(|error| error.to_string())?;
    if description.is_empty() || description.contains(CANARY) {
        return Err("external adapter returned an unsafe write description".into());
    }
    let secret = SecretString::from(CANARY.to_string());
    provider
        .set(core_address("TOKEN"), &secret)
        .map_err(|error| error.to_string())?;
    let found = provider
        .get(core_address("TOKEN"))
        .map_err(|error| error.to_string())?
        .ok_or_else(|| "external adapter missed a stored value".to_string())?;
    if found.expose_secret() != CANARY {
        return Err("external adapter returned the wrong stored value".into());
    }
    let batch = provider
        .get_many(&[
            ("token", core_address("TOKEN")),
            ("missing", core_address("MISSING")),
        ])
        .map_err(|error| error.to_string())?;
    if batch.len() != 1 || !batch.contains_key("token") {
        return Err("external adapter batch result is incorrect".into());
    }
    if !provider
        .exists(core_address("TOKEN"))
        .map_err(|error| error.to_string())?
    {
        return Err("external adapter presence check missed a stored value".into());
    }
    provider
        .set(core_address("SECRET_EXPIRY"), &secret)
        .map_err(|error| error.to_string())?;
    let validity_bounded = provider
        .get_with_metadata(core_address("SECRET_EXPIRY"))
        .map_err(|error| error.to_string())?
        .ok_or_else(|| "external adapter missed a validity-bounded value".to_string())?;
    if validity_bounded.expires_at_unix_ms.is_none() {
        return Err("external adapter dropped the provider-reported expiry".into());
    }
    if !provider
        .delete(core_address("SECRET_EXPIRY"))
        .map_err(|error| error.to_string())?
    {
        return Err("external adapter could not remove the validity fixture".into());
    }
    provider
        .set_expiring(core_address("TOKEN"), &secret, Duration::from_millis(250))
        .map_err(|error| error.to_string())?;
    let retained = provider
        .get_with_metadata(core_address("TOKEN"))
        .map_err(|error| error.to_string())?
        .ok_or_else(|| "external adapter missed an expiring value".to_string())?;
    if retained.expires_at_unix_ms.is_some() {
        return Err("external adapter confused store retention with secret validity".into());
    }
    std::thread::sleep(Duration::from_millis(350));
    if provider
        .get(core_address("TOKEN"))
        .map_err(|error| error.to_string())?
        .is_some()
    {
        return Err("external adapter retained an expired value".into());
    }

    provider
        .set(core_address("A"), &secret)
        .map_err(|error| error.to_string())?;
    provider
        .set(core_address("B"), &secret)
        .map_err(|error| error.to_string())?;
    provider
        .set(core_other_address("OTHER"), &secret)
        .map_err(|error| error.to_string())?;
    let cleared = provider
        .clear(ClearScope::Convention {
            project: "payments".into(),
            profile: "production".into(),
        })
        .map_err(|error| error.to_string())?;
    if cleared != 2
        || !provider
            .exists(core_other_address("OTHER"))
            .map_err(|error| error.to_string())?
    {
        return Err("external adapter clear escaped or under-cleared its namespace".into());
    }

    provider
        .set(core_address("DELETE"), &secret)
        .map_err(|error| error.to_string())?;
    if !provider
        .delete(core_address("DELETE"))
        .map_err(|error| error.to_string())?
        || provider
            .delete(core_address("DELETE"))
            .map_err(|error| error.to_string())?
    {
        return Err("external adapter delete is not idempotent".into());
    }
    let reflected = provider
        .reflect(DiscoveryContext::new("payments", "production"))
        .map_err(|error| error.to_string())?;
    if reflected.len() != 1 {
        return Err("external adapter reflection returned the wrong declarations".into());
    }
    drop(provider);
    Ok(operation_events())
}

fn operation_events() -> Vec<Value> {
    events(&[
        "initialized",
        "resolved_address",
        "read",
        "secret_expiry_reported",
        "batched",
        "preflighted",
        "mutated",
        "expired",
        "cleared",
        "reflected",
        "closed",
    ])
}

async fn run_endpoint_lifecycle(endpoint: &Path) -> Result<Vec<Value>, String> {
    let session = open_endpoint(endpoint, &[]).await?;
    let client = &session;
    let cancel_deadline = deadline_after(Duration::from_secs(2));
    let mut cancelled = client
        .raw()
        .start(
            "provider.get",
            &AddressParams {
                address: wire_address("__BLOCK__"),
            },
            cancel_deadline,
        )
        .await
        .map_err(stable)?;
    cancelled.cancel().await.map_err(stable)?;
    if !matches!(cancelled.wait().await, Err(Error::Cancelled)) {
        return Err("provider cancellation did not produce one cancelled terminal".into());
    }

    let expiry = deadline_after(Duration::from_millis(50));
    let mut expired = client
        .raw()
        .start(
            "provider.get",
            &AddressParams {
                address: wire_address("__BLOCK__"),
            },
            expiry,
        )
        .await
        .map_err(stable)?;
    if !matches!(expired.wait().await, Err(Error::DeadlineExceeded)) {
        return Err("provider deadline did not produce one deadline terminal".into());
    }
    session
        .close(deadline_after(Duration::from_secs(2)))
        .await
        .map_err(stable)?;
    Ok(events(&[
        "initialized",
        "cancelled",
        "deadline_exceeded",
        "terminal",
        "closed",
    ]))
}

fn run_adapter_reconnect(endpoint: &Path) -> Result<Vec<Value>, String> {
    let directory = tempfile::tempdir().map_err(|error| error.to_string())?;
    let marker = directory.path().join("crashed-once");
    let provider = external_provider(
        endpoint,
        vec![
            "--crash-on-get-once".into(),
            marker.to_string_lossy().into_owned(),
        ],
    )?;
    if provider.get(core_address("TOKEN")).is_ok() || !marker.exists() {
        return Err("external adapter did not observe the endpoint crash".into());
    }
    if provider
        .get(core_address("TOKEN"))
        .map_err(|error| error.to_string())?
        .is_some()
    {
        return Err("external adapter replayed or invented a value after reconnect".into());
    }
    drop(provider);
    Ok(events(&["initialized", "crashed", "reconnected", "closed"]))
}

async fn run_endpoint_errors(endpoint: &Path) -> Result<Vec<Value>, String> {
    let session = open_endpoint(endpoint, &[]).await?;
    let client = &session;
    for (key, expected) in [
        ("__INTERACTION_REQUIRED__", ErrorKind::InteractionRequired),
        ("__PERMISSION_DENIED__", ErrorKind::PermissionDenied),
        ("__UNAVAILABLE__", ErrorKind::Unavailable),
    ] {
        let result = client
            .call::<_, GetResult>(
                "provider.get",
                &AddressParams {
                    address: wire_address(key),
                },
                deadline_after(Duration::from_secs(2)),
            )
            .await;
        match result {
            Err(error) if error.rpc_kind() == Some(expected) => {}
            _ => return Err(format!("provider endpoint did not preserve {expected}")),
        }
    }
    let conflict = client
        .call::<_, wire::StoredResult>(
            "provider.set",
            &SetParams {
                address: wire_address("__CONFLICT__"),
                value: CANARY.into(),
            },
            deadline_after(Duration::from_secs(2)),
        )
        .await;
    if !matches!(conflict, Err(ref error) if error.rpc_kind() == Some(ErrorKind::Conflict)) {
        return Err("provider endpoint did not preserve conflict".into());
    }
    session
        .close(deadline_after(Duration::from_secs(2)))
        .await
        .map_err(stable)?;
    Ok(error_events())
}

fn provider_protocol_kind(error: SecretSpecError) -> Option<ErrorKind> {
    match error {
        SecretSpecError::ProviderProtocol(kind) => Some(kind),
        _ => None,
    }
}

fn run_adapter_errors(endpoint: &Path) -> Result<Vec<Value>, String> {
    let provider = external_provider(endpoint, Vec::new())?;
    for (key, expected) in [
        ("__INTERACTION_REQUIRED__", ErrorKind::InteractionRequired),
        ("__PERMISSION_DENIED__", ErrorKind::PermissionDenied),
        ("__UNAVAILABLE__", ErrorKind::Unavailable),
    ] {
        let error = provider
            .get(core_address(key))
            .expect_err("one-shot provider error was automatically replayed");
        if provider_protocol_kind(error) != Some(expected) {
            return Err(format!("external adapter did not preserve {expected}"));
        }
    }
    let error = provider
        .set(
            core_address("__CONFLICT__"),
            &SecretString::from(CANARY.to_string()),
        )
        .expect_err("one-shot provider conflict was automatically replayed");
    if provider_protocol_kind(error) != Some(ErrorKind::Conflict) {
        return Err("external adapter did not preserve conflict".into());
    }
    drop(provider);
    Ok(error_events())
}

fn error_events() -> Vec<Value> {
    events(&[
        "initialized",
        "interaction_required",
        "permission_denied",
        "conflict",
        "unavailable",
        "not_replayed",
        "closed",
    ])
}

fn run_adapter_session_isolation(endpoint: &Path) -> Result<Vec<Value>, String> {
    let first = external_provider_with_uri(endpoint, Vec::new(), "memory://session-a")?;
    first.set_reason(Some("session-a".into()));
    first
        .set(
            core_address("SHARED"),
            &SecretString::from(CANARY.to_string()),
        )
        .map_err(|error| error.to_string())?;
    drop(first);

    let second = external_provider_with_uri(endpoint, Vec::new(), "memory://session-b")?;
    second.set_reason(Some("session-b".into()));
    if second
        .get(core_address("SHARED"))
        .map_err(|error| error.to_string())?
        .is_some()
    {
        return Err("provider state crossed configured URI sessions".into());
    }
    second
        .set(
            core_address("SHARED"),
            &SecretString::from(CANARY.to_string()),
        )
        .map_err(|error| error.to_string())?;
    second.set_reason(Some("session-b-reason-2".into()));
    if second
        .get(core_address("SHARED"))
        .map_err(|error| error.to_string())?
        .is_some()
    {
        return Err("provider state crossed reason-bound sessions".into());
    }
    drop(second);
    Ok(events(&[
        "session_a_initialized",
        "session_a_closed",
        "session_b_initialized",
        "uri_isolated",
        "reason_isolated",
        "closed",
    ]))
}

fn run_async<F>(future: F) -> Result<Vec<Value>, String>
where
    F: std::future::Future<Output = Result<Vec<Value>, String>>,
{
    tokio::runtime::Runtime::new()
        .map_err(|error| error.to_string())?
        .block_on(future)
}

fn stable(error: secretspec_ipc::Error) -> String {
    error.stable_message().to_string()
}

fn run_fragmented_server(endpoint: &Path, case: &Case) -> Result<Vec<Value>, String> {
    require_action(&case.actions, "launch")?;
    require_action(&case.actions, "shutdown")?;
    let chunks = require_action(&case.actions, "peer_write")?
        .get("chunks")
        .and_then(Value::as_array)
        .ok_or_else(|| "fragmented case has no chunks".to_string())?
        .iter()
        .map(|value| {
            value
                .as_u64()
                .and_then(|value| usize::try_from(value).ok())
                .filter(|value| *value != 0)
                .ok_or_else(|| "invalid fragment size".to_string())
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut child = spawn_raw_endpoint(endpoint)?;
    let mut input = child
        .stdin
        .take()
        .ok_or_else(|| "endpoint stdin was not piped".to_string())?;
    let mut output = child
        .stdout
        .take()
        .ok_or_else(|| "endpoint stdout was not piped".to_string())?;
    let initialize = frame(&json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "rpc.initialize",
        "_meta": {"deadline_unix_ms": deadline_after(Duration::from_secs(2))},
        "params": initialize_params(),
    }))?;
    write_fragmented(&mut input, &initialize, &chunks)?;
    let response = read_json_frame(&mut output)?;
    if response.get("id").and_then(Value::as_u64) != Some(1) || response.get("result").is_none() {
        return Err("provider endpoint rejected fragmented initialization".into());
    }
    write_json_frame(
        &mut input,
        &json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "rpc.shutdown",
            "_meta": {"deadline_unix_ms": deadline_after(Duration::from_secs(2))},
            "params": {},
        }),
    )?;
    let shutdown = read_json_frame(&mut output)?;
    if shutdown.get("result") != Some(&json!({})) {
        return Err("provider endpoint returned an invalid shutdown response".into());
    }
    drop(input);
    if !child.wait().map_err(|error| error.to_string())?.success() {
        return Err("provider endpoint failed after fragmented initialization".into());
    }
    Ok(events(&["initialized", "frame_accepted", "closed"]))
}

fn run_fragmented_adapter(endpoint: &Path, case: &Case) -> Result<Vec<Value>, String> {
    require_action(&case.actions, "launch")?;
    require_action(&case.actions, "shutdown")?;
    let chunks = require_action(&case.actions, "peer_write")?
        .get("chunks")
        .and_then(Value::as_array)
        .ok_or_else(|| "fragmented case has no chunks".to_string())?
        .iter()
        .map(|value| {
            value
                .as_u64()
                .and_then(|value| usize::try_from(value).ok())
                .filter(|value| *value != 0)
                .ok_or_else(|| "invalid fragment size".to_string())
        })
        .collect::<Result<Vec<_>, _>>()?;
    let provider = external_provider(
        endpoint,
        vec![
            "--fragment-init".into(),
            chunks
                .iter()
                .map(usize::to_string)
                .collect::<Vec<_>>()
                .join(","),
        ],
    )?;
    if !provider.supports_delete() {
        return Err("external adapter rejected fragmented initialization".into());
    }
    drop(provider);
    Ok(events(&["initialized", "frame_accepted", "closed"]))
}

fn run_strict_server_rejections(endpoint: &Path, case: &Case) -> Result<Vec<Value>, String> {
    let actions = case
        .actions
        .iter()
        .filter(|action| action.get("kind").and_then(Value::as_str) == Some("raw_frame"))
        .collect::<Vec<_>>();
    if actions.is_empty() {
        return Err("strict rejection case has no raw frames".into());
    }
    let mut transcript = Vec::with_capacity(actions.len() + 1);
    for action in actions {
        let bytes = rejection_frame(action)?;
        let mut child = spawn_raw_endpoint(endpoint)?;
        let mut input = child
            .stdin
            .take()
            .ok_or_else(|| "endpoint stdin was not piped".to_string())?;
        input.write_all(&bytes).map_err(|error| error.to_string())?;
        input.flush().map_err(|error| error.to_string())?;
        drop(input);
        let output = child
            .wait_with_output()
            .map_err(|error| error.to_string())?;
        if output
            .stdout
            .windows(CANARY.len())
            .any(|value| value == CANARY.as_bytes())
            || output
                .stderr
                .windows(CANARY.len())
                .any(|value| value == CANARY.as_bytes())
        {
            return Err("provider endpoint exposed the canary while rejecting a frame".into());
        }
        transcript.push(event("rejected"));
    }
    transcript.push(event("closed"));
    Ok(transcript)
}

fn run_strict_adapter_rejections(endpoint: &Path, case: &Case) -> Result<Vec<Value>, String> {
    let actions = case
        .actions
        .iter()
        .filter(|action| action.get("kind").and_then(Value::as_str) == Some("raw_frame"))
        .collect::<Vec<_>>();
    if actions.is_empty() {
        return Err("strict rejection case has no raw frames".into());
    }
    let mut transcript = Vec::with_capacity(actions.len() + 1);
    for action in actions {
        let provider = external_provider(
            endpoint,
            vec!["--reject-init".into(), rejection_argument(action)?],
        )?;
        if provider
            .convention_address("payments", "production", "TOKEN")
            .is_ok()
        {
            return Err("external adapter accepted an invalid initialization frame".into());
        }
        transcript.push(event("rejected"));
    }
    transcript.push(event("closed"));
    Ok(transcript)
}

fn spawn_raw_endpoint(endpoint: &Path) -> Result<Child, String> {
    Command::new(endpoint)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| error.to_string())
}

fn frame(value: &Value) -> Result<Vec<u8>, String> {
    let payload = serde_json::to_vec(value).map_err(|error| error.to_string())?;
    let mut frame = payload;
    frame.push(b'\n');
    Ok(frame)
}

fn write_fragmented(writer: &mut impl Write, bytes: &[u8], chunks: &[usize]) -> Result<(), String> {
    let mut offset = 0;
    for chunk in chunks {
        if offset == bytes.len() {
            break;
        }
        let end = offset.saturating_add(*chunk).min(bytes.len());
        writer
            .write_all(&bytes[offset..end])
            .map_err(|error| error.to_string())?;
        writer.flush().map_err(|error| error.to_string())?;
        offset = end;
    }
    writer
        .write_all(&bytes[offset..])
        .map_err(|error| error.to_string())?;
    writer.flush().map_err(|error| error.to_string())
}

fn write_json_frame(writer: &mut impl Write, value: &Value) -> Result<(), String> {
    writer
        .write_all(&frame(value)?)
        .map_err(|error| error.to_string())?;
    writer.flush().map_err(|error| error.to_string())
}

fn read_json_frame(reader: &mut impl Read) -> Result<Value, String> {
    let mut payload = Vec::new();
    let mut byte = [0_u8; 1];
    loop {
        reader
            .read_exact(&mut byte)
            .map_err(|error| error.to_string())?;
        if byte[0] == b'\n' {
            break;
        }
        if byte[0] == b'\r' || payload.len() >= MAX_FRAME_BYTES {
            return Err("endpoint returned an invalid frame".into());
        }
        payload.push(byte[0]);
    }
    if payload.is_empty() {
        return Err("endpoint returned an empty frame".into());
    }
    serde_json::from_slice(&payload).map_err(|error| error.to_string())
}

fn rejection_frame(action: &Value) -> Result<Vec<u8>, String> {
    if action.get("prefix_hex").and_then(Value::as_str) == Some("0000") {
        return Ok(b"{".to_vec());
    }
    if action.get("declared_length").and_then(Value::as_u64) == Some(10)
        && action.get("payload_hex").and_then(Value::as_str) == Some("7b7d")
    {
        return Ok(b"{}".to_vec());
    }
    if action.get("payload_hex").and_then(Value::as_str) == Some("") {
        return Ok(b"\n".to_vec());
    }
    if action.get("payload_hex").and_then(Value::as_str) == Some("ff") {
        return Ok(vec![0xff, b'\n']);
    }
    if let Some(payload) = action.get("payload_utf8").and_then(Value::as_str) {
        let mut frame = payload.as_bytes().to_vec();
        frame.push(b'\n');
        return Ok(frame);
    }
    if let Some(length) = action.get("declared_length").and_then(Value::as_u64) {
        return Ok(vec![
            b'x';
            usize::try_from(length).map_err(|_| {
                "declared length exceeds usize".to_string()
            })?
        ]);
    }
    Err("unsupported strict rejection action".into())
}

fn rejection_argument(action: &Value) -> Result<String, String> {
    if action.get("prefix_hex").and_then(Value::as_str) == Some("0000") {
        return Ok("truncated-header".into());
    }
    if action.get("declared_length").and_then(Value::as_u64) == Some(10)
        && action.get("payload_hex").and_then(Value::as_str) == Some("7b7d")
    {
        return Ok("truncated-payload".into());
    }
    if action.get("payload_hex").and_then(Value::as_str) == Some("") {
        return Ok("empty".into());
    }
    if action.get("payload_hex").and_then(Value::as_str) == Some("ff") {
        return Ok("invalid-utf8".into());
    }
    match action.get("payload_utf8").and_then(Value::as_str) {
        Some("[]") => return Ok("batch".into()),
        Some(r#"{"jsonrpc":"2.0","jsonrpc":"2.0"}"#) => return Ok("duplicate-key".into()),
        Some(r#"{"jsonrpc":"2.0","id":999,"result":{}}"#) => return Ok("unknown-id".into()),
        Some(_) => return Err("unsupported malformed JSON response".into()),
        None => {}
    }
    if let Some(length) = action.get("declared_length").and_then(Value::as_u64) {
        return Ok(format!(
            "oversized:{}",
            u32::try_from(length).map_err(|_| "declared length exceeds u32".to_string())?
        ));
    }
    Err("unsupported strict rejection action".into())
}
