use async_trait::async_trait;
use secretspec_ipc::client::Client;
use secretspec_ipc::protocol::provider::{
    self as wire, Address, AddressParams, GetResult, InitializeApplication, InitializedApplication,
    Metadata, Persistence, ReflectParams, ReflectResult, ResolveAddressResult, SetParams,
};
use secretspec_ipc::protocol::{
    InitializeParams, Limits, PROTOCOL_VERSION, PROVIDER_PROTOCOL, Product,
};
use secretspec_ipc::provider::{ProvidedSecret, ProviderHandler, SecretValue, serve_provider};
use secretspec_ipc::server::{RequestContext, RpcResult, ServerConfig};
use std::collections::{BTreeMap, HashMap};
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Default)]
struct MemoryProvider {
    values: Mutex<HashMap<String, String>>,
}

fn key(address: Address) -> String {
    match address {
        Address::Convention {
            project,
            profile,
            key,
        } => format!("{project}/{profile}/{key}"),
        Address::Native { coordinates } => coordinates.item,
    }
}

#[async_trait]
impl ProviderHandler for MemoryProvider {
    fn capabilities(&self) -> Vec<String> {
        wire::CAPABILITIES
            .iter()
            .map(|value| (*value).to_string())
            .collect()
    }

    async fn initialize(
        &self,
        _context: &RequestContext,
        application: InitializeApplication,
    ) -> RpcResult<Metadata> {
        Ok(Metadata {
            name: application.scheme.clone(),
            display_uri: format!("{}://memory", application.scheme),
            supported_coordinates: Vec::new(),
            generated_value_persistence: Persistence::Persist,
            prompted_value_persistence: Persistence::Ephemeral,
            storage_identity: format!("{}://memory", application.scheme),
            entry_container_identity: format!("{}://memory", application.scheme),
            physical_store_path: None,
        })
    }

    async fn resolve_address(
        &self,
        _context: RequestContext,
        address: Address,
    ) -> RpcResult<ResolveAddressResult> {
        Ok(ResolveAddressResult {
            coordinates: wire::Coordinates {
                item: key(address),
                field: None,
                vault: None,
                section: None,
                version: None,
            },
        })
    }

    async fn get(
        &self,
        _context: RequestContext,
        address: Address,
    ) -> RpcResult<Option<ProvidedSecret>> {
        Ok(self
            .values
            .lock()
            .unwrap()
            .get(&key(address))
            .cloned()
            .map(|value| ProvidedSecret::new(value, None)))
    }

    async fn exists(&self, _context: RequestContext, address: Address) -> RpcResult<bool> {
        Ok(self.values.lock().unwrap().contains_key(&key(address)))
    }

    async fn set(
        &self,
        _context: RequestContext,
        address: Address,
        value: SecretValue,
    ) -> RpcResult<()> {
        self.values
            .lock()
            .unwrap()
            .insert(key(address), value.expose().to_string());
        Ok(())
    }

    async fn delete(&self, _context: RequestContext, address: Address) -> RpcResult<bool> {
        Ok(self.values.lock().unwrap().remove(&key(address)).is_some())
    }

    async fn check_writable(&self, _context: RequestContext, _address: Address) -> RpcResult<()> {
        Ok(())
    }

    async fn check_deletable(&self, _context: RequestContext, _address: Address) -> RpcResult<()> {
        Ok(())
    }

    async fn describe_write_target(
        &self,
        _context: RequestContext,
        address: Address,
    ) -> RpcResult<String> {
        Ok(format!("memory {}", key(address)))
    }

    async fn reflect(
        &self,
        _context: RequestContext,
        _params: ReflectParams,
    ) -> RpcResult<ReflectResult> {
        Ok(ReflectResult {
            schema_version: 1,
            declarations: BTreeMap::from([(
                "TOKEN".into(),
                wire::ReflectedDeclaration {
                    description: "Memory token".into(),
                    required: true,
                    reference: wire::Coordinates {
                        item: "token".into(),
                        field: None,
                        vault: None,
                        section: None,
                        version: None,
                    },
                },
            )]),
        })
    }
}

fn deadline() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
        + Duration::from_secs(2).as_millis() as u64
}

fn address() -> Address {
    Address::Convention {
        project: "payments".into(),
        profile: "production".into(),
        key: "TOKEN".into(),
    }
}

#[tokio::test]
async fn typed_provider_handler_covers_naming_reads_mutations_and_reflection() {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let (client_read, client_write) = tokio::io::split(client_io);
    let (server_read, server_write) = tokio::io::split(server_io);
    let server = tokio::spawn(serve_provider(
        server_read,
        server_write,
        MemoryProvider::default(),
        ServerConfig::default(),
    ));
    let initialize = InitializeParams {
        protocol: PROVIDER_PROTOCOL.into(),
        versions: vec![PROTOCOL_VERSION],
        client: Product {
            name: "provider-test".into(),
            version: "1".into(),
        },
        limits: Limits {
            max_frame_bytes: 32 * 1024,
            max_in_flight: 8,
        },
        client_methods: Vec::new(),
        application: InitializeApplication {
            scheme: "memory".into(),
            uri: "memory://default".into(),
            base_dir: None,
            credentials: BTreeMap::new(),
            reason: Some("test".into()),
        },
    };
    let (raw, initialized) = Client::connect::<_, _, _, InitializedApplication>(
        client_read,
        client_write,
        initialize,
        deadline(),
    )
    .await
    .unwrap();
    assert_eq!(initialized.application.provider.name, "memory");
    let client = raw;

    let resolved: ResolveAddressResult = client
        .call(
            wire::method::RESOLVE_ADDRESS,
            &AddressParams { address: address() },
            deadline(),
        )
        .await
        .unwrap();
    assert_eq!(resolved.coordinates.item, "payments/production/TOKEN");

    let missing: GetResult = client
        .call(
            wire::method::GET,
            &AddressParams { address: address() },
            deadline(),
        )
        .await
        .unwrap();
    assert_eq!(missing, GetResult::Missing);

    let stored: wire::StoredResult = client
        .call(
            wire::method::SET,
            &SetParams {
                address: address(),
                value: "canary-value".into(),
            },
            deadline(),
        )
        .await
        .unwrap();
    assert!(stored.stored);
    let found: GetResult = client
        .call(
            wire::method::GET,
            &AddressParams { address: address() },
            deadline(),
        )
        .await
        .unwrap();
    assert_eq!(
        found,
        GetResult::Found {
            value: "canary-value".into(),
            expires_at_unix_ms: None,
        }
    );
    let reflected: ReflectResult = client
        .call(
            wire::method::REFLECT,
            &ReflectParams {
                project: "payments".into(),
                profile: "production".into(),
            },
            deadline(),
        )
        .await
        .unwrap();
    assert_eq!(reflected.declarations.len(), 1);

    let deleted: wire::DeletedResult = client
        .call(
            wire::method::DELETE,
            &AddressParams { address: address() },
            deadline(),
        )
        .await
        .unwrap();
    assert!(deleted.deleted);
    client.close(deadline()).await.unwrap();
    server.await.unwrap().unwrap();
}
