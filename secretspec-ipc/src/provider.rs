use crate::error::{ErrorKind, RpcError};
use crate::protocol::PROVIDER_PROTOCOL;
use crate::protocol::callback::{self, CredentialParams, CredentialResult};
use crate::protocol::provider::{
    Address, AddressParams, CAPABILITIES, ClearParams, ClearResult, DescribeWriteTargetResult,
    ExistsResult, GetManyParams, GetManyResult, GetResult, InitializeApplication,
    InitializedApplication, Metadata, ReflectParams, ReflectResult, ResolveAddressResult,
    SetExpiringParams, SetParams, method,
};
use crate::server::{ApplicationHandler, RequestContext, RpcResult, ServerConfig};
use async_trait::async_trait;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use std::sync::Arc;
use std::sync::OnceLock;
use zeroize::Zeroizing;

/// Owned value passed across the endpoint-author boundary. Its backing bytes
/// are cleared on drop independently of the JSON frame buffer.
#[derive(Debug, Clone)]
pub struct SecretValue(Zeroizing<String>);

impl SecretValue {
    pub fn new(value: String) -> Self {
        Self(Zeroizing::new(value))
    }

    pub fn expose(&self) -> &str {
        self.0.as_str()
    }

    /// Copies the value out for JSON serialization.
    ///
    /// Deliberately a copy rather than `mem::take`: taking would move the
    /// backing allocation out of the `Zeroizing` wrapper, leaving it to wipe an
    /// empty string while the real bytes lived on un-wiped. Copying keeps this
    /// value's own buffer covered by its destructor.
    fn into_string(self) -> String {
        self.0.as_str().to_owned()
    }
}

/// A provider value and the absolute time at which the value itself expires.
///
/// `None` means the provider does not know a validity bound; it does not mean
/// the value is permanent. Cache freshness is owned by the resolver and is not
/// represented here.
#[derive(Debug, Clone)]
pub struct ProvidedSecret {
    value: SecretValue,
    expires_at_unix_ms: Option<u64>,
}

impl ProvidedSecret {
    pub fn new(value: String, expires_at_unix_ms: Option<u64>) -> Self {
        Self {
            value: SecretValue::new(value),
            expires_at_unix_ms,
        }
    }

    pub fn value(&self) -> &str {
        self.value.expose()
    }

    pub const fn expires_at_unix_ms(&self) -> Option<u64> {
        self.expires_at_unix_ms
    }

    fn into_parts(self) -> (String, Option<u64>) {
        (self.value.into_string(), self.expires_at_unix_ms)
    }
}

#[async_trait]
pub trait ProviderHandler: Send + Sync + 'static {
    /// Supported operation names. `provider.resolve_address` is mandatory.
    fn capabilities(&self) -> Vec<String>;

    async fn initialize(
        &self,
        context: &RequestContext,
        application: InitializeApplication,
    ) -> RpcResult<Metadata>;

    async fn resolve_address(
        &self,
        context: RequestContext,
        address: Address,
    ) -> RpcResult<ResolveAddressResult>;

    async fn get(
        &self,
        _context: RequestContext,
        _address: Address,
    ) -> RpcResult<Option<ProvidedSecret>> {
        Err(RpcError::new(ErrorKind::CapabilityRequired))
    }

    async fn get_many(
        &self,
        _context: RequestContext,
        _params: GetManyParams,
    ) -> RpcResult<GetManyResult> {
        Err(RpcError::new(ErrorKind::CapabilityRequired))
    }

    async fn exists(&self, _context: RequestContext, _address: Address) -> RpcResult<bool> {
        Err(RpcError::new(ErrorKind::CapabilityRequired))
    }

    async fn set(
        &self,
        _context: RequestContext,
        _address: Address,
        _value: SecretValue,
    ) -> RpcResult<()> {
        Err(RpcError::new(ErrorKind::CapabilityRequired))
    }

    async fn set_expiring(
        &self,
        _context: RequestContext,
        _address: Address,
        _value: SecretValue,
        _ttl_ms: u64,
    ) -> RpcResult<()> {
        Err(RpcError::new(ErrorKind::CapabilityRequired))
    }

    async fn delete(&self, _context: RequestContext, _address: Address) -> RpcResult<bool> {
        Err(RpcError::new(ErrorKind::CapabilityRequired))
    }

    async fn clear(&self, _context: RequestContext, _params: ClearParams) -> RpcResult<usize> {
        Err(RpcError::new(ErrorKind::CapabilityRequired))
    }

    async fn check_writable(&self, _context: RequestContext, _address: Address) -> RpcResult<()> {
        Err(RpcError::new(ErrorKind::CapabilityRequired))
    }

    async fn check_deletable(&self, _context: RequestContext, _address: Address) -> RpcResult<()> {
        Err(RpcError::new(ErrorKind::CapabilityRequired))
    }

    async fn describe_write_target(
        &self,
        _context: RequestContext,
        _address: Address,
    ) -> RpcResult<String> {
        Err(RpcError::new(ErrorKind::CapabilityRequired))
    }

    async fn reflect(
        &self,
        _context: RequestContext,
        _params: ReflectParams,
    ) -> RpcResult<ReflectResult> {
        Err(RpcError::new(ErrorKind::CapabilityRequired))
    }

    async fn shutdown(&self) {}
}

/// Requests one provider credential from the client while serving the current
/// request, normally from [`ProviderHandler::initialize`] (0.20+).
///
/// A client that did not advertise credential brokerage behaves like an empty
/// broker, allowing an endpoint to retain native environment, agent, or
/// workload-identity fallbacks without treating callback support as mandatory.
pub async fn request_credential(
    context: &RequestContext,
    params: CredentialParams,
) -> RpcResult<Option<SecretValue>> {
    params
        .validate()
        .map_err(|_| RpcError::new(ErrorKind::InvalidParams))?;
    if !context.peer.supports(callback::method::CREDENTIAL) {
        return Ok(None);
    }
    let result: CredentialResult = context
        .peer
        .call(callback::method::CREDENTIAL, &params, context)
        .await?;
    result
        .validate()
        .map_err(|_| RpcError::new(ErrorKind::OperationFailed))?;
    Ok(match result {
        CredentialResult::Found { value } => Some(SecretValue::new(value)),
        CredentialResult::Missing => None,
    })
}

struct ProviderApplication<H> {
    handler: Arc<H>,
    metadata: OnceLock<Metadata>,
}

impl<H> ProviderApplication<H> {
    fn new(handler: Arc<H>) -> Self {
        Self {
            handler,
            metadata: OnceLock::new(),
        }
    }

    fn validate_address(&self, address: &Address) -> RpcResult<()> {
        address.validate().map_err(invalid_params)?;
        let metadata = self
            .metadata
            .get()
            .ok_or_else(|| RpcError::new(ErrorKind::Internal))?;
        if let Address::Native { coordinates } = address
            && coordinates
                .unsupported(&metadata.supported_coordinates)
                .is_some()
        {
            return Err(RpcError::new(ErrorKind::InvalidParams));
        }
        Ok(())
    }

    fn address_params(&self, value: Value) -> RpcResult<AddressParams> {
        let params: AddressParams = parse(value)?;
        self.validate_address(&params.address)?;
        Ok(params)
    }
}

#[async_trait]
impl<H: ProviderHandler> ApplicationHandler for ProviderApplication<H> {
    fn protocol(&self) -> &'static str {
        PROVIDER_PROTOCOL
    }

    fn capabilities(&self) -> Vec<String> {
        let mut capabilities = self.handler.capabilities();
        capabilities.retain(|capability| CAPABILITIES.contains(&capability.as_str()));
        capabilities.sort();
        capabilities.dedup();
        capabilities
    }

    fn validate_capabilities(&self, capabilities: &[String]) -> RpcResult<()> {
        crate::protocol::provider::validate_capabilities(capabilities)
            .map_err(|_| RpcError::new(ErrorKind::CapabilityRequired))
    }

    async fn initialize(&self, context: &RequestContext, application: Value) -> RpcResult<Value> {
        let application: InitializeApplication = parse(application)?;
        application.validate().map_err(invalid_params)?;
        let scheme = application.scheme.clone();
        let metadata = self.handler.initialize(context, application).await?;
        metadata
            .validate()
            .map_err(|_| RpcError::new(ErrorKind::OperationFailed))?;
        if metadata.name != scheme {
            return Err(RpcError::new(ErrorKind::Conflict));
        }
        self.metadata
            .set(metadata.clone())
            .map_err(|_| RpcError::new(ErrorKind::Conflict))?;
        serde_json::to_value(InitializedApplication { provider: metadata })
            .map_err(|_| RpcError::new(ErrorKind::Internal))
    }

    async fn call(&self, context: RequestContext, method: &str, params: Value) -> RpcResult<Value> {
        match method {
            method::RESOLVE_ADDRESS => {
                let params = self.address_params(params)?;
                let result = self
                    .handler
                    .resolve_address(context, params.address)
                    .await?;
                result
                    .coordinates
                    .validate()
                    .map_err(|_| RpcError::new(ErrorKind::OperationFailed))?;
                if result
                    .coordinates
                    .unsupported(
                        &self
                            .metadata
                            .get()
                            .expect("provider initialized before calls")
                            .supported_coordinates,
                    )
                    .is_some()
                {
                    return Err(RpcError::new(ErrorKind::OperationFailed));
                }
                encode(result)
            }
            method::GET => {
                let params = self.address_params(params)?;
                let result = match self.handler.get(context, params.address).await? {
                    Some(value) => {
                        let (value, expires_at_unix_ms) = value.into_parts();
                        GetResult::Found {
                            value,
                            expires_at_unix_ms,
                        }
                    }
                    None => GetResult::Missing,
                };
                encode(result)
            }
            method::GET_MANY => {
                let params: GetManyParams = parse(params)?;
                params.validate().map_err(invalid_params)?;
                for request in &params.requests {
                    self.validate_address(&request.address)?;
                }
                let expected = params
                    .requests
                    .iter()
                    .map(|request| request.name.clone())
                    .collect::<Vec<_>>();
                let result = self.handler.get_many(context, params).await?;
                if result.results.len() != expected.len()
                    || result
                        .results
                        .iter()
                        .zip(expected)
                        .any(|(result, expected)| result.name != expected)
                {
                    return Err(RpcError::new(ErrorKind::OperationFailed));
                }
                encode(result)
            }
            method::EXISTS => {
                let params = self.address_params(params)?;
                encode(ExistsResult {
                    exists: self.handler.exists(context, params.address).await?,
                })
            }
            method::SET => {
                let params: SetParams = parse(params)?;
                params.validate().map_err(invalid_params)?;
                self.validate_address(&params.address)?;
                self.handler
                    .set(context, params.address, SecretValue::new(params.value))
                    .await?;
                Ok(json!({"stored": true}))
            }
            method::SET_EXPIRING => {
                let params: SetExpiringParams = parse(params)?;
                params.validate().map_err(invalid_params)?;
                self.validate_address(&params.address)?;
                self.handler
                    .set_expiring(
                        context,
                        params.address,
                        SecretValue::new(params.value),
                        params.ttl_ms,
                    )
                    .await?;
                Ok(json!({"stored": true}))
            }
            method::DELETE => {
                let params = self.address_params(params)?;
                Ok(json!({"deleted": self.handler.delete(context, params.address).await?}))
            }
            method::CLEAR => {
                let params: ClearParams = parse(params)?;
                params.validate().map_err(invalid_params)?;
                let cleared = self.handler.clear(context, params).await?;
                encode(ClearResult { cleared })
            }
            method::CHECK_WRITABLE => {
                let params = self.address_params(params)?;
                self.handler.check_writable(context, params.address).await?;
                Ok(json!({}))
            }
            method::CHECK_DELETABLE => {
                let params = self.address_params(params)?;
                self.handler
                    .check_deletable(context, params.address)
                    .await?;
                Ok(json!({}))
            }
            method::DESCRIBE_WRITE_TARGET => {
                let params = self.address_params(params)?;
                encode(DescribeWriteTargetResult {
                    description: self
                        .handler
                        .describe_write_target(context, params.address)
                        .await?,
                })
            }
            method::REFLECT => {
                let params: ReflectParams = parse(params)?;
                params.validate().map_err(invalid_params)?;
                let result = self.handler.reflect(context, params).await?;
                result
                    .validate()
                    .map_err(|_| RpcError::new(ErrorKind::OperationFailed))?;
                encode(result)
            }
            _ => Err(RpcError::new(ErrorKind::MethodNotFound)),
        }
    }

    async fn shutdown(&self) {
        self.handler.shutdown().await;
    }
}

fn parse<T: DeserializeOwned>(value: Value) -> RpcResult<T> {
    serde_json::from_value(value).map_err(|_| RpcError::new(ErrorKind::InvalidParams))
}

fn encode<T: serde::Serialize>(value: T) -> RpcResult<Value> {
    serde_json::to_value(value).map_err(|_| RpcError::new(ErrorKind::Internal))
}

fn invalid_params(_: crate::Error) -> RpcError {
    RpcError::new(ErrorKind::InvalidParams)
}

/// Serve one typed provider endpoint without assembling the generic adapter.
pub async fn serve_provider<R, W, H>(
    reader: R,
    writer: W,
    handler: H,
    config: ServerConfig,
) -> crate::Result<()>
where
    R: tokio::io::AsyncRead + Unpin + Send + 'static,
    W: tokio::io::AsyncWrite + Unpin + Send + 'static,
    H: ProviderHandler,
{
    crate::server::serve(
        reader,
        writer,
        Arc::new(ProviderApplication::new(Arc::new(handler))),
        config,
    )
    .await
}
