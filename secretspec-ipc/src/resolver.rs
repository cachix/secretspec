use crate::error::{ErrorKind, RpcError};
use crate::protocol::RESOLVER_PROTOCOL;
use crate::protocol::callback::{self, PromptParams, PromptResult};
use crate::protocol::resolver::{
    CAPABILITIES, DeleteParams, DeleteResult, GetParams, GetResult, InitializeApplication,
    InitializedApplication, ReleaseParams, ReleaseResult, SetParams, SetResult, method,
    validate_capabilities,
};
use crate::server::{ApplicationHandler, RequestContext, RpcResult, ServerConfig};
use async_trait::async_trait;
use serde::de::DeserializeOwned;
use serde_json::Value;
use std::sync::Arc;

/// Typed northbound handler. Implementations never parse JSON-RPC envelopes or
/// arbitrate cancellation/terminal races.
#[async_trait]
pub trait ResolverHandler: Send + Sync + 'static {
    async fn initialize(
        &self,
        context: &RequestContext,
        application: InitializeApplication,
    ) -> RpcResult<InitializedApplication>;

    async fn get(&self, context: RequestContext, params: GetParams) -> RpcResult<GetResult>;

    async fn release(
        &self,
        context: RequestContext,
        params: ReleaseParams,
    ) -> RpcResult<ReleaseResult>;

    /// Methods this endpoint advertises. The default is resolution only, so an
    /// endpoint gains a mutation method by naming it here and implementing it,
    /// never by inheriting one it never considered.
    fn capabilities(&self) -> Vec<String> {
        CAPABILITIES
            .iter()
            .map(|item| (*item).to_string())
            .collect()
    }

    /// Store one declared name (0.20+). Unreachable unless
    /// [`Self::capabilities`] advertises `resolver.set`: the server answers an
    /// unadvertised method itself and never reaches the handler.
    async fn set(&self, _context: RequestContext, _params: SetParams) -> RpcResult<SetResult> {
        Err(RpcError::new(ErrorKind::MethodNotFound))
    }

    /// Remove one declared name's stored value (0.20+), advertised as
    /// `resolver.delete` under the same rule as [`Self::set`].
    async fn delete(
        &self,
        _context: RequestContext,
        _params: DeleteParams,
    ) -> RpcResult<DeleteResult> {
        Err(RpcError::new(ErrorKind::MethodNotFound))
    }

    async fn request_finished(&self, _request_id: crate::RequestId, _committed: bool) {}

    async fn shutdown(&self) {}
}

struct ResolverApplication<H> {
    handler: Arc<H>,
}

impl<H> ResolverApplication<H> {
    fn new(handler: Arc<H>) -> Self {
        Self { handler }
    }
}

#[async_trait]
impl<H: ResolverHandler> ApplicationHandler for ResolverApplication<H> {
    fn protocol(&self) -> &'static str {
        RESOLVER_PROTOCOL
    }

    fn capabilities(&self) -> Vec<String> {
        self.handler.capabilities()
    }

    // The advertised list stopped being a constant once mutation methods became
    // opt-in, so an implementation can now omit a method version 1 requires.
    // That is a defect in the endpoint rather than anything a peer did, which is
    // why the server reports it as `internal`.
    fn validate_capabilities(&self, capabilities: &[String]) -> RpcResult<()> {
        validate_capabilities(capabilities).map_err(|_| RpcError::new(ErrorKind::Internal))
    }

    async fn initialize(&self, context: &RequestContext, application: Value) -> RpcResult<Value> {
        let application: InitializeApplication = parse(application)?;
        application.validate().map_err(invalid_params)?;
        let initialized = self.handler.initialize(context, application).await?;
        initialized
            .validate()
            .map_err(|_| RpcError::new(ErrorKind::OperationFailed))?;
        serde_json::to_value(initialized).map_err(|_| RpcError::new(ErrorKind::Internal))
    }

    async fn call(&self, context: RequestContext, method: &str, params: Value) -> RpcResult<Value> {
        match method {
            method::GET => {
                let params: GetParams = parse(params)?;
                params.validate().map_err(invalid_params)?;
                let result = self.handler.get(context, params).await?;
                serde_json::to_value(result).map_err(|_| RpcError::new(ErrorKind::Internal))
            }
            method::RELEASE => {
                let params: ReleaseParams = parse(params)?;
                params.validate().map_err(invalid_params)?;
                let result = self.handler.release(context, params).await?;
                serde_json::to_value(result).map_err(|_| RpcError::new(ErrorKind::Internal))
            }
            method::SET => {
                let params: SetParams = parse(params)?;
                params.validate().map_err(invalid_params)?;
                let result = self.handler.set(context, params).await?;
                serde_json::to_value(result).map_err(|_| RpcError::new(ErrorKind::Internal))
            }
            method::DELETE => {
                let params: DeleteParams = parse(params)?;
                params.validate().map_err(invalid_params)?;
                let result = self.handler.delete(context, params).await?;
                serde_json::to_value(result).map_err(|_| RpcError::new(ErrorKind::Internal))
            }
            _ => Err(RpcError::new(ErrorKind::MethodNotFound)),
        }
    }

    async fn request_finished(&self, request_id: crate::RequestId, committed: bool) {
        self.handler.request_finished(request_id, committed).await;
    }

    async fn shutdown(&self) {
        self.handler.shutdown().await;
    }
}

/// Ask the client for one secret value, on behalf of the request in `context`
/// (0.20+).
///
/// Returns `interaction_required` when the client advertised no way to ask,
/// which is the answer a headless consumer needs immediately rather than after
/// its deadline elapses. The prompt inherits the originating request's deadline
/// and cancellation, so it cannot outlive the resolve that raised it.
pub async fn prompt(context: &RequestContext, params: &PromptParams) -> RpcResult<PromptResult> {
    if !context.peer.supports(callback::method::PROMPT) {
        return Err(RpcError::new(ErrorKind::InteractionRequired));
    }
    params
        .validate()
        .map_err(|_| RpcError::new(ErrorKind::Internal))?;
    let result: PromptResult = context
        .peer
        .call(callback::method::PROMPT, params, context)
        .await?;
    // A client is not trusted to have sent something this endpoint would store:
    // an empty answer means different things to different stores, so it is
    // refused here rather than becoming a value.
    result
        .validate()
        .map_err(|_| RpcError::new(ErrorKind::OperationFailed))?;
    Ok(result)
}

fn parse<T: DeserializeOwned>(value: Value) -> RpcResult<T> {
    serde_json::from_value(value).map_err(|_| RpcError::new(ErrorKind::InvalidParams))
}

fn invalid_params(_: crate::Error) -> RpcError {
    RpcError::new(ErrorKind::InvalidParams)
}

/// Serve one typed resolution endpoint without assembling the generic adapter.
pub async fn serve_resolver<R, W, H>(
    reader: R,
    writer: W,
    handler: H,
    config: ServerConfig,
) -> crate::Result<()>
where
    R: tokio::io::AsyncRead + Unpin + Send + 'static,
    W: tokio::io::AsyncWrite + Unpin + Send + 'static,
    H: ResolverHandler,
{
    crate::server::serve(
        reader,
        writer,
        Arc::new(ResolverApplication::new(Arc::new(handler))),
        config,
    )
    .await
}
