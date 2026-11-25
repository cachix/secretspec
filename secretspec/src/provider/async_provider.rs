use super::address::OwnedAddress;
use super::{
    Address, DiscoveryContext, ProducedValuePersistence, Provider, ProviderCredentials,
    ProviderValue,
};
use crate::NativeAddress;
use crate::{Result, SecretBytes, SecretSpecError};
use async_trait::async_trait;
use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

/// Polls independent operations together in bounded waves without spawning
/// threads or requiring owned addresses. Results retain the input order.
pub(crate) async fn map_concurrently<'a, T, R, F, Fut>(
    items: &'a [T],
    concurrency: usize,
    map: F,
) -> Vec<R>
where
    F: Fn(&'a T) -> Fut,
    Fut: Future<Output = R>,
{
    let mut results = Vec::with_capacity(items.len());
    for chunk in items.chunks(concurrency.max(1)) {
        results.extend(futures_util::future::join_all(chunk.iter().map(&map)).await);
    }
    results
}

/// Shares each distinct address's result among its declaration names.
pub(crate) async fn get_each_with<'a, F, Fut, T>(
    requests: &[(&str, Address<'a>)],
    fetch: F,
) -> Result<HashMap<String, T>>
where
    F: Fn(Address<'a>) -> Fut,
    Fut: Future<Output = Result<Option<T>>>,
    T: Clone,
{
    let mut groups: HashMap<Address<'_>, Vec<&str>> = HashMap::new();
    for (name, addr) in requests {
        groups.entry(*addr).or_default().push(name);
    }
    let groups: Vec<_> = groups.into_iter().collect();
    let fetched = map_concurrently(&groups, super::get_each_concurrency(), |(addr, _)| {
        fetch(*addr)
    })
    .await;
    let mut values = HashMap::new();
    for ((_, names), result) in groups.into_iter().zip(fetched) {
        if let Some(value) = result? {
            for name in names {
                values.insert(name.to_owned(), value.clone());
            }
        }
    }
    Ok(values)
}

/// Awaitable secret storage interface, available starting with SecretSpec 0.22.
///
/// Implement with `#[async_trait::async_trait]` to support `dyn AsyncProvider`
/// and `Send` futures. Implementations should await I/O without blocking the
/// executor. Implement [`super::ProviderBase`] for configuration, naming, and
/// identity. [`super::SyncProviderAdapter`] supplies the synchronous interface;
/// the backend implements its storage operations only once.
/// Addresses and byte values have the same meaning as in [`Provider`].
/// Methods that write text-only stores must reject non-UTF-8 bytes without
/// including the value in an error.
///
/// This interface is independent of the synchronous resolver and its provider
/// registry. Existing synchronous providers can be used through
/// [`AsyncProviderAdapter`]. Native async implementations need no Tokio runtime
/// unless their underlying I/O library requires one.
///
/// URI factories select native async SDK, HTTP, and IPC implementations and
/// adapt synchronous backends automatically:
///
/// ```no_run
/// use secretspec::{Address, AsyncProvider};
/// # async fn example() -> secretspec::Result<()> {
/// let provider = Box::<dyn AsyncProvider>::try_from("dotenv://.env")?;
/// let value = provider.get(Address::convention("myapp", "default", "API_KEY")).await?;
/// # Ok(())
/// # }
/// ```
#[async_trait]
pub trait AsyncProvider: super::ProviderBase {
    /// Retrieves a secret, returning `None` when it does not exist.
    async fn get(&self, addr: Address<'_>) -> Result<Option<SecretBytes>>;

    /// Retrieves bytes and their authoritative expiry and revision metadata.
    /// Override this and [`Self::get_many_with_metadata`] when metadata is known.
    async fn get_with_metadata(&self, addr: Address<'_>) -> Result<Option<ProviderValue>> {
        self.get(addr)
            .await
            .map(|value| value.map(|value| ProviderValue::new(value, None)))
    }

    /// Tests presence. Write-only providers must override this without reading bytes.
    async fn exists(&self, addr: Address<'_>) -> Result<bool> {
        Ok(self.get(addr).await?.is_some())
    }

    /// Stores arbitrary secret bytes. Enforce the same policy as [`Self::check_writable`].
    async fn set(&self, addr: Address<'_>, value: &SecretBytes) -> Result<()>;

    /// Stores a value with an optional store-side lifetime hint, as in
    /// [`Provider::set_expiring`]. The default stores an ordinary value.
    async fn set_expiring(
        &self,
        addr: Address<'_>,
        value: &SecretBytes,
        max_age: Duration,
    ) -> Result<()> {
        let _ = max_age;
        self.set(addr, value).await
    }

    /// Deletes a secret, returning whether it existed. Deletion is opt-in.
    async fn delete(&self, addr: Address<'_>) -> Result<bool> {
        let _ = addr;
        Err(self.deletion_unsupported())
    }

    /// Checks deletion policy without mutating storage.
    /// Deletable providers should override this to validate the address.
    async fn check_deletable(&self, addr: Address<'_>) -> Result<()> {
        if !self.supports_delete() {
            return Err(self.deletion_unsupported());
        }
        AsyncProvider::resolve_address(self, addr).await.map(|_| ())
    }

    /// Checks write policy without writing. Read-only providers must override it.
    async fn check_writable(&self, addr: Address<'_>) -> Result<()> {
        let _ = addr;
        Ok(())
    }

    /// Discovers secret declarations within the supplied project and profile.
    async fn reflect(
        &self,
        context: DiscoveryContext<'_>,
    ) -> Result<HashMap<String, crate::Secret>> {
        let _ = context;
        Err(SecretSpecError::ProviderOperationFailed(format!(
            "Provider '{}' does not support reflection",
            self.name()
        )))
    }

    /// Retrieves several secrets, omitting missing values. The default awaits
    /// each unique address once with bounded concurrency; override for native batch I/O.
    async fn get_many(
        &self,
        requests: &[(&str, Address<'_>)],
    ) -> Result<HashMap<String, SecretBytes>> {
        get_each_with(requests, |addr| self.get(addr)).await
    }

    /// Batch reads with metadata. The default preserves optimized
    /// [`Self::get_many`] overrides and reports unknown expiry and revision,
    /// matching [`Provider::get_many_with_metadata`].
    async fn get_many_with_metadata(
        &self,
        requests: &[(&str, Address<'_>)],
    ) -> Result<HashMap<String, ProviderValue>> {
        self.get_many(requests).await.map(|values| {
            values
                .into_iter()
                .map(|(name, value)| (name, ProviderValue::new(value, None)))
                .collect()
        })
    }

    /// Tests batch presence, deduplicating addresses. Readable stores reuse
    /// [`Self::get_many`]; write-only stores use [`Self::exists`].
    async fn exists_many(&self, requests: &[(&str, Address<'_>)]) -> Result<HashSet<String>> {
        if self.supports_read() {
            return Ok(self.get_many(requests).await?.into_keys().collect());
        }
        let mut fetched = HashMap::new();
        let mut names = HashSet::new();
        for &(name, addr) in requests {
            if let std::collections::hash_map::Entry::Vacant(entry) = fetched.entry(addr) {
                entry.insert(self.exists(addr).await?);
            }
            if fetched[&addr] {
                names.insert(name.to_owned());
            }
        }
        Ok(names)
    }

    /// Negotiates dynamic capabilities before synchronous compatibility access.
    async fn initialize(&self) -> Result<()> {
        Ok(())
    }

    /// Resolves an address, awaiting backend lookups when required.
    async fn resolve_address<'a>(
        &self,
        addr: Address<'a>,
    ) -> Result<std::borrow::Cow<'a, crate::NativeAddress>> {
        super::ProviderBase::resolve_coords(self, addr)
    }

    /// Resolves the physical entry used by destructive preflight.
    async fn entry_coordinates<'a>(
        &self,
        addr: Address<'a>,
    ) -> Result<std::borrow::Cow<'a, crate::NativeAddress>> {
        self.configured_entry_coordinates(addr)
    }

    async fn entry_coordinates_many(
        &self,
        addrs: &[Address<'_>],
    ) -> Result<Vec<crate::NativeAddress>> {
        let mut entries = Vec::with_capacity(addrs.len());
        for addr in addrs {
            entries.push(self.entry_coordinates(*addr).await?.into_owned());
        }
        Ok(entries)
    }

    async fn write_target(&self, addr: Address<'_>) -> Result<String> {
        super::ProviderBase::describe_write_target(self, addr)
    }
}

#[async_trait]
impl<T: AsyncProvider + ?Sized> AsyncProvider for Box<T> {
    async fn get(&self, addr: Address<'_>) -> Result<Option<SecretBytes>> {
        (**self).get(addr).await
    }

    async fn get_with_metadata(&self, addr: Address<'_>) -> Result<Option<ProviderValue>> {
        (**self).get_with_metadata(addr).await
    }

    async fn exists(&self, addr: Address<'_>) -> Result<bool> {
        (**self).exists(addr).await
    }

    async fn set(&self, addr: Address<'_>, value: &SecretBytes) -> Result<()> {
        (**self).set(addr, value).await
    }

    async fn set_expiring(
        &self,
        addr: Address<'_>,
        value: &SecretBytes,
        max_age: Duration,
    ) -> Result<()> {
        (**self).set_expiring(addr, value, max_age).await
    }

    async fn delete(&self, addr: Address<'_>) -> Result<bool> {
        (**self).delete(addr).await
    }

    async fn check_deletable(&self, addr: Address<'_>) -> Result<()> {
        (**self).check_deletable(addr).await
    }

    async fn check_writable(&self, addr: Address<'_>) -> Result<()> {
        (**self).check_writable(addr).await
    }

    async fn reflect(
        &self,
        context: DiscoveryContext<'_>,
    ) -> Result<HashMap<String, crate::Secret>> {
        (**self).reflect(context).await
    }

    async fn get_many(
        &self,
        requests: &[(&str, Address<'_>)],
    ) -> Result<HashMap<String, SecretBytes>> {
        (**self).get_many(requests).await
    }

    async fn get_many_with_metadata(
        &self,
        requests: &[(&str, Address<'_>)],
    ) -> Result<HashMap<String, ProviderValue>> {
        (**self).get_many_with_metadata(requests).await
    }

    async fn exists_many(&self, requests: &[(&str, Address<'_>)]) -> Result<HashSet<String>> {
        (**self).exists_many(requests).await
    }

    async fn initialize(&self) -> Result<()> {
        (**self).initialize().await
    }

    async fn resolve_address<'a>(
        &self,
        addr: Address<'a>,
    ) -> Result<std::borrow::Cow<'a, crate::NativeAddress>> {
        (**self).resolve_address(addr).await
    }

    async fn entry_coordinates<'a>(
        &self,
        addr: Address<'a>,
    ) -> Result<std::borrow::Cow<'a, crate::NativeAddress>> {
        (**self).entry_coordinates(addr).await
    }

    async fn entry_coordinates_many(
        &self,
        addrs: &[Address<'_>],
    ) -> Result<Vec<crate::NativeAddress>> {
        (**self).entry_coordinates_many(addrs).await
    }

    async fn write_target(&self, addr: Address<'_>) -> Result<String> {
        (**self).write_target(addr).await
    }
}

/// Runs a synchronous [`Provider`] on Tokio's blocking pool (0.22+).
///
/// Requires an active Tokio runtime when awaiting I/O methods. Configure the
/// provider before sharing it. Every operation, including batch overrides,
/// preflight, and retries, is forwarded to the supplied instance.
///
/// Dropping a future does not stop an operation that has already started on
/// the blocking pool. In particular, cancelled writes may still complete.
/// Panics from the provider are resumed in the awaiting task.
///
/// ```no_run
/// use secretspec::{Address, AsyncProvider, AsyncProviderAdapter, Provider};
/// use std::sync::Arc;
///
/// # async fn example() -> secretspec::Result<()> {
/// let provider = Box::<dyn Provider>::try_from("dotenv://.env")?;
/// let provider = AsyncProviderAdapter::new(Arc::from(provider));
/// let value = provider.get(Address::convention("myapp", "default", "API_KEY")).await?;
/// # Ok(())
/// # }
/// ```
#[derive(Clone)]
pub struct AsyncProviderAdapter {
    inner: Arc<dyn Provider>,
}

impl AsyncProviderAdapter {
    /// Adapts a configured synchronous provider without changing its policies.
    pub fn new(provider: Arc<dyn Provider>) -> Self {
        Self { inner: provider }
    }

    async fn run<T, F>(&self, operation: F) -> Result<T>
    where
        T: Send + 'static,
        F: FnOnce(&dyn Provider) -> Result<T> + Send + 'static,
    {
        let provider = Arc::clone(&self.inner);
        match tokio::task::spawn_blocking(move || operation(provider.as_ref())).await {
            Ok(result) => result,
            Err(error) if error.is_panic() => std::panic::resume_unwind(error.into_panic()),
            Err(_) => Err(SecretSpecError::ProviderOperationFailed(
                "async provider blocking task was cancelled".into(),
            )),
        }
    }
}

fn own_address(addr: Address<'_>) -> OwnedAddress {
    match addr {
        Address::Convention {
            project,
            profile,
            key,
        } => OwnedAddress::convention(project, profile, key),
        Address::Native(native) => OwnedAddress::Native(native.clone()),
    }
}

fn own_requests(requests: &[(&str, Address<'_>)]) -> Vec<(String, OwnedAddress)> {
    requests
        .iter()
        .map(|(name, addr)| ((*name).to_owned(), own_address(*addr)))
        .collect()
}

fn borrowed_requests(requests: &[(String, OwnedAddress)]) -> Vec<(&str, Address<'_>)> {
    requests
        .iter()
        .map(|(name, addr)| (name.as_str(), addr.as_address()))
        .collect()
}

#[async_trait]
impl AsyncProvider for AsyncProviderAdapter {
    async fn get(&self, addr: Address<'_>) -> Result<Option<SecretBytes>> {
        let addr = own_address(addr);
        self.run(move |provider| provider.get(addr.as_address()))
            .await
    }

    async fn get_with_metadata(&self, addr: Address<'_>) -> Result<Option<ProviderValue>> {
        let addr = own_address(addr);
        self.run(move |provider| provider.get_with_metadata(addr.as_address()))
            .await
    }

    async fn exists(&self, addr: Address<'_>) -> Result<bool> {
        let addr = own_address(addr);
        self.run(move |provider| provider.exists(addr.as_address()))
            .await
    }

    async fn set(&self, addr: Address<'_>, value: &SecretBytes) -> Result<()> {
        let addr = own_address(addr);
        let value = value.clone();
        self.run(move |provider| provider.set(addr.as_address(), &value))
            .await
    }

    async fn set_expiring(
        &self,
        addr: Address<'_>,
        value: &SecretBytes,
        max_age: Duration,
    ) -> Result<()> {
        let addr = own_address(addr);
        let value = value.clone();
        self.run(move |provider| provider.set_expiring(addr.as_address(), &value, max_age))
            .await
    }

    async fn delete(&self, addr: Address<'_>) -> Result<bool> {
        let addr = own_address(addr);
        self.run(move |provider| provider.delete(addr.as_address()))
            .await
    }

    async fn check_deletable(&self, addr: Address<'_>) -> Result<()> {
        let addr = own_address(addr);
        self.run(move |provider| provider.check_deletable(addr.as_address()))
            .await
    }

    async fn check_writable(&self, addr: Address<'_>) -> Result<()> {
        let addr = own_address(addr);
        self.run(move |provider| provider.check_writable(addr.as_address()))
            .await
    }

    async fn reflect(
        &self,
        context: DiscoveryContext<'_>,
    ) -> Result<HashMap<String, crate::Secret>> {
        let project = context.project.to_owned();
        let profile = context.profile.to_owned();
        self.run(move |provider| provider.reflect(DiscoveryContext::new(&project, &profile)))
            .await
    }

    async fn get_many(
        &self,
        requests: &[(&str, Address<'_>)],
    ) -> Result<HashMap<String, SecretBytes>> {
        let requests = own_requests(requests);
        self.run(move |provider| provider.get_many(&borrowed_requests(&requests)))
            .await
    }

    async fn get_many_with_metadata(
        &self,
        requests: &[(&str, Address<'_>)],
    ) -> Result<HashMap<String, ProviderValue>> {
        let requests = own_requests(requests);
        self.run(move |provider| provider.get_many_with_metadata(&borrowed_requests(&requests)))
            .await
    }

    async fn exists_many(&self, requests: &[(&str, Address<'_>)]) -> Result<HashSet<String>> {
        let requests = own_requests(requests);
        self.run(move |provider| provider.exists_many(&borrowed_requests(&requests)))
            .await
    }

    async fn resolve_address<'a>(
        &self,
        addr: Address<'a>,
    ) -> Result<std::borrow::Cow<'a, crate::NativeAddress>> {
        let addr = own_address(addr);
        self.run(move |provider| {
            provider
                .resolve_coords(addr.as_address())
                .map(|coords| coords.into_owned())
        })
        .await
        .map(std::borrow::Cow::Owned)
    }

    async fn entry_coordinates<'a>(
        &self,
        addr: Address<'a>,
    ) -> Result<std::borrow::Cow<'a, crate::NativeAddress>> {
        let addr = own_address(addr);
        self.run(move |provider| {
            provider
                .entry_coordinates(addr.as_address())
                .map(|coords| coords.into_owned())
        })
        .await
        .map(std::borrow::Cow::Owned)
    }

    async fn entry_coordinates_many(
        &self,
        addrs: &[Address<'_>],
    ) -> Result<Vec<crate::NativeAddress>> {
        let requests: Vec<_> = addrs.iter().map(|addr| own_address(*addr)).collect();
        self.run(move |provider| {
            provider.entry_coordinates_many(
                &requests
                    .iter()
                    .map(OwnedAddress::as_address)
                    .collect::<Vec<_>>(),
            )
        })
        .await
    }

    async fn write_target(&self, addr: Address<'_>) -> Result<String> {
        let addr = own_address(addr);
        self.run(move |provider| provider.describe_write_target(addr.as_address()))
            .await
    }
}

impl super::ProviderBase for AsyncProviderAdapter {
    fn set_retry_policy(&mut self, _policy: super::RetryPolicy) {
        if let Some(provider) = Arc::get_mut(&mut self.inner) {
            provider.set_retry_policy(_policy);
        }
    }

    fn retry_ownership(&self) -> super::RetryOwnership {
        self.inner.retry_ownership()
    }

    fn retry_safe(&self, _operation: super::RetryOperation, _addr: Address<'_>) -> bool {
        self.inner.retry_safe(_operation, _addr)
    }

    fn convention_address(&self, project: &str, profile: &str, key: &str) -> Result<NativeAddress> {
        self.inner.convention_address(project, profile, key)
    }

    fn supported_coords(&self) -> &'static [&'static str] {
        self.inner.supported_coords()
    }

    fn supports_coord(&self, name: &str) -> bool {
        self.inner.supports_coord(name)
    }

    fn resolve_coords<'a>(&self, addr: Address<'a>) -> Result<Cow<'a, NativeAddress>> {
        self.inner.resolve_coords(addr)
    }

    fn configured_entry_coordinates<'a>(
        &self,
        addr: Address<'a>,
    ) -> Result<Cow<'a, NativeAddress>> {
        self.inner.configured_entry_coordinates(addr)
    }

    fn supports_read(&self) -> bool {
        self.inner.supports_read()
    }

    fn supports_delete(&self) -> bool {
        self.inner.supports_delete()
    }

    fn deletion_unsupported(&self) -> SecretSpecError {
        self.inner.deletion_unsupported()
    }

    fn generated_value_persistence(&self) -> ProducedValuePersistence {
        self.inner.generated_value_persistence()
    }

    fn prompted_value_persistence(&self) -> ProducedValuePersistence {
        self.inner.prompted_value_persistence()
    }

    fn describe_write_target(&self, addr: Address<'_>) -> Result<String> {
        self.inner.describe_write_target(addr)
    }

    fn auth_scope_key(&self) -> Option<String> {
        self.inner.auth_scope_key()
    }

    fn name(&self) -> &str {
        self.inner.name()
    }

    fn uri(&self) -> String {
        self.inner.uri()
    }

    fn storage_identity(&self) -> String {
        self.inner.storage_identity()
    }

    fn entry_container_identity(&self) -> String {
        self.inner.entry_container_identity()
    }

    fn physical_store_path(&self) -> Option<&std::path::Path> {
        self.inner.physical_store_path()
    }

    fn configured_physical_store_path(&self) -> Option<&std::path::Path> {
        self.inner.configured_physical_store_path()
    }

    fn set_reason(&self, _reason: Option<String>) {
        self.inner.set_reason(_reason)
    }

    fn set_requested_authorization_duration(&self, _duration: Option<std::time::Duration>) {
        self.inner.set_requested_authorization_duration(_duration)
    }

    fn set_caller(&self, _caller: Option<crate::CallerContext>) {
        self.inner.set_caller(_caller)
    }

    fn set_project(&self, _project: &str) {
        self.inner.set_project(_project)
    }

    fn set_profile(&self, _profile: &str) {
        self.inner.set_profile(_profile)
    }

    fn with_base_dir(&mut self, _base_dir: &std::path::Path) {
        if let Some(provider) = Arc::get_mut(&mut self.inner) {
            provider.with_base_dir(_base_dir);
        }
    }

    fn with_credentials(&mut self, _credentials: ProviderCredentials) {
        if let Some(provider) = Arc::get_mut(&mut self.inner) {
            provider.with_credentials(_credentials);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::map_concurrently;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[tokio::test(flavor = "current_thread")]
    async fn native_async_batches_are_bounded_and_preserve_order() {
        let active = AtomicUsize::new(0);
        let peak = AtomicUsize::new(0);
        let items = [5, 4, 3, 2, 1];
        let values = map_concurrently(&items, 2, |item| async {
            let count = active.fetch_add(1, Ordering::SeqCst) + 1;
            peak.fetch_max(count, Ordering::SeqCst);
            tokio::task::yield_now().await;
            active.fetch_sub(1, Ordering::SeqCst);
            *item * 2
        })
        .await;
        assert_eq!(values, [10, 8, 6, 4, 2]);
        assert_eq!(peak.load(Ordering::SeqCst), 2);
        assert_eq!(active.load(Ordering::SeqCst), 0);
    }
}
