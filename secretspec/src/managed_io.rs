//! File I/O used by opted-in providers on the request's joined worker.
use crate::request::RequestContext;
use crate::{Result, SecretSpecError};
use std::io::Read;
use std::path::Path;

pub(crate) fn read(path: &Path, request: Option<&RequestContext>) -> Result<Vec<u8>> {
    let Some(request) = request else {
        return Ok(std::fs::read(path)?);
    };
    request.checkpoint()?;
    if !std::fs::metadata(path)?.is_file() {
        return Err(crate::request::unsupported("reading a non-regular file"));
    }
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    // A FIFO substituted after metadata must not block in open(). Verify the
    // opened descriptor too; regular files ignore O_NONBLOCK.
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NONBLOCK);
    }
    request.checkpoint()?;
    let mut file = options.open(path)?;
    if !file.metadata()?.is_file() {
        return Err(crate::request::unsupported("reading a non-regular file"));
    }
    let mut bytes = Vec::new();
    let mut chunk = [0u8; 16 * 1024];
    loop {
        request.checkpoint()?;
        let count = match file.read(&mut chunk) {
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            result => result?,
        };
        if count == 0 {
            break;
        }
        bytes.extend_from_slice(&chunk[..count]);
    }
    request.checkpoint()?;
    Ok(bytes)
}

pub(crate) fn read_to_string(path: &Path, request: Option<&RequestContext>) -> Result<String> {
    String::from_utf8(read(path, request)?).map_err(|_| {
        SecretSpecError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "file is not UTF-8",
        ))
    })
}

pub(crate) fn lock<'a, T>(
    mutex: &'a std::sync::Mutex<T>,
    request: Option<&RequestContext>,
) -> Result<std::sync::MutexGuard<'a, T>> {
    let Some(request) = request else {
        return Ok(mutex.lock().unwrap_or_else(|poison| poison.into_inner()));
    };
    loop {
        request.checkpoint()?;
        match mutex.try_lock() {
            Ok(guard) => return Ok(guard),
            Err(std::sync::TryLockError::Poisoned(_)) => {
                return Err(SecretSpecError::ProviderOperationFailed(
                    "provider lock poisoned".into(),
                ));
            }
            Err(std::sync::TryLockError::WouldBlock) => {
                request.wait(std::time::Duration::from_millis(10))?
            }
        }
    }
}
