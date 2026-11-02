//! Locate a RAM disk by the identifier supplied at attachment time, even if
//! the attaching process never records its dynamically assigned device node.
use core_foundation::{
    base::{CFAllocatorRef, CFType, CFTypeRef, TCFType},
    dictionary::{CFDictionary, CFDictionaryRef},
    string::{CFString, CFStringRef},
};
use std::{io, mem, ptr};

pub(super) const LEASE_KEY: &str = "FileLeaseIdentifier";

#[link(name = "IOKit", kind = "framework")]
unsafe extern "C" {
    fn IOServiceGetMatchingServices(
        port: u32,
        matching: CFDictionaryRef,
        iterator: *mut u32,
    ) -> i32;
    fn IOIteratorNext(iterator: u32) -> u32;
    fn IOIteratorIsValid(iterator: u32) -> u32;
    fn IOObjectRelease(object: u32) -> i32;
    fn IORegistryEntryCreateIterator(
        entry: u32,
        plane: *const libc::c_char,
        options: u32,
        iterator: *mut u32,
    ) -> i32;
    fn IORegistryEntryCreateCFProperty(
        entry: u32,
        key: CFStringRef,
        allocator: CFAllocatorRef,
        options: u32,
    ) -> CFTypeRef;
}

struct Object(u32);
impl Drop for Object {
    fn drop(&mut self) {
        unsafe { IOObjectRelease(self.0) };
    }
}
impl Object {
    fn next(&self) -> io::Result<Option<Self>> {
        let next = unsafe { IOIteratorNext(self.0) };
        if next != 0 {
            Ok(Some(Self(next)))
        } else if unsafe { IOIteratorIsValid(self.0) } != 0 {
            Ok(None)
        } else {
            Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "IOKit iterator invalidated",
            ))
        }
    }

    fn string_property(&self, key: &str) -> Option<String> {
        let key = CFString::new(key);
        let value = unsafe {
            IORegistryEntryCreateCFProperty(self.0, key.as_concrete_TypeRef(), ptr::null(), 0)
        };
        if value.is_null() {
            return None;
        }
        let value: CFType = unsafe { TCFType::wrap_under_create_rule(value) };
        value
            .downcast::<CFString>()
            .map(|string| string.to_string())
    }

    fn collect_devices(&self, devices: &mut Vec<String>) {
        if let Some(name) = self.string_property("BSD Name")
            && name.strip_prefix("disk").is_some_and(|digits| {
                !digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_digit())
            })
        {
            devices.push(format!("/dev/{name}"));
        }
    }
}

fn check(result: i32) -> io::Result<()> {
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "IOKit registry lookup failed: {result}"
        )))
    }
}

pub(super) fn device(id: uuid::Uuid) -> io::Result<Option<String>> {
    retry_lookup(|| device_once(id))
}

fn retry_lookup(
    mut lookup: impl FnMut() -> io::Result<Option<String>>,
) -> io::Result<Option<String>> {
    for _ in 0..3 {
        match lookup() {
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            result => return result,
        }
    }
    Err(io::Error::other(
        "IOKit registry changed during file lease lookup",
    ))
}

fn device_once(id: uuid::Uuid) -> io::Result<Option<String>> {
    let properties = CFDictionary::from_CFType_pairs(&[(
        CFString::new(LEASE_KEY),
        CFString::new(&id.to_string()),
    )]);
    let matching = CFDictionary::from_CFType_pairs(&[
        (
            CFString::new("IOProviderClass"),
            CFString::new("IOService").as_CFType(),
        ),
        (CFString::new("IOPropertyMatch"), properties.as_CFType()),
    ]);
    let mut iterator = 0;
    let raw_matching = matching.as_concrete_TypeRef();
    // IOKit consumes the dictionary's reference, including on failure.
    mem::forget(matching);
    check(unsafe { IOServiceGetMatchingServices(0, raw_matching, &mut iterator) })?;
    // No matches can return success with a null iterator. It is an empty
    // result, not a registry iterator whose validity can be queried.
    if iterator == 0 {
        return Ok(None);
    }
    let iterator = Object(iterator);
    let mut devices = Vec::new();
    while let Some(entry) = iterator.next()? {
        entry.collect_devices(&mut devices);
        let mut children = 0;
        // kIORegistryIterateRecursively, in the IOService plane.
        check(unsafe {
            IORegistryEntryCreateIterator(entry.0, c"IOService".as_ptr(), 1, &mut children)
        })?;
        let children = Object(children);
        while let Some(child) = children.next()? {
            child.collect_devices(&mut devices);
        }
    }
    devices.sort();
    devices.dedup();
    match devices.len() {
        0 => Ok(None),
        1 => Ok(devices.pop()),
        _ => Err(io::Error::other(
            "Multiple devices claim the same file lease",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_identifier_has_no_device() {
        assert!(device(uuid::Uuid::new_v4()).unwrap().is_none());
    }

    #[test]
    fn invalidated_traversal_retries_without_reporting_absence() {
        let mut attempts = 0;
        let result = retry_lookup(|| {
            attempts += 1;
            if attempts == 1 {
                Err(io::Error::from(io::ErrorKind::Interrupted))
            } else {
                Ok(Some("/dev/disk42".into()))
            }
        })
        .unwrap();
        assert_eq!(result.as_deref(), Some("/dev/disk42"));
        assert_eq!(attempts, 2);
    }

    #[test]
    fn persistent_invalidation_fails_after_bounded_retries() {
        let mut attempts = 0;
        let result = retry_lookup(|| {
            attempts += 1;
            Err(io::Error::from(io::ErrorKind::Interrupted))
        });
        assert!(result.is_err());
        assert_eq!(attempts, 3);
    }
}
