//! Revision tokens derived solely from non-secret metadata (0.21+).

use crate::plan::PlannedSecret;
use secretspec_ipc::Revision;
use sha2::{Digest, Sha256};

/// Every field, including the domain, is UTF-8 with an unsigned 64-bit
/// big-endian byte-length prefix. Output is `ssr1:` plus lowercase SHA-256 hex.
/// Callers must never pass secret bytes or credential-bearing configuration.
pub(crate) fn digest(domain: &str, fields: &[&str]) -> Revision {
    let mut hash = Sha256::new();
    for field in std::iter::once(domain).chain(fields.iter().copied()) {
        hash.update((field.len() as u64).to_be_bytes());
        hash.update(field.as_bytes());
    }
    Revision::new(format!("ssr1:{:x}", hash.finalize())).expect("a digest is a valid revision")
}

pub(crate) fn effective(revision: Option<&Revision>, planned: &PlannedSecret) -> Option<Revision> {
    let revision = revision?;
    let extract = planned.extract();
    Some(digest(
        "secretspec.logical.v1",
        &[
            revision.as_str(),
            extract.map_or("", |e| e.format.as_str()),
            extract.map_or("", |e| e.pointer.as_str()),
            planned.encoding().map_or("", |e| e.as_str()),
        ],
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn revision_encoding_has_a_cross_client_test_vector() {
        assert_eq!(
            digest(
                "secretspec.awssm.v1",
                &[
                    "arn:aws:secretsmanager:us-east-1:123:secret:db-abcdef",
                    "generation-1",
                ]
            )
            .as_str(),
            "ssr1:349e0b0f3023130817fed919564410acbe95a5089e4bdef3e48a2349b1b0d76a"
        );
        assert_ne!(digest("test", &["ab", "c"]), digest("test", &["a", "bc"]));
        assert_ne!(digest("test", &["a"]), digest("other", &["a"]));
    }
}
