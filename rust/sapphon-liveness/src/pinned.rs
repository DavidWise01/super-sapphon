//! SAPPHON-133: bound owner-marker continuity to an independently retained digest.
//! A digest supplied by the same untrusted marker is NOT independent custody.
//! This module only qualifies evidence for further signed review; never clears locks.
use crate::{qualify, Error, Finding};
use sha2::{Digest, Sha256};
use std::{fs, path::Path};

pub const AUTHORITY: &str = "HOLD";
pub const MAX_MARKER_BYTES: u64 = 16 * 1024;

/// Call the trusted acquisition side to pin these bytes before process exit.
/// Persist the digest outside the writable lock directory; this crate does
/// not assert that the caller has established an independent custody root.
pub fn marker_digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// The expected SHA-256 must originate from trusted acquisition state, not
/// from owner.json or a value furnished by the potential recovery requester.
/// Both pre/post comparisons protect against an ordinary concurrent rewrite;
/// neither removes TOCTOU races or grants automatic recovery rights.
pub fn qualify_pinned(root: &Path, expected_marker_sha256: &str) -> Result<Finding, Error> {
    if expected_marker_sha256.len() != 64
        || !expected_marker_sha256
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(Error("PIN_INVALID"));
    }
    let marker = crate::owner_path(root);
    let metadata = fs::metadata(&marker).map_err(|_| Error("PIN_MARKER_UNREADABLE"))?;
    if !metadata.is_file() || metadata.len() > MAX_MARKER_BYTES {
        return Err(Error("PIN_MARKER_INVALID"));
    }
    let before = fs::read(&marker).map_err(|_| Error("PIN_MARKER_UNREADABLE"))?;
    if marker_digest(&before) != expected_marker_sha256 {
        return Err(Error("PIN_OWNER_MISMATCH"));
    }
    let finding = qualify(root)?;
    let after = fs::read(&marker).map_err(|_| Error("PIN_MARKER_UNREADABLE"))?;
    if marker_digest(&after) != expected_marker_sha256 {
        return Err(Error("PIN_OWNER_CHANGED"));
    }
    // Deliberately do not expose a function that removes a lock.
    Ok(finding)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn deterministic_digest_is_exact_bytes() {
        assert_eq!(marker_digest(b"{}"), marker_digest(b"{}"));
        assert_ne!(marker_digest(b"{}"), marker_digest(b"{} "));
    }
    #[test]
    fn invalid_pin_is_rejected_before_any_os_observation() {
        let nonexistent = Path::new("/nonexistent-sapphon-133");
        assert_eq!(
            qualify_pinned(nonexistent, "caller-declared-dead")
                .unwrap_err()
                .0,
            "PIN_INVALID"
        );
        assert_eq!(
            qualify_pinned(nonexistent, &"A".repeat(64)).unwrap_err().0,
            "PIN_INVALID"
        );
    }
    #[test]
    fn unknown_marker_cannot_claim_custody() {
        let nonexistent = Path::new("/nonexistent-sapphon-133");
        assert_eq!(
            qualify_pinned(nonexistent, &"a".repeat(64)).unwrap_err().0,
            "PIN_MARKER_UNREADABLE"
        );
    }
}
