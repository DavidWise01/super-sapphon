//! SAPPHON-207: bounded original vendor manifest and image evidence fence.
#![cfg(target_os = "linux")]
use crate::Error;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{File, OpenOptions},
    io::Write,
    path::Path,
};
pub const AUTHORITY: &str = "HOLD";
fn hex64(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}
fn hash(b: &[u8]) -> String {
    hex::encode(Sha256::digest(b))
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Input {
    pub lockfile_sha256: String,
    pub vendor_tree_sha256: String,
    pub vendor_archive_sha256: String,
    pub files: u32,
    pub original_file_hashes_verified: bool,
    pub no_symlinks_or_traversal: bool,
    pub archive_bytes_reverified: bool,
    pub cargo_offline_locked_observed: bool,
    pub image_base_reference: Option<String>,
    pub original_image_id: Option<String>,
    pub original_image_archive_sha256: Option<String>,
    pub archived_image_bytes_reverified: bool,
    pub independent_external_witness_claim: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Finding {
    pub schema: String,
    pub input_sha256: String,
    pub vendor_qualified: bool,
    pub local_image_archive_qualified: bool,
    pub blockers: Vec<String>,
    pub independent_witnesses: u8,
    pub authenticated_utc: bool,
    pub global_anti_rollback_authenticated: bool,
    pub recovery_authorized: bool,
    pub lock_cleared: bool,
    pub decision: String,
}
pub fn assess(x: &Input) -> Result<Finding, Error> {
    let mut bad = Vec::new();
    if !hex64(&x.lockfile_sha256)
        || !hex64(&x.vendor_tree_sha256)
        || !hex64(&x.vendor_archive_sha256)
        || x.files == 0
        || x.files > 20000
    {
        bad.push("LOCK_OR_VENDOR_DIGEST_INVALID".into());
    }
    if !x.original_file_hashes_verified
        || !x.no_symlinks_or_traversal
        || !x.archive_bytes_reverified
        || !x.cargo_offline_locked_observed
    {
        bad.push("VENDOR_OFFLINE_BYTES_UNVERIFIED".into());
    }
    let vendor = bad.is_empty();
    let image = x
        .image_base_reference
        .as_deref()
        .is_some_and(|v| v.contains("@sha256:") && v.rsplit("@sha256:").next().is_some_and(hex64))
        && x.original_image_id
            .as_deref()
            .is_some_and(|v| v.starts_with("sha256:") && hex64(&v[7..]))
        && x.original_image_archive_sha256
            .as_deref()
            .is_some_and(hex64)
        && x.archived_image_bytes_reverified;
    if !image {
        bad.push("LOCAL_IMAGE_ARCHIVE_NOT_QUALIFIED".into());
    }
    if x.independent_external_witness_claim {
        bad.push("UNSUPPORTED_EXTERNAL_WITNESS".into());
    }
    bad.sort();
    bad.dedup();
    let bytes = serde_json::to_vec(x).map_err(|_| Error("VENDOR207_ENCODING"))?;
    Ok(Finding {
        schema: "sapphon-207-rust-vendor-v1".into(),
        input_sha256: hash(&bytes),
        vendor_qualified: vendor,
        local_image_archive_qualified: vendor && image,
        blockers: bad,
        independent_witnesses: 0,
        authenticated_utc: false,
        global_anti_rollback_authenticated: false,
        recovery_authorized: false,
        lock_cleared: false,
        decision: "PHASE_XX_VENDOR_IMAGE_HOLD".into(),
    })
}
pub fn write_new(p: &Path, v: &Finding) -> Result<String, Error> {
    if v.schema != "sapphon-207-rust-vendor-v1"
        || v.decision != "PHASE_XX_VENDOR_IMAGE_HOLD"
        || v.independent_witnesses != 0
        || v.authenticated_utc
        || v.global_anti_rollback_authenticated
        || v.recovery_authorized
        || v.lock_cleared
    {
        return Err(Error("VENDOR207_AUTHORITY"));
    }
    let bytes = serde_json::to_vec(v).map_err(|_| Error("VENDOR207_ENCODING"))?;
    let mut f = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(p)
        .map_err(|_| Error("VENDOR207_EXISTS"))?;
    f.write_all(&bytes).map_err(|_| Error("VENDOR207_WRITE"))?;
    f.sync_all().map_err(|_| Error("VENDOR207_SYNC"))?;
    File::open(p.parent().ok_or(Error("VENDOR207_PARENT"))?)
        .and_then(|d| d.sync_all())
        .map_err(|_| Error("VENDOR207_DIRSYNC"))?;
    Ok(hash(&bytes))
}
#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> Input {
        Input {
            lockfile_sha256: "a".repeat(64),
            vendor_tree_sha256: "b".repeat(64),
            vendor_archive_sha256: "c".repeat(64),
            files: 32,
            original_file_hashes_verified: true,
            no_symlinks_or_traversal: true,
            archive_bytes_reverified: true,
            cargo_offline_locked_observed: true,
            image_base_reference: None,
            original_image_id: None,
            original_image_archive_sha256: None,
            archived_image_bytes_reverified: false,
            independent_external_witness_claim: false,
        }
    }
    #[test]
    fn vendor_only_no_recovery() {
        let r = assess(&fixture()).unwrap();
        assert!(r.vendor_qualified && !r.local_image_archive_qualified && !r.recovery_authorized);
    }
    #[test]
    fn missing_vendor_hash() {
        let mut x = fixture();
        x.vendor_tree_sha256 = "not".into();
        assert!(!assess(&x).unwrap().vendor_qualified);
    }
    #[test]
    fn no_offline_check() {
        let mut x = fixture();
        x.cargo_offline_locked_observed = false;
        assert!(!assess(&x).unwrap().vendor_qualified);
    }
    #[test]
    fn symlink_refused() {
        let mut x = fixture();
        x.no_symlinks_or_traversal = false;
        assert!(!assess(&x).unwrap().vendor_qualified);
    }
    #[test]
    fn archive_readback_needed() {
        let mut x = fixture();
        x.archive_bytes_reverified = false;
        assert!(!assess(&x).unwrap().vendor_qualified);
    }
    #[test]
    fn image_mutable_tag_denied() {
        let mut x = fixture();
        x.image_base_reference = Some("rust:latest".into());
        assert!(!assess(&x).unwrap().local_image_archive_qualified);
    }
    #[test]
    fn unverified_image_tar_denied() {
        let mut x = fixture();
        x.image_base_reference = Some(format!("rust@sha256:{}", "a".repeat(64)));
        x.original_image_id = Some(format!("sha256:{}", "b".repeat(64)));
        x.original_image_archive_sha256 = Some("c".repeat(64));
        assert!(!assess(&x).unwrap().local_image_archive_qualified);
    }
    #[test]
    fn local_image_qualified_still_hold() {
        let mut x = fixture();
        x.image_base_reference = Some(format!("rust@sha256:{}", "a".repeat(64)));
        x.original_image_id = Some(format!("sha256:{}", "b".repeat(64)));
        x.original_image_archive_sha256 = Some("c".repeat(64));
        x.archived_image_bytes_reverified = true;
        let r = assess(&x).unwrap();
        assert!(r.local_image_archive_qualified && !r.recovery_authorized);
    }
    #[test]
    fn unsupported_witness_refused() {
        let mut x = fixture();
        x.independent_external_witness_claim = true;
        assert!(assess(&x)
            .unwrap()
            .blockers
            .iter()
            .any(|s| s == "UNSUPPORTED_EXTERNAL_WITNESS"));
    }
    #[test]
    fn create_only() {
        let v = assess(&fixture()).unwrap();
        let p = std::env::temp_dir().join(format!("sapphon207-{}.json", std::process::id()));
        let _ = std::fs::remove_file(&p);
        write_new(&p, &v).unwrap();
        assert_eq!(write_new(&p, &v).unwrap_err().0, "VENDOR207_EXISTS");
        std::fs::remove_file(p).unwrap();
    }
}
