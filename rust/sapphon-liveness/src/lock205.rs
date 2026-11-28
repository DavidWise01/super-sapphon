//! SAPPHON-205: source-owned Cargo resolution provenance; replay authority HOLD.
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
const SOURCE: &str = "50680b739378147d626c4822862d73306acc26bf";
fn hex64(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|x| x.is_ascii_digit() || (b'a'..=b'f').contains(&x))
}
fn digest(raw: &[u8]) -> String {
    hex::encode(Sha256::digest(raw))
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Input {
    pub source_sha: String,
    pub manifest_sha256: String,
    pub cargo_lock_sha256: String,
    pub generated_lock_observed: bool,
    pub package_count: u32,
    pub registry_package_count: u32,
    pub vendor_completed: bool,
    pub offline_metadata_completed: bool,
    pub offline_check_completed: bool,
    pub all_registry_checksums_present: bool,
    pub image_digest_verified: bool,
    pub original_failure_observed: bool,
    pub untrusted_command_executed: bool,
    pub external_custody_claim: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Finding {
    pub schema: String,
    pub source_owned_offline_qualified: bool,
    pub blockers: Vec<String>,
    pub input_sha256: String,
    pub rust_replay_executed: bool,
    pub independent_witnesses: u8,
    pub authenticated_utc: bool,
    pub global_anti_rollback_authenticated: bool,
    pub recovery_authorized: bool,
    pub lock_cleared: bool,
    pub decision: String,
}
pub fn assess(x: &Input) -> Result<Finding, Error> {
    let mut bad = Vec::new();
    if x.source_sha != SOURCE || !hex64(&x.manifest_sha256) {
        bad.push("SOURCE_MANIFEST".into());
    }
    if !x.generated_lock_observed || !hex64(&x.cargo_lock_sha256) || x.package_count == 0 {
        bad.push("LOCK_GENESIS_NOT_VERIFIED".into());
    }
    if !x.all_registry_checksums_present {
        bad.push("REGISTRY_CHECKSUM_GAP".into());
    }
    if !x.vendor_completed || !x.offline_metadata_completed || !x.offline_check_completed {
        bad.push("OFFLINE_DEPENDENCY_TEST_MISSING".into());
    }
    if x.untrusted_command_executed || x.external_custody_claim {
        bad.push("UNSUPPORTED_AUTHORITY".into());
    }
    bad.sort();
    bad.dedup();
    let raw = serde_json::to_vec(x).map_err(|_| Error("LOCK205_ENCODING"))?;
    Ok(Finding {
        schema: "sapphon-205-rust-lock-provenance-v1".into(),
        source_owned_offline_qualified: bad.is_empty(),
        blockers: bad,
        input_sha256: digest(&raw),
        rust_replay_executed: false,
        independent_witnesses: 0,
        authenticated_utc: false,
        global_anti_rollback_authenticated: false,
        recovery_authorized: false,
        lock_cleared: false,
        decision: "PHASE_XX_DEPENDENCY_PROVENANCE_HOLD".into(),
    })
}
pub fn write_new(path: &Path, f: &Finding) -> Result<String, Error> {
    if f.schema != "sapphon-205-rust-lock-provenance-v1"
        || f.decision != "PHASE_XX_DEPENDENCY_PROVENANCE_HOLD"
        || f.rust_replay_executed
        || f.independent_witnesses != 0
        || f.authenticated_utc
        || f.global_anti_rollback_authenticated
        || f.recovery_authorized
        || f.lock_cleared
    {
        return Err(Error("LOCK205_AUTHORITY"));
    }
    let raw = serde_json::to_vec(f).map_err(|_| Error("LOCK205_ENCODING"))?;
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)
        .map_err(|_| Error("LOCK205_EXISTS"))?;
    file.write_all(&raw).map_err(|_| Error("LOCK205_WRITE"))?;
    file.sync_all().map_err(|_| Error("LOCK205_SYNC"))?;
    File::open(path.parent().ok_or(Error("LOCK205_PARENT"))?)
        .and_then(|x| x.sync_all())
        .map_err(|_| Error("LOCK205_DIRSYNC"))?;
    Ok(digest(&raw))
}
#[cfg(test)]
mod tests {
    use super::*;
    fn ok() -> Input {
        Input {
            source_sha: SOURCE.into(),
            manifest_sha256: "a".repeat(64),
            cargo_lock_sha256: "b".repeat(64),
            generated_lock_observed: true,
            package_count: 19,
            registry_package_count: 16,
            vendor_completed: true,
            offline_metadata_completed: true,
            offline_check_completed: true,
            all_registry_checksums_present: true,
            image_digest_verified: false,
            original_failure_observed: false,
            untrusted_command_executed: false,
            external_custody_claim: false,
        }
    }
    #[test]
    fn lock_does_not_clear_hold() {
        let x = assess(&ok()).unwrap();
        assert!(x.source_owned_offline_qualified && !x.recovery_authorized);
    }
    #[test]
    fn no_lock() {
        let mut x = ok();
        x.generated_lock_observed = false;
        assert!(!assess(&x).unwrap().source_owned_offline_qualified);
    }
    #[test]
    fn bad_hash() {
        let mut x = ok();
        x.cargo_lock_sha256 = "bad".into();
        assert!(!assess(&x).unwrap().source_owned_offline_qualified);
    }
    #[test]
    fn no_vendor() {
        let mut x = ok();
        x.vendor_completed = false;
        assert!(!assess(&x).unwrap().source_owned_offline_qualified);
    }
    #[test]
    fn no_offline_metadata() {
        let mut x = ok();
        x.offline_metadata_completed = false;
        assert!(!assess(&x).unwrap().source_owned_offline_qualified);
    }
    #[test]
    fn no_offline_build() {
        let mut x = ok();
        x.offline_check_completed = false;
        assert!(!assess(&x).unwrap().source_owned_offline_qualified);
    }
    #[test]
    fn incomplete_checksums() {
        let mut x = ok();
        x.all_registry_checksums_present = false;
        assert!(!assess(&x).unwrap().source_owned_offline_qualified);
    }
    #[test]
    fn forged_custody() {
        let mut x = ok();
        x.external_custody_claim = true;
        assert!(!assess(&x).unwrap().source_owned_offline_qualified);
    }
    #[test]
    fn lock_not_an_image() {
        let x = assess(&ok()).unwrap();
        assert!(!x.rust_replay_executed);
    }
    #[test]
    fn create_only() {
        let x = assess(&ok()).unwrap();
        let p = std::env::temp_dir().join(format!("sapphon205-{}.json", std::process::id()));
        let _ = std::fs::remove_file(&p);
        write_new(&p, &x).unwrap();
        assert_eq!(write_new(&p, &x).unwrap_err().0, "LOCK205_EXISTS");
        std::fs::remove_file(p).unwrap();
    }
}
