//! SAPPHON-204: offline Rust replay requires pinned Cargo.lock and image digest.
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
const SOURCE: &str = "ba4b068d6b86c193515ce39e02fb8cdbf711fb8f";
fn hex64(v: &str) -> bool {
    v.len() == 64
        && v.bytes()
            .all(|x| x.is_ascii_digit() || (b'a'..=b'f').contains(&x))
}
fn hash(b: &[u8]) -> String {
    hex::encode(Sha256::digest(b))
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Input {
    pub source_sha: String,
    pub original_run_id: u64,
    pub original_attempt: u32,
    pub actual_rust_failure_observed: bool,
    pub original_log_and_zip_observed: bool,
    pub prior_fresh_readbacks_match: bool,
    pub checkout_source_sha: String,
    pub lockfile_sha256: Option<String>,
    pub lockfile_contents_verified: bool,
    pub docker_image_digest: Option<String>,
    pub image_offline_verified: bool,
    pub cargo_offline_locked: bool,
    pub source_readonly: bool,
    pub network_disabled: bool,
    pub unprivileged: bool,
    pub untrusted_job_log_commands_used: bool,
    pub external_custody_claim: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Finding {
    pub schema: String,
    pub eligible_for_offline_rust_replay: bool,
    pub input_sha256: String,
    pub blockers: Vec<String>,
    pub actual_replay_executed: bool,
    pub independent_witnesses: u8,
    pub authenticated_utc: bool,
    pub global_anti_rollback_authenticated: bool,
    pub recovery_authorized: bool,
    pub lock_cleared: bool,
    pub decision: String,
}
pub fn assess(x: &Input) -> Result<Finding, Error> {
    let mut bad = Vec::new();
    if x.source_sha != SOURCE
        || x.checkout_source_sha != "b5ddf7f7d7d51a282c0109276dc37310f56eb240"
        || x.original_run_id == 0
        || x.original_attempt == 0
    {
        bad.push("SOURCE_RUN_ANCESTRY".into());
    }
    if !x.actual_rust_failure_observed
        || !x.original_log_and_zip_observed
        || !x.prior_fresh_readbacks_match
    {
        bad.push("ORIGINAL_FAILURE_NOT_PROVEN".into());
    }
    if !x.lockfile_contents_verified || x.lockfile_sha256.as_deref().is_none_or(|v| !hex64(v)) {
        bad.push("OFFLINE_DEPENDENCY_LOCK_NOT_VERIFIED".into());
    }
    if !x.image_offline_verified
        || x.docker_image_digest
            .as_deref()
            .is_none_or(|v| !v.starts_with("sha256:") || !hex64(&v[7..]))
    {
        bad.push("IMMUTABLE_IMAGE_NOT_VERIFIED".into());
    }
    if !x.cargo_offline_locked || !x.source_readonly || !x.network_disabled || !x.unprivileged {
        bad.push("SANDBOX_ISOLATION_INCOMPLETE".into());
    }
    if x.untrusted_job_log_commands_used || x.external_custody_claim {
        bad.push("UNTRUSTED_AUTHORITY_OR_CODE".into());
    }
    bad.sort();
    bad.dedup();
    let data = serde_json::to_vec(x).map_err(|_| Error("OFFLINE204_ENCODING"))?;
    Ok(Finding {
        schema: "sapphon-204-offline-rust-v1".into(),
        eligible_for_offline_rust_replay: bad.is_empty(),
        input_sha256: hash(&data),
        blockers: bad,
        actual_replay_executed: false,
        independent_witnesses: 0,
        authenticated_utc: false,
        global_anti_rollback_authenticated: false,
        recovery_authorized: false,
        lock_cleared: false,
        decision: "PHASE_XX_OFFLINE_RUST_HOLD".into(),
    })
}
pub fn write_new(path: &Path, r: &Finding) -> Result<String, Error> {
    if r.schema != "sapphon-204-offline-rust-v1"
        || r.decision != "PHASE_XX_OFFLINE_RUST_HOLD"
        || r.actual_replay_executed
        || r.independent_witnesses != 0
        || r.authenticated_utc
        || r.global_anti_rollback_authenticated
        || r.recovery_authorized
        || r.lock_cleared
    {
        return Err(Error("OFFLINE204_AUTHORITY"));
    }
    let b = serde_json::to_vec(r).map_err(|_| Error("OFFLINE204_ENCODING"))?;
    let mut f = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)
        .map_err(|_| Error("OFFLINE204_EXISTS"))?;
    f.write_all(&b).map_err(|_| Error("OFFLINE204_WRITE"))?;
    f.sync_all().map_err(|_| Error("OFFLINE204_SYNC"))?;
    File::open(path.parent().ok_or(Error("OFFLINE204_PARENT"))?)
        .and_then(|f| f.sync_all())
        .map_err(|_| Error("OFFLINE204_DIRSYNC"))?;
    Ok(hash(&b))
}
#[cfg(test)]
mod tests {
    use super::*;
    fn good() -> Input {
        Input {
            source_sha: SOURCE.into(),
            original_run_id: 201,
            original_attempt: 2,
            actual_rust_failure_observed: true,
            original_log_and_zip_observed: true,
            prior_fresh_readbacks_match: true,
            checkout_source_sha: "b5ddf7f7d7d51a282c0109276dc37310f56eb240".into(),
            lockfile_sha256: Some("a".repeat(64)),
            lockfile_contents_verified: true,
            docker_image_digest: Some(format!("sha256:{}", "b".repeat(64))),
            image_offline_verified: true,
            cargo_offline_locked: true,
            source_readonly: true,
            network_disabled: true,
            unprivileged: true,
            untrusted_job_log_commands_used: false,
            external_custody_claim: false,
        }
    }
    #[test]
    fn qualified_is_still_hold() {
        let v = assess(&good()).unwrap();
        assert!(v.eligible_for_offline_rust_replay && !v.recovery_authorized);
    }
    #[test]
    fn no_observed_failure() {
        let mut v = good();
        v.actual_rust_failure_observed = false;
        assert!(!assess(&v).unwrap().eligible_for_offline_rust_replay);
    }
    #[test]
    fn no_lock() {
        let mut v = good();
        v.lockfile_sha256 = None;
        assert!(!assess(&v).unwrap().eligible_for_offline_rust_replay);
    }
    #[test]
    fn lock_not_verified() {
        let mut v = good();
        v.lockfile_contents_verified = false;
        assert!(!assess(&v).unwrap().eligible_for_offline_rust_replay);
    }
    #[test]
    fn mutable_tag_denied() {
        let mut v = good();
        v.docker_image_digest = Some("rust:latest".into());
        assert!(!assess(&v).unwrap().eligible_for_offline_rust_replay);
    }
    #[test]
    fn image_not_cached() {
        let mut v = good();
        v.image_offline_verified = false;
        assert!(!assess(&v).unwrap().eligible_for_offline_rust_replay);
    }
    #[test]
    fn source_writes_denied() {
        let mut v = good();
        v.source_readonly = false;
        assert!(!assess(&v).unwrap().eligible_for_offline_rust_replay);
    }
    #[test]
    fn network_denied() {
        let mut v = good();
        v.network_disabled = false;
        assert!(!assess(&v).unwrap().eligible_for_offline_rust_replay);
    }
    #[test]
    fn log_command_denied() {
        let mut v = good();
        v.untrusted_job_log_commands_used = true;
        assert!(!assess(&v).unwrap().eligible_for_offline_rust_replay);
    }
    #[test]
    fn create_only() {
        let v = assess(&good()).unwrap();
        let p = std::env::temp_dir().join(format!("sapphon204-{}.json", std::process::id()));
        let _ = std::fs::remove_file(&p);
        write_new(&p, &v).unwrap();
        assert_eq!(write_new(&p, &v).unwrap_err().0, "OFFLINE204_EXISTS");
        std::fs::remove_file(p).unwrap();
    }
}
