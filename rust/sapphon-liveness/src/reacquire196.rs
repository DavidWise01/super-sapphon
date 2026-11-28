//! SAPPHON-196: fresh original-byte digest parity, never custody promotion.
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
const SOURCE: &str = "c5496fcaaa28ce37d9dcb43e69223b6566d1a1a3";
fn hex64(x: &str) -> bool {
    x.len() == 64
        && x.bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}
fn digest(b: &[u8]) -> String {
    hex::encode(Sha256::digest(b))
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Input {
    pub source_sha: String,
    pub original_run_id: u64,
    pub original_attempt: u32,
    pub report_run_attempt_matches: bool,
    pub artifact_attempt_matches: bool,
    pub job_attempt_matches: bool,
    pub listing_exhausted: bool,
    pub original_log_observed: bool,
    pub original_zip_observed: bool,
    pub artifact_expired: bool,
    pub reported_log_sha256: String,
    pub reported_zip_sha256: String,
    pub fresh_log_sha256: Option<String>,
    pub fresh_zip_sha256: Option<String>,
    pub external_custody_claim: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Finding {
    pub schema: String,
    pub input_sha256: String,
    pub observed_log_hash_match: bool,
    pub observed_zip_hash_match: bool,
    pub state: String,
    pub blockers: Vec<String>,
    pub original_bytes_reacquired: bool,
    pub independent_witnesses: u8,
    pub authenticated_utc: bool,
    pub global_anti_rollback_authenticated: bool,
    pub recovery_authorized: bool,
    pub lock_cleared: bool,
    pub decision: String,
}
pub fn assess(x: &Input) -> Result<Finding, Error> {
    let mut blockers = Vec::new();
    if x.source_sha != SOURCE || x.original_run_id == 0 || x.original_attempt == 0 {
        blockers.push("SOURCE_RUN_IDENTITY".into());
    }
    if !x.listing_exhausted
        || !x.report_run_attempt_matches
        || !x.artifact_attempt_matches
        || !x.job_attempt_matches
    {
        blockers.push("INCOMPLETE_ATTEMPT_ANCESTRY".into());
    }
    if x.artifact_expired {
        blockers.push("ARTIFACT_EXPIRED".into());
    }
    if !hex64(&x.reported_log_sha256) || !hex64(&x.reported_zip_sha256) {
        blockers.push("PRIOR_DIGESTS_INVALID".into());
    }
    let log_ok = x.original_log_observed && x.fresh_log_sha256.as_deref().is_some_and(hex64);
    let zip_ok = x.original_zip_observed && x.fresh_zip_sha256.as_deref().is_some_and(hex64);
    if !log_ok {
        blockers.push("ORIGINAL_JOB_LOG_NOT_REACQUIRED".into());
    }
    if !zip_ok {
        blockers.push("ORIGINAL_ZIP_NOT_REACQUIRED".into());
    }
    if x.external_custody_claim {
        blockers.push("UNSUPPORTED_EXTERNAL_WITNESS".into());
    }
    let matchlog = log_ok && x.fresh_log_sha256.as_deref() == Some(x.reported_log_sha256.as_str());
    let matchzip = zip_ok && x.fresh_zip_sha256.as_deref() == Some(x.reported_zip_sha256.as_str());
    let state = if !blockers.is_empty() {
        "REACQUISITION_INCOMPLETE"
    } else if matchlog && matchzip {
        "GITHUB_OWNED_HASH_MATCH"
    } else {
        "GITHUB_OWNED_READBACK_EQUIVOCATION"
    };
    blockers.sort();
    blockers.dedup();
    let encoded = serde_json::to_vec(x).map_err(|_| Error("REACQUIRE196_JSON"))?;
    Ok(Finding {
        schema: "sapphon-196-rust-parity-v1".into(),
        input_sha256: digest(&encoded),
        observed_log_hash_match: matchlog,
        observed_zip_hash_match: matchzip,
        state: state.into(),
        blockers,
        original_bytes_reacquired: log_ok && zip_ok,
        independent_witnesses: 0,
        authenticated_utc: false,
        global_anti_rollback_authenticated: false,
        recovery_authorized: false,
        lock_cleared: false,
        decision: "GITHUB_OWNED_READBACK_HOLD".into(),
    })
}
pub fn write_new(path: &Path, r: &Finding) -> Result<String, Error> {
    if r.schema != "sapphon-196-rust-parity-v1"
        || r.decision != "GITHUB_OWNED_READBACK_HOLD"
        || r.independent_witnesses != 0
        || r.authenticated_utc
        || r.global_anti_rollback_authenticated
        || r.recovery_authorized
        || r.lock_cleared
    {
        return Err(Error("REACQUIRE196_AUTHORITY"));
    }
    let encoded = serde_json::to_vec(r).map_err(|_| Error("REACQUIRE196_JSON"))?;
    let mut f = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)
        .map_err(|_| Error("REACQUIRE196_EXISTS"))?;
    f.write_all(&encoded)
        .map_err(|_| Error("REACQUIRE196_WRITE"))?;
    f.sync_all().map_err(|_| Error("REACQUIRE196_SYNC"))?;
    File::open(path.parent().ok_or(Error("REACQUIRE196_PARENT"))?)
        .and_then(|d| d.sync_all())
        .map_err(|_| Error("REACQUIRE196_DIRSYNC"))?;
    Ok(digest(&encoded))
}
#[cfg(test)]
mod tests {
    use super::*;
    fn good() -> Input {
        Input {
            source_sha: SOURCE.into(),
            original_run_id: 193,
            original_attempt: 2,
            report_run_attempt_matches: true,
            artifact_attempt_matches: true,
            job_attempt_matches: true,
            listing_exhausted: true,
            original_log_observed: true,
            original_zip_observed: true,
            artifact_expired: false,
            reported_log_sha256: "a".repeat(64),
            reported_zip_sha256: "b".repeat(64),
            fresh_log_sha256: Some("a".repeat(64)),
            fresh_zip_sha256: Some("b".repeat(64)),
            external_custody_claim: false,
        }
    }
    #[test]
    fn matching_byte_claims_only_owned() {
        let f = assess(&good()).unwrap();
        assert_eq!(f.state, "GITHUB_OWNED_HASH_MATCH");
        assert!(!f.recovery_authorized);
    }
    #[test]
    fn changed_log_is_equivocation() {
        let mut x = good();
        x.fresh_log_sha256 = Some("c".repeat(64));
        assert_eq!(
            assess(&x).unwrap().state,
            "GITHUB_OWNED_READBACK_EQUIVOCATION"
        );
    }
    #[test]
    fn changed_zip_is_equivocation() {
        let mut x = good();
        x.fresh_zip_sha256 = Some("c".repeat(64));
        assert_eq!(
            assess(&x).unwrap().state,
            "GITHUB_OWNED_READBACK_EQUIVOCATION"
        );
    }
    #[test]
    fn missing_log_is_unobserved() {
        let mut x = good();
        x.original_log_observed = false;
        assert_eq!(assess(&x).unwrap().state, "REACQUISITION_INCOMPLETE");
    }
    #[test]
    fn expired_artifact_is_not_equivocation() {
        let mut x = good();
        x.artifact_expired = true;
        assert_eq!(assess(&x).unwrap().state, "REACQUISITION_INCOMPLETE");
    }
    #[test]
    fn wrong_attempt_is_not_match() {
        let mut x = good();
        x.job_attempt_matches = false;
        assert_eq!(assess(&x).unwrap().state, "REACQUISITION_INCOMPLETE");
    }
    #[test]
    fn forged_external_claim_is_blocked() {
        let mut x = good();
        x.external_custody_claim = true;
        assert!(!assess(&x).unwrap().blockers.is_empty());
    }
    #[test]
    fn create_only() {
        let f = assess(&good()).unwrap();
        let p = std::env::temp_dir().join(format!("sapphon196-{}.json", std::process::id()));
        let _ = std::fs::remove_file(&p);
        write_new(&p, &f).unwrap();
        assert_eq!(write_new(&p, &f).unwrap_err().0, "REACQUIRE196_EXISTS");
        std::fs::remove_file(p).unwrap();
    }
}
