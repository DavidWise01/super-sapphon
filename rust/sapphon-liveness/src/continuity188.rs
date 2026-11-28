//! SAPPHON-188: source-owned prior ledger import and exact tip continuity.
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
const SOURCE: &str = "f404ed9e4c60558d82116cf86348304f17daed81";
fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
fn sha64(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|x| x.is_ascii_digit() || (b'a'..=b'f').contains(&x))
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Input {
    pub prior_source_sha: String,
    pub prior_run_id: u64,
    pub prior_attempt: u32,
    pub prior_artifact_id: u64,
    pub original_zip_sha256: String,
    pub imported_ledger_sha256: String,
    pub claimed_prior_tip: String,
    pub computed_prior_tip: String,
    pub imported_count: u64,
    pub chain_verified: bool,
    pub prior_summary_matches_attempt: bool,
    pub archive_complete: bool,
    pub independent_custody_claimed: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Finding {
    pub schema: String,
    pub source_owned_continuity: bool,
    pub transition_sha256: String,
    pub blockers: Vec<String>,
    pub authenticated_utc: bool,
    pub independent_custody_authenticated: bool,
    pub global_anti_rollback_authenticated: bool,
    pub recovery_authorized: bool,
    pub lock_cleared: bool,
    pub decision: String,
}
pub fn assess(x: &Input) -> Result<Finding, Error> {
    let mut bad = Vec::new();
    if x.prior_source_sha != SOURCE {
        bad.push("SOURCE_MISMATCH".to_owned());
    }
    if x.prior_run_id == 0 || x.prior_attempt == 0 || x.prior_artifact_id == 0 {
        bad.push("IDENTITY_INVALID".into());
    }
    for (name, h) in [
        ("ZIP", &x.original_zip_sha256),
        ("LEDGER", &x.imported_ledger_sha256),
        ("TIP", &x.claimed_prior_tip),
        ("COMPUTED", &x.computed_prior_tip),
    ] {
        if !sha64(h) {
            bad.push(format!("INVALID_HASH_{name}"));
        }
    }
    if x.claimed_prior_tip != x.computed_prior_tip {
        bad.push("PRIOR_TIP_CONFLICT".into());
    }
    if !x.chain_verified || x.imported_count == 0 {
        bad.push("PRIOR_CHAIN_UNVERIFIED".into());
    }
    if !x.prior_summary_matches_attempt {
        bad.push("ATTEMPT_SUBSTITUTION".into());
    }
    if !x.archive_complete {
        bad.push("ARCHIVE_INCOMPLETE".into());
    }
    if x.independent_custody_claimed {
        bad.push("UNSUPPORTED_AUTHORITY".into());
    }
    bad.sort();
    bad.dedup();
    let bytes = serde_json::to_vec(x).map_err(|_| Error("IMPORT188_ENCODING"))?;
    Ok(Finding {
        schema: "sapphon-188-rust-continuity-v1".into(),
        source_owned_continuity: bad.is_empty(),
        transition_sha256: digest(&bytes),
        blockers: bad,
        authenticated_utc: false,
        independent_custody_authenticated: false,
        global_anti_rollback_authenticated: false,
        recovery_authorized: false,
        lock_cleared: false,
        decision: "CROSS_RUN_IMPORT_HOLD".into(),
    })
}
pub fn write_new(path: &Path, f: &Finding) -> Result<String, Error> {
    if f.schema != "sapphon-188-rust-continuity-v1"
        || f.decision != "CROSS_RUN_IMPORT_HOLD"
        || f.authenticated_utc
        || f.independent_custody_authenticated
        || f.global_anti_rollback_authenticated
        || f.recovery_authorized
        || f.lock_cleared
    {
        return Err(Error("IMPORT188_AUTHORITY"));
    }
    let bytes = serde_json::to_vec(f).map_err(|_| Error("IMPORT188_ENCODING"))?;
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)
        .map_err(|_| Error("IMPORT188_EXISTS"))?;
    file.write_all(&bytes)
        .map_err(|_| Error("IMPORT188_WRITE"))?;
    file.sync_all().map_err(|_| Error("IMPORT188_SYNC"))?;
    File::open(path.parent().ok_or(Error("IMPORT188_PARENT"))?)
        .and_then(|d| d.sync_all())
        .map_err(|_| Error("IMPORT188_DIRSYNC"))?;
    Ok(digest(&bytes))
}
#[cfg(test)]
mod tests {
    use super::*;
    fn valid() -> Input {
        Input {
            prior_source_sha: SOURCE.into(),
            prior_run_id: 187,
            prior_attempt: 2,
            prior_artifact_id: 188,
            original_zip_sha256: "a".repeat(64),
            imported_ledger_sha256: "b".repeat(64),
            claimed_prior_tip: "c".repeat(64),
            computed_prior_tip: "c".repeat(64),
            imported_count: 1,
            chain_verified: true,
            prior_summary_matches_attempt: true,
            archive_complete: true,
            independent_custody_claimed: false,
        }
    }
    #[test]
    fn valid_owned_chain_still_hold() {
        let r = assess(&valid()).unwrap();
        assert!(r.source_owned_continuity && !r.recovery_authorized);
    }
    #[test]
    fn changed_tip_rejected() {
        let mut x = valid();
        x.claimed_prior_tip = "d".repeat(64);
        assert!(!assess(&x).unwrap().source_owned_continuity);
    }
    #[test]
    fn missing_archive_rejected() {
        let mut x = valid();
        x.archive_complete = false;
        assert!(!assess(&x).unwrap().source_owned_continuity);
    }
    #[test]
    fn no_chain_rejected() {
        let mut x = valid();
        x.chain_verified = false;
        assert!(!assess(&x).unwrap().source_owned_continuity);
    }
    #[test]
    fn wrong_attempt_rejected() {
        let mut x = valid();
        x.prior_summary_matches_attempt = false;
        assert!(!assess(&x).unwrap().source_owned_continuity);
    }
    #[test]
    fn forged_custody_rejected() {
        let mut x = valid();
        x.independent_custody_claimed = true;
        assert!(!assess(&x).unwrap().source_owned_continuity);
    }
    #[test]
    fn create_only() {
        let f = assess(&valid()).unwrap();
        let p = std::env::temp_dir().join(format!("sapphon188-{}.json", std::process::id()));
        let _ = std::fs::remove_file(&p);
        write_new(&p, &f).unwrap();
        assert_eq!(write_new(&p, &f).unwrap_err().0, "IMPORT188_EXISTS");
        std::fs::remove_file(p).unwrap();
    }
}
