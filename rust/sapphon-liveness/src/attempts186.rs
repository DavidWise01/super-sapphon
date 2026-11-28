//! SAPPHON-186: exhaustive page/attempt qualification of owned runner metadata.
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
const SOURCE: &str = "ae117baf57dd18ca3d4adade9700705faff9db1c";
fn sha(b: &[u8]) -> String {
    hex::encode(Sha256::digest(b))
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Input {
    pub source_sha: String,
    pub run_id: u64,
    pub run_attempt: u32,
    pub artifact_run_id: u64,
    pub artifact_attempt: u32,
    pub job_run_id: u64,
    pub job_attempt: u32,
    pub run_pages_exhausted: bool,
    pub job_pages_exhausted: bool,
    pub artifact_pages_exhausted: bool,
    pub required_job_count: u32,
    pub required_artifact_count: u32,
    pub original_zip_present: bool,
    pub summary_identity_verified: bool,
    pub unsupported_authority: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Finding {
    pub schema: String,
    pub input_sha256: String,
    pub source_owned_consistent: bool,
    pub blockers: Vec<String>,
    pub independent_custody_authenticated: bool,
    pub recovery_authorized: bool,
    pub lock_cleared: bool,
    pub decision: String,
}
pub fn assess(i: &Input) -> Result<Finding, Error> {
    let mut bad = Vec::new();
    if i.source_sha != SOURCE {
        bad.push("SOURCE_MISMATCH".to_owned());
    }
    if i.run_id == 0
        || i.run_attempt == 0
        || i.job_run_id == 0
        || i.job_attempt == 0
        || i.artifact_run_id == 0
        || i.artifact_attempt == 0
    {
        bad.push("RUN_IDENTITY".into());
    }
    if !i.run_pages_exhausted || !i.job_pages_exhausted || !i.artifact_pages_exhausted {
        bad.push("INCOMPLETE_PAGE_SEARCH".into());
    }
    if i.required_job_count != 1 {
        bad.push("REQUIRED_JOB_NOT_UNIQUE".into());
    }
    if i.required_artifact_count != 1 {
        bad.push("REQUIRED_ARTIFACT_NOT_UNIQUE".into());
    }
    if i.run_id != i.job_run_id || i.run_attempt != i.job_attempt {
        bad.push("JOB_ATTEMPT_MISMATCH".into());
    }
    if i.run_id != i.artifact_run_id || i.run_attempt != i.artifact_attempt {
        bad.push("ARTIFACT_ATTEMPT_MISMATCH".into());
    }
    if !i.original_zip_present || !i.summary_identity_verified {
        bad.push("ZIP_IDENTITY_NOT_PROVEN".into());
    }
    if i.unsupported_authority {
        bad.push("UNSUPPORTED_AUTHORITY".into());
    }
    bad.sort();
    bad.dedup();
    let bytes = serde_json::to_vec(i).map_err(|_| Error("ATTEMPT186_ENCODING"))?;
    Ok(Finding {
        schema: "sapphon-186-rust-attempts-v1".into(),
        input_sha256: sha(&bytes),
        source_owned_consistent: bad.is_empty(),
        blockers: bad,
        independent_custody_authenticated: false,
        recovery_authorized: false,
        lock_cleared: false,
        decision: "EXHAUSTIVE_ATTEMPT_ARTIFACT_HOLD".into(),
    })
}
pub fn write_new(path: &Path, f: &Finding) -> Result<String, Error> {
    if f.schema != "sapphon-186-rust-attempts-v1"
        || f.decision != "EXHAUSTIVE_ATTEMPT_ARTIFACT_HOLD"
        || f.independent_custody_authenticated
        || f.recovery_authorized
        || f.lock_cleared
    {
        return Err(Error("ATTEMPT186_AUTHORITY"));
    }
    let bytes = serde_json::to_vec(f).map_err(|_| Error("ATTEMPT186_ENCODING"))?;
    let mut handle = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)
        .map_err(|_| Error("ATTEMPT186_EXISTS"))?;
    handle
        .write_all(&bytes)
        .map_err(|_| Error("ATTEMPT186_WRITE"))?;
    handle.sync_all().map_err(|_| Error("ATTEMPT186_SYNC"))?;
    File::open(path.parent().ok_or(Error("ATTEMPT186_PARENT"))?)
        .and_then(|d| d.sync_all())
        .map_err(|_| Error("ATTEMPT186_DIRSYNC"))?;
    Ok(sha(&bytes))
}
#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> Input {
        Input {
            source_sha: SOURCE.into(),
            run_id: 185,
            run_attempt: 2,
            job_run_id: 185,
            job_attempt: 2,
            artifact_run_id: 185,
            artifact_attempt: 2,
            run_pages_exhausted: true,
            job_pages_exhausted: true,
            artifact_pages_exhausted: true,
            required_job_count: 1,
            required_artifact_count: 1,
            original_zip_present: true,
            summary_identity_verified: true,
            unsupported_authority: false,
        }
    }
    #[test]
    fn matching_owned_attempt_still_hold() {
        let f = assess(&fixture()).unwrap();
        assert!(f.source_owned_consistent && !f.recovery_authorized);
    }
    #[test]
    fn prior_attempt_zip_denied() {
        let mut x = fixture();
        x.artifact_attempt = 1;
        assert!(!assess(&x).unwrap().source_owned_consistent);
    }
    #[test]
    fn incomplete_artifact_page_denied() {
        let mut x = fixture();
        x.artifact_pages_exhausted = false;
        assert!(!assess(&x).unwrap().source_owned_consistent);
    }
    #[test]
    fn duplicate_artifact_denied() {
        let mut x = fixture();
        x.required_artifact_count = 2;
        assert!(!assess(&x).unwrap().source_owned_consistent);
    }
    #[test]
    fn missing_zip_denied() {
        let mut x = fixture();
        x.original_zip_present = false;
        assert!(!assess(&x).unwrap().source_owned_consistent);
    }
    #[test]
    fn forged_authority_denied() {
        let mut x = fixture();
        x.unsupported_authority = true;
        assert!(!assess(&x).unwrap().source_owned_consistent);
    }
    #[test]
    fn create_only() {
        let f = assess(&fixture()).unwrap();
        let p = std::env::temp_dir().join(format!("sapphon186-{}.json", std::process::id()));
        let _ = std::fs::remove_file(&p);
        write_new(&p, &f).unwrap();
        assert_eq!(write_new(&p, &f).unwrap_err().0, "ATTEMPT186_EXISTS");
        std::fs::remove_file(p).unwrap();
    }
}
