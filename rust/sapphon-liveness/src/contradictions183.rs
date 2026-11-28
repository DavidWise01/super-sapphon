//! SAPPHON-183: cross-source contradiction adjudication, always HOLD.
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
const SOURCE: &str = "bcc82842d0ebc090db6fb3b32c978a75db3cf9fd";
fn digest(v: &[u8]) -> String {
    hex::encode(Sha256::digest(v))
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Input {
    pub source_sha: String,
    pub run_id: Option<u64>,
    pub attempt: Option<u32>,
    pub python: String,
    pub rust: String,
    pub frozen: String,
    pub reported_source_pass: bool,
    pub acquisition_observed: bool,
    pub acquisition_step: String,
    pub crossfile_consistent: bool,
    pub crossfile_complete: bool,
    pub crossfile_step: String,
    pub exact_job_observed: bool,
    pub exact_job_matches_run: bool,
    pub external_custody_claimed: bool,
    pub recovery_claimed: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Finding {
    pub schema: String,
    pub input_sha256: String,
    pub source_tests_consistent: bool,
    pub complete_owned_evidence: bool,
    pub blockers: Vec<String>,
    pub independent_custody_authenticated: bool,
    pub recovery_authorized: bool,
    pub lock_cleared: bool,
    pub decision: String,
}
pub fn adjudicate(v: &Input) -> Result<Finding, Error> {
    let mut bad = Vec::new();
    if v.source_sha != SOURCE {
        bad.push("WRONG_SOURCE_SHA".to_owned());
    }
    if v.run_id.is_none_or(|n| n == 0) || v.attempt.is_none_or(|n| n == 0) {
        bad.push("RUN_IDENTITY".to_owned());
    }
    for (key, val) in [
        ("PYTHON", &v.python),
        ("RUST", &v.rust),
        ("FROZEN", &v.frozen),
        ("ACQUISITION", &v.acquisition_step),
        ("CROSSFILE", &v.crossfile_step),
    ] {
        if ![
            "success",
            "failure",
            "skipped",
            "cancelled",
            "timed_out",
            "not_observed",
        ]
        .contains(&val.as_str())
        {
            bad.push(format!("UNKNOWN_OUTCOME:{key}"));
        }
    }
    let passes = [&v.python, &v.rust, &v.frozen]
        .iter()
        .all(|s| s.as_str() == "success");
    if passes != v.reported_source_pass {
        bad.push("FALSE_SOURCE_PASS".to_owned());
    }
    if v.acquisition_observed && (v.acquisition_step != "success") {
        bad.push("ACQUISITION_STEP_CONFLICT".into());
    }
    if !v.acquisition_observed && v.acquisition_step == "success" {
        bad.push("ACQUISITION_FALSE_SUCCESS".into());
    }
    if v.crossfile_complete && !v.crossfile_consistent {
        bad.push("COMPLETE_WITHOUT_CONSISTENCY".into());
    }
    if v.crossfile_consistent && !v.acquisition_observed {
        bad.push("CROSSFILE_WITHOUT_ACQUISITION".into());
    }
    if v.crossfile_consistent && v.crossfile_step != "success" {
        bad.push("CROSSFILE_STEP_CONFLICT".into());
    }
    if v.exact_job_observed && !v.exact_job_matches_run {
        bad.push("JOB_RUN_CONTRADICTION".into());
    }
    if v.external_custody_claimed || v.recovery_claimed {
        bad.push("FORGED_AUTHORITY".into());
    }
    bad.sort();
    bad.dedup();
    let bytes = serde_json::to_vec(v).map_err(|_| Error("CON183_ENCODING"))?;
    Ok(Finding {
        schema: "sapphon-183-rust-contradictions-v1".into(),
        input_sha256: digest(&bytes),
        source_tests_consistent: passes
            && !bad
                .iter()
                .any(|s| s == "FALSE_SOURCE_PASS" || s.starts_with("UNKNOWN_OUTCOME")),
        complete_owned_evidence: bad.is_empty()
            && passes
            && v.acquisition_observed
            && v.crossfile_complete
            && v.exact_job_observed
            && v.exact_job_matches_run,
        blockers: bad,
        independent_custody_authenticated: false,
        recovery_authorized: false,
        lock_cleared: false,
        decision: "COMPLETED_RUN_CONTRADICTION_HOLD".into(),
    })
}
pub fn write_new(path: &Path, r: &Finding) -> Result<String, Error> {
    if r.schema != "sapphon-183-rust-contradictions-v1"
        || r.decision != "COMPLETED_RUN_CONTRADICTION_HOLD"
        || r.independent_custody_authenticated
        || r.recovery_authorized
        || r.lock_cleared
    {
        return Err(Error("CON183_AUTHORITY"));
    }
    let bytes = serde_json::to_vec(r).map_err(|_| Error("CON183_ENCODING"))?;
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)
        .map_err(|_| Error("CON183_EXISTS"))?;
    file.write_all(&bytes).map_err(|_| Error("CON183_WRITE"))?;
    file.sync_all().map_err(|_| Error("CON183_SYNC"))?;
    File::open(path.parent().ok_or(Error("CON183_PARENT"))?)
        .and_then(|d| d.sync_all())
        .map_err(|_| Error("CON183_DIRSYNC"))?;
    Ok(digest(&bytes))
}
#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> Input {
        Input {
            source_sha: SOURCE.into(),
            run_id: Some(182),
            attempt: Some(1),
            python: "success".into(),
            rust: "success".into(),
            frozen: "success".into(),
            reported_source_pass: true,
            acquisition_observed: true,
            acquisition_step: "success".into(),
            crossfile_consistent: true,
            crossfile_complete: true,
            crossfile_step: "success".into(),
            exact_job_observed: true,
            exact_job_matches_run: true,
            external_custody_claimed: false,
            recovery_claimed: false,
        }
    }
    #[test]
    fn source_consistent_still_hold() {
        let r = adjudicate(&fixture()).unwrap();
        assert!(r.complete_owned_evidence && !r.recovery_authorized);
    }
    #[test]
    fn false_pass_rejected() {
        let mut x = fixture();
        x.rust = "failure".into();
        assert!(adjudicate(&x)
            .unwrap()
            .blockers
            .contains(&"FALSE_SOURCE_PASS".into()));
    }
    #[test]
    fn missing_acquisition_rejected() {
        let mut x = fixture();
        x.acquisition_observed = false;
        assert!(!adjudicate(&x).unwrap().complete_owned_evidence);
    }
    #[test]
    fn crossfile_without_acquisition_rejected() {
        let mut x = fixture();
        x.acquisition_observed = false;
        assert!(adjudicate(&x)
            .unwrap()
            .blockers
            .contains(&"CROSSFILE_WITHOUT_ACQUISITION".into()));
    }
    #[test]
    fn job_run_mismatch_rejected() {
        let mut x = fixture();
        x.exact_job_matches_run = false;
        assert!(!adjudicate(&x).unwrap().complete_owned_evidence);
    }
    #[test]
    fn forged_recovery_rejected() {
        let mut x = fixture();
        x.recovery_claimed = true;
        assert!(!adjudicate(&x).unwrap().blockers.is_empty());
    }
    #[test]
    fn output_is_create_only() {
        let r = adjudicate(&fixture()).unwrap();
        let p = std::env::temp_dir().join(format!("sapphon183-{}.json", std::process::id()));
        let _ = std::fs::remove_file(&p);
        write_new(&p, &r).unwrap();
        assert_eq!(write_new(&p, &r).unwrap_err().0, "CON183_EXISTS");
        std::fs::remove_file(p).unwrap();
    }
}
