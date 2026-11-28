//! SAPPHON-172 — predecessor runtime reconciliation, never actuation.
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
fn sha(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
fn hex40(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Observation {
    pub source_sha: String,
    pub run_id: Option<u64>,
    pub attempt: Option<u32>,
    pub complete: bool,
    pub required_job_present: bool,
    pub run_success: bool,
    pub failed_step_count: usize,
    pub log_readback_observed: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Decision {
    pub schema: String,
    pub source_match: bool,
    pub source_diagnostic_consistent: bool,
    pub blockers: Vec<String>,
    pub input_sha256: String,
    pub committed_lock_qualified: bool,
    pub external_custody_authenticated: bool,
    pub recovery_authorized: bool,
    pub lock_cleared: bool,
    pub decision: String,
}
pub fn reconcile(expected_sha: &str, o: &Observation) -> Result<Decision, Error> {
    if !hex40(expected_sha) || !hex40(&o.source_sha) || o.failed_step_count > 10000 {
        return Err(Error("RECON172_FIELDS"));
    }
    let matching = o.source_sha == expected_sha;
    let mut blockers = vec![];
    if !matching {
        blockers.push("SOURCE_MISMATCH".to_owned());
    }
    if o.run_id.is_none_or(|n| n == 0) || o.attempt.is_none_or(|n| n == 0) {
        blockers.push("RUN_IDENTITY_MISSING".to_owned());
    }
    if !o.complete {
        blockers.push("RUN_INCOMPLETE".to_owned());
    }
    if !o.required_job_present {
        blockers.push("REQUIRED_JOB_MISSING".to_owned());
    }
    if !o.run_success {
        blockers.push("RUN_NOT_SUCCESS".to_owned());
    }
    if o.failed_step_count > 0 {
        blockers.push("FAILED_STEP_OBSERVED".to_owned());
    }
    if !o.log_readback_observed {
        blockers.push("JOB_READBACK_MISSING".to_owned());
    }
    blockers.sort();
    let payload = serde_json::to_vec(o).map_err(|_| Error("RECON172_ENCODING"))?;
    Ok(Decision {
        schema: "sapphon-172-run-reconciliation-v1".into(),
        source_match: matching,
        source_diagnostic_consistent: blockers.is_empty(),
        blockers,
        input_sha256: sha(&payload),
        committed_lock_qualified: false,
        external_custody_authenticated: false,
        recovery_authorized: false,
        lock_cleared: false,
        decision: "RUNTIME_RECONCILIATION_HOLD".into(),
    })
}
pub fn write_new(path: &Path, d: &Decision) -> Result<String, Error> {
    if d.schema != "sapphon-172-run-reconciliation-v1"
        || d.decision != "RUNTIME_RECONCILIATION_HOLD"
        || d.committed_lock_qualified
        || d.external_custody_authenticated
        || d.recovery_authorized
        || d.lock_cleared
    {
        return Err(Error("RECON172_AUTHORITY"));
    }
    let b = serde_json::to_vec(d).map_err(|_| Error("RECON172_ENCODING"))?;
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|_| Error("RECON172_EXISTS"))?;
    f.write_all(&b).map_err(|_| Error("RECON172_WRITE"))?;
    f.sync_all().map_err(|_| Error("RECON172_FSYNC"))?;
    File::open(path.parent().ok_or(Error("RECON172_PARENT"))?)
        .and_then(|dir| dir.sync_all())
        .map_err(|_| Error("RECON172_DIRSYNC"))?;
    Ok(sha(&b))
}
#[cfg(test)]
mod tests {
    use super::*;
    fn example() -> Observation {
        Observation {
            source_sha: "a".repeat(40),
            run_id: Some(172),
            attempt: Some(1),
            complete: true,
            required_job_present: true,
            run_success: true,
            failed_step_count: 0,
            log_readback_observed: true,
        }
    }
    #[test]
    fn success_still_hold() {
        let o = reconcile(&"a".repeat(40), &example()).unwrap();
        assert!(o.source_diagnostic_consistent);
        assert!(!o.recovery_authorized && !o.committed_lock_qualified);
    }
    #[test]
    fn wrong_sha_rejected() {
        assert!(
            !reconcile(&"b".repeat(40), &example())
                .unwrap()
                .source_diagnostic_consistent
        );
    }
    #[test]
    fn failed_child_step_blocks_green_parent() {
        let mut o = example();
        o.failed_step_count = 1;
        assert!(reconcile(&"a".repeat(40), &o)
            .unwrap()
            .blockers
            .contains(&"FAILED_STEP_OBSERVED".into()));
    }
    #[test]
    fn absent_run_id_rejected() {
        let mut o = example();
        o.run_id = None;
        assert!(
            !reconcile(&"a".repeat(40), &o)
                .unwrap()
                .source_diagnostic_consistent
        );
    }
    #[test]
    fn missing_job_blocks() {
        let mut o = example();
        o.required_job_present = false;
        assert!(
            !reconcile(&"a".repeat(40), &o)
                .unwrap()
                .source_diagnostic_consistent
        );
    }
    #[test]
    fn unobserved_log_blocks() {
        let mut o = example();
        o.log_readback_observed = false;
        assert!(
            !reconcile(&"a".repeat(40), &o)
                .unwrap()
                .source_diagnostic_consistent
        );
    }
    #[test]
    fn create_only_record() {
        let r = reconcile(&"a".repeat(40), &example()).unwrap();
        let p = std::env::temp_dir().join(format!("sapphon172-{}.json", std::process::id()));
        let _ = std::fs::remove_file(&p);
        write_new(&p, &r).unwrap();
        assert_eq!(write_new(&p, &r).unwrap_err().0, "RECON172_EXISTS");
        std::fs::remove_file(p).unwrap();
    }
}
