//! SAPPHON-193: exact SAPPHON-192 observed-run triage, no recovery authority.
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
const SOURCE: &str = "9c3734c78bab40690ca1f5f9b65e29362193a1bf";
const REQUIRED: [&str; 4] = [
    "Run eight-bound Python source regression inventory",
    "Compile inherited Rust and run exact Phase XVIII regressions",
    "Verify all 188 immutable historical files",
    "Build canonical checked-out final source freeze",
];
fn digest(b: &[u8]) -> String {
    hex::encode(Sha256::digest(b))
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Step {
    pub name: String,
    pub conclusion: String,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Input {
    pub source_sha: String,
    pub run_id: Option<u64>,
    pub attempt: Option<u32>,
    pub completed: bool,
    pub job_unique: bool,
    pub pages_exhausted: bool,
    pub parent_success: bool,
    pub failed_child: bool,
    pub steps: Vec<Step>,
    pub external_authority_claim: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Finding {
    pub schema: String,
    pub input_sha256: String,
    pub failures: Vec<String>,
    pub source_owned_critical_steps_pass: bool,
    pub independently_authenticated_witnesses: u8,
    pub authenticated_utc: bool,
    pub global_anti_rollback_authenticated: bool,
    pub recovery_authorized: bool,
    pub lock_cleared: bool,
    pub decision: String,
}
pub fn assess(v: &Input) -> Result<Finding, Error> {
    if v.steps.len() > 200 {
        return Err(Error("TRIAGE193_STEP_LIMIT"));
    }
    let mut bad = Vec::new();
    if v.source_sha != SOURCE {
        bad.push("SOURCE_CONFLICT".into());
    }
    if v.run_id.is_none_or(|n| n == 0) || v.attempt.is_none_or(|n| n == 0) {
        bad.push("RUN_IDENTITY".into());
    }
    if !v.completed {
        bad.push("RUN_INCOMPLETE".into());
    }
    if !v.job_unique {
        bad.push("REQUIRED_JOB_NOT_UNIQUE".into());
    }
    if !v.pages_exhausted {
        bad.push("INCOMPLETE_JOB_LISTING".into());
    }
    if !v.parent_success {
        bad.push("RUN_NOT_SUCCESS".into());
    }
    if v.failed_child {
        bad.push("FAILED_CHILD".into());
    }
    if v.external_authority_claim {
        bad.push("FORGED_AUTHORITY".into());
    }
    for (i, name) in REQUIRED.iter().enumerate() {
        let hits = v
            .steps
            .iter()
            .filter(|s| s.name == *name)
            .collect::<Vec<_>>();
        if hits.len() != 1 {
            bad.push(format!("STEP_NOT_UNIQUE:{i}"));
        } else if hits[0].conclusion != "success" {
            bad.push(format!("STEP_NOT_SUCCESS:{i}"));
        }
    }
    bad.sort();
    bad.dedup();
    let bytes = serde_json::to_vec(v).map_err(|_| Error("TRIAGE193_ENCODING"))?;
    Ok(Finding {
        schema: "sapphon-193-rust-runner-triage-v1".into(),
        input_sha256: digest(&bytes),
        source_owned_critical_steps_pass: bad.is_empty(),
        failures: bad,
        independently_authenticated_witnesses: 0,
        authenticated_utc: false,
        global_anti_rollback_authenticated: false,
        recovery_authorized: false,
        lock_cleared: false,
        decision: "PHASE_XIX_OBSERVED_RUNNER_REPAIR_HOLD".into(),
    })
}
pub fn write_new(path: &Path, r: &Finding) -> Result<String, Error> {
    if r.schema != "sapphon-193-rust-runner-triage-v1"
        || r.decision != "PHASE_XIX_OBSERVED_RUNNER_REPAIR_HOLD"
        || r.independently_authenticated_witnesses != 0
        || r.authenticated_utc
        || r.global_anti_rollback_authenticated
        || r.recovery_authorized
        || r.lock_cleared
    {
        return Err(Error("TRIAGE193_AUTHORITY"));
    }
    let bytes = serde_json::to_vec(r).map_err(|_| Error("TRIAGE193_ENCODING"))?;
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|_| Error("TRIAGE193_EXISTS"))?;
    f.write_all(&bytes).map_err(|_| Error("TRIAGE193_WRITE"))?;
    f.sync_all().map_err(|_| Error("TRIAGE193_FSYNC"))?;
    File::open(path.parent().ok_or(Error("TRIAGE193_PARENT"))?)
        .and_then(|d| d.sync_all())
        .map_err(|_| Error("TRIAGE193_DIRSYNC"))?;
    Ok(digest(&bytes))
}
#[cfg(test)]
mod tests {
    use super::*;
    fn good() -> Input {
        Input {
            source_sha: SOURCE.into(),
            run_id: Some(192),
            attempt: Some(1),
            completed: true,
            job_unique: true,
            pages_exhausted: true,
            parent_success: true,
            failed_child: false,
            external_authority_claim: false,
            steps: REQUIRED
                .iter()
                .map(|s| Step {
                    name: (*s).into(),
                    conclusion: "success".into(),
                })
                .collect(),
        }
    }
    #[test]
    fn owned_green_still_hold() {
        let f = assess(&good()).unwrap();
        assert!(f.source_owned_critical_steps_pass && !f.recovery_authorized);
    }
    #[test]
    fn missing_runner_denied() {
        let mut x = good();
        x.run_id = None;
        assert!(!assess(&x).unwrap().source_owned_critical_steps_pass);
    }
    #[test]
    fn pagination_denied() {
        let mut x = good();
        x.pages_exhausted = false;
        assert!(!assess(&x).unwrap().source_owned_critical_steps_pass);
    }
    #[test]
    fn failed_rust_denied() {
        let mut x = good();
        x.steps[1].conclusion = "failure".into();
        assert!(!assess(&x).unwrap().source_owned_critical_steps_pass);
    }
    #[test]
    fn duplicate_step_denied() {
        let mut x = good();
        x.steps.push(x.steps[0].clone());
        assert!(!assess(&x).unwrap().source_owned_critical_steps_pass);
    }
    #[test]
    fn failed_child_denied() {
        let mut x = good();
        x.failed_child = true;
        assert!(!assess(&x).unwrap().source_owned_critical_steps_pass);
    }
    #[test]
    fn forged_external_denied() {
        let mut x = good();
        x.external_authority_claim = true;
        assert!(!assess(&x).unwrap().source_owned_critical_steps_pass);
    }
    #[test]
    fn create_only() {
        let f = assess(&good()).unwrap();
        let p = std::env::temp_dir().join(format!("sapphon193-{}.json", std::process::id()));
        let _ = std::fs::remove_file(&p);
        write_new(&p, &f).unwrap();
        assert_eq!(write_new(&p, &f).unwrap_err().0, "TRIAGE193_EXISTS");
        std::fs::remove_file(p).unwrap();
    }
}
