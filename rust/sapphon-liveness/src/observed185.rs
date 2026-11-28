//! SAPPHON-185: observed Phase XVII final runner diagnostics, authority HOLD.
#![cfg(target_os = "linux")]
use crate::Error;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs::{File, OpenOptions},
    io::Write,
    path::Path,
};
pub const AUTHORITY: &str = "HOLD";
const SOURCE: &str = "edb582df9db3873d2fe308d219ed30b412d1b06d";
const STEP: [&str; 4] = [
    "Run Phase XVII Python regression tests",
    "Rust all-target build and inherited tests",
    "Verify all 188 protected historical hashes",
    "Build exact eight-bound source freeze from real checkout",
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
    pub unique_job: bool,
    pub pages_exhausted: bool,
    pub parent_success: bool,
    pub failed_child: bool,
    pub steps: Vec<Step>,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Finding {
    pub schema: String,
    pub record_sha256: String,
    pub step_status: [String; 4],
    pub blockers: Vec<String>,
    pub source_owned_pass: bool,
    pub external_custody_authenticated: bool,
    pub global_anti_rollback_authenticated: bool,
    pub recovery_authorized: bool,
    pub lock_cleared: bool,
    pub decision: String,
}
pub fn assess(v: &Input) -> Result<Finding, Error> {
    if v.steps.len() > 200 {
        return Err(Error("OBS185_STEP_LIMIT"));
    }
    let mut bad = Vec::new();
    let mut status = std::array::from_fn(|_| "NOT_OBSERVED".to_owned());
    if v.source_sha != SOURCE {
        bad.push("SOURCE_CONFLICT".to_owned());
    }
    if v.run_id.is_none_or(|n| n == 0) || v.attempt.is_none_or(|n| n == 0) {
        bad.push("INVALID_RUN_ID".into());
    }
    if !v.completed {
        bad.push("RUN_INCOMPLETE".into());
    }
    if !v.unique_job {
        bad.push("JOB_NOT_UNIQUE".into());
    }
    if !v.pages_exhausted {
        bad.push("JOB_PAGES_NOT_EXHAUSTED".into());
    }
    if !v.parent_success {
        bad.push("RUN_NOT_SUCCESS".into());
    }
    if v.failed_child {
        bad.push("FAILED_CHILD_PRESENT".into());
    }
    let mut seen = BTreeSet::new();
    for s in &v.steps {
        if !seen.insert(s.name.as_str()) {
            bad.push("DUPLICATE_STEP".into());
        }
    }
    for (idx, name) in STEP.iter().enumerate() {
        let matches = v
            .steps
            .iter()
            .filter(|s| s.name.as_str() == *name)
            .collect::<Vec<_>>();
        if matches.len() != 1 {
            bad.push(format!("REQUIRED_STEP_NOT_UNIQUE:{idx}"));
            continue;
        }
        status[idx] = matches[0].conclusion.clone();
        if status[idx] != "success" {
            bad.push(format!("REQUIRED_STEP_NOT_SUCCESS:{idx}"));
        }
    }
    bad.sort();
    bad.dedup();
    let data = serde_json::to_vec(v).map_err(|_| Error("OBS185_ENCODING"))?;
    Ok(Finding {
        schema: "sapphon-185-rust-observed-v1".into(),
        record_sha256: digest(&data),
        source_owned_pass: bad.is_empty(),
        step_status: status,
        blockers: bad,
        external_custody_authenticated: false,
        global_anti_rollback_authenticated: false,
        recovery_authorized: false,
        lock_cleared: false,
        decision: "OBSERVED_FAILURE_ISOLATION_HOLD".into(),
    })
}
pub fn write_new(path: &Path, f: &Finding) -> Result<String, Error> {
    if f.schema != "sapphon-185-rust-observed-v1"
        || f.decision != "OBSERVED_FAILURE_ISOLATION_HOLD"
        || f.external_custody_authenticated
        || f.global_anti_rollback_authenticated
        || f.recovery_authorized
        || f.lock_cleared
    {
        return Err(Error("OBS185_AUTHORITY"));
    }
    let data = serde_json::to_vec(f).map_err(|_| Error("OBS185_ENCODING"))?;
    let mut handle = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)
        .map_err(|_| Error("OBS185_EXISTS"))?;
    handle.write_all(&data).map_err(|_| Error("OBS185_WRITE"))?;
    handle.sync_all().map_err(|_| Error("OBS185_FSYNC"))?;
    File::open(path.parent().ok_or(Error("OBS185_PARENT"))?)
        .and_then(|dir| dir.sync_all())
        .map_err(|_| Error("OBS185_DIRSYNC"))?;
    Ok(digest(&data))
}
#[cfg(test)]
mod tests {
    use super::*;
    fn good() -> Input {
        Input {
            source_sha: SOURCE.into(),
            run_id: Some(184),
            attempt: Some(1),
            completed: true,
            unique_job: true,
            pages_exhausted: true,
            parent_success: true,
            failed_child: false,
            steps: STEP
                .iter()
                .map(|n| Step {
                    name: (*n).into(),
                    conclusion: "success".into(),
                })
                .collect(),
        }
    }
    #[test]
    fn exact_owned_pass_still_hold() {
        let r = assess(&good()).unwrap();
        assert!(r.source_owned_pass && !r.recovery_authorized);
    }
    #[test]
    fn no_exhaustion_no_pass() {
        let mut x = good();
        x.pages_exhausted = false;
        assert!(!assess(&x).unwrap().source_owned_pass);
    }
    #[test]
    fn failed_rust_denies_pass() {
        let mut x = good();
        x.steps[1].conclusion = "failure".into();
        assert!(!assess(&x).unwrap().source_owned_pass);
    }
    #[test]
    fn missing_step_denies_pass() {
        let mut x = good();
        x.steps.pop();
        assert!(!assess(&x).unwrap().source_owned_pass);
    }
    #[test]
    fn wrong_sha_denies_pass() {
        let mut x = good();
        x.source_sha = "a".repeat(40);
        assert!(!assess(&x).unwrap().source_owned_pass);
    }
    #[test]
    fn forged_child_denies_pass() {
        let mut x = good();
        x.failed_child = true;
        assert!(!assess(&x).unwrap().source_owned_pass);
    }
    #[test]
    fn create_only_record() {
        let r = assess(&good()).unwrap();
        let p = std::env::temp_dir().join(format!("sapphon185-{}.json", std::process::id()));
        let _ = std::fs::remove_file(&p);
        write_new(&p, &r).unwrap();
        assert_eq!(write_new(&p, &r).unwrap_err().0, "OBS185_EXISTS");
        std::fs::remove_file(p).unwrap();
    }
}
