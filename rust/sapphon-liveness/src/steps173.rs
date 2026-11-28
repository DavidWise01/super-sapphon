//! SAPPHON-173 — exact critical-step qualification observation. No actuation.
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
const REQUIRED: [&str; 3] = [
    "Execute targeted Python regression suites",
    "Run Rust all-target check and inherited test suites",
    "Recheck all 188 protected historical file hashes",
];
fn hash(b: &[u8]) -> String {
    hex::encode(Sha256::digest(b))
}
fn sha40(s: &str) -> bool {
    s.len() == 40
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
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
    pub expected_sha: String,
    pub observed_sha: String,
    pub run_id: u64,
    pub attempt: u32,
    pub completed: bool,
    pub job_success: bool,
    pub required_job_unique: bool,
    pub steps: Vec<Step>,
    pub failed_child_step: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Finding {
    pub schema: String,
    pub source_owned_critical_pass: bool,
    pub issues: Vec<String>,
    pub input_digest: String,
    pub npm_lock_qualified: bool,
    pub external_custody_authenticated: bool,
    pub global_anti_rollback_authenticated: bool,
    pub recovery_authorized: bool,
    pub lock_cleared: bool,
    pub decision: String,
}
pub fn assess(x: &Input) -> Result<Finding, Error> {
    if !sha40(&x.expected_sha)
        || !sha40(&x.observed_sha)
        || x.run_id == 0
        || x.attempt == 0
        || x.steps.len() > 128
    {
        return Err(Error("STEP173_INPUT"));
    }
    let mut issues = Vec::new();
    let mut found = BTreeSet::new();
    if x.expected_sha != x.observed_sha {
        issues.push("SOURCE_MISMATCH".to_owned());
    }
    if !x.completed {
        issues.push("RUN_INCOMPLETE".to_owned());
    }
    if !x.job_success {
        issues.push("JOB_NOT_SUCCESS".to_owned());
    }
    if !x.required_job_unique {
        issues.push("REQUIRED_JOB_NOT_UNIQUE".to_owned());
    }
    if x.failed_child_step {
        issues.push("FAILED_CHILD_STEP".to_owned());
    }
    for s in &x.steps {
        if !found.insert(s.name.as_str()) {
            issues.push("DUPLICATE_STEP".to_owned());
        }
    }
    for name in REQUIRED {
        if !x
            .steps
            .iter()
            .any(|s| s.name == name && s.conclusion == "success")
        {
            issues.push(format!("REQUIRED_STEP_UNVERIFIED:{name}"));
        }
    }
    if x.steps
        .iter()
        .any(|s| ["failure", "cancelled", "timed_out"].contains(&s.conclusion.as_str()))
    {
        issues.push("FAILED_STEP_OBSERVED".to_owned());
    }
    issues.sort();
    issues.dedup();
    let input = serde_json::to_vec(x).map_err(|_| Error("STEP173_ENCODING"))?;
    Ok(Finding {
        schema: "sapphon-173-critical-steps-rust-v1".into(),
        source_owned_critical_pass: issues.is_empty(),
        issues,
        input_digest: hash(&input),
        npm_lock_qualified: false,
        external_custody_authenticated: false,
        global_anti_rollback_authenticated: false,
        recovery_authorized: false,
        lock_cleared: false,
        decision: "CRITICAL_STEPS_HOLD".into(),
    })
}
pub fn write_new(path: &Path, finding: &Finding) -> Result<String, Error> {
    if finding.schema != "sapphon-173-critical-steps-rust-v1"
        || finding.decision != "CRITICAL_STEPS_HOLD"
        || finding.npm_lock_qualified
        || finding.external_custody_authenticated
        || finding.global_anti_rollback_authenticated
        || finding.recovery_authorized
        || finding.lock_cleared
    {
        return Err(Error("STEP173_AUTHORITY"));
    }
    let body = serde_json::to_vec(finding).map_err(|_| Error("STEP173_ENCODING"))?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|_| Error("STEP173_EXISTS"))?;
    file.write_all(&body).map_err(|_| Error("STEP173_WRITE"))?;
    file.sync_all().map_err(|_| Error("STEP173_FSYNC"))?;
    File::open(path.parent().ok_or(Error("STEP173_PARENT"))?)
        .and_then(|p| p.sync_all())
        .map_err(|_| Error("STEP173_DIRSYNC"))?;
    Ok(hash(&body))
}
#[cfg(test)]
mod tests {
    use super::*;
    fn base() -> Input {
        Input {
            expected_sha: "a".repeat(40),
            observed_sha: "a".repeat(40),
            run_id: 173,
            attempt: 1,
            completed: true,
            job_success: true,
            required_job_unique: true,
            steps: REQUIRED
                .iter()
                .map(|s| Step {
                    name: (*s).into(),
                    conclusion: "success".into(),
                })
                .collect(),
            failed_child_step: false,
        }
    }
    #[test]
    fn nominal_pass_still_hold() {
        let r = assess(&base()).unwrap();
        assert!(r.source_owned_critical_pass && !r.recovery_authorized);
    }
    #[test]
    fn skipped_rust_blocks() {
        let mut a = base();
        a.steps[1].conclusion = "skipped".into();
        assert!(!assess(&a).unwrap().source_owned_critical_pass);
    }
    #[test]
    fn absent_hash_step_blocks() {
        let mut a = base();
        a.steps.pop();
        assert!(!assess(&a).unwrap().source_owned_critical_pass);
    }
    #[test]
    fn duplicate_step_blocks() {
        let mut a = base();
        a.steps.push(a.steps[0].clone());
        assert!(!assess(&a).unwrap().source_owned_critical_pass);
    }
    #[test]
    fn wrong_commit_blocks() {
        let mut a = base();
        a.observed_sha = "b".repeat(40);
        assert!(!assess(&a).unwrap().source_owned_critical_pass);
    }
    #[test]
    fn failed_child_blocks() {
        let mut a = base();
        a.failed_child_step = true;
        assert!(!assess(&a).unwrap().source_owned_critical_pass);
    }
    #[test]
    fn create_only() {
        let r = assess(&base()).unwrap();
        let path = std::env::temp_dir().join(format!("sapphon173-{}.json", std::process::id()));
        let _ = std::fs::remove_file(&path);
        write_new(&path, &r).unwrap();
        assert_eq!(write_new(&path, &r).unwrap_err().0, "STEP173_EXISTS");
        std::fs::remove_file(path).unwrap();
    }
}
