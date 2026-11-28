//! SAPPHON-178: independent source-diagnostic gate classification. Authority HOLD.
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
fn hash(v: &[u8]) -> String {
    hex::encode(Sha256::digest(v))
}
fn sha40(v: &str) -> bool {
    v.len() == 40
        && v.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
const REQUIRED: [&str; 3] = [
    "Python tests, including frozen-source status regressions",
    "Rust typecheck and inherited suites",
    "Recheck 188 immutable historical source files",
];
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
    pub run_id: Option<u64>,
    pub attempt: Option<u32>,
    pub complete: bool,
    pub expected_job_unique: bool,
    pub run_success: bool,
    pub failed_child: bool,
    pub steps: Vec<Step>,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Finding {
    pub schema: String,
    pub gate_outcomes: [String; 3],
    pub blockers: Vec<String>,
    pub source_owned_pass: bool,
    pub input_sha256: String,
    pub independent_custody: bool,
    pub global_anti_rollback: bool,
    pub recovery_authorized: bool,
    pub lock_cleared: bool,
    pub decision: String,
}
pub fn isolate(x: &Input) -> Result<Finding, Error> {
    if !sha40(&x.expected_sha) || !sha40(&x.observed_sha) || x.steps.len() > 128 {
        return Err(Error("FAIL178_FIELDS"));
    }
    let mut blockers = Vec::new();
    let mut gates = [
        "NOT_OBSERVED".into(),
        "NOT_OBSERVED".into(),
        "NOT_OBSERVED".into(),
    ];
    if x.expected_sha != x.observed_sha {
        blockers.push("SOURCE_MISMATCH".into());
    }
    if x.run_id.is_none_or(|v| v == 0) || x.attempt.is_none_or(|v| v == 0) {
        blockers.push("MISSING_RUN_ID".into());
    }
    if !x.complete {
        blockers.push("INCOMPLETE_RUN".into());
    }
    if !x.expected_job_unique {
        blockers.push("AMBIGUOUS_JOB".into());
    }
    if !x.run_success {
        blockers.push("RUN_NOT_SUCCESS".into());
    }
    if x.failed_child {
        blockers.push("FAILED_CHILD".into());
    }
    for (i, name) in REQUIRED.iter().enumerate() {
        let matches = x
            .steps
            .iter()
            .filter(|s| s.name.as_str() == *name)
            .collect::<Vec<_>>();
        gates[i] = match matches.len() {
            0 => "NOT_OBSERVED".into(),
            1 if matches[0].conclusion == "success" => "PASS".into(),
            1 => "FAIL_OR_INCOMPLETE".into(),
            _ => "DUPLICATE".into(),
        };
        if gates[i] != "PASS" {
            blockers.push(format!("GATE_{}:{}", i, gates[i]));
        }
    }
    if x.steps.iter().any(|s| s.conclusion != "success") {
        blockers.push("UNSUCCESSFUL_CHILD".into());
    }
    blockers.sort();
    blockers.dedup();
    let serialized = serde_json::to_vec(x).map_err(|_| Error("FAIL178_ENCODING"))?;
    Ok(Finding {
        schema: "sapphon-178-isolation-v1".into(),
        source_owned_pass: blockers.is_empty(),
        blockers,
        gate_outcomes: gates,
        input_sha256: hash(&serialized),
        independent_custody: false,
        global_anti_rollback: false,
        recovery_authorized: false,
        lock_cleared: false,
        decision: "FAILURE_ISOLATION_HOLD".into(),
    })
}
pub fn write_new(path: &Path, f: &Finding) -> Result<String, Error> {
    if f.schema != "sapphon-178-isolation-v1"
        || f.decision != "FAILURE_ISOLATION_HOLD"
        || f.independent_custody
        || f.global_anti_rollback
        || f.recovery_authorized
        || f.lock_cleared
    {
        return Err(Error("FAIL178_AUTHORITY"));
    }
    let b = serde_json::to_vec(f).map_err(|_| Error("FAIL178_ENCODING"))?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|_| Error("FAIL178_EXISTS"))?;
    file.write_all(&b).map_err(|_| Error("FAIL178_WRITE"))?;
    file.sync_all().map_err(|_| Error("FAIL178_FSYNC"))?;
    File::open(path.parent().ok_or(Error("FAIL178_PARENT"))?)
        .and_then(|dir| dir.sync_all())
        .map_err(|_| Error("FAIL178_DIRSYNC"))?;
    Ok(hash(&b))
}
#[cfg(test)]
mod tests {
    use super::*;
    fn ok() -> Input {
        Input {
            expected_sha: "a".repeat(40),
            observed_sha: "a".repeat(40),
            run_id: Some(178),
            attempt: Some(1),
            complete: true,
            expected_job_unique: true,
            run_success: true,
            failed_child: false,
            steps: REQUIRED
                .iter()
                .map(|name| Step {
                    name: (*name).into(),
                    conclusion: "success".into(),
                })
                .collect(),
        }
    }
    #[test]
    fn source_pass_is_not_recovery() {
        let f = isolate(&ok()).unwrap();
        assert!(f.source_owned_pass && !f.recovery_authorized);
    }
    #[test]
    fn rust_fail_is_separate() {
        let mut v = ok();
        v.steps[1].conclusion = "failure".into();
        let f = isolate(&v).unwrap();
        assert_eq!(f.gate_outcomes[0], "PASS");
        assert_eq!(f.gate_outcomes[1], "FAIL_OR_INCOMPLETE");
    }
    #[test]
    fn missing_file_check_blocks() {
        let mut v = ok();
        v.steps.pop();
        assert_eq!(isolate(&v).unwrap().gate_outcomes[2], "NOT_OBSERVED");
    }
    #[test]
    fn duplicate_step_blocks() {
        let mut v = ok();
        v.steps.push(v.steps[0].clone());
        assert!(!isolate(&v).unwrap().source_owned_pass);
    }
    #[test]
    fn wrong_sha_blocks() {
        let mut v = ok();
        v.observed_sha = "b".repeat(40);
        assert!(!isolate(&v).unwrap().source_owned_pass);
    }
    #[test]
    fn failed_child_blocks() {
        let mut v = ok();
        v.failed_child = true;
        assert!(!isolate(&v).unwrap().source_owned_pass);
    }
    #[test]
    fn create_only() {
        let f = isolate(&ok()).unwrap();
        let path = std::env::temp_dir().join(format!("sapphon178-{}.json", std::process::id()));
        let _ = std::fs::remove_file(&path);
        write_new(&path, &f).unwrap();
        assert_eq!(write_new(&path, &f).unwrap_err().0, "FAIL178_EXISTS");
        std::fs::remove_file(path).unwrap();
    }
}
