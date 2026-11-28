//! SAPPHON-202: exact original hosted failure ancestry and reviewed replay identifiers.
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
const SOURCE: &str = "b5ddf7f7d7d51a282c0109276dc37310f56eb240";
fn valid(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}
fn digest(b: &[u8]) -> String {
    hex::encode(Sha256::digest(b))
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Step {
    pub id: String,
    pub outcome: String,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Input {
    pub source_sha: String,
    pub run_id: Option<u64>,
    pub attempt: Option<u32>,
    pub complete_run_and_job_pages: bool,
    pub complete_artifact_pages: bool,
    pub exact_job_unique: bool,
    pub job_attempt_matches: bool,
    pub archive_attempt_matches: bool,
    pub archive_summary_matches_steps: bool,
    pub original_log_sha256: Option<String>,
    pub original_zip_sha256: Option<String>,
    pub steps: Vec<Step>,
    pub untrusted_log_commands_present: bool,
    pub external_custody_claim: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Finding {
    pub schema: String,
    pub input_sha256: String,
    pub blockers: Vec<String>,
    pub observed_failure_steps: Vec<String>,
    pub plan_only_replay_ids: Vec<String>,
    pub original_bytes_complete: bool,
    pub replay_executed: bool,
    pub independent_witnesses: u8,
    pub authenticated_utc: bool,
    pub global_anti_rollback_authenticated: bool,
    pub recovery_authorized: bool,
    pub lock_cleared: bool,
    pub decision: String,
}
const REQUIRED: [&str; 4] = ["python", "rust", "frozen", "acquisition"];
pub fn assess(x: &Input) -> Result<Finding, Error> {
    if x.steps.len() > 64 {
        return Err(Error("REPLAY202_STEP_LIMIT"));
    }
    let mut bad = Vec::new();
    if x.source_sha != SOURCE || x.run_id.is_none_or(|v| v == 0) || x.attempt.is_none_or(|v| v == 0)
    {
        bad.push("SOURCE_RUN_IDENTITY".to_owned());
    }
    if !x.complete_run_and_job_pages || !x.complete_artifact_pages {
        bad.push("PAGINATION_INCOMPLETE".into());
    }
    if !x.exact_job_unique
        || !x.job_attempt_matches
        || !x.archive_attempt_matches
        || !x.archive_summary_matches_steps
    {
        bad.push("ORIGINAL_JOB_ARCHIVE_ANCESTRY".into());
    }
    let complete = x.original_log_sha256.as_deref().is_some_and(valid)
        && x.original_zip_sha256.as_deref().is_some_and(valid);
    if !complete {
        bad.push("ORIGINAL_BYTES_NOT_OBSERVED".into());
    }
    if x.external_custody_claim {
        bad.push("FORGED_CUSTODY".into());
    }
    let mut failures = Vec::new();
    for required in REQUIRED {
        let found: Vec<&Step> = x.steps.iter().filter(|s| s.id == required).collect();
        if found.len() != 1 {
            bad.push(format!("CRITICAL_STEP_NOT_UNIQUE:{required}"));
            continue;
        }
        let state = found[0].outcome.as_str();
        if !["success", "failure", "cancelled", "timed_out", "skipped"].contains(&state) {
            bad.push(format!("INVALID_STEP_OUTCOME:{required}"));
        } else if state != "success" {
            failures.push(required.to_owned());
        }
    }
    bad.sort();
    bad.dedup();
    let replay = if bad.is_empty() {
        failures
            .iter()
            .filter(|s| ["python", "rust", "frozen"].contains(&s.as_str()))
            .cloned()
            .collect()
    } else {
        Vec::new()
    };
    let raw = serde_json::to_vec(x).map_err(|_| Error("REPLAY202_ENCODING"))?;
    Ok(Finding {
        schema: "sapphon-202-rust-replay-v1".into(),
        input_sha256: digest(&raw),
        blockers: bad,
        observed_failure_steps: failures,
        plan_only_replay_ids: replay,
        original_bytes_complete: complete,
        replay_executed: false,
        independent_witnesses: 0,
        authenticated_utc: false,
        global_anti_rollback_authenticated: false,
        recovery_authorized: false,
        lock_cleared: false,
        decision: "PHASE_XX_REPRODUCIBLE_FAILURE_HOLD".into(),
    })
}
pub fn write_new(path: &Path, r: &Finding) -> Result<String, Error> {
    if r.schema != "sapphon-202-rust-replay-v1"
        || r.decision != "PHASE_XX_REPRODUCIBLE_FAILURE_HOLD"
        || r.replay_executed
        || r.independent_witnesses != 0
        || r.authenticated_utc
        || r.global_anti_rollback_authenticated
        || r.recovery_authorized
        || r.lock_cleared
    {
        return Err(Error("REPLAY202_AUTHORITY"));
    }
    let bytes = serde_json::to_vec(r).map_err(|_| Error("REPLAY202_ENCODING"))?;
    let mut f = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)
        .map_err(|_| Error("REPLAY202_EXISTS"))?;
    f.write_all(&bytes).map_err(|_| Error("REPLAY202_WRITE"))?;
    f.sync_all().map_err(|_| Error("REPLAY202_SYNC"))?;
    File::open(path.parent().ok_or(Error("REPLAY202_PARENT"))?)
        .and_then(|d| d.sync_all())
        .map_err(|_| Error("REPLAY202_DIRSYNC"))?;
    Ok(digest(&bytes))
}
#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> Input {
        Input {
            source_sha: SOURCE.into(),
            run_id: Some(201),
            attempt: Some(2),
            complete_run_and_job_pages: true,
            complete_artifact_pages: true,
            exact_job_unique: true,
            job_attempt_matches: true,
            archive_attempt_matches: true,
            archive_summary_matches_steps: true,
            original_log_sha256: Some("a".repeat(64)),
            original_zip_sha256: Some("b".repeat(64)),
            untrusted_log_commands_present: false,
            external_custody_claim: false,
            steps: REQUIRED
                .iter()
                .map(|v| Step {
                    id: (*v).into(),
                    outcome: "success".into(),
                })
                .collect(),
        }
    }
    #[test]
    fn source_owned_green_still_hold() {
        let x = assess(&fixture()).unwrap();
        assert!(x.original_bytes_complete && !x.recovery_authorized);
    }
    #[test]
    fn failed_rust_produces_plan_only() {
        let mut v = fixture();
        v.steps[1].outcome = "failure".into();
        let x = assess(&v).unwrap();
        assert_eq!(x.plan_only_replay_ids, vec!["rust"]);
        assert!(!x.replay_executed);
    }
    #[test]
    fn untrusted_log_no_execution() {
        let mut v = fixture();
        v.untrusted_log_commands_present = true;
        let x = assess(&v).unwrap();
        assert!(!x.replay_executed);
    }
    #[test]
    fn missing_log_blocks_plan() {
        let mut v = fixture();
        v.original_log_sha256 = None;
        v.steps[1].outcome = "failure".into();
        assert!(assess(&v).unwrap().plan_only_replay_ids.is_empty());
    }
    #[test]
    fn inconsistent_attempt_blocks_plan() {
        let mut v = fixture();
        v.archive_attempt_matches = false;
        v.steps[1].outcome = "failure".into();
        assert!(assess(&v).unwrap().plan_only_replay_ids.is_empty());
    }
    #[test]
    fn no_duplicate_critical_steps() {
        let mut v = fixture();
        v.steps.push(v.steps[0].clone());
        assert!(!assess(&v).unwrap().blockers.is_empty());
    }
    #[test]
    fn false_custody_denied() {
        let mut v = fixture();
        v.external_custody_claim = true;
        assert!(!assess(&v).unwrap().blockers.is_empty());
    }
    #[test]
    fn acquisition_failure_not_replay() {
        let mut v = fixture();
        v.steps[3].outcome = "failure".into();
        assert!(assess(&v).unwrap().plan_only_replay_ids.is_empty());
    }
    #[test]
    fn create_only() {
        let r = assess(&fixture()).unwrap();
        let p = std::env::temp_dir().join(format!("sapphon202-{}.json", std::process::id()));
        let _ = std::fs::remove_file(&p);
        write_new(&p, &r).unwrap();
        assert_eq!(write_new(&p, &r).unwrap_err().0, "REPLAY202_EXISTS");
        std::fs::remove_file(p).unwrap();
    }
}
