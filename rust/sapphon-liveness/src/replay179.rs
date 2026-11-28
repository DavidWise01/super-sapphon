//! SAPPHON-179: bounded provenance-bound failure replay; no arbitrary execution.
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
const SOURCE: &str = "71931a8602229cecad921297aabe633e810fb211";
const REQUIRED: [&str; 3] = [
    "Python regression diagnostics",
    "Rust compilation and inherited regression tests",
    "Recheck historical frozen source digests",
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
    pub run_id: u64,
    pub attempt: u32,
    pub completed: bool,
    pub unique_job: bool,
    pub parent_conclusion: String,
    pub steps: Vec<Step>,
    pub claimed_external_authority: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Plan {
    pub schema: String,
    pub evidence_sha256: String,
    pub replay_categories: Vec<String>,
    pub blockers: Vec<String>,
    pub commands_executed: bool,
    pub independent_custody: bool,
    pub global_anti_rollback: bool,
    pub recovery_authorized: bool,
    pub lock_cleared: bool,
    pub decision: String,
}
pub fn classify(x: &Input) -> Result<Plan, Error> {
    if x.run_id == 0 || x.attempt == 0 || x.steps.len() > 100 {
        return Err(Error("REPLAY179_ID"));
    }
    let mut blockers = vec![];
    let mut replay = vec![];
    if x.source_sha != SOURCE {
        blockers.push("WRONG_SOURCE".to_string());
    }
    if !x.completed {
        blockers.push("INCOMPLETE_RUN".into());
    }
    if !x.unique_job {
        blockers.push("DUPLICATE_JOB".into());
    }
    if x.claimed_external_authority {
        blockers.push("FORGED_AUTHORITY".into());
    }
    for (i, name) in REQUIRED.iter().enumerate() {
        let found = x
            .steps
            .iter()
            .filter(|s| s.name == *name)
            .collect::<Vec<_>>();
        if found.len() != 1 {
            blockers.push(format!("INVALID_STEP_{}", i));
            continue;
        }
        match found[0].conclusion.as_str() {
            "failure" | "cancelled" | "timed_out" => replay.push((*name).to_string()),
            "success" => {}
            _ => blockers.push(format!("UNRESOLVED_STEP_{}", i)),
        }
    }
    if !replay.is_empty() && x.parent_conclusion == "success" {
        blockers.push("PARENT_CHILD_CONTRADICTION".into());
    }
    if replay.is_empty() && x.parent_conclusion != "success" {
        blockers.push("FAILED_PARENT_NO_REPLAY".into());
    }
    if !blockers.is_empty() {
        replay.clear();
    }
    blockers.sort();
    let encoded = serde_json::to_vec(x).map_err(|_| Error("REPLAY179_JSON"))?;
    Ok(Plan {
        schema: "sapphon-179-provenance-replay-rust-v1".into(),
        evidence_sha256: digest(&encoded),
        replay_categories: replay,
        blockers,
        commands_executed: false,
        independent_custody: false,
        global_anti_rollback: false,
        recovery_authorized: false,
        lock_cleared: false,
        decision: "PROVENANCE_BOUND_REPLAY_HOLD".into(),
    })
}
pub fn write_new(path: &Path, p: &Plan) -> Result<String, Error> {
    if p.schema != "sapphon-179-provenance-replay-rust-v1"
        || p.decision != "PROVENANCE_BOUND_REPLAY_HOLD"
        || p.commands_executed
        || p.independent_custody
        || p.global_anti_rollback
        || p.recovery_authorized
        || p.lock_cleared
    {
        return Err(Error("REPLAY179_AUTHORITY"));
    }
    let data = serde_json::to_vec(p).map_err(|_| Error("REPLAY179_JSON"))?;
    let mut f = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)
        .map_err(|_| Error("REPLAY179_EXISTS"))?;
    f.write_all(&data).map_err(|_| Error("REPLAY179_WRITE"))?;
    f.sync_all().map_err(|_| Error("REPLAY179_SYNC"))?;
    File::open(path.parent().ok_or(Error("REPLAY179_PARENT"))?)
        .and_then(|d| d.sync_all())
        .map_err(|_| Error("REPLAY179_DIRSYNC"))?;
    Ok(digest(&data))
}
#[cfg(test)]
mod tests {
    use super::*;
    fn failed() -> Input {
        Input {
            source_sha: SOURCE.into(),
            run_id: 178,
            attempt: 1,
            completed: true,
            unique_job: true,
            parent_conclusion: "failure".into(),
            steps: REQUIRED
                .iter()
                .enumerate()
                .map(|(i, n)| Step {
                    name: (*n).into(),
                    conclusion: if i == 1 { "failure" } else { "success" }.into(),
                })
                .collect(),
            claimed_external_authority: false,
        }
    }
    #[test]
    fn rust_failure_replay_without_actuation() {
        let p = classify(&failed()).unwrap();
        assert_eq!(p.replay_categories, vec![REQUIRED[1]]);
        assert!(!p.commands_executed && !p.recovery_authorized);
    }
    #[test]
    fn wrong_source_blocks() {
        let mut x = failed();
        x.source_sha = "a".repeat(40);
        assert!(classify(&x).unwrap().replay_categories.is_empty());
    }
    #[test]
    fn parent_conflict_blocks() {
        let mut x = failed();
        x.parent_conclusion = "success".into();
        assert!(classify(&x).unwrap().replay_categories.is_empty());
    }
    #[test]
    fn forged_authority_blocks() {
        let mut x = failed();
        x.claimed_external_authority = true;
        assert!(classify(&x).unwrap().replay_categories.is_empty());
    }
    #[test]
    fn missing_step_blocks() {
        let mut x = failed();
        x.steps.pop();
        assert!(classify(&x).unwrap().replay_categories.is_empty());
    }
    #[test]
    fn output_is_create_only() {
        let p = classify(&failed()).unwrap();
        let path = std::env::temp_dir().join(format!("sapphon179-{}.json", std::process::id()));
        let _ = std::fs::remove_file(&path);
        write_new(&path, &p).unwrap();
        assert_eq!(write_new(&path, &p).unwrap_err().0, "REPLAY179_EXISTS");
        std::fs::remove_file(path).unwrap();
    }
}
