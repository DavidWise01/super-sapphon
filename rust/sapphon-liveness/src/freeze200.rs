//! SAPPHON-200: Phase XIX exact eight-Rust-module source-design freeze.
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
const PATHS: [&str; 8] = [
    "rust/sapphon-liveness/src/triage193.rs",
    "rust/sapphon-liveness/src/acquire194.rs",
    "rust/sapphon-liveness/src/crossverify195.rs",
    "rust/sapphon-liveness/src/reacquire196.rs",
    "rust/sapphon-liveness/src/monotonic197.rs",
    "rust/sapphon-liveness/src/import198.rs",
    "rust/sapphon-liveness/src/retention199.rs",
    "rust/sapphon-liveness/src/freeze200.rs",
];
fn digest(b: &[u8]) -> String {
    hex::encode(Sha256::digest(b))
}
fn hex40(s: &str) -> bool {
    s.len() == 40
        && s.bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}
fn hex64(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Source {
    pub bound: u16,
    pub path: String,
    pub bytes: u64,
    pub sha256: String,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Input {
    pub head: String,
    pub sources: Vec<Source>,
    pub python: String,
    pub rust: String,
    pub frozen: String,
    pub retention: String,
    pub pages: String,
    pub browser: String,
    pub independently_verified_retention: bool,
    pub independently_enrolled_witnesses: u8,
    pub unsupported_deletion_claim: bool,
    pub unsupported_recovery_claim: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Finding {
    pub schema: String,
    pub phase: u8,
    pub source_design_complete: bool,
    pub inventory_sha256: String,
    pub blockers: Vec<String>,
    pub hosted_runner_success_independently_verified: bool,
    pub independently_authenticated_witnesses: u8,
    pub authenticated_utc: bool,
    pub global_anti_rollback_authenticated: bool,
    pub recovery_authorized: bool,
    pub lock_cleared: bool,
    pub decision: String,
}
pub fn assess(x: &Input) -> Result<Finding, Error> {
    if !hex40(&x.head) || x.sources.len() != 8 {
        return Err(Error("FREEZE200_HEAD_OR_COUNT"));
    }
    let mut files = x.sources.clone();
    files.sort_by_key(|f| f.bound);
    for (i, f) in files.iter().enumerate() {
        if f.bound != 193 + i as u16 || f.path != PATHS[i] || f.bytes == 0 || !hex64(&f.sha256) {
            return Err(Error("FREEZE200_CANONICAL_SOURCE"));
        }
    }
    for outcome in [
        &x.python,
        &x.rust,
        &x.frozen,
        &x.retention,
        &x.pages,
        &x.browser,
    ] {
        if ![
            "success",
            "failure",
            "cancelled",
            "timed_out",
            "skipped",
            "not_observed",
        ]
        .contains(&outcome.as_str())
        {
            return Err(Error("FREEZE200_OUTCOME"));
        }
    }
    let mut blockers = Vec::new();
    for (label, status) in [
        ("PYTHON", &x.python),
        ("RUST", &x.rust),
        ("FROZEN", &x.frozen),
        ("RETENTION", &x.retention),
        ("PAGES", &x.pages),
        ("BROWSER", &x.browser),
    ] {
        if status != "success" {
            blockers.push(format!("{label}:{status}"));
        }
    }
    if x.independently_verified_retention
        || x.independently_enrolled_witnesses != 0
        || x.unsupported_deletion_claim
        || x.unsupported_recovery_claim
    {
        blockers.push("UNSUPPORTED_EXTERNAL_AUTHORITY".into());
    }
    blockers.push("OWNED_SOURCE_NOT_INDEPENDENT_CUSTODY".into());
    blockers.sort();
    blockers.dedup();
    let bytes = serde_json::to_vec(&files).map_err(|_| Error("FREEZE200_ENCODING"))?;
    Ok(Finding {
        schema: "sapphon-200-rust-final-freeze-v1".into(),
        phase: 19,
        source_design_complete: true,
        inventory_sha256: digest(&bytes),
        blockers,
        hosted_runner_success_independently_verified: false,
        independently_authenticated_witnesses: 0,
        authenticated_utc: false,
        global_anti_rollback_authenticated: false,
        recovery_authorized: false,
        lock_cleared: false,
        decision: "PHASE_XIX_FINAL_SOURCE_FREEZE_HOLD".into(),
    })
}
pub fn write_new(path: &Path, r: &Finding) -> Result<String, Error> {
    if r.schema != "sapphon-200-rust-final-freeze-v1"
        || r.phase != 19
        || r.decision != "PHASE_XIX_FINAL_SOURCE_FREEZE_HOLD"
        || r.hosted_runner_success_independently_verified
        || r.independently_authenticated_witnesses != 0
        || r.authenticated_utc
        || r.global_anti_rollback_authenticated
        || r.recovery_authorized
        || r.lock_cleared
    {
        return Err(Error("FREEZE200_AUTHORITY"));
    }
    let bytes = serde_json::to_vec(r).map_err(|_| Error("FREEZE200_ENCODING"))?;
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)
        .map_err(|_| Error("FREEZE200_EXISTS"))?;
    file.write_all(&bytes)
        .map_err(|_| Error("FREEZE200_WRITE"))?;
    file.sync_all().map_err(|_| Error("FREEZE200_SYNC"))?;
    File::open(path.parent().ok_or(Error("FREEZE200_PARENT"))?)
        .and_then(|d| d.sync_all())
        .map_err(|_| Error("FREEZE200_DIRSYNC"))?;
    Ok(digest(&bytes))
}
#[cfg(test)]
mod tests {
    use super::*;
    fn sample() -> Input {
        Input {
            head: "a".repeat(40),
            sources: PATHS
                .iter()
                .enumerate()
                .map(|(i, p)| Source {
                    bound: 193 + i as u16,
                    path: (*p).into(),
                    bytes: 100,
                    sha256: "b".repeat(64),
                })
                .collect(),
            python: "not_observed".into(),
            rust: "not_observed".into(),
            frozen: "not_observed".into(),
            retention: "not_observed".into(),
            pages: "not_observed".into(),
            browser: "not_observed".into(),
            independently_verified_retention: false,
            independently_enrolled_witnesses: 0,
            unsupported_deletion_claim: false,
            unsupported_recovery_claim: false,
        }
    }
    #[test]
    fn eight_sources_and_hold() {
        let v = assess(&sample()).unwrap();
        assert!(v.source_design_complete && !v.recovery_authorized);
    }
    #[test]
    fn wrong_module_path_rejected() {
        let mut x = sample();
        x.sources[2].path = "wrong.rs".into();
        assert_eq!(assess(&x).unwrap_err().0, "FREEZE200_CANONICAL_SOURCE");
    }
    #[test]
    fn truncated_hash_rejected() {
        let mut x = sample();
        x.sources[7].sha256 = "abc".into();
        assert_eq!(assess(&x).unwrap_err().0, "FREEZE200_CANONICAL_SOURCE");
    }
    #[test]
    fn missing_source_rejected() {
        let mut x = sample();
        x.sources.pop();
        assert_eq!(assess(&x).unwrap_err().0, "FREEZE200_HEAD_OR_COUNT");
    }
    #[test]
    fn malformed_outcome_rejected() {
        let mut x = sample();
        x.rust = "CERTIFIED".into();
        assert_eq!(assess(&x).unwrap_err().0, "FREEZE200_OUTCOME");
    }
    #[test]
    fn all_tests_green_still_hold() {
        let mut x = sample();
        x.python = "success".into();
        x.rust = "success".into();
        x.frozen = "success".into();
        assert!(!assess(&x).unwrap().recovery_authorized);
    }
    #[test]
    fn false_external_witness_rejected() {
        let mut x = sample();
        x.independently_enrolled_witnesses = 1;
        assert!(assess(&x)
            .unwrap()
            .blockers
            .iter()
            .any(|f| f == "UNSUPPORTED_EXTERNAL_AUTHORITY"));
    }
    #[test]
    fn forged_deletion_rejected() {
        let mut x = sample();
        x.unsupported_deletion_claim = true;
        assert!(!assess(&x).unwrap().recovery_authorized);
    }
    #[test]
    fn create_only() {
        let r = assess(&sample()).unwrap();
        let p = std::env::temp_dir().join(format!("sapphon200-{}.json", std::process::id()));
        let _ = std::fs::remove_file(&p);
        write_new(&p, &r).unwrap();
        assert_eq!(write_new(&p, &r).unwrap_err().0, "FREEZE200_EXISTS");
        std::fs::remove_file(p).unwrap();
    }
}
