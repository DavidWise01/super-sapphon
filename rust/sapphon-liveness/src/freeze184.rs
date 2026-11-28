//! SAPPHON-184: final Phase XVII canonical source inventory; recovery HOLD.
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
const PATHS: [&str; 8] = [
    "rust/sapphon-liveness/src/evidence177.rs",
    "rust/sapphon-liveness/src/isolation178.rs",
    "rust/sapphon-liveness/src/replay179.rs",
    "rust/sapphon-liveness/src/binding180.rs",
    "rust/sapphon-liveness/src/archive181.rs",
    "rust/sapphon-liveness/src/crossfile182.rs",
    "rust/sapphon-liveness/src/contradictions183.rs",
    "rust/sapphon-liveness/src/freeze184.rs",
];
fn valid40(s: &str) -> bool {
    s.len() == 40
        && s.bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}
fn valid64(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}
fn digest(b: &[u8]) -> String {
    hex::encode(Sha256::digest(b))
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
    pub historical_188: String,
    pub original_archive: String,
    pub external_custody: String,
    pub unsupported_recovery_claim: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Finding {
    pub schema: String,
    pub phase: u8,
    pub source_design_complete: bool,
    pub source_inventory_sha256: String,
    pub blockers: Vec<String>,
    pub hosted_test_execution_verified: bool,
    pub npm_integrity_qualified: bool,
    pub independent_custody_authenticated: bool,
    pub global_anti_rollback: bool,
    pub recovery_authorized: bool,
    pub lock_cleared: bool,
    pub decision: String,
}
pub fn assess(x: &Input) -> Result<Finding, Error> {
    if !valid40(&x.head) || x.sources.len() != 8 {
        return Err(Error("FREEZE184_HEAD_OR_COUNT"));
    }
    let mut files = x.sources.clone();
    files.sort_by_key(|x| x.bound);
    let mut seen = BTreeSet::new();
    for (i, source) in files.iter().enumerate() {
        if source.bound != 177 + i as u16
            || source.path != PATHS[i]
            || source.bytes == 0
            || !valid64(&source.sha256)
            || !seen.insert(source.path.as_str())
        {
            return Err(Error("FREEZE184_CANONICAL_SOURCE"));
        }
    }
    let valid_states = [
        "success",
        "failure",
        "skipped",
        "cancelled",
        "timed_out",
        "not_observed",
    ];
    for val in [
        &x.python,
        &x.rust,
        &x.historical_188,
        &x.original_archive,
        &x.external_custody,
    ] {
        if !valid_states.contains(&val.as_str()) {
            return Err(Error("FREEZE184_OUTCOME"));
        }
    }
    let mut blockers = Vec::new();
    for (kind, status) in [
        ("PYTHON", &x.python),
        ("RUST", &x.rust),
        ("HISTORICAL_188", &x.historical_188),
        ("ARCHIVE", &x.original_archive),
        ("EXTERNAL_CUSTODY", &x.external_custody),
    ] {
        if status != "success" {
            blockers.push(format!("{kind}:{status}"));
        }
    }
    if x.unsupported_recovery_claim {
        blockers.push("UNSUPPORTED_AUTHORITY_CLAIM".into());
    }
    blockers.push("GITHUB_ACTIONS_PAGES_ONE_SOURCE_ANCESTRY".into());
    blockers.sort();
    let data = serde_json::to_vec(&files).map_err(|_| Error("FREEZE184_ENCODING"))?;
    Ok(Finding {
        schema: "sapphon-184-rust-final-freeze-v1".into(),
        phase: 17,
        source_design_complete: true,
        source_inventory_sha256: digest(&data),
        blockers,
        hosted_test_execution_verified: false,
        npm_integrity_qualified: false,
        independent_custody_authenticated: false,
        global_anti_rollback: false,
        recovery_authorized: false,
        lock_cleared: false,
        decision: "PHASE_XVII_DESIGN_FREEZE_QUALIFICATION_HOLD".into(),
    })
}
pub fn write_new(path: &Path, f: &Finding) -> Result<String, Error> {
    if f.schema != "sapphon-184-rust-final-freeze-v1"
        || f.decision != "PHASE_XVII_DESIGN_FREEZE_QUALIFICATION_HOLD"
        || f.hosted_test_execution_verified
        || f.npm_integrity_qualified
        || f.independent_custody_authenticated
        || f.global_anti_rollback
        || f.recovery_authorized
        || f.lock_cleared
    {
        return Err(Error("FREEZE184_AUTHORITY"));
    }
    let b = serde_json::to_vec(f).map_err(|_| Error("FREEZE184_ENCODING"))?;
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)
        .map_err(|_| Error("FREEZE184_EXISTS"))?;
    file.write_all(&b).map_err(|_| Error("FREEZE184_WRITE"))?;
    file.sync_all().map_err(|_| Error("FREEZE184_FSYNC"))?;
    File::open(path.parent().ok_or(Error("FREEZE184_PARENT"))?)
        .and_then(|d| d.sync_all())
        .map_err(|_| Error("FREEZE184_DIRSYNC"))?;
    Ok(digest(&b))
}
#[cfg(test)]
mod tests {
    use super::*;
    fn good() -> Input {
        Input {
            head: "a".repeat(40),
            sources: PATHS
                .iter()
                .enumerate()
                .map(|(i, p)| Source {
                    bound: 177 + i as u16,
                    path: (*p).into(),
                    bytes: 100,
                    sha256: "b".repeat(64),
                })
                .collect(),
            python: "not_observed".into(),
            rust: "not_observed".into(),
            historical_188: "not_observed".into(),
            original_archive: "not_observed".into(),
            external_custody: "not_observed".into(),
            unsupported_recovery_claim: false,
        }
    }
    #[test]
    fn eight_sources_still_hold() {
        let f = assess(&good()).unwrap();
        assert!(f.source_design_complete && !f.recovery_authorized);
    }
    #[test]
    fn substituted_path_rejected() {
        let mut x = good();
        x.sources[0].path = "rust/sapphon-liveness/src/other.rs".into();
        assert_eq!(assess(&x).unwrap_err().0, "FREEZE184_CANONICAL_SOURCE");
    }
    #[test]
    fn missing_source_rejected() {
        let mut x = good();
        x.sources.pop();
        assert_eq!(assess(&x).unwrap_err().0, "FREEZE184_HEAD_OR_COUNT");
    }
    #[test]
    fn wrong_digest_rejected() {
        let mut x = good();
        x.sources[1].sha256 = "bad".into();
        assert_eq!(assess(&x).unwrap_err().0, "FREEZE184_CANONICAL_SOURCE");
    }
    #[test]
    fn unsupported_outcome_rejected() {
        let mut x = good();
        x.rust = "PASS_CLAIM".into();
        assert_eq!(assess(&x).unwrap_err().0, "FREEZE184_OUTCOME");
    }
    #[test]
    fn green_owned_tests_still_hold() {
        let mut x = good();
        x.rust = "success".into();
        x.python = "success".into();
        x.historical_188 = "success".into();
        let f = assess(&x).unwrap();
        assert!(!f.recovery_authorized);
    }
    #[test]
    fn duplicate_write_refused() {
        let f = assess(&good()).unwrap();
        let p = std::env::temp_dir().join(format!("sapphon184-{}.json", std::process::id()));
        let _ = std::fs::remove_file(&p);
        write_new(&p, &f).unwrap();
        assert_eq!(write_new(&p, &f).unwrap_err().0, "FREEZE184_EXISTS");
        std::fs::remove_file(p).unwrap();
    }
}
