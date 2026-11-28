//! SAPPHON-176 — final Phase XVI source freeze, no external authority.
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
const BOUNDS: [u16; 8] = [169, 170, 171, 172, 173, 174, 175, 176];
const CANONICAL: [&str; 8] = [
    "runtime169.rs",
    "isolate170.rs",
    "joblog171.rs",
    "reconcile172.rs",
    "steps173.rs",
    "outcomes174.rs",
    "runner175.rs",
    "freeze176.rs",
];
fn hash(b: &[u8]) -> String {
    hex::encode(Sha256::digest(b))
}
fn sha64(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}
fn sha40(s: &str) -> bool {
    s.len() == 40
        && s.bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Source {
    pub bound: u16,
    pub path: String,
    pub sha256: String,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Input {
    pub commit: String,
    pub sources: Vec<Source>,
    pub rust_ci: String,
    pub python_ci: String,
    pub historical_188: String,
    pub npm_lock: String,
    pub pages: String,
    pub external_custody: String,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Freeze {
    pub schema: String,
    pub phase: u8,
    pub design_percent: u8,
    pub immutable_source_inventory_sha256: String,
    pub findings: Vec<String>,
    pub source_design_complete: bool,
    pub successful_ci_authenticated_externally: bool,
    pub npm_lock_qualified: bool,
    pub pages_verified: bool,
    pub external_custody_authenticated: bool,
    pub global_anti_rollback_authenticated: bool,
    pub recovery_authorized: bool,
    pub lock_cleared: bool,
    pub decision: String,
}
pub fn evaluate(x: &Input) -> Result<Freeze, Error> {
    if !sha40(&x.commit) || x.sources.len() != 8 {
        return Err(Error("FREEZE176_INPUT"));
    }
    let mut sorted = x.sources.clone();
    sorted.sort_by_key(|s| s.bound);
    let mut seen = BTreeSet::new();
    for (index, item) in sorted.iter().enumerate() {
        if item.bound != BOUNDS[index]
            || !seen.insert(item.bound)
            || !sha64(&item.sha256)
            || item.path != format!("rust/sapphon-liveness/src/{}", CANONICAL[index])
        {
            return Err(Error("FREEZE176_SOURCE"));
        }
    }
    let mut findings = Vec::new();
    for (n, status) in [
        ("RUST", &x.rust_ci),
        ("PYTHON", &x.python_ci),
        ("HISTORICAL_188", &x.historical_188),
        ("NPM_LOCK", &x.npm_lock),
        ("PAGES", &x.pages),
        ("CUSTODY", &x.external_custody),
    ] {
        if !["success", "failure", "skipped", "not_observed"].contains(&status.as_str()) {
            return Err(Error("FREEZE176_STATUS"));
        }
        if status != "success" {
            findings.push(format!("{n}:{status}"));
        }
    }
    findings.push("OWNED_GITHUB_SURFACES_NOT_INDEPENDENT".into());
    findings.sort();
    let body = serde_json::to_vec(&sorted).map_err(|_| Error("FREEZE176_ENCODING"))?;
    Ok(Freeze {
        schema: "sapphon-176-final-source-freeze-v1".into(),
        phase: 16,
        design_percent: 100,
        immutable_source_inventory_sha256: hash(&body),
        findings,
        source_design_complete: true,
        successful_ci_authenticated_externally: false,
        npm_lock_qualified: false,
        pages_verified: false,
        external_custody_authenticated: false,
        global_anti_rollback_authenticated: false,
        recovery_authorized: false,
        lock_cleared: false,
        decision: "PHASE_XVI_DESIGN_COMPLETE_QUALIFICATION_HOLD".into(),
    })
}
pub fn write_new(path: &Path, r: &Freeze) -> Result<String, Error> {
    if r.schema != "sapphon-176-final-source-freeze-v1"
        || r.decision != "PHASE_XVI_DESIGN_COMPLETE_QUALIFICATION_HOLD"
        || r.successful_ci_authenticated_externally
        || r.npm_lock_qualified
        || r.pages_verified
        || r.external_custody_authenticated
        || r.global_anti_rollback_authenticated
        || r.recovery_authorized
        || r.lock_cleared
    {
        return Err(Error("FREEZE176_AUTHORITY"));
    }
    let body = serde_json::to_vec(r).map_err(|_| Error("FREEZE176_ENCODING"))?;
    let mut f = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)
        .map_err(|_| Error("FREEZE176_EXISTS"))?;
    f.write_all(&body).map_err(|_| Error("FREEZE176_WRITE"))?;
    f.sync_all().map_err(|_| Error("FREEZE176_FSYNC"))?;
    File::open(path.parent().ok_or(Error("FREEZE176_PARENT"))?)
        .and_then(|d| d.sync_all())
        .map_err(|_| Error("FREEZE176_DIRSYNC"))?;
    Ok(hash(&body))
}
#[cfg(test)]
mod tests {
    use super::*;
    fn sample() -> Input {
        Input {
            commit: "a".repeat(40),
            sources: BOUNDS
                .iter()
                .map(|n| Source {
                    bound: *n,
                    path: format!(
                        "rust/sapphon-liveness/src/{}",
                        CANONICAL[(n - 169) as usize]
                    ),
                    sha256: "b".repeat(64),
                })
                .collect(),
            rust_ci: "not_observed".into(),
            python_ci: "not_observed".into(),
            historical_188: "not_observed".into(),
            npm_lock: "failure".into(),
            pages: "not_observed".into(),
            external_custody: "not_observed".into(),
        }
    }
    #[test]
    fn design_can_complete_without_test_execution() {
        let r = evaluate(&sample()).unwrap();
        assert!(r.source_design_complete);
        assert!(!r.recovery_authorized && !r.npm_lock_qualified);
    }
    #[test]
    fn missing_bound_rejected() {
        let mut x = sample();
        x.sources.pop();
        assert_eq!(evaluate(&x).unwrap_err().0, "FREEZE176_INPUT");
    }
    #[test]
    fn duplicate_source_rejected() {
        let mut x = sample();
        x.sources[1] = x.sources[0].clone();
        assert_eq!(evaluate(&x).unwrap_err().0, "FREEZE176_SOURCE");
    }
    #[test]
    fn substituted_source_path_rejected() {
        let mut x = sample();
        x.sources[0].path = "rust/sapphon-liveness/src/wrong.rs".into();
        assert_eq!(evaluate(&x).unwrap_err().0, "FREEZE176_SOURCE");
    }
    #[test]
    fn forged_status_rejected() {
        let mut x = sample();
        x.rust_ci = "independently passed".into();
        assert_eq!(evaluate(&x).unwrap_err().0, "FREEZE176_STATUS");
    }
    #[test]
    fn all_source_passes_still_hold() {
        let mut x = sample();
        x.rust_ci = "success".into();
        x.python_ci = "success".into();
        x.historical_188 = "success".into();
        let r = evaluate(&x).unwrap();
        assert!(!r.successful_ci_authenticated_externally && !r.recovery_authorized);
    }
    #[test]
    fn create_only_evidence() {
        let r = evaluate(&sample()).unwrap();
        let p = std::env::temp_dir().join(format!("sapphon176-{}.json", std::process::id()));
        let _ = std::fs::remove_file(&p);
        write_new(&p, &r).unwrap();
        assert_eq!(write_new(&p, &r).unwrap_err().0, "FREEZE176_EXISTS");
        std::fs::remove_file(p).unwrap();
    }
}
