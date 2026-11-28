//! SAPPHON-161 — read-only CI diagnostic classification.
//! Real GitHub API readback and job logs must be acquired outside this module.
//! Classifying failures is not certifying CI or physical custody.
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
fn sha(b: &[u8]) -> String {
    hex::encode(Sha256::digest(b))
}
fn git_sha(s: &str) -> bool {
    s.len() == 40
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Check {
    pub name: String,
    pub conclusion: String,
    pub observed_from: String,
    pub log_sha256: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Evidence {
    pub schema: String,
    pub repository: String,
    pub commit_sha: String,
    pub run_id: u64,
    pub run_attempt: u32,
    pub checks: Vec<Check>,
    pub github_api_readback_claimed: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Diagnosis {
    pub schema: String,
    pub commit_sha: String,
    pub run_id: u64,
    pub run_attempt: u32,
    pub passed: Vec<String>,
    pub failed: Vec<String>,
    pub missing: Vec<String>,
    pub skipped_or_unknown: Vec<String>,
    pub evidence_sha256: String,
    pub api_source_authenticated: bool,
    pub ci_qualified: bool,
    pub pages_browser_qualified: bool,
    pub independent_custody_authenticated: bool,
    pub recovery_authorized: bool,
    pub lock_cleared: bool,
    pub decision: String,
}
const EXPECTED: [&str; 5] = [
    "rust-check",
    "rust-tests",
    "historical-freeze",
    "pages-http",
    "browser-smoke",
];
/// Keep separate conclusions: one failure cannot be hidden by other passes.
/// Missing steps remain missing, and a self-described GitHub API readback is
/// not an authenticated one.
pub fn diagnose(e: &Evidence) -> Result<Diagnosis, Error> {
    if e.schema != "sapphon-161-check-evidence-v1"
        || e.repository != "DavidWise01/super-sapphon"
        || !git_sha(&e.commit_sha)
        || e.run_id == 0
        || e.run_attempt == 0
        || e.checks.len() > 24
    {
        return Err(Error("DIAG161_INPUT"));
    }
    let mut seen = BTreeSet::new();
    let (mut passed, mut failed, mut unknown) = (vec![], vec![], vec![]);
    for check in &e.checks {
        if !EXPECTED.contains(&check.name.as_str())
            || !seen.insert(check.name.as_str())
            || check.observed_from.len() > 512
            || check.observed_from.is_empty()
            || check.log_sha256.as_ref().is_some_and(|s| {
                s.len() != 64
                    || !s
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            })
        {
            return Err(Error("DIAG161_CHECK_FIELDS"));
        }
        match check.conclusion.as_str() {
            "success" => passed.push(check.name.clone()),
            "failure" | "timed_out" | "cancelled" => failed.push(check.name.clone()),
            "skipped" | "neutral" | "action_required" | "in_progress" | "unknown" => {
                unknown.push(check.name.clone())
            }
            _ => return Err(Error("DIAG161_CONCLUSION")),
        }
    }
    let missing = EXPECTED
        .iter()
        .filter(|n| !seen.contains(*n))
        .map(|n| (*n).to_string())
        .collect::<Vec<_>>();
    passed.sort();
    failed.sort();
    unknown.sort();
    let mut canonical = e.checks.clone();
    canonical.sort_by(|a, b| a.name.cmp(&b.name));
    let bytes = serde_json::to_vec(&(
        e.repository.as_str(),
        e.commit_sha.as_str(),
        e.run_id,
        e.run_attempt,
        &canonical,
    ))
    .map_err(|_| Error("DIAG161_ENCODING"))?;
    Ok(Diagnosis {
        schema: "sapphon-161-diagnosis-v1".into(),
        commit_sha: e.commit_sha.clone(),
        run_id: e.run_id,
        run_attempt: e.run_attempt,
        passed,
        failed,
        missing,
        skipped_or_unknown: unknown,
        evidence_sha256: sha(&bytes),
        api_source_authenticated: false,
        ci_qualified: false,
        pages_browser_qualified: false,
        independent_custody_authenticated: false,
        recovery_authorized: false,
        lock_cleared: false,
        decision: "DIAGNOSTIC_ONLY_HOLD".into(),
    })
}
pub fn write_new(path: &Path, report: &Diagnosis) -> Result<String, Error> {
    if report.schema != "sapphon-161-diagnosis-v1"
        || report.decision != "DIAGNOSTIC_ONLY_HOLD"
        || report.api_source_authenticated
        || report.ci_qualified
        || report.pages_browser_qualified
        || report.independent_custody_authenticated
        || report.recovery_authorized
        || report.lock_cleared
    {
        return Err(Error("DIAG161_AUTHORITY"));
    }
    let body = serde_json::to_vec(report).map_err(|_| Error("DIAG161_ENCODING"))?;
    if body.len() > 1024 * 1024 {
        return Err(Error("DIAG161_SIZE"));
    }
    let mut f = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)
        .map_err(|_| Error("DIAG161_EXISTS"))?;
    f.write_all(&body).map_err(|_| Error("DIAG161_WRITE"))?;
    f.sync_all().map_err(|_| Error("DIAG161_FSYNC"))?;
    File::open(path.parent().ok_or(Error("DIAG161_PARENT"))?)
        .and_then(|d| d.sync_all())
        .map_err(|_| Error("DIAG161_DIRSYNC"))?;
    Ok(sha(&body))
}
#[cfg(test)]
mod tests {
    use super::*;
    fn sample() -> Evidence {
        Evidence {
            schema: "sapphon-161-check-evidence-v1".into(),
            repository: "DavidWise01/super-sapphon".into(),
            commit_sha: "a".repeat(40),
            run_id: 123,
            run_attempt: 1,
            github_api_readback_claimed: false,
            checks: vec![
                Check {
                    name: "rust-check".into(),
                    conclusion: "success".into(),
                    observed_from: "github-runner".into(),
                    log_sha256: None,
                },
                Check {
                    name: "rust-tests".into(),
                    conclusion: "failure".into(),
                    observed_from: "github-runner".into(),
                    log_sha256: None,
                },
            ],
        }
    }
    #[test]
    fn failures_preserved_missing_not_promoted() {
        let d = diagnose(&sample()).unwrap();
        assert_eq!(d.failed, vec!["rust-tests"]);
        assert_eq!(d.missing.len(), 3);
        assert!(!d.ci_qualified && !d.recovery_authorized);
    }
    #[test]
    fn fabricated_api_flag_cannot_certify() {
        let mut x = sample();
        x.github_api_readback_claimed = true;
        assert!(!diagnose(&x).unwrap().api_source_authenticated);
    }
    #[test]
    fn duplicate_check_rejected() {
        let mut x = sample();
        x.checks.push(x.checks[0].clone());
        assert_eq!(diagnose(&x).unwrap_err().0, "DIAG161_CHECK_FIELDS");
    }
    #[test]
    fn unknown_check_rejected() {
        let mut x = sample();
        x.checks[0].name = "everything-passed".into();
        assert_eq!(diagnose(&x).unwrap_err().0, "DIAG161_CHECK_FIELDS");
    }
    #[test]
    fn unsupported_conclusion_rejected() {
        let mut x = sample();
        x.checks[0].conclusion = "certified".into();
        assert_eq!(diagnose(&x).unwrap_err().0, "DIAG161_CONCLUSION");
    }
    #[test]
    fn reordered_checks_same_digest() {
        let x = sample();
        let mut y = x.clone();
        y.checks.reverse();
        assert_eq!(diagnose(&x).unwrap(), diagnose(&y).unwrap());
    }
    #[test]
    fn skipped_is_neither_success_nor_failure() {
        let mut x = sample();
        x.checks[1].conclusion = "skipped".into();
        let d = diagnose(&x).unwrap();
        assert_eq!(d.skipped_or_unknown, vec!["rust-tests"]);
        assert!(d.failed.is_empty());
    }
    #[test]
    fn malformed_commit_rejected() {
        let mut x = sample();
        x.commit_sha = "not-a-commit".into();
        assert_eq!(diagnose(&x).unwrap_err().0, "DIAG161_INPUT");
    }
    #[test]
    fn create_only_report_denies_overwrite() {
        let d = diagnose(&sample()).unwrap();
        let path = std::env::temp_dir().join(format!("sapphon161-{}.json", std::process::id()));
        let _ = std::fs::remove_file(&path);
        write_new(&path, &d).unwrap();
        assert_eq!(write_new(&path, &d).unwrap_err().0, "DIAG161_EXISTS");
        std::fs::remove_file(path).unwrap();
    }
}
