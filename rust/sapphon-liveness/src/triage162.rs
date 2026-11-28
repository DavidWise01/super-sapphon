//! SAPPHON-162 — source-owned browser observation and CI triage join.
//! An observed browser result must never imply independent physical custody.
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
fn sha(x: &[u8]) -> String {
    hex::encode(Sha256::digest(x))
}
fn valid(x: &str) -> bool {
    x.len() == 64
        && x.bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BrowserCase {
    pub page: String,
    pub screenshot_sha256: String,
    pub canvas_present: bool,
    pub interaction_assertions: u16,
    pub exception_count: u16,
    pub recovery_hold_visible: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TriageInput {
    pub source_commit: String,
    pub rust_check: String,
    pub rust_tests: String,
    pub historical_freeze: String,
    pub pages_http: String,
    pub chromium_browser: String,
    pub cases: Vec<BrowserCase>,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Triage {
    pub schema: String,
    pub blocked_stages: Vec<String>,
    pub source_observations_consistent: bool,
    pub observable_browser_assertions: u16,
    pub full_browser_qualification: bool,
    pub ci_authenticated: bool,
    pub independent_custody_authenticated: bool,
    pub global_anti_rollback_authenticated: bool,
    pub recovery_authorized: bool,
    pub lock_cleared: bool,
    pub evidence_digest: String,
    pub decision: String,
}
/// Triage is a pure comparison of supplied job and browser evidence; it does
/// not fetch GitHub's API or authenticate the observation origin.
pub fn triage(i: &TriageInput) -> Result<Triage, Error> {
    if i.source_commit.len() != 40
        || !i
            .source_commit
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        || i.cases.len() > 8
    {
        return Err(Error("TRIAGE162_FIELDS"));
    }
    let stages = [
        ("rust-check", &i.rust_check),
        ("rust-tests", &i.rust_tests),
        ("historical-freeze", &i.historical_freeze),
        ("pages-http", &i.pages_http),
        ("browser-interactions", &i.chromium_browser),
    ];
    let mut blocked = vec![];
    for (stage, status) in stages {
        if !["success", "failure", "skipped", "cancelled", "unknown"].contains(&status.as_str()) {
            return Err(Error("TRIAGE162_STATUS"));
        }
        if status != "success" {
            blocked.push(format!("{stage}:{status}"));
        }
    }
    let mut seen = BTreeSet::new();
    let mut total = 0u16;
    for c in &i.cases {
        if !["SAPPHON-160", "SAPPHON-161"].contains(&c.page.as_str())
            || !seen.insert(c.page.as_str())
            || !valid(&c.screenshot_sha256)
        {
            return Err(Error("TRIAGE162_CASE_FIELDS"));
        }
        total = total
            .checked_add(c.interaction_assertions)
            .ok_or(Error("TRIAGE162_COUNT"))?;
        if !c.canvas_present
            || !c.recovery_hold_visible
            || c.exception_count != 0
            || c.interaction_assertions < 4
        {
            blocked.push(format!("browser-case:{}:INCOMPLETE", c.page));
        }
    }
    if seen.len() != 2 {
        blocked.push("browser-cases:NOT_ALL_OBSERVED".into());
    }
    blocked.sort();
    let bytes = serde_json::to_vec(i).map_err(|_| Error("TRIAGE162_ENCODING"))?;
    Ok(Triage {
        schema: "sapphon-162-triage-v1".into(),
        blocked_stages: blocked.clone(),
        source_observations_consistent: blocked.is_empty(),
        observable_browser_assertions: total,
        full_browser_qualification: false,
        ci_authenticated: false,
        independent_custody_authenticated: false,
        global_anti_rollback_authenticated: false,
        recovery_authorized: false,
        lock_cleared: false,
        evidence_digest: sha(&bytes),
        decision: "INTERACTIVE_OBSERVATION_HOLD".into(),
    })
}
pub fn write_new(path: &Path, report: &Triage) -> Result<String, Error> {
    if report.schema != "sapphon-162-triage-v1"
        || report.decision != "INTERACTIVE_OBSERVATION_HOLD"
        || report.full_browser_qualification
        || report.ci_authenticated
        || report.independent_custody_authenticated
        || report.global_anti_rollback_authenticated
        || report.recovery_authorized
        || report.lock_cleared
    {
        return Err(Error("TRIAGE162_AUTHORITY"));
    }
    let bytes = serde_json::to_vec(report).map_err(|_| Error("TRIAGE162_ENCODING"))?;
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)
        .map_err(|_| Error("TRIAGE162_EXISTS"))?;
    file.write_all(&bytes)
        .map_err(|_| Error("TRIAGE162_WRITE"))?;
    file.sync_all().map_err(|_| Error("TRIAGE162_FSYNC"))?;
    File::open(path.parent().ok_or(Error("TRIAGE162_PARENT"))?)
        .and_then(|f| f.sync_all())
        .map_err(|_| Error("TRIAGE162_DIRSYNC"))?;
    Ok(sha(&bytes))
}
#[cfg(test)]
mod tests {
    use super::*;
    fn specimen() -> TriageInput {
        TriageInput {
            source_commit: "a".repeat(40),
            rust_check: "success".into(),
            rust_tests: "success".into(),
            historical_freeze: "success".into(),
            pages_http: "success".into(),
            chromium_browser: "success".into(),
            cases: ["SAPPHON-160", "SAPPHON-161"]
                .into_iter()
                .map(|page| BrowserCase {
                    page: page.into(),
                    screenshot_sha256: "b".repeat(64),
                    canvas_present: true,
                    interaction_assertions: 4,
                    exception_count: 0,
                    recovery_hold_visible: true,
                })
                .collect(),
        }
    }
    #[test]
    fn passing_claims_never_certify_authority() {
        let r = triage(&specimen()).unwrap();
        assert!(r.source_observations_consistent);
        assert!(
            !r.ci_authenticated
                && !r.full_browser_qualification
                && !r.recovery_authorized
                && !r.independent_custody_authenticated
        );
    }
    #[test]
    fn failed_rust_is_preserved() {
        let mut i = specimen();
        i.rust_tests = "failure".into();
        assert!(triage(&i)
            .unwrap()
            .blocked_stages
            .contains(&"rust-tests:failure".into()));
    }
    #[test]
    fn historical_hash_failure_is_blocking() {
        let mut i = specimen();
        i.historical_freeze = "failure".into();
        assert!(!triage(&i).unwrap().source_observations_consistent);
    }
    #[test]
    fn missing_browser_case_is_blocking() {
        let mut i = specimen();
        i.cases.pop();
        assert!(triage(&i)
            .unwrap()
            .blocked_stages
            .iter()
            .any(|x| x.contains("NOT_ALL_OBSERVED")));
    }
    #[test]
    fn javascript_errors_are_blocking() {
        let mut i = specimen();
        i.cases[0].exception_count = 1;
        assert!(!triage(&i).unwrap().source_observations_consistent);
    }
    #[test]
    fn missing_hold_text_is_blocking() {
        let mut i = specimen();
        i.cases[0].recovery_hold_visible = false;
        assert!(!triage(&i).unwrap().source_observations_consistent);
    }
    #[test]
    fn fabricated_browser_status_rejected() {
        let mut i = specimen();
        i.chromium_browser = "certified".into();
        assert_eq!(triage(&i).unwrap_err().0, "TRIAGE162_STATUS");
    }
    #[test]
    fn identical_page_cannot_count_twice() {
        let mut i = specimen();
        i.cases[1].page = "SAPPHON-160".into();
        assert_eq!(triage(&i).unwrap_err().0, "TRIAGE162_CASE_FIELDS");
    }
    #[test]
    fn report_is_create_only() {
        let r = triage(&specimen()).unwrap();
        let path = std::env::temp_dir().join(format!("sapphon162-{}.json", std::process::id()));
        let _ = std::fs::remove_file(&path);
        write_new(&path, &r).unwrap();
        assert_eq!(write_new(&path, &r).unwrap_err().0, "TRIAGE162_EXISTS");
        std::fs::remove_file(path).unwrap();
    }
}
