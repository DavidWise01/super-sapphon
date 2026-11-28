//! SAPPHON-160 — Phase XIV final DESIGN manifest, not operational certification.
//! Identical source or GitHub-runner provenance is one ancestry.
//! No source-owned status may promote external custody or clear a lock.
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
const MAX: usize = 1024 * 1024;
fn digest(b: &[u8]) -> String {
    hex::encode(Sha256::digest(b))
}
fn valid64(v: &str) -> bool {
    v.len() == 64
        && v.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn valid40(v: &str) -> bool {
    v.len() == 40
        && v.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Bound {
    pub number: u16,
    pub relative_source_path: String,
    pub expected_source_sha256: String,
    pub claimed_source_ancestry: String,
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum Observation {
    NotObserved,
    SourceOnly,
    Failed,
    ClaimedPass,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Inputs {
    pub repository: String,
    pub head_commit: String,
    pub bounds: Vec<Bound>,
    pub rust_ci: Observation,
    pub frozen_188_hashes: Observation,
    pub browser_acceptance: Observation,
    pub pages_deployment: Observation,
    pub externally_authenticated_custody: Observation,
    pub externally_authenticated_monotonicity: Observation,
    pub authenticated_utc: Observation,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Freeze {
    pub schema: String,
    pub phase: u8,
    pub bound: u16,
    pub design_progress_percent: u8,
    pub source_manifest_sha256: String,
    pub source_ancestry_roots: usize,
    pub rust_ci_verified: bool,
    pub frozen_188_hashes_verified: bool,
    pub browser_verified: bool,
    pub pages_verified: bool,
    pub independent_custody_proven: bool,
    pub monotonic_external_anchor_proven: bool,
    pub authenticated_utc_proven: bool,
    pub recovery_authorized: bool,
    pub key_rotation_authorized: bool,
    pub lock_cleared: bool,
    pub evidence_findings: Vec<String>,
    pub decision: String,
}
/// Validates source-design identity, and records observations. Expected hashes
/// are declarations, not proof that source bytes were read or externally pinned.
pub fn evaluate(input: &Inputs) -> Result<Freeze, Error> {
    if input.repository != "DavidWise01/super-sapphon"
        || !valid40(&input.head_commit)
        || input.bounds.len() != 7
    {
        return Err(Error("FREEZE160_INPUT"));
    }
    let mut bounds = input.bounds.clone();
    bounds.sort_by_key(|b| b.number);
    let mut roots = BTreeSet::new();
    for (i, b) in bounds.iter().enumerate() {
        if b.number != 153 + i as u16
            || !valid64(&b.expected_source_sha256)
            || !b
                .relative_source_path
                .starts_with("rust/sapphon-liveness/src/")
            || !b.relative_source_path.ends_with(".rs")
            || b.relative_source_path.contains("..")
            || b.claimed_source_ancestry.is_empty()
            || b.claimed_source_ancestry.len() > 128
        {
            return Err(Error("FREEZE160_BOUND_FIELDS"));
        }
        roots.insert(b.claimed_source_ancestry.clone());
    }
    let manifest = serde_json::to_vec(&bounds).map_err(|_| Error("FREEZE160_ENCODING"))?;
    let mut findings = vec![
        "SOURCE_HASHES_NOT_INDEPENDENTLY_PINNED".to_owned(),
        "GITHUB_SOURCE_AND_ACTIONS_SHARE_ANCESTRY".to_owned(),
        "OPERATIONAL_AUTHORITY_HOLD".to_owned(),
    ];
    let observations = [
        ("RUST_CI", input.rust_ci),
        ("HISTORICAL_HASHES", input.frozen_188_hashes),
        ("BROWSER", input.browser_acceptance),
        ("PAGES", input.pages_deployment),
        ("EXTERNAL_CUSTODY", input.externally_authenticated_custody),
        (
            "EXTERNAL_MONOTONICITY",
            input.externally_authenticated_monotonicity,
        ),
        ("AUTHENTICATED_UTC", input.authenticated_utc),
    ];
    for (name, observation) in observations {
        let label = match observation {
            Observation::NotObserved => "NOT_OBSERVED",
            Observation::SourceOnly => "SOURCE_ONLY",
            Observation::Failed => "FAILED",
            Observation::ClaimedPass => "CLAIMED_PASS_UNAUTHENTICATED",
        };
        findings.push(format!("{name}:{label}"));
    }
    findings.sort();
    Ok(Freeze {
        schema: "sapphon-160-phase-xiv-design-freeze-v1".into(),
        phase: 14,
        bound: 160,
        design_progress_percent: 100,
        source_manifest_sha256: digest(&manifest),
        source_ancestry_roots: roots.len(),
        rust_ci_verified: false,
        frozen_188_hashes_verified: false,
        browser_verified: false,
        pages_verified: false,
        independent_custody_proven: false,
        monotonic_external_anchor_proven: false,
        authenticated_utc_proven: false,
        recovery_authorized: false,
        key_rotation_authorized: false,
        lock_cleared: false,
        evidence_findings: findings,
        decision: "DESIGN_COMPLETE_QUALIFICATION_HOLD".into(),
    })
}
pub fn verify_report(body: &[u8], expected_sha256: &str) -> Result<Freeze, Error> {
    if body.len() > MAX || !valid64(expected_sha256) || digest(body) != expected_sha256 {
        return Err(Error("FREEZE160_REPORT_DIGEST"));
    }
    let r: Freeze = serde_json::from_slice(body).map_err(|_| Error("FREEZE160_REPORT_CORRUPT"))?;
    if r.schema != "sapphon-160-phase-xiv-design-freeze-v1"
        || r.phase != 14
        || r.bound != 160
        || r.design_progress_percent != 100
        || r.decision != "DESIGN_COMPLETE_QUALIFICATION_HOLD"
        || r.rust_ci_verified
        || r.frozen_188_hashes_verified
        || r.browser_verified
        || r.pages_verified
        || r.independent_custody_proven
        || r.monotonic_external_anchor_proven
        || r.authenticated_utc_proven
        || r.recovery_authorized
        || r.key_rotation_authorized
        || r.lock_cleared
    {
        return Err(Error("FREEZE160_AUTHORITY"));
    }
    Ok(r)
}
pub fn write_new(path: &Path, report: &Freeze) -> Result<String, Error> {
    let body = serde_json::to_vec(report).map_err(|_| Error("FREEZE160_ENCODING"))?;
    // Check semantic authority invariants even if caller mutates the struct.
    verify_report(&body, &digest(&body))?;
    let mut f = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)
        .map_err(|_| Error("FREEZE160_EXISTS"))?;
    f.write_all(&body).map_err(|_| Error("FREEZE160_WRITE"))?;
    f.sync_all().map_err(|_| Error("FREEZE160_FSYNC"))?;
    File::open(path.parent().ok_or(Error("FREEZE160_PARENT"))?)
        .and_then(|dir| dir.sync_all())
        .map_err(|_| Error("FREEZE160_DIRSYNC"))?;
    Ok(digest(&body))
}
#[cfg(test)]
mod tests {
    use super::*;
    fn input() -> Inputs {
        let paths = [
            "qualification153",
            "readback154",
            "artifact155",
            "custody156",
            "enrollment157",
            "challenge158",
            "nonce159",
        ];
        Inputs {
            repository: "DavidWise01/super-sapphon".into(),
            head_commit: "a".repeat(40),
            bounds: paths
                .into_iter()
                .enumerate()
                .map(|(i, path)| Bound {
                    number: 153 + i as u16,
                    relative_source_path: format!("rust/sapphon-liveness/src/{path}.rs"),
                    expected_source_sha256: format!("{:064x}", i + 1),
                    claimed_source_ancestry: "github-owned-corpus".into(),
                })
                .collect(),
            rust_ci: Observation::NotObserved,
            frozen_188_hashes: Observation::NotObserved,
            browser_acceptance: Observation::NotObserved,
            pages_deployment: Observation::NotObserved,
            externally_authenticated_custody: Observation::NotObserved,
            externally_authenticated_monotonicity: Observation::NotObserved,
            authenticated_utc: Observation::NotObserved,
        }
    }
    #[test]
    fn source_design_completed_without_authority() {
        let r = evaluate(&input()).unwrap();
        assert_eq!(r.design_progress_percent, 100);
        assert!(
            !r.rust_ci_verified
                && !r.independent_custody_proven
                && !r.recovery_authorized
                && !r.lock_cleared
        );
    }
    #[test]
    fn seven_github_modules_count_as_one_ancestry() {
        assert_eq!(evaluate(&input()).unwrap().source_ancestry_roots, 1);
    }
    #[test]
    fn forged_pass_claim_stays_unqualified() {
        let mut i = input();
        i.rust_ci = Observation::ClaimedPass;
        let r = evaluate(&i).unwrap();
        assert!(r
            .evidence_findings
            .iter()
            .any(|s| s == "RUST_CI:CLAIMED_PASS_UNAUTHENTICATED"));
        assert!(!r.rust_ci_verified);
    }
    #[test]
    fn failed_ci_not_silenced() {
        let mut i = input();
        i.rust_ci = Observation::Failed;
        assert!(evaluate(&i)
            .unwrap()
            .evidence_findings
            .iter()
            .any(|s| s == "RUST_CI:FAILED"));
    }
    #[test]
    fn incomplete_phase_manifest_rejected() {
        let mut i = input();
        i.bounds.pop();
        assert_eq!(evaluate(&i).unwrap_err().0, "FREEZE160_INPUT");
    }
    #[test]
    fn duplicate_phase_bound_rejected() {
        let mut i = input();
        i.bounds[1].number = 153;
        assert_eq!(evaluate(&i).unwrap_err().0, "FREEZE160_BOUND_FIELDS");
    }
    #[test]
    fn input_order_does_not_affect_digest() {
        let i = input();
        let mut j = i.clone();
        j.bounds.reverse();
        assert_eq!(evaluate(&i).unwrap(), evaluate(&j).unwrap());
    }
    #[test]
    fn external_custody_claim_still_hold() {
        let mut i = input();
        i.externally_authenticated_custody = Observation::ClaimedPass;
        assert!(!evaluate(&i).unwrap().independent_custody_proven);
    }
    #[test]
    fn tampering_with_export_detected() {
        let r = evaluate(&input()).unwrap();
        let mut b = serde_json::to_vec(&r).unwrap();
        let h = digest(&b);
        b.push(b' ');
        assert_eq!(
            verify_report(&b, &h).unwrap_err().0,
            "FREEZE160_REPORT_DIGEST"
        );
    }
    #[test]
    fn forged_authority_flag_detected() {
        let mut r = evaluate(&input()).unwrap();
        r.lock_cleared = true;
        let b = serde_json::to_vec(&r).unwrap();
        assert_eq!(
            verify_report(&b, &digest(&b)).unwrap_err().0,
            "FREEZE160_AUTHORITY"
        );
    }
    #[test]
    fn create_only_report_rejects_overwrite() {
        let r = evaluate(&input()).unwrap();
        let path = std::env::temp_dir().join(format!("sapphon160-{}.json", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let h = write_new(&path, &r).unwrap();
        let body = std::fs::read(&path).unwrap();
        assert_eq!(verify_report(&body, &h).unwrap(), r);
        assert_eq!(write_new(&path, &r).unwrap_err().0, "FREEZE160_EXISTS");
        std::fs::remove_file(path).unwrap();
    }
}
