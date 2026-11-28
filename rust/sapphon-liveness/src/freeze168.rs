//! SAPPHON-168 — final Phase XV design freeze, qualification not implied.
//! GitHub source, Actions and Pages are one owned ancestry.
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
fn sha(b: &[u8]) -> String {
    hex::encode(Sha256::digest(b))
}
fn hex(s: &str, n: usize) -> bool {
    s.len() == n
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Bound {
    pub number: u16,
    pub source_path: String,
    pub declared_sha256: String,
    pub source_ancestry: String,
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum Outcome {
    NotObserved,
    Configured,
    Failed,
    PassedClaim,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Input {
    pub repository: String,
    pub head_commit: String,
    pub bounds: Vec<Bound>,
    pub registry_candidate: Outcome,
    pub committed_lock_integrity: Outcome,
    pub rust_ci: Outcome,
    pub historical_188: Outcome,
    pub chromium: Outcome,
    pub pages_parity: Outcome,
    pub independently_authenticated_custody: Outcome,
    pub externally_anchored_monotonicity: Outcome,
    pub authenticated_utc: Outcome,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Freeze {
    pub schema: String,
    pub phase: u8,
    pub last_bound: u16,
    pub design_percent: u8,
    pub bound_manifest_sha256: String,
    pub source_ancestry_root_count: usize,
    pub findings: Vec<String>,
    pub lockfile_qualified: bool,
    pub ci_externally_authenticated: bool,
    pub browser_externally_authenticated: bool,
    pub independent_custody_authenticated: bool,
    pub global_anti_rollback_authenticated: bool,
    pub authenticated_utc_proven: bool,
    pub recovery_authorized: bool,
    pub key_rotation_authorized: bool,
    pub lock_cleared: bool,
    pub decision: String,
}
/// A caller's own PASS claim cannot certify a source-origin test or
/// independent custodian. A complete source design is not a passing build.
pub fn evaluate(input: &Input) -> Result<Freeze, Error> {
    if input.repository != "DavidWise01/super-sapphon"
        || !hex(&input.head_commit, 40)
        || input.bounds.len() != 7
    {
        return Err(Error("FREEZE168_INPUT"));
    }
    let mut b = input.bounds.clone();
    b.sort_by_key(|v| v.number);
    let mut ancestors = BTreeSet::new();
    for (i, x) in b.iter().enumerate() {
        let expected = [
            "rust/sapphon-liveness/src/diagnostic161.rs",
            "rust/sapphon-liveness/src/triage162.rs",
            "rust/sapphon-liveness/src/parity163.rs",
            "tools/sapphon_164_pages_parity.py",
            "tools/sapphon_165_lock_inspect.py",
            "rust/sapphon-liveness/src/candidate166.rs",
            "rust/sapphon-liveness/src/promotion167.rs",
        ][i];
        if x.number != 161 + i as u16
            || !hex(&x.declared_sha256, 64)
            || x.source_path != expected
            || x.source_ancestry.len() > 128
            || x.source_ancestry.is_empty()
        {
            return Err(Error("FREEZE168_BOUND_FIELDS"));
        }
        ancestors.insert(x.source_ancestry.clone());
    }
    let bytes = serde_json::to_vec(&b).map_err(|_| Error("FREEZE168_ENCODING"))?;
    let named = [
        ("REGISTRY_CANDIDATE", input.registry_candidate),
        ("COMMITTED_LOCK", input.committed_lock_integrity),
        ("RUST_CI", input.rust_ci),
        ("HISTORICAL_188", input.historical_188),
        ("CHROMIUM", input.chromium),
        ("PAGES_PARITY", input.pages_parity),
        (
            "EXTERNAL_CUSTODY",
            input.independently_authenticated_custody,
        ),
        (
            "EXTERNAL_MONOTONICITY",
            input.externally_anchored_monotonicity,
        ),
        ("AUTHENTICATED_UTC", input.authenticated_utc),
    ];
    let mut findings = vec!["GITHUB_OWNED_SURFACES_SHARE_ONE_ANCESTRY".to_owned()];
    for (label, state) in named {
        let s = match state {
            Outcome::NotObserved => "NOT_OBSERVED",
            Outcome::Configured => "CONFIGURED_ONLY",
            Outcome::Failed => "FAILED",
            Outcome::PassedClaim => "UNAUTHENTICATED_PASS_CLAIM",
        };
        findings.push(format!("{label}:{s}"));
    }
    findings.sort();
    Ok(Freeze {
        schema: "sapphon-168-phase-xv-design-freeze-v1".into(),
        phase: 15,
        last_bound: 168,
        design_percent: 100,
        bound_manifest_sha256: sha(&bytes),
        source_ancestry_root_count: ancestors.len(),
        findings,
        lockfile_qualified: false,
        ci_externally_authenticated: false,
        browser_externally_authenticated: false,
        independent_custody_authenticated: false,
        global_anti_rollback_authenticated: false,
        authenticated_utc_proven: false,
        recovery_authorized: false,
        key_rotation_authorized: false,
        lock_cleared: false,
        decision: "DESIGN_COMPLETE_QUALIFICATION_HOLD".into(),
    })
}
pub fn verify(bytes: &[u8], expected_sha256: &str) -> Result<Freeze, Error> {
    if bytes.len() > MAX || !hex(expected_sha256, 64) || sha(bytes) != expected_sha256 {
        return Err(Error("FREEZE168_DIGEST"));
    }
    let r: Freeze = serde_json::from_slice(bytes).map_err(|_| Error("FREEZE168_CORRUPT"))?;
    if r.schema != "sapphon-168-phase-xv-design-freeze-v1"
        || r.phase != 15
        || r.last_bound != 168
        || r.design_percent != 100
        || r.decision != "DESIGN_COMPLETE_QUALIFICATION_HOLD"
        || r.lockfile_qualified
        || r.ci_externally_authenticated
        || r.browser_externally_authenticated
        || r.independent_custody_authenticated
        || r.global_anti_rollback_authenticated
        || r.authenticated_utc_proven
        || r.recovery_authorized
        || r.key_rotation_authorized
        || r.lock_cleared
    {
        return Err(Error("FREEZE168_AUTHORITY"));
    }
    Ok(r)
}
pub fn write_new(path: &Path, r: &Freeze) -> Result<String, Error> {
    let bytes = serde_json::to_vec(r).map_err(|_| Error("FREEZE168_ENCODING"))?;
    verify(&bytes, &sha(&bytes))?;
    let mut f = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)
        .map_err(|_| Error("FREEZE168_EXISTS"))?;
    f.write_all(&bytes).map_err(|_| Error("FREEZE168_WRITE"))?;
    f.sync_all().map_err(|_| Error("FREEZE168_FSYNC"))?;
    File::open(path.parent().ok_or(Error("FREEZE168_PARENT"))?)
        .and_then(|p| p.sync_all())
        .map_err(|_| Error("FREEZE168_DIRSYNC"))?;
    Ok(sha(&bytes))
}
#[cfg(test)]
mod tests {
    use super::*;
    fn base() -> Input {
        let src = [
            "rust/sapphon-liveness/src/diagnostic161.rs",
            "rust/sapphon-liveness/src/triage162.rs",
            "rust/sapphon-liveness/src/parity163.rs",
            "tools/sapphon_164_pages_parity.py",
            "tools/sapphon_165_lock_inspect.py",
            "rust/sapphon-liveness/src/candidate166.rs",
            "rust/sapphon-liveness/src/promotion167.rs",
        ];
        Input {
            repository: "DavidWise01/super-sapphon".into(),
            head_commit: "a".repeat(40),
            bounds: src
                .into_iter()
                .enumerate()
                .map(|(i, s)| Bound {
                    number: 161 + i as u16,
                    source_path: s.into(),
                    declared_sha256: format!("{:064x}", i + 1),
                    source_ancestry: "github-owned-corpus".into(),
                })
                .collect(),
            registry_candidate: Outcome::NotObserved,
            committed_lock_integrity: Outcome::Configured,
            rust_ci: Outcome::NotObserved,
            historical_188: Outcome::NotObserved,
            chromium: Outcome::NotObserved,
            pages_parity: Outcome::NotObserved,
            independently_authenticated_custody: Outcome::NotObserved,
            externally_anchored_monotonicity: Outcome::NotObserved,
            authenticated_utc: Outcome::NotObserved,
        }
    }
    #[test]
    fn design_complete_is_not_operational() {
        let r = evaluate(&base()).unwrap();
        assert_eq!(r.design_percent, 100);
        assert!(!r.lockfile_qualified && !r.recovery_authorized && !r.lock_cleared);
    }
    #[test]
    fn all_github_sources_are_one_ancestry() {
        assert_eq!(evaluate(&base()).unwrap().source_ancestry_root_count, 1);
    }
    #[test]
    fn claimed_ci_pass_never_promotes() {
        let mut x = base();
        x.rust_ci = Outcome::PassedClaim;
        let r = evaluate(&x).unwrap();
        assert!(!r.ci_externally_authenticated);
        assert!(r
            .findings
            .contains(&"RUST_CI:UNAUTHENTICATED_PASS_CLAIM".into()));
    }
    #[test]
    fn failed_lock_visible() {
        let mut x = base();
        x.committed_lock_integrity = Outcome::Failed;
        assert!(evaluate(&x)
            .unwrap()
            .findings
            .contains(&"COMMITTED_LOCK:FAILED".into()));
    }
    #[test]
    fn missing_phase_bound_rejected() {
        let mut x = base();
        x.bounds.pop();
        assert_eq!(evaluate(&x).unwrap_err().0, "FREEZE168_INPUT");
    }
    #[test]
    fn duplicate_bound_rejected() {
        let mut x = base();
        x.bounds[1].number = 161;
        assert_eq!(evaluate(&x).unwrap_err().0, "FREEZE168_BOUND_FIELDS");
    }
    #[test]
    fn order_does_not_change_digest() {
        let x = base();
        let mut y = x.clone();
        y.bounds.reverse();
        assert_eq!(evaluate(&x).unwrap(), evaluate(&y).unwrap());
    }
    #[test]
    fn source_claimed_external_custody_still_hold() {
        let mut x = base();
        x.independently_authenticated_custody = Outcome::PassedClaim;
        assert!(!evaluate(&x).unwrap().independent_custody_authenticated);
    }
    #[test]
    fn tampered_report_bytes_rejected() {
        let r = evaluate(&base()).unwrap();
        let mut bytes = serde_json::to_vec(&r).unwrap();
        let original = sha(&bytes);
        bytes.push(b' ');
        assert_eq!(verify(&bytes, &original).unwrap_err().0, "FREEZE168_DIGEST");
    }
    #[test]
    fn forged_recovery_flag_rejected() {
        let mut r = evaluate(&base()).unwrap();
        r.recovery_authorized = true;
        let b = serde_json::to_vec(&r).unwrap();
        assert_eq!(verify(&b, &sha(&b)).unwrap_err().0, "FREEZE168_AUTHORITY");
    }
    #[test]
    fn create_only_record_rejects_overwrite() {
        let r = evaluate(&base()).unwrap();
        let p = std::env::temp_dir().join(format!("sapphon168-{}.json", std::process::id()));
        let _ = std::fs::remove_file(&p);
        let h = write_new(&p, &r).unwrap();
        assert_eq!(verify(&std::fs::read(&p).unwrap(), &h).unwrap(), r);
        assert_eq!(write_new(&p, &r).unwrap_err().0, "FREEZE168_EXISTS");
        std::fs::remove_file(p).unwrap();
    }
}
