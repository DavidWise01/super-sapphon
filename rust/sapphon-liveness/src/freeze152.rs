//! SAPPHON-152 — Phase XIII final, read-only evidence qualification ledger.
//! A completed source-design phase cannot certify CI or independent custody.
//! External attestations are *caller-supplied claims*, never accepted as proof.
#![cfg(target_os = "linux")]
use crate::{blind151::ChallengeReport, substitution150::SubstitutionReport, Error};
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
fn sha(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}
fn valid(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PhaseSource {
    pub phase_bound: u16,
    pub relative_path: String,
    pub expected_sha256: String,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Qualification {
    pub schema: String,
    pub source_manifest_sha256: String,
    pub source_design_complete: bool,
    pub source_hashes_externally_pinned: bool,
    pub rust_ci_pass_confirmed: bool,
    pub historical_188_hash_pass_confirmed: bool,
    pub pages_deployment_confirmed: bool,
    pub independent_custody_authenticated: bool,
    pub external_anti_rollback_authenticated: bool,
    pub authenticated_utc: bool,
    pub lock_cleared: bool,
    pub recovery_authorized: bool,
    pub findings: Vec<String>,
    pub decision: String,
}
/// Deterministic seven-bound manifest. This certifies *neither* the supplied
/// digests nor the provenance of the files being described.
pub fn manifest_digest(sources: &[PhaseSource]) -> Result<String, Error> {
    if sources.len() != 7 {
        return Err(Error("FREEZE152_SOURCE_COUNT"));
    }
    let mut ordered = sources.to_vec();
    ordered.sort_by_key(|s| s.phase_bound);
    let mut seen = BTreeSet::new();
    for (i, item) in ordered.iter().enumerate() {
        if item.phase_bound != 145 + i as u16
            || !seen.insert(item.phase_bound)
            || !valid(&item.expected_sha256)
            || !item.relative_path.starts_with("rust/sapphon-liveness/src/")
            || !item.relative_path.ends_with(".rs")
            || item.relative_path.contains("..")
        {
            return Err(Error("FREEZE152_SOURCE_FIELDS"));
        }
    }
    let bytes = serde_json::to_vec(&ordered).map_err(|_| Error("FREEZE152_ENCODING"))?;
    Ok(sha(&bytes))
}
/// Phase XIII includes 145..151; 152 is the unqualified closure record.
/// An externally pinned source manifest alone does not establish test success.
pub fn evaluate(
    sources: &[PhaseSource],
    challenge: &ChallengeReport,
    substitution: &SubstitutionReport,
) -> Result<Qualification, Error> {
    if challenge.schema != "sapphon-151-blind-challenge-v1"
        || challenge.decision != "HOLD"
        || challenge.independent_custody_proven
        || challenge.recovery_authorized
        || challenge.replacement_key_accepted
        || challenge.lock_cleared
    {
        return Err(Error("FREEZE152_CHALLENGE_UNTRUSTED"));
    }
    if substitution.schema != "sapphon-150-substitution-report-v1"
        || substitution.decision != "HOLD"
        || substitution.independent_custody_proven
        || substitution.replacement_key_accepted
        || substitution.lock_cleared
    {
        return Err(Error("FREEZE152_SUBSTITUTION_UNTRUSTED"));
    }
    let mut findings = vec![
        "CI_EXECUTION_NOT_ATTESTED".to_string(),
        "HISTORICAL_HASH_RUN_NOT_ATTESTED".to_string(),
        "EXTERNAL_CUSTODY_NOT_AUTHENTICATED".to_string(),
        "ANTI_ROLLBACK_NOT_AUTHENTICATED".to_string(),
    ];
    for f in &challenge.findings {
        findings.push(format!("CHALLENGE:{}", f.kind));
    }
    if substitution.state != crate::substitution150::SubstitutionState::AllLocalEvidenceMatches {
        findings.push(format!("SUBSTITUTION:{:?}", substitution.state));
    }
    findings.sort();
    findings.dedup();
    Ok(Qualification {
        schema: "sapphon-152-phase-xiii-freeze-v1".into(),
        source_manifest_sha256: manifest_digest(sources)?,
        source_design_complete: true,
        source_hashes_externally_pinned: false,
        rust_ci_pass_confirmed: false,
        historical_188_hash_pass_confirmed: false,
        pages_deployment_confirmed: false,
        independent_custody_authenticated: false,
        external_anti_rollback_authenticated: false,
        authenticated_utc: false,
        lock_cleared: false,
        recovery_authorized: false,
        findings,
        decision: "DESIGN_COMPLETE_QUALIFICATION_HOLD".into(),
    })
}
pub fn write_new(path: &Path, record: &Qualification) -> Result<String, Error> {
    if record.schema != "sapphon-152-phase-xiii-freeze-v1"
        || record.decision != "DESIGN_COMPLETE_QUALIFICATION_HOLD"
        || record.rust_ci_pass_confirmed
        || record.historical_188_hash_pass_confirmed
        || record.source_hashes_externally_pinned
        || record.pages_deployment_confirmed
        || record.independent_custody_authenticated
        || record.external_anti_rollback_authenticated
        || record.authenticated_utc
        || record.lock_cleared
        || record.recovery_authorized
    {
        return Err(Error("FREEZE152_AUTHORITY"));
    }
    let body = serde_json::to_vec(record).map_err(|_| Error("FREEZE152_ENCODING"))?;
    if body.len() > MAX {
        return Err(Error("FREEZE152_SIZE"));
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|_| Error("FREEZE152_EXISTS"))?;
    file.write_all(&body)
        .map_err(|_| Error("FREEZE152_WRITE"))?;
    file.sync_all().map_err(|_| Error("FREEZE152_FSYNC"))?;
    File::open(path.parent().ok_or(Error("FREEZE152_PARENT"))?)
        .and_then(|dir| dir.sync_all())
        .map_err(|_| Error("FREEZE152_DIRSYNC"))?;
    Ok(sha(&body))
}
pub fn verify_export(bytes: &[u8], expected: &str) -> Result<Qualification, Error> {
    if bytes.len() > MAX || !valid(expected) || sha(bytes) != expected {
        return Err(Error("FREEZE152_DIGEST"));
    }
    let rec: Qualification =
        serde_json::from_slice(bytes).map_err(|_| Error("FREEZE152_CORRUPT"))?;
    if rec.schema != "sapphon-152-phase-xiii-freeze-v1"
        || rec.decision != "DESIGN_COMPLETE_QUALIFICATION_HOLD"
        || !rec.source_design_complete
        || rec.source_hashes_externally_pinned
        || rec.rust_ci_pass_confirmed
        || rec.historical_188_hash_pass_confirmed
        || rec.pages_deployment_confirmed
        || rec.independent_custody_authenticated
        || rec.external_anti_rollback_authenticated
        || rec.authenticated_utc
        || rec.lock_cleared
        || rec.recovery_authorized
    {
        return Err(Error("FREEZE152_AUTHORITY"));
    }
    Ok(rec)
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{blind151::Finding, substitution150::SubstitutionState};
    fn sources() -> Vec<PhaseSource> {
        (145..=151)
            .map(|phase_bound| PhaseSource {
                phase_bound,
                relative_path: format!("rust/sapphon-liveness/src/bound{phase_bound}.rs"),
                expected_sha256: format!("{phase_bound:064x}"),
            })
            .collect()
    }
    fn challenge() -> ChallengeReport {
        ChallengeReport {
            schema: "sapphon-151-blind-challenge-v1".into(),
            challenge_id: "test".into(),
            packet_ids: vec![],
            findings: vec![Finding {
                kind: "SHARED_ANCESTRY".into(),
                left_id: "a".into(),
                right_id: "b".into(),
                detail: "same".into(),
            }],
            verified_signatures: 2,
            claimed_roots: 1,
            independent_custody_proven: false,
            recovery_authorized: false,
            replacement_key_accepted: false,
            lock_cleared: false,
            decision: "HOLD".into(),
        }
    }
    fn substitution() -> SubstitutionReport {
        SubstitutionReport {
            schema: "sapphon-150-substitution-report-v1".into(),
            state: SubstitutionState::RegistryRolledBack,
            observed_registry_sha256: "a".repeat(64),
            observed_intent_sha256: None,
            observed_provider_sha256: "b".repeat(64),
            trusted_provider_sha256: "c".repeat(64),
            trusted_registry_sha256: "d".repeat(64),
            trusted_intent_sha256: "e".repeat(64),
            signed_anchor_head: "f".repeat(64),
            signed_anchor_sequence: 1,
            provider_signature_verified: true,
            independent_custody_proven: false,
            replacement_key_accepted: false,
            lock_cleared: false,
            decision: "HOLD".into(),
        }
    }
    #[test]
    fn design_complete_never_certifies_software_or_authority() {
        let r = evaluate(&sources(), &challenge(), &substitution()).unwrap();
        assert!(r.source_design_complete);
        assert!(
            !r.rust_ci_pass_confirmed
                && !r.independent_custody_authenticated
                && !r.recovery_authorized
                && !r.lock_cleared
        );
        assert_eq!(r.decision, "DESIGN_COMPLETE_QUALIFICATION_HOLD");
    }
    #[test]
    fn challenge_conflicts_not_discarded() {
        let r = evaluate(&sources(), &challenge(), &substitution()).unwrap();
        assert!(r.findings.iter().any(|s| s == "CHALLENGE:SHARED_ANCESTRY"));
        assert!(r
            .findings
            .iter()
            .any(|s| s == "SUBSTITUTION:RegistryRolledBack"));
    }
    #[test]
    fn wrong_source_count_rejected() {
        let mut entries = sources();
        entries.pop();
        assert_eq!(
            manifest_digest(&entries).unwrap_err().0,
            "FREEZE152_SOURCE_COUNT"
        );
    }
    #[test]
    fn duplicate_source_bound_rejected() {
        let mut entries = sources();
        entries[1].phase_bound = 145;
        assert_eq!(
            manifest_digest(&entries).unwrap_err().0,
            "FREEZE152_SOURCE_FIELDS"
        );
    }
    #[test]
    fn spoofed_qualified_challenge_rejected() {
        let mut c = challenge();
        c.independent_custody_proven = true;
        assert_eq!(
            evaluate(&sources(), &c, &substitution()).unwrap_err().0,
            "FREEZE152_CHALLENGE_UNTRUSTED"
        );
    }
    #[test]
    fn create_only_digest_verified_hold_record() {
        let r = evaluate(&sources(), &challenge(), &substitution()).unwrap();
        let path = std::env::temp_dir().join(format!("sapphon152-{}.json", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let h = write_new(&path, &r).unwrap();
        let mut bytes = std::fs::read(&path).unwrap();
        assert_eq!(verify_export(&bytes, &h).unwrap(), r);
        assert_eq!(write_new(&path, &r).unwrap_err().0, "FREEZE152_EXISTS");
        bytes.push(b' ');
        assert_eq!(verify_export(&bytes, &h).unwrap_err().0, "FREEZE152_DIGEST");
        std::fs::remove_file(path).unwrap();
    }
}
