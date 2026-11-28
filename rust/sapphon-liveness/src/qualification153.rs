//! SAPPHON-153 — qualification evidence boundary for Phase XIV.
//! A claimed URL or successful status in a user-owned file is not GitHub
//! readback. This module is an observation ledger, NOT a CI certification API.
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
const LIMIT: usize = 1024 * 1024;
fn sha(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
fn sha_valid(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EvidenceKind {
    RustCi,
    HistoricalHashes,
    PagesDeployment,
    CustodyRoot,
    MonotonicAnchor,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReadbackState {
    NotObserved,
    ClaimedOnly,
    FailedReadback,
    ObservedSuccessful,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EvidenceClaim {
    pub kind: EvidenceKind,
    pub claimed_commit_sha: String,
    pub claimed_locator: String,
    pub readback: ReadbackState,
    pub independent_provenance: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Gate {
    pub schema: String,
    pub phase: u8,
    pub bound: u16,
    pub claims: Vec<EvidenceClaim>,
    pub witnessed_ci_pass: bool,
    pub witnessed_hash_pass: bool,
    pub witnessed_pages_deployment: bool,
    pub independent_custody_authenticated: bool,
    pub global_anti_rollback_authenticated: bool,
    pub recovery_authorized: bool,
    pub lock_cleared: bool,
    pub decision: String,
    pub packet_sha256: String,
}
/// Fail closed on unverifiable claims. No supplied EvidenceClaim may promote
/// an authority bit, even when it advertises ObservedSuccessful. A real
/// independent readback must be performed outside this source-owned ledger.
pub fn assess(claims: &[EvidenceClaim]) -> Result<Gate, Error> {
    if claims.len() != 5 {
        return Err(Error("QUAL153_CLAIM_COUNT"));
    }
    let mut kinds = BTreeSet::new();
    for c in claims {
        let code = match c.kind {
            EvidenceKind::RustCi => 0,
            EvidenceKind::HistoricalHashes => 1,
            EvidenceKind::PagesDeployment => 2,
            EvidenceKind::CustodyRoot => 3,
            EvidenceKind::MonotonicAnchor => 4,
        };
        if !kinds.insert(code)
            || c.claimed_commit_sha.len() != 40
            || !c
                .claimed_commit_sha
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || c.claimed_locator.len() > 2048
        {
            return Err(Error("QUAL153_CLAIM_FIELDS"));
        }
    }
    let mut sorted = claims.to_vec();
    sorted.sort_by_key(|c| match c.kind {
        EvidenceKind::RustCi => 0,
        EvidenceKind::HistoricalHashes => 1,
        EvidenceKind::PagesDeployment => 2,
        EvidenceKind::CustodyRoot => 3,
        EvidenceKind::MonotonicAnchor => 4,
    });
    let body = serde_json::to_vec(&sorted).map_err(|_| Error("QUAL153_ENCODING"))?;
    Ok(Gate {
        schema: "sapphon-153-phase-xiv-qualification-v1".into(),
        phase: 14,
        bound: 153,
        claims: sorted,
        witnessed_ci_pass: false,
        witnessed_hash_pass: false,
        witnessed_pages_deployment: false,
        independent_custody_authenticated: false,
        global_anti_rollback_authenticated: false,
        recovery_authorized: false,
        lock_cleared: false,
        decision: "OBSERVATION_ONLY_HOLD".into(),
        packet_sha256: sha(&body),
    })
}
pub fn verify_gate(bytes: &[u8], external_digest: &str) -> Result<Gate, Error> {
    if bytes.len() > LIMIT || !sha_valid(external_digest) || sha(bytes) != external_digest {
        return Err(Error("QUAL153_DIGEST"));
    }
    let g: Gate = serde_json::from_slice(bytes).map_err(|_| Error("QUAL153_CORRUPT"))?;
    if g.schema != "sapphon-153-phase-xiv-qualification-v1"
        || g.phase != 14
        || g.bound != 153
        || g.decision != "OBSERVATION_ONLY_HOLD"
        || g.witnessed_ci_pass
        || g.witnessed_hash_pass
        || g.witnessed_pages_deployment
        || g.independent_custody_authenticated
        || g.global_anti_rollback_authenticated
        || g.recovery_authorized
        || g.lock_cleared
    {
        return Err(Error("QUAL153_AUTHORITY"));
    }
    let expected = assess(&g.claims)?;
    if g != expected {
        return Err(Error("QUAL153_FIELDS"));
    }
    Ok(g)
}
pub fn write_new(path: &Path, record: &Gate) -> Result<String, Error> {
    if record != &assess(&record.claims)? {
        return Err(Error("QUAL153_FIELDS"));
    }
    let bytes = serde_json::to_vec(record).map_err(|_| Error("QUAL153_ENCODING"))?;
    if bytes.len() > LIMIT {
        return Err(Error("QUAL153_LIMIT"));
    }
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|_| Error("QUAL153_ALREADY_EXISTS"))?;
    f.write_all(&bytes).map_err(|_| Error("QUAL153_WRITE"))?;
    f.sync_all().map_err(|_| Error("QUAL153_FSYNC"))?;
    File::open(path.parent().ok_or(Error("QUAL153_PARENT"))?)
        .and_then(|dir| dir.sync_all())
        .map_err(|_| Error("QUAL153_DIRSYNC"))?;
    Ok(sha(&bytes))
}
#[cfg(test)]
mod tests {
    use super::*;
    fn claims() -> Vec<EvidenceClaim> {
        [
            EvidenceKind::RustCi,
            EvidenceKind::HistoricalHashes,
            EvidenceKind::PagesDeployment,
            EvidenceKind::CustodyRoot,
            EvidenceKind::MonotonicAnchor,
        ]
        .into_iter()
        .map(|kind| EvidenceClaim {
            kind,
            claimed_commit_sha: "a".repeat(40),
            claimed_locator: "https://github.com/example/fake".into(),
            readback: ReadbackState::NotObserved,
            independent_provenance: false,
        })
        .collect()
    }
    #[test]
    fn source_claims_never_grant_authority() {
        let g = assess(&claims()).unwrap();
        assert_eq!(g.decision, "OBSERVATION_ONLY_HOLD");
        assert!(
            !g.witnessed_ci_pass
                && !g.independent_custody_authenticated
                && !g.recovery_authorized
                && !g.lock_cleared
        );
    }
    #[test]
    fn self_reported_success_never_proves_ci() {
        let mut cs = claims();
        cs[0].readback = ReadbackState::ObservedSuccessful;
        cs[0].independent_provenance = true;
        let g = assess(&cs).unwrap();
        assert!(!g.witnessed_ci_pass && !g.witnessed_hash_pass);
    }
    #[test]
    fn duplicate_evidence_categories_rejected() {
        let mut cs = claims();
        cs[1].kind = EvidenceKind::RustCi;
        assert_eq!(assess(&cs).unwrap_err().0, "QUAL153_CLAIM_FIELDS");
    }
    #[test]
    fn order_independent_claim_digest() {
        let mut cs = claims();
        let a = assess(&cs).unwrap();
        cs.reverse();
        assert_eq!(a, assess(&cs).unwrap());
    }
    #[test]
    fn immutable_write_and_detected_tamper() {
        let g = assess(&claims()).unwrap();
        let path = std::env::temp_dir().join(format!("sapphon153-{}.json", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let h = write_new(&path, &g).unwrap();
        let mut body = std::fs::read(&path).unwrap();
        assert_eq!(verify_gate(&body, &h).unwrap(), g);
        assert_eq!(
            write_new(&path, &g).unwrap_err().0,
            "QUAL153_ALREADY_EXISTS"
        );
        body.push(b' ');
        assert_eq!(verify_gate(&body, &h).unwrap_err().0, "QUAL153_DIGEST");
        std::fs::remove_file(path).unwrap();
    }
    #[test]
    fn forged_authority_flags_rejected_even_with_updated_digest() {
        let mut g = assess(&claims()).unwrap();
        g.witnessed_ci_pass = true;
        let data = serde_json::to_vec(&g).unwrap();
        assert_eq!(
            verify_gate(&data, &sha(&data)).unwrap_err().0,
            "QUAL153_AUTHORITY"
        );
    }
}
