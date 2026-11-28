//! SAPPHON-167 — bounded source lock promotion review, observation only.
//! A verified source-owned candidate is NOT an externally authenticated custodian.
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
fn digest(b: &[u8]) -> String {
    hex::encode(Sha256::digest(b))
}
fn h64(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn h40(s: &str) -> bool {
    s.len() == 40
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Candidate {
    pub schema: String,
    pub prior_run_commit: String,
    pub reviewer_commit: String,
    pub run_id: u64,
    pub attempt: u32,
    pub source_candidate_sha256: String,
    pub observed_candidate_sha256: String,
    pub registry_metadata_present: bool,
    pub prior_review_passed: bool,
    pub provenance_shared_with_github: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Review {
    pub schema: String,
    pub byte_identity_matched: bool,
    pub predecessor_ancestry_consistent: bool,
    pub candidate_review_eligible: bool,
    pub source_lock_replaced: bool,
    pub npm_archive_bytes_verified: bool,
    pub external_custody_authenticated: bool,
    pub global_anti_rollback_authenticated: bool,
    pub recovery_authorized: bool,
    pub lock_cleared: bool,
    pub decision: String,
    pub review_sha256: String,
}
pub fn inspect(c: &Candidate) -> Result<Review, Error> {
    if c.schema != "sapphon-167-lock-promotion-input-v1"
        || !h40(&c.prior_run_commit)
        || !h40(&c.reviewer_commit)
        || !h64(&c.source_candidate_sha256)
        || !h64(&c.observed_candidate_sha256)
        || c.run_id == 0
        || c.attempt == 0
    {
        return Err(Error("PROM167_FIELDS"));
    }
    let matched = c.source_candidate_sha256 == c.observed_candidate_sha256;
    let valid_prior = c.prior_review_passed && c.provenance_shared_with_github;
    let eligible = matched && valid_prior && c.registry_metadata_present;
    let bytes = serde_json::to_vec(c).map_err(|_| Error("PROM167_ENCODING"))?;
    Ok(Review {
        schema: "sapphon-167-lock-promotion-review-v1".into(),
        byte_identity_matched: matched,
        predecessor_ancestry_consistent: valid_prior,
        candidate_review_eligible: eligible,
        source_lock_replaced: false,
        npm_archive_bytes_verified: false,
        external_custody_authenticated: false,
        global_anti_rollback_authenticated: false,
        recovery_authorized: false,
        lock_cleared: false,
        decision: "LOCK_REVIEW_HOLD".into(),
        review_sha256: digest(&bytes),
    })
}
pub fn write_new(path: &Path, r: &Review) -> Result<String, Error> {
    if r.schema != "sapphon-167-lock-promotion-review-v1"
        || r.decision != "LOCK_REVIEW_HOLD"
        || r.source_lock_replaced
        || r.npm_archive_bytes_verified
        || r.external_custody_authenticated
        || r.global_anti_rollback_authenticated
        || r.recovery_authorized
        || r.lock_cleared
    {
        return Err(Error("PROM167_AUTHORITY"));
    }
    let b = serde_json::to_vec(r).map_err(|_| Error("PROM167_ENCODING"))?;
    if b.len() > 1024 * 1024 {
        return Err(Error("PROM167_SIZE"));
    }
    let mut f = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)
        .map_err(|_| Error("PROM167_EXISTS"))?;
    f.write_all(&b).map_err(|_| Error("PROM167_WRITE"))?;
    f.sync_all().map_err(|_| Error("PROM167_FSYNC"))?;
    File::open(path.parent().ok_or(Error("PROM167_PARENT"))?)
        .and_then(|p| p.sync_all())
        .map_err(|_| Error("PROM167_DIRSYNC"))?;
    Ok(digest(&b))
}
#[cfg(test)]
mod tests {
    use super::*;
    fn input() -> Candidate {
        Candidate {
            schema: "sapphon-167-lock-promotion-input-v1".into(),
            prior_run_commit: "a".repeat(40),
            reviewer_commit: "b".repeat(40),
            run_id: 123,
            attempt: 2,
            source_candidate_sha256: "c".repeat(64),
            observed_candidate_sha256: "c".repeat(64),
            registry_metadata_present: true,
            prior_review_passed: true,
            provenance_shared_with_github: true,
        }
    }
    #[test]
    fn eligible_cannot_authorize() {
        let o = inspect(&input()).unwrap();
        assert!(o.candidate_review_eligible);
        assert!(
            !o.source_lock_replaced
                && !o.npm_archive_bytes_verified
                && !o.recovery_authorized
                && !o.lock_cleared
        );
    }
    #[test]
    fn digest_mismatch_blocks() {
        let mut c = input();
        c.observed_candidate_sha256 = "d".repeat(64);
        let o = inspect(&c).unwrap();
        assert!(!o.byte_identity_matched && !o.candidate_review_eligible);
    }
    #[test]
    fn missing_registry_metadata_blocks() {
        let mut c = input();
        c.registry_metadata_present = false;
        assert!(!inspect(&c).unwrap().candidate_review_eligible);
    }
    #[test]
    fn missing_prior_review_blocks() {
        let mut c = input();
        c.prior_review_passed = false;
        assert!(!inspect(&c).unwrap().candidate_review_eligible);
    }
    #[test]
    fn false_independent_provenance_blocks() {
        let mut c = input();
        c.provenance_shared_with_github = false;
        assert!(!inspect(&c).unwrap().candidate_review_eligible);
    }
    #[test]
    fn invalid_run_rejected() {
        let mut c = input();
        c.attempt = 0;
        assert_eq!(inspect(&c).unwrap_err().0, "PROM167_FIELDS");
    }
    #[test]
    fn deterministic_evidence_digest() {
        assert_eq!(inspect(&input()).unwrap(), inspect(&input()).unwrap());
    }
    #[test]
    fn forged_recovery_review_rejected() {
        let mut r = inspect(&input()).unwrap();
        r.recovery_authorized = true;
        let p = std::env::temp_dir().join(format!("sapphon167-forged-{}.json", std::process::id()));
        assert_eq!(write_new(&p, &r).unwrap_err().0, "PROM167_AUTHORITY");
    }
    #[test]
    fn create_only_output() {
        let r = inspect(&input()).unwrap();
        let p = std::env::temp_dir().join(format!("sapphon167-{}.json", std::process::id()));
        let _ = std::fs::remove_file(&p);
        write_new(&p, &r).unwrap();
        assert_eq!(write_new(&p, &r).unwrap_err().0, "PROM167_EXISTS");
        std::fs::remove_file(p).unwrap();
    }
}
