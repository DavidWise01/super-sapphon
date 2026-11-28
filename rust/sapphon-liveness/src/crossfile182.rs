//! SAPPHON-182: cross-file provenance findings, no archive execution.
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
const SOURCE: &str = "dd1d778c522aa18fb399c052958f05c4f5b02dd9";
const FILES: [&str; 3] = [
    "180-summary.json",
    "180-binding.json",
    "180-predecessor.json",
];
fn hash(b: &[u8]) -> String {
    hex::encode(Sha256::digest(b))
}
fn valid_sha(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    pub name: String,
    pub size: u64,
    pub crc32: String,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Inspection {
    pub schema: String,
    pub source_sha: String,
    pub artifact_sha256: String,
    pub entries: Vec<Entry>,
    pub findings: Vec<String>,
    pub archive_records_structurally_consistent: bool,
    pub complete_predecessor_and_raw_byte_evidence: bool,
    pub disk_extraction_performed: bool,
    pub archive_code_executed: bool,
    pub independent_custody_authenticated: bool,
    pub global_anti_rollback_authenticated: bool,
    pub recovery_authorized: bool,
    pub lock_cleared: bool,
    pub decision: String,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Finding {
    pub schema: String,
    pub observation_digest: String,
    pub source_consistency: bool,
    pub complete_owned_evidence: bool,
    pub blockers: Vec<String>,
    pub independent_custody_authenticated: bool,
    pub recovery_authorized: bool,
    pub lock_cleared: bool,
    pub decision: String,
}
pub fn assess(i: &Inspection) -> Result<Finding, Error> {
    let mut bad = Vec::new();
    if i.schema != "sapphon-182-cross-file-v1"
        || i.source_sha != SOURCE
        || !valid_sha(&i.artifact_sha256)
    {
        bad.push("ANCESTRY_OR_DIGEST".to_string());
    }
    let names = i
        .entries
        .iter()
        .map(|e| e.name.as_str())
        .collect::<BTreeSet<_>>();
    if names.len() != 3 || FILES.iter().any(|name| !names.contains(name)) {
        bad.push("REQUIRED_FILE_SET".into());
    }
    if i.entries.len() != 3 || i.entries.iter().any(|x| x.size > 2 * 1024 * 1024) {
        bad.push("ENTRY_LIMIT".into());
    }
    if !i.findings.is_empty() || !i.archive_records_structurally_consistent {
        bad.push("CROSS_FILE_INCONSISTENCY".into());
    }
    if i.complete_predecessor_and_raw_byte_evidence && !i.archive_records_structurally_consistent {
        bad.push("CONTRADICTORY_COMPLETENESS".into());
    }
    if i.disk_extraction_performed
        || i.archive_code_executed
        || i.independent_custody_authenticated
        || i.global_anti_rollback_authenticated
        || i.recovery_authorized
        || i.lock_cleared
    {
        bad.push("AUTHORITY_OR_EXECUTION".into());
    }
    bad.sort();
    bad.dedup();
    let bytes = serde_json::to_vec(i).map_err(|_| Error("CROSS182_JSON"))?;
    Ok(Finding {
        schema: "sapphon-182-rust-crossfile-v1".into(),
        observation_digest: hash(&bytes),
        source_consistency: bad.is_empty(),
        complete_owned_evidence: bad.is_empty() && i.complete_predecessor_and_raw_byte_evidence,
        blockers: bad,
        independent_custody_authenticated: false,
        recovery_authorized: false,
        lock_cleared: false,
        decision: "CROSS_FILE_PROVENANCE_HOLD".into(),
    })
}
pub fn write_new(path: &Path, f: &Finding) -> Result<String, Error> {
    if f.schema != "sapphon-182-rust-crossfile-v1"
        || f.decision != "CROSS_FILE_PROVENANCE_HOLD"
        || f.independent_custody_authenticated
        || f.recovery_authorized
        || f.lock_cleared
    {
        return Err(Error("CROSS182_AUTHORITY"));
    }
    let bytes = serde_json::to_vec(f).map_err(|_| Error("CROSS182_JSON"))?;
    let mut handle = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)
        .map_err(|_| Error("CROSS182_EXISTS"))?;
    handle
        .write_all(&bytes)
        .map_err(|_| Error("CROSS182_WRITE"))?;
    handle.sync_all().map_err(|_| Error("CROSS182_SYNC"))?;
    File::open(path.parent().ok_or(Error("CROSS182_PARENT"))?)
        .and_then(|p| p.sync_all())
        .map_err(|_| Error("CROSS182_DIRSYNC"))?;
    Ok(hash(&bytes))
}
#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> Inspection {
        Inspection {
            schema: "sapphon-182-cross-file-v1".into(),
            source_sha: SOURCE.into(),
            artifact_sha256: "a".repeat(64),
            entries: FILES
                .iter()
                .map(|x| Entry {
                    name: (*x).into(),
                    size: 200,
                    crc32: "01234567".into(),
                })
                .collect(),
            findings: vec![],
            archive_records_structurally_consistent: true,
            complete_predecessor_and_raw_byte_evidence: false,
            disk_extraction_performed: false,
            archive_code_executed: false,
            independent_custody_authenticated: false,
            global_anti_rollback_authenticated: false,
            recovery_authorized: false,
            lock_cleared: false,
            decision: "CROSS_FILE_PROVENANCE_HOLD".into(),
        }
    }
    #[test]
    fn structural_pass_does_not_promote() {
        let f = assess(&fixture()).unwrap();
        assert!(f.source_consistency && !f.complete_owned_evidence && !f.recovery_authorized);
    }
    #[test]
    fn missing_record_blocks() {
        let mut x = fixture();
        x.entries.pop();
        assert!(!assess(&x).unwrap().source_consistency);
    }
    #[test]
    fn mismatched_source_blocks() {
        let mut x = fixture();
        x.source_sha = "b".repeat(40);
        assert!(!assess(&x).unwrap().source_consistency);
    }
    #[test]
    fn findings_block() {
        let mut x = fixture();
        x.findings.push("SUMMARY_CONFLICT".into());
        assert!(!assess(&x).unwrap().source_consistency);
    }
    #[test]
    fn extraction_blocks() {
        let mut x = fixture();
        x.disk_extraction_performed = true;
        assert!(!assess(&x).unwrap().source_consistency);
    }
    #[test]
    fn complete_owned_evidence_still_hold() {
        let mut x = fixture();
        x.complete_predecessor_and_raw_byte_evidence = true;
        let r = assess(&x).unwrap();
        assert!(r.complete_owned_evidence && !r.recovery_authorized);
    }
    #[test]
    fn create_only() {
        let f = assess(&fixture()).unwrap();
        let p = std::env::temp_dir().join(format!("sapphon182-{}.json", std::process::id()));
        let _ = std::fs::remove_file(&p);
        write_new(&p, &f).unwrap();
        assert_eq!(write_new(&p, &f).unwrap_err().0, "CROSS182_EXISTS");
        std::fs::remove_file(p).unwrap();
    }
}
