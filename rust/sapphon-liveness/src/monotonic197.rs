//! SAPPHON-197 append-only original-byte readback sequence and source-owned forks.
#![cfg(target_os = "linux")]
use crate::Error;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{File, OpenOptions},
    io::Write,
    path::Path,
};
pub const AUTHORITY: &str = "HOLD";
const SOURCE: &str = "56d66ad2390063f08e33872299eebe6c8d78a8fe";
fn digest(b: &[u8]) -> String {
    hex::encode(Sha256::digest(b))
}
fn hex64(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Observation {
    pub source_sha: String,
    pub original_run_id: Option<u64>,
    pub original_attempt: Option<u32>,
    pub state: String,
    pub log_sha256: Option<String>,
    pub zip_sha256: Option<String>,
    pub bytes_reacquired: bool,
    pub external_custody_claim: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    pub sequence: u32,
    pub previous_sha256: String,
    pub observation: Observation,
    pub sha256: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Finding {
    pub schema: String,
    pub tip_sha256: String,
    pub entries: usize,
    pub source_owned_forks: Vec<String>,
    pub unavailable: usize,
    pub independent_witnesses: u8,
    pub authenticated_utc: bool,
    pub global_anti_rollback_authenticated: bool,
    pub recovery_authorized: bool,
    pub lock_cleared: bool,
    pub decision: String,
}
fn envelope_digest(sequence: u32, previous: &str, o: &Observation) -> Result<String, Error> {
    let data =
        serde_json::to_vec(&(sequence, previous, o)).map_err(|_| Error("LEDGER197_ENCODING"))?;
    Ok(digest(&data))
}
fn check_observation(o: &Observation) -> Result<(), Error> {
    if o.source_sha != SOURCE || o.external_custody_claim {
        return Err(Error("LEDGER197_AUTHORITY"));
    }
    let observed = [
        "GITHUB_OWNED_HASH_MATCH",
        "GITHUB_OWNED_READBACK_EQUIVOCATION",
    ]
    .contains(&o.state.as_str());
    if observed {
        if !o.bytes_reacquired
            || o.original_run_id.is_none_or(|v| v == 0)
            || o.original_attempt.is_none_or(|v| v == 0)
            || o.log_sha256.as_deref().is_none_or(|v| !hex64(v))
            || o.zip_sha256.as_deref().is_none_or(|v| !hex64(v))
        {
            return Err(Error("LEDGER197_OBSERVED_BYTES"));
        }
    } else {
        if ![
            "READBACK_UNAVAILABLE",
            "NOT_OBSERVED",
            "193_ARTIFACT_EXPIRED",
            "193_ARTIFACT_EXPIRY_UNKNOWN",
            "193_LOG_DOWNLOAD_FAILED",
            "193_ZIP_DOWNLOAD_FAILED",
            "195_RUN_NOT_FOUND",
        ]
        .contains(&o.state.as_str())
            || o.bytes_reacquired
            || o.log_sha256.is_some()
            || o.zip_sha256.is_some()
        {
            return Err(Error("LEDGER197_UNOBSERVED_BYTES"));
        }
        if o.original_run_id.is_some() != o.original_attempt.is_some()
            || o.original_run_id.is_some_and(|v| v == 0)
            || o.original_attempt.is_some_and(|v| v == 0)
        {
            return Err(Error("LEDGER197_RUN"));
        }
    }
    Ok(())
}
pub fn validate(items: &[Entry]) -> Result<Finding, Error> {
    if items.len() > 10000 {
        return Err(Error("LEDGER197_LIMIT"));
    }
    let mut previous = "0".repeat(64);
    let mut first = BTreeMap::<(u64, u32), (String, String)>::new();
    let mut forks = Vec::new();
    let mut unavailable = 0;
    for (i, item) in items.iter().enumerate() {
        check_observation(&item.observation)?;
        if item.sequence as usize != i + 1
            || item.previous_sha256 != previous
            || item.sha256 != envelope_digest(item.sequence, &previous, &item.observation)?
        {
            return Err(Error("LEDGER197_CHAIN_BROKEN"));
        }
        let o = &item.observation;
        if o.bytes_reacquired {
            let key = (o.original_run_id.unwrap(), o.original_attempt.unwrap());
            let hashes = (o.log_sha256.clone().unwrap(), o.zip_sha256.clone().unwrap());
            if let Some(first_hashes) = first.get(&key) {
                if first_hashes != &hashes {
                    forks.push(format!(
                        "SAME_ORIGINAL_ATTEMPT_FORK:{}:{}:{}",
                        key.0, key.1, item.sequence
                    ));
                }
            } else {
                first.insert(key, hashes);
            }
        } else {
            unavailable += 1;
        }
        previous = item.sha256.clone();
    }
    Ok(Finding {
        schema: "sapphon-197-rust-monotonic-ledger-v1".into(),
        tip_sha256: previous,
        entries: items.len(),
        source_owned_forks: forks,
        unavailable,
        independent_witnesses: 0,
        authenticated_utc: false,
        global_anti_rollback_authenticated: false,
        recovery_authorized: false,
        lock_cleared: false,
        decision: "MONOTONIC_READBACK_EVIDENCE_HOLD".into(),
    })
}
pub fn append(previous: &[Entry], observed: Observation) -> Result<Vec<Entry>, Error> {
    let result = validate(previous)?;
    check_observation(&observed)?;
    if previous.len() >= 10000 {
        return Err(Error("LEDGER197_LIMIT"));
    }
    let sequence = (previous.len() + 1) as u32;
    let hash = envelope_digest(sequence, &result.tip_sha256, &observed)?;
    let mut entries = previous.to_vec();
    entries.push(Entry {
        sequence,
        previous_sha256: result.tip_sha256,
        observation: observed,
        sha256: hash,
    });
    Ok(entries)
}
pub fn write_new(path: &Path, report: &Finding) -> Result<String, Error> {
    if report.schema != "sapphon-197-rust-monotonic-ledger-v1"
        || report.decision != "MONOTONIC_READBACK_EVIDENCE_HOLD"
        || report.independent_witnesses != 0
        || report.authenticated_utc
        || report.global_anti_rollback_authenticated
        || report.recovery_authorized
        || report.lock_cleared
    {
        return Err(Error("LEDGER197_AUTHORITY"));
    }
    let bytes = serde_json::to_vec(report).map_err(|_| Error("LEDGER197_ENCODING"))?;
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)
        .map_err(|_| Error("LEDGER197_EXISTS"))?;
    file.write_all(&bytes)
        .map_err(|_| Error("LEDGER197_WRITE"))?;
    file.sync_all().map_err(|_| Error("LEDGER197_SYNC"))?;
    File::open(path.parent().ok_or(Error("LEDGER197_PARENT"))?)
        .and_then(|f| f.sync_all())
        .map_err(|_| Error("LEDGER197_DIRSYNC"))?;
    Ok(digest(&bytes))
}
#[cfg(test)]
mod tests {
    use super::*;
    fn o() -> Observation {
        Observation {
            source_sha: SOURCE.into(),
            original_run_id: Some(193),
            original_attempt: Some(2),
            state: "GITHUB_OWNED_HASH_MATCH".into(),
            log_sha256: Some("a".repeat(64)),
            zip_sha256: Some("b".repeat(64)),
            bytes_reacquired: true,
            external_custody_claim: false,
        }
    }
    #[test]
    fn matching_observations_only_owned() {
        let v = append(&[], o()).unwrap();
        let r = validate(&append(&v, o()).unwrap()).unwrap();
        assert!(r.source_owned_forks.is_empty() && !r.recovery_authorized);
    }
    #[test]
    fn changed_log_forks() {
        let x = append(&[], o()).unwrap();
        let mut y = o();
        y.log_sha256 = Some("c".repeat(64));
        assert_eq!(
            validate(&append(&x, y).unwrap())
                .unwrap()
                .source_owned_forks
                .len(),
            1
        );
    }
    #[test]
    fn changed_zip_forks() {
        let x = append(&[], o()).unwrap();
        let mut y = o();
        y.zip_sha256 = Some("c".repeat(64));
        assert_eq!(
            validate(&append(&x, y).unwrap())
                .unwrap()
                .source_owned_forks
                .len(),
            1
        );
    }
    #[test]
    fn different_attempt_not_fork() {
        let x = append(&[], o()).unwrap();
        let mut y = o();
        y.original_attempt = Some(3);
        y.log_sha256 = Some("c".repeat(64));
        assert!(validate(&append(&x, y).unwrap())
            .unwrap()
            .source_owned_forks
            .is_empty());
    }
    #[test]
    fn expired_not_a_fork() {
        let x = append(&[], o()).unwrap();
        let mut y = o();
        y.state = "193_ARTIFACT_EXPIRED".into();
        y.bytes_reacquired = false;
        y.log_sha256 = None;
        y.zip_sha256 = None;
        let r = validate(&append(&x, y).unwrap()).unwrap();
        assert_eq!(r.unavailable, 1);
        assert!(r.source_owned_forks.is_empty());
    }
    #[test]
    fn altered_history_refused() {
        let mut x = append(&[], o()).unwrap();
        x[0].observation.log_sha256 = Some("d".repeat(64));
        assert_eq!(validate(&x).unwrap_err().0, "LEDGER197_CHAIN_BROKEN");
    }
    #[test]
    fn forged_custody_refused() {
        let mut x = o();
        x.external_custody_claim = true;
        assert_eq!(append(&[], x).unwrap_err().0, "LEDGER197_AUTHORITY");
    }
    #[test]
    fn create_only() {
        let report = validate(&[]).unwrap();
        let p = std::env::temp_dir().join(format!("sapphon197-{}.json", std::process::id()));
        let _ = std::fs::remove_file(&p);
        write_new(&p, &report).unwrap();
        assert_eq!(write_new(&p, &report).unwrap_err().0, "LEDGER197_EXISTS");
        std::fs::remove_file(p).unwrap();
    }
}
