//! SAPPHON-163 — pinned deployed asset comparison, observation only.
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
fn sha(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}
fn hex40(v: &str) -> bool {
    v.len() == 40
        && v.bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}
fn hex64(v: &str) -> bool {
    v.len() == 64
        && v.bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Asset {
    pub label: String,
    pub source_sha256: String,
    pub deployed_sha256: String,
    pub source_bytes: u64,
    pub deployed_bytes: u64,
    pub http_status: u16,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Review {
    pub schema: String,
    pub source_commit: String,
    pub matched: Vec<String>,
    pub mismatched: Vec<String>,
    pub missing: Vec<String>,
    pub asset_set_digest: String,
    pub source_owned_pages_match: bool,
    pub runner_observation_authenticated: bool,
    pub independent_custody_authenticated: bool,
    pub recovery_authorized: bool,
    pub lock_cleared: bool,
    pub decision: String,
}
const REQUIRED: [&str; 3] = ["SAPPHON-160", "SAPPHON-161", "SAPPHON-162"];
pub fn inspect(source_commit: &str, assets: &[Asset]) -> Result<Review, Error> {
    if !hex40(source_commit) || assets.len() > 8 {
        return Err(Error("ASSET163_FIELDS"));
    }
    let mut seen = BTreeSet::new();
    let mut matched = vec![];
    let mut mismatched = vec![];
    for a in assets {
        if !REQUIRED.contains(&a.label.as_str())
            || !seen.insert(a.label.as_str())
            || !hex64(&a.source_sha256)
            || !hex64(&a.deployed_sha256)
        {
            return Err(Error("ASSET163_ASSET_FIELDS"));
        }
        if a.source_sha256 == a.deployed_sha256
            && a.source_bytes == a.deployed_bytes
            && a.http_status == 200
        {
            matched.push(a.label.clone());
        } else {
            mismatched.push(a.label.clone());
        }
    }
    let missing = REQUIRED
        .iter()
        .filter(|x| !seen.contains(*x))
        .map(|x| (*x).to_owned())
        .collect::<Vec<_>>();
    matched.sort();
    mismatched.sort();
    let mut sorted = assets.to_vec();
    sorted.sort_by(|a, b| a.label.cmp(&b.label));
    let b = serde_json::to_vec(&sorted).map_err(|_| Error("ASSET163_ENCODING"))?;
    Ok(Review {
        schema: "sapphon-163-asset-review-v1".into(),
        source_commit: source_commit.to_owned(),
        source_owned_pages_match: missing.is_empty() && mismatched.is_empty(),
        matched,
        mismatched,
        missing,
        asset_set_digest: sha(&b),
        runner_observation_authenticated: false,
        independent_custody_authenticated: false,
        recovery_authorized: false,
        lock_cleared: false,
        decision: "PINNED_ASSET_HOLD".into(),
    })
}
pub fn write_new(path: &Path, report: &Review) -> Result<String, Error> {
    if report.schema != "sapphon-163-asset-review-v1"
        || report.decision != "PINNED_ASSET_HOLD"
        || report.runner_observation_authenticated
        || report.independent_custody_authenticated
        || report.recovery_authorized
        || report.lock_cleared
    {
        return Err(Error("ASSET163_AUTHORITY"));
    }
    let b = serde_json::to_vec(report).map_err(|_| Error("ASSET163_ENCODING"))?;
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|_| Error("ASSET163_EXISTS"))?;
    f.write_all(&b).map_err(|_| Error("ASSET163_WRITE"))?;
    f.sync_all().map_err(|_| Error("ASSET163_FSYNC"))?;
    File::open(path.parent().ok_or(Error("ASSET163_PARENT"))?)
        .and_then(|d| d.sync_all())
        .map_err(|_| Error("ASSET163_DIRSYNC"))?;
    Ok(sha(&b))
}
#[cfg(test)]
mod tests {
    use super::*;
    fn entries() -> Vec<Asset> {
        REQUIRED
            .into_iter()
            .map(|n| Asset {
                label: n.into(),
                source_sha256: "a".repeat(64),
                deployed_sha256: "a".repeat(64),
                source_bytes: 100,
                deployed_bytes: 100,
                http_status: 200,
            })
            .collect()
    }
    #[test]
    fn source_parity_does_not_grant_custody() {
        let r = inspect(&"a".repeat(40), &entries()).unwrap();
        assert!(r.source_owned_pages_match);
        assert!(!r.independent_custody_authenticated && !r.recovery_authorized);
    }
    #[test]
    fn one_changed_byte_hash_fails() {
        let mut e = entries();
        e[1].deployed_sha256 = "b".repeat(64);
        assert_eq!(
            inspect(&"a".repeat(40), &e).unwrap().mismatched,
            vec!["SAPPHON-161"]
        );
    }
    #[test]
    fn missing_page_cannot_pass() {
        let mut e = entries();
        e.pop();
        assert!(
            !inspect(&"a".repeat(40), &e)
                .unwrap()
                .source_owned_pages_match
        );
    }
    #[test]
    fn http_failure_cannot_pass() {
        let mut e = entries();
        e[0].http_status = 404;
        assert!(
            !inspect(&"a".repeat(40), &e)
                .unwrap()
                .source_owned_pages_match
        );
    }
    #[test]
    fn duplicate_asset_rejected() {
        let mut e = entries();
        e.push(e[0].clone());
        assert_eq!(
            inspect(&"a".repeat(40), &e).unwrap_err().0,
            "ASSET163_ASSET_FIELDS"
        );
    }
    #[test]
    fn order_independent_digest() {
        let x = entries();
        let mut y = x.clone();
        y.reverse();
        assert_eq!(
            inspect(&"a".repeat(40), &x).unwrap(),
            inspect(&"a".repeat(40), &y).unwrap()
        );
    }
    #[test]
    fn create_only_record_prevents_overwrite() {
        let r = inspect(&"a".repeat(40), &entries()).unwrap();
        let p = std::env::temp_dir().join(format!("sapphon163-{}.json", std::process::id()));
        let _ = std::fs::remove_file(&p);
        write_new(&p, &r).unwrap();
        assert_eq!(write_new(&p, &r).unwrap_err().0, "ASSET163_EXISTS");
        std::fs::remove_file(p).unwrap();
    }
}
