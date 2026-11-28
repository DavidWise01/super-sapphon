//! SAPPHON-142 — deterministic evidence package and independent-source screening.
//! An exported digest and signed receipts do not establish physical independence.
//! No automatic repair, trusted anchor update, recovery authorization or lock removal.
#![cfg(target_os = "linux")]
use crate::{
    attest136::TrustedKey, checkpoint140::CheckpointReceipt, equivocation141::History, registry137,
    Error,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{File, OpenOptions},
    io::Write,
    path::Path,
};

pub const AUTHORITY: &str = "HOLD";
const MAX_EXPORT: usize = 1024 * 1024;
fn hash(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
fn valid_hash(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RootClaim {
    pub witness_id: String,
    pub ancestry_root: String,
    pub custodian_id: String,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Conflict {
    pub witness_id: String,
    pub seq: u64,
    pub left_head: String,
    pub right_head: String,
    pub code: String,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Evidence {
    pub schema: String,
    pub registry_seq: u64,
    pub registry_head: String,
    pub history_before_sha256: String,
    pub history_after_sha256: String,
    pub claims: Vec<RootClaim>,
    pub receipts: Vec<CheckpointReceipt>,
    pub conflicts: Vec<Conflict>,
    pub authority: String,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportResult {
    pub sha256: String,
    pub bytes: usize,
    pub decision: &'static str,
    pub independent_custody_proven: bool,
    pub lock_cleared: bool,
}
fn conflicts(history: &History, receipts: &[CheckpointReceipt]) -> Vec<Conflict> {
    let mut heads: BTreeMap<(String, u64), String> = BTreeMap::new();
    let mut out = Vec::new();
    for e in &history.entries {
        heads.insert((e.witness_id.clone(), e.seq), e.head.clone());
    }
    for r in receipts {
        let key = (r.witness_id.clone(), r.seq);
        if let Some(old) = heads.get(&key) {
            if old != &r.head {
                out.push(Conflict {
                    witness_id: r.witness_id.clone(),
                    seq: r.seq,
                    left_head: old.clone(),
                    right_head: r.head.clone(),
                    code: "EQUIVOCATION".into(),
                });
            }
        } else {
            heads.insert(key, r.head.clone());
        }
    }
    out.sort_by(|a, b| {
        a.witness_id
            .cmp(&b.witness_id)
            .then(a.seq.cmp(&b.seq))
            .then(a.right_head.cmp(&b.right_head))
    });
    out.dedup();
    out
}
/// Refuse to produce an apparently clean export if any source conflicts.
/// The prior history digest is caller-supplied, not independently authenticated
/// in this library. A separate custodian must preserve the package digest.
pub fn assemble(
    history: &History,
    trusted_history_digest: &str,
    registry_bytes: &[u8],
    registry_seq: u64,
    registry_head: &str,
    keys: &[TrustedKey],
    receipts: &[CheckpointReceipt],
    claims: &[RootClaim],
) -> Result<(Evidence, ExportResult), Error> {
    if history.digest()? != trusted_history_digest || !valid_hash(trusted_history_digest) {
        return Err(Error("EXPORT_HISTORY_ANCHOR"));
    }
    registry137::verify(registry_bytes, registry_seq, registry_head)?;
    if receipts.len() > 32 || claims.len() > 32 || keys.len() > 32 {
        return Err(Error("EXPORT_LIMIT"));
    }
    let mut keyed = BTreeMap::new();
    for k in keys {
        if keyed.insert(k.witness_id.as_str(), k).is_some() {
            return Err(Error("EXPORT_DUPLICATE_KEY"));
        }
    }
    let mut roots = BTreeSet::new();
    let mut custodians = BTreeSet::new();
    let mut witness_ids = BTreeSet::new();
    for claim in claims {
        if claim.witness_id.is_empty()
            || claim.ancestry_root.is_empty()
            || claim.custodian_id.is_empty()
            || !roots.insert(claim.ancestry_root.as_str())
            || !custodians.insert(claim.custodian_id.as_str())
            || !witness_ids.insert(claim.witness_id.as_str())
        {
            return Err(Error("EXPORT_SHARED_ANCESTRY"));
        }
        let k = keyed
            .get(claim.witness_id.as_str())
            .ok_or(Error("EXPORT_UNKNOWN_WITNESS"))?;
        if k.ancestry_root != claim.ancestry_root {
            return Err(Error("EXPORT_ANCESTRY_MISMATCH"));
        }
    }
    if receipts
        .iter()
        .any(|r| !witness_ids.contains(r.witness_id.as_str()))
    {
        return Err(Error("EXPORT_MISSING_CUSTODY_CLAIM"));
    }
    let findings = conflicts(history, receipts);
    if !findings.is_empty() {
        return Err(Error("EXPORT_EQUIVOCATION"));
    }
    // Validates all receipt signatures and counter floors through SAPPHON-141.
    let (new_history, _screen) = history.append_verified(trusted_history_digest, keys, receipts)?;
    let mut ordered_receipts = receipts.to_vec();
    ordered_receipts.sort_by(|a, b| a.witness_id.cmp(&b.witness_id).then(a.seq.cmp(&b.seq)));
    let mut ordered_claims = claims.to_vec();
    ordered_claims.sort_by(|a, b| a.witness_id.cmp(&b.witness_id));
    let package = Evidence {
        schema: "sapphon-142-evidence-v1".into(),
        registry_seq,
        registry_head: registry_head.into(),
        history_before_sha256: trusted_history_digest.into(),
        history_after_sha256: new_history.digest()?,
        claims: ordered_claims,
        receipts: ordered_receipts,
        conflicts: findings,
        authority: "HOLD".into(),
    };
    let bytes = serde_json::to_vec(&package).map_err(|_| Error("EXPORT_ENCODING"))?;
    if bytes.len() > MAX_EXPORT {
        return Err(Error("EXPORT_TOO_LARGE"));
    }
    let result = ExportResult {
        sha256: hash(&bytes),
        bytes: bytes.len(),
        decision: "HOLD",
        independent_custody_proven: false,
        lock_cleared: false,
    };
    Ok((package, result))
}
/// Create-only export. Never overwrite a previously published evidence file.
pub fn write_new(
    path: &Path,
    package: &Evidence,
    expected_sha256: &str,
) -> Result<ExportResult, Error> {
    if package.schema != "sapphon-142-evidence-v1" || package.authority != "HOLD" {
        return Err(Error("EXPORT_FIELDS"));
    }
    let bytes = serde_json::to_vec(package).map_err(|_| Error("EXPORT_ENCODING"))?;
    if bytes.len() > MAX_EXPORT {
        return Err(Error("EXPORT_TOO_LARGE"));
    }
    let digest = hash(&bytes);
    if digest != expected_sha256 {
        return Err(Error("EXPORT_DIGEST_CONFLICT"));
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|_| Error("EXPORT_ALREADY_EXISTS"))?;
    file.write_all(&bytes)
        .map_err(|_| Error("EXPORT_WRITE_FAILED"))?;
    file.sync_all().map_err(|_| Error("EXPORT_FSYNC_FAILED"))?;
    let parent = path.parent().ok_or(Error("EXPORT_PARENT"))?;
    File::open(parent)
        .and_then(|f| f.sync_all())
        .map_err(|_| Error("EXPORT_DIRSYNC_FAILED"))?;
    Ok(ExportResult {
        sha256: digest,
        bytes: bytes.len(),
        decision: "HOLD",
        independent_custody_proven: false,
        lock_cleared: false,
    })
}
pub fn verify_export(data: &[u8], expected_sha256: &str) -> Result<Evidence, Error> {
    if data.len() > MAX_EXPORT || !valid_hash(expected_sha256) || hash(data) != expected_sha256 {
        return Err(Error("EXPORT_DIGEST_CONFLICT"));
    }
    let evidence: Evidence = serde_json::from_slice(data).map_err(|_| Error("EXPORT_CORRUPT"))?;
    if evidence.schema != "sapphon-142-evidence-v1" || evidence.authority != "HOLD" {
        return Err(Error("EXPORT_FIELDS"));
    }
    Ok(evidence)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use ed25519_dalek::{Signer, SigningKey};
    fn key(seed: u8, id: &str, ancestry: &str) -> (TrustedKey, SigningKey) {
        let sk = SigningKey::from_bytes(&[seed; 32]);
        (
            TrustedKey {
                witness_id: id.into(),
                ancestry_root: ancestry.into(),
                public_key_hex: hex::encode(sk.verifying_key().as_bytes()),
                revoked: false,
                min_counter: 0,
            },
            sk,
        )
    }
    fn receipt(sk: &SigningKey, id: &str, head: &str) -> CheckpointReceipt {
        let mut r = CheckpointReceipt {
            schema: "sapphon-140-checkpoint-receipt-v1".into(),
            witness_id: id.into(),
            seq: 1,
            head: head.into(),
            prior_seq: 0,
            prior_head: "a".repeat(64),
            witness_counter: 1,
            signature_base64: String::new(),
        };
        r.signature_base64 = STANDARD.encode(
            sk.sign(&crate::checkpoint140::receipt_message(&r))
                .to_bytes(),
        );
        r
    }
    fn build() -> (
        History,
        Vec<TrustedKey>,
        Vec<CheckpointReceipt>,
        Vec<RootClaim>,
    ) {
        let h = History::empty();
        let (a, sk1) = key(1, "witness-a", "root-a");
        let (b, sk2) = key(2, "witness-b", "root-b");
        (
            h,
            vec![a, b],
            vec![
                receipt(&sk1, "witness-a", &"b".repeat(64)),
                receipt(&sk2, "witness-b", &"b".repeat(64)),
            ],
            vec![
                RootClaim {
                    witness_id: "witness-a".into(),
                    ancestry_root: "root-a".into(),
                    custodian_id: "custodian-a".into(),
                },
                RootClaim {
                    witness_id: "witness-b".into(),
                    ancestry_root: "root-b".into(),
                    custodian_id: "custodian-b".into(),
                },
            ],
        )
    }
    #[test]
    fn deterministic_export_is_hold() {
        let (h, k, r, c) = build();
        let anchor = registry137::genesis_head();
        let (p, x) = assemble(&h, &h.digest().unwrap(), &[], 0, &anchor, &k, &r, &c).unwrap();
        let (p2, x2) = assemble(&h, &h.digest().unwrap(), &[], 0, &anchor, &k, &r, &c).unwrap();
        assert_eq!(p, p2);
        assert_eq!(x.sha256, x2.sha256);
        assert_eq!(x.decision, "HOLD");
        assert!(!x.independent_custody_proven && !x.lock_cleared);
    }
    #[test]
    fn same_ancestry_cannot_fake_independence() {
        let (h, k, r, mut c) = build();
        c[1].ancestry_root = "root-a".into();
        assert_eq!(
            assemble(
                &h,
                &h.digest().unwrap(),
                &[],
                0,
                &registry137::genesis_head(),
                &k,
                &r,
                &c
            )
            .unwrap_err()
            .0,
            "EXPORT_SHARED_ANCESTRY"
        );
    }
    #[test]
    fn conflict_with_existing_history_is_rejected() {
        let (h, k, r, c) = build();
        let (older, _) = h.append_verified(&h.digest().unwrap(), &k, &r).unwrap();
        let mut mutated = r.clone();
        mutated[0].head = "c".repeat(64);
        assert_eq!(
            assemble(
                &older,
                &older.digest().unwrap(),
                &[],
                0,
                &registry137::genesis_head(),
                &k,
                &mutated,
                &c
            )
            .unwrap_err()
            .0,
            "EXPORT_EQUIVOCATION"
        );
    }
    #[test]
    fn tampered_export_is_rejected() {
        let (h, k, r, c) = build();
        let (p, x) = assemble(
            &h,
            &h.digest().unwrap(),
            &[],
            0,
            &registry137::genesis_head(),
            &k,
            &r,
            &c,
        )
        .unwrap();
        let mut data = serde_json::to_vec(&p).unwrap();
        assert!(verify_export(&data, &x.sha256).is_ok());
        data.push(b' ');
        assert_eq!(
            verify_export(&data, &x.sha256).unwrap_err().0,
            "EXPORT_DIGEST_CONFLICT"
        );
    }
    #[test]
    fn immutable_export_wont_overwrite() {
        let (h, k, r, c) = build();
        let (p, x) = assemble(
            &h,
            &h.digest().unwrap(),
            &[],
            0,
            &registry137::genesis_head(),
            &k,
            &r,
            &c,
        )
        .unwrap();
        let path =
            std::env::temp_dir().join(format!("sapphon142-{}-export.json", std::process::id()));
        let _ = std::fs::remove_file(&path);
        write_new(&path, &p, &x.sha256).unwrap();
        assert_eq!(
            write_new(&path, &p, &x.sha256).unwrap_err().0,
            "EXPORT_ALREADY_EXISTS"
        );
        std::fs::remove_file(path).unwrap();
    }
    #[test]
    fn untrusted_prior_anchor_rejected() {
        let (h, k, r, c) = build();
        assert_eq!(
            assemble(
                &h,
                &"0".repeat(64),
                &[],
                0,
                &registry137::genesis_head(),
                &k,
                &r,
                &c
            )
            .unwrap_err()
            .0,
            "EXPORT_HISTORY_ANCHOR"
        );
    }
}
