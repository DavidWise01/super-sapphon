//! SAPPHON-143: quarantine contradictory claims without promoting their truth.
//! Evidence capture is not signature authentication or independent custody.
#![cfg(target_os = "linux")]
use crate::{
    attest136::TrustedKey, checkpoint140::CheckpointReceipt, equivocation141::History, Error,
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
const MAX_BYTES: usize = 1024 * 1024;
fn digest(b: &[u8]) -> String {
    hex::encode(Sha256::digest(b))
}
fn valid_hash(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
pub struct Finding {
    pub code: String,
    pub witness_id: String,
    pub seq: u64,
    pub first_head: String,
    pub other_head: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Quarantine {
    pub schema: String,
    pub previous_history_sha256: String,
    pub receipts: Vec<CheckpointReceipt>,
    pub findings: Vec<Finding>,
    pub declared_ancestry: Vec<Ancestry>,
    pub authority: String,
    pub cryptographic_authentication: String,
    pub independent_custody: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Ancestry {
    pub witness_id: String,
    pub declared_root: String,
    pub key_sha256: String,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Packet {
    pub digest: String,
    pub bytes: Vec<u8>,
    pub decision: &'static str,
    pub lock_cleared: bool,
}
/// This detector is deliberately blind to friendly witness display names:
/// it compares signed payload claims and registry ancestry fields, not labels.
/// All reported claims remain UNVERIFIED until a separate signature verifier runs.
pub fn quarantine(
    history: &History,
    supplied_history_digest: &str,
    keys: &[TrustedKey],
    receipts: &[CheckpointReceipt],
) -> Result<Packet, Error> {
    if !valid_hash(supplied_history_digest) || history.digest()? != supplied_history_digest {
        return Err(Error("QUARANTINE_ANCHOR"));
    }
    if keys.len() > 32 || receipts.len() > 32 {
        return Err(Error("QUARANTINE_LIMIT"));
    }
    let mut map = BTreeMap::new();
    for key in keys {
        if map.insert(key.witness_id.as_str(), key).is_some() {
            return Err(Error("QUARANTINE_DUPLICATE_REGISTRY_ID"));
        }
    }
    let mut known: BTreeMap<(String, u64), String> = BTreeMap::new();
    for item in &history.entries {
        let k = (item.witness_id.clone(), item.seq);
        if let Some(old) = known.insert(k, item.head.clone()) {
            if old != item.head {
                return Err(Error("QUARANTINE_HISTORY_CONFLICT"));
            }
        }
    }
    let mut findings = BTreeSet::new();
    let mut incoming = BTreeMap::new();
    for receipt in receipts {
        if receipt.schema != "sapphon-140-checkpoint-receipt-v1"
            || !valid_hash(&receipt.head)
            || !valid_hash(&receipt.prior_head)
        {
            return Err(Error("QUARANTINE_RECEIPT_FIELDS"));
        }
        let k = (receipt.witness_id.clone(), receipt.seq);
        if let Some(old) = known.get(&k) {
            if old != &receipt.head {
                let (a, b) = if old < &receipt.head {
                    (old.clone(), receipt.head.clone())
                } else {
                    (receipt.head.clone(), old.clone())
                };
                findings.insert(Finding {
                    code: "CONFLICTING_HEAD".into(),
                    witness_id: receipt.witness_id.clone(),
                    seq: receipt.seq,
                    first_head: a,
                    other_head: b,
                });
            }
        }
        if let Some(old) = incoming.insert(k, receipt.head.clone()) {
            if old != receipt.head {
                let (a, b) = if old < receipt.head {
                    (old, receipt.head.clone())
                } else {
                    (receipt.head.clone(), old)
                };
                findings.insert(Finding {
                    code: "BATCH_EQUIVOCATION".into(),
                    witness_id: receipt.witness_id.clone(),
                    seq: receipt.seq,
                    first_head: a,
                    other_head: b,
                });
            }
        }
    }
    let mut ancestry = Vec::new();
    let mut roots = BTreeMap::<String, String>::new();
    let mut public_keys = BTreeMap::<String, String>::new();
    for key in keys {
        let pk = digest(key.public_key_hex.as_bytes());
        if let Some(other) = public_keys.insert(pk.clone(), key.witness_id.clone()) {
            findings.insert(Finding {
                code: "SHARED_PUBLIC_KEY".into(),
                witness_id: key.witness_id.clone(),
                seq: 0,
                first_head: other,
                other_head: key.witness_id.clone(),
            });
        }
        if let Some(other) = roots.insert(key.ancestry_root.clone(), key.witness_id.clone()) {
            findings.insert(Finding {
                code: "DECLARED_SHARED_ANCESTRY".into(),
                witness_id: key.witness_id.clone(),
                seq: 0,
                first_head: other,
                other_head: key.witness_id.clone(),
            });
        }
        ancestry.push(Ancestry {
            witness_id: key.witness_id.clone(),
            declared_root: key.ancestry_root.clone(),
            key_sha256: pk,
        });
    }
    ancestry.sort_by(|a, b| a.witness_id.cmp(&b.witness_id));
    for r in receipts {
        if !map.contains_key(r.witness_id.as_str()) {
            findings.insert(Finding {
                code: "UNKNOWN_WITNESS".into(),
                witness_id: r.witness_id.clone(),
                seq: r.seq,
                first_head: String::new(),
                other_head: r.head.clone(),
            });
        }
    }
    let mut sorted = receipts.to_vec();
    sorted.sort_by(|a, b| {
        a.witness_id
            .cmp(&b.witness_id)
            .then(a.seq.cmp(&b.seq))
            .then(a.head.cmp(&b.head))
            .then(a.signature_base64.cmp(&b.signature_base64))
    });
    let packet = Quarantine {
        schema: "sapphon-143-quarantine-v1".into(),
        previous_history_sha256: supplied_history_digest.into(),
        receipts: sorted,
        findings: findings.into_iter().collect(),
        declared_ancestry: ancestry,
        authority: "HOLD".into(),
        cryptographic_authentication: "NOT_PERFORMED".into(),
        independent_custody: false,
    };
    let bytes = serde_json::to_vec(&packet).map_err(|_| Error("QUARANTINE_ENCODING"))?;
    if bytes.len() > MAX_BYTES {
        return Err(Error("QUARANTINE_TOO_LARGE"));
    }
    Ok(Packet {
        digest: digest(&bytes),
        bytes,
        decision: "HOLD",
        lock_cleared: false,
    })
}
/// Create-only, no overwrite. Export hash must be separately preserved;
/// this function does not authenticate custody or seal hostile filesystems.
pub fn write_new(path: &Path, packet: &Packet) -> Result<(), Error> {
    if packet.decision != "HOLD"
        || packet.lock_cleared
        || packet.bytes.len() > MAX_BYTES
        || packet.digest != digest(&packet.bytes)
    {
        return Err(Error("QUARANTINE_PACKET_INVALID"));
    }
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|_| Error("QUARANTINE_ALREADY_EXISTS"))?;
    f.write_all(&packet.bytes)
        .map_err(|_| Error("QUARANTINE_WRITE"))?;
    f.sync_all().map_err(|_| Error("QUARANTINE_FSYNC"))?;
    let parent = path.parent().ok_or(Error("QUARANTINE_PARENT"))?;
    File::open(parent)
        .and_then(|p| p.sync_all())
        .map_err(|_| Error("QUARANTINE_DIRSYNC"))?;
    Ok(())
}
pub fn verify_packet(bytes: &[u8], expected_digest: &str) -> Result<Quarantine, Error> {
    if bytes.len() > MAX_BYTES || !valid_hash(expected_digest) || digest(bytes) != expected_digest {
        return Err(Error("QUARANTINE_DIGEST"));
    }
    let packet: Quarantine =
        serde_json::from_slice(bytes).map_err(|_| Error("QUARANTINE_CORRUPT"))?;
    if packet.schema != "sapphon-143-quarantine-v1"
        || packet.authority != "HOLD"
        || packet.independent_custody
        || packet.cryptographic_authentication != "NOT_PERFORMED"
    {
        return Err(Error("QUARANTINE_FIELDS"));
    }
    Ok(packet)
}
#[cfg(test)]
mod tests {
    use super::*;
    fn receipt(id: &str, head: &str) -> CheckpointReceipt {
        CheckpointReceipt {
            schema: "sapphon-140-checkpoint-receipt-v1".into(),
            witness_id: id.into(),
            seq: 1,
            head: head.into(),
            prior_seq: 0,
            prior_head: "a".repeat(64),
            witness_counter: 1,
            signature_base64: "unverified-fixture".into(),
        }
    }
    fn key(id: &str, root: &str) -> TrustedKey {
        TrustedKey {
            witness_id: id.into(),
            ancestry_root: root.into(),
            public_key_hex: id.repeat(8),
            revoked: false,
            min_counter: 0,
        }
    }
    fn capture(keys: &[TrustedKey], receipts: &[CheckpointReceipt]) -> Packet {
        let h = History::empty();
        quarantine(&h, &h.digest().unwrap(), keys, receipts).unwrap()
    }
    #[test]
    fn conflicting_heads_in_batch_are_retained_not_discarded() {
        let p = capture(
            &[key("first", "root-a")],
            &[
                receipt("first", &"a".repeat(64)),
                receipt("first", &"b".repeat(64)),
            ],
        );
        let q = verify_packet(&p.bytes, &p.digest).unwrap();
        assert_eq!(q.receipts.len(), 2);
        assert!(q.findings.iter().any(|f| f.code == "BATCH_EQUIVOCATION"));
        assert_eq!(q.authority, "HOLD");
        assert!(!q.independent_custody);
    }
    #[test]
    fn matching_content_is_not_independent_source_evidence() {
        let p = capture(
            &[key("first", "same-root"), key("other", "same-root")],
            &[
                receipt("first", &"b".repeat(64)),
                receipt("other", &"b".repeat(64)),
            ],
        );
        let q = verify_packet(&p.bytes, &p.digest).unwrap();
        assert!(q
            .findings
            .iter()
            .any(|f| f.code == "DECLARED_SHARED_ANCESTRY"));
        assert!(!q.independent_custody);
    }
    #[test]
    fn deterministic_packet_and_tamper_detection() {
        let keys = [key("first", "root-a")];
        let receipts = [receipt("first", &"b".repeat(64))];
        let a = capture(&keys, &receipts);
        let b = capture(&keys, &receipts);
        assert_eq!(a.digest, b.digest);
        let mut altered = a.bytes.clone();
        altered.push(b' ');
        assert_eq!(
            verify_packet(&altered, &a.digest).unwrap_err().0,
            "QUARANTINE_DIGEST"
        );
    }
    #[test]
    fn old_history_anchor_required() {
        let h = History::empty();
        assert_eq!(
            quarantine(&h, &"0".repeat(64), &[], &[]).unwrap_err().0,
            "QUARANTINE_ANCHOR"
        );
    }
    #[test]
    fn create_only_packet_does_not_overwrite() {
        let packet = capture(&[], &[]);
        let path =
            std::env::temp_dir().join(format!("sapphon143-{}-packet.json", std::process::id()));
        let _ = std::fs::remove_file(&path);
        write_new(&path, &packet).unwrap();
        assert_eq!(
            write_new(&path, &packet).unwrap_err().0,
            "QUARANTINE_ALREADY_EXISTS"
        );
        std::fs::remove_file(path).unwrap();
    }
}
