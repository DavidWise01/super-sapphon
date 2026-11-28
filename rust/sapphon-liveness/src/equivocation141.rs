//! SAPPHON-141: detect witness equivocation across a retained receipt transcript.
//! The supplied trust registry and retained history require independent custody.
//! A signature verifies key possession, NOT physical independence or UTC.
use crate::{
    attest136::TrustedKey,
    checkpoint140::{receipt_message, CheckpointReceipt},
    Error,
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap, HashSet};
pub const AUTHORITY: &str = "HOLD";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HistoryEntry {
    pub witness_id: String,
    pub seq: u64,
    pub head: String,
    pub prior_seq: u64,
    pub prior_head: String,
    pub counter: u64,
    pub receipt_sha256: String,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct History {
    pub schema: String,
    pub entries: Vec<HistoryEntry>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Screening {
    pub receipts_seen: usize,
    pub witnesses_seen: usize,
    pub history_digest: String,
    pub decision: &'static str,
    pub checkpoint_acknowledged: bool,
    pub lock_cleared: bool,
    pub independence_proven: bool,
}
fn sha(b: &[u8]) -> String {
    hex::encode(Sha256::digest(b))
}
fn good_sha(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|x| x.is_ascii_digit() || (b'a'..=b'f').contains(&x))
}
impl History {
    pub fn empty() -> Self {
        Self {
            schema: "sapphon-141-history-v1".into(),
            entries: Vec::new(),
        }
    }
    pub fn digest(&self) -> Result<String, Error> {
        let b = serde_json::to_vec(self).map_err(|_| Error("HISTORY_ENCODING"))?;
        Ok(sha(&b))
    }
    /// Requires an independently trusted digest over the entire prior history.
    /// A digest taken from this mutable history is NOT an anti-rollback anchor.
    pub fn append_verified(
        &self,
        trusted_head: &str,
        registry: &[TrustedKey],
        receipts: &[CheckpointReceipt],
    ) -> Result<(Self, Screening), Error> {
        if !good_sha(trusted_head) || self.digest()? != trusted_head {
            return Err(Error("HISTORY_ANCHOR_MISMATCH"));
        }
        if self.schema != "sapphon-141-history-v1"
            || self.entries.len() > 8192
            || registry.len() > 32
            || receipts.len() > 32
        {
            return Err(Error("HISTORY_FIELDS"));
        }
        let mut keys = HashMap::new();
        let mut public_keys = HashSet::new();
        for key in registry {
            if keys.insert(key.witness_id.as_str(), key).is_some()
                || !public_keys.insert(key.public_key_hex.as_str())
            {
                return Err(Error("HISTORY_KEY_COLLISION"));
            }
        }
        let mut heads: BTreeMap<(&str, u64), &str> = BTreeMap::new();
        let mut floors: HashMap<&str, u64> = HashMap::new();
        for prev in &self.entries {
            if !good_sha(&prev.head)
                || !good_sha(&prev.prior_head)
                || !good_sha(&prev.receipt_sha256)
            {
                return Err(Error("HISTORY_CORRUPT"));
            }
            if let Some(old) = heads.insert((&prev.witness_id, prev.seq), prev.head.as_str()) {
                if old != prev.head {
                    return Err(Error("HISTORY_EQUIVOCATION"));
                }
                return Err(Error("HISTORY_DUPLICATE"));
            }
            if let Some(old) = floors.insert(prev.witness_id.as_str(), prev.counter) {
                if prev.counter <= old {
                    return Err(Error("HISTORY_COUNTER_ROLLBACK"));
                }
            }
        }
        let mut next = self.clone();
        let mut seen = HashSet::new();
        let mut roots = HashSet::new();
        for receipt in receipts {
            if receipt.schema != "sapphon-140-checkpoint-receipt-v1"
                || !good_sha(&receipt.head)
                || !good_sha(&receipt.prior_head)
                || receipt.seq
                    != receipt
                        .prior_seq
                        .checked_add(1)
                        .ok_or(Error("HISTORY_SEQUENCE"))?
            {
                return Err(Error("HISTORY_RECEIPT_FIELDS"));
            }
            if !seen.insert(receipt.witness_id.as_str()) {
                return Err(Error("HISTORY_DUPLICATE_RECEIPT"));
            }
            let key = keys
                .get(receipt.witness_id.as_str())
                .ok_or(Error("HISTORY_UNKNOWN_KEY"))?;
            if key.revoked {
                return Err(Error("HISTORY_REVOKED"));
            }
            if let Some(old) = heads.get(&(receipt.witness_id.as_str(), receipt.seq)) {
                if *old != receipt.head {
                    return Err(Error("HISTORY_EQUIVOCATION"));
                }
                return Err(Error("HISTORY_DUPLICATE"));
            }
            let floor = floors
                .get(receipt.witness_id.as_str())
                .copied()
                .unwrap_or(0)
                .max(key.min_counter);
            if receipt.witness_counter <= floor {
                return Err(Error("HISTORY_REPLAY"));
            }
            let key_bytes =
                hex::decode(&key.public_key_hex).map_err(|_| Error("HISTORY_KEY_INVALID"))?;
            let pubkey: [u8; 32] = key_bytes
                .try_into()
                .map_err(|_| Error("HISTORY_KEY_INVALID"))?;
            let vk = VerifyingKey::from_bytes(&pubkey).map_err(|_| Error("HISTORY_KEY_INVALID"))?;
            let sig_bytes = STANDARD
                .decode(&receipt.signature_base64)
                .map_err(|_| Error("HISTORY_SIGNATURE_INVALID"))?;
            let sig: [u8; 64] = sig_bytes
                .try_into()
                .map_err(|_| Error("HISTORY_SIGNATURE_INVALID"))?;
            vk.verify(&receipt_message(receipt), &Signature::from_bytes(&sig))
                .map_err(|_| Error("HISTORY_SIGNATURE_INVALID"))?;
            if !roots.insert(key.ancestry_root.as_str()) {
                return Err(Error("HISTORY_SHARED_ANCESTRY"));
            }
            let signed = serde_json::to_vec(receipt).map_err(|_| Error("HISTORY_ENCODING"))?;
            next.entries.push(HistoryEntry {
                witness_id: receipt.witness_id.clone(),
                seq: receipt.seq,
                head: receipt.head.clone(),
                prior_seq: receipt.prior_seq,
                prior_head: receipt.prior_head.clone(),
                counter: receipt.witness_counter,
                receipt_sha256: sha(&signed),
            });
            floors.insert(receipt.witness_id.as_str(), receipt.witness_counter);
        }
        next.entries
            .sort_by(|a, b| a.witness_id.cmp(&b.witness_id).then(a.seq.cmp(&b.seq)));
        let screening = Screening {
            receipts_seen: receipts.len(),
            witnesses_seen: roots.len(),
            history_digest: next.digest()?,
            decision: "HOLD",
            checkpoint_acknowledged: false,
            lock_cleared: false,
            independence_proven: false,
        };
        Ok((next, screening))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    fn sample(
        id: &str,
        seed: u8,
        seq: u64,
        head: &str,
        counter: u64,
    ) -> (TrustedKey, CheckpointReceipt) {
        let sk = SigningKey::from_bytes(&[seed; 32]);
        let mut r = CheckpointReceipt {
            schema: "sapphon-140-checkpoint-receipt-v1".into(),
            witness_id: id.into(),
            seq,
            head: head.into(),
            prior_seq: seq - 1,
            prior_head: "a".repeat(64),
            witness_counter: counter,
            signature_base64: String::new(),
        };
        r.signature_base64 = STANDARD.encode(sk.sign(&receipt_message(&r)).to_bytes());
        (
            TrustedKey {
                witness_id: id.into(),
                ancestry_root: format!("root-{id}"),
                public_key_hex: hex::encode(sk.verifying_key().as_bytes()),
                revoked: false,
                min_counter: 0,
            },
            r,
        )
    }
    #[test]
    fn signed_receipts_remain_hold() {
        let history = History::empty();
        let (k1, r1) = sample("first", 1, 1, &"b".repeat(64), 1);
        let (k2, r2) = sample("second", 2, 1, &"b".repeat(64), 1);
        let (_, v) = history
            .append_verified(&history.digest().unwrap(), &[k1, k2], &[r1, r2])
            .unwrap();
        assert_eq!(v.receipts_seen, 2);
        assert_eq!(v.decision, "HOLD");
        assert!(!v.independence_proven && !v.checkpoint_acknowledged && !v.lock_cleared);
    }
    #[test]
    fn conflicting_heads_at_same_sequence_are_detected() {
        let h = History::empty();
        let (k, r) = sample("first", 1, 1, &"b".repeat(64), 1);
        let (stored, _) = h
            .append_verified(&h.digest().unwrap(), &[k.clone()], &[r])
            .unwrap();
        let (_, contradiction) = sample("first", 1, 1, &"c".repeat(64), 2);
        assert_eq!(
            stored
                .append_verified(&stored.digest().unwrap(), &[k], &[contradiction])
                .unwrap_err()
                .0,
            "HISTORY_EQUIVOCATION"
        );
    }
    #[test]
    fn stale_counter_cannot_be_replayed_on_restart() {
        let h = History::empty();
        let (k, r) = sample("first", 1, 1, &"b".repeat(64), 3);
        let (stored, _) = h
            .append_verified(&h.digest().unwrap(), &[k.clone()], &[r])
            .unwrap();
        let (_, stale) = sample("first", 1, 2, &"c".repeat(64), 2);
        assert_eq!(
            stored
                .append_verified(&stored.digest().unwrap(), &[k], &[stale])
                .unwrap_err()
                .0,
            "HISTORY_REPLAY"
        );
    }
    #[test]
    fn stale_history_anchor_is_rejected() {
        let h = History::empty();
        assert_eq!(
            h.append_verified(&"0".repeat(64), &[], &[]).unwrap_err().0,
            "HISTORY_ANCHOR_MISMATCH"
        );
    }
    #[test]
    fn revoked_key_is_rejected() {
        let h = History::empty();
        let (mut k, r) = sample("first", 1, 1, &"b".repeat(64), 1);
        k.revoked = true;
        assert_eq!(
            h.append_verified(&h.digest().unwrap(), &[k], &[r])
                .unwrap_err()
                .0,
            "HISTORY_REVOKED"
        );
    }
    #[test]
    fn forged_signature_is_rejected() {
        let h = History::empty();
        let (k, mut r) = sample("first", 1, 1, &"b".repeat(64), 1);
        r.signature_base64 = STANDARD.encode([0u8; 64]);
        assert_eq!(
            h.append_verified(&h.digest().unwrap(), &[k], &[r])
                .unwrap_err()
                .0,
            "HISTORY_SIGNATURE_INVALID"
        );
    }
}
