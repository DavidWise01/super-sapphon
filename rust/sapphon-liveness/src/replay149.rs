//! SAPPHON-149 — full-local-state replacement and recovery replay inspection.
//! The expected checkpoint and intent digests MUST be independently retained.
//! Local files, signatures and this module cannot grant recovery authority.
#![cfg(target_os = "linux")]
use crate::{
    anchor145::{self, Anchor, ProvisionedProvider},
    failover148::{self, Intent},
    registry137, Error,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const AUTHORITY: &str = "HOLD";
const MAX_BYTES: usize = 1024 * 1024;
fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
fn valid_sha(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReplayState {
    MatchedExternalEvidence,
    LocalHistoryRolledBack,
    LocalHistoryAheadPending,
    ContradictoryLocalHistory,
    LocalHistoryCorrupt,
    IntentUnavailable,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Review {
    pub schema: String,
    pub state: ReplayState,
    pub trusted_intent_sha256: String,
    pub trusted_anchor_sequence: u64,
    pub trusted_anchor_head: String,
    pub observed_local_sequence: Option<u64>,
    pub observed_local_head: Option<String>,
    pub independent_custody_proven: bool,
    pub lock_cleared: bool,
    pub replacement_key_accepted: bool,
    pub decision: String,
}
/// Recovery review is read-only. An absent, corrupted, or replaced local
/// transcript is a reported observation, not a trigger to reconstruct it.
/// The signature of the supplied anchor is verified before using it.
pub fn inspect(
    local_registry: &[u8],
    local_intent: Option<&[u8]>,
    expected_intent_sha256: &str,
    trusted_history_sha256: &str,
    anchor: &Anchor,
    provider: &ProvisionedProvider,
) -> Result<Review, Error> {
    if local_registry.len() > MAX_BYTES
        || !valid_sha(expected_intent_sha256)
        || !valid_sha(trusted_history_sha256)
    {
        return Err(Error("REPLAY_INPUT_INVALID"));
    }
    anchor145::verify_anchor(anchor, provider)?;
    let parsed_intent = match local_intent {
        Some(bytes) => {
            // Local corruption remains HOLD and never becomes an alternative
            // clean intent. Report absence/corruption without key promotion.
            match failover148::read_intent(bytes, expected_intent_sha256) {
                Ok(i) => Some(i),
                Err(_) => None,
            }
        }
        None => None,
    };
    let intent_valid = parsed_intent
        .as_ref()
        .map(|i| {
            i.expected_history_sha256 == trusted_history_sha256
                && i.old_provider_id == provider.provider_id
        })
        .unwrap_or(false);
    let mut observed_seq = None;
    let mut observed_head = None;
    let mut state = if intent_valid {
        ReplayState::MatchedExternalEvidence
    } else {
        ReplayState::IntentUnavailable
    };
    if !local_registry.is_empty() && local_registry.last() != Some(&b'\n') {
        state = ReplayState::LocalHistoryCorrupt;
    } else {
        // Validate self-contained syntax and chain first, but NEVER treat
        // the computed head as an independently trusted custody anchor.
        let mut events = Vec::new();
        for line in local_registry
            .split(|c| *c == b'\n')
            .filter(|line| !line.is_empty())
        {
            match serde_json::from_slice::<registry137::Event>(line) {
                Ok(event) => events.push(event),
                Err(_) => {
                    state = ReplayState::LocalHistoryCorrupt;
                    break;
                }
            }
        }
        if state != ReplayState::LocalHistoryCorrupt {
            let mut computed = registry137::genesis_head();
            for event in &events {
                let bytes = serde_json::to_vec(event).map_err(|_| Error("REPLAY_ENCODING"))?;
                computed = digest(&bytes);
            }
            let seq = events.len() as u64;
            if registry137::verify(local_registry, seq, &computed).is_err() {
                state = ReplayState::LocalHistoryCorrupt;
            } else {
                observed_seq = Some(seq);
                observed_head = Some(computed.clone());
                if seq < anchor.sequence {
                    state = ReplayState::LocalHistoryRolledBack;
                } else {
                    // We must compare the signed anchor against the head at
                    // its exact position, not merely the local final head.
                    let mut prefix = registry137::genesis_head();
                    if anchor.sequence > 0 {
                        for event in events.iter().take(anchor.sequence as usize) {
                            prefix = digest(
                                &serde_json::to_vec(event).map_err(|_| Error("REPLAY_ENCODING"))?,
                            );
                        }
                    }
                    state = if prefix != anchor.head_sha256 {
                        ReplayState::ContradictoryLocalHistory
                    } else if seq > anchor.sequence {
                        ReplayState::LocalHistoryAheadPending
                    } else if !intent_valid {
                        ReplayState::IntentUnavailable
                    } else {
                        ReplayState::MatchedExternalEvidence
                    };
                }
            }
        }
    }
    Ok(Review {
        schema: "sapphon-149-recovery-review-v1".into(),
        state,
        trusted_intent_sha256: expected_intent_sha256.into(),
        trusted_anchor_sequence: anchor.sequence,
        trusted_anchor_head: anchor.head_sha256.clone(),
        observed_local_sequence: observed_seq,
        observed_local_head: observed_head,
        independent_custody_proven: false,
        lock_cleared: false,
        replacement_key_accepted: false,
        decision: "HOLD".into(),
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use ed25519_dalek::{Signer, SigningKey};
    fn anchor(seq: u64, head: &str) -> (Anchor, ProvisionedProvider) {
        let signer = SigningKey::from_bytes(&[19; 32]);
        let mut a = Anchor {
            schema: "sapphon-145-anchor-v1".into(),
            provider_id: "custodian-one".into(),
            sequence: seq,
            head_sha256: head.into(),
            epoch: 2,
            counter: 4,
            signature_base64: String::new(),
        };
        a.signature_base64 =
            STANDARD.encode(signer.sign(&anchor145::anchor_message(&a)).to_bytes());
        let p = ProvisionedProvider {
            provider_id: a.provider_id.clone(),
            public_key_hex: hex::encode(signer.verifying_key().as_bytes()),
            min_counter: 2,
            min_sequence: 0,
            min_epoch: 1,
            revoked: false,
        };
        (a, p)
    }
    fn intent() -> (Vec<u8>, String) {
        let old = SigningKey::from_bytes(&[1; 32]);
        let new = SigningKey::from_bytes(&[2; 32]);
        let r = crate::lineage147::KeyRotation {
            schema: "sapphon-147-key-rotation-v1".into(),
            provider_id: "custodian-one".into(),
            prior_key_hex: hex::encode(old.verifying_key().as_bytes()),
            replacement_key_hex: hex::encode(new.verifying_key().as_bytes()),
            prior_epoch: 2,
            replacement_epoch: 3,
            prior_counter: 3,
            replacement_counter: 4,
            old_signature_base64: String::new(),
            new_signature_base64: String::new(),
        };
        let i = Intent {
            schema: "sapphon-148-intent-v1".into(),
            expected_history_sha256: "a".repeat(64),
            rotation: r,
            old_provider_id: "custodian-one".into(),
            authority: "HOLD".into(),
        };
        let bytes = serde_json::to_vec(&i).unwrap();
        let hash = digest(&bytes);
        (bytes, hash)
    }
    fn one_event() -> (Vec<u8>, String) {
        let zero = registry137::verify(&[], 0, &registry137::genesis_head()).unwrap();
        let signer = SigningKey::from_bytes(&[7; 32]);
        let event = registry137::next(
            &zero,
            "register",
            "witness-one",
            "root-one",
            &hex::encode(signer.verifying_key().as_bytes()),
            1,
        );
        let data = serde_json::to_vec(&event).unwrap();
        let head = digest(&data);
        let mut transcript = data;
        transcript.push(b'\n');
        (transcript, head)
    }
    #[test]
    fn matching_replay_still_hold() {
        let (bytes, head) = one_event();
        let (a, p) = anchor(1, &head);
        let (i, ih) = intent();
        let v = inspect(&bytes, Some(&i), &ih, &"a".repeat(64), &a, &p).unwrap();
        assert_eq!(v.state, ReplayState::MatchedExternalEvidence);
        assert_eq!(v.decision, "HOLD");
        assert!(!v.independent_custody_proven && !v.lock_cleared && !v.replacement_key_accepted);
    }
    #[test]
    fn empty_local_registry_is_rollback_not_clean_recovery() {
        let (_, head) = one_event();
        let (a, p) = anchor(1, &head);
        let (i, ih) = intent();
        let v = inspect(&[], Some(&i), &ih, &"a".repeat(64), &a, &p).unwrap();
        assert_eq!(v.state, ReplayState::LocalHistoryRolledBack);
    }
    #[test]
    fn replaced_intent_fails_closed() {
        let (bytes, head) = one_event();
        let (a, p) = anchor(1, &head);
        let (i, ih) = intent();
        let mut changed = i;
        changed.push(b' ');
        let v = inspect(&bytes, Some(&changed), &ih, &"a".repeat(64), &a, &p).unwrap();
        assert_eq!(v.state, ReplayState::IntentUnavailable);
    }
    #[test]
    fn truncated_registry_is_quarantined() {
        let (mut bytes, head) = one_event();
        bytes.pop();
        let (a, p) = anchor(1, &head);
        let (i, ih) = intent();
        let v = inspect(&bytes, Some(&i), &ih, &"a".repeat(64), &a, &p).unwrap();
        assert_eq!(v.state, ReplayState::LocalHistoryCorrupt);
    }
    #[test]
    fn conflicting_signed_anchor_cannot_be_satisfied_by_local_substitution() {
        let (bytes, _) = one_event();
        let (a, p) = anchor(1, &"b".repeat(64));
        let (i, ih) = intent();
        let v = inspect(&bytes, Some(&i), &ih, &"a".repeat(64), &a, &p).unwrap();
        assert_eq!(v.state, ReplayState::ContradictoryLocalHistory);
    }
    #[test]
    fn lost_intent_remains_unavailable() {
        let (bytes, head) = one_event();
        let (a, p) = anchor(1, &head);
        let (_, ih) = intent();
        let v = inspect(&bytes, None, &ih, &"a".repeat(64), &a, &p).unwrap();
        assert_eq!(v.state, ReplayState::IntentUnavailable);
    }
    #[test]
    fn forged_anchor_signature_fails() {
        let (bytes, head) = one_event();
        let (mut a, p) = anchor(1, &head);
        let (i, ih) = intent();
        a.signature_base64 = STANDARD.encode([0u8; 64]);
        assert_eq!(
            inspect(&bytes, Some(&i), &ih, &"a".repeat(64), &a, &p)
                .unwrap_err()
                .0,
            "ANCHOR_SIGNATURE"
        );
    }
}
