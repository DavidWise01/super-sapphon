//! SAPPHON-147: verify actual checkpoint ancestry and dual-signed key rotation.
//! Local content, signed keys and ancestry labels do not establish independent
//! physical custody. No lock clearing, anchor advancement, or recovery authority.
#![cfg(target_os = "linux")]
use crate::{
    anchor145::{self, Anchor, ProvisionedProvider},
    dual_anchor146::{self, Custodian},
    registry137, Error,
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const AUTHORITY: &str = "HOLD";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Lineage {
    Identical,
    ProvenPrefixWithLag,
    ConflictingHistory,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LineageReview {
    pub lineage: Lineage,
    pub older_seq: u64,
    pub newer_seq: u64,
    pub older_head: String,
    pub newer_head: String,
    pub evidence_digest: String,
    pub independently_custodied: bool,
    pub lock_cleared: bool,
    pub authority: String,
}
/// The transcript must be exact, verified local content; the provider keys and
/// counter floors must be independently provisioned and retained elsewhere.
pub fn inspect_lineage(
    transcript: &[u8],
    local_seq: u64,
    local_head: &str,
    a: (&Anchor, Custodian<'_>),
    b: (&Anchor, Custodian<'_>),
) -> Result<LineageReview, Error> {
    let pair = dual_anchor146::compare(a.clone(), b.clone())?;
    let verified = registry137::verify(transcript, local_seq, local_head)?;
    let (older, newer) = if a.0.sequence <= b.0.sequence {
        (a.0, b.0)
    } else {
        (b.0, a.0)
    };
    if newer.sequence > verified.seq {
        return Err(Error("LINEAGE_NEWER_NOT_OBSERVED"));
    }
    let mut prefix_heads = vec![registry137::genesis_head()];
    for line in transcript.split_inclusive(|ch| *ch == b'\n') {
        if line.is_empty() {
            continue;
        }
        if line.last() != Some(&b'\n') {
            return Err(Error("LINEAGE_TRUNCATED"));
        }
        let event: registry137::Event = serde_json::from_slice(&line[..line.len() - 1])
            .map_err(|_| Error("LINEAGE_CORRUPT"))?;
        let canonical = serde_json::to_vec(&event).map_err(|_| Error("LINEAGE_ENCODING"))?;
        prefix_heads.push(hex::encode(Sha256::digest(canonical)));
    }
    let older_head = prefix_heads
        .get(older.sequence as usize)
        .ok_or(Error("LINEAGE_PREFIX_UNKNOWN"))?;
    let newer_head = prefix_heads
        .get(newer.sequence as usize)
        .ok_or(Error("LINEAGE_PREFIX_UNKNOWN"))?;
    let lineage = if older_head != &older.head_sha256 || newer_head != &newer.head_sha256 {
        Lineage::ConflictingHistory
    } else if older.sequence == newer.sequence {
        Lineage::Identical
    } else {
        Lineage::ProvenPrefixWithLag
    };
    let evidence = format!(
        "SAPPHON-147-LINEAGE-v1\n{}\n{}\n{}\n{}\n{}\n{}\n",
        older.provider_id,
        older.sequence,
        older.head_sha256,
        newer.provider_id,
        newer.sequence,
        newer.head_sha256
    );
    Ok(LineageReview {
        lineage,
        older_seq: older.sequence,
        newer_seq: newer.sequence,
        older_head: older.head_sha256.clone(),
        newer_head: newer.head_sha256.clone(),
        evidence_digest: hex::encode(Sha256::digest(evidence.as_bytes())),
        independently_custodied: false,
        lock_cleared: false,
        authority: pair.decision,
    })
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct KeyRotation {
    pub schema: String,
    pub provider_id: String,
    pub prior_key_hex: String,
    pub replacement_key_hex: String,
    pub prior_epoch: u64,
    pub replacement_epoch: u64,
    pub prior_counter: u64,
    pub replacement_counter: u64,
    pub old_signature_base64: String,
    pub new_signature_base64: String,
}
pub fn rotation_message(r: &KeyRotation) -> Vec<u8> {
    format!(
        "SAPPHON-147-KEY-ROTATION-v1\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n",
        r.provider_id,
        r.prior_key_hex,
        r.replacement_key_hex,
        r.prior_epoch,
        r.replacement_epoch,
        r.prior_counter,
        r.replacement_counter
    )
    .into_bytes()
}
fn signed_with(key_hex: &str, message: &[u8], signature: &str) -> Result<(), Error> {
    let raw = hex::decode(key_hex).map_err(|_| Error("ROTATION_KEY"))?;
    let pubkey: [u8; 32] = raw.try_into().map_err(|_| Error("ROTATION_KEY"))?;
    let vk = VerifyingKey::from_bytes(&pubkey).map_err(|_| Error("ROTATION_KEY"))?;
    let raw = STANDARD
        .decode(signature)
        .map_err(|_| Error("ROTATION_SIGNATURE"))?;
    let sig: [u8; 64] = raw.try_into().map_err(|_| Error("ROTATION_SIGNATURE"))?;
    vk.verify(message, &Signature::from_bytes(&sig))
        .map_err(|_| Error("ROTATION_SIGNATURE"))
}
/// Both old and new private keys must attest to exactly the same continuity
/// statement; a hostile owner can still control both keys. No trust update.
pub fn verify_rotation(r: &KeyRotation, prior: &ProvisionedProvider) -> Result<(), Error> {
    if prior.revoked {
        return Err(Error("ROTATION_REVOKED"));
    }
    if r.schema != "sapphon-147-key-rotation-v1"
        || r.provider_id != prior.provider_id
        || r.prior_key_hex != prior.public_key_hex
        || r.prior_key_hex == r.replacement_key_hex
    {
        return Err(Error("ROTATION_FIELDS"));
    }
    if r.prior_epoch < prior.min_epoch
        || r.replacement_epoch <= r.prior_epoch
        || r.prior_counter <= prior.min_counter
        || r.replacement_counter <= r.prior_counter
    {
        return Err(Error("ROTATION_ROLLBACK"));
    }
    let message = rotation_message(r);
    signed_with(&r.prior_key_hex, &message, &r.old_signature_base64)?;
    signed_with(&r.replacement_key_hex, &message, &r.new_signature_base64)?;
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    fn anchor(seed: u8, id: &str, seq: u64, head: &str) -> (Anchor, ProvisionedProvider) {
        let k = SigningKey::from_bytes(&[seed; 32]);
        let mut a = Anchor {
            schema: "sapphon-145-anchor-v1".into(),
            provider_id: id.into(),
            sequence: seq,
            head_sha256: head.into(),
            epoch: 2,
            counter: 3,
            signature_base64: String::new(),
        };
        a.signature_base64 = STANDARD.encode(k.sign(&anchor145::anchor_message(&a)).to_bytes());
        (
            a,
            ProvisionedProvider {
                provider_id: id.into(),
                public_key_hex: hex::encode(k.verifying_key().as_bytes()),
                min_counter: 0,
                min_sequence: 0,
                min_epoch: 0,
                revoked: false,
            },
        )
    }
    fn run(
        transcript: &[u8],
        seq: u64,
        head: &str,
        a: &Anchor,
        ap: &ProvisionedProvider,
        b: &Anchor,
        bp: &ProvisionedProvider,
    ) -> Result<LineageReview, Error> {
        inspect_lineage(
            transcript,
            seq,
            head,
            (
                a,
                Custodian {
                    provider: ap,
                    claimed_root: "root-left",
                },
            ),
            (
                b,
                Custodian {
                    provider: bp,
                    claimed_root: "root-right",
                },
            ),
        )
    }
    fn one_event() -> (Vec<u8>, String) {
        let base = registry137::verify(&[], 0, &registry137::genesis_head()).unwrap();
        let key = SigningKey::from_bytes(&[9u8; 32]);
        let e = registry137::next(
            &base,
            "register",
            "witness-one",
            "root-one",
            &hex::encode(key.verifying_key().as_bytes()),
            1,
        );
        let body = serde_json::to_vec(&e).unwrap();
        let head = hex::encode(Sha256::digest(&body));
        let mut bytes = body;
        bytes.push(b'\n');
        (bytes, head)
    }
    #[test]
    fn actual_prefix_allows_lag_but_never_recovery() {
        let (bytes, head) = one_event();
        let genesis = registry137::genesis_head();
        let (a, ap) = anchor(1, "custodian-a", 0, &genesis);
        let (b, bp) = anchor(2, "custodian-b", 1, &head);
        let v = run(&bytes, 1, &head, &a, &ap, &b, &bp).unwrap();
        assert_eq!(v.lineage, Lineage::ProvenPrefixWithLag);
        assert!(!v.independently_custodied && !v.lock_cleared);
        assert_eq!(v.authority, "HOLD");
    }
    #[test]
    fn divergent_signed_prefix_is_not_lag() {
        let (bytes, head) = one_event();
        let (a, ap) = anchor(1, "custodian-a", 0, &"a".repeat(64));
        let (b, bp) = anchor(2, "custodian-b", 1, &head);
        assert_eq!(
            run(&bytes, 1, &head, &a, &ap, &b, &bp).unwrap().lineage,
            Lineage::ConflictingHistory
        );
    }
    #[test]
    fn missing_newer_history_fails_closed() {
        let (a, ap) = anchor(1, "custodian-a", 0, &registry137::genesis_head());
        let (b, bp) = anchor(2, "custodian-b", 2, &"b".repeat(64));
        assert_eq!(
            run(&[], 0, &registry137::genesis_head(), &a, &ap, &b, &bp)
                .unwrap_err()
                .0,
            "LINEAGE_NEWER_NOT_OBSERVED"
        );
    }
    fn rotate() -> (KeyRotation, ProvisionedProvider) {
        let old = SigningKey::from_bytes(&[1u8; 32]);
        let new = SigningKey::from_bytes(&[2u8; 32]);
        let mut r = KeyRotation {
            schema: "sapphon-147-key-rotation-v1".into(),
            provider_id: "custodian-a".into(),
            prior_key_hex: hex::encode(old.verifying_key().as_bytes()),
            replacement_key_hex: hex::encode(new.verifying_key().as_bytes()),
            prior_epoch: 2,
            replacement_epoch: 3,
            prior_counter: 2,
            replacement_counter: 3,
            old_signature_base64: String::new(),
            new_signature_base64: String::new(),
        };
        let payload = rotation_message(&r);
        r.old_signature_base64 = STANDARD.encode(old.sign(&payload).to_bytes());
        r.new_signature_base64 = STANDARD.encode(new.sign(&payload).to_bytes());
        let p = ProvisionedProvider {
            provider_id: r.provider_id.clone(),
            public_key_hex: r.prior_key_hex.clone(),
            min_counter: 1,
            min_sequence: 0,
            min_epoch: 1,
            revoked: false,
        };
        (r, p)
    }
    #[test]
    fn dual_signed_rotation_checks_both_keys() {
        let (r, p) = rotate();
        verify_rotation(&r, &p).unwrap();
    }
    #[test]
    fn replacement_key_without_own_signature_fails() {
        let (mut r, p) = rotate();
        r.new_signature_base64 = STANDARD.encode([0u8; 64]);
        assert_eq!(verify_rotation(&r, &p).unwrap_err().0, "ROTATION_SIGNATURE");
    }
    #[test]
    fn key_rotation_replay_fails() {
        let (r, mut p) = rotate();
        p.min_counter = 2;
        assert_eq!(verify_rotation(&r, &p).unwrap_err().0, "ROTATION_ROLLBACK");
    }
    #[test]
    fn provider_disappearance_cannot_be_silently_filled() {
        let (bytes, head) = one_event();
        let (a, ap) = anchor(1, "custodian-a", 0, &registry137::genesis_head());
        let (b, mut bp) = anchor(2, "custodian-b", 1, &head);
        bp.revoked = true;
        assert_eq!(
            run(&bytes, 1, &head, &a, &ap, &b, &bp).unwrap_err().0,
            "ANCHOR_REVOKED"
        );
    }
}
