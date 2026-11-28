//! SAPPHON-146: two signed anchor providers and cross-custodian disagreement.
//! This is a comparison of *provisioned* signing keys and claimed custody roots.
//! It does not prove physical independence, global rollback security, or recovery.
use crate::{
    anchor145::{self, Anchor, ProvisionedProvider},
    Error,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const AUTHORITY: &str = "HOLD";

#[derive(Clone, Debug)]
pub struct Custodian<'a> {
    pub provider: &'a ProvisionedProvider,
    /// Independently authenticated ancestry is required outside this process.
    pub claimed_root: &'a str,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Comparison {
    SameCheckpoint,
    ConflictingHeadAtSameSequence,
    DifferentSequenceFloors,
    DifferentEpochs,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Finding {
    pub schema: String,
    pub comparison: Comparison,
    pub first_provider_id: String,
    pub second_provider_id: String,
    pub first_sequence: u64,
    pub second_sequence: u64,
    pub first_head: String,
    pub second_head: String,
    pub first_epoch: u64,
    pub second_epoch: u64,
    pub transcript_sha256: String,
    pub claimed_roots_distinct: bool,
    pub signatures_valid: bool,
    pub independent_custody_proven: bool,
    pub external_checkpoint_accepted: bool,
    pub lock_cleared: bool,
    pub decision: String,
}
fn valid_root(root: &str) -> bool {
    (4..=128).contains(&root.len())
        && root
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}
fn key_fingerprint(provider: &ProvisionedProvider) -> Result<String, Error> {
    let raw = hex::decode(&provider.public_key_hex).map_err(|_| Error("DUAL_KEY_INVALID"))?;
    if raw.len() != 32 {
        return Err(Error("DUAL_KEY_INVALID"));
    }
    Ok(hex::encode(Sha256::digest(raw)))
}
/// Both signatures are checked *before* comparing checkpoint claims.
/// No comparison outcome grants authority, even when keys and heads agree.
pub fn compare(
    first: (&Anchor, Custodian<'_>),
    second: (&Anchor, Custodian<'_>),
) -> Result<Finding, Error> {
    let (a, ap) = first;
    let (b, bp) = second;
    if ap.provider.provider_id == bp.provider.provider_id
        || a.provider_id == b.provider_id
        || !valid_root(ap.claimed_root)
        || !valid_root(bp.claimed_root)
        || ap.claimed_root == bp.claimed_root
    {
        return Err(Error("DUAL_SHARED_ANCESTRY"));
    }
    if key_fingerprint(ap.provider)? == key_fingerprint(bp.provider)? {
        return Err(Error("DUAL_SHARED_SIGNING_KEY"));
    }
    anchor145::verify_anchor(a, ap.provider)?;
    anchor145::verify_anchor(b, bp.provider)?;
    let comparison = if a.sequence == b.sequence && a.head_sha256 != b.head_sha256 {
        Comparison::ConflictingHeadAtSameSequence
    } else if a.sequence != b.sequence {
        Comparison::DifferentSequenceFloors
    } else if a.epoch != b.epoch {
        Comparison::DifferentEpochs
    } else {
        Comparison::SameCheckpoint
    };
    let (a, b) = if a.provider_id <= b.provider_id {
        (a, b)
    } else {
        (b, a)
    };
    let canonical = format!(
        "SAPPHON-146-EVIDENCE-v1\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n",
        a.provider_id,
        a.sequence,
        a.head_sha256,
        a.epoch,
        b.provider_id,
        b.sequence,
        b.head_sha256,
        b.epoch
    );
    Ok(Finding {
        schema: "sapphon-146-dual-anchor-v1".into(),
        comparison,
        first_provider_id: a.provider_id.clone(),
        second_provider_id: b.provider_id.clone(),
        first_sequence: a.sequence,
        second_sequence: b.sequence,
        first_head: a.head_sha256.clone(),
        second_head: b.head_sha256.clone(),
        first_epoch: a.epoch,
        second_epoch: b.epoch,
        transcript_sha256: hex::encode(Sha256::digest(canonical.as_bytes())),
        claimed_roots_distinct: true,
        signatures_valid: true,
        independent_custody_proven: false,
        external_checkpoint_accepted: false,
        lock_cleared: false,
        decision: "HOLD".into(),
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use ed25519_dalek::{Signer, SigningKey};

    fn pair(seed: u8, id: &str, seq: u64, head: &str, epoch: u64) -> (Anchor, ProvisionedProvider) {
        let signing = SigningKey::from_bytes(&[seed; 32]);
        let mut a = Anchor {
            schema: "sapphon-145-anchor-v1".into(),
            provider_id: id.into(),
            sequence: seq,
            head_sha256: head.into(),
            epoch,
            counter: 4,
            signature_base64: String::new(),
        };
        a.signature_base64 =
            STANDARD.encode(signing.sign(&anchor145::anchor_message(&a)).to_bytes());
        let p = ProvisionedProvider {
            provider_id: id.into(),
            public_key_hex: hex::encode(signing.verifying_key().as_bytes()),
            min_counter: 1,
            min_sequence: 0,
            min_epoch: 1,
            revoked: false,
        };
        (a, p)
    }
    fn run(
        a: &Anchor,
        ap: &ProvisionedProvider,
        b: &Anchor,
        bp: &ProvisionedProvider,
        roots: (&str, &str),
    ) -> Result<Finding, Error> {
        compare(
            (
                a,
                Custodian {
                    provider: ap,
                    claimed_root: roots.0,
                },
            ),
            (
                b,
                Custodian {
                    provider: bp,
                    claimed_root: roots.1,
                },
            ),
        )
    }
    #[test]
    fn matching_signatures_still_hold() {
        let (a, ap) = pair(1, "custodian-a", 2, &"a".repeat(64), 2);
        let (b, bp) = pair(2, "custodian-b", 2, &"a".repeat(64), 2);
        let finding = run(&a, &ap, &b, &bp, ("root-a", "root-b")).unwrap();
        assert_eq!(finding.comparison, Comparison::SameCheckpoint);
        assert!(finding.signatures_valid);
        assert!(
            !finding.independent_custody_proven
                && !finding.lock_cleared
                && !finding.external_checkpoint_accepted
        );
        assert_eq!(finding.decision, "HOLD");
    }
    #[test]
    fn conflicting_heads_at_same_sequence_detected() {
        let (a, ap) = pair(1, "custodian-a", 2, &"a".repeat(64), 2);
        let (b, bp) = pair(2, "custodian-b", 2, &"b".repeat(64), 2);
        let v = run(&a, &ap, &b, &bp, ("root-a", "root-b")).unwrap();
        assert_eq!(v.comparison, Comparison::ConflictingHeadAtSameSequence);
        assert_eq!(v.decision, "HOLD");
    }
    #[test]
    fn staggered_sequences_not_misreported_as_equivocation() {
        let (a, ap) = pair(1, "custodian-a", 2, &"a".repeat(64), 2);
        let (b, bp) = pair(2, "custodian-b", 3, &"b".repeat(64), 2);
        assert_eq!(
            run(&a, &ap, &b, &bp, ("root-a", "root-b"))
                .unwrap()
                .comparison,
            Comparison::DifferentSequenceFloors
        );
    }
    #[test]
    fn duplicate_ancestry_and_signing_key_fail_closed() {
        let (a, ap) = pair(1, "custodian-a", 2, &"a".repeat(64), 2);
        let (b, bp) = pair(1, "custodian-b", 2, &"a".repeat(64), 2);
        assert_eq!(
            run(&a, &ap, &b, &bp, ("root-a", "root-a")).unwrap_err().0,
            "DUAL_SHARED_ANCESTRY"
        );
        assert_eq!(
            run(&a, &ap, &b, &bp, ("root-a", "root-b")).unwrap_err().0,
            "DUAL_SHARED_SIGNING_KEY"
        );
    }
    #[test]
    fn forged_second_signature_blocks_comparison() {
        let (a, ap) = pair(1, "custodian-a", 2, &"a".repeat(64), 2);
        let (mut b, bp) = pair(2, "custodian-b", 2, &"a".repeat(64), 2);
        b.signature_base64 = STANDARD.encode([0u8; 64]);
        assert_eq!(
            run(&a, &ap, &b, &bp, ("root-a", "root-b")).unwrap_err().0,
            "ANCHOR_SIGNATURE"
        );
    }
    #[test]
    fn revoked_or_stale_provider_blocks_comparison() {
        let (a, ap) = pair(1, "custodian-a", 2, &"a".repeat(64), 2);
        let (b, mut bp) = pair(2, "custodian-b", 2, &"a".repeat(64), 2);
        bp.revoked = true;
        assert_eq!(
            run(&a, &ap, &b, &bp, ("root-a", "root-b")).unwrap_err().0,
            "ANCHOR_REVOKED"
        );
        bp.revoked = false;
        bp.min_counter = 4;
        assert_eq!(
            run(&a, &ap, &b, &bp, ("root-a", "root-b")).unwrap_err().0,
            "ANCHOR_ROLLBACK"
        );
    }
    #[test]
    fn ordering_does_not_change_evidence_digest() {
        let (a, ap) = pair(1, "custodian-a", 2, &"a".repeat(64), 2);
        let (b, bp) = pair(2, "custodian-b", 2, &"a".repeat(64), 2);
        let left = run(&a, &ap, &b, &bp, ("root-a", "root-b")).unwrap();
        let right = run(&b, &bp, &a, &ap, ("root-b", "root-a")).unwrap();
        assert_eq!(left, right);
    }
}
