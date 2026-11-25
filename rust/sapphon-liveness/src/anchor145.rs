//! SAPPHON-145: read-only anchor-provider qualification and restart recovery inspection.
//! Ed25519 authentication is bounded to a pre-provisioned key, not independent
//! custody. No local record, callback or signature can authorize lock removal.
use crate::{registry137, Error};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::Digest;

pub const AUTHORITY: &str = "HOLD";
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Anchor {
    pub schema: String,
    pub provider_id: String,
    pub sequence: u64,
    pub head_sha256: String,
    pub epoch: u64,
    pub counter: u64,
    pub signature_base64: String,
}
#[derive(Clone, Debug)]
pub struct ProvisionedProvider {
    pub provider_id: String,
    pub public_key_hex: String,
    /// Last *externally retained* monotonic counter. Not read from local journal.
    pub min_counter: u64,
    /// Last *externally retained* checkpoint.
    pub min_sequence: u64,
    pub min_epoch: u64,
    pub revoked: bool,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryState {
    MatchesSuppliedAnchor,
    LocalAheadOfAnchor,
    LocalBehindAnchor,
    LocalConflictsWithAnchor,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Assessment {
    pub state: RecoveryState,
    pub signed_anchor_verified: bool,
    pub provider_independence_proven: bool,
    pub authority: &'static str,
    pub lock_cleared: bool,
    pub external_checkpoint_accepted: bool,
}
fn digest(s: &str) -> bool {
    s.len()==64 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
pub fn anchor_message(a: &Anchor) -> Vec<u8> {
    format!("SAPPHON-145-ANCHOR-v1\n{}\n{}\n{}\n{}\n{}\n",
        a.provider_id, a.sequence, a.head_sha256, a.epoch, a.counter).into_bytes()
}
/// Validate a signed anchor against provisioned trust and independently held
/// counter floors. This cannot prove that the provisioner is external.
pub fn verify_anchor(a: &Anchor, p: &ProvisionedProvider) -> Result<(), Error> {
    if a.schema != "sapphon-145-anchor-v1"
        || a.provider_id.is_empty() || a.provider_id != p.provider_id
        || !digest(&a.head_sha256) { return Err(Error("ANCHOR_FIELDS")); }
    if p.revoked { return Err(Error("ANCHOR_REVOKED")); }
    if a.counter <= p.min_counter || a.sequence < p.min_sequence
        || a.epoch < p.min_epoch { return Err(Error("ANCHOR_ROLLBACK")); }
    let key=hex::decode(&p.public_key_hex).map_err(|_|Error("ANCHOR_KEY"))?;
    let key: [u8;32]=key.try_into().map_err(|_|Error("ANCHOR_KEY"))?;
    let verifying_key=VerifyingKey::from_bytes(&key).map_err(|_|Error("ANCHOR_KEY"))?;
    let signature=STANDARD.decode(&a.signature_base64).map_err(|_|Error("ANCHOR_SIGNATURE"))?;
    let sig: [u8;64]=signature.try_into().map_err(|_|Error("ANCHOR_SIGNATURE"))?;
    verifying_key.verify(&anchor_message(a), &Signature::from_bytes(&sig))
        .map_err(|_|Error("ANCHOR_SIGNATURE"))
}
/// Does not repair rollback or promote a matching local history. A corrupted
/// journal is an error, never a candidate for recovery.
/// Prefix-compatible histories are classified; contradictory equal-sequence
/// histories are conflicts. Only one provisioned signing root is considered.
pub fn inspect_restart(
    transcript: &[u8],
    expected_local_sequence: u64,
    expected_local_head: &str,
    anchor: &Anchor,
    provider: &ProvisionedProvider,
) -> Result<Assessment, Error> {
    verify_anchor(anchor, provider)?;
    let local=registry137::verify(transcript,expected_local_sequence,expected_local_head)?;
    // Need to prove anchor is a retained prefix, not infer it from sequence.
    let mut selected_head=registry137::genesis_head();
    if anchor.sequence>0 && local.seq>=anchor.sequence {
        let mut lines=transcript.split_inclusive(|b|*b==b'\n');
        for _ in 0..anchor.sequence {
            let line=lines.next().ok_or(Error("ANCHOR_PREFIX_UNKNOWN"))?;
            if line.last()!=Some(&b'\n') { return Err(Error("ANCHOR_PREFIX_UNKNOWN")); }
            let e:registry137::Event=serde_json::from_slice(&line[..line.len()-1])
                .map_err(|_|Error("ANCHOR_PREFIX_CORRUPT"))?;
            selected_head=hex::encode(sha2::Sha256::digest(
                serde_json::to_vec(&e).map_err(|_|Error("ANCHOR_ENCODING"))?));
        }
    }
    let state=if local.seq<anchor.sequence {
        RecoveryState::LocalBehindAnchor
    } else if local.seq==anchor.sequence {
        if local.head==anchor.head_sha256 {RecoveryState::MatchesSuppliedAnchor}
        else {RecoveryState::LocalConflictsWithAnchor}
    } else if local.seq>anchor.sequence {
        if selected_head==anchor.head_sha256 {RecoveryState::LocalAheadOfAnchor}
        else {RecoveryState::LocalConflictsWithAnchor}
    } else {
        RecoveryState::LocalConflictsWithAnchor
    };
    Ok(Assessment {
        state,signed_anchor_verified:true,provider_independence_proven:false,
        authority:"HOLD",lock_cleared:false,external_checkpoint_accepted:false,
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer,SigningKey};
    use sha2::Digest;
    fn signed(seq:u64,head:&str,counter:u64) -> (Anchor,ProvisionedProvider) {
        let sk=SigningKey::from_bytes(&[17;32]);
        let mut a=Anchor{schema:"sapphon-145-anchor-v1".into(),
            provider_id:"custodian-one".into(),sequence:seq,head_sha256:head.into(),
            epoch:9,counter,signature_base64:String::new()};
        a.signature_base64=STANDARD.encode(sk.sign(&anchor_message(&a)).to_bytes());
        let p=ProvisionedProvider{provider_id:a.provider_id.clone(),
            public_key_hex:hex::encode(sk.verifying_key().as_bytes()),
            min_counter:1,min_sequence:0,min_epoch:8,revoked:false};
        (a,p)
    }
    #[test] fn signed_genesis_stays_hold() {
        let h=registry137::genesis_head();let (a,p)=signed(0,&h,2);
        let v=inspect_restart(&[],0,&h,&a,&p).unwrap();
        assert_eq!(v.state,RecoveryState::MatchesSuppliedAnchor);
        assert!(v.signed_anchor_verified);
        assert!(!v.provider_independence_proven && !v.lock_cleared
            && !v.external_checkpoint_accepted);
        assert_eq!(v.authority,"HOLD");
    }
    #[test] fn forged_anchor_rejected() {
        let h=registry137::genesis_head();let (mut a,p)=signed(0,&h,2);
        a.signature_base64=STANDARD.encode([0u8;64]);
        assert_eq!(verify_anchor(&a,&p).unwrap_err().0,"ANCHOR_SIGNATURE");
    }
    #[test] fn revoked_and_stale_anchor_rejected() {
        let h=registry137::genesis_head();let (a,mut p)=signed(0,&h,2);
        p.revoked=true;assert_eq!(verify_anchor(&a,&p).unwrap_err().0,"ANCHOR_REVOKED");
        p.revoked=false;p.min_counter=2;
        assert_eq!(verify_anchor(&a,&p).unwrap_err().0,"ANCHOR_ROLLBACK");
    }
    #[test] fn local_data_cannot_replace_external_anchor() {
        let h=registry137::genesis_head();let (a,p)=signed(0,&h,2);
        assert_eq!(inspect_restart(b"{}\n",1,&h,&a,&p).unwrap_err().0,
            "REGISTRY_CHAIN");
    }
}
