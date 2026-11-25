//! SAPPHON-140 — dual-signature checkpoint receipts and restart reconciliation.
//! Signatures validate against a *caller-supplied* independently provisioned
//! registry. Two keys/ancestry labels do not prove independent physical custody.
//! No method updates the externally trusted registry anchor or clears a lock.
use crate::{
    attest136::TrustedKey,
    registry137,
    writer139::PendingCheckpoint,
    Error,
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};

pub const AUTHORITY: &str = "HOLD";
pub const REQUIRED_SIGNERS: usize = 2;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CheckpointReceipt {
    pub schema: String,
    pub witness_id: String,
    pub seq: u64,
    pub head: String,
    pub prior_seq: u64,
    pub prior_head: String,
    pub witness_counter: u64,
    pub signature_base64: String,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reconciliation {
    /// Local fsync completed, checkpoint not authenticated by two keys.
    LocalDurablePending,
    /// Two signatures verified, but external monotonic custody is not proven.
    DualSignedCustodyPending,
    /// Same checkpoint exists at the independently supplied anchor.
    /// Still no recovery or clock authority.
    AtSuppliedAnchorHold,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Review {
    pub state: Reconciliation,
    pub validated_signatures: usize,
    pub distinct_declared_roots: usize,
    pub decision: &'static str,
    pub external_checkpoint_acknowledged: bool,
    pub lock_cleared: bool,
    pub global_anti_rollback: bool,
}
pub fn receipt_message(r: &CheckpointReceipt) -> Vec<u8> {
    format!(
        "SAPPHON-140-CHECKPOINT-v1\n{}\n{}\n{}\n{}\n{}\n{}\n",
        r.witness_id,r.seq,r.head,r.prior_seq,r.prior_head,r.witness_counter
    ).into_bytes()
}
fn digest(s: &str) -> bool {
    s.len()==64 && s.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}
fn validate_receipts(
    pending: &PendingCheckpoint,
    prior_seq: u64,
    prior_head: &str,
    registry: &[TrustedKey],
    receipts: &[CheckpointReceipt],
) -> Result<(usize, usize), Error> {
    if registry.len()>32 || receipts.len()>32 {return Err(Error("CHECKPOINT_LIMIT"));}
    let mut by_id=HashMap::new();
    let mut pubkeys=HashSet::new();
    for key in registry {
        if key.witness_id.is_empty() || key.ancestry_root.is_empty()
           || !pubkeys.insert(key.public_key_hex.as_str())
           || by_id.insert(key.witness_id.as_str(),key).is_some() {
            return Err(Error("CHECKPOINT_REGISTRY_CONFLICT"));
        }
    }
    let mut seen=HashSet::new();
    let mut roots=HashSet::new();
    for r in receipts {
        if r.schema!="sapphon-140-checkpoint-receipt-v1" || !digest(&r.head)
           || !digest(&r.prior_head) {
            return Err(Error("CHECKPOINT_FIELDS"));
        }
        if !seen.insert(r.witness_id.as_str()) {return Err(Error("CHECKPOINT_DUPLICATE"));}
        if r.seq!=pending.seq || r.head!=pending.head
           || r.prior_seq!=prior_seq || r.prior_head!=prior_head {
            return Err(Error("CHECKPOINT_EQUIVOCATION"));
        }
        let key=by_id.get(r.witness_id.as_str()).ok_or(Error("CHECKPOINT_UNKNOWN_KEY"))?;
        if key.revoked {return Err(Error("CHECKPOINT_REVOKED"));}
        if r.witness_counter<=key.min_counter {return Err(Error("CHECKPOINT_REPLAY"));}
        let raw=hex::decode(&key.public_key_hex).map_err(|_|Error("CHECKPOINT_KEY_INVALID"))?;
        let bytes: [u8;32]=raw.try_into().map_err(|_|Error("CHECKPOINT_KEY_INVALID"))?;
        let vk=VerifyingKey::from_bytes(&bytes).map_err(|_|Error("CHECKPOINT_KEY_INVALID"))?;
        let raw_sig=STANDARD.decode(&r.signature_base64).map_err(|_|Error("CHECKPOINT_SIGNATURE"))?;
        let sig_bytes: [u8;64]=raw_sig.try_into().map_err(|_|Error("CHECKPOINT_SIGNATURE"))?;
        vk.verify(&receipt_message(r),&Signature::from_bytes(&sig_bytes))
            .map_err(|_|Error("CHECKPOINT_SIGNATURE"))?;
        if !roots.insert(key.ancestry_root.as_str()) {
            return Err(Error("CHECKPOINT_SHARED_ANCESTRY"));
        }
    }
    Ok((receipts.len(),roots.len()))
}
/// The **prior** anchor must be retained in independent trusted storage.
/// The locally durable event must be exactly one new append to that anchor.
/// A signed acknowledgement is evidence only, never authority.
pub fn reconcile(
    transcript: &[u8],
    pending: &PendingCheckpoint,
    prior_seq: u64,
    prior_head: &str,
    registry: &[TrustedKey],
    receipts: &[CheckpointReceipt],
) -> Result<Review,Error> {
    if !pending.local_fsync_observed || pending.external_checkpoint_acknowledged
       || pending.decision!="HOLD" || pending.lock_cleared
       || !digest(prior_head) || !digest(&pending.head)
       || pending.seq!=prior_seq.checked_add(1).ok_or(Error("CHECKPOINT_OVERFLOW"))? {
        return Err(Error("CHECKPOINT_PENDING_INVALID"));
    }
    // Split only on the terminal newline: a truncated tail is quarantined.
    if transcript.last()!=Some(&b'\n') {return Err(Error("CHECKPOINT_TRUNCATED"));}
    let trimmed=&transcript[..transcript.len()-1];
    let start=trimmed.iter().rposition(|b|*b==b'\n').map_or(0,|i|i+1);
    let prefix=&transcript[..start];
    let last: registry137::Event=serde_json::from_slice(&trimmed[start..])
        .map_err(|_|Error("CHECKPOINT_CORRUPT"))?;
    registry137::verify(prefix,prior_seq,prior_head)?;
    if last.seq!=pending.seq || last.prev_hash!=prior_head {
        return Err(Error("CHECKPOINT_TRANSITION"));
    }
    let bytes=serde_json::to_vec(&last).map_err(|_|Error("CHECKPOINT_ENCODING"))?;
    let event_head=hex::encode(Sha256::digest(&bytes));
    if pending.head!=event_head {return Err(Error("CHECKPOINT_HEAD_MISMATCH"));}
    registry137::verify(transcript,pending.seq,&pending.head)?;
    let (valid,roots)=validate_receipts(pending,prior_seq,prior_head,registry,receipts)?;
    let state=if valid>=REQUIRED_SIGNERS {
        Reconciliation::DualSignedCustodyPending
    } else {
        Reconciliation::LocalDurablePending
    };
    Ok(Review {
        state,validated_signatures:valid,distinct_declared_roots:roots,
        decision:"HOLD",external_checkpoint_acknowledged:false,
        lock_cleared:false,global_anti_rollback:false,
    })
}
/// Review a checkpoint against a separately supplied accepted sequence/head.
/// This does NOT verify how that anchor was obtained or retained.
pub fn inspect_supplied_anchor(
    transcript: &[u8], anchor_seq: u64, anchor_head: &str
) -> Result<Review,Error> {
    registry137::verify(transcript,anchor_seq,anchor_head)?;
    Ok(Review {
        state:Reconciliation::AtSuppliedAnchorHold,
        validated_signatures:0,distinct_declared_roots:0,decision:"HOLD",
        external_checkpoint_acknowledged:false,lock_cleared:false,
        global_anti_rollback:false,
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    fn key(seed:u8)->SigningKey {SigningKey::from_bytes(&[seed;32])}
    fn record() -> (Vec<u8>,PendingCheckpoint,String) {
        let prior=registry137::genesis_head();
        let old=registry137::verify(&[],0,&prior).unwrap();
        let key_hex=hex::encode(key(7).verifying_key().as_bytes());
        let e=registry137::next(&old,"register","witness-one","root-one",&key_hex,1);
        let mut b=serde_json::to_vec(&e).unwrap();let head=hex::encode(Sha256::digest(&b));
        b.push(b'\n');
        (b,PendingCheckpoint{seq:1,head,local_fsync_observed:true,
            external_checkpoint_acknowledged:false,decision:"HOLD",lock_cleared:false},prior)
    }
    fn signed(p:&PendingCheckpoint,prior:&str,id:&str,root:&str,seed:u8)
      -> (TrustedKey,CheckpointReceipt) {
        let signer=key(seed);
        let mut r=CheckpointReceipt{
            schema:"sapphon-140-checkpoint-receipt-v1".into(), witness_id:id.into(),
            seq:p.seq,head:p.head.clone(),prior_seq:0,prior_head:prior.into(),
            witness_counter:3, signature_base64:String::new()
        };
        r.signature_base64=STANDARD.encode(signer.sign(&receipt_message(&r)).to_bytes());
        (TrustedKey{witness_id:id.into(),ancestry_root:root.into(),
            public_key_hex:hex::encode(signer.verifying_key().as_bytes()),
            revoked:false,min_counter:2},r)
    }
    #[test] fn no_receipts_remains_local_pending() {
        let (t,p,h)=record();
        let result=reconcile(&t,&p,0,&h,&[],&[]).unwrap();
        assert_eq!(result.state,Reconciliation::LocalDurablePending);
        assert_eq!(result.decision,"HOLD");
        assert!(!result.external_checkpoint_acknowledged);
    }
    #[test] fn two_valid_signatures_still_cannot_acknowledge_external_custody() {
        let(t,p,h)=record();
        let (a,x)=signed(&p,&h,"witness-a","root-a",2);
        let (b,y)=signed(&p,&h,"witness-b","root-b",3);
        let result=reconcile(&t,&p,0,&h,&[a,b],&[x,y]).unwrap();
        assert_eq!(result.state,Reconciliation::DualSignedCustodyPending);
        assert_eq!(result.validated_signatures,2);
        assert!(!result.lock_cleared && !result.external_checkpoint_acknowledged
            && !result.global_anti_rollback);
    }
    #[test] fn reused_ancestry_is_rejected() {
        let(t,p,h)=record();
        let(a,x)=signed(&p,&h,"witness-a","one-root",2);
        let(b,y)=signed(&p,&h,"witness-b","one-root",3);
        assert_eq!(reconcile(&t,&p,0,&h,&[a,b],&[x,y]).unwrap_err().0,
            "CHECKPOINT_SHARED_ANCESTRY");
    }
    #[test] fn forged_receipt_fails_closed() {
        let(t,p,h)=record();let(k,mut r)=signed(&p,&h,"witness-a","root-a",2);
        r.signature_base64=STANDARD.encode([0u8;64]);
        assert_eq!(reconcile(&t,&p,0,&h,&[k],&[r]).unwrap_err().0,
            "CHECKPOINT_SIGNATURE");
    }
    #[test] fn revoked_and_stale_signatures_fail() {
        let(t,p,h)=record();let(mut k,r)=signed(&p,&h,"witness-a","root-a",2);
        k.revoked=true;
        assert_eq!(reconcile(&t,&p,0,&h,&[k.clone()],[r.clone()].as_slice()).unwrap_err().0,
            "CHECKPOINT_REVOKED");
        k.revoked=false;k.min_counter=3;
        assert_eq!(reconcile(&t,&p,0,&h,&[k],&[r]).unwrap_err().0,"CHECKPOINT_REPLAY");
    }
    #[test] fn incorrect_prior_anchor_cannot_promote_local_record() {
        let(t,p,_)=record();
        assert!(reconcile(&t,&p,0,&"0".repeat(64),&[],&[]).is_err());
    }
    #[test] fn restart_with_truncated_tail_is_quarantined() {
        let(mut t,p,h)=record();t.pop();
        assert_eq!(reconcile(&t,&p,0,&h,&[],&[]).unwrap_err().0,"CHECKPOINT_TRUNCATED");
    }
    #[test] fn supplied_current_anchor_never_grants_recovery() {
        let(t,p,_)=record();
        let result=inspect_supplied_anchor(&t,p.seq,&p.head).unwrap();
        assert_eq!(result.state,Reconciliation::AtSuppliedAnchorHold);
        assert!(!result.external_checkpoint_acknowledged && !result.lock_cleared);
    }
}
