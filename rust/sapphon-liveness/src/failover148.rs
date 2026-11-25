//! SAPPHON-148: immutable rotation-intent ledger and observation-only failover.
#![cfg(target_os = "linux")]
use crate::{anchor145::{self,Anchor,ProvisionedProvider},lineage147::{self,KeyRotation},Error};
use serde::{Serialize,Deserialize};
use sha2::{Digest,Sha256};
use std::{fs::{File,OpenOptions},io::Write,path::Path};
pub const AUTHORITY:&str="HOLD";
const LIMIT:usize=1024*1024;
fn sha(b:&[u8])->String {hex::encode(Sha256::digest(b))}
fn valid_sha(s:&str)->bool{s.len()==64&&s.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b))}
#[derive(Debug,Clone,Serialize,Deserialize,PartialEq,Eq)]
#[serde(deny_unknown_fields)]
pub struct Intent{
    pub schema:String,
    pub expected_history_sha256:String,
    pub rotation:KeyRotation,
    pub old_provider_id:String,
    pub authority:String,
}
#[derive(Debug,Clone,Copy,PartialEq,Eq)]
pub enum RotationState{Pending,ContinuityVerifiedCustodyPending,InterruptedHold,ConflictHold}
#[derive(Debug,Clone,PartialEq,Eq)]
pub struct RotationReview{
    pub state:RotationState,
    pub continuity_signatures_verified:bool,
    pub independent_custody_acknowledged:bool,
    pub replacement_key_accepted:bool,
    pub lock_cleared:bool,
    pub decision:&'static str,
}
pub fn inspect_intent(
    intent:&Intent, trusted_history_digest:&str,
    prior:&ProvisionedProvider, interrupted:bool
)->Result<RotationReview,Error>{
    if intent.schema!="sapphon-148-intent-v1" || intent.authority!="HOLD"
      || !valid_sha(&intent.expected_history_sha256)
      || intent.expected_history_sha256!=trusted_history_digest
      || intent.old_provider_id!=prior.provider_id {
        return Err(Error("FAILOVER_INTENT_MISMATCH"));
    }
    // An interrupted recording remains HOLD even when only a partial intent exists.
    if interrupted {
        return Ok(RotationReview{state:RotationState::InterruptedHold,
            continuity_signatures_verified:false,independent_custody_acknowledged:false,
            replacement_key_accepted:false,lock_cleared:false,decision:"HOLD"});
    }
    lineage147::verify_rotation(&intent.rotation,prior)?;
    Ok(RotationReview{state:RotationState::ContinuityVerifiedCustodyPending,
        continuity_signatures_verified:true,independent_custody_acknowledged:false,
        replacement_key_accepted:false,lock_cleared:false,decision:"HOLD"})
}
pub fn write_intent_new(path:&Path,intent:&Intent)->Result<String,Error>{
    if intent.schema!="sapphon-148-intent-v1" || intent.authority!="HOLD"
       || !valid_sha(&intent.expected_history_sha256) {
        return Err(Error("FAILOVER_INTENT_FIELDS"));
    }
    let bytes=serde_json::to_vec(intent).map_err(|_|Error("FAILOVER_ENCODING"))?;
    if bytes.len()>LIMIT{return Err(Error("FAILOVER_LIMIT"));}
    let mut f=OpenOptions::new().write(true).create_new(true).open(path)
        .map_err(|_|Error("FAILOVER_ALREADY_EXISTS"))?;
    f.write_all(&bytes).map_err(|_|Error("FAILOVER_WRITE"))?;
    f.sync_all().map_err(|_|Error("FAILOVER_FSYNC"))?;
    File::open(path.parent().ok_or(Error("FAILOVER_PARENT"))?)
        .and_then(|dir|dir.sync_all()).map_err(|_|Error("FAILOVER_DIRSYNC"))?;
    Ok(sha(&bytes))
}
pub fn read_intent(bytes:&[u8],expected_sha:&str)->Result<Intent,Error>{
    if bytes.len()>LIMIT || !valid_sha(expected_sha) || sha(bytes)!=expected_sha {
        return Err(Error("FAILOVER_DIGEST"));
    }
    let intent:Intent=serde_json::from_slice(bytes).map_err(|_|Error("FAILOVER_CORRUPT"))?;
    if intent.authority!="HOLD"||intent.schema!="sapphon-148-intent-v1"{
        return Err(Error("FAILOVER_INTENT_FIELDS"));
    }
    Ok(intent)
}
#[derive(Debug,Clone,Copy,PartialEq,Eq)]
pub enum ProviderState{Observed,Delayed,Missing,Revoked}
#[derive(Debug,Clone,Copy,PartialEq,Eq)]
pub enum FailoverFinding{BothPresent,OneDelayed,ProviderMissing,ProviderRevoked,ConflictingHeads}
#[derive(Debug,Clone,PartialEq,Eq)]
pub struct FailoverReview{
    pub finding:FailoverFinding,
    pub observed_signatures:usize,
    pub replacement_key_accepted:bool,
    pub custody_proven:bool,
    pub lock_cleared:bool,
    pub decision:&'static str,
}
/// Both independent signing claims must be externally provisioned.
/// Lack of response is NOT a signature and can never be replaced by a timer.
pub fn inspect_failover(
    a:Option<(&Anchor,&ProvisionedProvider,ProviderState)>,
    b:Option<(&Anchor,&ProvisionedProvider,ProviderState)>,
)->Result<FailoverReview,Error>{
    let mut verified=0;
    for item in [a,b].iter().flatten(){
        if item.2==ProviderState::Observed || item.2==ProviderState::Delayed {
            anchor145::verify_anchor(item.0,item.1)?;
            verified+=1;
        }
    }
    let finding=match (a,b) {
        (Some((aa,_,ProviderState::Observed)),Some((bb,_,ProviderState::Observed)))=>{
            if aa.sequence==bb.sequence && aa.head_sha256!=bb.head_sha256 {
                FailoverFinding::ConflictingHeads
            } else {FailoverFinding::BothPresent}
        },
        (Some((_,_,ProviderState::Revoked)),_)|(_,Some((_,_,ProviderState::Revoked)))=>
            FailoverFinding::ProviderRevoked,
        (Some((_,_,ProviderState::Delayed)),_)|(_,Some((_,_,ProviderState::Delayed)))=>
            FailoverFinding::OneDelayed,
        _=>FailoverFinding::ProviderMissing,
    };
    Ok(FailoverReview{finding,observed_signatures:verified,
        replacement_key_accepted:false,custody_proven:false,
        lock_cleared:false,decision:"HOLD"})
}
#[cfg(test)]
mod tests{
    use super::*;
    use base64::{engine::general_purpose::STANDARD,Engine as _};
    use ed25519_dalek::{SigningKey,Signer};
    fn key(seed:u8)->SigningKey{SigningKey::from_bytes(&[seed;32])}
    fn prior()->ProvisionedProvider{
        ProvisionedProvider{provider_id:"custodian-one".into(),
            public_key_hex:hex::encode(key(1).verifying_key().as_bytes()),
            min_counter:1,min_sequence:0,min_epoch:1,revoked:false}
    }
    fn intent()->Intent{
        let old=key(1);let new=key(2);
        let mut r=KeyRotation{schema:"sapphon-147-key-rotation-v1".into(),
            provider_id:"custodian-one".into(),
            prior_key_hex:hex::encode(old.verifying_key().as_bytes()),
            replacement_key_hex:hex::encode(new.verifying_key().as_bytes()),
            prior_epoch:2,replacement_epoch:3,prior_counter:2,replacement_counter:3,
            old_signature_base64:String::new(),new_signature_base64:String::new()};
        let m=lineage147::rotation_message(&r);
        r.old_signature_base64=STANDARD.encode(old.sign(&m).to_bytes());
        r.new_signature_base64=STANDARD.encode(new.sign(&m).to_bytes());
        Intent{schema:"sapphon-148-intent-v1".into(),
            expected_history_sha256:"a".repeat(64),rotation:r,
            old_provider_id:"custodian-one".into(),authority:"HOLD".into()}
    }
    fn anchor(seed:u8,id:&str,head:&str)->(Anchor,ProvisionedProvider){
        let k=key(seed);let mut a=Anchor{schema:"sapphon-145-anchor-v1".into(),
            provider_id:id.into(),sequence:1,head_sha256:head.into(),
            epoch:2,counter:2,signature_base64:String::new()};
        a.signature_base64=STANDARD.encode(k.sign(&anchor145::anchor_message(&a)).to_bytes());
        (a,ProvisionedProvider{provider_id:id.into(),
            public_key_hex:hex::encode(k.verifying_key().as_bytes()),
            min_counter:1,min_sequence:0,min_epoch:1,revoked:false})
    }
    #[test]fn dual_signed_intent_remains_pending(){
        let r=inspect_intent(&intent(),&"a".repeat(64),&prior(),false).unwrap();
        assert_eq!(r.state,RotationState::ContinuityVerifiedCustodyPending);
        assert!(r.continuity_signatures_verified);
        assert!(!r.replacement_key_accepted&&!r.lock_cleared&&!r.independent_custody_acknowledged);
    }
    #[test]fn interrupted_intent_never_accepts_key(){
        let r=inspect_intent(&intent(),&"a".repeat(64),&prior(),true).unwrap();
        assert_eq!(r.state,RotationState::InterruptedHold);
        assert!(!r.replacement_key_accepted);
    }
    #[test]fn changed_history_anchor_rejected(){
        assert_eq!(inspect_intent(&intent(),&"b".repeat(64),&prior(),false)
            .unwrap_err().0,"FAILOVER_INTENT_MISMATCH");
    }
    #[test]fn missing_second_custodian_does_not_authorize_failover(){
        let(a,ap)=anchor(1,"custodian-one",&"a".repeat(64));
        let r=inspect_failover(Some((&a,&ap,ProviderState::Observed)),None).unwrap();
        assert_eq!(r.finding,FailoverFinding::ProviderMissing);
        assert!(!r.replacement_key_accepted&&!r.custody_proven);
    }
    #[test]fn delayed_second_custodian_does_not_become_missing(){
        let(a,ap)=anchor(1,"custodian-one",&"a".repeat(64));
        let(b,bp)=anchor(2,"custodian-two",&"a".repeat(64));
        let r=inspect_failover(Some((&a,&ap,ProviderState::Observed)),
            Some((&b,&bp,ProviderState::Delayed))).unwrap();
        assert_eq!(r.finding,FailoverFinding::OneDelayed);
        assert_eq!(r.observed_signatures,2);
        assert_eq!(r.decision,"HOLD");
    }
    #[test]fn matching_signatures_cannot_clear_lock(){
        let(a,ap)=anchor(1,"custodian-one",&"a".repeat(64));
        let(b,bp)=anchor(2,"custodian-two",&"a".repeat(64));
        let r=inspect_failover(Some((&a,&ap,ProviderState::Observed)),
            Some((&b,&bp,ProviderState::Observed))).unwrap();
        assert_eq!(r.finding,FailoverFinding::BothPresent);
        assert!(!r.lock_cleared&&!r.replacement_key_accepted);
    }
    #[test]fn create_only_intent_detects_tamper_and_rewrite(){
        let p=std::env::temp_dir().join(format!("sapphon148-{}.json",std::process::id()));
        let _=std::fs::remove_file(&p);
        let digest=write_intent_new(&p,&intent()).unwrap();
        let bytes=std::fs::read(&p).unwrap();
        assert!(read_intent(&bytes,&digest).is_ok());
        assert_eq!(write_intent_new(&p,&intent()).unwrap_err().0,"FAILOVER_ALREADY_EXISTS");
        let mut altered=bytes;altered.push(b' ');
        assert_eq!(read_intent(&altered,&digest).unwrap_err().0,"FAILOVER_DIGEST");
        std::fs::remove_file(&p).unwrap();
    }
    #[test]fn conflicting_heads_preserved_as_disagreement(){
        let(a,ap)=anchor(1,"custodian-one",&"a".repeat(64));
        let(b,bp)=anchor(2,"custodian-two",&"b".repeat(64));
        let r=inspect_failover(Some((&a,&ap,ProviderState::Observed)),
            Some((&b,&bp,ProviderState::Observed))).unwrap();
        assert_eq!(r.finding,FailoverFinding::ConflictingHeads);
        assert_eq!(r.decision,"HOLD");
    }
    #[test]fn unavailable_revoked_provider_cannot_be_substituted(){
        let(a,ap)=anchor(1,"custodian-one",&"a".repeat(64));
        let(b,bp)=anchor(2,"custodian-two",&"a".repeat(64));
        let r=inspect_failover(Some((&a,&ap,ProviderState::Observed)),
            Some((&b,&bp,ProviderState::Revoked))).unwrap();
        assert_eq!(r.finding,FailoverFinding::ProviderRevoked);
        assert!(!r.replacement_key_accepted);
    }
    #[test]fn missing_rotation_signature_fails_continuity(){
        let mut i=intent();
        i.rotation.new_signature_base64=STANDARD.encode([0u8;64]);
        assert_eq!(inspect_intent(&i,&"a".repeat(64),&prior(),false)
            .unwrap_err().0,"ROTATION_SIGNATURE");
    }

}
