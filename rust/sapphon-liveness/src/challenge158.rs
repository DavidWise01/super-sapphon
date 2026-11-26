//! SAPPHON-158 — out-of-band challenge binding and replay inspection.
//! The challenge manifest and used-nonce history MUST be externally retained.
//! Cryptographic validity alone never proves real-world custody independence.
#![cfg(target_os="linux")]
use crate::{enrollment157::{self,Enrollment,ExternallyProvisioned},Error};
use serde::{Deserialize,Serialize};
use sha2::{Digest,Sha256};
use std::{collections::BTreeSet,fs::{File,OpenOptions},io::Write,path::Path};
pub const AUTHORITY:&str="HOLD";
const MAX:usize=1024*1024;
fn sha(b:&[u8])->String{hex::encode(Sha256::digest(b))}
fn valid(s:&str)->bool{s.len()==64&&s.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b))}
#[derive(Debug,Clone,Serialize,Deserialize,PartialEq,Eq)]
#[serde(deny_unknown_fields)]
pub struct Challenge {
    pub schema:String,
    pub challenge_id:String,
    pub custodian_id:String,
    pub expected_nonce_sha256:String,
    pub expected_artifact_sha256:String,
    pub expected_ancestry_sha256:String,
    pub epoch_floor:u64,
    pub counter_floor:u64,
}
#[derive(Debug,Clone,Serialize,Deserialize,PartialEq,Eq)]
#[serde(deny_unknown_fields)]
pub struct ReplayReview {
    pub schema:String,
    pub challenge_id:String,
    pub custodian_id:String,
    pub verified_receipt_signature:bool,
    pub challenge_binding_verified:bool,
    pub nonce_new_against_supplied_history:bool,
    pub external_history_authenticated:bool,
    pub external_custody_authenticated:bool,
    pub accepted_as_external_custodian:bool,
    pub recovery_authorized:bool,
    pub lock_cleared:bool,
    pub decision:String,
    pub evidence_sha256:String,
}
/// Previous nonces are supplied as a retained set. We do not trust a local
/// self-reported set to establish freshness across process restarts.
pub fn inspect(
    receipt:&Enrollment,
    provisioned:&ExternallyProvisioned,
    challenge:&Challenge,
    consumed_nonce_sha256:&[String],
)->Result<ReplayReview,Error>{
    if challenge.schema!="sapphon-158-challenge-v1"
       ||challenge.challenge_id.is_empty()||challenge.challenge_id.len()>128
       ||challenge.custodian_id!=receipt.custodian_id
       ||!valid(&challenge.expected_nonce_sha256)
       ||!valid(&challenge.expected_artifact_sha256)
       ||!valid(&challenge.expected_ancestry_sha256){
        return Err(Error("CHAL158_FIELDS"));
    }
    if consumed_nonce_sha256.len()>4096 ||consumed_nonce_sha256.iter().any(|s|!valid(s)){
        return Err(Error("CHAL158_HISTORY_FIELDS"));
    }
    // Domain-separated Ed25519 signature, provisioning floors and revocation
    // are checked by the predecessor's enrollment verifier.
    let enrollment157::EnrollmentReview { .. } = enrollment157::inspect(
        receipt,Some(provisioned),receipt,Some(provisioned))?;
    if receipt.nonce_sha256!=challenge.expected_nonce_sha256
        ||receipt.signed_receipt_sha256!=challenge.expected_artifact_sha256
        ||receipt.ancestry_sha256!=challenge.expected_ancestry_sha256{
        return Err(Error("CHAL158_BINDING_MISMATCH"));
    }
    if receipt.epoch<challenge.epoch_floor
        ||receipt.counter<=challenge.counter_floor {
        return Err(Error("CHAL158_STALE_COUNTER"));
    }
    let mut unique=BTreeSet::new();
    for nonce in consumed_nonce_sha256{
        if !unique.insert(nonce.as_str()){
            return Err(Error("CHAL158_HISTORY_DUPLICATE"));
        }
    }
    if unique.contains(receipt.nonce_sha256.as_str()){
        return Err(Error("CHAL158_NONCE_REPLAY"));
    }
    let canonical=serde_json::to_vec(&(challenge,receipt,consumed_nonce_sha256))
        .map_err(|_|Error("CHAL158_ENCODING"))?;
    Ok(ReplayReview{
        schema:"sapphon-158-replay-review-v1".into(),
        challenge_id:challenge.challenge_id.clone(),
        custodian_id:receipt.custodian_id.clone(),
        verified_receipt_signature:true,
        challenge_binding_verified:true,
        nonce_new_against_supplied_history:true,
        external_history_authenticated:false,
        external_custody_authenticated:false,
        accepted_as_external_custodian:false,
        recovery_authorized:false,lock_cleared:false,
        decision:"CHALLENGE_HOLD".into(),evidence_sha256:sha(&canonical),
    })
}
pub fn write_new(path:&Path,r:&ReplayReview)->Result<String,Error>{
    if r.schema!="sapphon-158-replay-review-v1"
       ||r.decision!="CHALLENGE_HOLD"
       ||r.external_history_authenticated||r.external_custody_authenticated
       ||r.accepted_as_external_custodian||r.recovery_authorized||r.lock_cleared{
        return Err(Error("CHAL158_AUTHORITY"));
    }
    let bytes=serde_json::to_vec(r).map_err(|_|Error("CHAL158_ENCODING"))?;
    if bytes.len()>MAX{return Err(Error("CHAL158_LIMIT"));}
    let mut f=OpenOptions::new().write(true).create_new(true).open(path)
        .map_err(|_|Error("CHAL158_EXISTS"))?;
    f.write_all(&bytes).map_err(|_|Error("CHAL158_WRITE"))?;
    f.sync_all().map_err(|_|Error("CHAL158_FSYNC"))?;
    File::open(path.parent().ok_or(Error("CHAL158_PARENT"))?)
        .and_then(|p|p.sync_all()).map_err(|_|Error("CHAL158_DIRSYNC"))?;
    Ok(sha(&bytes))
}
#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::STANDARD,Engine as _};
    use ed25519_dalek::{SigningKey,Signer};
    fn fixture()->(Enrollment,ExternallyProvisioned,Challenge){
        let sk=SigningKey::from_bytes(&[8;32]);
        let mut receipt=Enrollment{
            schema:"sapphon-157-enrollment-v1".into(),
            custodian_id:"custodian-outside".into(),
            claimed_organization:"outside-operator".into(),
            ancestry_sha256:"c".repeat(64),
            public_key_hex:hex::encode(sk.verifying_key().as_bytes()),
            nonce_sha256:"a".repeat(64),
            signed_receipt_sha256:"b".repeat(64),
            epoch:3,counter:7,signature_base64:String::new(),
        };
        receipt.signature_base64=STANDARD.encode(
            sk.sign(&enrollment157::signature_message(&receipt)).to_bytes());
        let provisioned=ExternallyProvisioned{
            custodian_id:receipt.custodian_id.clone(),
            public_key_hex:receipt.public_key_hex.clone(),
            min_epoch:2,min_counter:5,revoked:false,
        };
        let challenge=Challenge{
            schema:"sapphon-158-challenge-v1".into(),challenge_id:"challenge-001".into(),
            custodian_id:receipt.custodian_id.clone(),
            expected_nonce_sha256:receipt.nonce_sha256.clone(),
            expected_artifact_sha256:receipt.signed_receipt_sha256.clone(),
            expected_ancestry_sha256:receipt.ancestry_sha256.clone(),
            epoch_floor:3,counter_floor:6,
        };
        (receipt,provisioned,challenge)
    }
    fn resign(r:&mut Enrollment){
        let sk=SigningKey::from_bytes(&[8;32]);
        r.signature_base64=STANDARD.encode(
            sk.sign(&enrollment157::signature_message(r)).to_bytes());
    }
    #[test]fn fresh_verified_receipt_still_hold(){
        let(r,p,c)=fixture();let o=inspect(&r,&p,&c,&[]).unwrap();
        assert!(o.verified_receipt_signature&&o.challenge_binding_verified);
        assert!(!o.external_history_authenticated&&!o.external_custody_authenticated
            &&!o.recovery_authorized&&!o.lock_cleared);
    }
    #[test]fn replayed_nonce_is_rejected(){
        let(r,p,c)=fixture();
        assert_eq!(inspect(&r,&p,&c,&[r.nonce_sha256.clone()]).unwrap_err().0,
            "CHAL158_NONCE_REPLAY");
    }
    #[test]fn counterfeit_challenge_nonce_rejected(){
        let(r,p,mut c)=fixture();c.expected_nonce_sha256="e".repeat(64);
        assert_eq!(inspect(&r,&p,&c,&[]).unwrap_err().0,"CHAL158_BINDING_MISMATCH");
    }
    #[test]fn changed_artifact_binding_rejected(){
        let(r,p,mut c)=fixture();c.expected_artifact_sha256="e".repeat(64);
        assert_eq!(inspect(&r,&p,&c,&[]).unwrap_err().0,"CHAL158_BINDING_MISMATCH");
    }
    #[test]fn changed_signed_nonce_fails_signature(){
        let(mut r,p,c)=fixture();r.nonce_sha256="d".repeat(64);
        assert_eq!(inspect(&r,&p,&c,&[]).unwrap_err().0,"ENR157_SIGNATURE");
    }
    #[test]fn stale_counter_rejected_even_with_valid_signature(){
        let(r,p,mut c)=fixture();c.counter_floor=7;
        assert_eq!(inspect(&r,&p,&c,&[]).unwrap_err().0,"CHAL158_STALE_COUNTER");
    }
    #[test]fn revoked_custodian_is_rejected(){
        let(r,mut p,c)=fixture();p.revoked=true;
        assert_eq!(inspect(&r,&p,&c,&[]).unwrap_err().0,"ENR157_REVOKED");
    }
    #[test]fn mismatched_ancestry_is_rejected(){
        let(r,p,mut c)=fixture();c.expected_ancestry_sha256="d".repeat(64);
        assert_eq!(inspect(&r,&p,&c,&[]).unwrap_err().0,"CHAL158_BINDING_MISMATCH");
    }
    #[test]fn modified_signed_artifact_requires_new_signature(){
        let(mut r,p,c)=fixture();r.signed_receipt_sha256="e".repeat(64);
        assert_eq!(inspect(&r,&p,&c,&[]).unwrap_err().0,"ENR157_SIGNATURE");
    }
    #[test]fn duplicate_prior_nonces_are_invalid_history(){
        let(r,p,c)=fixture();let previous="f".repeat(64);
        assert_eq!(inspect(&r,&p,&c,&[previous.clone(),previous]).unwrap_err().0,
            "CHAL158_HISTORY_DUPLICATE");
    }
    #[test]fn valid_resigned_receipt_must_match_pinned_challenge(){
        let(mut r,p,c)=fixture();r.nonce_sha256="f".repeat(64);resign(&mut r);
        assert_eq!(inspect(&r,&p,&c,&[]).unwrap_err().0,"CHAL158_BINDING_MISMATCH");
    }
    #[test]fn create_only_report_denies_overwrite(){
        let(r,p,c)=fixture();let review=inspect(&r,&p,&c,&[]).unwrap();
        let path=std::env::temp_dir().join(format!("sapphon158-{}.json",std::process::id()));
        let _=std::fs::remove_file(&path);
        write_new(&path,&review).unwrap();
        assert_eq!(write_new(&path,&review).unwrap_err().0,"CHAL158_EXISTS");
        std::fs::remove_file(path).unwrap();
    }
}
