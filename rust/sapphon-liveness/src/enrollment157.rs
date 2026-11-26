//! SAPPHON-157: separately provisioned external custodian enrollment.
//! Cryptographic proof of key possession is not proof of organizational or
//! physical separation. Enrollment is proposed only; authority remains HOLD.
#![cfg(target_os="linux")]
use crate::{custody156, Error};
use base64::{engine::general_purpose::STANDARD,Engine as _};
use ed25519_dalek::{Signature,Verifier,VerifyingKey};
use serde::{Deserialize,Serialize};
use sha2::{Digest,Sha256};
use std::{fs::{File,OpenOptions},io::Write,path::Path};
pub const AUTHORITY:&str="HOLD";
fn hash(b:&[u8])->String{hex::encode(Sha256::digest(b))}
fn hex64(s:&str)->bool{s.len()==64&&s.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b))}
#[derive(Debug,Clone,Serialize,Deserialize,PartialEq,Eq)]
#[serde(deny_unknown_fields)]
pub struct Enrollment{
    pub schema:String,
    pub custodian_id:String,
    pub claimed_organization:String,
    pub ancestry_sha256:String,
    pub public_key_hex:String,
    pub nonce_sha256:String,
    pub signed_receipt_sha256:String,
    pub epoch:u64,
    pub counter:u64,
    pub signature_base64:String,
}
#[derive(Debug,Clone)]
pub struct ExternallyProvisioned {
    pub custodian_id:String,
    pub public_key_hex:String,
    pub min_epoch:u64,
    pub min_counter:u64,
    pub revoked:bool,
}
#[derive(Debug,Clone,Copy,Serialize,Deserialize,PartialEq,Eq)]
pub enum EnrollmentFinding{VerifiedKeyPossessionCustodyUnqualified,SharedClaimedAncestry,DuplicateKeyOrCustodian,ConflictingArtifact,Unprovisioned}
#[derive(Debug,Clone,Serialize,Deserialize,PartialEq,Eq)]
#[serde(deny_unknown_fields)]
pub struct EnrollmentReview{
    pub schema:String,
    pub finding:EnrollmentFinding,
    pub signed_receipt_verified:bool,
    pub provisioned_identity_verified:bool,
    pub independent_custody_authenticated:bool,
    pub accepted_as_external_custodian:bool,
    pub recovery_authorized:bool,
    pub lock_cleared:bool,
    pub decision:String,
    pub evidence_sha256:String,
}
pub fn signature_message(r:&Enrollment)->Vec<u8>{
    format!("SAPPHON-157-EXTERNAL-ENROLLMENT-v1\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n",
        r.custodian_id,r.claimed_organization,r.ancestry_sha256,
        r.public_key_hex,r.nonce_sha256,r.signed_receipt_sha256,
        r.epoch,r.counter).into_bytes()
}
fn verify_one(e:&Enrollment,p:&ExternallyProvisioned)->Result<(),Error>{
    if e.schema!="sapphon-157-enrollment-v1"||e.custodian_id!=p.custodian_id
        ||e.public_key_hex!=p.public_key_hex
        ||e.custodian_id.len()<4||e.custodian_id.len()>96
        ||e.claimed_organization.len()<4||e.claimed_organization.len()>128
        ||!hex64(&e.ancestry_sha256)||!hex64(&e.nonce_sha256)
        ||!hex64(&e.signed_receipt_sha256)||!hex64(&e.public_key_hex) {
        return Err(Error("ENR157_FIELDS"));
    }
    if p.revoked {return Err(Error("ENR157_REVOKED"));}
    if e.epoch<p.min_epoch||e.counter<=p.min_counter{
        return Err(Error("ENR157_ROLLBACK"));
    }
    let bytes=hex::decode(&p.public_key_hex).map_err(|_|Error("ENR157_KEY"))?;
    let key:[u8;32]=bytes.try_into().map_err(|_|Error("ENR157_KEY"))?;
    let vk=VerifyingKey::from_bytes(&key).map_err(|_|Error("ENR157_KEY"))?;
    let sig=STANDARD.decode(&e.signature_base64).map_err(|_|Error("ENR157_SIGNATURE"))?;
    let raw:[u8;64]=sig.try_into().map_err(|_|Error("ENR157_SIGNATURE"))?;
    vk.verify(&signature_message(e),&Signature::from_bytes(&raw))
        .map_err(|_|Error("ENR157_SIGNATURE"))
}
/// Provisioned keys must come from an outside trust process. This function
/// verifies two distinct cryptographic keys but cannot authenticate custody.
pub fn inspect(
    a:&Enrollment,ap:Option<&ExternallyProvisioned>,
    b:&Enrollment,bp:Option<&ExternallyProvisioned>,
)->Result<EnrollmentReview,Error>{
    let (pa,pb)=match (ap,bp){
        (Some(x),Some(y))=>(x,y),
        _=>return Err(Error("ENR157_UNPROVISIONED")),
    };
    verify_one(a,pa)?;
    verify_one(b,pb)?;
    let finding=if a.custodian_id==b.custodian_id
        ||a.public_key_hex==b.public_key_hex{
        EnrollmentFinding::DuplicateKeyOrCustodian
    }else if a.ancestry_sha256==b.ancestry_sha256{
        EnrollmentFinding::SharedClaimedAncestry
    }else if a.signed_receipt_sha256!=b.signed_receipt_sha256{
        EnrollmentFinding::ConflictingArtifact
    }else{
        EnrollmentFinding::VerifiedKeyPossessionCustodyUnqualified
    };
    let mut statements=[a,b];
    statements.sort_by(|x,y|x.custodian_id.cmp(&y.custodian_id));
    let evidence=serde_json::to_vec(&statements).map_err(|_|Error("ENR157_ENCODING"))?;
    Ok(EnrollmentReview{
        schema:"sapphon-157-enrollment-review-v1".into(),finding,
        signed_receipt_verified:true,provisioned_identity_verified:true,
        independent_custody_authenticated:false,accepted_as_external_custodian:false,
        recovery_authorized:false,lock_cleared:false,
        decision:"ENROLLMENT_HOLD".into(),evidence_sha256:hash(&evidence),
    })
}
pub fn write_new(path:&Path,r:&EnrollmentReview)->Result<String,Error>{
    if r.schema!="sapphon-157-enrollment-review-v1"||r.decision!="ENROLLMENT_HOLD"
        ||r.independent_custody_authenticated||r.accepted_as_external_custodian
        ||r.recovery_authorized||r.lock_cleared{
        return Err(Error("ENR157_AUTHORITY"));
    }
    let bytes=serde_json::to_vec(r).map_err(|_|Error("ENR157_ENCODING"))?;
    if bytes.len()>1024*1024{return Err(Error("ENR157_LIMIT"));}
    let mut f=OpenOptions::new().write(true).create_new(true).open(path)
        .map_err(|_|Error("ENR157_EXISTS"))?;
    f.write_all(&bytes).map_err(|_|Error("ENR157_WRITE"))?;
    f.sync_all().map_err(|_|Error("ENR157_FSYNC"))?;
    File::open(path.parent().ok_or(Error("ENR157_PARENT"))?)
        .and_then(|p|p.sync_all()).map_err(|_|Error("ENR157_DIRSYNC"))?;
    Ok(hash(&bytes))
}
#[cfg(test)]
mod tests{
    use super::*;
    use ed25519_dalek::{Signer,SigningKey};
    fn signed(seed:u8,id:&str,ancestry:&str)->(Enrollment,ExternallyProvisioned){
        let sk=SigningKey::from_bytes(&[seed;32]);
        let mut e=Enrollment{schema:"sapphon-157-enrollment-v1".into(),
            custodian_id:id.into(),claimed_organization:format!("org-{id}"),
            ancestry_sha256:ancestry.into(),
            public_key_hex:hex::encode(sk.verifying_key().as_bytes()),
            nonce_sha256:"a".repeat(64),signed_receipt_sha256:"b".repeat(64),
            epoch:2,counter:3,signature_base64:String::new()};
        e.signature_base64=STANDARD.encode(sk.sign(&signature_message(&e)).to_bytes());
        let p=ExternallyProvisioned{custodian_id:id.into(),public_key_hex:e.public_key_hex.clone(),
            min_epoch:1,min_counter:1,revoked:false};
        (e,p)
    }
    #[test]fn two_verified_signatures_do_not_prove_independence(){
        let(a,pa)=signed(1,"source-a",&"c".repeat(64));
        let(b,pb)=signed(2,"source-b",&"d".repeat(64));
        let r=inspect(&a,Some(&pa),&b,Some(&pb)).unwrap();
        assert_eq!(r.finding,EnrollmentFinding::VerifiedKeyPossessionCustodyUnqualified);
        assert!(r.signed_receipt_verified&&!r.independent_custody_authenticated);
        assert!(!r.accepted_as_external_custodian&&!r.recovery_authorized);
    }
    #[test]fn shared_ancestry_is_not_second_witness(){
        let(a,pa)=signed(1,"source-a",&"c".repeat(64));
        let(b,pb)=signed(2,"source-b",&"c".repeat(64));
        assert_eq!(inspect(&a,Some(&pa),&b,Some(&pb)).unwrap().finding,
            EnrollmentFinding::SharedClaimedAncestry);
    }
    #[test]fn duplicated_signer_detected(){
        let(a,pa)=signed(1,"source-a",&"c".repeat(64));
        let(b,pb)=signed(1,"source-a",&"d".repeat(64));
        assert_eq!(inspect(&a,Some(&pa),&b,Some(&pb)).unwrap().finding,
            EnrollmentFinding::DuplicateKeyOrCustodian);
    }
    #[test]fn missing_external_provisioning_rejected(){
        let(a,pa)=signed(1,"source-a",&"c".repeat(64));
        let(b,_)=signed(2,"source-b",&"d".repeat(64));
        assert_eq!(inspect(&a,Some(&pa),&b,None).unwrap_err().0,"ENR157_UNPROVISIONED");
    }
    #[test]fn forged_signature_rejected(){
        let(a,pa)=signed(1,"source-a",&"c".repeat(64));
        let(mut b,pb)=signed(2,"source-b",&"d".repeat(64));
        b.nonce_sha256="f".repeat(64);
        assert_eq!(inspect(&a,Some(&pa),&b,Some(&pb)).unwrap_err().0,"ENR157_SIGNATURE");
    }
    #[test]fn stale_counter_rejected(){
        let(a,pa)=signed(1,"source-a",&"c".repeat(64));
        let(b,mut pb)=signed(2,"source-b",&"d".repeat(64));pb.min_counter=3;
        assert_eq!(inspect(&a,Some(&pa),&b,Some(&pb)).unwrap_err().0,"ENR157_ROLLBACK");
    }
    #[test]fn revoked_provider_rejected(){
        let(a,pa)=signed(1,"source-a",&"c".repeat(64));
        let(b,mut pb)=signed(2,"source-b",&"d".repeat(64));pb.revoked=true;
        assert_eq!(inspect(&a,Some(&pa),&b,Some(&pb)).unwrap_err().0,"ENR157_REVOKED");
    }
    #[test]fn conflicting_artifact_is_retained(){
        let(a,pa)=signed(1,"source-a",&"c".repeat(64));
        let(mut b,pb)=signed(2,"source-b",&"d".repeat(64));
        b.signed_receipt_sha256="e".repeat(64);
        let sk=SigningKey::from_bytes(&[2;32]);
        b.signature_base64=STANDARD.encode(sk.sign(&signature_message(&b)).to_bytes());
        assert_eq!(inspect(&a,Some(&pa),&b,Some(&pb)).unwrap().finding,
            EnrollmentFinding::ConflictingArtifact);
    }
    #[test]fn order_invariance_preserved(){
        let(a,pa)=signed(1,"source-a",&"c".repeat(64));
        let(b,pb)=signed(2,"source-b",&"d".repeat(64));
        assert_eq!(inspect(&a,Some(&pa),&b,Some(&pb)).unwrap(),
            inspect(&b,Some(&pb),&a,Some(&pa)).unwrap());
    }
}
