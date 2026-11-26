//! SAPPHON-159 — signed nonce-consumption transitions and fork inspection.
//! Verified signatures and self-hashes cannot establish external anti-rollback.
//! A trusted checkpoint and nonce-history root must be retained OUTSIDE GitHub.
#![cfg(target_os="linux")]
use crate::Error;
use base64::{engine::general_purpose::STANDARD,Engine as _};
use ed25519_dalek::{Signature,Verifier,VerifyingKey};
use serde::{Deserialize,Serialize};
use sha2::{Digest,Sha256};
use std::{collections::BTreeSet,fs::{File,OpenOptions},io::Write,path::Path};
pub const AUTHORITY:&str="HOLD";
const MAX_EVENTS:usize=2048;
fn sha(b:&[u8])->String{hex::encode(Sha256::digest(b))}
fn valid(s:&str)->bool{s.len()==64&&s.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b))}
pub fn genesis_head()->String{sha(b"SAPPHON-159-NONCE-LEDGER-GENESIS-v1")}
#[derive(Debug,Clone,Serialize,Deserialize,PartialEq,Eq)]
#[serde(deny_unknown_fields)]
pub struct Event{
    pub schema:String,
    pub sequence:u64,
    pub previous_sha256:String,
    pub custodian_id:String,
    pub nonce_sha256:String,
    pub artifact_sha256:String,
    pub counter:u64,
    pub signature_base64:String,
}
#[derive(Debug,Clone,Serialize,Deserialize,PartialEq,Eq)]
#[serde(deny_unknown_fields)]
pub struct ExternalFloor{
    pub schema:String,
    pub sequence:u64,
    pub head_sha256:String,
    pub minimum_counter:u64,
    pub custodian_id:String,
    pub public_key_hex:String,
    pub revoked:bool,
}
#[derive(Debug,Clone,Serialize,Deserialize,PartialEq,Eq)]
#[serde(deny_unknown_fields)]
pub struct ChainReview{
    pub schema:String,
    pub observed_sequence:u64,
    pub observed_head_sha256:String,
    pub trusted_floor_sequence:u64,
    pub trusted_floor_head_sha256:String,
    pub nonce_count:usize,
    pub signatures_verified:bool,
    pub external_floor_authenticated:bool,
    pub independent_custody_authenticated:bool,
    pub recovery_authorized:bool,
    pub lock_cleared:bool,
    pub decision:String,
}
#[derive(Debug,Clone,Copy,Serialize,Deserialize,PartialEq,Eq)]
pub enum ForkFinding{MatchingHead,EquivocationAtSameSequence,DifferentUnqualifiedHeights}
#[derive(Debug,Clone,Serialize,Deserialize,PartialEq,Eq)]
#[serde(deny_unknown_fields)]
pub struct ForkReview{
    pub schema:String,
    pub finding:ForkFinding,
    pub left_sequence:u64,
    pub right_sequence:u64,
    pub left_head_sha256:String,
    pub right_head_sha256:String,
    pub independent_custody_authenticated:bool,
    pub global_anti_rollback_authenticated:bool,
    pub recovery_authorized:bool,
    pub decision:String,
}
pub fn signed_message(e:&Event)->Vec<u8>{
    format!("SAPPHON-159-NONCE-EVENT-v1\n{}\n{}\n{}\n{}\n{}\n{}\n",
        e.sequence,e.previous_sha256,e.custodian_id,
        e.nonce_sha256,e.artifact_sha256,e.counter).into_bytes()
}
pub fn event_digest(e:&Event)->Result<String,Error>{
    serde_json::to_vec(e).map(|b|sha(&b)).map_err(|_|Error("LEDGER159_ENCODING"))
}
/// Validate the ENTIRE supplied lineage from the canonical genesis through
/// the trusted historical prefix; do not trust a locally chosen genesis.
/// This ledger is not a network-custody or physical-clock authority.
pub fn inspect(events:&[Event],floor:&ExternalFloor)->Result<ChainReview,Error>{
    if events.len()>MAX_EVENTS||floor.schema!="sapphon-159-external-floor-v1"
        ||!valid(&floor.head_sha256)||floor.custodian_id.len()<4
        ||floor.custodian_id.len()>96||floor.revoked{
        return Err(Error("LEDGER159_FLOOR_FIELDS"));
    }
    let raw=hex::decode(&floor.public_key_hex).map_err(|_|Error("LEDGER159_KEY"))?;
    let bytes:[u8;32]=raw.try_into().map_err(|_|Error("LEDGER159_KEY"))?;
    let key=VerifyingKey::from_bytes(&bytes).map_err(|_|Error("LEDGER159_KEY"))?;
    if floor.sequence>events.len() as u64{return Err(Error("LEDGER159_ROLLBACK"));}
    let mut head=genesis_head();
    let mut witnessed_floor=if floor.sequence==0{Some(head.clone())}else{None};
    let mut seen=BTreeSet::new();
    let mut counter=0_u64;
    for (i,e) in events.iter().enumerate(){
        let expected_sequence=(i as u64).checked_add(1).ok_or(Error("LEDGER159_SEQUENCE"))?;
        if e.schema!="sapphon-159-consumption-v1"
            ||e.sequence!=expected_sequence||e.previous_sha256!=head
            ||e.custodian_id!=floor.custodian_id
            ||!valid(&e.nonce_sha256)||!valid(&e.artifact_sha256){
            return Err(Error("LEDGER159_CHAIN"));
        }
        if !seen.insert(e.nonce_sha256.as_str()){return Err(Error("LEDGER159_NONCE_REPLAY"));}
        if e.counter<=counter{return Err(Error("LEDGER159_COUNTER_REPLAY"));}
        let sig=STANDARD.decode(&e.signature_base64)
            .map_err(|_|Error("LEDGER159_SIGNATURE"))?;
        let sig:[u8;64]=sig.try_into().map_err(|_|Error("LEDGER159_SIGNATURE"))?;
        key.verify(&signed_message(e),&Signature::from_bytes(&sig))
            .map_err(|_|Error("LEDGER159_SIGNATURE"))?;
        counter=e.counter;
        head=event_digest(e)?;
        if expected_sequence==floor.sequence{witnessed_floor=Some(head.clone());}
    }
    if witnessed_floor.as_deref()!=Some(floor.head_sha256.as_str()){
        return Err(Error("LEDGER159_PINNED_HEAD_CONFLICT"));
    }
    if counter<floor.minimum_counter{return Err(Error("LEDGER159_COUNTER_ROLLBACK"));}
    Ok(ChainReview{
        schema:"sapphon-159-chain-review-v1".into(),
        observed_sequence:events.len() as u64,observed_head_sha256:head,
        trusted_floor_sequence:floor.sequence,
        trusted_floor_head_sha256:floor.head_sha256.clone(),
        nonce_count:seen.len(),signatures_verified:true,
        external_floor_authenticated:false,independent_custody_authenticated:false,
        recovery_authorized:false,lock_cleared:false,decision:"LEDGER_HOLD".into(),
    })
}
/// Given two individually checked chains against the SAME trusted prefix,
/// a fork is observed only at equal sequence with different heads.
/// Different heights alone are not equivocation: require prefix evidence.
pub fn compare_forks(a:&ChainReview,b:&ChainReview)->Result<ForkReview,Error>{
    if a.schema!="sapphon-159-chain-review-v1"||b.schema!="sapphon-159-chain-review-v1"
      ||a.decision!="LEDGER_HOLD"||b.decision!="LEDGER_HOLD"
      ||!a.signatures_verified||!b.signatures_verified
      ||a.trusted_floor_sequence!=b.trusted_floor_sequence
      ||a.trusted_floor_head_sha256!=b.trusted_floor_head_sha256
      ||a.external_floor_authenticated||b.external_floor_authenticated
      ||a.independent_custody_authenticated||b.independent_custody_authenticated
      ||a.recovery_authorized||b.recovery_authorized
      ||a.lock_cleared||b.lock_cleared{
        return Err(Error("LEDGER159_FORK_CONTEXT"));
    }
    let finding=if a.observed_sequence==b.observed_sequence{
        if a.observed_head_sha256==b.observed_head_sha256{
            ForkFinding::MatchingHead
        }else{ForkFinding::EquivocationAtSameSequence}
    }else{ForkFinding::DifferentUnqualifiedHeights};
    Ok(ForkReview{
        schema:"sapphon-159-fork-review-v1".into(),finding,
        left_sequence:a.observed_sequence,right_sequence:b.observed_sequence,
        left_head_sha256:a.observed_head_sha256.clone(),
        right_head_sha256:b.observed_head_sha256.clone(),
        independent_custody_authenticated:false,
        global_anti_rollback_authenticated:false,
        recovery_authorized:false,decision:"FORK_HOLD".into(),
    })
}
pub fn write_new(path:&Path,review:&ForkReview)->Result<String,Error>{
    if review.schema!="sapphon-159-fork-review-v1"||review.decision!="FORK_HOLD"
       ||review.independent_custody_authenticated
       ||review.global_anti_rollback_authenticated||review.recovery_authorized{
        return Err(Error("LEDGER159_AUTHORITY"));
    }
    let bytes=serde_json::to_vec(review).map_err(|_|Error("LEDGER159_ENCODING"))?;
    if bytes.len()>1024*1024{return Err(Error("LEDGER159_SIZE"));}
    let mut f=OpenOptions::new().create_new(true).write(true).open(path)
        .map_err(|_|Error("LEDGER159_EXISTS"))?;
    f.write_all(&bytes).map_err(|_|Error("LEDGER159_WRITE"))?;
    f.sync_all().map_err(|_|Error("LEDGER159_FSYNC"))?;
    File::open(path.parent().ok_or(Error("LEDGER159_PARENT"))?)
        .and_then(|p|p.sync_all()).map_err(|_|Error("LEDGER159_DIRSYNC"))?;
    Ok(sha(&bytes))
}
#[cfg(test)]
mod tests{
    use super::*;
    use base64::{engine::general_purpose::STANDARD,Engine as _};
    use ed25519_dalek::{Signer,SigningKey};
    fn setup()->(SigningKey,ExternalFloor){
        let sk=SigningKey::from_bytes(&[29;32]);
        let floor=ExternalFloor{schema:"sapphon-159-external-floor-v1".into(),
            sequence:0,head_sha256:genesis_head(),minimum_counter:0,
            custodian_id:"outside-custodian".into(),
            public_key_hex:hex::encode(sk.verifying_key().as_bytes()),revoked:false};
        (sk,floor)
    }
    fn next(sk:&SigningKey,prev:Option<&Event>,nonce:&str,counter:u64)->Event{
        let mut e=Event{schema:"sapphon-159-consumption-v1".into(),
            sequence:prev.map_or(1,|x|x.sequence+1),
            previous_sha256:prev.map_or_else(genesis_head,|e|event_digest(e).unwrap()),
            custodian_id:"outside-custodian".into(),
            nonce_sha256:nonce.into(),artifact_sha256:"f".repeat(64),
            counter,signature_base64:String::new()};
        e.signature_base64=STANDARD.encode(sk.sign(&signed_message(&e)).to_bytes());e
    }
    #[test]fn signed_chain_still_hold(){
        let(sk,f)=setup();let a=next(&sk,None,&"a".repeat(64),1);
        let r=inspect(&[a],&f).unwrap();
        assert!(r.signatures_verified&&!r.external_floor_authenticated);
        assert!(!r.independent_custody_authenticated&&!r.recovery_authorized&&!r.lock_cleared);
    }
    #[test]fn repeated_nonce_rejected(){
        let(sk,f)=setup();let a=next(&sk,None,&"a".repeat(64),1);
        let b=next(&sk,Some(&a),&"a".repeat(64),2);
        assert_eq!(inspect(&[a,b],&f).unwrap_err().0,"LEDGER159_NONCE_REPLAY");
    }
    #[test]fn duplicate_counter_rejected(){
        let(sk,f)=setup();let a=next(&sk,None,&"a".repeat(64),1);
        let b=next(&sk,Some(&a),&"b".repeat(64),1);
        assert_eq!(inspect(&[a,b],&f).unwrap_err().0,"LEDGER159_COUNTER_REPLAY");
    }
    #[test]fn forged_signature_rejected(){
        let(sk,f)=setup();let mut a=next(&sk,None,&"a".repeat(64),1);
        a.signature_base64=STANDARD.encode([0u8;64]);
        assert_eq!(inspect(&[a],&f).unwrap_err().0,"LEDGER159_SIGNATURE");
    }
    #[test]fn truncated_below_trusted_floor_rejected(){
        let(sk,mut f)=setup();let a=next(&sk,None,&"a".repeat(64),1);
        f.sequence=1;f.head_sha256=event_digest(&a).unwrap();
        assert_eq!(inspect(&[],&f).unwrap_err().0,"LEDGER159_ROLLBACK");
    }
    #[test]fn substituted_history_conflicts_with_pinned_prefix(){
        let(sk,mut f)=setup();let a=next(&sk,None,&"a".repeat(64),1);
        f.sequence=1;f.head_sha256=event_digest(&a).unwrap();
        let alternate=next(&sk,None,&"b".repeat(64),1);
        assert_eq!(inspect(&[alternate],&f).unwrap_err().0,
            "LEDGER159_PINNED_HEAD_CONFLICT");
    }
    #[test]fn signed_forks_at_same_height_detected(){
        let(sk,f)=setup();let a=next(&sk,None,&"a".repeat(64),1);
        let b=next(&sk,None,&"b".repeat(64),1);
        let ra=inspect(&[a],&f).unwrap();let rb=inspect(&[b],&f).unwrap();
        assert_eq!(compare_forks(&ra,&rb).unwrap().finding,
            ForkFinding::EquivocationAtSameSequence);
    }
    #[test]fn unequal_height_is_not_alone_fork_proof(){
        let(sk,f)=setup();let a=next(&sk,None,&"a".repeat(64),1);
        let b=next(&sk,Some(&a),&"b".repeat(64),2);
        let ra=inspect(&[a.clone()],&f).unwrap();
        let rb=inspect(&[a,b],&f).unwrap();
        assert_eq!(compare_forks(&ra,&rb).unwrap().finding,
            ForkFinding::DifferentUnqualifiedHeights);
    }
    #[test]fn independent_prefix_floor_allows_valid_extension(){
        let(sk,mut f)=setup();let a=next(&sk,None,&"a".repeat(64),1);
        f.sequence=1;f.head_sha256=event_digest(&a).unwrap();f.minimum_counter=1;
        let b=next(&sk,Some(&a),&"b".repeat(64),2);
        assert_eq!(inspect(&[a,b],&f).unwrap().observed_sequence,2);
    }
    #[test]fn create_only_fork_report_cannot_overwrite(){
        let(sk,f)=setup();let a=next(&sk,None,&"a".repeat(64),1);
        let b=next(&sk,None,&"b".repeat(64),1);
        let report=compare_forks(&inspect(&[a],&f).unwrap(),
            &inspect(&[b],&f).unwrap()).unwrap();
        let path=std::env::temp_dir().join(format!("sapphon159-{}.json",std::process::id()));
        let _=std::fs::remove_file(&path);
        write_new(&path,&report).unwrap();
        assert_eq!(write_new(&path,&report).unwrap_err().0,"LEDGER159_EXISTS");
        std::fs::remove_file(path).unwrap();
    }
}
