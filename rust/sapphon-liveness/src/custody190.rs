//! SAPPHON-190: cryptographic Ed25519 receipt proof is not independent custody.
#![cfg(target_os="linux")]
use crate::Error;
use base64::{engine::general_purpose::STANDARD,Engine as _};
use ed25519_dalek::{Signature,VerifyingKey,Verifier};
use serde::{Deserialize,Serialize};
use sha2::{Digest,Sha256};
use std::{collections::BTreeSet,fs::{File,OpenOptions},io::Write,path::Path};
pub const AUTHORITY:&str="HOLD";
const SOURCE:&str="8dfc2f0851df7bc02ac29977529bafe9c0b2101e";
const DOMAIN:&[u8]=b"SAPPHON-190-CUSTODY-RECEIPT-V1\0";
fn sha(b:&[u8])->String{hex::encode(Sha256::digest(b))}
fn hex64(s:&str)->bool{s.len()==64&&s.bytes().all(|c|c.is_ascii_digit()||(b'a'..=b'f').contains(&c))}
#[derive(Clone,Debug,Serialize,Deserialize,PartialEq,Eq)]
#[serde(deny_unknown_fields)]
pub struct Receipt{
 pub source_sha:String,pub root_sha256:String,
 pub run_id:u64,pub attempt:u32,
 pub custodian_id:String,pub nonce_hex:String,pub sequence:u64,
 pub previous_receipt_sha256:String,pub public_key_b64:String,
 pub key_fingerprint_sha256:String,pub signature_b64:String,
 pub recovery_authorized:bool
}
#[derive(Clone,Debug,Serialize,Deserialize,PartialEq,Eq)]
#[serde(deny_unknown_fields)]
pub struct ResultRecord{
 pub schema:String,pub cryptographic_valid:bool,
 pub receipt_sha256:String,pub blockers:Vec<String>,
 pub independently_enrolled_keys:u8,pub independent_witnesses:u8,
 pub independent_custody_authenticated:bool,pub authenticated_utc:bool,
 pub global_anti_rollback_authenticated:bool,
 pub recovery_authorized:bool,pub lock_cleared:bool,pub decision:String
}
pub fn signed_message(r:&Receipt)->Result<Vec<u8>,Error>{
 if r.source_sha!=SOURCE||!hex64(&r.root_sha256)||!hex64(&r.nonce_hex)
   ||!hex64(&r.previous_receipt_sha256)||r.run_id==0||r.attempt==0
   ||r.sequence==0||r.custodian_id.is_empty()||r.custodian_id.len()>100
   ||r.recovery_authorized{
  return Err(Error("RECEIPT190_FIELDS"));
 }
 // Explicit length-prefixing prevents unambiguous concatenation attacks.
 let mut data=DOMAIN.to_vec();
 for item in [r.source_sha.as_bytes(),r.root_sha256.as_bytes(),
              &r.run_id.to_be_bytes(),&r.attempt.to_be_bytes(),
              r.custodian_id.as_bytes(),r.nonce_hex.as_bytes(),
              &r.sequence.to_be_bytes(),r.previous_receipt_sha256.as_bytes()]{
  data.extend_from_slice(&(item.len() as u32).to_be_bytes());
  data.extend_from_slice(item);
 }
 Ok(data)
}
pub fn verify_signature(r:&Receipt)->Result<bool,Error>{
 let data=signed_message(r)?;
 let pk=STANDARD.decode(&r.public_key_b64).map_err(|_|Error("RECEIPT190_PUBKEY"))?;
 let key_bytes:[u8;32]=pk.as_slice().try_into().map_err(|_|Error("RECEIPT190_PUBKEY"))?;
 if sha(&key_bytes)!=r.key_fingerprint_sha256{return Err(Error("RECEIPT190_KEY_FINGERPRINT"));}
 let key=VerifyingKey::from_bytes(&key_bytes).map_err(|_|Error("RECEIPT190_PUBKEY"))?;
 let sig_bytes=STANDARD.decode(&r.signature_b64).map_err(|_|Error("RECEIPT190_SIGNATURE"))?;
 let sig=Signature::from_slice(&sig_bytes).map_err(|_|Error("RECEIPT190_SIGNATURE"))?;
 Ok(key.verify(&data,&sig).is_ok())
}
pub fn adjudicate(receipts:&[Receipt])->Result<ResultRecord,Error>{
 if receipts.len()>64{return Err(Error("RECEIPT190_LIMIT"));}
 let mut blockers=Vec::new();
 let mut identities=BTreeSet::new();
 let mut all_valid=!receipts.is_empty();
 for (i,r) in receipts.iter().enumerate(){
  let valid=verify_signature(r)?;
  if !valid{all_valid=false;blockers.push(format!("INVALID_SIGNATURE:{i}"));}
  if !identities.insert((r.custodian_id.clone(),r.nonce_hex.clone(),r.sequence)){
   all_valid=false;blockers.push(format!("REPLAYED_RECEIPT:{i}"));
  }
  blockers.push(format!("NO_OUT_OF_BAND_KEY_ENROLLMENT:{i}"));
 }
 blockers.sort();blockers.dedup();
 let data=serde_json::to_vec(receipts).map_err(|_|Error("RECEIPT190_JSON"))?;
 Ok(ResultRecord{schema:"sapphon-190-rust-receipt-v1".into(),
  cryptographic_valid:all_valid,receipt_sha256:sha(&data),blockers,
  independently_enrolled_keys:0,independent_witnesses:0,
  independent_custody_authenticated:false,authenticated_utc:false,
  global_anti_rollback_authenticated:false,recovery_authorized:false,
  lock_cleared:false,decision:"INDEPENDENT_CUSTODY_ENROLLMENT_HOLD".into()})
}
pub fn write_new(path:&Path,r:&ResultRecord)->Result<String,Error>{
 if r.schema!="sapphon-190-rust-receipt-v1"||
 r.decision!="INDEPENDENT_CUSTODY_ENROLLMENT_HOLD"||
 r.independently_enrolled_keys!=0||r.independent_witnesses!=0||
 r.independent_custody_authenticated||r.authenticated_utc||
 r.global_anti_rollback_authenticated||r.recovery_authorized||r.lock_cleared{
  return Err(Error("RECEIPT190_AUTHORITY"));
 }
 let bytes=serde_json::to_vec(r).map_err(|_|Error("RECEIPT190_JSON"))?;
 let mut f=OpenOptions::new().write(true).create_new(true).open(path)
  .map_err(|_|Error("RECEIPT190_EXISTS"))?;
 f.write_all(&bytes).map_err(|_|Error("RECEIPT190_WRITE"))?;
 f.sync_all().map_err(|_|Error("RECEIPT190_FSYNC"))?;
 File::open(path.parent().ok_or(Error("RECEIPT190_PARENT"))?)
  .and_then(|d|d.sync_all()).map_err(|_|Error("RECEIPT190_DIRSYNC"))?;
 Ok(sha(&bytes))
}
#[cfg(test)]
mod tests{
 use super::*;
 use ed25519_dalek::{SigningKey,Signer};
 fn sample()->(Receipt,SigningKey){
  // Fixed test-only key: NEVER an operational custody signing key.
  let key=SigningKey::from_bytes(&[7u8;32]);
  let public=key.verifying_key().to_bytes();
  let r=Receipt{source_sha:SOURCE.into(),root_sha256:"a".repeat(64),
    run_id:189,attempt:1,custodian_id:"test-only".into(),
    nonce_hex:"b".repeat(64),sequence:1,
    previous_receipt_sha256:"0".repeat(64),
    public_key_b64:STANDARD.encode(public),key_fingerprint_sha256:sha(&public),
    signature_b64:String::new(),recovery_authorized:false};
  (r,key)
 }
 fn signed()->Receipt{let (mut r,k)=sample();let msg=signed_message(&r).unwrap();
  r.signature_b64=STANDARD.encode(k.sign(&msg).to_bytes());r}
 #[test]fn real_signature_valid_still_zero_witness(){let r=signed();
  assert!(verify_signature(&r).unwrap());
  let result=adjudicate(&[r]).unwrap();
  assert!(result.cryptographic_valid);
  assert_eq!(result.independent_witnesses,0);
  assert!(!result.recovery_authorized);}
 #[test]fn tampered_root_fails_signature(){let mut r=signed();r.root_sha256="c".repeat(64);
  assert!(!verify_signature(&r).unwrap());}
 #[test]fn bad_key_fingerprint_fails(){let mut r=signed();r.key_fingerprint_sha256="d".repeat(64);
  assert_eq!(verify_signature(&r).unwrap_err().0,"RECEIPT190_KEY_FINGERPRINT");}
 #[test]fn replayed_nonce_detected(){let r=signed();
  assert!(adjudicate(&[r.clone(),r]).unwrap().blockers.iter().any(|x|x.starts_with("REPLAYED_RECEIPT")));}
 #[test]fn forged_authority_fails(){let mut r=signed();r.recovery_authorized=true;
  assert_eq!(verify_signature(&r).unwrap_err().0,"RECEIPT190_FIELDS");}
 #[test]fn empty_receipts_no_crypto_pass(){let r=adjudicate(&[]).unwrap();
  assert!(!r.cryptographic_valid&&!r.recovery_authorized);}
 #[test]fn create_only(){let r=adjudicate(&[]).unwrap();
  let p=std::env::temp_dir().join(format!("sapphon190-{}.json",std::process::id()));
  let _=std::fs::remove_file(&p);write_new(&p,&r).unwrap();
  assert_eq!(write_new(&p,&r).unwrap_err().0,"RECEIPT190_EXISTS");
  std::fs::remove_file(p).unwrap();}
}
