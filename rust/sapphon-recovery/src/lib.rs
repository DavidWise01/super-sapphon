//! SAPPHON-131 — synthetic operator-signed recovery receipts.
//! Does not prove the claimed PID actually exited. That must be checked by
//! the independent test coordinator before authoring an approval.
//! This API never steals locks by timeout and never claims external authority.
use base64::Engine;
use ed25519_dalek::{Signature,Verifier,VerifyingKey};
use sapphon_audit::{Journal,PinRegistry};
use serde::{Serialize,Deserialize};
use sha2::{Digest,Sha256};
use std::{fs::{self,File,OpenOptions},io::{Read,Write},path::{Path,PathBuf},sync::atomic::{AtomicU64,Ordering}};
static NEXT:AtomicU64=AtomicU64::new(0);
const MAX:u64=16*1024*1024;
const SCHEMA:&str="sapphon-131-recovery-v1";
pub const EXTERNAL_AUTHORITY:&str="HOLD";
#[derive(Debug,PartialEq,Eq)]
pub struct Error(pub &'static str);
impl std::fmt::Display for Error {fn fmt(&self,f:&mut std::fmt::Formatter<'_>)->std::fmt::Result{f.write_str(self.0)}}
impl std::error::Error for Error{}
type Result<T>=std::result::Result<T,Error>;
fn fail(x:&'static str)->Error{Error(x)}
fn hash(b:&[u8])->String{hex::encode(Sha256::digest(b))}
fn valid_hash(h:&str)->bool{h.len()==64&&h.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b))}
fn valid_id(s:&str)->bool{(4..=64).contains(&s.len())&&s.bytes().all(|b|b.is_ascii_lowercase()||b.is_ascii_digit()||b==b'-')}
#[derive(Clone,Debug,Serialize,Deserialize,PartialEq,Eq)]
#[serde(deny_unknown_fields)]
pub struct Approval {
 pub schema:String,pub operator_id:String,pub nonce:String,pub journal_sha256:String,
 pub expected_revision:u64,pub lock_owner_pid:u32,pub coordinator_confirmed_exit:bool,
 pub sequence:u64,pub previous_receipt_sha256:Option<String>
}
impl Approval{
 pub fn bytes(&self)->Result<Vec<u8>>{
  if self.schema!=SCHEMA||!valid_id(&self.operator_id)||!valid_hash(&self.nonce)||
    !valid_hash(&self.journal_sha256)||self.lock_owner_pid==0||!self.coordinator_confirmed_exit||
    self.sequence==0||(self.sequence==1)!=self.previous_receipt_sha256.is_none()||
    self.previous_receipt_sha256.as_ref().is_some_and(|x|!valid_hash(x)){
   return Err(fail("APPROVAL_FIELDS"));
  }
  serde_json::to_vec(&(
   &self.schema,&self.operator_id,&self.nonce,&self.journal_sha256,self.expected_revision,
   self.lock_owner_pid,self.coordinator_confirmed_exit,self.sequence,&self.previous_receipt_sha256
  )).map_err(|_|fail("APPROVAL_ENCODING"))
 }
}
#[derive(Clone,Debug,Serialize,Deserialize,PartialEq,Eq)]
#[serde(deny_unknown_fields)]
pub struct SignedApproval {pub payload:Approval,pub signature:String}
pub fn verify(s:&SignedApproval,key:&VerifyingKey)->Result<String>{
 let body=s.payload.bytes()?;
 let decoded=base64::engine::general_purpose::STANDARD.decode(&s.signature).map_err(|_|fail("APPROVAL_SIGNATURE"))?;
 let bytes:[u8;64]=decoded.try_into().map_err(|_|fail("APPROVAL_SIGNATURE"))?;
 key.verify(&body,&Signature::from_bytes(&bytes)).map_err(|_|fail("APPROVAL_SIGNATURE"))?;
 Ok(hash(&body))
}
#[derive(Clone,Debug,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiptLog {pub schema:String,pub records:Vec<SignedApproval>}
impl Default for ReceiptLog {
 fn default()->Self{Self{schema:"sapphon-131-receipts-v1".into(),records:vec![]}}
}
impl ReceiptLog {
 pub fn validate(&self,key:&VerifyingKey)->Result<()>{
  if self.schema!="sapphon-131-receipts-v1"||self.records.len()>512{return Err(fail("RECEIPT_LOG_CORRUPT"));}
  let mut previous=None;let mut used=std::collections::BTreeSet::new();
  for (i,signed) in self.records.iter().enumerate(){
    let digest=verify(signed,key)?;
    if signed.payload.sequence!=i as u64+1||
      signed.payload.previous_receipt_sha256!=previous||
      !used.insert(&signed.payload.nonce){return Err(fail("RECEIPT_CHAIN_BROKEN"));}
    previous=Some(digest);
  }
  Ok(())
 }
 pub fn next(&self)->(u64,Option<String>){
  (self.records.len() as u64+1,self.records.last().map(|x|hash(&x.payload.bytes().expect("validated receipt"))))
 }
}
struct Gate{path:PathBuf}
impl Gate{
 fn acquire(root:&Path)->Result<Self>{
  if !root.is_dir(){return Err(fail("STORE_MISSING"));}
  let p=root.join(".recovery-exclusive");
  fs::create_dir(&p).map_err(|_|fail("RECOVERY_BUSY"))?;
  Ok(Self{path:p})
 }
}
impl Drop for Gate {fn drop(&mut self){let _=fs::remove_dir(&self.path);}}
struct Temp{path:PathBuf}
impl Drop for Temp{fn drop(&mut self){let _=fs::remove_file(&self.path);}}
fn read_log(root:&Path,key:&VerifyingKey)->Result<ReceiptLog>{
 let path=root.join("recovery-receipts.json");
 if !path.exists(){return Ok(ReceiptLog::default());}
 let mut f=File::open(path).map_err(|_|fail("RECEIPT_UNREADABLE"))?;
 if f.metadata().map_err(|_|fail("RECEIPT_UNREADABLE"))?.len()>MAX{return Err(fail("RECEIPT_TOO_LARGE"));}
 let mut bytes=Vec::new();
 f.read_to_end(&mut bytes).map_err(|_|fail("RECEIPT_UNREADABLE"))?;
 let log:ReceiptLog=serde_json::from_slice(&bytes).map_err(|_|fail("RECEIPT_LOG_CORRUPT"))?;
 log.validate(key)?;Ok(log)
}
fn persist(root:&Path,log:&ReceiptLog)->Result<()>{
 let bytes=serde_json::to_vec_pretty(log).map_err(|_|fail("RECEIPT_ENCODING"))?;
 if bytes.len() as u64>MAX{return Err(fail("RECEIPT_TOO_LARGE"));}
 let t=Temp{path:root.join(format!(".recovery-{}-{}",std::process::id(),NEXT.fetch_add(1,Ordering::SeqCst)))};
 let mut f=OpenOptions::new().create_new(true).write(true).open(&t.path).map_err(|_|fail("RECEIPT_TEMP_FAILED"))?;
 f.write_all(&bytes).map_err(|_|fail("RECEIPT_WRITE_FAILED"))?;
 f.sync_all().map_err(|_|fail("RECEIPT_FSYNC_FAILED"))?;drop(f);
 fs::rename(&t.path,root.join("recovery-receipts.json")).map_err(|_|fail("RECEIPT_RENAME_FAILED"))?;
 File::open(root).and_then(|f|f.sync_all()).map_err(|_|fail("RECEIPT_DIRSYNC_FAILED"))
}
fn current_journal(root:&Path,pins:&PinRegistry)->Result<(u64,String)>{
 let mut f=File::open(root.join("journal.json")).map_err(|_|fail("JOURNAL_UNREADABLE"))?;
 if f.metadata().map_err(|_|fail("JOURNAL_UNREADABLE"))?.len()>MAX{return Err(fail("JOURNAL_TOO_LARGE"));}
 let mut b=Vec::new();f.read_to_end(&mut b).map_err(|_|fail("JOURNAL_UNREADABLE"))?;
 let j:Journal=serde_json::from_slice(&b).map_err(|_|fail("JOURNAL_CORRUPT"))?;
 j.validate(pins).map_err(|_|fail("JOURNAL_INVALID"))?;
 Ok((j.revision,hash(&b)))
}
pub fn observe(root:&Path,key:&VerifyingKey)->Result<ReceiptLog>{
 let _gate=Gate::acquire(root)?;read_log(root,key)
}
/// Durable PREPARED receipt is written while the stale journal writer lock
/// remains held. A failed append cannot be confused with a cleared lock.
pub fn prepare(root:&Path,pins:&PinRegistry,key:&VerifyingKey,receipt:SignedApproval)->Result<&'static str>{
 let _gate=Gate::acquire(root)?;
 let mut log=read_log(root,key)?;
 let digest=verify(&receipt,key)?;
 let (revision,journal_digest)=current_journal(root,pins)?;
 if !root.join(".exclusive-lock").is_dir(){return Err(fail("LOCK_NOT_PRESENT"));}
 if receipt.payload.expected_revision!=revision||receipt.payload.journal_sha256!=journal_digest{
  return Err(fail("JOURNAL_BINDING"));
 }
 if log.records.iter().any(|r|r.payload.nonce==receipt.payload.nonce){
  if log.records.iter().any(|r|verify(r,key).ok().as_deref()==Some(digest.as_str())){
   return Ok("ALREADY_PREPARED_HOLD");
  }
  return Err(fail("NONCE_REPLAY"));
 }
 let (seq,prev)=log.next();
 if receipt.payload.sequence!=seq||receipt.payload.previous_receipt_sha256!=prev{
  return Err(fail("RECEIPT_CHAIN_BROKEN"));
 }
 if log.records.len()>=512{return Err(fail("RECEIPT_CAPACITY_HOLD"));}
 log.records.push(receipt);
 log.validate(key)?;
 persist(root,&log)?;
 Ok("PREPARED_HOLD")
}
/// Clears only a journal lock with an exact already-durable operator approval.
/// The coordinator's process-exit statement is an explicit *claim*, not OS proof.
pub fn clear(root:&Path,pins:&PinRegistry,key:&VerifyingKey,receipt:&SignedApproval)->Result<&'static str>{
 let _gate=Gate::acquire(root)?;
 let log=read_log(root,key)?;
 let digest=verify(receipt,key)?;
 if !log.records.iter().any(|x|verify(x,key).ok().as_deref()==Some(digest.as_str())){
  return Err(fail("RECEIPT_NOT_DURABLE"));
 }
 let (revision,journal_digest)=current_journal(root,pins)?;
 if receipt.payload.expected_revision!=revision||receipt.payload.journal_sha256!=journal_digest{
  return Err(fail("JOURNAL_BINDING"));
 }
 let lock=root.join(".exclusive-lock");
 if !lock.is_dir(){return Err(fail("LOCK_NOT_PRESENT"));}
 fs::remove_dir(&lock).map_err(|_|fail("LOCK_CLEAR_FAILED"))?;
 File::open(root).and_then(|f|f.sync_all()).map_err(|_|fail("LOCK_DIRSYNC_FAILED"))?;
 Ok("LOCK_CLEARED_LOCAL_HOLD")
}
pub fn fingerprint(root:&Path,pins:&PinRegistry)->Result<(u64,String)>{
 let _gate=Gate::acquire(root)?;current_journal(root,pins)
}
