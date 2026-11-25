use base64::Engine;
use ed25519_dalek::{Signer,SigningKey};
use sapphon_audit::PinRegistry;
use sapphon_journal::initialize;
use sapphon_recovery::{Approval,SignedApproval,prepare,clear,observe,fingerprint,EXTERNAL_AUTHORITY};
use std::{fs,path::PathBuf,sync::atomic::{AtomicU64,Ordering}};
static NEXT:AtomicU64=AtomicU64::new(0);
struct F {root:PathBuf,pins:PinRegistry,key:SigningKey}
impl F{
 fn new()->Self {
  let root=std::env::temp_dir().join(format!("sapphon131-{}-{}",std::process::id(),NEXT.fetch_add(1,Ordering::SeqCst)));
  let pins=PinRegistry::new();initialize(&root,&pins).unwrap();
  let key=SigningKey::from_bytes(&[31u8;32]);
  Self{root,pins,key}
 }
 fn lock(&self){fs::create_dir(self.root.join(".exclusive-lock")).unwrap();}
 fn approval(&self,nonce:&str,confirmed:bool)->SignedApproval{
  let (rev,digest)=fingerprint(&self.root,&self.pins).unwrap();
  let old=observe(&self.root,&self.key.verifying_key()).unwrap();
  let (seq,previous)=old.next();
  let payload=Approval{
   schema:"sapphon-131-recovery-v1".into(),operator_id:"test-operator".into(),
   nonce:nonce.repeat(64),journal_sha256:digest,expected_revision:rev,
   lock_owner_pid:12345,coordinator_confirmed_exit:confirmed,
   sequence:seq,previous_receipt_sha256:previous,
  };
  self.sign(payload)
 }
 fn sign(&self,payload:Approval)->SignedApproval{
  let sig=self.key.sign(&payload.bytes().unwrap_or_default());
  SignedApproval{payload,signature:base64::engine::general_purpose::STANDARD.encode(sig.to_bytes())}
 }
 fn prepare(&self,r:SignedApproval)->Result<&'static str,String>{
  prepare(&self.root,&self.pins,&self.key.verifying_key(),r).map_err(|e|e.0.into())
 }
 fn clear(&self,r:&SignedApproval)->Result<&'static str,String>{
  clear(&self.root,&self.pins,&self.key.verifying_key(),r).map_err(|e|e.0.into())
 }
 fn observed(&self)->usize{observe(&self.root,&self.key.verifying_key()).unwrap().records.len()}
}
impl Drop for F{fn drop(&mut self){let _=fs::remove_dir_all(&self.root);}}
#[test]fn no_lock_cannot_prepare_receipt(){
 let f=F::new();let a=f.approval("a",true);
 assert_eq!(f.prepare(a).unwrap_err(),"LOCK_NOT_PRESENT");assert_eq!(f.observed(),0);
}
#[test]fn explicit_signed_receipt_is_prepared_before_clear(){
 let f=F::new();f.lock();let r=f.approval("a",true);
 assert_eq!(f.prepare(r.clone()).unwrap(),"PREPARED_HOLD");
 assert!(f.root.join(".exclusive-lock").exists());assert_eq!(f.observed(),1);
 assert_eq!(f.clear(&r).unwrap(),"LOCK_CLEARED_LOCAL_HOLD");
 assert!(!f.root.join(".exclusive-lock").exists());
}
#[test]fn unsigned_undurable_approval_cannot_clear_lock(){
 let f=F::new();f.lock();let a=f.approval("a",true);
 assert_eq!(f.clear(&a).unwrap_err(),"RECEIPT_NOT_DURABLE");
 assert!(f.root.join(".exclusive-lock").exists());
}
#[test]fn confirmed_exit_false_does_not_create_receipt(){
 let f=F::new();f.lock();let a=f.approval("a",false);
 assert_eq!(f.prepare(a).unwrap_err(),"APPROVAL_FIELDS");assert_eq!(f.observed(),0);
}
#[test]fn signature_from_wrong_operator_cannot_prepare(){
 let f=F::new();f.lock();let mut a=f.approval("a",true);
 let rogue=SigningKey::from_bytes(&[32u8;32]);
 a.signature=base64::engine::general_purpose::STANDARD.encode(
  rogue.sign(&a.payload.bytes().unwrap()).to_bytes());
 assert_eq!(f.prepare(a).unwrap_err(),"APPROVAL_SIGNATURE");
}
#[test]fn stale_digest_cannot_prepare(){
 let f=F::new();f.lock();let a=f.approval("a",true);
 let mut payload=a.payload;payload.journal_sha256="f".repeat(64);
 let forged=f.sign(payload);
 assert_eq!(f.prepare(forged).unwrap_err(),"JOURNAL_BINDING");
}
#[test]fn stale_revision_cannot_prepare(){
 let f=F::new();f.lock();let a=f.approval("a",true);
 let mut payload=a.payload;payload.expected_revision=27;
 assert_eq!(f.prepare(f.sign(payload)).unwrap_err(),"JOURNAL_BINDING");
}
#[test]fn receipt_is_idempotent_after_lost_acknowledgement(){
 let f=F::new();f.lock();let a=f.approval("a",true);
 assert_eq!(f.prepare(a.clone()).unwrap(),"PREPARED_HOLD");
 assert_eq!(f.prepare(a).unwrap(),"ALREADY_PREPARED_HOLD");
 assert_eq!(f.observed(),1);
}
#[test]fn nonce_reuse_with_changed_payload_is_denied(){
 let f=F::new();f.lock();let a=f.approval("a",true);
 f.prepare(a.clone()).unwrap();
 let mut p=a.payload;p.lock_owner_pid=45678;
 assert_eq!(f.prepare(f.sign(p)).unwrap_err(),"NONCE_REPLAY");
}
#[test]fn receipt_chain_requires_exact_previous_digest(){
 let f=F::new();f.lock();let a=f.approval("a",true);
 f.prepare(a).unwrap();
 let mut second=f.approval("b",true).payload;
 second.previous_receipt_sha256=Some("f".repeat(64));
 assert_eq!(f.prepare(f.sign(second)).unwrap_err(),"RECEIPT_CHAIN_BROKEN");
}
#[test]fn forged_sequence_cannot_skip_receipts(){
 let f=F::new();f.lock();let mut p=f.approval("a",true).payload;
 p.sequence=3;p.previous_receipt_sha256=Some("f".repeat(64));
 assert_eq!(f.prepare(f.sign(p)).unwrap_err(),"RECEIPT_CHAIN_BROKEN");
}
#[test]fn readback_retains_signed_receipt_after_restart(){
 let f=F::new();f.lock();let a=f.approval("a",true);f.prepare(a).unwrap();
 let content=fs::read(f.root.join("recovery-receipts.json")).unwrap();
 let j:sapphon_recovery::ReceiptLog=serde_json::from_slice(&content).unwrap();
 j.validate(&f.key.verifying_key()).unwrap();assert_eq!(j.records.len(),1);
}
#[test]fn corrupt_receipt_log_refuses_clear_and_preserves_lock(){
 let f=F::new();f.lock();let a=f.approval("a",true);f.prepare(a.clone()).unwrap();
 fs::write(f.root.join("recovery-receipts.json"),b"{broken").unwrap();
 assert_eq!(f.clear(&a).unwrap_err(),"RECEIPT_LOG_CORRUPT");
 assert!(f.root.join(".exclusive-lock").exists());
}
#[test]fn tampered_signed_receipt_refuses_clear(){
 let f=F::new();f.lock();let a=f.approval("a",true);f.prepare(a.clone()).unwrap();
 let mut bad=a.clone();bad.payload.lock_owner_pid=999;
 assert_eq!(f.clear(&bad).unwrap_err(),"APPROVAL_SIGNATURE");
 assert!(f.root.join(".exclusive-lock").exists());
}
#[test]fn stale_recovery_mutex_blocks_clear(){
 let f=F::new();f.lock();let a=f.approval("a",true);f.prepare(a.clone()).unwrap();
 fs::create_dir(f.root.join(".recovery-exclusive")).unwrap();
 assert_eq!(f.clear(&a).unwrap_err(),"RECOVERY_BUSY");
 assert!(f.root.join(".exclusive-lock").exists());
}
#[test]fn already_cleared_lock_does_not_reauthorize_replay(){
 let f=F::new();f.lock();let a=f.approval("a",true);f.prepare(a.clone()).unwrap();f.clear(&a).unwrap();
 assert_eq!(f.clear(&a).unwrap_err(),"LOCK_NOT_PRESENT");
}
#[test]fn changed_journal_bytes_prevent_clear_even_with_valid_receipt(){
 let f=F::new();f.lock();let a=f.approval("a",true);f.prepare(a.clone()).unwrap();
 let file=f.root.join("journal.json");let mut bytes=fs::read(&file).unwrap();
 bytes.push(b' ');fs::write(&file,bytes).unwrap();
 assert_eq!(f.clear(&a).unwrap_err(),"JOURNAL_BINDING");
 assert!(f.root.join(".exclusive-lock").exists());
}
#[test]fn false_external_authority_stays_hold(){
 let f=F::new();f.lock();let a=f.approval("a",true);f.prepare(a).unwrap();
 assert_eq!(EXTERNAL_AUTHORITY,"HOLD");
}
