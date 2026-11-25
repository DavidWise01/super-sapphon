use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use sapphon_audit::{Journal, PinRegistry, PublisherPin, SignedSnapshot, SnapshotPayload, SNAPSHOT_SCHEMA};
use sapphon_journal::{append, initialize, inspect, Fault, EXTERNAL_AUTHORITY};
use std::{collections::BTreeMap, fs, path::PathBuf, sync::atomic::{AtomicU64, Ordering}};
static ID: AtomicU64 = AtomicU64::new(0);

struct Fixture { dir: PathBuf, pins: PinRegistry, key: SigningKey }
impl Fixture {
 fn new() -> Self {
    let dir=std::env::temp_dir().join(format!("sapphon-129-{}-{}",std::process::id(),ID.fetch_add(1,Ordering::SeqCst)));
    let key=SigningKey::from_bytes(&[19u8;32]);
    let pins=BTreeMap::from([("publisher-one".into(),PublisherPin {
        control_root:"owned-root".into(),public_key:key.verifying_key().to_bytes(),revoked:false
    })]);
    initialize(&dir,&pins).unwrap();
    Self{dir,pins,key}
 }
 fn signed(&self,issuer_revoked:bool)->SignedSnapshot {
    let payload=SnapshotPayload {
      schema:SNAPSHOT_SCHEMA.into(),publisher_id:"publisher-one".into(),
      control_root:"owned-root".into(),generation:1,issuer_generation:1,operator_generation:1,
      issuer_revoked,operator_revoked:false,previous_digest:None,mode:"synthetic-local-replica".into()
    };
    let sig=self.key.sign(&payload.canonical_bytes().unwrap());
    SignedSnapshot{payload,signature:base64::engine::general_purpose::STANDARD.encode(sig.to_bytes())}
 }
 fn append(&self,revision:u64,snapshot:SignedSnapshot,source:&str,fault:Fault)->Result<String,String>{
    append(&self.dir,&self.pins,revision,snapshot,source,vec!["owned-root".into()],fault)
       .map(|x|x.decision.into()).map_err(|e|e.0.into())
 }
 fn state(&self)->Journal{inspect(&self.dir,&self.pins).unwrap()}
}
impl Drop for Fixture { fn drop(&mut self){let _=fs::remove_dir_all(&self.dir);} }

#[test] fn initializes_and_reads_verified_empty_journal(){
 let f=Fixture::new();assert_eq!(f.state().revision,0);assert_eq!(f.state().observations.len(),0);
}
#[test] fn durable_restart_reads_one_signed_entry(){
 let f=Fixture::new();
 assert_eq!(f.append(0,f.signed(false),"source-one",Fault::None).unwrap(),"HOLD");
 assert_eq!(inspect(&f.dir,&f.pins).unwrap().revision,1);
}
#[test] fn interrupted_before_rename_retains_exact_old_journal(){
 let f=Fixture::new();
 assert_eq!(f.append(0,f.signed(false),"source-one",Fault::BeforeRename).unwrap_err(),"INJECTED_BEFORE_RENAME");
 assert_eq!(f.state().revision,0);
 assert_eq!(fs::read_dir(&f.dir).unwrap().count(),1); // no lingering temp file
}
#[test] fn after_rename_acknowledgement_loss_does_not_claim_rollback(){
 let f=Fixture::new();
 assert_eq!(f.append(0,f.signed(false),"source-one",Fault::AfterRename).unwrap_err(),"INJECTED_AFTER_RENAME");
 // Readback resolves which version is visible; the returned error never claims durable acknowledgement.
 let readback=f.state();assert_eq!(readback.revision,1);
 assert_eq!(readback.observations.len(),1);
}
#[test] fn stale_revision_is_rejected_after_restart(){
 let f=Fixture::new();
 f.append(0,f.signed(false),"source-one",Fault::None).unwrap();
 assert_eq!(f.append(0,f.signed(true),"source-two",Fault::None).unwrap_err(),"REVISION_CONFLICT");
 assert_eq!(f.state().observations.len(),1);
}
#[test] fn duplicate_observation_is_idempotent(){
 let f=Fixture::new();let s=f.signed(false);
 f.append(0,s.clone(),"source-one",Fault::None).unwrap();
 assert_eq!(f.append(1,s,"source-one",Fault::None).unwrap(),"DUPLICATE_OBSERVATION");
 assert_eq!(f.state().revision,1);
}
#[test] fn signed_fork_survives_complete_restart(){
 let f=Fixture::new();
 f.append(0,f.signed(false),"source-one",Fault::None).unwrap();
 f.append(1,f.signed(true),"source-two",Fault::None).unwrap();
 let disk=fs::read(f.dir.join("journal.json")).unwrap();
 let reloaded:Journal=serde_json::from_slice(&disk).unwrap();
 assert_eq!(reloaded.conflicts.len(),1);
 assert_eq!(f.state().conflicts.len(),1);
 assert_eq!(f.state().observations.len(),2);
}
#[test] fn mirrored_ancestry_remains_one_origin_after_persistence(){
 let f=Fixture::new();let s=f.signed(false);
 f.append(0,s.clone(),"github-mirror",Fault::None).unwrap();
 f.append(1,s,"pages-mirror",Fault::None).unwrap();
 let assessment=f.state().assess("publisher-one",1,&[],&f.pins).unwrap();
 assert!(assessment.shared_ancestry_detected);
 assert!(!assessment.independent_witnesses_authenticated);
}
#[test] fn exclusive_process_lock_fails_closed_without_mutation(){
 let f=Fixture::new();fs::create_dir(f.dir.join(".exclusive-lock")).unwrap();
 let err=f.append(0,f.signed(false),"source-one",Fault::None).unwrap_err();
 assert_eq!(err,"STORE_BUSY");
 fs::remove_dir(f.dir.join(".exclusive-lock")).unwrap();
 assert_eq!(f.state().revision,0);
}
#[test] fn malformed_disk_json_denies_all_reads_and_writes(){
 let f=Fixture::new();fs::write(f.dir.join("journal.json"),b"{garbage").unwrap();
 assert_eq!(inspect(&f.dir,&f.pins).unwrap_err().0,"JOURNAL_CORRUPT");
 assert_eq!(f.append(0,f.signed(false),"source-one",Fault::None).unwrap_err(),"JOURNAL_CORRUPT");
}
#[test] fn missing_journal_is_not_silently_recreated(){
 let f=Fixture::new();fs::remove_file(f.dir.join("journal.json")).unwrap();
 assert_eq!(inspect(&f.dir,&f.pins).unwrap_err().0,"JOURNAL_UNREADABLE");
}
#[test] fn missing_store_cannot_be_read(){
 let missing=std::env::temp_dir().join(format!("sapphon-missing-{}-{}",std::process::id(),ID.fetch_add(1,Ordering::SeqCst)));
 assert_eq!(inspect(&missing,&PinRegistry::new()).unwrap_err().0,"STORE_MISSING");
}
#[test] fn cannot_overwrite_initialized_store(){
 let f=Fixture::new();assert_eq!(initialize(&f.dir,&f.pins).unwrap_err().0,"JOURNAL_ALREADY_EXISTS");
}
#[test] fn forged_snapshot_does_not_change_disk(){
 let f=Fixture::new();let bad=SigningKey::from_bytes(&[20u8;32]);
 let mut s=f.signed(false);
 s.signature=base64::engine::general_purpose::STANDARD.encode(bad.sign(&s.payload.canonical_bytes().unwrap()).to_bytes());
 assert_eq!(f.append(0,s,"source-one",Fault::None).unwrap_err(),"SIGNATURE_OR_JOURNAL_INVALID");
 assert_eq!(f.state().revision,0);
}
#[test] fn revoked_publisher_blocks_reopening_until_a_valid_registry_is_supplied(){
 let f=Fixture::new();f.append(0,f.signed(false),"source-one",Fault::None).unwrap();
 let mut revoked=f.pins.clone();revoked.get_mut("publisher-one").unwrap().revoked=true;
 assert_eq!(inspect(&f.dir,&revoked).unwrap_err().0,"SIGNATURE_OR_JOURNAL_INVALID");
 assert_eq!(f.state().revision,1);
}
#[test] fn journal_mutation_with_missing_conflict_fails_closed(){
 let f=Fixture::new();f.append(0,f.signed(false),"source-one",Fault::None).unwrap();
 f.append(1,f.signed(true),"source-two",Fault::None).unwrap();
 let file=f.dir.join("journal.json");let mut j=f.state();j.conflicts.clear();
 fs::write(&file,serde_json::to_vec(&j).unwrap()).unwrap();
 assert_eq!(inspect(&f.dir,&f.pins).unwrap_err().0,"SIGNATURE_OR_JOURNAL_INVALID");
}
#[test] fn fabricated_authority_field_is_rejected(){
 let f=Fixture::new();let file=f.dir.join("journal.json");
 let mut v:serde_json::Value=serde_json::from_slice(&fs::read(&file).unwrap()).unwrap();
 v["utc_authority"]=serde_json::Value::Bool(true);
 fs::write(&file,serde_json::to_vec(&v).unwrap()).unwrap();
 assert_eq!(inspect(&f.dir,&f.pins).unwrap_err().0,"JOURNAL_CORRUPT");
}
#[test] fn no_external_authority_is_claimed_by_successful_atomic_write(){
 let f=Fixture::new();f.append(0,f.signed(false),"source-one",Fault::None).unwrap();
 assert_eq!(EXTERNAL_AUTHORITY,"HOLD");
}
