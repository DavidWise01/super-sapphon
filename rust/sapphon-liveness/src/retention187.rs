//! SAPPHON-187: bounded source-owned attempt hash chain and equivocation fence.
#![cfg(target_os="linux")]
use crate::Error;
use serde::{Deserialize,Serialize};
use sha2::{Digest,Sha256};
use std::{collections::BTreeMap,fs::{File,OpenOptions},io::Write,path::Path};
pub const AUTHORITY:&str="HOLD";
const SOURCE:&str="a18115b4099c0eac6bef1c624efd73573aaffe8e";
fn digest(b:&[u8])->String{hex::encode(Sha256::digest(b))}
fn sha64(s:&str)->bool{s.len()==64&&s.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b))}
#[derive(Debug,Clone,Serialize,Deserialize,PartialEq,Eq)]
#[serde(deny_unknown_fields)]
pub struct Observation{
 pub source_sha:String,pub run_id:u64,pub attempt:u32,
 pub state:String,pub artifact_id:Option<u64>,
 pub zip_sha256:Option<String>,pub embedded_run_id:Option<u64>,
 pub embedded_attempt:Option<u32>,pub deletion_confirmed:bool,
 pub external_custody_claim:bool
}
#[derive(Debug,Clone,Serialize,Deserialize,PartialEq,Eq)]
#[serde(deny_unknown_fields)]
pub struct Envelope{
 pub sequence:u64,pub previous_sha256:String,
 pub observation:Observation
}
#[derive(Debug,Clone,Serialize,Deserialize,PartialEq,Eq)]
#[serde(deny_unknown_fields)]
pub struct Record{pub envelope:Envelope,pub sha256:String}
#[derive(Debug,Clone,Serialize,Deserialize,PartialEq,Eq)]
#[serde(deny_unknown_fields)]
pub struct Finding{
 pub schema:String,pub entries:usize,pub tip_sha256:String,
 pub equivocations:Vec<String>,pub source_owned_chain_consistent:bool,
 pub independent_custody_authenticated:bool,pub authenticated_utc:bool,
 pub recovery_authorized:bool,pub lock_cleared:bool,pub decision:String
}
fn check_observation(x:&Observation)->Result<(),Error>{
 if x.source_sha!=SOURCE||x.run_id==0||x.attempt==0||x.external_custody_claim{
  return Err(Error("LEDGER187_ANCESTRY_AUTHORITY"));
 }
 let known=["OBSERVED","EXPIRED","DELETED_OBSERVED","READBACK_UNAVAILABLE",
  "NOT_FOUND_IN_EXHAUSTED_LISTING","LISTING_INCOMPLETE"];
 if !known.contains(&x.state.as_str()){return Err(Error("LEDGER187_STATE"));}
 if x.state=="OBSERVED"{
  if x.artifact_id.is_none_or(|n|n==0)||
    x.zip_sha256.as_ref().is_none_or(|s|!sha64(s))||
    x.embedded_run_id!=Some(x.run_id)||x.embedded_attempt!=Some(x.attempt){
   return Err(Error("LEDGER187_EMBEDDED"));
  }
 }else if x.zip_sha256.is_some()||x.embedded_run_id.is_some()||
         x.embedded_attempt.is_some(){
  return Err(Error("LEDGER187_UNOBSERVED_BYTES"));
 }
 if x.state=="DELETED_OBSERVED"&&(!x.deletion_confirmed||x.artifact_id.is_none_or(|n|n==0)){
  return Err(Error("LEDGER187_UNPROVEN_DELETION"));
 }
 Ok(())
}
pub fn verify(records:&[Record])->Result<Finding,Error>{
 if records.len()>10000{return Err(Error("LEDGER187_LENGTH"));}
 let mut prev="0".repeat(64);
 let mut attempts=BTreeMap::<(u64,u32),(u64,String)>::new();
 let mut conflicts=Vec::new();
 for (idx,r) in records.iter().enumerate(){
  check_observation(&r.envelope.observation)?;
  if r.envelope.sequence!=idx as u64+1||r.envelope.previous_sha256!=prev{
   return Err(Error("LEDGER187_CHAIN"));
  }
  let bytes=serde_json::to_vec(&r.envelope).map_err(|_|Error("LEDGER187_JSON"))?;
  let actual=digest(&bytes);
  if actual!=r.sha256{return Err(Error("LEDGER187_DIGEST"));}
  let x=&r.envelope.observation;
  if x.state=="OBSERVED"{
   let key=(x.run_id,x.attempt);
   let identity=(x.artifact_id.unwrap_or(0),x.zip_sha256.clone().unwrap_or_default());
   if attempts.get(&key).is_some_and(|old|old!=&identity){
    conflicts.push(format!("ATTEMPT_EQUIVOCATION:{}:{}",x.run_id,x.attempt));
   }
   attempts.insert(key,identity);
  }
  prev=actual;
 }
 Ok(Finding{schema:"sapphon-187-rust-ledger-v1".into(),entries:records.len(),
  tip_sha256:prev,source_owned_chain_consistent:conflicts.is_empty(),
  equivocations:conflicts,independent_custody_authenticated:false,
  authenticated_utc:false,recovery_authorized:false,lock_cleared:false,
  decision:"CROSS_ATTEMPT_RETENTION_HOLD".into()})
}
pub fn extend(records:&[Record],observation:Observation)->Result<Vec<Record>,Error>{
 verify(records)?;check_observation(&observation)?;
 let previous=records.last().map(|r|r.sha256.clone()).unwrap_or_else(||"0".repeat(64));
 let envelope=Envelope{sequence:records.len() as u64+1,previous_sha256:previous,observation};
 let bytes=serde_json::to_vec(&envelope).map_err(|_|Error("LEDGER187_JSON"))?;
 let mut result=records.to_vec();
 result.push(Record{envelope,sha256:digest(&bytes)});
 Ok(result)
}
pub fn write_new(path:&Path,report:&Finding)->Result<String,Error>{
 if report.schema!="sapphon-187-rust-ledger-v1"||report.decision!="CROSS_ATTEMPT_RETENTION_HOLD"||
 report.independent_custody_authenticated||report.authenticated_utc||
 report.recovery_authorized||report.lock_cleared{return Err(Error("LEDGER187_AUTHORITY"));}
 let bytes=serde_json::to_vec(report).map_err(|_|Error("LEDGER187_JSON"))?;
 let mut file=OpenOptions::new().write(true).create_new(true).open(path)
  .map_err(|_|Error("LEDGER187_EXISTS"))?;
 file.write_all(&bytes).map_err(|_|Error("LEDGER187_WRITE"))?;
 file.sync_all().map_err(|_|Error("LEDGER187_SYNC"))?;
 File::open(path.parent().ok_or(Error("LEDGER187_PARENT"))?)
  .and_then(|d|d.sync_all()).map_err(|_|Error("LEDGER187_DIRSYNC"))?;
 Ok(digest(&bytes))
}
#[cfg(test)]
mod tests{
 use super::*;
 fn observed(attempt:u32,hash:&str)->Observation{Observation{
  source_sha:SOURCE.into(),run_id:186,attempt,state:"OBSERVED".into(),
  artifact_id:Some(attempt as u64),zip_sha256:Some(hash.repeat(64)),
  embedded_run_id:Some(186),embedded_attempt:Some(attempt),
  deletion_confirmed:false,external_custody_claim:false}}
 #[test]fn distinct_attempts_allowed(){let a=extend(&[],observed(1,"a")).unwrap();
  let b=extend(&a,observed(2,"b")).unwrap();
  assert!(verify(&b).unwrap().source_owned_chain_consistent);}
 #[test]fn same_attempt_conflict_holds(){let a=extend(&[],observed(1,"a")).unwrap();
  let mut b=observed(1,"b");b.artifact_id=Some(1);
  assert!(!verify(&extend(&a,b).unwrap()).unwrap().source_owned_chain_consistent);}
 #[test]fn tamper_denied(){let mut a=extend(&[],observed(1,"a")).unwrap();
  a[0].envelope.observation.artifact_id=Some(99);
  assert_eq!(verify(&a).unwrap_err().0,"LEDGER187_DIGEST");}
 #[test]fn incomplete_deletion_denied(){let mut x=observed(1,"a");
  x.state="DELETED_OBSERVED".into();x.zip_sha256=None;x.embedded_run_id=None;
  x.embedded_attempt=None;
  assert_eq!(extend(&[],x).unwrap_err().0,"LEDGER187_UNPROVEN_DELETION");}
 #[test]fn unobserved_hash_denied(){let mut x=observed(1,"a");
  x.state="READBACK_UNAVAILABLE".into();
  assert_eq!(extend(&[],x).unwrap_err().0,"LEDGER187_UNOBSERVED_BYTES");}
 #[test]fn forged_authority_denied(){let mut x=observed(1,"a");x.external_custody_claim=true;
  assert_eq!(extend(&[],x).unwrap_err().0,"LEDGER187_ANCESTRY_AUTHORITY");}
 #[test]fn no_recovery_after_match(){let f=verify(&extend(&[],observed(1,"a")).unwrap()).unwrap();
  assert!(!f.recovery_authorized&&!f.authenticated_utc);}
 #[test]fn create_only(){let f=verify(&[]).unwrap();
  let p=std::env::temp_dir().join(format!("sapphon187-{}.json",std::process::id()));
  let _=std::fs::remove_file(&p);write_new(&p,&f).unwrap();
  assert_eq!(write_new(&p,&f).unwrap_err().0,"LEDGER187_EXISTS");
  std::fs::remove_file(p).unwrap();}
}
