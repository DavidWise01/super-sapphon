//! SAPPHON-177. Exact-source owned execution findings; recovery HOLD.
#![cfg(target_os="linux")]
use crate::Error;
use serde::{Deserialize,Serialize};
use sha2::{Digest,Sha256};
use std::{collections::BTreeSet,fs::{File,OpenOptions},io::Write,path::Path};
pub const AUTHORITY:&str="HOLD";
const REQUIRED:[&str;3]=["Execute Python adversarial and source-freeze tests",
 "Run all inherited Rust source checks and test suites",
 "Check exact bytes and SHA-256 for 188 inherited frozen sources"];
fn hex40(s:&str)->bool{s.len()==40&&s.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b))}
fn hash(b:&[u8])->String{hex::encode(Sha256::digest(b))}
#[derive(Debug,Clone,Serialize,Deserialize,PartialEq,Eq)]
#[serde(deny_unknown_fields)]
pub struct Step{pub name:String,pub conclusion:String}
#[derive(Debug,Clone,Serialize,Deserialize,PartialEq,Eq)]
#[serde(deny_unknown_fields)]
pub struct Input{pub expected_sha:String,pub observed_sha:String,pub run_id:Option<u64>,
 pub attempt:Option<u32>,pub complete:bool,pub expected_job_unique:bool,
 pub run_success:bool,pub steps:Vec<Step>,pub failed_child:bool}
#[derive(Debug,Clone,Serialize,Deserialize,PartialEq,Eq)]
#[serde(deny_unknown_fields)]
pub struct Finding{pub schema:String,pub source_pass_consistent:bool,
 pub blockers:Vec<String>,pub input_sha256:String,
 pub externally_authenticated_custody:bool,pub global_anti_rollback:bool,
 pub npm_lock_qualified:bool,pub recovery_authorized:bool,pub lock_cleared:bool,
 pub decision:String}
pub fn assess(x:&Input)->Result<Finding,Error>{
 if !hex40(&x.expected_sha)||!hex40(&x.observed_sha)||x.steps.len()>128{
  return Err(Error("EVID177_INPUT"));
 }
 let mut blockers=vec![];let mut seen=BTreeSet::new();
 if x.expected_sha!=x.observed_sha{blockers.push("SOURCE_MISMATCH".to_owned());}
 if x.run_id.is_none_or(|id|id==0)||x.attempt.is_none_or(|id|id==0){
  blockers.push("RUN_IDENTITY_MISSING".to_owned());
 }
 if !x.complete{blockers.push("INCOMPLETE".to_owned());}
 if !x.expected_job_unique{blockers.push("JOB_NOT_UNIQUE".to_owned());}
 if !x.run_success{blockers.push("RUN_NOT_SUCCESS".to_owned());}
 if x.failed_child{blockers.push("FAILED_CHILD".to_owned());}
 for s in &x.steps{
  if !seen.insert(s.name.as_str()){blockers.push("DUPLICATE_STEP".to_owned());}
  if s.conclusion!="success"{blockers.push("UNSUCCESSFUL_STEP".to_owned());}
 }
 for required in REQUIRED{
  if x.steps.iter().filter(|s|s.name==required&&s.conclusion=="success").count()!=1{
   blockers.push(format!("MISSING_CRITICAL_STEP:{required}"));
  }
 }
 blockers.sort();blockers.dedup();
 let b=serde_json::to_vec(x).map_err(|_|Error("EVID177_ENCODING"))?;
 Ok(Finding{schema:"sapphon-177-evidence-first-rust-v1".into(),
  source_pass_consistent:blockers.is_empty(),blockers,input_sha256:hash(&b),
  externally_authenticated_custody:false,global_anti_rollback:false,
  npm_lock_qualified:false,recovery_authorized:false,lock_cleared:false,
  decision:"EVIDENCE_FIRST_HOLD".into()})
}
pub fn write_new(path:&Path,r:&Finding)->Result<String,Error>{
 if r.schema!="sapphon-177-evidence-first-rust-v1"||r.decision!="EVIDENCE_FIRST_HOLD"
   ||r.externally_authenticated_custody||r.global_anti_rollback
   ||r.npm_lock_qualified||r.recovery_authorized||r.lock_cleared{
  return Err(Error("EVID177_AUTHORITY"));
 }
 let b=serde_json::to_vec(r).map_err(|_|Error("EVID177_ENCODING"))?;
 let mut f=OpenOptions::new().create_new(true).write(true).open(path)
  .map_err(|_|Error("EVID177_EXISTS"))?;
 f.write_all(&b).map_err(|_|Error("EVID177_WRITE"))?;
 f.sync_all().map_err(|_|Error("EVID177_FSYNC"))?;
 File::open(path.parent().ok_or(Error("EVID177_PARENT"))?)
  .and_then(|d|d.sync_all()).map_err(|_|Error("EVID177_DIRSYNC"))?;
 Ok(hash(&b))
}
#[cfg(test)]
mod tests{
 use super::*;
 fn good()->Input{Input{expected_sha:"a".repeat(40),observed_sha:"a".repeat(40),
  run_id:Some(176),attempt:Some(1),complete:true,expected_job_unique:true,
  run_success:true,failed_child:false,
  steps:REQUIRED.iter().map(|s|Step{name:(*s).into(),conclusion:"success".into()}).collect()}}
 #[test]fn source_pass_never_recovers(){let r=assess(&good()).unwrap();
  assert!(r.source_pass_consistent&&!r.recovery_authorized);}
 #[test]fn missing_run_blocks(){let mut x=good();x.run_id=None;
  assert!(!assess(&x).unwrap().source_pass_consistent);}
 #[test]fn skipped_step_blocks(){let mut x=good();x.steps[1].conclusion="skipped".into();
  assert!(!assess(&x).unwrap().source_pass_consistent);}
 #[test]fn duplicate_step_blocks(){let mut x=good();x.steps.push(x.steps[0].clone());
  assert!(!assess(&x).unwrap().source_pass_consistent);}
 #[test]fn wrong_sha_blocks(){let mut x=good();x.observed_sha="b".repeat(40);
  assert!(!assess(&x).unwrap().source_pass_consistent);}
 #[test]fn create_only(){let r=assess(&good()).unwrap();
  let p=std::env::temp_dir().join(format!("sapphon177-{}.json",std::process::id()));
  let _=std::fs::remove_file(&p);write_new(&p,&r).unwrap();
  assert_eq!(write_new(&p,&r).unwrap_err().0,"EVID177_EXISTS");std::fs::remove_file(p).unwrap();}
}
