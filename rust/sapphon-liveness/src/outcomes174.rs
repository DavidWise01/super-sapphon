//! SAPPHON-174 — source-owned runner outcome separation, always operational HOLD.
#![cfg(target_os="linux")]
use crate::Error;
use serde::{Deserialize,Serialize};
use sha2::{Digest,Sha256};
use std::{collections::BTreeSet,fs::{File,OpenOptions},io::Write,path::Path};
pub const AUTHORITY:&str="HOLD";
fn sha(b:&[u8])->String{hex::encode(Sha256::digest(b))}
fn valid(s:&str)->bool{s.len()==40&&s.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b))}
const STEPS:[&str;3]=["Execute Python critical-step regressions",
  "Run Rust typecheck and inherited test suites",
  "Check 188 inherited frozen source hashes"];
#[derive(Debug,Clone,Serialize,Deserialize,PartialEq,Eq)]
#[serde(deny_unknown_fields)]
pub struct Step{pub name:String,pub conclusion:String}
#[derive(Debug,Clone,Serialize,Deserialize,PartialEq,Eq)]
#[serde(deny_unknown_fields)]
pub struct Input{pub expected_sha:String,pub observed_sha:String,
 pub run_id:u64,pub attempt:u32,pub completed:bool,
 pub expected_job_unique:bool,pub run_success:bool,
 pub steps:Vec<Step>,pub failed_child:bool}
#[derive(Debug,Clone,Serialize,Deserialize,PartialEq,Eq)]
#[serde(deny_unknown_fields)]
pub struct Report{pub schema:String,pub source_owned_pass:bool,
 pub blockers:Vec<String>,pub input_sha256:String,
 pub npm_lock_qualified:bool,pub pages_verified:bool,
 pub custody_authenticated:bool,pub anti_rollback_authenticated:bool,
 pub recovery_authorized:bool,pub lock_cleared:bool,pub decision:String}
pub fn inspect(x:&Input)->Result<Report,Error>{
 if !valid(&x.expected_sha)||!valid(&x.observed_sha)||x.run_id==0||x.attempt==0
    ||x.steps.len()>100{return Err(Error("OUT174_FIELDS"));}
 let mut bad=Vec::new();let mut names=BTreeSet::new();
 if x.expected_sha!=x.observed_sha{bad.push("WRONG_SHA".into());}
 if !x.completed{bad.push("INCOMPLETE".into());}
 if !x.expected_job_unique{bad.push("AMBIGUOUS_JOB".into());}
 if !x.run_success{bad.push("RUN_FAILED".into());}
 if x.failed_child{bad.push("FAILED_CHILD".into());}
 for s in &x.steps{if !names.insert(s.name.as_str()){bad.push("DUPLICATE_STEP".into());}}
 for name in STEPS{
  if x.steps.iter().filter(|s|s.name==name&&s.conclusion=="success").count()!=1{
   bad.push(format!("REQUIRED_STEP_UNVERIFIED:{name}"));
  }
 }
 if x.steps.iter().any(|s|["failure","timed_out","cancelled","skipped"].contains(&s.conclusion.as_str())){
  bad.push("UNRESOLVED_STEP".into());
 }
 bad.sort();bad.dedup();
 let b=serde_json::to_vec(x).map_err(|_|Error("OUT174_ENCODING"))?;
 Ok(Report{schema:"sapphon-174-source-outcomes-v1".into(),source_owned_pass:bad.is_empty(),
   blockers:bad,input_sha256:sha(&b),npm_lock_qualified:false,pages_verified:false,
   custody_authenticated:false,anti_rollback_authenticated:false,
   recovery_authorized:false,lock_cleared:false,decision:"SOURCE_OUTCOMES_HOLD".into()})
}
pub fn write_new(path:&Path,r:&Report)->Result<String,Error>{
 if r.schema!="sapphon-174-source-outcomes-v1"||r.decision!="SOURCE_OUTCOMES_HOLD"
    ||r.npm_lock_qualified||r.pages_verified||r.custody_authenticated
    ||r.anti_rollback_authenticated||r.recovery_authorized||r.lock_cleared{
   return Err(Error("OUT174_AUTHORITY"));
 }
 let b=serde_json::to_vec(r).map_err(|_|Error("OUT174_ENCODING"))?;
 let mut f=OpenOptions::new().create_new(true).write(true).open(path)
   .map_err(|_|Error("OUT174_EXISTS"))?;
 f.write_all(&b).map_err(|_|Error("OUT174_WRITE"))?;
 f.sync_all().map_err(|_|Error("OUT174_FSYNC"))?;
 File::open(path.parent().ok_or(Error("OUT174_PARENT"))?)
   .and_then(|p|p.sync_all()).map_err(|_|Error("OUT174_DIRSYNC"))?;
 Ok(sha(&b))
}
#[cfg(test)]
mod tests{
 use super::*;
 fn fixture()->Input{Input{expected_sha:"a".repeat(40),observed_sha:"a".repeat(40),
   run_id:174,attempt:2,completed:true,expected_job_unique:true,run_success:true,
   steps:STEPS.iter().map(|s|Step{name:(*s).into(),conclusion:"success".into()}).collect(),
   failed_child:false}}
 #[test]fn source_pass_is_not_custody(){let r=inspect(&fixture()).unwrap();
    assert!(r.source_owned_pass&&!r.custody_authenticated&&!r.recovery_authorized);}
 #[test]fn missing_hash_step_fails(){let mut i=fixture();i.steps.pop();
    assert!(!inspect(&i).unwrap().source_owned_pass);}
 #[test]fn failed_child_fails(){let mut i=fixture();i.failed_child=true;
    assert!(!inspect(&i).unwrap().source_owned_pass);}
 #[test]fn duplicate_step_fails(){let mut i=fixture();i.steps.push(i.steps[0].clone());
    assert!(!inspect(&i).unwrap().source_owned_pass);}
 #[test]fn skipped_rust_fails(){let mut i=fixture();i.steps[1].conclusion="skipped".into();
    assert!(!inspect(&i).unwrap().source_owned_pass);}
 #[test]fn create_only(){let r=inspect(&fixture()).unwrap();
    let path=std::env::temp_dir().join(format!("sapphon174-{}.json",std::process::id()));
    let _=std::fs::remove_file(&path);write_new(&path,&r).unwrap();
    assert_eq!(write_new(&path,&r).unwrap_err().0,"OUT174_EXISTS");
    std::fs::remove_file(path).unwrap();}
}
