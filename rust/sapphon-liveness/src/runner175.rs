//! SAPPHON-175 — run observation versus independent qualification. HOLD.
#![cfg(target_os="linux")]
use crate::Error;
use serde::{Deserialize,Serialize};
use sha2::{Digest,Sha256};
use std::{collections::BTreeSet,fs::{File,OpenOptions},io::Write,path::Path};
pub const AUTHORITY:&str="HOLD";
fn hash(b:&[u8])->String{hex::encode(Sha256::digest(b))}
fn valid(s:&str)->bool{s.len()==40&&s.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b))}
const REQUIRED:[&str;3]=["Run offline Python regressions",
 "Run inherited Rust regression suites",
 "Verify inherited 188 historical byte and SHA256 constraints"];
#[derive(Debug,Clone,Serialize,Deserialize,PartialEq,Eq)]
#[serde(deny_unknown_fields)]
pub struct Step{pub name:String,pub conclusion:String}
#[derive(Debug,Clone,Serialize,Deserialize,PartialEq,Eq)]
#[serde(deny_unknown_fields)]
pub struct Input{pub expected_sha:String,pub observed_sha:String,pub run_id:Option<u64>,
 pub attempt:Option<u32>,pub exact_run_observed:bool,
 pub complete:bool,pub expected_job_unique:bool,pub run_success:bool,
 pub failed_child:bool,pub steps:Vec<Step>}
#[derive(Debug,Clone,Serialize,Deserialize,PartialEq,Eq)]
#[serde(deny_unknown_fields)]
pub struct Finding{pub schema:String,pub source_owned_diagnostics_consistent:bool,
 pub blockers:Vec<String>,pub input_sha256:String,
 pub committed_lock_qualified:bool,pub pages_verified:bool,
 pub independent_custody_authenticated:bool,pub global_anti_rollback_authenticated:bool,
 pub recovery_authorized:bool,pub lock_cleared:bool,pub decision:String}
pub fn inspect(x:&Input)->Result<Finding,Error>{
 if !valid(&x.expected_sha)||!valid(&x.observed_sha)||x.steps.len()>128{
    return Err(Error("RUN175_INPUT"));
 }
 let mut blockers=Vec::new();let mut names=BTreeSet::new();
 if x.expected_sha!=x.observed_sha{blockers.push("WRONG_SHA".to_owned());}
 if x.run_id.is_none_or(|n|n==0)||x.attempt.is_none_or(|n|n==0){
    blockers.push("RUN_IDENTITY_MISSING".to_owned());
 }
 if !x.exact_run_observed{blockers.push("EXACT_RUN_NOT_OBSERVED".to_owned());}
 if !x.complete{blockers.push("RUN_INCOMPLETE".to_owned());}
 if !x.expected_job_unique{blockers.push("REQUIRED_JOB_AMBIGUOUS".to_owned());}
 if !x.run_success{blockers.push("RUN_NOT_SUCCESS".to_owned());}
 if x.failed_child{blockers.push("FAILED_CHILD_STEP".to_owned());}
 for s in &x.steps{
   if !names.insert(s.name.as_str()){blockers.push("DUPLICATE_STEP".to_owned());}
   if s.conclusion!="success"{blockers.push("NON_SUCCESS_STEP".to_owned());}
 }
 for name in REQUIRED{
   if x.steps.iter().filter(|s|s.name==name&&s.conclusion=="success").count()!=1{
     blockers.push(format!("REQUIRED_STEP_UNVERIFIED:{name}"));
   }
 }
 blockers.sort();blockers.dedup();
 let b=serde_json::to_vec(x).map_err(|_|Error("RUN175_ENCODING"))?;
 Ok(Finding{schema:"sapphon-175-source-observation-v1".into(),
   source_owned_diagnostics_consistent:blockers.is_empty(),blockers,
   input_sha256:hash(&b),committed_lock_qualified:false,pages_verified:false,
   independent_custody_authenticated:false,global_anti_rollback_authenticated:false,
   recovery_authorized:false,lock_cleared:false,decision:"RUN_OBSERVATION_HOLD".into()})
}
pub fn write_new(path:&Path,r:&Finding)->Result<String,Error>{
 if r.schema!="sapphon-175-source-observation-v1"||r.decision!="RUN_OBSERVATION_HOLD"
    ||r.committed_lock_qualified||r.pages_verified||r.independent_custody_authenticated
    ||r.global_anti_rollback_authenticated||r.recovery_authorized||r.lock_cleared{
     return Err(Error("RUN175_AUTHORITY"));
 }
 let b=serde_json::to_vec(r).map_err(|_|Error("RUN175_ENCODING"))?;
 let mut f=OpenOptions::new().create_new(true).write(true).open(path)
    .map_err(|_|Error("RUN175_EXISTS"))?;
 f.write_all(&b).map_err(|_|Error("RUN175_WRITE"))?;
 f.sync_all().map_err(|_|Error("RUN175_FSYNC"))?;
 File::open(path.parent().ok_or(Error("RUN175_PARENT"))?)
    .and_then(|d|d.sync_all()).map_err(|_|Error("RUN175_DIRSYNC"))?;
 Ok(hash(&b))
}
#[cfg(test)]
mod tests{
 use super::*;
 fn good()->Input{Input{expected_sha:"a".repeat(40),observed_sha:"a".repeat(40),
   run_id:Some(175),attempt:Some(2),exact_run_observed:true,complete:true,
   expected_job_unique:true,run_success:true,failed_child:false,
   steps:REQUIRED.iter().map(|s|Step{name:(*s).into(),conclusion:"success".into()}).collect()}}
 #[test]fn qualified_source_still_no_recovery(){
    let r=inspect(&good()).unwrap();
    assert!(r.source_owned_diagnostics_consistent&&!r.recovery_authorized);
 }
 #[test]fn missing_exact_run_blocks(){let mut a=good();a.exact_run_observed=false;
    assert!(!inspect(&a).unwrap().source_owned_diagnostics_consistent);}
 #[test]fn old_green_missing_run_blocks(){let mut a=good();a.run_id=None;
    assert!(!inspect(&a).unwrap().source_owned_diagnostics_consistent);}
 #[test]fn skipped_rust_blocks(){let mut a=good();a.steps[1].conclusion="skipped".into();
    assert!(!inspect(&a).unwrap().source_owned_diagnostics_consistent);}
 #[test]fn duplicate_step_blocks(){let mut a=good();a.steps.push(a.steps[0].clone());
    assert!(!inspect(&a).unwrap().source_owned_diagnostics_consistent);}
 #[test]fn wrong_commit_blocks(){let mut a=good();a.observed_sha="b".repeat(40);
    assert!(!inspect(&a).unwrap().source_owned_diagnostics_consistent);}
 #[test]fn create_only(){let r=inspect(&good()).unwrap();
    let path=std::env::temp_dir().join(format!("sapphon175-{}.json",std::process::id()));
    let _=std::fs::remove_file(&path);write_new(&path,&r).unwrap();
    assert_eq!(write_new(&path,&r).unwrap_err().0,"RUN175_EXISTS");
    std::fs::remove_file(path).unwrap();}
}
