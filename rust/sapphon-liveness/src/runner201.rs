//! SAPPHON-201: qualification of exact Phase XIX hosted runner evidence.
#![cfg(target_os="linux")]
use crate::Error;
use serde::{Deserialize,Serialize};
use sha2::{Digest,Sha256};
use std::{fs::{File,OpenOptions},io::Write,path::Path};
pub const AUTHORITY:&str="HOLD";
const SOURCE:&str="c914d2710192cf0c80e12641dfad82a4a006998d";
fn valid(s:&str)->bool{s.len()==64&&s.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b))}
fn hash(b:&[u8])->String{hex::encode(Sha256::digest(b))}
#[derive(Clone,Debug,Serialize,Deserialize,PartialEq,Eq)]
#[serde(deny_unknown_fields)]
pub struct Step{pub name:String,pub outcome:String}
#[derive(Clone,Debug,Serialize,Deserialize,PartialEq,Eq)]
#[serde(deny_unknown_fields)]
pub struct Input{
 pub original_source_sha:String,pub run_id:Option<u64>,pub run_attempt:Option<u32>,
 pub completed:bool,pub run_success:bool,pub required_job_unique:bool,
 pub required_job_success:bool,pub run_pages_exhausted:bool,
 pub job_pages_exhausted:bool,pub artifact_pages_exhausted:bool,
 pub log_sha256:Option<String>,pub artifact_sha256:Option<String>,
 pub artifact_attempt_matched:bool,pub original_freeze_source_matched:bool,
 pub steps:Vec<Step>,pub external_authority_claim:bool
}
#[derive(Clone,Debug,Serialize,Deserialize,PartialEq,Eq)]
#[serde(deny_unknown_fields)]
pub struct Finding{
 pub schema:String,pub input_sha256:String,pub source_owned_runner_qualified:bool,
 pub blockers:Vec<String>,pub independently_authenticated_witnesses:u8,
 pub external_custody_authenticated:bool,pub authenticated_utc:bool,
 pub global_anti_rollback_authenticated:bool,pub recovery_authorized:bool,
 pub lock_cleared:bool,pub decision:String
}
const REQUIRED:[&str;4]=["python","rust","frozen","freeze"];
pub fn assess(v:&Input)->Result<Finding,Error>{
 if v.steps.len()>128{return Err(Error("RUNNER201_STEP_LIMIT"));}
 let mut bad=Vec::new();
 if v.original_source_sha!=SOURCE||v.run_id.is_none_or(|n|n==0)||
    v.run_attempt.is_none_or(|n|n==0){bad.push("EXACT_SOURCE_RUN_IDENTITY".into());}
 if !v.completed||!v.run_success||!v.required_job_unique||!v.required_job_success{
  bad.push("RUN_OR_JOB_NOT_SUCCESS".into());
 }
 if !v.run_pages_exhausted||!v.job_pages_exhausted||!v.artifact_pages_exhausted{
  bad.push("LISTING_NOT_EXHAUSTED".into());
 }
 if v.log_sha256.as_deref().is_none_or(|s|!valid(s))||
    v.artifact_sha256.as_deref().is_none_or(|s|!valid(s)){
  bad.push("ORIGINAL_BYTES_MISSING".into());
 }
 if !v.artifact_attempt_matched||!v.original_freeze_source_matched{
  bad.push("ORIGINAL_ARTIFACT_ANCESTRY".into());
 }
 for required in REQUIRED{
  let matches:Vec<&Step>=v.steps.iter().filter(|s|s.name==required).collect();
  if matches.len()!=1||matches[0].outcome!="success"{
   bad.push(format!("CRITICAL_STEP_NOT_SUCCESS:{required}"));
  }
 }
 if v.external_authority_claim{bad.push("FORGED_EXTERNAL_AUTHORITY".into());}
 bad.sort();bad.dedup();
 let data=serde_json::to_vec(v).map_err(|_|Error("RUNNER201_JSON"))?;
 Ok(Finding{schema:"sapphon-201-rust-runner-v1".into(),
   input_sha256:hash(&data),source_owned_runner_qualified:bad.is_empty(),
   blockers:bad,independently_authenticated_witnesses:0,
   external_custody_authenticated:false,authenticated_utc:false,
   global_anti_rollback_authenticated:false,recovery_authorized:false,
   lock_cleared:false,decision:"PHASE_XX_HOSTED_QUALIFICATION_HOLD".into()})
}
pub fn write_new(path:&Path,report:&Finding)->Result<String,Error>{
 if report.schema!="sapphon-201-rust-runner-v1"||
    report.decision!="PHASE_XX_HOSTED_QUALIFICATION_HOLD"||
    report.independently_authenticated_witnesses!=0||
    report.external_custody_authenticated||report.authenticated_utc||
    report.global_anti_rollback_authenticated||report.recovery_authorized||
    report.lock_cleared{return Err(Error("RUNNER201_AUTHORITY"));}
 let bytes=serde_json::to_vec(report).map_err(|_|Error("RUNNER201_JSON"))?;
 let mut f=OpenOptions::new().create_new(true).write(true).open(path)
  .map_err(|_|Error("RUNNER201_EXISTS"))?;
 f.write_all(&bytes).map_err(|_|Error("RUNNER201_WRITE"))?;
 f.sync_all().map_err(|_|Error("RUNNER201_SYNC"))?;
 File::open(path.parent().ok_or(Error("RUNNER201_PARENT"))?)
  .and_then(|d|d.sync_all()).map_err(|_|Error("RUNNER201_DIRSYNC"))?;
 Ok(hash(&bytes))
}
#[cfg(test)]
mod tests{
 use super::*;
 fn fixture()->Input{Input{original_source_sha:SOURCE.into(),run_id:Some(200),
   run_attempt:Some(2),completed:true,run_success:true,required_job_unique:true,
   required_job_success:true,run_pages_exhausted:true,job_pages_exhausted:true,
   artifact_pages_exhausted:true,log_sha256:Some("a".repeat(64)),
   artifact_sha256:Some("b".repeat(64)),artifact_attempt_matched:true,
   original_freeze_source_matched:true,external_authority_claim:false,
   steps:REQUIRED.iter().map(|n|Step{name:(*n).into(),outcome:"success".into()}).collect()}}
 #[test]fn owned_green_still_hold(){let x=assess(&fixture()).unwrap();
  assert!(x.source_owned_runner_qualified&&!x.recovery_authorized);}
 #[test]fn unavailable_log_denied(){let mut x=fixture();x.log_sha256=None;
  assert!(!assess(&x).unwrap().source_owned_runner_qualified);}
 #[test]fn wrong_attempt_denied(){let mut x=fixture();x.artifact_attempt_matched=false;
  assert!(!assess(&x).unwrap().source_owned_runner_qualified);}
 #[test]fn failed_child_denied(){let mut x=fixture();x.steps[1].outcome="failure".into();
  assert!(!assess(&x).unwrap().source_owned_runner_qualified);}
 #[test]fn missing_child_denied(){let mut x=fixture();x.steps.pop();
  assert!(!assess(&x).unwrap().source_owned_runner_qualified);}
 #[test]fn duplicated_child_denied(){let mut x=fixture();x.steps.push(x.steps[0].clone());
  assert!(!assess(&x).unwrap().source_owned_runner_qualified);}
 #[test]fn unexhausted_job_pages_denied(){let mut x=fixture();x.job_pages_exhausted=false;
  assert!(!assess(&x).unwrap().source_owned_runner_qualified);}
 #[test]fn external_custody_denied(){let mut x=fixture();x.external_authority_claim=true;
  assert!(!assess(&x).unwrap().source_owned_runner_qualified);}
 #[test]fn create_only(){let x=assess(&fixture()).unwrap();
  let p=std::env::temp_dir().join(format!("sapphon201-{}.json",std::process::id()));
  let _=std::fs::remove_file(&p);write_new(&p,&x).unwrap();
  assert_eq!(write_new(&p,&x).unwrap_err().0,"RUNNER201_EXISTS");
  std::fs::remove_file(p).unwrap();}
}
