//! SAPPHON-194: exact original hosted job and archive identity observation.
#![cfg(target_os="linux")]
use crate::Error;
use serde::{Deserialize,Serialize};
use sha2::{Digest,Sha256};
use std::{fs::{File,OpenOptions},io::Write,path::Path};
pub const AUTHORITY:&str="HOLD";
const SOURCE:&str="517959b0c98b65bafefaba5ae5e18065b2e27212";
fn hex64(x:&str)->bool{x.len()==64&&x.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b))}
fn hash(x:&[u8])->String{hex::encode(Sha256::digest(x))}
#[derive(Clone,Debug,Serialize,Deserialize,PartialEq,Eq)]
#[serde(deny_unknown_fields)]
pub struct Input{
 pub source_sha:String,pub run_id:Option<u64>,pub attempt:Option<u32>,
 pub completed:bool,pub job_unique:bool,pub run_pages_exhausted:bool,
 pub job_pages_exhausted:bool,pub artifact_pages_exhausted:bool,
 pub log_bytes_sha256:Option<String>,pub zip_bytes_sha256:Option<String>,
 pub zip_embedded_attempt_matches:bool,
 pub failed_step_count:u32,pub expected_artifact_unique:bool,
 pub external_authority_claim:bool
}
#[derive(Clone,Debug,Serialize,Deserialize,PartialEq,Eq)]
#[serde(deny_unknown_fields)]
pub struct Finding{
 pub schema:String,pub input_sha256:String,
 pub owned_original_bytes_consistent:bool,pub blockers:Vec<String>,
 pub actual_failures_count:u32,
 pub independent_witnesses:u8,pub authenticated_utc:bool,
 pub global_anti_rollback_authenticated:bool,
 pub recovery_authorized:bool,pub lock_cleared:bool,pub decision:String
}
pub fn assess(x:&Input)->Result<Finding,Error>{
 let mut blockers=Vec::new();
 if x.source_sha!=SOURCE{blockers.push("SOURCE_MISMATCH".to_owned());}
 if x.run_id.is_none_or(|n|n==0)||x.attempt.is_none_or(|n|n==0)||
    !x.completed{blockers.push("RUN_NOT_IDENTIFIED".into());}
 if !x.run_pages_exhausted||!x.job_pages_exhausted||!x.artifact_pages_exhausted{
  blockers.push("INCOMPLETE_PAGINATION".into());
 }
 if !x.job_unique||!x.expected_artifact_unique{blockers.push("NONUNIQUE_REQUIRED_RECORD".into());}
 for (name,value) in [("JOB_LOG",&x.log_bytes_sha256),("ZIP",&x.zip_bytes_sha256)]{
  if value.as_deref().is_none_or(|v|!hex64(v)){
   blockers.push(format!("ORIGINAL_{name}_UNOBSERVED"));
  }
 }
 if !x.zip_embedded_attempt_matches{blockers.push("EMBEDDED_ATTEMPT_MISMATCH".into());}
 if x.external_authority_claim{blockers.push("FORGED_EXTERNAL_AUTHORITY".into());}
 blockers.sort();blockers.dedup();
 let bytes=serde_json::to_vec(x).map_err(|_|Error("ACQUIRE194_ENCODING"))?;
 Ok(Finding{schema:"sapphon-194-rust-evidence-v1".into(),
  input_sha256:hash(&bytes),owned_original_bytes_consistent:blockers.is_empty(),
  blockers,actual_failures_count:x.failed_step_count,
  independent_witnesses:0,authenticated_utc:false,
  global_anti_rollback_authenticated:false,
  recovery_authorized:false,lock_cleared:false,
  decision:"HOSTED_ORIGINAL_BYTES_ACQUISITION_HOLD".into()})
}
pub fn write_new(path:&Path,f:&Finding)->Result<String,Error>{
 if f.schema!="sapphon-194-rust-evidence-v1"||
 f.decision!="HOSTED_ORIGINAL_BYTES_ACQUISITION_HOLD"||
 f.independent_witnesses!=0||f.authenticated_utc||
 f.global_anti_rollback_authenticated||f.recovery_authorized||f.lock_cleared{
  return Err(Error("ACQUIRE194_AUTHORITY"));
 }
 let bytes=serde_json::to_vec(f).map_err(|_|Error("ACQUIRE194_ENCODING"))?;
 let mut handle=OpenOptions::new().write(true).create_new(true).open(path)
  .map_err(|_|Error("ACQUIRE194_EXISTS"))?;
 handle.write_all(&bytes).map_err(|_|Error("ACQUIRE194_WRITE"))?;
 handle.sync_all().map_err(|_|Error("ACQUIRE194_SYNC"))?;
 File::open(path.parent().ok_or(Error("ACQUIRE194_PARENT"))?)
  .and_then(|d|d.sync_all()).map_err(|_|Error("ACQUIRE194_DIRSYNC"))?;
 Ok(hash(&bytes))
}
#[cfg(test)]
mod tests{
 use super::*;
 fn good()->Input{Input{
  source_sha:SOURCE.into(),run_id:Some(193),attempt:Some(2),
  completed:true,job_unique:true,run_pages_exhausted:true,
  job_pages_exhausted:true,artifact_pages_exhausted:true,
  log_bytes_sha256:Some("a".repeat(64)),zip_bytes_sha256:Some("b".repeat(64)),
  zip_embedded_attempt_matches:true,failed_step_count:0,
  expected_artifact_unique:true,external_authority_claim:false}}
 #[test]fn original_hashes_only_owned(){let r=assess(&good()).unwrap();
  assert!(r.owned_original_bytes_consistent&&!r.recovery_authorized);}
 #[test]fn absent_log_denied(){let mut x=good();x.log_bytes_sha256=None;
  assert!(!assess(&x).unwrap().owned_original_bytes_consistent);}
 #[test]fn prior_attempt_denied(){let mut x=good();x.zip_embedded_attempt_matches=false;
  assert!(!assess(&x).unwrap().owned_original_bytes_consistent);}
 #[test]fn incomplete_jobs_denied(){let mut x=good();x.job_pages_exhausted=false;
  assert!(!assess(&x).unwrap().owned_original_bytes_consistent);}
 #[test]fn duplicate_artifact_denied(){let mut x=good();x.expected_artifact_unique=false;
  assert!(!assess(&x).unwrap().owned_original_bytes_consistent);}
 #[test]fn observed_failure_retained(){let mut x=good();x.failed_step_count=2;
  let r=assess(&x).unwrap();assert_eq!(r.actual_failures_count,2);}
 #[test]fn false_custody_denied(){let mut x=good();x.external_authority_claim=true;
  assert!(!assess(&x).unwrap().owned_original_bytes_consistent);}
 #[test]fn create_only(){let r=assess(&good()).unwrap();
  let p=std::env::temp_dir().join(format!("sapphon194-{}.json",std::process::id()));
  let _=std::fs::remove_file(&p);write_new(&p,&r).unwrap();
  assert_eq!(write_new(&p,&r).unwrap_err().0,"ACQUIRE194_EXISTS");
  std::fs::remove_file(p).unwrap();}
}
