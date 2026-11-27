//! SAPPHON-195 original log and artifact attestation parity, replay PLAN_ONLY.
#![cfg(target_os="linux")]
use crate::Error;
use serde::{Deserialize,Serialize};
use sha2::{Digest,Sha256};
use std::{fs::{File,OpenOptions},io::Write,path::Path};
pub const AUTHORITY:&str="HOLD";
const SOURCE:&str="c2f237a5065c29a13947657c707d101ff2dca31e";
fn hex64(s:&str)->bool{s.len()==64&&s.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b))}
fn digest(data:&[u8])->String{hex::encode(Sha256::digest(data))}
#[derive(Debug,Clone,Serialize,Deserialize,PartialEq,Eq)]
#[serde(deny_unknown_fields)]
pub struct Input{
 pub source_sha:String,pub original_run_id:Option<u64>,pub original_attempt:Option<u32>,
 pub log_sha256:Option<String>,pub artifact_sha256:Option<String>,
 pub complete_job_and_artifact_pages:bool,pub original_archive_attempt_matches:bool,
 pub acquisition_summary_agrees:bool,pub failed_steps:Vec<String>,
 pub untrusted_commands_present:bool,pub external_custody_claim:bool
}
#[derive(Debug,Clone,Serialize,Deserialize,PartialEq,Eq)]
#[serde(deny_unknown_fields)]
pub struct Finding{
 pub schema:String,pub input_sha256:String,pub blockers:Vec<String>,
 pub owned_report_parity:bool,pub allowlisted_replay_ids:Vec<String>,
 pub replay_executed:bool,pub original_bytes_reread:bool,
 pub independent_witnesses:u8,pub authenticated_utc:bool,
 pub global_anti_rollback_authenticated:bool,
 pub recovery_authorized:bool,pub lock_cleared:bool,pub decision:String
}
pub fn assess(v:&Input)->Result<Finding,Error>{
 if v.failed_steps.len()>64{return Err(Error("CROSSVERIFY195_STEP_LIMIT"));}
 let mut bad=Vec::new();
 if v.source_sha!=SOURCE{bad.push("SOURCE_MISMATCH".to_owned());}
 if v.original_run_id.is_none_or(|x|x==0)||v.original_attempt.is_none_or(|x|x==0){
  bad.push("ORIGINAL_ATTEMPT_MISSING".into());
 }
 if v.log_sha256.as_deref().is_none_or(|x|!hex64(x)){
  bad.push("ORIGINAL_LOG_DIGEST_MISSING".into());
 }
 if v.artifact_sha256.as_deref().is_none_or(|x|!hex64(x)){
  bad.push("ORIGINAL_ZIP_DIGEST_MISSING".into());
 }
 if !v.complete_job_and_artifact_pages{bad.push("PAGINATION_INCOMPLETE".into());}
 if !v.original_archive_attempt_matches{bad.push("ARCHIVE_ATTEMPT_MISMATCH".into());}
 if !v.acquisition_summary_agrees{bad.push("SOURCE_REPORT_EQUIVOCATION".into());}
 if v.external_custody_claim{bad.push("FORGED_EXTERNAL_CUSTODY".into());}
 let mut replay=Vec::new();
 if bad.is_empty(){
  for name in &v.failed_steps{
   let id=match name.as_str(){
    "Execute Python exact-run diagnostics and inherited regressions"=>Some("PYTHON_TRIAGE"),
    "Compile and test Rust runner failure diagnostic"=>Some("RUST_TESTS"),
    "Verify protected 188 historical immutable files"=>Some("FROZEN_HISTORY"),
    _=>None};
   if let Some(id)=id{
    if !replay.contains(&id.to_owned()){replay.push(id.to_owned());}
   }
  }
 }
 // Untrusted command text is never used as executable source.
 bad.sort();bad.dedup();
 let input=serde_json::to_vec(v).map_err(|_|Error("CROSSVERIFY195_JSON"))?;
 Ok(Finding{schema:"sapphon-195-rust-crossverify-v1".into(),input_sha256:digest(&input),
  owned_report_parity:bad.is_empty(),blockers:bad,allowlisted_replay_ids:replay,
  replay_executed:false,original_bytes_reread:false,
  independent_witnesses:0,authenticated_utc:false,
  global_anti_rollback_authenticated:false,recovery_authorized:false,
  lock_cleared:false,decision:"LOG_ARTIFACT_CROSS_VERIFICATION_HOLD".into()})
}
pub fn write_new(path:&Path,r:&Finding)->Result<String,Error>{
 if r.schema!="sapphon-195-rust-crossverify-v1"||
 r.decision!="LOG_ARTIFACT_CROSS_VERIFICATION_HOLD"||
 r.replay_executed||r.original_bytes_reread||r.independent_witnesses!=0||
 r.authenticated_utc||r.global_anti_rollback_authenticated||
 r.recovery_authorized||r.lock_cleared{return Err(Error("CROSSVERIFY195_AUTHORITY"));}
 let bytes=serde_json::to_vec(r).map_err(|_|Error("CROSSVERIFY195_JSON"))?;
 let mut f=OpenOptions::new().write(true).create_new(true).open(path)
  .map_err(|_|Error("CROSSVERIFY195_EXISTS"))?;
 f.write_all(&bytes).map_err(|_|Error("CROSSVERIFY195_WRITE"))?;
 f.sync_all().map_err(|_|Error("CROSSVERIFY195_SYNC"))?;
 File::open(path.parent().ok_or(Error("CROSSVERIFY195_PARENT"))?)
  .and_then(|d|d.sync_all()).map_err(|_|Error("CROSSVERIFY195_DIRSYNC"))?;
 Ok(digest(&bytes))
}
#[cfg(test)]
mod tests{
 use super::*;
 fn fixture()->Input{Input{source_sha:SOURCE.into(),original_run_id:Some(193),
  original_attempt:Some(2),log_sha256:Some("a".repeat(64)),
  artifact_sha256:Some("b".repeat(64)),complete_job_and_artifact_pages:true,
  original_archive_attempt_matches:true,acquisition_summary_agrees:true,
  failed_steps:vec!["Compile and test Rust runner failure diagnostic".into()],
  untrusted_commands_present:false,external_custody_claim:false}}
 #[test]fn valid_owned_reports_only_plan(){let f=assess(&fixture()).unwrap();
  assert!(f.owned_report_parity&&!f.replay_executed&&!f.recovery_authorized);
  assert_eq!(f.allowlisted_replay_ids,vec!["RUST_TESTS"]);}
 #[test]fn missing_log_rejected(){let mut v=fixture();v.log_sha256=None;
  assert!(!assess(&v).unwrap().owned_report_parity);}
 #[test]fn wrong_attempt_rejected(){let mut v=fixture();v.original_archive_attempt_matches=false;
  assert!(!assess(&v).unwrap().owned_report_parity);}
 #[test]fn report_conflict_rejected(){let mut v=fixture();v.acquisition_summary_agrees=false;
  assert!(!assess(&v).unwrap().owned_report_parity);}
 #[test]fn untrusted_command_never_allowlisted(){let mut v=fixture();
  v.failed_steps=vec!["rm -rf /".into()];v.untrusted_commands_present=true;
  assert!(assess(&v).unwrap().allowlisted_replay_ids.is_empty());}
 #[test]fn duplicate_known_steps_single_plan(){let mut v=fixture();
  v.failed_steps.push(v.failed_steps[0].clone());
  assert_eq!(assess(&v).unwrap().allowlisted_replay_ids.len(),1);}
 #[test]fn external_claim_rejected(){let mut v=fixture();v.external_custody_claim=true;
  assert!(!assess(&v).unwrap().owned_report_parity);}
 #[test]fn create_only(){let f=assess(&fixture()).unwrap();
  let p=std::env::temp_dir().join(format!("sapphon195-{}.json",std::process::id()));
  let _=std::fs::remove_file(&p);write_new(&p,&f).unwrap();
  assert_eq!(write_new(&p,&f).unwrap_err().0,"CROSSVERIFY195_EXISTS");
  std::fs::remove_file(p).unwrap();}
}
