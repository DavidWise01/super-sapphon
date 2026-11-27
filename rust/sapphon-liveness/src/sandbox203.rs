//! SAPPHON-203: exact evidence ancestry and isolated diagnostic replay fence.
#![cfg(target_os="linux")]
use crate::Error;
use serde::{Deserialize,Serialize};
use sha2::{Digest,Sha256};
use std::{fs::{File,OpenOptions},io::Write,path::Path};
pub const AUTHORITY:&str="HOLD";
const SOURCE:&str="e3053b2b52317fc5d5cf1f2546b1e1f0efcc2c6f";
fn hash(s:&[u8])->String{hex::encode(Sha256::digest(s))}
fn hex64(s:&str)->bool{s.len()==64&&s.bytes().all(|c|c.is_ascii_digit()||(b'a'..=b'f').contains(&c))}
#[derive(Clone,Debug,Serialize,Deserialize,PartialEq,Eq)]
#[serde(deny_unknown_fields)]
pub struct Input{
 pub source_sha:String,pub original_201_run_id:u64,pub original_201_attempt:u32,
 pub prior_202_artifact_observed:bool,pub fresh_201_original_bytes_observed:bool,
 pub prior_log_sha256:String,pub fresh_log_sha256:String,
 pub prior_zip_sha256:String,pub fresh_zip_sha256:String,
 pub source_checkout_sha:String,pub observed_failed_step:String,
 pub replay_command_id:String,pub network_disabled:bool,
 pub source_mount_readonly:bool,pub sandbox_no_new_privileges:bool,
 pub original_log_commands_ignored:bool,pub external_witness_claim:bool
}
#[derive(Clone,Debug,Serialize,Deserialize,PartialEq,Eq)]
#[serde(deny_unknown_fields)]
pub struct Finding{
 pub schema:String,pub input_sha256:String,
 pub sandboxed_replay_eligible:bool,pub blockers:Vec<String>,
 pub replay_executed:bool,pub independent_witnesses:u8,
 pub authenticated_utc:bool,pub global_anti_rollback_authenticated:bool,
 pub recovery_authorized:bool,pub lock_cleared:bool,pub decision:String
}
pub fn assess(x:&Input)->Result<Finding,Error>{
 let mut blockers=Vec::new();
 if x.source_sha!=SOURCE||x.source_checkout_sha!="b5ddf7f7d7d51a282c0109276dc37310f56eb240"||
 x.original_201_run_id==0||x.original_201_attempt==0{
  blockers.push("SOURCE_OR_RUN_IDENTITY".into());
 }
 if !x.prior_202_artifact_observed||!x.fresh_201_original_bytes_observed{
  blockers.push("TWO_READBACKS_INCOMPLETE".into());
 }
 if !hex64(&x.prior_log_sha256)||!hex64(&x.prior_zip_sha256)||
 x.prior_log_sha256!=x.fresh_log_sha256||x.prior_zip_sha256!=x.fresh_zip_sha256{
  blockers.push("ORIGINAL_BYTE_EQUIVOCATION".into());
 }
 if !["python","frozen"].contains(&x.observed_failed_step.as_str())||
 x.observed_failed_step!=x.replay_command_id{
  blockers.push("REPLAY_NOT_IN_REVIEWED_ALLOWLIST".into());
 }
 if !x.network_disabled||!x.source_mount_readonly||!x.sandbox_no_new_privileges||
 !x.original_log_commands_ignored{
  blockers.push("ISOLATION_GUARD_NOT_PROVEN".into());
 }
 if x.external_witness_claim{blockers.push("UNSUPPORTED_EXTERNAL_WITNESS".into());}
 blockers.sort();blockers.dedup();
 let bytes=serde_json::to_vec(x).map_err(|_|Error("SANDBOX203_ENCODING"))?;
 Ok(Finding{schema:"sapphon-203-rust-sandbox-v1".into(),input_sha256:hash(&bytes),
  sandboxed_replay_eligible:blockers.is_empty(),blockers,replay_executed:false,
  independent_witnesses:0,authenticated_utc:false,
  global_anti_rollback_authenticated:false,recovery_authorized:false,
  lock_cleared:false,decision:"PHASE_XX_SANDBOXED_REPLAY_HOLD".into()})
}
pub fn write_new(path:&Path,v:&Finding)->Result<String,Error>{
 if v.schema!="sapphon-203-rust-sandbox-v1"||
 v.decision!="PHASE_XX_SANDBOXED_REPLAY_HOLD"||v.replay_executed||
 v.independent_witnesses!=0||v.authenticated_utc||
 v.global_anti_rollback_authenticated||v.recovery_authorized||v.lock_cleared{
  return Err(Error("SANDBOX203_AUTHORITY"));
 }
 let raw=serde_json::to_vec(v).map_err(|_|Error("SANDBOX203_ENCODING"))?;
 let mut f=OpenOptions::new().write(true).create_new(true).open(path)
  .map_err(|_|Error("SANDBOX203_EXISTS"))?;
 f.write_all(&raw).map_err(|_|Error("SANDBOX203_WRITE"))?;
 f.sync_all().map_err(|_|Error("SANDBOX203_SYNC"))?;
 File::open(path.parent().ok_or(Error("SANDBOX203_PARENT"))?)
  .and_then(|x|x.sync_all()).map_err(|_|Error("SANDBOX203_DIRSYNC"))?;
 Ok(hash(&raw))
}
#[cfg(test)]
mod tests{
 use super::*;
 fn good()->Input{Input{source_sha:SOURCE.into(),original_201_run_id:201,
  original_201_attempt:2,prior_202_artifact_observed:true,
  fresh_201_original_bytes_observed:true,prior_log_sha256:"a".repeat(64),
  fresh_log_sha256:"a".repeat(64),prior_zip_sha256:"b".repeat(64),
  fresh_zip_sha256:"b".repeat(64),
  source_checkout_sha:"b5ddf7f7d7d51a282c0109276dc37310f56eb240".into(),
  observed_failed_step:"python".into(),replay_command_id:"python".into(),
  network_disabled:true,source_mount_readonly:true,
  sandbox_no_new_privileges:true,original_log_commands_ignored:true,
  external_witness_claim:false}}
 #[test]fn qualified_still_hold(){let r=assess(&good()).unwrap();
  assert!(r.sandboxed_replay_eligible&&!r.recovery_authorized&&!r.replay_executed);}
 #[test]fn no_second_readback(){let mut x=good();x.fresh_201_original_bytes_observed=false;
  assert!(!assess(&x).unwrap().sandboxed_replay_eligible);}
 #[test]fn changed_log_blocks(){let mut x=good();x.fresh_log_sha256="c".repeat(64);
  assert!(!assess(&x).unwrap().sandboxed_replay_eligible);}
 #[test]fn changed_zip_blocks(){let mut x=good();x.fresh_zip_sha256="c".repeat(64);
  assert!(!assess(&x).unwrap().sandboxed_replay_eligible);}
 #[test]fn rust_replay_refused(){let mut x=good();x.replay_command_id="rust".into();
  assert!(!assess(&x).unwrap().sandboxed_replay_eligible);}
 #[test]fn network_required_off(){let mut x=good();x.network_disabled=false;
  assert!(!assess(&x).unwrap().sandboxed_replay_eligible);}
 #[test]fn no_source_writes(){let mut x=good();x.source_mount_readonly=false;
  assert!(!assess(&x).unwrap().sandboxed_replay_eligible);}
 #[test]fn source_revision_locked(){let mut x=good();x.source_checkout_sha="d".repeat(40);
  assert!(!assess(&x).unwrap().sandboxed_replay_eligible);}
 #[test]fn fake_external_witness(){let mut x=good();x.external_witness_claim=true;
  assert!(!assess(&x).unwrap().sandboxed_replay_eligible);}
 #[test]fn create_only(){let r=assess(&good()).unwrap();
  let p=std::env::temp_dir().join(format!("sapphon203-{}.json",std::process::id()));
  let _=std::fs::remove_file(&p);write_new(&p,&r).unwrap();
  assert_eq!(write_new(&p,&r).unwrap_err().0,"SANDBOX203_EXISTS");
  std::fs::remove_file(p).unwrap();}
}
