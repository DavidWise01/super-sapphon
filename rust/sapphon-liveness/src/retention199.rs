//! SAPPHON-199: immutable parent replay and bounded retention-pressure evidence.
#![cfg(target_os="linux")]
use crate::Error;
use serde::{Deserialize,Serialize};
use sha2::{Digest,Sha256};
use std::{fs::{File,OpenOptions},io::Write,path::Path};
pub const AUTHORITY:&str="HOLD";
const SOURCE:&str="16aebb4fc9551e505ec7f461b7db05db6f340d86";
fn valid(s:&str)->bool{s.len()==64&&s.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b))}
fn hash(x:&[u8])->String{hex::encode(Sha256::digest(x))}
#[derive(Clone,Debug,Serialize,Deserialize,PartialEq,Eq)]
#[serde(deny_unknown_fields)]
pub struct Input{
 pub source_sha:String,pub run_id:Option<u64>,pub attempt:Option<u32>,
 pub original_archive_observed:bool,pub original_archive_sha256:Option<String>,
 pub parent_tip_claim:Option<String>,pub parent_tip_recomputed:Option<String>,
 pub appended_parent_tip:Option<String>,pub prior_entries:u64,pub new_entries:u64,
 pub inherited_fork_count:u32,pub current_fork_count:u32,
 pub immutable_prefix_preserved:bool,pub artifact_expired_metadata:bool,
 pub deletion_endpoint_confirmed:bool,pub global_anti_rollback_claim:bool,
 pub external_authority_claim:bool
}
#[derive(Clone,Debug,Serialize,Deserialize,PartialEq,Eq)]
#[serde(deny_unknown_fields)]
pub struct Finding{
 pub schema:String,pub input_sha256:String,pub parent_replay_qualified:bool,
 pub blockers:Vec<String>,pub inherited_fork_count:u32,pub current_fork_count:u32,
 pub deletion_proven:bool,pub independent_witnesses:u8,pub authenticated_utc:bool,
 pub global_anti_rollback_authenticated:bool,pub recovery_authorized:bool,
 pub lock_cleared:bool,pub decision:String
}
pub fn assess(x:&Input)->Result<Finding,Error>{
 let mut bad=Vec::new();
 if x.source_sha!=SOURCE||x.run_id.is_none_or(|v|v==0)||x.attempt.is_none_or(|v|v==0){
  bad.push("RUN_OR_SOURCE_CONFLICT".to_string());
 }
 if !x.original_archive_observed||x.original_archive_sha256.as_deref().is_none_or(|s|!valid(s)){
  bad.push("ORIGINAL_ARCHIVE_NOT_OBSERVED".into());
 }
 if x.parent_tip_claim.as_deref().is_none_or(|v|!valid(v))||
    x.parent_tip_claim!=x.parent_tip_recomputed||x.parent_tip_claim!=x.appended_parent_tip{
  bad.push("PARENT_TIP_CONFLICT".into());
 }
 if !x.immutable_prefix_preserved||x.new_entries!=x.prior_entries.saturating_add(1){
  bad.push("HISTORY_NOT_APPEND_ONLY".into());
 }
 if x.current_fork_count<x.inherited_fork_count{bad.push("INHERITED_FORK_ERASED".into());}
 if x.artifact_expired_metadata && x.original_archive_observed{
  bad.push("EXPIRED_METADATA_CONFLICT".into());
 }
 if x.global_anti_rollback_claim||x.external_authority_claim{
  bad.push("UNSUPPORTED_OPERATIONAL_AUTHORITY".into());
 }
 bad.sort();bad.dedup();
 let data=serde_json::to_vec(x).map_err(|_|Error("RETENTION199_ENCODING"))?;
 // Even a separately confirmed deletion endpoint is not an independent witness.
 Ok(Finding{schema:"sapphon-199-rust-retention-v1".into(),
  input_sha256:hash(&data),parent_replay_qualified:bad.is_empty(),
  blockers:bad,inherited_fork_count:x.inherited_fork_count,
  current_fork_count:x.current_fork_count,
  deletion_proven:x.deletion_endpoint_confirmed,
  independent_witnesses:0,authenticated_utc:false,
  global_anti_rollback_authenticated:false,
  recovery_authorized:false,lock_cleared:false,
  decision:"PARENT_RETENTION_PRESSURE_HOLD".into()})
}
pub fn write_new(path:&Path,r:&Finding)->Result<String,Error>{
 if r.schema!="sapphon-199-rust-retention-v1"||
    r.decision!="PARENT_RETENTION_PRESSURE_HOLD"||
    r.independent_witnesses!=0||r.authenticated_utc||
    r.global_anti_rollback_authenticated||r.recovery_authorized||r.lock_cleared{
   return Err(Error("RETENTION199_AUTHORITY"));
 }
 let bytes=serde_json::to_vec(r).map_err(|_|Error("RETENTION199_ENCODING"))?;
 let mut f=OpenOptions::new().create_new(true).write(true).open(path)
  .map_err(|_|Error("RETENTION199_EXISTS"))?;
 f.write_all(&bytes).map_err(|_|Error("RETENTION199_WRITE"))?;
 f.sync_all().map_err(|_|Error("RETENTION199_SYNC"))?;
 File::open(path.parent().ok_or(Error("RETENTION199_PARENT"))?)
  .and_then(|d|d.sync_all()).map_err(|_|Error("RETENTION199_DIRSYNC"))?;
 Ok(hash(&bytes))
}
#[cfg(test)]
mod tests{
 use super::*;
 fn good()->Input{Input{source_sha:SOURCE.into(),run_id:Some(198),attempt:Some(2),
  original_archive_observed:true,original_archive_sha256:Some("a".repeat(64)),
  parent_tip_claim:Some("b".repeat(64)),parent_tip_recomputed:Some("b".repeat(64)),
  appended_parent_tip:Some("b".repeat(64)),prior_entries:2,new_entries:3,
  inherited_fork_count:0,current_fork_count:0,
  immutable_prefix_preserved:true,artifact_expired_metadata:false,
  deletion_endpoint_confirmed:false,global_anti_rollback_claim:false,
  external_authority_claim:false}}
 #[test]fn original_source_parity_is_hold(){let f=assess(&good()).unwrap();
  assert!(f.parent_replay_qualified&&!f.recovery_authorized);}
 #[test]fn missing_archive_rejected(){let mut x=good();x.original_archive_observed=false;
  assert!(!assess(&x).unwrap().parent_replay_qualified);}
 #[test]fn wrong_parent_denied(){let mut x=good();x.parent_tip_recomputed=Some("c".repeat(64));
  assert!(!assess(&x).unwrap().parent_replay_qualified);}
 #[test]fn discarded_prefix_denied(){let mut x=good();x.immutable_prefix_preserved=false;
  assert!(!assess(&x).unwrap().parent_replay_qualified);}
 #[test]fn fork_erasure_denied(){let mut x=good();x.inherited_fork_count=2;
  assert!(!assess(&x).unwrap().parent_replay_qualified);}
 #[test]fn expired_does_not_prove_deletion(){let mut x=good();x.artifact_expired_metadata=true;
  let f=assess(&x).unwrap();assert!(!f.deletion_proven);}
 #[test]fn authority_claim_denied(){let mut x=good();x.global_anti_rollback_claim=true;
  assert!(!assess(&x).unwrap().parent_replay_qualified);}
 #[test]fn create_only(){let r=assess(&good()).unwrap();
  let p=std::env::temp_dir().join(format!("sapphon199-{}.json",std::process::id()));
  let _=std::fs::remove_file(&p);write_new(&p,&r).unwrap();
  assert_eq!(write_new(&p,&r).unwrap_err().0,"RETENTION199_EXISTS");
  std::fs::remove_file(p).unwrap();}
}
