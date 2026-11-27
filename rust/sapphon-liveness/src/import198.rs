//! SAPPHON-198: exact prior tip ancestry gate; prior freeze is immutable.
#![cfg(target_os="linux")]
use crate::Error;
use serde::{Deserialize,Serialize};
use sha2::{Digest,Sha256};
use std::{fs::{File,OpenOptions},io::Write,path::Path};
pub const AUTHORITY:&str="HOLD";
const SOURCE:&str="9bddb4491893ee121f71821b61692685508adae6";
fn hex64(x:&str)->bool{x.len()==64&&x.bytes().all(|c|c.is_ascii_digit()||(b'a'..=b'f').contains(&c))}
fn digest(b:&[u8])->String{hex::encode(Sha256::digest(b))}
#[derive(Clone,Debug,Serialize,Deserialize,PartialEq,Eq)]
#[serde(deny_unknown_fields)]
pub struct Import{
 pub source_sha:String,pub prior_run_id:u64,pub prior_attempt:u32,
 pub prior_entries:u64,pub prior_tip_sha256:String,
 pub independently_recomputed_tip_sha256:String,
 pub artifact_zip_sha256:String,pub source_owned_original_archive_verified:bool,
 pub observed_inherited_forks:u32,pub observed_new_forks:u32,
 pub historical_record_bytes_unchanged:bool,pub proposed_parent_tip_sha256:String,
 pub external_custody_claim:bool
}
#[derive(Clone,Debug,Serialize,Deserialize,PartialEq,Eq)]
#[serde(deny_unknown_fields)]
pub struct Finding{
 pub schema:String,pub input_sha256:String,pub accepted_source_owned_parent:bool,
 pub blockers:Vec<String>,pub inherited_forks:u32,pub total_forks:u32,
 pub independent_witnesses:u8,pub authenticated_utc:bool,
 pub global_anti_rollback_authenticated:bool,pub recovery_authorized:bool,
 pub lock_cleared:bool,pub decision:String
}
pub fn assess(x:&Import)->Result<Finding,Error>{
 let mut bad=Vec::new();
 if x.source_sha!=SOURCE||x.prior_run_id==0||x.prior_attempt==0{
  bad.push("SOURCE_IDENTITY".into());
 }
 if !x.source_owned_original_archive_verified||!hex64(&x.artifact_zip_sha256){
  bad.push("ORIGINAL_ARCHIVE_NOT_VERIFIED".into());
 }
 if !hex64(&x.prior_tip_sha256)||x.prior_tip_sha256!=x.independently_recomputed_tip_sha256{
  bad.push("PRIOR_TIP_CONFLICT".into());
 }
 if x.prior_tip_sha256!=x.proposed_parent_tip_sha256{
  bad.push("NONMONOTONIC_PARENT".into());
 }
 if !x.historical_record_bytes_unchanged{
  bad.push("PREDECESSOR_MUTATED".into());
 }
 if x.external_custody_claim{
  bad.push("UNSUPPORTED_EXTERNAL_AUTHORITY".into());
 }
 let total=x.observed_inherited_forks.checked_add(x.observed_new_forks)
  .ok_or(Error("IMPORT198_FORK_OVERFLOW"))?;
 bad.sort();bad.dedup();
 let bytes=serde_json::to_vec(x).map_err(|_|Error("IMPORT198_JSON"))?;
 Ok(Finding{schema:"sapphon-198-rust-tip-inheritance-v1".into(),
  input_sha256:digest(&bytes),accepted_source_owned_parent:bad.is_empty(),
  blockers:bad,inherited_forks:x.observed_inherited_forks,total_forks:total,
  independent_witnesses:0,authenticated_utc:false,
  global_anti_rollback_authenticated:false,recovery_authorized:false,
  lock_cleared:false,decision:"CROSS_RUN_LEDGER_TIP_HOLD".into()})
}
pub fn write_new(path:&Path,r:&Finding)->Result<String,Error>{
 if r.schema!="sapphon-198-rust-tip-inheritance-v1"||
    r.decision!="CROSS_RUN_LEDGER_TIP_HOLD"||
    r.independent_witnesses!=0||r.authenticated_utc||
    r.global_anti_rollback_authenticated||r.recovery_authorized||r.lock_cleared{
  return Err(Error("IMPORT198_AUTHORITY"));
 }
 let data=serde_json::to_vec(r).map_err(|_|Error("IMPORT198_JSON"))?;
 let mut f=OpenOptions::new().write(true).create_new(true).open(path)
  .map_err(|_|Error("IMPORT198_EXISTS"))?;
 f.write_all(&data).map_err(|_|Error("IMPORT198_WRITE"))?;
 f.sync_all().map_err(|_|Error("IMPORT198_SYNC"))?;
 File::open(path.parent().ok_or(Error("IMPORT198_PARENT"))?)
  .and_then(|p|p.sync_all()).map_err(|_|Error("IMPORT198_DIRSYNC"))?;
 Ok(digest(&data))
}
#[cfg(test)]
mod tests{
 use super::*;
 fn sample()->Import{Import{source_sha:SOURCE.into(),prior_run_id:197,prior_attempt:1,
  prior_entries:2,prior_tip_sha256:"a".repeat(64),
  independently_recomputed_tip_sha256:"a".repeat(64),
  artifact_zip_sha256:"b".repeat(64),source_owned_original_archive_verified:true,
  observed_inherited_forks:0,observed_new_forks:0,
  historical_record_bytes_unchanged:true,proposed_parent_tip_sha256:"a".repeat(64),
  external_custody_claim:false}}
 #[test]fn tip_matched_only_owned(){let r=assess(&sample()).unwrap();
  assert!(r.accepted_source_owned_parent&&!r.recovery_authorized);}
 #[test]fn absent_archive_denied(){let mut v=sample();v.source_owned_original_archive_verified=false;
  assert!(!assess(&v).unwrap().accepted_source_owned_parent);}
 #[test]fn forged_tip_denied(){let mut v=sample();v.independently_recomputed_tip_sha256="c".repeat(64);
  assert!(!assess(&v).unwrap().accepted_source_owned_parent);}
 #[test]fn wrong_parent_denied(){let mut v=sample();v.proposed_parent_tip_sha256="c".repeat(64);
  assert!(!assess(&v).unwrap().accepted_source_owned_parent);}
 #[test]fn historical_mutation_denied(){let mut v=sample();v.historical_record_bytes_unchanged=false;
  assert!(!assess(&v).unwrap().accepted_source_owned_parent);}
 #[test]fn forks_retained(){let mut v=sample();v.observed_inherited_forks=2;v.observed_new_forks=1;
  let r=assess(&v).unwrap();assert_eq!(r.inherited_forks,2);assert_eq!(r.total_forks,3);}
 #[test]fn external_custody_refused(){let mut v=sample();v.external_custody_claim=true;
  assert!(!assess(&v).unwrap().accepted_source_owned_parent);}
 #[test]fn create_only(){let r=assess(&sample()).unwrap();
  let p=std::env::temp_dir().join(format!("sapphon198-{}.json",std::process::id()));
  let _=std::fs::remove_file(&p);write_new(&p,&r).unwrap();
  assert_eq!(write_new(&p,&r).unwrap_err().0,"IMPORT198_EXISTS");
  std::fs::remove_file(p).unwrap();}
}
