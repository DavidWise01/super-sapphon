//! SAPPHON-192: final Phase XVIII eight canonical Rust source modules.
#![cfg(target_os="linux")]
use crate::Error;
use serde::{Deserialize,Serialize};
use sha2::{Digest,Sha256};
use std::{fs::{File,OpenOptions},io::Write,path::Path};
pub const AUTHORITY:&str="HOLD";
const PATHS:[&str;8]=[
 "rust/sapphon-liveness/src/observed185.rs",
 "rust/sapphon-liveness/src/attempts186.rs",
 "rust/sapphon-liveness/src/retention187.rs",
 "rust/sapphon-liveness/src/continuity188.rs",
 "rust/sapphon-liveness/src/forks189.rs",
 "rust/sapphon-liveness/src/custody190.rs",
 "rust/sapphon-liveness/src/challenge191.rs",
 "rust/sapphon-liveness/src/freeze192.rs"];
fn hex40(s:&str)->bool{s.len()==40&&s.bytes().all(|c|c.is_ascii_digit()||(b'a'..=b'f').contains(&c))}
fn hex64(s:&str)->bool{s.len()==64&&s.bytes().all(|c|c.is_ascii_digit()||(b'a'..=b'f').contains(&c))}
fn digest(bytes:&[u8])->String{hex::encode(Sha256::digest(bytes))}
#[derive(Debug,Clone,Serialize,Deserialize,PartialEq,Eq)]
#[serde(deny_unknown_fields)]
pub struct Source{pub bound:u16,pub path:String,pub bytes:u64,pub sha256:String}
#[derive(Debug,Clone,Serialize,Deserialize,PartialEq,Eq)]
#[serde(deny_unknown_fields)]
pub struct Input{
 pub head:String,pub sources:Vec<Source>,
 pub python:String,pub rust:String,pub historical_188:String,
 pub predecessor_readback:String,pub pages:String,
 pub independently_enrolled_keys:u8,pub external_challenges_observed:bool,
 pub unsupported_recovery_claim:bool
}
#[derive(Debug,Clone,Serialize,Deserialize,PartialEq,Eq)]
#[serde(deny_unknown_fields)]
pub struct Finding{
 pub schema:String,pub phase:u8,pub source_design_complete:bool,
 pub inventory_sha256:String,pub blockers:Vec<String>,
 pub independent_witnesses:u8,pub authenticated_utc:bool,
 pub global_anti_rollback_authenticated:bool,pub npm_integrity_qualified:bool,
 pub recovery_authorized:bool,pub lock_cleared:bool,pub decision:String
}
pub fn assess(v:&Input)->Result<Finding,Error>{
 if !hex40(&v.head)||v.sources.len()!=8{return Err(Error("FREEZE192_HEAD_OR_COUNT"));}
 let mut files=v.sources.clone();files.sort_by_key(|f|f.bound);
 for (idx,f) in files.iter().enumerate(){
  if f.bound!=185+idx as u16||f.path!=PATHS[idx]||
     f.bytes==0||!hex64(&f.sha256){
   return Err(Error("FREEZE192_CANONICAL_SOURCE"));
  }
 }
 for outcome in [&v.python,&v.rust,&v.historical_188,&v.predecessor_readback,&v.pages]{
  if !["success","failure","cancelled","timed_out","skipped","not_observed"]
    .contains(&outcome.as_str()){return Err(Error("FREEZE192_OUTCOME"));}
 }
 let mut bad=Vec::new();
 for (name,state) in [("PYTHON",&v.python),("RUST",&v.rust),
  ("FROZEN",&v.historical_188),("PREDECESSOR",&v.predecessor_readback),("PAGES",&v.pages)]{
  if state!="success"{bad.push(format!("{name}:{state}"));}
 }
 if v.independently_enrolled_keys!=0||v.external_challenges_observed||
    v.unsupported_recovery_claim{
  bad.push("UNSUPPORTED_EXTERNAL_AUTHORITY".into());
 }
 bad.push("OWNED_SOURCE_NOT_INDEPENDENT_CUSTODY".into());
 bad.sort();bad.dedup();
 let bytes=serde_json::to_vec(&files).map_err(|_|Error("FREEZE192_ENCODING"))?;
 Ok(Finding{schema:"sapphon-192-rust-final-freeze-v1".into(),
  phase:18,source_design_complete:true,inventory_sha256:digest(&bytes),
  blockers:bad,independent_witnesses:0,authenticated_utc:false,
  global_anti_rollback_authenticated:false,npm_integrity_qualified:false,
  recovery_authorized:false,lock_cleared:false,
  decision:"PHASE_XVIII_FINAL_SOURCE_FREEZE_HOLD".into()})
}
pub fn write_new(path:&Path,f:&Finding)->Result<String,Error>{
 if f.schema!="sapphon-192-rust-final-freeze-v1"||f.phase!=18||
    f.decision!="PHASE_XVIII_FINAL_SOURCE_FREEZE_HOLD"||
    f.independent_witnesses!=0||f.authenticated_utc||
    f.global_anti_rollback_authenticated||f.npm_integrity_qualified||
    f.recovery_authorized||f.lock_cleared{
  return Err(Error("FREEZE192_AUTHORITY"));
 }
 let bytes=serde_json::to_vec(f).map_err(|_|Error("FREEZE192_ENCODING"))?;
 let mut file=OpenOptions::new().create_new(true).write(true).open(path)
  .map_err(|_|Error("FREEZE192_EXISTS"))?;
 file.write_all(&bytes).map_err(|_|Error("FREEZE192_WRITE"))?;
 file.sync_all().map_err(|_|Error("FREEZE192_SYNC"))?;
 File::open(path.parent().ok_or(Error("FREEZE192_PARENT"))?)
  .and_then(|d|d.sync_all()).map_err(|_|Error("FREEZE192_DIRSYNC"))?;
 Ok(digest(&bytes))
}
#[cfg(test)]
mod tests{
 use super::*;
 fn valid()->Input{Input{head:"a".repeat(40),
  sources:PATHS.iter().enumerate().map(|(i,p)|Source{
   bound:185+i as u16,path:(*p).into(),bytes:100,sha256:"b".repeat(64)}).collect(),
  python:"not_observed".into(),rust:"not_observed".into(),
  historical_188:"not_observed".into(),predecessor_readback:"not_observed".into(),
  pages:"not_observed".into(),independently_enrolled_keys:0,
  external_challenges_observed:false,unsupported_recovery_claim:false}}
 #[test]fn eight_modules_still_hold(){let f=assess(&valid()).unwrap();
  assert!(f.source_design_complete&&!f.recovery_authorized);}
 #[test]fn substituted_source_rejected(){let mut v=valid();v.sources[3].path="other".into();
  assert_eq!(assess(&v).unwrap_err().0,"FREEZE192_CANONICAL_SOURCE");}
 #[test]fn truncated_digest_rejected(){let mut v=valid();v.sources[6].sha256="abc".into();
  assert_eq!(assess(&v).unwrap_err().0,"FREEZE192_CANONICAL_SOURCE");}
 #[test]fn missing_source_rejected(){let mut v=valid();v.sources.pop();
  assert_eq!(assess(&v).unwrap_err().0,"FREEZE192_HEAD_OR_COUNT");}
 #[test]fn malformed_outcome_rejected(){let mut v=valid();v.rust="PASS_CLAIM".into();
  assert_eq!(assess(&v).unwrap_err().0,"FREEZE192_OUTCOME");}
 #[test]fn green_source_checks_not_custody(){let mut v=valid();
  v.python="success".into();v.rust="success".into();v.historical_188="success".into();
  let f=assess(&v).unwrap();assert!(!f.recovery_authorized);}
 #[test]fn forged_enrollment_denied(){let mut v=valid();v.independently_enrolled_keys=1;
  assert!(assess(&v).unwrap().blockers.iter().any(|x|x=="UNSUPPORTED_EXTERNAL_AUTHORITY"));}
 #[test]fn create_only(){let f=assess(&valid()).unwrap();
  let p=std::env::temp_dir().join(format!("sapphon192-{}.json",std::process::id()));
  let _=std::fs::remove_file(&p);write_new(&p,&f).unwrap();
  assert_eq!(write_new(&p,&f).unwrap_err().0,"FREEZE192_EXISTS");
  std::fs::remove_file(p).unwrap();}
}
