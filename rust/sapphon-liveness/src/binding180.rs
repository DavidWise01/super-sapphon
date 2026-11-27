//! SAPPHON-180: raw log and artifact ZIP byte binding, no actuation.
#![cfg(target_os="linux")]
use crate::Error;
use serde::{Deserialize,Serialize};
use sha2::{Digest,Sha256};
use std::{fs::{File,OpenOptions},io::Write,path::Path};
pub const AUTHORITY:&str="HOLD";
const SOURCE:&str="d07203a254678fdf7df05a75c1d144c7a8337f87";
fn hash(b:&[u8])->String{hex::encode(Sha256::digest(b))}
fn valid(s:&str)->bool{s.len()==64&&s.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b))}
#[derive(Debug,Clone,Serialize,Deserialize,PartialEq,Eq)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
 pub source_sha:String,pub workflow:String,pub job_name:String,
 pub run_id:u64,pub attempt:u32,pub job_id:u64,pub artifact_id:u64,
 pub artifact_name:String,pub run_status:String,pub run_conclusion:String,
 pub job_conclusion:String,pub artifact_expired:bool,
 pub log_kind:String,pub artifact_kind:String,
 pub log_sha256:String,pub artifact_sha256:String,
 pub unsupported_authority_claim:bool
}
#[derive(Debug,Clone,Serialize,Deserialize,PartialEq,Eq)]
#[serde(deny_unknown_fields)]
pub struct Finding {
 pub schema:String,pub raw_log_sha256:String,pub artifact_zip_sha256:String,
 pub source_owned_binding_consistent:bool,pub blockers:Vec<String>,
 pub external_metadata_authenticated:bool,pub independent_custody:bool,
 pub recovery_authorized:bool,pub lock_cleared:bool,pub decision:String
}
pub fn bind(m:&Manifest,raw:&[u8],zip:&[u8])->Result<Finding,Error>{
 if raw.len()>8*1024*1024||zip.len()>64*1024*1024{
  return Err(Error("BIND180_SIZE"));
 }
 let mut bad=Vec::new();let raw_hash=hash(raw);let zip_hash=hash(zip);
 if m.source_sha!=SOURCE||m.workflow!="sapphon-179-replay.yml"
   ||m.job_name!="replay-diagnostics"{bad.push("ANCESTRY".into());}
 if m.run_id==0||m.attempt==0||m.job_id==0||m.artifact_id==0{
  bad.push("RUN_IDENTITY".into());
 }
 if m.artifact_name!="sapphon-179-provenance-replay"||m.artifact_expired{
  bad.push("ARTIFACT_IDENTITY".into());
 }
 if m.run_status!="completed"||!["failure","success"].contains(&m.run_conclusion.as_str())
   ||!["failure","success"].contains(&m.job_conclusion.as_str()){
  bad.push("INCOMPLETE_RUN".into());
 }
 if m.run_conclusion=="success"&&m.job_conclusion=="failure"{
  bad.push("PARENT_JOB_CONTRADICTION".into());
 }
 if m.log_kind!="RAW_JOB_LOG"||m.artifact_kind!="ORIGINAL_ZIP"{
  bad.push("ALTERED_KIND".into());
 }
 if raw.is_empty()||zip.is_empty(){bad.push("MISSING_BYTES".into());}
 if !valid(&m.log_sha256)||m.log_sha256!=raw_hash{bad.push("LOG_DIGEST".into());}
 if !valid(&m.artifact_sha256)||m.artifact_sha256!=zip_hash{
  bad.push("ARTIFACT_DIGEST".into());
 }
 if m.unsupported_authority_claim{bad.push("AUTHORITY".into());}
 bad.sort();bad.dedup();
 Ok(Finding{schema:"sapphon-180-rust-raw-binding-v1".into(),
  raw_log_sha256:raw_hash,artifact_zip_sha256:zip_hash,
  source_owned_binding_consistent:bad.is_empty(),blockers:bad,
  external_metadata_authenticated:false,independent_custody:false,
  recovery_authorized:false,lock_cleared:false,decision:"RAW_EVIDENCE_BINDING_HOLD".into()})
}
pub fn write_new(path:&Path,f:&Finding)->Result<String,Error>{
 if f.schema!="sapphon-180-rust-raw-binding-v1"||f.decision!="RAW_EVIDENCE_BINDING_HOLD"
   ||f.external_metadata_authenticated||f.independent_custody
   ||f.recovery_authorized||f.lock_cleared{return Err(Error("BIND180_AUTHORITY"));}
 let bytes=serde_json::to_vec(f).map_err(|_|Error("BIND180_ENCODING"))?;
 let mut file=OpenOptions::new().write(true).create_new(true).open(path)
   .map_err(|_|Error("BIND180_EXISTS"))?;
 file.write_all(&bytes).map_err(|_|Error("BIND180_WRITE"))?;
 file.sync_all().map_err(|_|Error("BIND180_SYNC"))?;
 File::open(path.parent().ok_or(Error("BIND180_PARENT"))?)
   .and_then(|d|d.sync_all()).map_err(|_|Error("BIND180_DIRSYNC"))?;
 Ok(hash(&bytes))
}
#[cfg(test)]
mod tests{
 use super::*;
 fn good()->Manifest{let l=b"raw";let z=b"zip";
  Manifest{source_sha:SOURCE.into(),workflow:"sapphon-179-replay.yml".into(),
   job_name:"replay-diagnostics".into(),run_id:179,attempt:1,job_id:9,artifact_id:8,
   artifact_name:"sapphon-179-provenance-replay".into(),run_status:"completed".into(),
   run_conclusion:"failure".into(),job_conclusion:"failure".into(),
   artifact_expired:false,log_kind:"RAW_JOB_LOG".into(),
   artifact_kind:"ORIGINAL_ZIP".into(),log_sha256:hash(l),artifact_sha256:hash(z),
   unsupported_authority_claim:false}}
 #[test]fn matching_bytes_still_hold(){let f=bind(&good(),b"raw",b"zip").unwrap();
  assert!(f.source_owned_binding_consistent&&!f.recovery_authorized);}
 #[test]fn altered_log_rejected(){let f=bind(&good(),b"raw!",b"zip").unwrap();
  assert!(f.blockers.contains(&"LOG_DIGEST".into()));}
 #[test]fn altered_zip_rejected(){let f=bind(&good(),b"raw",b"zip!").unwrap();
  assert!(f.blockers.contains(&"ARTIFACT_DIGEST".into()));}
 #[test]fn wrong_run_rejected(){let mut m=good();m.attempt=0;
  assert!(!bind(&m,b"raw",b"zip").unwrap().source_owned_binding_consistent);}
 #[test]fn excerpt_rejected(){let mut m=good();m.log_kind="REDACTED_EXCERPT".into();
  assert!(!bind(&m,b"raw",b"zip").unwrap().source_owned_binding_consistent);}
 #[test]fn create_only(){let f=bind(&good(),b"raw",b"zip").unwrap();
  let p=std::env::temp_dir().join(format!("sapphon180-{}.json",std::process::id()));
  let _=std::fs::remove_file(&p);write_new(&p,&f).unwrap();
  assert_eq!(write_new(&p,&f).unwrap_err().0,"BIND180_EXISTS");
  std::fs::remove_file(p).unwrap();}
}
