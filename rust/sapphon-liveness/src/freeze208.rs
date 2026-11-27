//! SAPPHON-208 final eight-bound Phase XX source and original-byte freeze.
#![cfg(target_os="linux")]
use crate::Error;
use serde::{Deserialize,Serialize};
use sha2::{Digest,Sha256};
use std::{fs::{File,OpenOptions},io::Write,path::Path};
pub const AUTHORITY:&str="HOLD";
const PATHS:[&str;8]=[
 "rust/sapphon-liveness/src/runner201.rs",
 "rust/sapphon-liveness/src/replay202.rs",
 "rust/sapphon-liveness/src/sandbox203.rs",
 "rust/sapphon-liveness/src/offline204.rs",
 "rust/sapphon-liveness/src/lock205.rs",
 "rust/sapphon-liveness/src/import206.rs",
 "rust/sapphon-liveness/src/vendor207.rs",
 "rust/sapphon-liveness/src/freeze208.rs"];
fn hex64(s:&str)->bool{s.len()==64&&s.bytes().all(|v|v.is_ascii_digit()||(b'a'..=b'f').contains(&v))}
fn sha(b:&[u8])->String{hex::encode(Sha256::digest(b))}
#[derive(Clone,Debug,Serialize,Deserialize,PartialEq,Eq)]
#[serde(deny_unknown_fields)]
pub struct Source{pub bound:u16,pub path:String,pub bytes:u64,pub sha256:String}
#[derive(Clone,Debug,Serialize,Deserialize,PartialEq,Eq)]
#[serde(deny_unknown_fields)]
pub struct Input{
 pub sources:Vec<Source>,pub original_207_run_attempt_matched:bool,
 pub original_207_vendor_bytes_verified:bool,pub original_207_image_bytes_verified:bool,
 pub cargo_lock_sha256:Option<String>,pub vendor_tree_sha256:Option<String>,
 pub vendor_archive_sha256:Option<String>,pub local_image_archive_sha256:Option<String>,
 pub run_source_owned:bool,pub external_witness_claim:bool,
 pub recovery_claim:bool
}
#[derive(Clone,Debug,Serialize,Deserialize,PartialEq,Eq)]
#[serde(deny_unknown_fields)]
pub struct Finding{
 pub schema:String,pub source_design_complete:bool,
 pub vendor_readback_qualified:bool,pub local_image_readback_qualified:bool,
 pub blockers:Vec<String>,pub source_inventory_sha256:String,
 pub independently_authenticated_witnesses:u8,
 pub authenticated_utc:bool,pub global_anti_rollback_authenticated:bool,
 pub recovery_authorized:bool,pub lock_cleared:bool,pub decision:String
}
pub fn assess(x:&Input)->Result<Finding,Error>{
 if x.sources.len()!=8{return Err(Error("FREEZE208_SOURCE_COUNT"));}
 let mut ordered=x.sources.clone();ordered.sort_by_key(|x|x.bound);
 for (index,source) in ordered.iter().enumerate(){
  if source.bound!=201+index as u16||source.path!=PATHS[index]||
    source.bytes==0||!hex64(&source.sha256){
   return Err(Error("FREEZE208_CANONICAL_MODULE"));
  }
 }
 let mut errors=Vec::new();
 let vendor=x.original_207_run_attempt_matched&&x.original_207_vendor_bytes_verified&&
  x.run_source_owned&&x.cargo_lock_sha256.as_deref().is_some_and(hex64)&&
  x.vendor_tree_sha256.as_deref().is_some_and(hex64)&&
  x.vendor_archive_sha256.as_deref().is_some_and(hex64);
 if !vendor{errors.push("ORIGINAL_VENDOR_BYTES_UNVERIFIED".into());}
 let image=vendor&&x.original_207_image_bytes_verified&&
   x.local_image_archive_sha256.as_deref().is_some_and(hex64);
 if !image{errors.push("ORIGINAL_LOCAL_IMAGE_BYTES_UNVERIFIED".into());}
 if x.external_witness_claim||x.recovery_claim{
  errors.push("FALSE_OPERATIONAL_AUTHORITY".into());
 }
 errors.sort();errors.dedup();
 let bytes=serde_json::to_vec(&ordered).map_err(|_|Error("FREEZE208_ENCODING"))?;
 Ok(Finding{schema:"sapphon-208-rust-final-freeze-v1",
  source_design_complete:true,vendor_readback_qualified:vendor,
  local_image_readback_qualified:image,blockers:errors,
  source_inventory_sha256:sha(&bytes),
  independently_authenticated_witnesses:0,authenticated_utc:false,
  global_anti_rollback_authenticated:false,recovery_authorized:false,
  lock_cleared:false,decision:"PHASE_XX_FINAL_FREEZE_HOLD".into()})
}
pub fn write_new(path:&Path,v:&Finding)->Result<String,Error>{
 if v.schema!="sapphon-208-rust-final-freeze-v1"||
 v.decision!="PHASE_XX_FINAL_FREEZE_HOLD"||
 v.independently_authenticated_witnesses!=0||v.authenticated_utc||
 v.global_anti_rollback_authenticated||v.recovery_authorized||v.lock_cleared{
  return Err(Error("FREEZE208_AUTHORITY"));
 }
 let data=serde_json::to_vec(v).map_err(|_|Error("FREEZE208_ENCODING"))?;
 let mut f=OpenOptions::new().create_new(true).write(true).open(path)
  .map_err(|_|Error("FREEZE208_EXISTS"))?;
 f.write_all(&data).map_err(|_|Error("FREEZE208_WRITE"))?;
 f.sync_all().map_err(|_|Error("FREEZE208_SYNC"))?;
 File::open(path.parent().ok_or(Error("FREEZE208_PARENT"))?)
   .and_then(|d|d.sync_all()).map_err(|_|Error("FREEZE208_DIRSYNC"))?;
 Ok(sha(&data))
}
#[cfg(test)]
mod tests{
 use super::*;
 fn input()->Input{Input{
  sources:PATHS.iter().enumerate().map(|(i,p)|Source{
   bound:201+i as u16,path:(*p).into(),bytes:500,sha256:"a".repeat(64)}).collect(),
  original_207_run_attempt_matched:false,original_207_vendor_bytes_verified:false,
  original_207_image_bytes_verified:false,cargo_lock_sha256:None,
  vendor_tree_sha256:None,vendor_archive_sha256:None,
  local_image_archive_sha256:None,run_source_owned:true,
  external_witness_claim:false,recovery_claim:false}}
 #[test]fn source_complete_evidence_hold(){let x=assess(&input()).unwrap();
  assert!(x.source_design_complete&&!x.vendor_readback_qualified&&!x.recovery_authorized);}
 #[test]fn missing_source_rejected(){let mut x=input();x.sources.pop();
  assert_eq!(assess(&x).unwrap_err().0,"FREEZE208_SOURCE_COUNT");}
 #[test]fn forged_source_path_rejected(){let mut x=input();x.sources[0].path="fake.rs".into();
  assert_eq!(assess(&x).unwrap_err().0,"FREEZE208_CANONICAL_MODULE");}
 #[test]fn invalid_hash_rejected(){let mut x=input();x.sources[7].sha256="bad".into();
  assert_eq!(assess(&x).unwrap_err().0,"FREEZE208_CANONICAL_MODULE");}
 #[test]fn vendor_without_image_not_image(){let mut x=input();
  x.original_207_run_attempt_matched=true;x.original_207_vendor_bytes_verified=true;
  x.cargo_lock_sha256=Some("a".repeat(64));
  x.vendor_tree_sha256=Some("b".repeat(64));x.vendor_archive_sha256=Some("c".repeat(64));
  let f=assess(&x).unwrap();assert!(f.vendor_readback_qualified&&!f.local_image_readback_qualified);}
 #[test]fn locally_qualified_still_hold(){let mut x=input();
  x.original_207_run_attempt_matched=true;x.original_207_vendor_bytes_verified=true;
  x.original_207_image_bytes_verified=true;
  x.cargo_lock_sha256=Some("a".repeat(64));
  x.vendor_tree_sha256=Some("b".repeat(64));x.vendor_archive_sha256=Some("c".repeat(64));
  x.local_image_archive_sha256=Some("d".repeat(64));
  let f=assess(&x).unwrap();assert!(f.local_image_readback_qualified&&!f.recovery_authorized);}
 #[test]fn claimed_external_witness_not_promotion(){let mut x=input();x.external_witness_claim=true;
  let f=assess(&x).unwrap();assert!(!f.recovery_authorized);}
 #[test]fn create_only(){let f=assess(&input()).unwrap();
  let p=std::env::temp_dir().join(format!("sapphon208-{}.json",std::process::id()));
  let _=std::fs::remove_file(&p);write_new(&p,&f).unwrap();
  assert_eq!(write_new(&p,&f).unwrap_err().0,"FREEZE208_EXISTS");
  std::fs::remove_file(p).unwrap();}
}
