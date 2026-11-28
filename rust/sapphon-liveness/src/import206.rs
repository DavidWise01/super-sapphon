//! SAPPHON-206 exact original lockfile import; image/vendor gap stays HOLD.
#![cfg(target_os="linux")]
use crate::Error;
use serde::{Deserialize,Serialize};
use sha2::{Digest,Sha256};
use std::{fs::{File,OpenOptions},io::Write,path::Path};
pub const AUTHORITY:&str="HOLD";
const SOURCE:&str="a73488b1cbfa353d7a2e0d0bd762f7402f7117ee";
fn hex64(s:&str)->bool{s.len()==64&&s.bytes().all(|v|v.is_ascii_digit()||(b'a'..=b'f').contains(&v))}
fn digest(raw:&[u8])->String{hex::encode(Sha256::digest(raw))}
#[derive(Clone,Debug,Serialize,Deserialize,PartialEq,Eq)]
#[serde(deny_unknown_fields)]
pub struct Input{
 pub source_sha:String,pub original_run_id:u64,pub original_attempt:u32,
 pub exact_artifact_observed:bool,pub archive_run_attempt_matched:bool,
 pub cargo_lock_sha256:Option<String>,pub reported_lock_sha256:Option<String>,
 pub summary_lock_sha256:Option<String>,
 pub original_vendor_bytes_observed:bool,pub vendor_sha256:Option<String>,
 pub original_image_digest_verified:bool,
 pub external_custody_claim:bool,pub recovery_claim:bool
}
#[derive(Clone,Debug,Serialize,Deserialize,PartialEq,Eq)]
#[serde(deny_unknown_fields)]
pub struct Finding{
 pub schema:String,pub original_lock_bytes_consistent:bool,
 pub offline_image_qualified:bool,pub source_promotable:bool,
 pub blockers:Vec<String>,pub input_sha256:String,
 pub independent_witnesses:u8,pub authenticated_utc:bool,
 pub global_anti_rollback_authenticated:bool,pub recovery_authorized:bool,
 pub lock_cleared:bool,pub decision:String
}
pub fn assess(x:&Input)->Result<Finding,Error>{
 let mut bad=Vec::new();
 if x.source_sha!=SOURCE||x.original_run_id==0||x.original_attempt==0{
  bad.push("EXACT_RUN_ANCESTRY".into());
 }
 if !x.exact_artifact_observed||!x.archive_run_attempt_matched{
  bad.push("ORIGINAL_ARTIFACT_UNOBSERVED".into());
 }
 let matched=x.cargo_lock_sha256.as_deref().is_some_and(hex64)&&
  x.cargo_lock_sha256==x.reported_lock_sha256&&
  x.cargo_lock_sha256==x.summary_lock_sha256;
 if !matched{bad.push("CARGO_LOCK_BYTE_FORK_OR_MISSING".into());}
 if !x.original_vendor_bytes_observed||!x.vendor_sha256.as_deref().is_some_and(hex64){
  bad.push("ORIGINAL_VENDOR_BYTES_NOT_OBSERVED".into());
 }
 if !x.original_image_digest_verified{
  bad.push("IMMUTABLE_OFFLINE_IMAGE_NOT_VERIFIED".into());
 }
 if x.external_custody_claim||x.recovery_claim{bad.push("FALSE_AUTHORITY_CLAIM".into());}
 bad.sort();bad.dedup();
 let bytes=serde_json::to_vec(x).map_err(|_|Error("IMPORT206_ENCODING"))?;
 Ok(Finding{schema:"sapphon-206-rust-lock-import-v1".into(),
  original_lock_bytes_consistent:matched&&x.exact_artifact_observed&&
   x.archive_run_attempt_matched&&x.source_sha==SOURCE,
  offline_image_qualified:bad.is_empty(),
  source_promotable:matched&&x.exact_artifact_observed&&x.archive_run_attempt_matched&&x.source_sha==SOURCE,
  blockers:bad,input_sha256:digest(&bytes),independent_witnesses:0,
  authenticated_utc:false,global_anti_rollback_authenticated:false,
  recovery_authorized:false,lock_cleared:false,
  decision:"PHASE_XX_LOCK_IMPORT_HOLD".into()})
}
pub fn write_new(path:&Path,r:&Finding)->Result<String,Error>{
 if r.schema!="sapphon-206-rust-lock-import-v1"||
 r.decision!="PHASE_XX_LOCK_IMPORT_HOLD"||r.independent_witnesses!=0||
 r.authenticated_utc||r.global_anti_rollback_authenticated||
 r.recovery_authorized||r.lock_cleared{return Err(Error("IMPORT206_AUTHORITY"));}
 let data=serde_json::to_vec(r).map_err(|_|Error("IMPORT206_ENCODING"))?;
 let mut f=OpenOptions::new().write(true).create_new(true).open(path)
  .map_err(|_|Error("IMPORT206_EXISTS"))?;
 f.write_all(&data).map_err(|_|Error("IMPORT206_WRITE"))?;
 f.sync_all().map_err(|_|Error("IMPORT206_SYNC"))?;
 File::open(path.parent().ok_or(Error("IMPORT206_PARENT"))?)
  .and_then(|f|f.sync_all()).map_err(|_|Error("IMPORT206_DIRSYNC"))?;
 Ok(digest(&data))
}
#[cfg(test)]
mod tests{
 use super::*;
 fn good()->Input{Input{source_sha:SOURCE.into(),original_run_id:205,
 original_attempt:2,exact_artifact_observed:true,archive_run_attempt_matched:true,
 cargo_lock_sha256:Some("a".repeat(64)),reported_lock_sha256:Some("a".repeat(64)),
 summary_lock_sha256:Some("a".repeat(64)),
 original_vendor_bytes_observed:false,vendor_sha256:None,
 original_image_digest_verified:false,external_custody_claim:false,recovery_claim:false}}
 #[test]fn matched_lock_not_image(){let x=assess(&good()).unwrap();
 assert!(x.original_lock_bytes_consistent&&!x.offline_image_qualified);}
 #[test]fn missing_zip_denied(){let mut x=good();x.exact_artifact_observed=false;
 assert!(!assess(&x).unwrap().source_promotable);}
 #[test]fn wrong_attempt_denied(){let mut x=good();x.archive_run_attempt_matched=false;
 assert!(!assess(&x).unwrap().source_promotable);}
 #[test]fn hash_fork_denied(){let mut x=good();x.reported_lock_sha256=Some("b".repeat(64));
 assert!(!assess(&x).unwrap().original_lock_bytes_consistent);}
 #[test]fn missing_vendor_denied(){let x=assess(&good()).unwrap();
 assert!(x.blockers.iter().any(|b|b=="ORIGINAL_VENDOR_BYTES_NOT_OBSERVED"));}
 #[test]fn malformed_vendor_hash_denied(){let mut x=good();
 x.original_vendor_bytes_observed=true;x.vendor_sha256=Some("not-sha256".into());
 x.original_image_digest_verified=true;let r=assess(&x).unwrap();
 assert!(!r.offline_image_qualified);
 assert!(r.blockers.iter().any(|b|b=="ORIGINAL_VENDOR_BYTES_NOT_OBSERVED"));
 assert!(!r.recovery_authorized);}
 #[test]fn false_external_custody(){let mut x=good();x.external_custody_claim=true;
 assert!(!assess(&x).unwrap().offline_image_qualified);}
 #[test]fn no_recovery_even_complete(){let mut x=good();
 x.original_vendor_bytes_observed=true;x.vendor_sha256=Some("c".repeat(64));
 x.original_image_digest_verified=true;let r=assess(&x).unwrap();
 assert!(r.offline_image_qualified&&!r.recovery_authorized);}
 #[test]fn create_only(){let r=assess(&good()).unwrap();
 let p=std::env::temp_dir().join(format!("sapphon206-{}.json",std::process::id()));
 let _=std::fs::remove_file(&p);write_new(&p,&r).unwrap();
 assert_eq!(write_new(&p,&r).unwrap_err().0,"IMPORT206_EXISTS");
 std::fs::remove_file(p).unwrap();}
}
