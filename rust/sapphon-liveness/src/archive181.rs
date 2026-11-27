//! SAPPHON-181: validate safe archive-inspection findings; no ZIP extraction.
#![cfg(target_os="linux")]
use crate::Error;
use serde::{Deserialize,Serialize};
use sha2::{Digest,Sha256};
use std::{fs::{File,OpenOptions},io::Write,path::Path};
pub const AUTHORITY:&str="HOLD";
const SOURCE:&str="dd1d778c522aa18fb399c052958f05c4f5b02dd9";
fn valid_hash(s:&str)->bool{s.len()==64&&s.bytes().all(|c|c.is_ascii_digit()||(b'a'..=b'f').contains(&c))}
fn digest(v:&[u8])->String{hex::encode(Sha256::digest(v))}
#[derive(Debug,Clone,Serialize,Deserialize,PartialEq,Eq)]
#[serde(deny_unknown_fields)]
pub struct Entry{pub name:String,pub bytes:u64,pub crc32:String}
#[derive(Debug,Clone,Serialize,Deserialize,PartialEq,Eq)]
#[serde(deny_unknown_fields)]
pub struct Inspection{pub schema:String,pub source_sha:String,
 pub run_id:Option<u64>,pub attempt:Option<u32>,pub artifact_id:Option<u64>,
 pub original_zip_sha256:String,pub entries:Vec<Entry>,pub findings:Vec<String>,
 pub source_owned_zip_consistent:bool,pub bytes_extracted_to_disk:bool,
 pub archive_code_executed:bool,pub external_metadata_authenticated:bool,
 pub independent_custody_authenticated:bool,pub recovery_authorized:bool,
 pub lock_cleared:bool,pub decision:String}
#[derive(Debug,Clone,Serialize,Deserialize,PartialEq,Eq)]
#[serde(deny_unknown_fields)]
pub struct Finding{pub schema:String,pub inspection_digest:String,pub blockers:Vec<String>,
 pub source_owned_consistency:bool,pub independently_authenticated:bool,
 pub recovery_authorized:bool,pub lock_cleared:bool,pub decision:String}
pub fn adjudicate(i:&Inspection)->Result<Finding,Error>{
 let mut blockers=Vec::new();
 if i.schema!="sapphon-181-safe-zip-inspection-v1"||i.source_sha!=SOURCE{
  blockers.push("INSPECTION_ANCESTRY".into());
 }
 if !valid_hash(&i.original_zip_sha256){blockers.push("INVALID_DIGEST".into());}
 if i.run_id.is_none_or(|n|n==0)||i.attempt.is_none_or(|n|n==0)
  ||i.artifact_id.is_none_or(|n|n==0){blockers.push("IDENTITY".into());}
 if i.entries.is_empty()||i.entries.len()>48{blockers.push("ENTRY_COUNT".into());}
 if !i.entries.iter().any(|e|e.name=="180-summary.json"){
  blockers.push("SUMMARY_MISSING".into());
 }
 if i.entries.iter().any(|e|e.bytes>2*1024*1024){
  blockers.push("OVERSIZE_ENTRY".into());
 }
 if !i.findings.is_empty()||!i.source_owned_zip_consistent{
  blockers.push("SOURCE_FINDINGS".into());
 }
 if i.bytes_extracted_to_disk||i.archive_code_executed
   ||i.external_metadata_authenticated||i.independent_custody_authenticated
   ||i.recovery_authorized||i.lock_cleared{
  blockers.push("AUTHORITY_OR_EXTRACTION".into());
 }
 blockers.sort();blockers.dedup();
 let data=serde_json::to_vec(i).map_err(|_|Error("ZIP181_ENCODING"))?;
 Ok(Finding{schema:"sapphon-181-archive-adjudication-v1".into(),
  inspection_digest:digest(&data),source_owned_consistency:blockers.is_empty(),
  blockers,independently_authenticated:false,recovery_authorized:false,
  lock_cleared:false,decision:"ARCHIVE_ADJUDICATION_HOLD".into()})
}
pub fn write_new(path:&Path,f:&Finding)->Result<String,Error>{
 if f.schema!="sapphon-181-archive-adjudication-v1"
    ||f.decision!="ARCHIVE_ADJUDICATION_HOLD"||f.independently_authenticated
    ||f.recovery_authorized||f.lock_cleared{return Err(Error("ZIP181_AUTHORITY"));}
 let bytes=serde_json::to_vec(f).map_err(|_|Error("ZIP181_ENCODING"))?;
 let mut file=OpenOptions::new().write(true).create_new(true).open(path)
  .map_err(|_|Error("ZIP181_EXISTS"))?;
 file.write_all(&bytes).map_err(|_|Error("ZIP181_WRITE"))?;
 file.sync_all().map_err(|_|Error("ZIP181_SYNC"))?;
 File::open(path.parent().ok_or(Error("ZIP181_PARENT"))?)
  .and_then(|d|d.sync_all()).map_err(|_|Error("ZIP181_DIRSYNC"))?;
 Ok(digest(&bytes))
}
#[cfg(test)]
mod tests{
 use super::*;
 fn sample()->Inspection{Inspection{schema:"sapphon-181-safe-zip-inspection-v1".into(),
 source_sha:SOURCE.into(),run_id:Some(180),attempt:Some(1),artifact_id:Some(800),
 original_zip_sha256:"a".repeat(64),entries:vec![Entry{
 name:"180-summary.json".into(),bytes:256,crc32:"12345678".into()}],
 findings:vec![],source_owned_zip_consistent:true,
 bytes_extracted_to_disk:false,archive_code_executed:false,
 external_metadata_authenticated:false,independent_custody_authenticated:false,
 recovery_authorized:false,lock_cleared:false,decision:"ORIGINAL_ZIP_INSPECTION_HOLD".into()}}
 #[test]fn matching_finding_still_hold(){let f=adjudicate(&sample()).unwrap();
 assert!(f.source_owned_consistency&&!f.recovery_authorized);}
 #[test]fn traversal_error_blocks(){let mut i=sample();i.findings.push("UNSAFE_PATH".into());
 assert!(!adjudicate(&i).unwrap().source_owned_consistency);}
 #[test]fn extraction_claim_blocks(){let mut i=sample();i.bytes_extracted_to_disk=true;
 assert!(!adjudicate(&i).unwrap().source_owned_consistency);}
 #[test]fn authority_claim_blocks(){let mut i=sample();i.recovery_authorized=true;
 assert!(!adjudicate(&i).unwrap().source_owned_consistency);}
 #[test]fn invalid_digest_blocks(){let mut i=sample();i.original_zip_sha256="bad".into();
 assert!(!adjudicate(&i).unwrap().source_owned_consistency);}
 #[test]fn create_only(){let r=adjudicate(&sample()).unwrap();
 let p=std::env::temp_dir().join(format!("sapphon181-{}.json",std::process::id()));
 let _=std::fs::remove_file(&p);write_new(&p,&r).unwrap();
 assert_eq!(write_new(&p,&r).unwrap_err().0,"ZIP181_EXISTS");
 std::fs::remove_file(p).unwrap();}
}
