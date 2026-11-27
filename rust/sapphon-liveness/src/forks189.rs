//! SAPPHON-189: same-lineage root fork detection, owned ancestry only.
#![cfg(target_os="linux")]
use crate::Error;
use serde::{Deserialize,Serialize};
use sha2::{Digest,Sha256};
use std::{collections::{BTreeMap,BTreeSet},fs::{File,OpenOptions},io::Write,path::Path};
pub const AUTHORITY:&str="HOLD";
const SOURCE:&str="011ad7d5623d7d5db8ec2183bcf7207a0e8ec42c";
fn hex64(s:&str)->bool{s.len()==64&&s.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b))}
fn digest(data:&[u8])->String{hex::encode(Sha256::digest(data))}
#[derive(Clone,Debug,Serialize,Deserialize,PartialEq,Eq)]
#[serde(deny_unknown_fields)]
pub struct RootClaim{
 pub source_sha:String,pub run_id:u64,pub attempt:u32,
 pub lineage_id:String,pub surface:String,pub state:String,
 pub root_sha256:Option<String>,pub custodian:String,
 pub independent_authentication_claim:bool
}
#[derive(Clone,Debug,Serialize,Deserialize,PartialEq,Eq)]
#[serde(deny_unknown_fields)]
pub struct Finding{
 pub schema:String,pub claim_set_sha256:String,pub observed_roots:usize,
 pub forks:Vec<String>,pub owned_roots_consistent:bool,
 pub independent_witnesses:u8,pub authenticated_utc:bool,
 pub global_anti_rollback_authenticated:bool,
 pub recovery_authorized:bool,pub lock_cleared:bool,
 pub decision:String
}
pub fn compare(claims:&[RootClaim])->Result<Finding,Error>{
 if claims.len()>64{return Err(Error("FORK189_CLAIM_LIMIT"));}
 let mut seen=BTreeSet::new();
 let mut roots=BTreeMap::<(u64,u32,String),BTreeSet<String>>::new();
 let mut count=0;
 for x in claims{
  if x.source_sha!=SOURCE||x.run_id==0||x.attempt==0||
   x.lineage_id.is_empty()||x.lineage_id.len()>128||x.custodian!="github-owned"||
   x.independent_authentication_claim{return Err(Error("FORK189_AUTHORITY_OR_SOURCE"));}
  if !["github-source","github-actions","github-pages","github-api"].contains(&x.surface.as_str()){
   return Err(Error("FORK189_SURFACE"));
  }
  if !seen.insert((x.surface.clone(),x.run_id,x.attempt,x.lineage_id.clone())){
   return Err(Error("FORK189_DUPLICATE_SURFACE"));
  }
  match x.state.as_str(){
   "OBSERVED"=>{
    let h=x.root_sha256.as_deref().ok_or(Error("FORK189_DIGEST"))?;
    if !hex64(h){return Err(Error("FORK189_DIGEST"));}
    roots.entry((x.run_id,x.attempt,x.lineage_id.clone()))
     .or_default().insert(h.to_owned());count+=1;
   }
   "READBACK_UNAVAILABLE"|"ARTIFACT_EXPIRED"|"ARTIFACT_MISSING"|"PAGE_CAP"=>{
    if x.root_sha256.is_some(){return Err(Error("FORK189_UNOBSERVED_HASH"));}
   }
   _=>return Err(Error("FORK189_STATE"))
  }
 }
 let forks=roots.into_iter().filter(|(_,set)|set.len()>1)
  .map(|((run,attempt,lineage),_)|format!("{run}:{attempt}:{lineage}"))
  .collect::<Vec<_>>();
 let bytes=serde_json::to_vec(claims).map_err(|_|Error("FORK189_SERIALIZE"))?;
 Ok(Finding{schema:"sapphon-189-rust-fork-v1".into(),
  claim_set_sha256:digest(&bytes),observed_roots:count,
  owned_roots_consistent:count>0&&forks.is_empty(),
  forks,independent_witnesses:0,authenticated_utc:false,
  global_anti_rollback_authenticated:false,recovery_authorized:false,
  lock_cleared:false,decision:"CUSTODY_ROOT_FORK_HOLD".into()})
}
pub fn write_new(path:&Path,f:&Finding)->Result<String,Error>{
 if f.schema!="sapphon-189-rust-fork-v1"||f.decision!="CUSTODY_ROOT_FORK_HOLD"||
 f.independent_witnesses!=0||f.authenticated_utc||
 f.global_anti_rollback_authenticated||f.recovery_authorized||f.lock_cleared{
  return Err(Error("FORK189_AUTHORITY"));
 }
 let bytes=serde_json::to_vec(f).map_err(|_|Error("FORK189_SERIALIZE"))?;
 let mut file=OpenOptions::new().write(true).create_new(true).open(path)
  .map_err(|_|Error("FORK189_EXISTS"))?;
 file.write_all(&bytes).map_err(|_|Error("FORK189_WRITE"))?;
 file.sync_all().map_err(|_|Error("FORK189_SYNC"))?;
 File::open(path.parent().ok_or(Error("FORK189_PARENT"))?)
  .and_then(|d|d.sync_all()).map_err(|_|Error("FORK189_DIRSYNC"))?;
 Ok(digest(&bytes))
}
#[cfg(test)]
mod tests{
 use super::*;
 fn claim(surface:&str,hash:Option<&str>,attempt:u32)->RootClaim{
  RootClaim{source_sha:SOURCE.into(),run_id:188,attempt,
   lineage_id:"original-188".into(),surface:surface.into(),
   state:if hash.is_some(){"OBSERVED"}else{"READBACK_UNAVAILABLE"}.into(),
   root_sha256:hash.map(str::to_owned),custodian:"github-owned".into(),
   independent_authentication_claim:false}}
 #[test]fn mirrors_are_one_ancestry(){let a="a".repeat(64);
  let x=compare(&[claim("github-api",Some(&a),1),claim("github-actions",Some(&a),1)]).unwrap();
  assert!(x.owned_roots_consistent);assert_eq!(x.independent_witnesses,0);}
 #[test]fn competing_roots_are_fork(){let a="a".repeat(64);let b="b".repeat(64);
  assert_eq!(compare(&[claim("github-api",Some(&a),1),
   claim("github-actions",Some(&b),1)]).unwrap().forks.len(),1);}
 #[test]fn rerun_not_fork(){let a="a".repeat(64);let b="b".repeat(64);
  assert!(compare(&[claim("github-api",Some(&a),1),
   claim("github-actions",Some(&b),2)]).unwrap().forks.is_empty());}
 #[test]fn no_roots_is_not_pass(){
  assert!(!compare(&[claim("github-api",None,1)]).unwrap().owned_roots_consistent);}
 #[test]fn forged_witness_refused(){let mut c=claim("github-api",None,1);
  c.independent_authentication_claim=true;
  assert_eq!(compare(&[c]).unwrap_err().0,"FORK189_AUTHORITY_OR_SOURCE");}
 #[test]fn duplicate_mirror_refused(){
  let c=claim("github-api",None,1);
  assert_eq!(compare(&[c.clone(),c]).unwrap_err().0,"FORK189_DUPLICATE_SURFACE");}
 #[test]fn create_only(){let f=compare(&[]).unwrap();
  let p=std::env::temp_dir().join(format!("sapphon189-{}.json",std::process::id()));
  let _=std::fs::remove_file(&p);write_new(&p,&f).unwrap();
  assert_eq!(write_new(&p,&f).unwrap_err().0,"FORK189_EXISTS");
  std::fs::remove_file(p).unwrap();}
}
