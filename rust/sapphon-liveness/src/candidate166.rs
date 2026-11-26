//! SAPPHON-166 — candidate lock provenance gate.
//! Matching a source-owned Actions artifact does NOT grant external authority.
#![cfg(target_os="linux")]
use crate::Error;
use serde::{Deserialize,Serialize};
use sha2::{Digest,Sha256};
use std::{fs::{File,OpenOptions},io::Write,path::Path};
pub const AUTHORITY:&str="HOLD";
fn sha(b:&[u8])->String{hex::encode(Sha256::digest(b))}
fn good64(s:&str)->bool{s.len()==64&&s.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b))}
fn good40(s:&str)->bool{s.len()==40&&s.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b))}
#[derive(Debug,Clone,Serialize,Deserialize,PartialEq,Eq)]
#[serde(deny_unknown_fields)]
pub struct Candidate {
    pub schema:String,
    pub expected_source_commit:String,
    pub observed_source_commit:String,
    pub requested_run_id:u64,
    pub observed_run_id:u64,
    pub requested_attempt:u32,
    pub observed_attempt:u32,
    pub expected_candidate_sha256:String,
    pub observed_candidate_sha256:String,
    pub integrity_fields_present:bool,
    pub registry_step_pass_claimed:bool,
}
#[derive(Debug,Clone,Serialize,Deserialize,PartialEq,Eq)]
#[serde(deny_unknown_fields)]
pub struct Review {
    pub schema:String,
    pub exact_run_identified:bool,
    pub candidate_digest_agreement:bool,
    pub fields_consistent:bool,
    pub candidate_qualified_for_commit_review:bool,
    pub committed_lock_verified:bool,
    pub independent_custody_authenticated:bool,
    pub global_anti_rollback_authenticated:bool,
    pub recovery_authorized:bool,
    pub lock_cleared:bool,
    pub decision:String,
    pub evidence_sha256:String,
}
pub fn inspect(c:&Candidate)->Result<Review,Error>{
    if c.schema!="sapphon-166-candidate-v1"
        ||!good40(&c.expected_source_commit)||!good40(&c.observed_source_commit)
        ||!good64(&c.expected_candidate_sha256)||!good64(&c.observed_candidate_sha256)
        ||c.requested_run_id==0||c.observed_run_id==0
        ||c.requested_attempt==0||c.observed_attempt==0{
        return Err(Error("CAND166_FIELDS"));
    }
    let run=c.expected_source_commit==c.observed_source_commit
        &&c.requested_run_id==c.observed_run_id
        &&c.requested_attempt==c.observed_attempt;
    let digest=c.expected_candidate_sha256==c.observed_candidate_sha256;
    let consistent=run&&digest&&c.integrity_fields_present&&c.registry_step_pass_claimed;
    let bytes=serde_json::to_vec(c).map_err(|_|Error("CAND166_ENCODING"))?;
    Ok(Review{schema:"sapphon-166-candidate-review-v1".into(),
        exact_run_identified:run,candidate_digest_agreement:digest,
        fields_consistent:consistent,candidate_qualified_for_commit_review:consistent,
        committed_lock_verified:false,independent_custody_authenticated:false,
        global_anti_rollback_authenticated:false,recovery_authorized:false,
        lock_cleared:false,decision:"CANDIDATE_SOURCE_ONLY_HOLD".into(),
        evidence_sha256:sha(&bytes)})
}
pub fn write_new(path:&Path,r:&Review)->Result<String,Error>{
    if r.schema!="sapphon-166-candidate-review-v1"
        ||r.decision!="CANDIDATE_SOURCE_ONLY_HOLD"
        ||r.committed_lock_verified||r.independent_custody_authenticated
        ||r.global_anti_rollback_authenticated||r.recovery_authorized||r.lock_cleared{
        return Err(Error("CAND166_AUTHORITY"));
    }
    let b=serde_json::to_vec(r).map_err(|_|Error("CAND166_ENCODING"))?;
    let mut f=OpenOptions::new().create_new(true).write(true).open(path)
        .map_err(|_|Error("CAND166_EXISTS"))?;
    f.write_all(&b).map_err(|_|Error("CAND166_WRITE"))?;
    f.sync_all().map_err(|_|Error("CAND166_FSYNC"))?;
    File::open(path.parent().ok_or(Error("CAND166_PARENT"))?)
        .and_then(|d|d.sync_all()).map_err(|_|Error("CAND166_DIRSYNC"))?;
    Ok(sha(&b))
}
#[cfg(test)]
mod tests{
    use super::*;
    fn fixture()->Candidate{
       Candidate{schema:"sapphon-166-candidate-v1".into(),
        expected_source_commit:"a".repeat(40),observed_source_commit:"a".repeat(40),
        requested_run_id:42,observed_run_id:42,requested_attempt:2,observed_attempt:2,
        expected_candidate_sha256:"b".repeat(64),observed_candidate_sha256:"b".repeat(64),
        integrity_fields_present:true,registry_step_pass_claimed:true}
    }
    #[test]fn matched_source_still_hold(){
        let o=inspect(&fixture()).unwrap();
        assert!(o.candidate_qualified_for_commit_review);
        assert!(!o.committed_lock_verified&&!o.recovery_authorized&&!o.lock_cleared);
    }
    #[test]fn wrong_commit_blocked(){
        let mut c=fixture();c.observed_source_commit="c".repeat(40);
        assert!(!inspect(&c).unwrap().fields_consistent);
    }
    #[test]fn wrong_attempt_blocked(){
        let mut c=fixture();c.observed_attempt=1;
        assert!(!inspect(&c).unwrap().exact_run_identified);
    }
    #[test]fn wrong_run_blocked(){
        let mut c=fixture();c.observed_run_id=41;
        assert!(!inspect(&c).unwrap().fields_consistent);
    }
    #[test]fn wrong_digest_blocked(){
        let mut c=fixture();c.observed_candidate_sha256="d".repeat(64);
        assert!(!inspect(&c).unwrap().candidate_digest_agreement);
    }
    #[test]fn registry_failed_blocked(){
        let mut c=fixture();c.registry_step_pass_claimed=false;
        assert!(!inspect(&c).unwrap().candidate_qualified_for_commit_review);
    }
    #[test]fn absent_integrity_blocked(){
        let mut c=fixture();c.integrity_fields_present=false;
        assert!(!inspect(&c).unwrap().fields_consistent);
    }
    #[test]fn create_only_output(){
        let r=inspect(&fixture()).unwrap();
        let p=std::env::temp_dir().join(format!("sapphon166-{}.json",std::process::id()));
        let _=std::fs::remove_file(&p);
        write_new(&p,&r).unwrap();
        assert_eq!(write_new(&p,&r).unwrap_err().0,"CAND166_EXISTS");
        std::fs::remove_file(p).unwrap();
    }
}
