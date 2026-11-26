//! SAPPHON-169 — exact workflow runtime-evidence adjudication.
//! GitHub-owned observations do not establish external physical custody.
#![cfg(target_os="linux")]
use crate::Error;
use serde::{Deserialize,Serialize};
use sha2::{Digest,Sha256};
use std::{collections::BTreeSet,fs::{File,OpenOptions},io::Write,path::Path};
pub const AUTHORITY:&str="HOLD";
fn sha(b:&[u8])->String{hex::encode(Sha256::digest(b))}
fn goodsha(s:&str)->bool{s.len()==40&&s.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b))}
#[derive(Debug,Clone,Serialize,Deserialize,PartialEq,Eq)]
#[serde(deny_unknown_fields)]
pub struct Job{pub name:String,pub conclusion:String,pub status:String}
#[derive(Debug,Clone,Serialize,Deserialize,PartialEq,Eq)]
#[serde(deny_unknown_fields)]
pub struct Run{
 pub commit:String,pub run_id:u64,pub attempt:u32,
 pub status:String,pub conclusion:String,pub jobs:Vec<Job>
}
#[derive(Debug,Clone,Serialize,Deserialize,PartialEq,Eq)]
#[serde(deny_unknown_fields)]
pub struct Review{
 pub schema:String,pub expected_commit:String,pub matching_runs:usize,
 pub completed_source_owned_pass:bool,pub failed_jobs:Vec<String>,
 pub incomplete_runs:Vec<u64>,pub evidence_digest:String,
 pub npm_lockfile_authenticated:bool,pub browser_externally_authenticated:bool,
 pub independent_custody_authenticated:bool,pub global_anti_rollback_authenticated:bool,
 pub recovery_authorized:bool,pub lock_cleared:bool,pub decision:String
}
pub fn inspect(expected_commit:&str,runs:&[Run])->Result<Review,Error>{
 if !goodsha(expected_commit)||runs.len()>100{return Err(Error("RUN169_FIELDS"));}
 let mut found=BTreeSet::new();let mut failed=Vec::new();let mut incomplete=Vec::new();
 let mut count=0;let mut pass=false;
 for r in runs {
   if !goodsha(&r.commit)||r.run_id==0||r.attempt==0||r.jobs.len()>100{
      return Err(Error("RUN169_RUN_FIELDS"));
   }
   if r.commit!=expected_commit{continue;}
   if !found.insert((r.run_id,r.attempt)){return Err(Error("RUN169_DUPLICATE"));}
   count+=1;
   if r.status!="completed"||r.conclusion=="pending"{
      incomplete.push(r.run_id);
   }
   let mut names=BTreeSet::new();
   for job in &r.jobs{
     if job.name.is_empty()||!names.insert(job.name.as_str())
        ||!["success","failure","cancelled","skipped","timed_out","neutral","pending"].contains(&job.conclusion.as_str()){
        return Err(Error("RUN169_JOB_FIELDS"));
     }
     if ["failure","cancelled","timed_out"].contains(&job.conclusion.as_str()){
        failed.push(format!("{}:{}:{}",r.run_id,job.name,job.conclusion));
     }
   }
   if r.status=="completed"&&r.conclusion=="success"&&!r.jobs.is_empty()
      &&r.jobs.iter().all(|j|j.conclusion=="success"){pass=true;}
 }
 failed.sort();incomplete.sort();
 let body=serde_json::to_vec(runs).map_err(|_|Error("RUN169_ENCODING"))?;
 Ok(Review{schema:"sapphon-169-runtime-review-v1".into(),
    expected_commit:expected_commit.into(),matching_runs:count,
    completed_source_owned_pass:pass,failed_jobs:failed,incomplete_runs:incomplete,
    evidence_digest:sha(&body),npm_lockfile_authenticated:false,
    browser_externally_authenticated:false,
    independent_custody_authenticated:false,global_anti_rollback_authenticated:false,
    recovery_authorized:false,lock_cleared:false,decision:"RUNTIME_EVIDENCE_HOLD".into()})
}
pub fn write_new(path:&Path,r:&Review)->Result<String,Error>{
 if r.schema!="sapphon-169-runtime-review-v1"||r.decision!="RUNTIME_EVIDENCE_HOLD"
    ||r.npm_lockfile_authenticated||r.browser_externally_authenticated
    ||r.independent_custody_authenticated||r.global_anti_rollback_authenticated
    ||r.recovery_authorized||r.lock_cleared{return Err(Error("RUN169_AUTHORITY"));}
 let b=serde_json::to_vec(r).map_err(|_|Error("RUN169_ENCODING"))?;
 let mut f=OpenOptions::new().create_new(true).write(true).open(path)
    .map_err(|_|Error("RUN169_EXISTS"))?;
 f.write_all(&b).map_err(|_|Error("RUN169_WRITE"))?;
 f.sync_all().map_err(|_|Error("RUN169_FSYNC"))?;
 File::open(path.parent().ok_or(Error("RUN169_PARENT"))?)
    .and_then(|d|d.sync_all()).map_err(|_|Error("RUN169_DIRSYNC"))?;
 Ok(sha(&b))
}
#[cfg(test)]
mod tests{
 use super::*;
 fn example()->Run{Run{commit:"a".repeat(40),run_id:169,attempt:1,
    status:"completed".into(),conclusion:"success".into(),
    jobs:vec![Job{name:"Rust".into(),conclusion:"success".into(),status:"completed".into()}]}}
 #[test]fn pass_is_source_owned_only(){
    let r=inspect(&"a".repeat(40),&[example()]).unwrap();
    assert!(r.completed_source_owned_pass);
    assert!(!r.recovery_authorized&&!r.independent_custody_authenticated);
 }
 #[test]fn wrong_sha_no_match(){assert_eq!(inspect(&"b".repeat(40),&[example()]).unwrap().matching_runs,0);}
 #[test]fn empty_jobs_not_pass(){let mut x=example();x.jobs.clear();assert!(!inspect(&"a".repeat(40),&[x]).unwrap().completed_source_owned_pass);}
 #[test]fn failed_job_visible(){let mut x=example();x.jobs[0].conclusion="failure".into();
    let r=inspect(&"a".repeat(40),&[x]).unwrap();assert_eq!(r.failed_jobs.len(),1);}
 #[test]fn incomplete_run_visible(){let mut x=example();x.status="in_progress".into();
    assert_eq!(inspect(&"a".repeat(40),&[x]).unwrap().incomplete_runs,vec![169]);}
 #[test]fn duplicate_attempt_rejected(){let x=example();
    assert_eq!(inspect(&"a".repeat(40),&[x.clone(),x]).unwrap_err().0,"RUN169_DUPLICATE");}
 #[test]fn invalid_job_conclusion_rejected(){let mut x=example();x.jobs[0].conclusion="authentic".into();
    assert_eq!(inspect(&"a".repeat(40),&[x]).unwrap_err().0,"RUN169_JOB_FIELDS");}
 #[test]fn create_only_report(){let r=inspect(&"a".repeat(40),&[example()]).unwrap();
    let p=std::env::temp_dir().join(format!("sapphon169-{}.json",std::process::id()));
    let _=std::fs::remove_file(&p);write_new(&p,&r).unwrap();
    assert_eq!(write_new(&p,&r).unwrap_err().0,"RUN169_EXISTS");std::fs::remove_file(p).unwrap();}
}
