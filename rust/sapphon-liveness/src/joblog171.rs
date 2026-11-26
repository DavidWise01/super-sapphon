//! SAPPHON-171 — failed-job evidence classifications, no operational actuation.
#![cfg(target_os="linux")]
use crate::Error;
use serde::{Deserialize,Serialize};
use sha2::{Digest,Sha256};
use std::{collections::BTreeSet,fs::{File,OpenOptions},io::Write,path::Path};
pub const AUTHORITY:&str="HOLD";
fn sha(b:&[u8])->String{hex::encode(Sha256::digest(b))}
fn good_sha(s:&str)->bool{s.len()==40&&s.bytes().all(|c|c.is_ascii_digit()||(b'a'..=b'f').contains(&c))}
#[derive(Debug,Clone,Serialize,Deserialize,PartialEq,Eq)]
#[serde(deny_unknown_fields)]
pub struct ObservedJob{pub name:String,pub conclusion:String,pub steps:Vec<Step>}
#[derive(Debug,Clone,Serialize,Deserialize,PartialEq,Eq)]
#[serde(deny_unknown_fields)]
pub struct Step{pub name:String,pub conclusion:String}
#[derive(Debug,Clone,Serialize,Deserialize,PartialEq,Eq)]
#[serde(deny_unknown_fields)]
pub struct Observation{
 pub expected_sha:String,pub observed_sha:String,
 pub run_id:u64,pub run_attempt:u32,pub status:String,pub conclusion:String,
 pub jobs:Vec<ObservedJob>,pub excerpt_digest:Option<String>,
}
#[derive(Debug,Clone,Serialize,Deserialize,PartialEq,Eq)]
#[serde(deny_unknown_fields)]
pub struct Decision{
 pub schema:String,pub exact_source:bool,pub required_job_present:bool,
 pub completed_source_pass:bool,pub failed_steps:Vec<String>,
 pub blocked_reasons:Vec<String>,pub observation_sha256:String,
 pub external_custody_authenticated:bool,pub authenticated_utc:bool,
 pub recovery_authorized:bool,pub lock_cleared:bool,pub decision:String,
}
pub fn adjudicate(o:&Observation)->Result<Decision,Error>{
 if !good_sha(&o.expected_sha)||!good_sha(&o.observed_sha)
    ||o.run_id==0||o.run_attempt==0||o.jobs.len()>100
    ||o.excerpt_digest.as_ref().is_some_and(|s|s.len()!=64
      ||!s.bytes().all(|c|c.is_ascii_digit()||(b'a'..=b'f').contains(&c))){
   return Err(Error("LOG171_FIELDS"));
 }
 let mut names=BTreeSet::new();let mut failed=Vec::new();
 for job in &o.jobs{
    if job.name.is_empty()||job.name.len()>128
      ||!names.insert(job.name.as_str())||job.steps.len()>128
      ||!["success","failure","skipped","cancelled","timed_out","neutral","pending"].contains(&job.conclusion.as_str()){
      return Err(Error("LOG171_JOB"));
    }
    for step in &job.steps{
      if step.name.is_empty()||step.name.len()>256
       ||!["success","failure","skipped","cancelled","timed_out","neutral","pending"].contains(&step.conclusion.as_str()){
        return Err(Error("LOG171_STEP"));
      }
      if ["failure","cancelled","timed_out"].contains(&step.conclusion.as_str()){
        failed.push(format!("{}:{}:{}",job.name,step.name,step.conclusion));
      }
    }
 }
 failed.sort();
 let exact=o.expected_sha==o.observed_sha;
 let required=names.contains("deterministic-diagnostics");
 let pass=exact&&required&&o.status=="completed"&&o.conclusion=="success"
   &&!o.jobs.is_empty()&&failed.is_empty()
   &&o.jobs.iter().all(|j|j.conclusion=="success");
 let mut reasons=Vec::new();
 if !exact{reasons.push("COMMIT_MISMATCH".to_owned());}
 if !required{reasons.push("REQUIRED_JOB_MISSING".to_owned());}
 if o.status!="completed"{reasons.push("RUN_INCOMPLETE".to_owned());}
 if o.conclusion!="success"{reasons.push("RUN_NOT_SUCCESS".to_owned());}
 if !failed.is_empty(){reasons.push("FAILED_STEPS_PRESENT".to_owned());}
 reasons.sort();
 let bytes=serde_json::to_vec(o).map_err(|_|Error("LOG171_ENCODING"))?;
 Ok(Decision{
    schema:"sapphon-171-job-log-adjudication-v1".into(),
    exact_source:exact,required_job_present:required,completed_source_pass:pass,
    failed_steps:failed,blocked_reasons:reasons,
    observation_sha256:sha(&bytes),
    external_custody_authenticated:false,authenticated_utc:false,
    recovery_authorized:false,lock_cleared:false,
    decision:"JOB_LOG_OBSERVATION_HOLD".into()
 })
}
pub fn write_new(path:&Path,r:&Decision)->Result<String,Error>{
 if r.schema!="sapphon-171-job-log-adjudication-v1"
    ||r.decision!="JOB_LOG_OBSERVATION_HOLD"
    ||r.external_custody_authenticated||r.authenticated_utc
    ||r.recovery_authorized||r.lock_cleared{return Err(Error("LOG171_AUTHORITY"));}
 let b=serde_json::to_vec(r).map_err(|_|Error("LOG171_ENCODING"))?;
 let mut f=OpenOptions::new().write(true).create_new(true).open(path)
    .map_err(|_|Error("LOG171_EXISTS"))?;
 f.write_all(&b).map_err(|_|Error("LOG171_WRITE"))?;
 f.sync_all().map_err(|_|Error("LOG171_FSYNC"))?;
 File::open(path.parent().ok_or(Error("LOG171_PARENT"))?)
    .and_then(|d|d.sync_all()).map_err(|_|Error("LOG171_DIRSYNC"))?;
 Ok(sha(&b))
}
#[cfg(test)]
mod tests{
 use super::*;
 fn sample()->Observation{
   Observation{expected_sha:"a".repeat(40),observed_sha:"a".repeat(40),
    run_id:171,run_attempt:1,status:"completed".into(),conclusion:"success".into(),
    excerpt_digest:None,jobs:vec![ObservedJob{name:"deterministic-diagnostics".into(),
      conclusion:"success".into(),steps:vec![Step{name:"cargo test".into(),conclusion:"success".into()}]}]}
 }
 #[test]fn source_pass_is_not_recovery(){
    let r=adjudicate(&sample()).unwrap();
    assert!(r.completed_source_pass&&!r.recovery_authorized&&!r.external_custody_authenticated);
 }
 #[test]fn wrong_sha_denies_pass(){
    let mut x=sample();x.observed_sha="b".repeat(40);
    assert!(!adjudicate(&x).unwrap().completed_source_pass);
 }
 #[test]fn missing_required_job_denies_pass(){
    let mut x=sample();x.jobs[0].name="other".into();
    assert_eq!(adjudicate(&x).unwrap().blocked_reasons,vec!["REQUIRED_JOB_MISSING"]);
 }
 #[test]fn failed_step_preserved(){
    let mut x=sample();x.jobs[0].steps[0].conclusion="failure".into();
    assert_eq!(adjudicate(&x).unwrap().failed_steps.len(),1);
 }
 #[test]fn failed_step_under_green_job_denies_pass(){
    let mut x=sample();x.jobs[0].steps[0].conclusion="failure".into();
    assert!(!adjudicate(&x).unwrap().completed_source_pass);
 }
 #[test]fn failed_run_denies_pass(){
    let mut x=sample();x.conclusion="failure".into();
    assert!(!adjudicate(&x).unwrap().completed_source_pass);
 }
 #[test]fn incomplete_run_denies_pass(){
    let mut x=sample();x.status="in_progress".into();
    assert!(!adjudicate(&x).unwrap().completed_source_pass);
 }
 #[test]fn duplicate_job_rejected(){
    let mut x=sample();x.jobs.push(x.jobs[0].clone());
    assert_eq!(adjudicate(&x).unwrap_err().0,"LOG171_JOB");
 }
 #[test]fn create_only_evidence(){
    let r=adjudicate(&sample()).unwrap();
    let p=std::env::temp_dir().join(format!("sapphon171-{}.json",std::process::id()));
    let _=std::fs::remove_file(&p);
    write_new(&p,&r).unwrap();
    assert_eq!(write_new(&p,&r).unwrap_err().0,"LOG171_EXISTS");
    std::fs::remove_file(p).unwrap();
 }
}
