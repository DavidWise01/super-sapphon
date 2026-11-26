//! SAPPHON-154 — strict CI readback reconciliation.
//! Inputs here are snapshots, not independently fetched API responses.
//! The Rust layer can reject contradictions but cannot authenticate GitHub.
#![cfg(target_os = "linux")]
use crate::Error;
use serde::{Deserialize,Serialize};
use sha2::{Digest,Sha256};
use std::{collections::BTreeSet,fs::{File,OpenOptions},io::Write,path::Path};
pub const AUTHORITY:&str="HOLD";
const MAX:usize=1024*1024;
fn sha(bytes:&[u8])->String{hex::encode(Sha256::digest(bytes))}
fn hex40(s:&str)->bool{s.len()==40&&s.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b))}
fn hex64(s:&str)->bool{s.len()==64&&s.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b))}
#[derive(Debug,Clone,Serialize,Deserialize,PartialEq,Eq)]
#[serde(deny_unknown_fields)]
pub struct RunReadback {
    pub repository:String,
    pub commit_sha:String,
    pub workflow_path:String,
    pub run_id:u64,
    pub attempt:u32,
    pub event:String,
    pub run_status:String,
    pub run_conclusion:Option<String>,
    pub jobs:Vec<JobReadback>,
    pub artifact:Option<ArtifactReadback>,
}
#[derive(Debug,Clone,Serialize,Deserialize,PartialEq,Eq)]
#[serde(deny_unknown_fields)]
pub struct JobReadback {
    pub name:String,
    pub status:String,
    pub conclusion:Option<String>,
}
#[derive(Debug,Clone,Serialize,Deserialize,PartialEq,Eq)]
#[serde(deny_unknown_fields)]
pub struct ArtifactReadback {
    pub repository:String,
    pub commit_sha:String,
    pub run_id:u64,
    pub attempt:u32,
    pub bytes_sha256:String,
    pub name:String,
}
#[derive(Debug,Clone,Copy,Serialize,Deserialize,PartialEq,Eq)]
pub enum RunFinding{
    VerifiedSnapshotConsistent,
    IncompleteOrUnsuccessfulRun,
    MissingRequiredJob,
    ArtifactAbsentOrMismatched,
}
#[derive(Debug,Clone,Serialize,Deserialize,PartialEq,Eq)]
#[serde(deny_unknown_fields)]
pub struct Review {
    pub schema:String,
    pub finding:RunFinding,
    pub repository:String,
    pub commit_sha:String,
    pub run_id:u64,
    pub attempt:u32,
    pub snapshot_sha256:String,
    pub signature_or_source_authenticated:bool,
    pub external_custody_authenticated:bool,
    pub run_success_qualified:bool,
    pub recovery_authorized:bool,
    pub lock_cleared:bool,
    pub decision:String,
}
/// Only compares a supplied snapshot against independently specified expected
/// identifiers and required job names; it cannot verify API provenance.
pub fn reconcile(
    snapshot:&RunReadback,
    expected_repository:&str,
    expected_commit:&str,
    expected_workflow:&str,
    expected_run_id:u64,
    expected_attempt:u32,
    expected_artifact_sha256:&str,
    required_jobs:&[&str],
)->Result<Review,Error>{
    if expected_repository.is_empty()||expected_workflow.is_empty()
        ||!hex40(expected_commit)||!hex64(expected_artifact_sha256)
        ||expected_run_id==0||expected_attempt==0||required_jobs.is_empty()
        ||required_jobs.len()>16{
        return Err(Error("RUN154_EXPECTATIONS"));
    }
    if snapshot.repository!=expected_repository
        ||snapshot.commit_sha!=expected_commit
        ||snapshot.workflow_path!=expected_workflow
        ||snapshot.run_id!=expected_run_id||snapshot.attempt!=expected_attempt
        ||snapshot.event!="push"&&snapshot.event!="workflow_dispatch"{
        return Err(Error("RUN154_IDENTITY_MISMATCH"));
    }
    let mut names=BTreeSet::new();
    for j in &snapshot.jobs{
        if j.name.is_empty()||!names.insert(j.name.as_str()){
            return Err(Error("RUN154_DUPLICATE_JOB"));
        }
    }
    let finding=if snapshot.run_status!="completed"
        ||snapshot.run_conclusion.as_deref()!=Some("success")
        ||snapshot.jobs.iter().any(|j|j.status!="completed"
            ||j.conclusion.as_deref()!=Some("success")){
        RunFinding::IncompleteOrUnsuccessfulRun
    }else if required_jobs.iter().any(|job|!names.contains(job)){
        RunFinding::MissingRequiredJob
    }else{
        match &snapshot.artifact{
            None=>RunFinding::ArtifactAbsentOrMismatched,
            Some(a) if a.repository!=expected_repository
                ||a.commit_sha!=expected_commit
                ||a.run_id!=expected_run_id||a.attempt!=expected_attempt
                ||a.bytes_sha256!=expected_artifact_sha256
                ||a.name!="sapphon-153-ci-claim"=>
                    RunFinding::ArtifactAbsentOrMismatched,
            Some(_)=>RunFinding::VerifiedSnapshotConsistent,
        }
    };
    let snapshot_bytes=serde_json::to_vec(snapshot)
        .map_err(|_|Error("RUN154_ENCODING"))?;
    Ok(Review{
        schema:"sapphon-154-readback-v1".into(),
        finding,repository:expected_repository.into(),
        commit_sha:expected_commit.into(),run_id:expected_run_id,
        attempt:expected_attempt,snapshot_sha256:sha(&snapshot_bytes),
        signature_or_source_authenticated:false,
        external_custody_authenticated:false,run_success_qualified:false,
        recovery_authorized:false,lock_cleared:false,
        decision:"SNAPSHOT_ONLY_HOLD".into(),
    })
}
pub fn write_new(path:&Path,r:&Review)->Result<String,Error>{
    if r.schema!="sapphon-154-readback-v1"||r.decision!="SNAPSHOT_ONLY_HOLD"
       ||r.signature_or_source_authenticated||r.external_custody_authenticated
       ||r.run_success_qualified||r.recovery_authorized||r.lock_cleared {
        return Err(Error("RUN154_AUTHORITY"));
    }
    let bytes=serde_json::to_vec(r).map_err(|_|Error("RUN154_ENCODING"))?;
    if bytes.len()>MAX{return Err(Error("RUN154_LIMIT"));}
    let mut f=OpenOptions::new().write(true).create_new(true).open(path)
        .map_err(|_|Error("RUN154_EXISTS"))?;
    f.write_all(&bytes).map_err(|_|Error("RUN154_WRITE"))?;
    f.sync_all().map_err(|_|Error("RUN154_FSYNC"))?;
    File::open(path.parent().ok_or(Error("RUN154_PARENT"))?)
        .and_then(|dir|dir.sync_all()).map_err(|_|Error("RUN154_DIRSYNC"))?;
    Ok(sha(&bytes))
}
#[cfg(test)]
mod tests{
    use super::*;
    fn fixture()->RunReadback{
        RunReadback{repository:"DavidWise01/super-sapphon".into(),
          commit_sha:"a".repeat(40),
          workflow_path:".github/workflows/sapphon-153-qualification.yml".into(),
          run_id:123,attempt:1,event:"push".into(),run_status:"completed".into(),
          run_conclusion:Some("success".into()),
          jobs:vec![JobReadback{name:"qualification".into(),
              status:"completed".into(),conclusion:Some("success".into())}],
          artifact:Some(ArtifactReadback{
              repository:"DavidWise01/super-sapphon".into(),commit_sha:"a".repeat(40),
              run_id:123,attempt:1,bytes_sha256:"b".repeat(64),
              name:"sapphon-153-ci-claim".into()})}
    }
    fn run(s:&RunReadback)->Result<Review,Error>{
        reconcile(s,"DavidWise01/super-sapphon",&"a".repeat(40),
          ".github/workflows/sapphon-153-qualification.yml",123,1,&"b".repeat(64),
          &["qualification"])
    }
    #[test]fn matching_snapshot_cannot_certify_ci(){
        let r=run(&fixture()).unwrap();
        assert_eq!(r.finding,RunFinding::VerifiedSnapshotConsistent);
        assert!(!r.signature_or_source_authenticated&&!r.run_success_qualified
          &&!r.external_custody_authenticated&&!r.recovery_authorized);
    }
    #[test]fn mismatched_commit_rejected(){
        let mut s=fixture();s.commit_sha="c".repeat(40);
        assert_eq!(run(&s).unwrap_err().0,"RUN154_IDENTITY_MISMATCH");
    }
    #[test]fn mismatched_attempt_rejected(){
        let mut s=fixture();s.attempt=2;
        assert_eq!(run(&s).unwrap_err().0,"RUN154_IDENTITY_MISMATCH");
    }
    #[test]fn failed_job_not_a_success(){
        let mut s=fixture();s.jobs[0].conclusion=Some("failure".into());
        assert_eq!(run(&s).unwrap().finding,RunFinding::IncompleteOrUnsuccessfulRun);
    }
    #[test]fn pending_run_not_a_success(){
        let mut s=fixture();s.run_status="in_progress".into();
        assert_eq!(run(&s).unwrap().finding,RunFinding::IncompleteOrUnsuccessfulRun);
    }
    #[test]fn no_artifact_remains_unqualified(){
        let mut s=fixture();s.artifact=None;
        assert_eq!(run(&s).unwrap().finding,RunFinding::ArtifactAbsentOrMismatched);
    }
    #[test]fn replayed_artifact_from_other_run_is_detected(){
        let mut s=fixture();s.artifact.as_mut().unwrap().run_id=5;
        assert_eq!(run(&s).unwrap().finding,RunFinding::ArtifactAbsentOrMismatched);
    }
    #[test]fn missing_expected_job_is_detected(){
        let mut s=fixture();s.jobs.clear();
        assert_eq!(run(&s).unwrap().finding,RunFinding::MissingRequiredJob);
    }
    #[test]fn duplicate_jobs_rejected(){
        let mut s=fixture();s.jobs.push(s.jobs[0].clone());
        assert_eq!(run(&s).unwrap_err().0,"RUN154_DUPLICATE_JOB");
    }
    #[test]fn create_only_review_export(){
        let r=run(&fixture()).unwrap();
        let path=std::env::temp_dir().join(format!("sapphon154-{}.json",std::process::id()));
        let _=std::fs::remove_file(&path);
        write_new(&path,&r).unwrap();
        assert_eq!(write_new(&path,&r).unwrap_err().0,"RUN154_EXISTS");
        std::fs::remove_file(path).unwrap();
    }
}
