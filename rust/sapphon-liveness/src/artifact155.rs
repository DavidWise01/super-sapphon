//! SAPPHON-155 — readback of exact runner artifact bytes.
//! Caller supplies downloaded bytes and GitHub metadata. Neither is authenticated
//! by this pure Rust module; the workflow's API query is a separate trust boundary.
#![cfg(target_os = "linux")]
use crate::{
    readback154::{self, RunFinding, RunReadback},
    Error,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
pub const AUTHORITY: &str = "HOLD";
const MAX_BYTES: usize = 1024 * 1024;
fn digest(b: &[u8]) -> String {
    hex::encode(Sha256::digest(b))
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Claim {
    pub schema: String,
    pub repository: String,
    pub git_commit: String,
    pub run_id: String,
    pub run_attempt: String,
    pub rust_tests: String,
    pub historical_188_hashes: String,
    pub independent_custody_authenticated: bool,
    pub recovery_authority: String,
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum Assessment {
    ConsistentUntrustedSnapshot,
    RunnerArtifactMismatch,
    RunOrJobIncomplete,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ArtifactReview {
    pub schema: String,
    pub assessment: Assessment,
    pub downloaded_bytes_sha256: String,
    pub expected_bytes_sha256: String,
    pub run_id: u64,
    pub attempt: u32,
    pub commit_sha: String,
    pub runner_evidence_consistent: bool,
    pub external_custody_authenticated: bool,
    pub operational_recovery_authorized: bool,
    pub lock_cleared: bool,
    pub decision: String,
}
/// Checks exact JSON bytes, decoded claim values and supplied GitHub metadata.
/// GitHub's ZIP artifact digest must not be confused with the JSON-entry digest.
pub fn inspect(
    snapshot: &RunReadback,
    downloaded_json: &[u8],
    expected_json_sha256: &str,
    repo: &str,
    commit: &str,
    workflow: &str,
    run_id: u64,
    attempt: u32,
    required_jobs: &[&str],
) -> Result<ArtifactReview, Error> {
    if downloaded_json.len() > MAX_BYTES
        || expected_json_sha256.len() != 64
        || !expected_json_sha256
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(Error("ART155_EXPECTATIONS"));
    }
    // SAPPHON-154 checks repository, commit, run, attempt, jobs, artifact metadata.
    let comparison = readback154::reconcile(
        snapshot,
        repo,
        commit,
        workflow,
        run_id,
        attempt,
        expected_json_sha256,
        required_jobs,
    )?;
    let actual = digest(downloaded_json);
    let valid_bytes = actual == expected_json_sha256;
    let claim: Option<Claim> = if valid_bytes {
        serde_json::from_slice(downloaded_json).ok()
    } else {
        None
    };
    let matching = claim.as_ref().is_some_and(|c| {
        c.schema == "sapphon-153-actions-run-v1"
            && c.repository == repo
            && c.git_commit == commit
            && c.run_id == run_id.to_string()
            && c.run_attempt == attempt.to_string()
            && c.rust_tests == "completed_prior_steps"
            && c.historical_188_hashes == "completed_prior_steps"
            && !c.independent_custody_authenticated
            && c.recovery_authority == "HOLD"
    });
    let result = if comparison.finding == RunFinding::IncompleteOrUnsuccessfulRun
        || comparison.finding == RunFinding::MissingRequiredJob
    {
        Assessment::RunOrJobIncomplete
    } else if !valid_bytes
        || !matching
        || comparison.finding != RunFinding::VerifiedSnapshotConsistent
    {
        Assessment::RunnerArtifactMismatch
    } else {
        Assessment::ConsistentUntrustedSnapshot
    };
    Ok(ArtifactReview {
        schema: "sapphon-155-artifact-readback-v1".into(),
        assessment: result,
        downloaded_bytes_sha256: actual,
        expected_bytes_sha256: expected_json_sha256.into(),
        run_id,
        attempt,
        commit_sha: commit.into(),
        runner_evidence_consistent: result == Assessment::ConsistentUntrustedSnapshot,
        external_custody_authenticated: false,
        operational_recovery_authorized: false,
        lock_cleared: false,
        decision: "RUNNER_EVIDENCE_ONLY_HOLD".into(),
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::readback154::{ArtifactReadback, JobReadback};
    fn claim() -> Vec<u8> {
        let c = Claim {
            schema: "sapphon-153-actions-run-v1".into(),
            repository: "DavidWise01/super-sapphon".into(),
            git_commit: "a".repeat(40),
            run_id: "42".into(),
            run_attempt: "2".into(),
            rust_tests: "completed_prior_steps".into(),
            historical_188_hashes: "completed_prior_steps".into(),
            independent_custody_authenticated: false,
            recovery_authority: "HOLD".into(),
        };
        serde_json::to_vec(&c).unwrap()
    }
    fn snapshot(expected: &str) -> RunReadback {
        RunReadback {
            repository: "DavidWise01/super-sapphon".into(),
            commit_sha: "a".repeat(40),
            workflow_path: ".github/workflows/sapphon-153-qualification.yml".into(),
            run_id: 42,
            attempt: 2,
            event: "push".into(),
            run_status: "completed".into(),
            run_conclusion: Some("success".into()),
            jobs: vec![JobReadback {
                name: "qualification".into(),
                status: "completed".into(),
                conclusion: Some("success".into()),
            }],
            artifact: Some(ArtifactReadback {
                repository: "DavidWise01/super-sapphon".into(),
                commit_sha: "a".repeat(40),
                run_id: 42,
                attempt: 2,
                bytes_sha256: expected.into(),
                name: "sapphon-153-ci-claim".into(),
            }),
        }
    }
    fn review(s: &RunReadback, b: &[u8], expected: &str) -> Result<ArtifactReview, Error> {
        inspect(
            s,
            b,
            expected,
            "DavidWise01/super-sapphon",
            &"a".repeat(40),
            ".github/workflows/sapphon-153-qualification.yml",
            42,
            2,
            &["qualification"],
        )
    }
    #[test]
    fn exact_json_bytes_match_but_custody_remains_hold() {
        let b = claim();
        let h = digest(&b);
        let r = review(&snapshot(&h), &b, &h).unwrap();
        assert_eq!(r.assessment, Assessment::ConsistentUntrustedSnapshot);
        assert!(
            !r.external_custody_authenticated
                && !r.operational_recovery_authorized
                && !r.lock_cleared
        );
    }
    #[test]
    fn mutated_entry_bytes_cannot_pass() {
        let b = claim();
        let h = digest(&b);
        let mut wrong = b.clone();
        wrong.push(b' ');
        assert_eq!(
            review(&snapshot(&h), &wrong, &h).unwrap().assessment,
            Assessment::RunnerArtifactMismatch
        );
    }
    #[test]
    fn replay_from_other_attempt_fails_closed() {
        let b = claim();
        let h = digest(&b);
        let mut s = snapshot(&h);
        s.artifact.as_mut().unwrap().attempt = 1;
        assert_eq!(
            review(&s, &b, &h).unwrap().assessment,
            Assessment::RunnerArtifactMismatch
        );
    }
    #[test]
    fn changed_embedded_run_id_rejected_even_with_valid_digest() {
        let b = claim();
        let mut claim: Claim = serde_json::from_slice(&b).unwrap();
        claim.run_id = "43".into();
        let wrong = serde_json::to_vec(&claim).unwrap();
        let h = digest(&wrong);
        assert_eq!(
            review(&snapshot(&h), &wrong, &h).unwrap().assessment,
            Assessment::RunnerArtifactMismatch
        );
    }
    #[test]
    fn failed_job_is_reported_not_promoted() {
        let b = claim();
        let h = digest(&b);
        let mut s = snapshot(&h);
        s.jobs[0].conclusion = Some("failure".into());
        assert_eq!(
            review(&s, &b, &h).unwrap().assessment,
            Assessment::RunOrJobIncomplete
        );
    }
    #[test]
    fn missing_artifact_fails_closed() {
        let b = claim();
        let h = digest(&b);
        let mut s = snapshot(&h);
        s.artifact = None;
        assert_eq!(
            review(&s, &b, &h).unwrap().assessment,
            Assessment::RunnerArtifactMismatch
        );
    }
    #[test]
    fn claim_of_independent_custody_cannot_promote_authority() {
        let mut c: Claim = serde_json::from_slice(&claim()).unwrap();
        c.independent_custody_authenticated = true;
        let b = serde_json::to_vec(&c).unwrap();
        let h = digest(&b);
        assert_eq!(
            review(&snapshot(&h), &b, &h).unwrap().assessment,
            Assessment::RunnerArtifactMismatch
        );
    }
}
