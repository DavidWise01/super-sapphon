//! SAPPHON-170 — newest-attempt runtime failure isolation.
//! A stale passing attempt cannot mask the latest failure. Authority stays HOLD.
#![cfg(target_os = "linux")]
use crate::Error;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs::{File, OpenOptions},
    io::Write,
    path::Path,
};
pub const AUTHORITY: &str = "HOLD";
fn sha(b: &[u8]) -> String {
    hex::encode(Sha256::digest(b))
}
fn goodsha(s: &str) -> bool {
    s.len() == 40
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Attempt {
    pub commit: String,
    pub run_id: u64,
    pub attempt: u32,
    pub status: String,
    pub conclusion: Option<String>,
    pub job_name: String,
    pub job_conclusion: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Isolation {
    pub schema: String,
    pub expected_commit: String,
    pub selected_run_id: Option<u64>,
    pub selected_attempt: Option<u32>,
    pub prior_green_ignored: bool,
    pub required_job_present: bool,
    pub latest_source_owned_pass: bool,
    pub blocked_reason: String,
    pub evidence_sha256: String,
    pub independent_custody_authenticated: bool,
    pub global_anti_rollback_authenticated: bool,
    pub recovery_authorized: bool,
    pub lock_cleared: bool,
    pub decision: String,
}
pub fn isolate(commit: &str, attempts: &[Attempt]) -> Result<Isolation, Error> {
    if !goodsha(commit) || attempts.len() > 128 {
        return Err(Error("ISO170_INPUT"));
    }
    let mut seen = BTreeSet::new();
    for a in attempts {
        if !goodsha(&a.commit)
            || a.run_id == 0
            || a.attempt == 0
            || a.job_name.len() > 128
            || ![
                "completed",
                "in_progress",
                "queued",
                "waiting",
                "requested",
                "pending",
            ]
            .contains(&a.status.as_str())
            || a.conclusion.as_ref().is_some_and(|c| {
                ![
                    "success",
                    "failure",
                    "cancelled",
                    "timed_out",
                    "skipped",
                    "neutral",
                ]
                .contains(&c.as_str())
            })
            || a.job_conclusion.as_ref().is_some_and(|c| {
                ![
                    "success",
                    "failure",
                    "cancelled",
                    "timed_out",
                    "skipped",
                    "neutral",
                ]
                .contains(&c.as_str())
            })
        {
            return Err(Error("ISO170_FIELDS"));
        }
        if !seen.insert((a.run_id, a.attempt, a.job_name.as_str())) {
            return Err(Error("ISO170_DUPLICATE"));
        }
    }
    let mut matching = attempts
        .iter()
        .filter(|a| a.commit == commit)
        .collect::<Vec<_>>();
    matching.sort_by_key(|a| (a.run_id, a.attempt));
    let last = matching.last().copied();
    let source_pass = last.is_some_and(|a| {
        a.status == "completed"
            && a.conclusion.as_deref() == Some("success")
            && a.job_name == "runtime-evidence"
            && a.job_conclusion.as_deref() == Some("success")
    });
    let prior_green_ignored = matching
        .iter()
        .rev()
        .skip(1)
        .any(|a| a.status == "completed" && a.conclusion.as_deref() == Some("success"));
    let reason = match last {
        None => "NO_MATCHING_RUN",
        Some(a) if a.status != "completed" => "LATEST_INCOMPLETE",
        Some(a) if a.job_name != "runtime-evidence" => "REQUIRED_JOB_MISSING",
        Some(a) if a.conclusion.as_deref() != Some("success") => "LATEST_RUN_NOT_SUCCESS",
        Some(a) if a.job_conclusion.as_deref() != Some("success") => "LATEST_JOB_NOT_SUCCESS",
        Some(_) => "SOURCE_OWNED_PASS_ONLY",
    };
    let body = serde_json::to_vec(attempts).map_err(|_| Error("ISO170_ENCODING"))?;
    Ok(Isolation {
        schema: "sapphon-170-runtime-isolation-v1".into(),
        expected_commit: commit.into(),
        selected_run_id: last.map(|a| a.run_id),
        selected_attempt: last.map(|a| a.attempt),
        prior_green_ignored,
        required_job_present: last.is_some_and(|a| a.job_name == "runtime-evidence"),
        latest_source_owned_pass: source_pass,
        blocked_reason: reason.into(),
        evidence_sha256: sha(&body),
        independent_custody_authenticated: false,
        global_anti_rollback_authenticated: false,
        recovery_authorized: false,
        lock_cleared: false,
        decision: "LATEST_RUN_DIAGNOSTIC_HOLD".into(),
    })
}
pub fn write_new(path: &Path, r: &Isolation) -> Result<String, Error> {
    if r.schema != "sapphon-170-runtime-isolation-v1"
        || r.decision != "LATEST_RUN_DIAGNOSTIC_HOLD"
        || r.independent_custody_authenticated
        || r.global_anti_rollback_authenticated
        || r.recovery_authorized
        || r.lock_cleared
    {
        return Err(Error("ISO170_AUTHORITY"));
    }
    let body = serde_json::to_vec(r).map_err(|_| Error("ISO170_ENCODING"))?;
    let mut f = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)
        .map_err(|_| Error("ISO170_EXISTS"))?;
    f.write_all(&body).map_err(|_| Error("ISO170_WRITE"))?;
    f.sync_all().map_err(|_| Error("ISO170_FSYNC"))?;
    File::open(path.parent().ok_or(Error("ISO170_PARENT"))?)
        .and_then(|d| d.sync_all())
        .map_err(|_| Error("ISO170_DIRSYNC"))?;
    Ok(sha(&body))
}
#[cfg(test)]
mod tests {
    use super::*;
    fn x() -> Attempt {
        Attempt {
            commit: "a".repeat(40),
            run_id: 169,
            attempt: 1,
            status: "completed".into(),
            conclusion: Some("success".into()),
            job_name: "runtime-evidence".into(),
            job_conclusion: Some("success".into()),
        }
    }
    #[test]
    fn success_only_source_owned() {
        let r = isolate(&"a".repeat(40), &[x()]).unwrap();
        assert!(r.latest_source_owned_pass);
        assert!(!r.recovery_authorized);
    }
    #[test]
    fn newer_failure_masks_green() {
        let old = x();
        let mut new = old.clone();
        new.run_id = 170;
        new.conclusion = Some("failure".into());
        let r = isolate(&"a".repeat(40), &[old, new]).unwrap();
        assert!(!r.latest_source_owned_pass);
        assert!(r.prior_green_ignored);
    }
    #[test]
    fn new_attempt_failure_masks_green() {
        let old = x();
        let mut new = old.clone();
        new.attempt = 2;
        new.job_conclusion = Some("failure".into());
        assert!(
            !isolate(&"a".repeat(40), &[old, new])
                .unwrap()
                .latest_source_owned_pass
        );
    }
    #[test]
    fn missing_job_denies_green() {
        let mut a = x();
        a.job_name = "other".into();
        assert_eq!(
            isolate(&"a".repeat(40), &[a]).unwrap().blocked_reason,
            "REQUIRED_JOB_MISSING"
        );
    }
    #[test]
    fn incomplete_run_denies_green() {
        let mut a = x();
        a.status = "in_progress".into();
        a.conclusion = None;
        assert_eq!(
            isolate(&"a".repeat(40), &[a]).unwrap().blocked_reason,
            "LATEST_INCOMPLETE"
        );
    }
    #[test]
    fn unrelated_source_ignored() {
        assert_eq!(
            isolate(&"b".repeat(40), &[x()]).unwrap().blocked_reason,
            "NO_MATCHING_RUN"
        );
    }
    #[test]
    fn duplicate_job_rejected() {
        let a = x();
        assert_eq!(
            isolate(&"a".repeat(40), &[a.clone(), a]).unwrap_err().0,
            "ISO170_DUPLICATE"
        );
    }
    #[test]
    fn create_only_output() {
        let r = isolate(&"a".repeat(40), &[x()]).unwrap();
        let p = std::env::temp_dir().join(format!("sapphon170-{}.json", std::process::id()));
        let _ = std::fs::remove_file(&p);
        write_new(&p, &r).unwrap();
        assert_eq!(write_new(&p, &r).unwrap_err().0, "ISO170_EXISTS");
        std::fs::remove_file(p).unwrap();
    }
}
