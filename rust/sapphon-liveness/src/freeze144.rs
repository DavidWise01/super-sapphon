//! SAPPHON-144 — Phase XII source-evidence freeze adjudicator.
//! "Design complete" is NOT a verified software, physical, or authority freeze.
//! The verifier never removes locks or promotes evidence into operating authority.
#![cfg(target_os = "linux")]
use crate::{export142::Evidence, quarantine143::Quarantine, Error};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
pub const AUTHORITY: &str = "HOLD";
const MAX: usize = 1024 * 1024;

fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
fn valid_digest(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Assessment {
    pub schema: String,
    pub clean_export_sha256: String,
    pub quarantine_sha256: String,
    pub declared_roots: usize,
    pub reported_conflicts: usize,
    pub design_steps_completed: u8,
    pub design_steps_total: u8,
    pub source_evidence_qualified: bool,
    pub independent_custody_qualified: bool,
    pub ci_verified: bool,
    pub global_anti_rollback: bool,
    pub authenticated_utc: bool,
    pub lock_cleared: bool,
    pub authority: String,
    pub decision: String,
}
/// Inputs are data, not instructions or trust anchors. The hashes in the
/// calling environment require separate read-only custody to mean anything.
pub fn adjudicate(
    clean_bytes: &[u8],
    clean_expected_sha256: &str,
    quarantine_bytes: &[u8],
    quarantine_expected_sha256: &str,
) -> Result<Assessment, Error> {
    if clean_bytes.len() > MAX
        || quarantine_bytes.len() > MAX
        || !valid_digest(clean_expected_sha256)
        || !valid_digest(quarantine_expected_sha256)
        || digest(clean_bytes) != clean_expected_sha256
        || digest(quarantine_bytes) != quarantine_expected_sha256
    {
        return Err(Error("FREEZE_DIGEST_CONFLICT"));
    }
    let clean: Evidence =
        serde_json::from_slice(clean_bytes).map_err(|_| Error("FREEZE_CLEAN_CORRUPT"))?;
    let quarantine: Quarantine =
        serde_json::from_slice(quarantine_bytes).map_err(|_| Error("FREEZE_QUARANTINE_CORRUPT"))?;
    if clean.schema != "sapphon-142-evidence-v1"
        || clean.authority != "HOLD"
        || quarantine.schema != "sapphon-143-quarantine-v1"
        || quarantine.authority != "HOLD"
        || quarantine.independent_custody
        || quarantine.cryptographic_authentication != "NOT_PERFORMED"
    {
        return Err(Error("FREEZE_AUTHORITY_CONFLICT"));
    }
    if clean.history_before_sha256 != quarantine.previous_history_sha256 {
        return Err(Error("FREEZE_ANCESTRY_CONFLICT"));
    }
    if !valid_digest(&clean.history_after_sha256)
        || !valid_digest(&clean.registry_head)
        || !valid_digest(&clean.history_before_sha256)
        || !clean.conflicts.is_empty()
    {
        return Err(Error("FREEZE_SOURCE_CONFLICT"));
    }
    let mut ids = BTreeSet::new();
    let mut roots = BTreeSet::new();
    let mut custodians = BTreeSet::new();
    for claim in &clean.claims {
        if claim.witness_id.is_empty()
            || claim.ancestry_root.is_empty()
            || claim.custodian_id.is_empty()
            || !ids.insert(claim.witness_id.as_str())
            || !roots.insert(claim.ancestry_root.as_str())
            || !custodians.insert(claim.custodian_id.as_str())
        {
            return Err(Error("FREEZE_DUPLICATE_CLAIM"));
        }
    }
    let mut observed = BTreeMap::new();
    for receipt in &clean.receipts {
        if !ids.contains(receipt.witness_id.as_str()) {
            return Err(Error("FREEZE_MISSING_CLAIM"));
        }
        let key = (receipt.witness_id.as_str(), receipt.seq);
        if let Some(previous) = observed.insert(key, receipt.head.as_str()) {
            if previous != receipt.head {
                return Err(Error("FREEZE_EQUIVOCATION"));
            }
            return Err(Error("FREEZE_DUPLICATE_RECEIPT"));
        }
    }
    // Contradictions are retained and explicitly disqualify a freeze.
    // A cryptographic signature does not create a separate ancestral source.
    let conflicts = quarantine.findings.len();
    let decision = if conflicts > 0 {
        "EVIDENCE_CONFLICT_HOLD"
    } else {
        "DESIGN_COMPLETE_QUALIFICATION_HOLD"
    };
    Ok(Assessment {
        schema: "sapphon-144-phase-xii-assessment-v1".into(),
        clean_export_sha256: clean_expected_sha256.into(),
        quarantine_sha256: quarantine_expected_sha256.into(),
        declared_roots: roots.len(),
        reported_conflicts: conflicts,
        design_steps_completed: 8,
        design_steps_total: 8,
        source_evidence_qualified: false,
        independent_custody_qualified: false,
        ci_verified: false,
        global_anti_rollback: false,
        authenticated_utc: false,
        lock_cleared: false,
        authority: "HOLD".into(),
        decision: decision.into(),
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        export142::{Evidence, RootClaim},
        quarantine143::{Finding, Quarantine},
    };
    fn fixture(conflict: bool) -> (Vec<u8>, String, Vec<u8>, String) {
        let history = "a".repeat(64);
        let clean = Evidence {
            schema: "sapphon-142-evidence-v1".into(),
            registry_seq: 0,
            registry_head: "b".repeat(64),
            history_before_sha256: history.clone(),
            history_after_sha256: "c".repeat(64),
            claims: vec![RootClaim {
                witness_id: "first".into(),
                ancestry_root: "root-a".into(),
                custodian_id: "custodian-a".into(),
            }],
            receipts: vec![],
            conflicts: vec![],
            authority: "HOLD".into(),
        };
        let q = Quarantine {
            schema: "sapphon-143-quarantine-v1".into(),
            previous_history_sha256: history,
            receipts: vec![],
            findings: if conflict {
                vec![Finding {
                    code: "BATCH_EQUIVOCATION".into(),
                    witness_id: "first".into(),
                    seq: 2,
                    first_head: "d".repeat(64),
                    other_head: "e".repeat(64),
                }]
            } else {
                vec![]
            },
            declared_ancestry: vec![],
            authority: "HOLD".into(),
            cryptographic_authentication: "NOT_PERFORMED".into(),
            independent_custody: false,
        };
        let a = serde_json::to_vec(&clean).unwrap();
        let b = serde_json::to_vec(&q).unwrap();
        let ad = digest(&a);
        let bd = digest(&b);
        (a, ad, b, bd)
    }
    #[test]
    fn complete_design_does_not_grant_operational_authority() {
        let (a, ad, b, bd) = fixture(false);
        let v = adjudicate(&a, &ad, &b, &bd).unwrap();
        assert_eq!((v.design_steps_completed, v.design_steps_total), (8, 8));
        assert_eq!(v.decision, "DESIGN_COMPLETE_QUALIFICATION_HOLD");
        assert!(
            !v.independent_custody_qualified
                && !v.source_evidence_qualified
                && !v.ci_verified
                && !v.lock_cleared
                && !v.authenticated_utc
        );
    }
    #[test]
    fn conflicting_quarantine_stays_visible_and_blocks_freeze() {
        let (a, ad, b, bd) = fixture(true);
        let v = adjudicate(&a, &ad, &b, &bd).unwrap();
        assert_eq!(v.reported_conflicts, 1);
        assert_eq!(v.decision, "EVIDENCE_CONFLICT_HOLD");
        assert_eq!(v.authority, "HOLD");
    }
    #[test]
    fn byte_mutation_fails_closed() {
        let (a, ad, mut b, bd) = fixture(false);
        b.push(b' ');
        assert_eq!(
            adjudicate(&a, &ad, &b, &bd).unwrap_err().0,
            "FREEZE_DIGEST_CONFLICT"
        );
    }
    #[test]
    fn mismatched_history_ancestry_fails_closed() {
        let (a, ad, b, _) = fixture(false);
        let mut q: Quarantine = serde_json::from_slice(&b).unwrap();
        q.previous_history_sha256 = "0".repeat(64);
        let altered = serde_json::to_vec(&q).unwrap();
        assert_eq!(
            adjudicate(&a, &ad, &altered, &digest(&altered))
                .unwrap_err()
                .0,
            "FREEZE_ANCESTRY_CONFLICT"
        );
    }
    #[test]
    fn shared_claimed_root_cannot_be_counted_twice() {
        let (a, _, b, bd) = fixture(false);
        let mut c: Evidence = serde_json::from_slice(&a).unwrap();
        c.claims.push(RootClaim {
            witness_id: "second".into(),
            ancestry_root: "root-a".into(),
            custodian_id: "custodian-b".into(),
        });
        let body = serde_json::to_vec(&c).unwrap();
        assert_eq!(
            adjudicate(&body, &digest(&body), &b, &bd).unwrap_err().0,
            "FREEZE_DUPLICATE_CLAIM"
        );
    }
}
