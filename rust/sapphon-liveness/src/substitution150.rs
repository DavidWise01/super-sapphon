//! SAPPHON-150 — total local-state substitution evidence review.
//! Externally provisioned expected digests are inputs, never derived authority.
//! A matching byte digest cannot prove independent physical custody.
#![cfg(target_os = "linux")]
use crate::{
    anchor145::{self, Anchor, ProvisionedProvider},
    failover148,
    replay149::{self, ReplayState},
    Error,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{File, OpenOptions},
    io::Write,
    path::Path,
};
pub const AUTHORITY: &str = "HOLD";
const LIMIT: usize = 1024 * 1024;
fn sha(b: &[u8]) -> String {
    hex::encode(Sha256::digest(b))
}
fn good(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
/// This identifies exact provisioned provider bytes: key, identity and floors.
/// A local fingerprint calculated at recovery time is not a trust root.
pub fn provider_fingerprint(p: &ProvisionedProvider) -> Result<String, Error> {
    let bytes = hex::decode(&p.public_key_hex).map_err(|_| Error("SUBSTITUTION_KEY"))?;
    if bytes.len() != 32 {
        return Err(Error("SUBSTITUTION_KEY"));
    }
    let data = format!(
        "SAPPHON-150-PROVIDER-v1\n{}\n{}\n{}\n{}\n{}\n{}\n",
        p.provider_id, p.public_key_hex, p.min_counter, p.min_sequence, p.min_epoch, p.revoked
    );
    Ok(sha(data.as_bytes()))
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum SubstitutionState {
    AllLocalEvidenceMatches,
    ProviderConfigurationReplaced,
    RotationIntentReplacedOrMissing,
    RegistryReplacedOrCorrupt,
    RegistryRolledBack,
    UnanchoredLocalAdvance,
    AnchoredHistoryConflict,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SubstitutionReport {
    pub schema: String,
    pub state: SubstitutionState,
    pub observed_registry_sha256: String,
    pub observed_intent_sha256: Option<String>,
    pub observed_provider_sha256: String,
    pub trusted_provider_sha256: String,
    pub trusted_registry_sha256: String,
    pub trusted_intent_sha256: String,
    pub signed_anchor_head: String,
    pub signed_anchor_sequence: u64,
    pub provider_signature_verified: bool,
    pub independent_custody_proven: bool,
    pub replacement_key_accepted: bool,
    pub lock_cleared: bool,
    pub decision: String,
}
/// Trusted provider configuration is passed separately. The allegedly
/// recovered configuration is never used for signature verification.
pub fn inspect(
    registry: &[u8],
    intent: Option<&[u8]>,
    recovered_provider: &ProvisionedProvider,
    trusted_provider: &ProvisionedProvider,
    trusted_provider_sha256: &str,
    trusted_registry_sha256: &str,
    trusted_intent_sha256: &str,
    trusted_history_sha256: &str,
    anchor: &Anchor,
) -> Result<SubstitutionReport, Error> {
    if registry.len() > LIMIT
        || intent.is_some_and(|b| b.len() > LIMIT)
        || !good(trusted_provider_sha256)
        || !good(trusted_registry_sha256)
        || !good(trusted_intent_sha256)
        || !good(trusted_history_sha256)
    {
        return Err(Error("SUBSTITUTION_INPUT"));
    }
    if provider_fingerprint(trusted_provider)? != trusted_provider_sha256 {
        return Err(Error("SUBSTITUTION_TRUSTED_PROVIDER_ANCHOR"));
    }
    // Always verify against the independently supplied trusted provider,
    // not the mutable local provider registry.
    anchor145::verify_anchor(anchor, trusted_provider)?;
    let registry_digest = sha(registry);
    let intent_digest = intent.map(sha);
    let provider_digest = provider_fingerprint(recovered_provider)?;
    let state = if provider_digest != trusted_provider_sha256 {
        SubstitutionState::ProviderConfigurationReplaced
    } else if intent_digest.as_deref() != Some(trusted_intent_sha256) {
        SubstitutionState::RotationIntentReplacedOrMissing
    } else if registry_digest != trusted_registry_sha256 {
        // Exact externally pinned registry bytes differ. Distinguish the
        // rollback from arbitrary substitution only through the signed head.
        let r = replay149::inspect(
            registry,
            intent,
            trusted_intent_sha256,
            trusted_history_sha256,
            anchor,
            trusted_provider,
        )?;
        match r.state {
            ReplayState::LocalHistoryRolledBack => SubstitutionState::RegistryRolledBack,
            ReplayState::LocalHistoryCorrupt => SubstitutionState::RegistryReplacedOrCorrupt,
            ReplayState::ContradictoryLocalHistory => SubstitutionState::AnchoredHistoryConflict,
            ReplayState::LocalHistoryAheadPending => SubstitutionState::UnanchoredLocalAdvance,
            _ => SubstitutionState::RegistryReplacedOrCorrupt,
        }
    } else {
        // Match to externally retained bytes is necessary but not sufficient.
        // Check the chain, signed prefix, and intent linkage too.
        let r = replay149::inspect(
            registry,
            intent,
            trusted_intent_sha256,
            trusted_history_sha256,
            anchor,
            trusted_provider,
        )?;
        match r.state {
            ReplayState::MatchedExternalEvidence => SubstitutionState::AllLocalEvidenceMatches,
            ReplayState::LocalHistoryRolledBack => SubstitutionState::RegistryRolledBack,
            ReplayState::LocalHistoryAheadPending => SubstitutionState::UnanchoredLocalAdvance,
            ReplayState::ContradictoryLocalHistory => SubstitutionState::AnchoredHistoryConflict,
            _ => SubstitutionState::RegistryReplacedOrCorrupt,
        }
    };
    Ok(SubstitutionReport {
        schema: "sapphon-150-substitution-report-v1".into(),
        state,
        observed_registry_sha256: registry_digest,
        observed_intent_sha256: intent_digest,
        observed_provider_sha256: provider_digest,
        trusted_provider_sha256: trusted_provider_sha256.into(),
        trusted_registry_sha256: trusted_registry_sha256.into(),
        trusted_intent_sha256: trusted_intent_sha256.into(),
        signed_anchor_head: anchor.head_sha256.clone(),
        signed_anchor_sequence: anchor.sequence,
        provider_signature_verified: true,
        independent_custody_proven: false,
        replacement_key_accepted: false,
        lock_cleared: false,
        decision: "HOLD".into(),
    })
}
/// Create-only report. A hostile party may still remove this file or rewrite
/// its local copy; keep the returned digest in independently secured custody.
pub fn write_report_new(path: &Path, report: &SubstitutionReport) -> Result<String, Error> {
    if report.schema != "sapphon-150-substitution-report-v1"
        || report.decision != "HOLD"
        || report.lock_cleared
        || report.replacement_key_accepted
        || report.independent_custody_proven
    {
        return Err(Error("SUBSTITUTION_REPORT_FIELDS"));
    }
    let bytes = serde_json::to_vec(report).map_err(|_| Error("SUBSTITUTION_ENCODING"))?;
    if bytes.len() > LIMIT {
        return Err(Error("SUBSTITUTION_LIMIT"));
    }
    let mut f = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)
        .map_err(|_| Error("SUBSTITUTION_ALREADY_EXISTS"))?;
    f.write_all(&bytes)
        .map_err(|_| Error("SUBSTITUTION_WRITE"))?;
    f.sync_all().map_err(|_| Error("SUBSTITUTION_FSYNC"))?;
    File::open(path.parent().ok_or(Error("SUBSTITUTION_PARENT"))?)
        .and_then(|p| p.sync_all())
        .map_err(|_| Error("SUBSTITUTION_DIRSYNC"))?;
    Ok(sha(&bytes))
}
pub fn verify_report(bytes: &[u8], trusted_sha256: &str) -> Result<SubstitutionReport, Error> {
    if bytes.len() > LIMIT || !good(trusted_sha256) || sha(bytes) != trusted_sha256 {
        return Err(Error("SUBSTITUTION_REPORT_DIGEST"));
    }
    let r: SubstitutionReport =
        serde_json::from_slice(bytes).map_err(|_| Error("SUBSTITUTION_REPORT_CORRUPT"))?;
    if r.schema != "sapphon-150-substitution-report-v1"
        || r.decision != "HOLD"
        || r.lock_cleared
        || r.replacement_key_accepted
        || r.independent_custody_proven
    {
        return Err(Error("SUBSTITUTION_REPORT_FIELDS"));
    }
    Ok(r)
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{failover148::Intent, lineage147::KeyRotation, registry137};
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use ed25519_dalek::{Signer, SigningKey};
    fn fixture() -> (Vec<u8>, Vec<u8>, ProvisionedProvider, Anchor) {
        let signing = SigningKey::from_bytes(&[19u8; 32]);
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let zero = registry137::verify(&[], 0, &registry137::genesis_head()).unwrap();
        let event = registry137::next(
            &zero,
            "register",
            "witness-one",
            "root-one",
            &hex::encode(key.verifying_key().as_bytes()),
            1,
        );
        let mut registry = serde_json::to_vec(&event).unwrap();
        let head = sha(&registry);
        registry.push(b'\n');
        let mut anchor = Anchor {
            schema: "sapphon-145-anchor-v1".into(),
            provider_id: "custodian-one".into(),
            sequence: 1,
            head_sha256: head,
            epoch: 2,
            counter: 4,
            signature_base64: String::new(),
        };
        anchor.signature_base64 =
            STANDARD.encode(signing.sign(&anchor145::anchor_message(&anchor)).to_bytes());
        let provider = ProvisionedProvider {
            provider_id: "custodian-one".into(),
            public_key_hex: hex::encode(signing.verifying_key().as_bytes()),
            min_counter: 2,
            min_sequence: 0,
            min_epoch: 1,
            revoked: false,
        };
        let intent = Intent {
            schema: "sapphon-148-intent-v1".into(),
            expected_history_sha256: "a".repeat(64),
            rotation: KeyRotation {
                schema: "sapphon-147-key-rotation-v1".into(),
                provider_id: "custodian-one".into(),
                prior_key_hex: "b".repeat(64),
                replacement_key_hex: "c".repeat(64),
                prior_epoch: 2,
                replacement_epoch: 3,
                prior_counter: 3,
                replacement_counter: 4,
                old_signature_base64: String::new(),
                new_signature_base64: String::new(),
            },
            old_provider_id: "custodian-one".into(),
            authority: "HOLD".into(),
        };
        (
            registry,
            serde_json::to_vec(&intent).unwrap(),
            provider,
            anchor,
        )
    }
    fn run(
        registry: &[u8],
        intent: Option<&[u8]>,
        recovered: &ProvisionedProvider,
        trusted: &ProvisionedProvider,
        a: &Anchor,
        reg_sha: &str,
        int_sha: &str,
    ) -> Result<SubstitutionReport, Error> {
        inspect(
            registry,
            intent,
            recovered,
            trusted,
            &provider_fingerprint(trusted)?,
            reg_sha,
            int_sha,
            &"a".repeat(64),
            a,
        )
    }
    #[test]
    fn exact_reconstruction_still_hold() {
        let (r, i, p, a) = fixture();
        let review = run(&r, Some(&i), &p, &p, &a, &sha(&r), &sha(&i)).unwrap();
        assert_eq!(review.state, SubstitutionState::AllLocalEvidenceMatches);
        assert!(review.provider_signature_verified);
        assert!(
            !review.independent_custody_proven
                && !review.lock_cleared
                && !review.replacement_key_accepted
        );
    }
    #[test]
    fn simultaneous_registry_intent_and_provider_replacement_is_detected() {
        let (r, i, p, a) = fixture();
        let mut attack = p.clone();
        attack.public_key_hex = "0".repeat(64);
        let mut changed = i.clone();
        changed.push(b' ');
        let report = run(&[], Some(&changed), &attack, &p, &a, &sha(&r), &sha(&i)).unwrap();
        assert_eq!(
            report.state,
            SubstitutionState::ProviderConfigurationReplaced
        );
        assert_eq!(report.decision, "HOLD");
        assert_ne!(
            report.observed_registry_sha256,
            report.trusted_registry_sha256
        );
        assert_ne!(
            report.observed_intent_sha256.as_deref(),
            Some(report.trusted_intent_sha256.as_str())
        );
    }
    #[test]
    fn lost_or_replaced_intent_is_not_accepted() {
        let (r, i, p, a) = fixture();
        let report = run(&r, None, &p, &p, &a, &sha(&r), &sha(&i)).unwrap();
        assert_eq!(
            report.state,
            SubstitutionState::RotationIntentReplacedOrMissing
        );
    }
    #[test]
    fn rollback_and_corruption_are_distinct() {
        let (r, i, p, a) = fixture();
        let rollback = run(&[], Some(&i), &p, &p, &a, &sha(&r), &sha(&i)).unwrap();
        assert_eq!(rollback.state, SubstitutionState::RegistryRolledBack);
        let mut corrupt = r.clone();
        corrupt.pop();
        let review = run(&corrupt, Some(&i), &p, &p, &a, &sha(&r), &sha(&i)).unwrap();
        assert_eq!(review.state, SubstitutionState::RegistryReplacedOrCorrupt);
    }
    #[test]
    fn local_provider_cannot_override_trusted_signature_key() {
        let (r, i, p, mut a) = fixture();
        a.signature_base64 = STANDARD.encode([0u8; 64]);
        assert_eq!(
            run(&r, Some(&i), &p, &p, &a, &sha(&r), &sha(&i))
                .unwrap_err()
                .0,
            "ANCHOR_SIGNATURE"
        );
    }
    #[test]
    fn substituted_trust_anchor_rejected() {
        let (r, i, p, a) = fixture();
        assert_eq!(
            inspect(
                &r,
                Some(&i),
                &p,
                &p,
                &"0".repeat(64),
                &sha(&r),
                &sha(&i),
                &"a".repeat(64),
                &a
            )
            .unwrap_err()
            .0,
            "SUBSTITUTION_TRUSTED_PROVIDER_ANCHOR"
        );
    }
    #[test]
    fn create_only_report_and_tamper_detection() {
        let (r, i, p, a) = fixture();
        let report = run(&r, Some(&i), &p, &p, &a, &sha(&r), &sha(&i)).unwrap();
        let path = std::env::temp_dir().join(format!("sapphon150-{}.json", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let digest = write_report_new(&path, &report).unwrap();
        let data = std::fs::read(&path).unwrap();
        assert_eq!(verify_report(&data, &digest).unwrap(), report);
        assert_eq!(
            write_report_new(&path, &report).unwrap_err().0,
            "SUBSTITUTION_ALREADY_EXISTS"
        );
        let mut changed = data;
        changed.push(b' ');
        assert_eq!(
            verify_report(&changed, &digest).unwrap_err().0,
            "SUBSTITUTION_REPORT_DIGEST"
        );
        std::fs::remove_file(&path).unwrap();
    }
}
