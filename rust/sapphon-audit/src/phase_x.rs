//! Phase X final adversarial closure. Rust is the primary software auditor.
//! A passing synthetic audit never upgrades local source ancestry to physical witnesses.
use crate::{verify_signed, AuditError, Journal, PinRegistry};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
type Result<T> = std::result::Result<T, AuditError>;
#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct PhaseXClosure {
    pub schema: &'static str,
    pub decision: &'static str,
    pub signed_observations: usize,
    pub conflicting_generations: usize,
    pub conflicting_digests: usize,
    pub shared_ancestry_pairs: usize,
    pub broken_predecessor_links: usize,
    pub generation_gaps: usize,
    pub revocation_resurrections: usize,
    pub cross_source_independence_authenticated: bool,
    pub physical_clock_authority: bool,
    pub utc_authority: bool,
    pub external_effects_authorized: bool,
}
/// Validate every signed observation and expose incompatible history.
pub fn close_phase_x(journal: &Journal, pins: &PinRegistry) -> Result<PhaseXClosure> {
    journal.validate(pins)?;
    let mut by_generation: BTreeMap<(&str, u64), BTreeSet<&str>> = BTreeMap::new();
    let mut by_publisher: BTreeMap<&str, BTreeMap<u64, Vec<&crate::Observation>>> = BTreeMap::new();
    let mut shared = 0usize;
    for (index, item) in journal.observations.iter().enumerate() {
        verify_signed(&item.snapshot, pins)?;
        by_generation
            .entry((&item.publisher_id, item.generation))
            .or_default()
            .insert(&item.digest);
        by_publisher
            .entry(&item.publisher_id)
            .or_default()
            .entry(item.generation)
            .or_default()
            .push(item);
        for next in journal.observations.iter().skip(index + 1) {
            if item
                .ancestry_roots
                .iter()
                .any(|x| next.ancestry_roots.contains(x))
            {
                shared += 1;
            }
        }
    }
    let mut broken = 0usize;
    let mut gaps = 0usize;
    let mut resurrections = 0usize;
    for generations in by_publisher.values() {
        let mut previous: Option<(u64, BTreeSet<&str>, bool, bool)> = None;
        for (&generation, items) in generations {
            let digests: BTreeSet<&str> = items.iter().map(|o| o.digest.as_str()).collect();
            if let Some((prev_generation, ref previous_digests, issuer_revoked, operator_revoked)) =
                previous
            {
                if generation > prev_generation + 1 {
                    gaps += 1;
                }
                for item in items {
                    if item
                        .snapshot
                        .payload
                        .previous_digest
                        .as_ref()
                        .is_none_or(|link| !previous_digests.contains(link.as_str()))
                    {
                        broken += 1;
                    }
                    if issuer_revoked && !item.snapshot.payload.issuer_revoked {
                        resurrections += 1;
                    }
                    if operator_revoked && !item.snapshot.payload.operator_revoked {
                        resurrections += 1;
                    }
                }
            } else {
                for item in items {
                    if generation != 1 || item.snapshot.payload.previous_digest.is_some() {
                        broken += 1;
                    }
                }
            }
            let any_issuer_revoked = items.iter().any(|o| o.snapshot.payload.issuer_revoked);
            let any_operator_revoked = items.iter().any(|o| o.snapshot.payload.operator_revoked);
            previous = Some((
                generation,
                digests,
                any_issuer_revoked,
                any_operator_revoked,
            ));
        }
    }
    Ok(PhaseXClosure {
        schema: "sapphon-128-phase-x-rust-closure-v1",
        decision: "HOLD",
        signed_observations: journal.observations.len(),
        conflicting_generations: by_generation.values().filter(|x| x.len() > 1).count(),
        conflicting_digests: by_generation
            .values()
            .map(|x| x.len().saturating_sub(1))
            .sum(),
        shared_ancestry_pairs: shared,
        broken_predecessor_links: broken,
        generation_gaps: gaps,
        revocation_resurrections: resurrections,
        cross_source_independence_authenticated: false,
        physical_clock_authority: false,
        utc_authority: false,
        external_effects_authorized: false,
    })
}
