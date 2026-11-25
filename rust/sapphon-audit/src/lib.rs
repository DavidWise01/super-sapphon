//! SAPPHON-127 Rust port. Observation-only synthetic audit.
//!
//! A valid Ed25519 signature proves possession of an enrolled fixture key,
//! not independence, external custody, true time, or global publication truth.
//! The SAPPHON-125 digest is SHA-256 of JSON.stringify(F.map(k => payload[k])).
use base64::Engine;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

pub const JOURNAL_SCHEMA: &str = "sapphon-127-rust-audit-v1";
pub const SNAPSHOT_SCHEMA: &str = "sapphon-125-revocation-snapshot-v1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditError(pub &'static str);
impl std::fmt::Display for AuditError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}
impl std::error::Error for AuditError {}
type Result<T> = std::result::Result<T, AuditError>;

fn valid_id(id: &str) -> bool {
    (4..=64).contains(&id.len())
        && id
            .bytes()
            .all(|x| x.is_ascii_lowercase() || x.is_ascii_digit() || x == b'-')
}
fn valid_hex(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
}
fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SnapshotPayload {
    pub schema: String,
    pub publisher_id: String,
    pub control_root: String,
    pub generation: u64,
    pub issuer_generation: u64,
    pub operator_generation: u64,
    pub issuer_revoked: bool,
    pub operator_revoked: bool,
    pub previous_digest: Option<String>,
    pub mode: String,
}
impl SnapshotPayload {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        if self.schema != SNAPSHOT_SCHEMA
            || !valid_id(&self.publisher_id)
            || !valid_id(&self.control_root)
            || self.generation == 0
            || self.issuer_generation == 0
            || self.operator_generation == 0
            || self.mode != "synthetic-local-replica"
            || (self.generation == 1) != self.previous_digest.is_none()
            || self.previous_digest.as_ref().is_some_and(|s| !valid_hex(s))
        {
            return Err(AuditError("SNAPSHOT_FIELDS"));
        }
        // Preserve the SAPPHON-125 JavaScript canonical array order, not Rust struct field order.
        let a = [
            Value::String(self.schema.clone()),
            Value::String(self.publisher_id.clone()),
            Value::String(self.control_root.clone()),
            Value::from(self.generation),
            Value::from(self.issuer_generation),
            Value::from(self.operator_generation),
            Value::Bool(self.issuer_revoked),
            Value::Bool(self.operator_revoked),
            self.previous_digest
                .as_ref()
                .map_or(Value::Null, |s| Value::String(s.clone())),
            Value::String(self.mode.clone()),
        ];
        serde_json::to_vec(&a).map_err(|_| AuditError("SNAPSHOT_SERIALIZE"))
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignedSnapshot {
    pub payload: SnapshotPayload,
    pub signature: String,
}
#[derive(Clone, Debug)]
pub struct PublisherPin {
    pub control_root: String,
    pub public_key: [u8; 32],
    pub revoked: bool,
}
pub type PinRegistry = BTreeMap<String, PublisherPin>;

pub fn verify_signed(snapshot: &SignedSnapshot, pins: &PinRegistry) -> Result<String> {
    let bytes = snapshot.payload.canonical_bytes()?;
    let pin = pins
        .get(&snapshot.payload.publisher_id)
        .ok_or(AuditError("PUBLISHER_NOT_PINNED"))?;
    if pin.revoked {
        return Err(AuditError("PUBLISHER_REVOKED"));
    }
    if pin.control_root != snapshot.payload.control_root {
        return Err(AuditError("PUBLISHER_IDENTITY"));
    }
    let key = VerifyingKey::from_bytes(&pin.public_key)
        .map_err(|_| AuditError("PUBLISHER_PIN_INVALID"))?;
    let signature_bytes = base64::engine::general_purpose::STANDARD
        .decode(snapshot.signature.as_bytes())
        .map_err(|_| AuditError("SNAPSHOT_SIGNATURE"))?;
    let sig: [u8; 64] = signature_bytes
        .try_into()
        .map_err(|_| AuditError("SNAPSHOT_SIGNATURE"))?;
    let sig = Signature::from_bytes(&sig);
    key.verify(&bytes, &sig)
        .map_err(|_| AuditError("SNAPSHOT_SIGNATURE"))?;
    Ok(digest(&bytes))
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Observation {
    pub publisher_id: String,
    pub generation: u64,
    pub digest: String,
    pub snapshot: SignedSnapshot,
    pub source_id: String,
    pub ancestry_roots: Vec<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Conflict {
    pub publisher_id: String,
    pub generation: u64,
    pub digest_a: String,
    pub digest_b: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Journal {
    pub schema: String,
    pub revision: u64,
    pub observations: Vec<Observation>,
    pub conflicts: Vec<Conflict>,
}
impl Default for Journal {
    fn default() -> Self {
        Self {
            schema: JOURNAL_SCHEMA.into(),
            revision: 0,
            observations: vec![],
            conflicts: vec![],
        }
    }
}
#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct IngestResult {
    pub decision: &'static str,
    pub equivocation: bool,
    pub conflict_count: usize,
    pub external_custody_authenticated: bool,
}
#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct Assessment {
    pub decision: &'static str,
    pub observed_snapshots: usize,
    pub distinct_declared_first_roots: usize,
    pub conflict_detected: bool,
    pub shared_ancestry_detected: bool,
    pub source_owned_overlap: bool,
    pub independent_witnesses_authenticated: bool,
    pub publication_freshness_authenticated: bool,
    pub external_finality: bool,
    pub utc_authority: bool,
}
impl Journal {
    pub fn validate(&self, pins: &PinRegistry) -> Result<()> {
        if self.schema != JOURNAL_SCHEMA
            || self.observations.len() > 1024
            || self.conflicts.len() > 1024
        {
            return Err(AuditError("JOURNAL_CORRUPT"));
        }
        let mut sources = BTreeSet::new();
        for o in &self.observations {
            if !valid_id(&o.source_id)
                || !valid_hex(&o.digest)
                || !valid_id(&o.publisher_id)
                || o.generation == 0
                || o.ancestry_roots.is_empty()
                || o.ancestry_roots.iter().any(|r| !valid_id(r))
                || o.ancestry_roots.iter().collect::<BTreeSet<_>>().len() != o.ancestry_roots.len()
                || o.publisher_id != o.snapshot.payload.publisher_id
                || o.generation != o.snapshot.payload.generation
            {
                return Err(AuditError("JOURNAL_CORRUPT"));
            }
            if verify_signed(&o.snapshot, pins)? != o.digest {
                return Err(AuditError("JOURNAL_CORRUPT"));
            }
            if !sources.insert((&o.source_id, &o.digest)) {
                return Err(AuditError("JOURNAL_CORRUPT"));
            }
        }
        let mut unique = BTreeSet::new();
        for c in &self.conflicts {
            if !valid_id(&c.publisher_id)
                || c.generation == 0
                || !valid_hex(&c.digest_a)
                || !valid_hex(&c.digest_b)
                || c.digest_a == c.digest_b
            {
                return Err(AuditError("JOURNAL_CORRUPT"));
            }
            let (a, b) = if c.digest_a < c.digest_b {
                (&c.digest_a, &c.digest_b)
            } else {
                (&c.digest_b, &c.digest_a)
            };
            if !unique.insert((&c.publisher_id, c.generation, a, b)) {
                return Err(AuditError("JOURNAL_CORRUPT"));
            }
            if !self.observations.iter().any(|o| {
                o.publisher_id == c.publisher_id && o.generation == c.generation && o.digest == *a
            }) || !self.observations.iter().any(|o| {
                o.publisher_id == c.publisher_id && o.generation == c.generation && o.digest == *b
            }) {
                return Err(AuditError("JOURNAL_CORRUPT"));
            }
        }
        for (i, a) in self.observations.iter().enumerate() {
            for b in self.observations.iter().skip(i + 1) {
                if a.publisher_id == b.publisher_id
                    && a.generation == b.generation
                    && a.digest != b.digest
                {
                    if !unique.contains(&(
                        &a.publisher_id,
                        a.generation,
                        if a.digest < b.digest {
                            &a.digest
                        } else {
                            &b.digest
                        },
                        if a.digest < b.digest {
                            &b.digest
                        } else {
                            &a.digest
                        },
                    )) {
                        return Err(AuditError("MISSING_EQUIVOCATION_RECORD"));
                    }
                }
            }
        }
        Ok(())
    }

    pub fn ingest(
        &mut self,
        snapshot: SignedSnapshot,
        source_id: &str,
        ancestry_roots: Vec<String>,
        pins: &PinRegistry,
    ) -> Result<IngestResult> {
        self.validate(pins)?;
        let digest = verify_signed(&snapshot, pins)?;
        if !valid_id(source_id)
            || ancestry_roots.is_empty()
            || ancestry_roots.iter().any(|r| !valid_id(r))
            || ancestry_roots.iter().collect::<BTreeSet<_>>().len() != ancestry_roots.len()
        {
            return Err(AuditError("PROVENANCE_FIELDS"));
        }
        if self
            .observations
            .iter()
            .any(|o| o.source_id == source_id && o.digest == digest)
        {
            return Ok(IngestResult {
                decision: "DUPLICATE_OBSERVATION",
                equivocation: !self.conflicts.is_empty(),
                conflict_count: self.conflicts.len(),
                external_custody_authenticated: false,
            });
        }
        if self.observations.len() >= 1024 {
            return Err(AuditError("JOURNAL_CAPACITY_HOLD"));
        }
        let pub_id = snapshot.payload.publisher_id.clone();
        let generation = snapshot.payload.generation;
        let others: BTreeSet<_> = self
            .observations
            .iter()
            .filter(|o| {
                o.publisher_id == pub_id && o.generation == generation && o.digest != digest
            })
            .map(|o| o.digest.clone())
            .collect();
        // Mutation is serialized at caller boundary; retain every fork as evidence.
        self.observations.push(Observation {
            publisher_id: pub_id.clone(),
            generation,
            digest: digest.clone(),
            snapshot,
            source_id: source_id.into(),
            ancestry_roots,
        });
        for other in &others {
            if !self.conflicts.iter().any(|c| {
                c.publisher_id == pub_id
                    && c.generation == generation
                    && ((c.digest_a == *other && c.digest_b == digest)
                        || (c.digest_b == *other && c.digest_a == digest))
            }) {
                self.conflicts.push(Conflict {
                    publisher_id: pub_id.clone(),
                    generation,
                    digest_a: other.clone(),
                    digest_b: digest.clone(),
                });
            }
        }
        self.revision = self
            .revision
            .checked_add(1)
            .ok_or(AuditError("REVISION_OVERFLOW"))?;
        Ok(IngestResult {
            decision: "HOLD",
            equivocation: !others.is_empty(),
            conflict_count: self.conflicts.len(),
            external_custody_authenticated: false,
        })
    }

    pub fn assess(
        &self,
        publisher_id: &str,
        generation: u64,
        source_ancestry: &[String],
        pins: &PinRegistry,
    ) -> Result<Assessment> {
        if !valid_id(publisher_id)
            || generation == 0
            || source_ancestry.iter().any(|x| !valid_id(x))
        {
            return Err(AuditError("ASSESSMENT_FIELDS"));
        }
        self.validate(pins)?;
        let records: Vec<_> = self
            .observations
            .iter()
            .filter(|o| o.publisher_id == publisher_id && o.generation == generation)
            .collect();
        let shared = records.iter().enumerate().any(|(i, a)| {
            records.iter().skip(i + 1).any(|b| {
                a.ancestry_roots
                    .iter()
                    .any(|x| b.ancestry_roots.contains(x))
            })
        });
        let source: BTreeSet<_> = source_ancestry.iter().collect();
        Ok(Assessment {
            decision: "HOLD",
            observed_snapshots: records.len(),
            distinct_declared_first_roots: records
                .iter()
                .filter_map(|o| o.ancestry_roots.first())
                .collect::<BTreeSet<_>>()
                .len(),
            conflict_detected: self
                .conflicts
                .iter()
                .any(|c| c.publisher_id == publisher_id && c.generation == generation),
            shared_ancestry_detected: shared,
            source_owned_overlap: records
                .iter()
                .any(|o| o.ancestry_roots.iter().any(|r| source.contains(r))),
            independent_witnesses_authenticated: false,
            publication_freshness_authenticated: false,
            external_finality: false,
            utc_authority: false,
        })
    }
}
