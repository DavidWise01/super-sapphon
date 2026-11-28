//! SAPPHON-137 — append-only local key-registry journal.
//! Hash chaining detects mutation only when an independently trusted head is supplied.
//! A local file, hash, counter, or self-supplied head is NOT global anti-rollback.
use crate::{attest136::TrustedKey, Error};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::Write,
    path::Path,
};

pub const AUTHORITY: &str = "HOLD";
const MAX_BYTES: u64 = 1024 * 1024;
pub const GENESIS: &str = "sapphon-137-genesis-v1";
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Event {
    pub schema: String,
    pub seq: u64,
    pub prev_hash: String,
    pub kind: String,
    pub witness_id: String,
    pub ancestry_root: String,
    pub public_key_hex: String,
    pub counter_floor: u64,
}
#[derive(Debug, Clone)]
pub struct Snapshot {
    pub seq: u64,
    pub head: String,
    pub keys: Vec<TrustedKey>,
}
fn hash(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
fn name(s: &str) -> bool {
    (4..=96).contains(&s.len())
        && s.bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-' || c == b'_')
}
fn validate(e: &Event) -> Result<(), Error> {
    if e.schema != "sapphon-137-registry-event-v1"
        || !["register", "advance", "revoke"].contains(&e.kind.as_str())
        || !name(&e.witness_id)
        || !name(&e.ancestry_root)
        || e.public_key_hex.len() != 64
        || !e
            .public_key_hex
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    {
        return Err(Error("REGISTRY_FIELDS"));
    }
    let bytes = hex::decode(&e.public_key_hex).map_err(|_| Error("REGISTRY_KEY"))?;
    let array: [u8; 32] = bytes.try_into().map_err(|_| Error("REGISTRY_KEY"))?;
    ed25519_dalek::VerifyingKey::from_bytes(&array).map_err(|_| Error("REGISTRY_KEY"))?;
    Ok(())
}
fn fold(events: &[Event]) -> Result<Snapshot, Error> {
    if events.len() > 2048 {
        return Err(Error("REGISTRY_LIMIT"));
    }
    let mut keys: BTreeMap<String, TrustedKey> = BTreeMap::new();
    let mut prior = hash(GENESIS.as_bytes());
    for (i, e) in events.iter().enumerate() {
        validate(e)?;
        if e.seq != (i as u64) + 1 || e.prev_hash != prior {
            return Err(Error("REGISTRY_CHAIN"));
        }
        if e.kind == "register" {
            if keys.contains_key(&e.witness_id) {
                return Err(Error("REGISTRY_TRANSITION"));
            }
            if keys.values().any(|k| k.public_key_hex == e.public_key_hex) {
                return Err(Error("REGISTRY_DUPLICATE_KEY"));
            }
            keys.insert(
                e.witness_id.clone(),
                TrustedKey {
                    witness_id: e.witness_id.clone(),
                    ancestry_root: e.ancestry_root.clone(),
                    public_key_hex: e.public_key_hex.clone(),
                    revoked: false,
                    min_counter: e.counter_floor,
                },
            );
        } else {
            let k = keys
                .get_mut(&e.witness_id)
                .ok_or(Error("REGISTRY_TRANSITION"))?;
            if k.revoked
                || k.ancestry_root != e.ancestry_root
                || k.public_key_hex != e.public_key_hex
                || (e.kind == "advance" && e.counter_floor <= k.min_counter)
                || (e.kind == "revoke" && e.counter_floor < k.min_counter)
            {
                return Err(Error("REGISTRY_TRANSITION"));
            }
            k.min_counter = e.counter_floor;
            if e.kind == "revoke" {
                k.revoked = true;
            }
        }
        let encoded = serde_json::to_vec(e).map_err(|_| Error("REGISTRY_ENCODING"))?;
        prior = hash(&encoded);
    }
    Ok(Snapshot {
        seq: events.len() as u64,
        head: prior,
        keys: keys.into_values().collect(),
    })
}
/// Parses the entire append-only transcript, requiring an externally pinned
/// exact sequence AND head. Neither anchor can originate from this file.
pub fn verify(bytes: &[u8], anchored_seq: u64, anchored_head: &str) -> Result<Snapshot, Error> {
    if bytes.len() > MAX_BYTES as usize {
        return Err(Error("REGISTRY_TOO_LARGE"));
    }
    let events: Vec<Event> = if bytes.is_empty() {
        vec![]
    } else {
        if *bytes.last().unwrap() != b'\n' {
            return Err(Error("REGISTRY_TRUNCATED"));
        }
        bytes
            .split(|b| *b == b'\n')
            .filter(|b| !b.is_empty())
            .map(|line| serde_json::from_slice(line).map_err(|_| Error("REGISTRY_CORRUPT")))
            .collect::<Result<_, _>>()?
    };
    let state = fold(&events)?;
    if state.seq != anchored_seq || state.head != anchored_head {
        return Err(Error("REGISTRY_ANCHOR_MISMATCH"));
    }
    Ok(state)
}
pub fn genesis_head() -> String {
    hash(GENESIS.as_bytes())
}
/// Generate next entry against externally validated state. No key change can
/// un-revoke a key or lower its counter floor.
pub fn next(
    state: &Snapshot,
    kind: &str,
    id: &str,
    ancestry: &str,
    public_key_hex: &str,
    floor: u64,
) -> Event {
    Event {
        schema: "sapphon-137-registry-event-v1".into(),
        seq: state.seq + 1,
        prev_hash: state.head.clone(),
        kind: kind.into(),
        witness_id: id.into(),
        ancestry_root: ancestry.into(),
        public_key_hex: public_key_hex.into(),
        counter_floor: floor,
    }
}
/// Local durable append. Caller MUST hold an exclusive writer lock and
/// independently persist the new {sequence,head}; neither is provided here.
/// The caller must supply a verified existing snapshot and file contents.
pub fn append_checked(
    path: &Path,
    old: &[u8],
    anchor_seq: u64,
    anchor_head: &str,
    event: &Event,
) -> Result<Snapshot, Error> {
    let current = verify(old, anchor_seq, anchor_head)?;
    if event.prev_hash != current.head || event.seq != current.seq + 1 {
        return Err(Error("REGISTRY_CHAIN"));
    }
    let mut all = old.to_vec();
    if !all.is_empty() && all.last() != Some(&b'\n') {
        return Err(Error("REGISTRY_TRUNCATED"));
    }
    all.extend(serde_json::to_vec(event).map_err(|_| Error("REGISTRY_ENCODING"))?);
    all.push(b'\n');
    // Validate the whole candidate before touching the file.
    let events: Vec<Event> = all
        .split(|b| *b == b'\n')
        .filter(|b| !b.is_empty())
        .map(|line| serde_json::from_slice(line).map_err(|_| Error("REGISTRY_CORRUPT")))
        .collect::<Result<_, _>>()?;
    let updated = fold(&events)?;
    let disk = fs::read(path).map_err(|_| Error("REGISTRY_UNREADABLE"))?;
    if disk != old {
        return Err(Error("REGISTRY_CONCURRENT_CHANGE"));
    }
    let mut handle = OpenOptions::new()
        .append(true)
        .open(path)
        .map_err(|_| Error("REGISTRY_UNREADABLE"))?;
    handle
        .write_all(&all[old.len()..])
        .map_err(|_| Error("REGISTRY_WRITE_FAILED"))?;
    handle
        .sync_all()
        .map_err(|_| Error("REGISTRY_FSYNC_FAILED"))?;
    Ok(updated)
}
pub fn create_empty(path: &Path) -> Result<Snapshot, Error> {
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|_| Error("REGISTRY_ALREADY_EXISTS"))?;
    file.sync_all()
        .map_err(|_| Error("REGISTRY_FSYNC_FAILED"))?;
    let parent = path.parent().ok_or(Error("REGISTRY_PARENT"))?;
    File::open(parent)
        .and_then(|f| f.sync_all())
        .map_err(|_| Error("REGISTRY_DIRSYNC_FAILED"))?;
    Ok(Snapshot {
        seq: 0,
        head: genesis_head(),
        keys: vec![],
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    fn key(seed: u8) -> String {
        hex::encode(
            SigningKey::from_bytes(&[seed; 32])
                .verifying_key()
                .as_bytes(),
        )
    }
    fn line(e: &Event) -> Vec<u8> {
        let mut v = serde_json::to_vec(e).unwrap();
        v.push(b'\n');
        v
    }
    #[test]
    fn restart_replay_revocation_and_rollback_hold() {
        let zero = verify(&[], 0, &genesis_head()).unwrap();
        let a = next(&zero, "register", "witness-one", "root-one", &key(1), 0);
        let bytes = line(&a);
        let s = fold(&[a.clone()]).unwrap();
        let after_restart = verify(&bytes, 1, &s.head).unwrap();
        assert_eq!(after_restart.keys.len(), 1);
        let r = next(
            &after_restart,
            "revoke",
            "witness-one",
            "root-one",
            &key(1),
            4,
        );
        let mut full = bytes.clone();
        full.extend(line(&r));
        let later = fold(&[a, r]).unwrap();
        assert!(verify(&full, 2, &later.head).unwrap().keys[0].revoked);
        assert_eq!(
            verify(&bytes, 2, &later.head).unwrap_err().0,
            "REGISTRY_ANCHOR_MISMATCH"
        );
        assert_eq!(
            verify(&full, 1, &s.head).unwrap_err().0,
            "REGISTRY_ANCHOR_MISMATCH"
        );
    }
    #[test]
    fn cannot_unrevoke_or_lower_floor() {
        let a = next(
            &verify(&[], 0, &genesis_head()).unwrap(),
            "register",
            "witness-one",
            "root-one",
            &key(1),
            5,
        );
        let s = fold(&[a.clone()]).unwrap();
        let lower = next(&s, "advance", "witness-one", "root-one", &key(1), 4);
        assert_eq!(
            fold(&[a.clone(), lower]).unwrap_err().0,
            "REGISTRY_TRANSITION"
        );
        let revoked = next(&s, "revoke", "witness-one", "root-one", &key(1), 6);
        let s2 = fold(&[a.clone(), revoked.clone()]).unwrap();
        let resurrect = next(&s2, "advance", "witness-one", "root-one", &key(1), 7);
        assert_eq!(
            fold(&[a, revoked, resurrect]).unwrap_err().0,
            "REGISTRY_TRANSITION"
        );
    }
    #[test]
    fn missing_newline_and_tampered_body_rejected() {
        let zero = verify(&[], 0, &genesis_head()).unwrap();
        let a = next(&zero, "register", "witness-one", "root-one", &key(1), 1);
        let body = serde_json::to_vec(&a).unwrap();
        assert_eq!(
            verify(&body, 1, &genesis_head()).unwrap_err().0,
            "REGISTRY_TRUNCATED"
        );
        let mut broken = line(&a);
        broken[3] = b'X';
        assert!(verify(&broken, 1, &genesis_head()).is_err());
    }
    #[test]
    fn durable_append_reload_and_replay_rejection() {
        let dir = std::env::temp_dir().join(format!("sapphon137-registry-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("ledger.jsonl");
        let _ = std::fs::remove_file(&path);
        let zero = create_empty(&path).unwrap();
        let event = next(&zero, "register", "witness-one", "root-one", &key(1), 3);
        let saved = append_checked(&path, &[], 0, &zero.head, &event).unwrap();
        assert_eq!(saved.seq, 1);
        let disk = std::fs::read(&path).unwrap();
        let restarted = verify(&disk, 1, &saved.head).unwrap();
        assert_eq!(restarted.keys[0].min_counter, 3);
        assert_eq!(
            verify(&disk, 0, &zero.head).unwrap_err().0,
            "REGISTRY_ANCHOR_MISMATCH"
        );
        let same = next(&restarted, "advance", "witness-one", "root-one", &key(1), 3);
        assert_eq!(
            append_checked(&path, &disk, 1, &saved.head, &same)
                .unwrap_err()
                .0,
            "REGISTRY_TRANSITION"
        );
        std::fs::remove_file(&path).unwrap();
        std::fs::remove_dir(&dir).unwrap();
    }
}
