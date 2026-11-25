//! SAPPHON-134: acquisition-time local custody of an exact owner-marker digest.
//! This is a local continuity witness, NOT independent external custody.
//! Neither the record nor a dead PID authorizes lock removal.
use crate::{acquire, owner_path, pinned::{marker_digest, qualify_pinned}, Error, Finding, Owner};
use serde::{Deserialize, Serialize};
use std::{fs::{self, File, OpenOptions}, io::Write, path::Path};

pub const AUTHORITY: &str = "HOLD";
const MAX_CUSTODY_BYTES: u64 = 16 * 1024;
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalPin {
    pub schema: String,
    pub owner_pid: u32,
    pub owner_start_ticks: u64,
    pub owner_boot_id: String,
    pub journal_sha256: String,
    pub marker_sha256: String,
}

fn check_external_path(root: &Path, custody: &Path) -> Result<(), Error> {
    let store = fs::canonicalize(root).map_err(|_| Error("CUSTODY_STORE_UNAVAILABLE"))?;
    let parent = custody.parent().ok_or(Error("CUSTODY_PATH_INVALID"))?;
    let dir = fs::canonicalize(parent).map_err(|_| Error("CUSTODY_PARENT_UNAVAILABLE"))?;
    if dir.starts_with(&store) || custody.file_name().is_none() {
        return Err(Error("CUSTODY_INSIDE_STORE"));
    }
    Ok(())
}
fn owner_pin(owner: &Owner, bytes: &[u8]) -> LocalPin {
    LocalPin {
        schema: "sapphon-134-local-pin-v1".into(),
        owner_pid: owner.pid,
        owner_start_ticks: owner.proc_start_ticks,
        owner_boot_id: owner.boot_id.clone(),
        journal_sha256: owner.journal_sha256.clone(),
        marker_sha256: marker_digest(bytes),
    }
}
/// Acquire an exclusive owner lock, then atomically create a separate local
/// acquisition receipt. A failure deliberately leaves the lock retained.
/// The caller MUST ensure custody-directory permissions before calling.
pub fn acquire_with_local_pin(root: &Path, who: &str, custody: &Path) -> Result<Owner, Error> {
    check_external_path(root, custody)?;
    if fs::symlink_metadata(custody).is_ok() {
        return Err(Error("CUSTODY_ALREADY_EXISTS"));
    }
    let owner = acquire(root, who)?;
    let bytes = fs::read(owner_path(root)).map_err(|_| Error("OWNER_MARKER_MISSING"))?;
    let pin = owner_pin(&owner, &bytes);
    let encoded = serde_json::to_vec_pretty(&pin).map_err(|_| Error("CUSTODY_ENCODING"))?;
    let mut file = OpenOptions::new().write(true).create_new(true).open(custody)
        .map_err(|_| Error("CUSTODY_CREATE_FAILED"))?;
    file.write_all(&encoded).map_err(|_| Error("CUSTODY_WRITE_FAILED"))?;
    file.sync_all().map_err(|_| Error("CUSTODY_FSYNC_FAILED"))?;
    let parent = custody.parent().ok_or(Error("CUSTODY_PATH_INVALID"))?;
    File::open(parent).and_then(|f| f.sync_all())
        .map_err(|_| Error("CUSTODY_DIRSYNC_FAILED"))?;
    Ok(owner)
}
/// Fail closed on local pin substitution, marker rewriting, PID editing,
/// and journal changes. The caller retains the lock in every outcome.
pub fn qualify_local_pin(root: &Path, custody: &Path) -> Result<Finding, Error> {
    check_external_path(root, custody)?;
    let meta = fs::symlink_metadata(custody).map_err(|_| Error("CUSTODY_MISSING"))?;
    if !meta.file_type().is_file() || meta.len() > MAX_CUSTODY_BYTES {
        return Err(Error("CUSTODY_INVALID"));
    }
    let bytes = fs::read(custody).map_err(|_| Error("CUSTODY_UNREADABLE"))?;
    let pin: LocalPin = serde_json::from_slice(&bytes).map_err(|_| Error("CUSTODY_CORRUPT"))?;
    if pin.schema != "sapphon-134-local-pin-v1" || pin.owner_pid == 0 || pin.owner_start_ticks == 0 {
        return Err(Error("CUSTODY_FIELDS"));
    }
    let finding = qualify_pinned(root, &pin.marker_sha256)?;
    let owner = crate::read_owner(root)?;
    if owner.pid != pin.owner_pid || owner.proc_start_ticks != pin.owner_start_ticks
        || owner.boot_id != pin.owner_boot_id || owner.journal_sha256 != pin.journal_sha256
        || finding.lock_cleared || finding.external_authority || finding.decision != "HOLD"
    {
        return Err(Error("CUSTODY_IDENTITY_CONFLICT"));
    }
    if fs::read(custody).map_err(|_| Error("CUSTODY_UNREADABLE"))? != bytes {
        return Err(Error("CUSTODY_CHANGED"));
    }
    Ok(finding)
}
