//! SAPPHON-129: durable local observation journal.
//!
//! One directory lock guards read–verify–revision-check–write. The replacement
//! file is fsynced, renamed over journal.json, then the directory is fsynced.
//! Crashes before rename retain the old complete journal; after rename can
//! leave an unknown acknowledgement, resolved by readback and revision check.
//! Local disk integrity is NOT proof of independent custody or global anti-rollback.
use sapphon_audit::{AuditError, IngestResult, Journal, PinRegistry, SignedSnapshot};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};
static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);
const MAX_FILE: u64 = 16 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fault {
    None,
    BeforeRename,
    AfterRename,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreError(pub &'static str);
impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}
impl std::error::Error for StoreError {}
impl From<AuditError> for StoreError {
    fn from(_: AuditError) -> Self {
        StoreError("SIGNATURE_OR_JOURNAL_INVALID")
    }
}
type Result<T> = std::result::Result<T, StoreError>;

fn failed(error: &'static str) -> StoreError {
    StoreError(error)
}
struct Lock {
    path: PathBuf,
}
impl Lock {
    fn acquire(root: &Path) -> Result<Self> {
        if !root.is_dir() {
            return Err(failed("STORE_MISSING"));
        }
        let path = root.join(".exclusive-lock");
        fs::create_dir(&path).map_err(|_| failed("STORE_BUSY"))?;
        Ok(Self { path })
    }
}
impl Drop for Lock {
    fn drop(&mut self) {
        // If cleanup fails, the lock remains and future transactions HOLD.
        let _ = fs::remove_dir(&self.path);
    }
}
struct Temporary {
    path: PathBuf,
}
impl Drop for Temporary {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}
fn journal_path(root: &Path) -> PathBuf {
    root.join("journal.json")
}
fn read_locked(root: &Path, pins: &PinRegistry) -> Result<Journal> {
    let file = journal_path(root);
    let mut fd = File::open(&file).map_err(|_| failed("JOURNAL_UNREADABLE"))?;
    let size = fd
        .metadata()
        .map_err(|_| failed("JOURNAL_UNREADABLE"))?
        .len();
    if size > MAX_FILE {
        return Err(failed("JOURNAL_TOO_LARGE"));
    }
    let mut bytes = Vec::new();
    fd.read_to_end(&mut bytes)
        .map_err(|_| failed("JOURNAL_UNREADABLE"))?;
    let journal: Journal = serde_json::from_slice(&bytes).map_err(|_| failed("JOURNAL_CORRUPT"))?;
    journal.validate(pins)?;
    Ok(journal)
}
fn save_locked(root: &Path, journal: &Journal, fault: Fault) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(journal).map_err(|_| failed("JOURNAL_SERIALIZATION"))?;
    if bytes.len() as u64 > MAX_FILE {
        return Err(failed("JOURNAL_TOO_LARGE"));
    }
    let name = format!(
        ".journal-{}-{}",
        std::process::id(),
        NEXT_TEMP.fetch_add(1, Ordering::SeqCst)
    );
    let tmp = Temporary {
        path: root.join(name),
    };
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&tmp.path)
        .map_err(|_| failed("TEMP_CREATE_FAILED"))?;
    output
        .write_all(&bytes)
        .map_err(|_| failed("TEMP_WRITE_FAILED"))?;
    output.sync_all().map_err(|_| failed("TEMP_FSYNC_FAILED"))?;
    drop(output);
    if fault == Fault::BeforeRename {
        return Err(failed("INJECTED_BEFORE_RENAME"));
    }
    fs::rename(&tmp.path, journal_path(root)).map_err(|_| failed("ATOMIC_RENAME_FAILED"))?;
    if fault == Fault::AfterRename {
        // A crash now could leave the new file or the previous one on disk,
        // depending on filesystem crash semantics. Never claim durability.
        return Err(failed("INJECTED_AFTER_RENAME"));
    }
    File::open(root)
        .and_then(|dir| dir.sync_all())
        .map_err(|_| failed("DIRECTORY_FSYNC_FAILED"))?;
    Ok(())
}

/// Initialize an empty, signed-observation journal. Refuses existing stores.
pub fn initialize(root: &Path, pins: &PinRegistry) -> Result<()> {
    fs::create_dir_all(root).map_err(|_| failed("STORE_CREATE_FAILED"))?;
    let _lock = Lock::acquire(root)?;
    if journal_path(root).exists() {
        return Err(failed("JOURNAL_ALREADY_EXISTS"));
    }
    let empty = Journal::default();
    empty.validate(pins)?;
    save_locked(root, &empty, Fault::None)
}
/// Verify the entire journal before returning a current local observation.
pub fn inspect(root: &Path, pins: &PinRegistry) -> Result<Journal> {
    let _lock = Lock::acquire(root)?;
    read_locked(root, pins)
}
/// Atomically append one signed observation if expected_revision matches.
/// A duplicate is idempotent and does not consume a new revision.
pub fn append(
    root: &Path,
    pins: &PinRegistry,
    expected_revision: u64,
    signed: SignedSnapshot,
    source_id: &str,
    ancestry_roots: Vec<String>,
    fault: Fault,
) -> Result<IngestResult> {
    let _lock = Lock::acquire(root)?;
    let mut current = read_locked(root, pins)?;
    if current.revision != expected_revision {
        return Err(failed("REVISION_CONFLICT"));
    }
    let old = current.revision;
    let result = current.ingest(signed, source_id, ancestry_roots, pins)?;
    if current.revision == old {
        return Ok(result);
    }
    current.validate(pins)?;
    save_locked(root, &current, fault)?;
    Ok(result)
}
/// No API for deleting evidence, rewriting a historical entry or promoting
/// synthetic observations to real-world authorization.
pub const EXTERNAL_AUTHORITY: &str = "HOLD";
