//! SAPPHON-132: Linux OS process identity observation for retained journal locks.
//! Never interpret the operator's signed "exited" boolean as independent proof.
//! No lock is automatically stolen or cleared by this module.
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Write},
    path::Path,
};
pub const AUTHORITY: &str = "HOLD";
pub mod custody;
pub mod pinned;
pub mod witness135;
pub mod attest136;
pub mod registry137;
pub mod fence138;
#[cfg(target_os = "linux")]
pub mod writer139;
#[cfg(target_os = "linux")]
pub mod checkpoint140;
#[cfg(target_os = "linux")]
pub mod equivocation141;
#[cfg(target_os = "linux")]
pub mod export142;
#[cfg(target_os = "linux")]
pub mod quarantine143;
#[cfg(target_os = "linux")]
pub mod freeze144;
#[cfg(target_os = "linux")]
pub mod anchor145;
#[cfg(target_os = "linux")]
pub mod dual_anchor146;
#[cfg(target_os = "linux")]
pub mod lineage147;
#[cfg(target_os = "linux")]
pub mod failover148;
#[cfg(target_os = "linux")]
pub mod replay149;
#[cfg(target_os = "linux")]
pub mod substitution150;
#[cfg(target_os = "linux")]
pub mod blind151;
#[cfg(target_os = "linux")]
pub mod freeze152;
#[cfg(target_os = "linux")]
pub mod qualification153;
#[cfg(target_os = "linux")]
pub mod readback154;
#[cfg(target_os = "linux")]
pub mod artifact155;
#[cfg(target_os = "linux")]
pub mod custody156;
#[cfg(target_os = "linux")]
pub mod enrollment157;
#[cfg(target_os = "linux")]
pub mod challenge158;
#[cfg(target_os = "linux")]
pub mod nonce159;
#[cfg(target_os = "linux")]
pub mod freeze160;
#[cfg(target_os = "linux")]
pub mod diagnostic161;
#[cfg(target_os = "linux")]
pub mod triage162;
#[cfg(target_os = "linux")]
pub mod parity163;
#[cfg(target_os = "linux")]
pub mod candidate166;
#[cfg(target_os = "linux")]
pub mod promotion167;
#[cfg(target_os = "linux")]
pub mod freeze168;
#[cfg(target_os = "linux")]
pub mod runtime169;
#[cfg(target_os = "linux")]
pub mod isolate170;
#[cfg(target_os = "linux")]
pub mod joblog171;
#[cfg(target_os = "linux")]
pub mod reconcile172;
#[cfg(target_os = "linux")]
pub mod steps173;
#[cfg(target_os = "linux")]
pub mod outcomes174;
#[cfg(target_os = "linux")]
pub mod runner175;
#[cfg(target_os = "linux")]
pub mod freeze176;
#[cfg(target_os = "linux")]
pub mod evidence177;
#[cfg(target_os = "linux")]
pub mod isolation178;
#[cfg(target_os = "linux")]
pub mod replay179;
#[cfg(target_os = "linux")]
pub mod binding180;
#[cfg(target_os = "linux")]
pub mod archive181;
#[cfg(target_os = "linux")]
pub mod crossfile182;
#[cfg(target_os = "linux")]
pub mod contradictions183;
#[cfg(target_os = "linux")]
pub mod freeze184;
#[cfg(target_os = "linux")]
pub mod observed185;
#[cfg(target_os = "linux")]
pub mod attempts186;
#[cfg(target_os = "linux")]
pub mod retention187;
#[cfg(target_os = "linux")]
pub mod retention187;
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error(pub &'static str);
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}
impl std::error::Error for Error {}
type Result<T> = std::result::Result<T, Error>;
fn fail(s: &'static str) -> Error {
    Error(s)
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Owner {
    pub schema: String,
    pub pid: u32,
    pub proc_start_ticks: u64,
    pub boot_id: String,
    pub journal_sha256: String,
    pub acquired_by: String,
}
fn valid_id(s: &str) -> bool {
    (4..=64).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}
fn valid_sha(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn validate(o: &Owner) -> Result<()> {
    if o.schema != "sapphon-132-linux-lock-owner-v1"
        || o.pid == 0
        || o.proc_start_ticks == 0
        || o.boot_id.len() < 8
        || o.boot_id.len() > 80
        || !o
            .boot_id
            .bytes()
            .all(|b| b.is_ascii_hexdigit() || b == b'-')
        || !valid_sha(&o.journal_sha256)
        || !valid_id(&o.acquired_by)
    {
        return Err(fail("OWNER_FIELDS"));
    }
    Ok(())
}
fn boot_id() -> Result<String> {
    fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .map(|s| s.trim().to_string())
        .map_err(|_| fail("BOOT_UNAVAILABLE"))
}
/// /proc/<pid>/stat field 22 is process starttime in clock ticks. The
/// comm field (2) may contain whitespace and parentheses; split after LAST ')'.
pub fn parse_linux_stat(stat: &str) -> Result<(char, u64)> {
    let close = stat.rfind(')').ok_or(fail("PROC_STAT_INVALID"))?;
    let after = stat.get(close + 1..).ok_or(fail("PROC_STAT_INVALID"))?;
    let fields: Vec<&str> = after.split_whitespace().collect();
    if fields.len() <= 19 {
        return Err(fail("PROC_STAT_INVALID"));
    }
    let state = fields[0].chars().next().ok_or(fail("PROC_STAT_INVALID"))?;
    let start = fields[19]
        .parse::<u64>()
        .map_err(|_| fail("PROC_STAT_INVALID"))?;
    if start == 0 {
        return Err(fail("PROC_STAT_INVALID"));
    }
    Ok((state, start))
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Identity {
    Alive,
    Dead,
    Unknown,
}
pub fn observe_identity(owner: &Owner) -> Result<Identity> {
    validate(owner)?;
    if boot_id()? != owner.boot_id {
        return Ok(Identity::Unknown);
    }
    let path = format!("/proc/{}/stat", owner.pid);
    let body = match fs::read_to_string(path) {
        Ok(v) => v,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Identity::Dead),
        Err(_) => return Ok(Identity::Unknown),
    };
    let (state, start) = parse_linux_stat(&body)?;
    if start != owner.proc_start_ticks {
        return Ok(Identity::Dead);
    }
    if state == 'Z' || state == 'X' {
        return Ok(Identity::Dead);
    }
    Ok(Identity::Alive)
}
pub fn owner_path(root: &Path) -> std::path::PathBuf {
    root.join(".exclusive-lock").join("owner.json")
}
pub fn journal_hash(root: &Path) -> Result<String> {
    let bytes = fs::read(root.join("journal.json")).map_err(|_| fail("JOURNAL_UNREADABLE"))?;
    if bytes.len() > 16 * 1024 * 1024 {
        return Err(fail("JOURNAL_TOO_LARGE"));
    }
    let _: sapphon_audit::Journal =
        serde_json::from_slice(&bytes).map_err(|_| fail("JOURNAL_CORRUPT"))?;
    Ok(hex::encode(Sha256::digest(bytes)))
}
/// Acquire one exclusive directory and publish the *actual* current Linux
/// process's PID, boot id and /proc starttime, then fsync marker + directory.
pub fn acquire(root: &Path, who: &str) -> Result<Owner> {
    if !valid_id(who) {
        return Err(fail("OWNER_FIELDS"));
    }
    if !root.is_dir() {
        return Err(fail("STORE_MISSING"));
    }
    let lock = root.join(".exclusive-lock");
    fs::create_dir(&lock).map_err(|_| fail("STORE_BUSY"))?;
    // On metadata acquisition failures we intentionally leave a lock behind
    // rather than risk a competing process taking it.
    let pid = std::process::id();
    let stat =
        fs::read_to_string(format!("/proc/{pid}/stat")).map_err(|_| fail("PROC_UNAVAILABLE"))?;
    let (_, start) = parse_linux_stat(&stat)?;
    let owner = Owner {
        schema: "sapphon-132-linux-lock-owner-v1".into(),
        pid,
        proc_start_ticks: start,
        boot_id: boot_id()?,
        journal_sha256: journal_hash(root)?,
        acquired_by: who.into(),
    };
    validate(&owner)?;
    let bytes = serde_json::to_vec_pretty(&owner).map_err(|_| fail("OWNER_ENCODING"))?;
    let marker = owner_path(root);
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(marker)
        .map_err(|_| fail("OWNER_MARKER_FAILED"))?;
    file.write_all(&bytes)
        .map_err(|_| fail("OWNER_MARKER_FAILED"))?;
    file.sync_all().map_err(|_| fail("OWNER_FSYNC_FAILED"))?;
    File::open(&lock)
        .and_then(|f| f.sync_all())
        .map_err(|_| fail("OWNER_DIRSYNC_FAILED"))?;
    File::open(root)
        .and_then(|f| f.sync_all())
        .map_err(|_| fail("OWNER_DIRSYNC_FAILED"))?;
    Ok(owner)
}
pub fn read_owner(root: &Path) -> Result<Owner> {
    let data = fs::read(owner_path(root)).map_err(|_| fail("OWNER_MARKER_MISSING"))?;
    let o: Owner = serde_json::from_slice(&data).map_err(|_| fail("OWNER_MARKER_CORRUPT"))?;
    validate(&o)?;
    Ok(o)
}
#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct Finding {
    pub decision: &'static str,
    pub owner_pid: u32,
    pub owner_start_ticks: u64,
    pub journal_sha256: String,
    pub os_observation: &'static str,
    pub eligible_for_signed_review: bool,
    pub lock_cleared: bool,
    pub external_authority: bool,
}
/// A positive finding is **only** a candidate for a separate signed human
/// review: this operation does NOT clear the lock or sign a receipt.
/// Callers must also check the journal digest and operator receipt.
pub fn qualify(root: &Path) -> Result<Finding> {
    let o = read_owner(root)?;
    let observed = observe_identity(&o)?;
    if journal_hash(root)? != o.journal_sha256 {
        return Err(fail("OWNER_JOURNAL_CONFLICT"));
    }
    let (status, eligible) = match observed {
        Identity::Alive => ("ALIVE", false),
        Identity::Dead => ("DEAD", true),
        Identity::Unknown => ("UNKNOWN", false),
    };
    Ok(Finding {
        decision: "HOLD",
        owner_pid: o.pid,
        owner_start_ticks: o.proc_start_ticks,
        journal_sha256: o.journal_sha256,
        os_observation: status,
        eligible_for_signed_review: eligible,
        lock_cleared: false,
        external_authority: false,
    })
}
