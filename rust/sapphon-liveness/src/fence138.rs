//! SAPPHON-138: Linux descriptor-bound, cooperative registry fencing.
//! No local file or caller-supplied anchor certifies independent custody.
//! The guard is observation-only and never permits recovery or lock removal.
#[cfg(target_os = "linux")]
mod linux {
    use crate::{registry137::{self, Snapshot}, Error};
    use std::{fs::{self, File, OpenOptions}, io::Read,
        os::{fd::AsRawFd, unix::fs::{MetadataExt, OpenOptionsExt}},
        path::Path};
    pub const AUTHORITY: &str = "HOLD";
    const LIMIT: u64 = 1024 * 1024;
    // Linux O_NOFOLLOW. Open failure must fail closed.
    const NOFOLLOW: i32 = 0o400000;
    const CLOEXEC: i32 = 0o2000000;

    /// Exclusive flock is advisory: every writer must cooperate.
    /// Keeping the descriptor alive keeps the lock held.
    pub struct Guard {
        file: File,
        dev: u64,
        ino: u64,
    }
    impl Guard {
        pub fn open(path: &Path) -> Result<Self, Error> {
            let mut options = OpenOptions::new();
            options.read(true).custom_flags(NOFOLLOW | CLOEXEC);
            let file = options.open(path).map_err(|_| Error("FENCE_OPEN_DENIED"))?;
            let meta = file.metadata().map_err(|_| Error("FENCE_METADATA"))?;
            if !meta.is_file() || meta.nlink() != 1 || meta.len() > LIMIT {
                return Err(Error("FENCE_UNSAFE_FILE"));
            }
            let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
            if result != 0 { return Err(Error("FENCE_BUSY")); }
            Ok(Self { file, dev: meta.dev(), ino: meta.ino() })
        }
        /// Require the pathname still identifies this inode. A hostile
        /// uncooperative writer can still mutate bytes or replace paths.
        pub fn verify(&mut self, path: &Path, seq: u64, head: &str)
            -> Result<Snapshot, Error> {
            let named = fs::symlink_metadata(path).map_err(|_| Error("FENCE_PATH_CHANGED"))?;
            if !named.is_file() || named.dev() != self.dev || named.ino() != self.ino {
                return Err(Error("FENCE_PATH_CHANGED"));
            }
            let meta = self.file.metadata().map_err(|_| Error("FENCE_METADATA"))?;
            if meta.len() > LIMIT || meta.dev() != self.dev || meta.ino() != self.ino {
                return Err(Error("FENCE_UNSAFE_FILE"));
            }
            let mut bytes = Vec::new();
            let mut handle = &self.file;
            // File::try_clone shares the offset: use positional read instead.
            use std::os::unix::fs::FileExt;
            let mut offset = 0u64;
            while offset < LIMIT + 1 {
                let mut block = [0u8;8192];
                let got = self.file.read_at(&mut block, offset)
                    .map_err(|_| Error("FENCE_READ"))?;
                if got == 0 { break; }
                bytes.extend_from_slice(&block[..got]);
                offset += got as u64;
            }
            if bytes.len() as u64 > LIMIT { return Err(Error("REGISTRY_TOO_LARGE")); }
            let state = registry137::verify(&bytes, seq, head)?;
            let after = fs::symlink_metadata(path).map_err(|_| Error("FENCE_PATH_CHANGED"))?;
            let descriptor = self.file.metadata().map_err(|_| Error("FENCE_METADATA"))?;
            if after.dev() != self.dev || after.ino() != self.ino ||
               descriptor.dev() != self.dev || descriptor.ino() != self.ino ||
               descriptor.len() != bytes.len() as u64 {
                return Err(Error("FENCE_PATH_CHANGED"));
            }
            Ok(state)
        }
    }
    #[cfg(test)]
    mod tests {
        use super::*;
        use std::os::unix::fs::symlink;
        use std::io::Write;
        fn temp(name: &str) -> std::path::PathBuf {
            std::env::temp_dir().join(format!("sapphon138-{name}-{}",std::process::id()))
        }
        #[test] fn symlink_is_not_trusted() {
            let real=temp("real"); let link=temp("link");
            fs::write(&real,b"").unwrap();let _=fs::remove_file(&link);
            symlink(&real,&link).unwrap();
            assert_eq!(Guard::open(&link).err().unwrap().0,"FENCE_OPEN_DENIED");
            fs::remove_file(link).unwrap();fs::remove_file(real).unwrap();
        }
        #[test] fn two_cooperative_writers_cannot_hold_lock() {
            let p=temp("flock");fs::write(&p,b"").unwrap();
            let _first=Guard::open(&p).unwrap();
            assert_eq!(Guard::open(&p).err().unwrap().0,"FENCE_BUSY");
            fs::remove_file(p).unwrap();
        }
        #[test] fn pathname_swap_fails_closed() {
            let p=temp("swap");let moved=temp("moved");
            let _=fs::remove_file(&moved);
            fs::write(&p,b"").unwrap();
            let mut guard=Guard::open(&p).unwrap();
            fs::rename(&p,&moved).unwrap();
            fs::write(&p,b"").unwrap();
            assert_eq!(guard.verify(&p,0,&registry137::genesis_head()).unwrap_err().0,
                "FENCE_PATH_CHANGED");
            fs::remove_file(p).unwrap();fs::remove_file(moved).unwrap();
        }
        #[test] fn trusted_anchor_mismatch_fails_closed() {
            let p=temp("anchor");fs::write(&p,b"").unwrap();
            let mut guard=Guard::open(&p).unwrap();
            assert_eq!(guard.verify(&p,1,&registry137::genesis_head()).unwrap_err().0,
                "REGISTRY_ANCHOR_MISMATCH");
            assert_eq!(guard.verify(&p,0,&registry137::genesis_head()).unwrap().seq,0);
            fs::remove_file(p).unwrap();
        }
    }
}
#[cfg(target_os = "linux")]
pub use linux::{Guard, AUTHORITY};
