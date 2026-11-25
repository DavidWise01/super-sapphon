//! SAPPHON-139: supervised, descriptor-bound, single-writer local registry append.
//! Local fsync is not an external checkpoint acknowledgement.
//! A partial write remains quarantined; never silently truncate or authorize recovery.
#![cfg(target_os = "linux")]
use crate::{registry137::{self, Event}, Error};
use std::{fs::{self, File, OpenOptions}, os::{fd::AsRawFd, unix::fs::{FileExt, MetadataExt, OpenOptionsExt}}, path::{Path, PathBuf}};
pub const AUTHORITY: &str = "HOLD";
const O_NOFOLLOW: i32 = libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK;
const LIMIT: usize = 1024*1024;

pub struct SupervisedWriter {
    file: File, path: PathBuf, dev: u64, ino: u64,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingCheckpoint {
    pub seq: u64, pub head: String,
    pub local_fsync_observed: bool,
    pub external_checkpoint_acknowledged: bool,
    pub decision: &'static str,
    pub lock_cleared: bool,
}
impl SupervisedWriter {
    pub fn open(path: &Path) -> Result<Self, Error> {
        let file=OpenOptions::new().read(true).write(true)
            .custom_flags(O_NOFOLLOW).open(path).map_err(|_|Error("WRITER_OPEN_DENIED"))?;
        let m=file.metadata().map_err(|_|Error("WRITER_METADATA"))?;
        if !m.is_file() || m.nlink()!=1 || m.len()>LIMIT as u64 {
            return Err(Error("WRITER_UNSAFE_FILE"));
        }
        if unsafe { libc::flock(file.as_raw_fd(),libc::LOCK_EX|libc::LOCK_NB) } != 0 {
            return Err(Error("WRITER_BUSY"));
        }
        let me=Self{file,path:path.to_path_buf(),dev:m.dev(),ino:m.ino()};
        me.check_path()?;
        Ok(me)
    }
    fn check_path(&self)->Result<(),Error>{
        let p=fs::symlink_metadata(&self.path).map_err(|_|Error("WRITER_PATH_CHANGED"))?;
        let m=self.file.metadata().map_err(|_|Error("WRITER_METADATA"))?;
        if !p.is_file() || p.nlink()!=1 || p.dev()!=self.dev || p.ino()!=self.ino
            || m.dev()!=self.dev || m.ino()!=self.ino {
            return Err(Error("WRITER_PATH_CHANGED"));
        }
        Ok(())
    }
    fn read_all(&self)->Result<Vec<u8>,Error>{
        self.check_path()?;
        let mut body=Vec::new();let mut offset=0u64;
        loop {
            let mut b=[0u8;8192];
            let n=self.file.read_at(&mut b,offset).map_err(|_|Error("WRITER_READ"))?;
            if n==0 {break;}
            body.extend_from_slice(&b[..n]);offset+=n as u64;
            if body.len()>LIMIT {return Err(Error("REGISTRY_TOO_LARGE"));}
        }
        self.check_path()?;
        if self.file.metadata().map_err(|_|Error("WRITER_METADATA"))?.len()!=body.len() as u64 {
            return Err(Error("WRITER_CONCURRENT_CHANGE"));
        }
        Ok(body)
    }
    /// Fails before writing unless externally pinned anchor matches the bytes
    /// on the originally opened, locked descriptor. A write may still partially
    /// succeed on storage failure; recovery must re-verify and remain HOLD.
    pub fn append(&mut self, anchored_seq:u64, anchored_head:&str,
                  event:&Event) -> Result<PendingCheckpoint,Error> {
        let before=self.read_all()?;
        let state=registry137::verify(&before,anchored_seq,anchored_head)?;
        if event.seq!=state.seq+1 || event.prev_hash!=state.head {
            return Err(Error("WRITER_CHAIN"));
        }
        let mut candidate=before.clone();
        let encoded=serde_json::to_vec(event).map_err(|_|Error("WRITER_ENCODING"))?;
        candidate.extend_from_slice(&encoded);candidate.push(b'\n');
        if candidate.len()>LIMIT {return Err(Error("REGISTRY_TOO_LARGE"));}
        // Validate candidate transitions using only immutable candidate bytes.
        // Extract full head/sequence independently, rather than trusting caller's event.
        let mut head=String::new();
        // The new event head is SHA-256 over canonical serialized event bytes.
        use sha2::{Digest,Sha256};
        head.push_str(&hex::encode(Sha256::digest(&encoded)));
        let updated=registry137::verify(&candidate,state.seq+1,&head)?;
        self.check_path()?;
        if self.read_all()?!=before {return Err(Error("WRITER_CONCURRENT_CHANGE"));}
        let mut pos=before.len() as u64;
        let suffix=&candidate[before.len()..];
        let mut written=0;
        while written<suffix.len() {
            let n=self.file.write_at(&suffix[written..],pos)
                .map_err(|_|Error("WRITER_PARTIAL_WRITE"))?;
            if n==0 {return Err(Error("WRITER_PARTIAL_WRITE"));}
            pos+=n as u64;written+=n;
        }
        self.file.sync_all().map_err(|_|Error("WRITER_FSYNC_FAILED"))?;
        self.check_path()?;
        let readback=self.read_all()?;
        if readback!=candidate {return Err(Error("WRITER_READBACK_MISMATCH"));}
        Ok(PendingCheckpoint{
            seq:updated.seq,head:updated.head,local_fsync_observed:true,
            external_checkpoint_acknowledged:false,decision:"HOLD",lock_cleared:false
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    fn fixture(name:&str)->PathBuf {
        let p=std::env::temp_dir().join(format!("sapphon139-{name}-{}",std::process::id()));
        let _=fs::remove_file(&p);fs::write(&p,b"").unwrap();p
    }
    fn key()->String {hex::encode(SigningKey::from_bytes(&[7u8;32]).verifying_key().as_bytes())}
    #[test] fn supervised_append_fsync_and_restart_still_hold() {
        let p=fixture("success");
        let mut writer=SupervisedWriter::open(&p).unwrap();
        let head=registry137::genesis_head();
        let zero=registry137::verify(&[],0,&head).unwrap();
        let event=registry137::next(&zero,"register","witness-one","root-one",&key(),1);
        let checkpoint=writer.append(0,&head,&event).unwrap();
        assert_eq!(checkpoint.seq,1);
        assert!(checkpoint.local_fsync_observed);
        assert!(!checkpoint.external_checkpoint_acknowledged);
        assert_eq!(checkpoint.decision,"HOLD");
        assert!(!checkpoint.lock_cleared);
        drop(writer);
        let disk=fs::read(&p).unwrap();
        assert_eq!(registry137::verify(&disk,1,&checkpoint.head).unwrap().seq,1);
        fs::remove_file(&p).unwrap();
    }
    #[test] fn duplicate_cooperative_writer_is_blocked() {
        let p=fixture("busy");let writer=SupervisedWriter::open(&p).unwrap();
        assert_eq!(SupervisedWriter::open(&p).err().unwrap().0,"WRITER_BUSY");
        drop(writer);fs::remove_file(p).unwrap();
    }
    #[test] fn stale_anchor_rejected_without_write() {
        let p=fixture("anchor");let mut writer=SupervisedWriter::open(&p).unwrap();
        let zero=registry137::verify(&[],0,&registry137::genesis_head()).unwrap();
        let event=registry137::next(&zero,"register","witness-one","root-one",&key(),1);
        assert_eq!(writer.append(1,&registry137::genesis_head(),&event).unwrap_err().0,
            "REGISTRY_ANCHOR_MISMATCH");
        assert_eq!(fs::metadata(&p).unwrap().len(),0);
        drop(writer);fs::remove_file(p).unwrap();
    }
    #[test] fn partial_tail_is_quarantined_after_interruption() {
        let p=fixture("partial");
        fs::write(&p,b"{\"schema\":").unwrap();
        let mut writer=SupervisedWriter::open(&p).unwrap();
        let zero=registry137::verify(&[],0,&registry137::genesis_head()).unwrap();
        let event=registry137::next(&zero,"register","witness-one","root-one",&key(),1);
        assert_eq!(writer.append(0,&registry137::genesis_head(),&event).unwrap_err().0,
            "REGISTRY_TRUNCATED");
        assert_eq!(fs::read(&p).unwrap(),b"{\"schema\":");
        drop(writer);fs::remove_file(p).unwrap();
    }
    #[test] fn swapped_path_detected_before_write() {
        let p=fixture("swap");let other=p.with_extension("other");
        let _=fs::remove_file(&other);
        let mut writer=SupervisedWriter::open(&p).unwrap();
        fs::rename(&p,&other).unwrap();fs::write(&p,b"").unwrap();
        let zero=registry137::verify(&[],0,&registry137::genesis_head()).unwrap();
        let event=registry137::next(&zero,"register","witness-one","root-one",&key(),1);
        assert_eq!(writer.append(0,&registry137::genesis_head(),&event).unwrap_err().0,
            "WRITER_PATH_CHANGED");
        drop(writer);fs::remove_file(p).unwrap();fs::remove_file(other).unwrap();
    }
}
