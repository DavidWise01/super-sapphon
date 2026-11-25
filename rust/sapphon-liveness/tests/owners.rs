use sapphon_audit::PinRegistry;
use sapphon_journal::initialize;
use sapphon_liveness::{parse_linux_stat,observe_identity,qualify,read_owner,owner_path,Identity,AUTHORITY,Owner};
use std::{fs,path::PathBuf,process::{Command,Child},sync::atomic::{AtomicU64,Ordering},thread,time::Duration};
static COUNTER:AtomicU64=AtomicU64::new(0);
const BIN:&str=env!("CARGO_BIN_EXE_sapphon-liveness");
struct Fixture{root:PathBuf}
impl Fixture{
 fn new()->Self{
  let root=std::env::temp_dir().join(format!("sapphon132-{}-{}",std::process::id(),COUNTER.fetch_add(1,Ordering::SeqCst)));
  initialize(&root,&PinRegistry::new()).unwrap();Self{root}
 }
 fn start(&self,mode:&str)->(Child,PathBuf){
  let ready=self.root.with_extension("ready");
  let mut child=Command::new(BIN).arg(mode).arg(&self.root).arg("operator-fixture").arg(&ready).spawn().unwrap();
  for _ in 0..200{
   if ready.exists(){return (child,ready);}
   if let Ok(Some(exit))=child.try_wait(){panic!("child exited before marker: {exit:?}");}
   thread::sleep(Duration::from_millis(10));
  }
  panic!("timeout waiting for child to acquire lock")
 }
 fn clear(&self,ready:&PathBuf){
  fs::remove_file(owner_path(&self.root)).unwrap();
  fs::remove_dir(self.root.join(".exclusive-lock")).unwrap();
  if ready.exists(){fs::remove_file(ready).unwrap();}
 }
}
impl Drop for Fixture{fn drop(&mut self){let _=fs::remove_dir_all(&self.root);}}
#[test]fn actual_running_process_identity_is_live(){
 let f=Fixture::new();let(mut child,ready)=f.start("hold");
 let o=read_owner(&f.root).unwrap();
 assert_eq!(o.pid,child.id());
 assert_eq!(observe_identity(&o).unwrap(),Identity::Alive);
 let assessment=qualify(&f.root).unwrap();
 assert_eq!(assessment.os_observation,"ALIVE");
 assert!(!assessment.eligible_for_signed_review);
 assert!(!assessment.lock_cleared);
 child.kill().unwrap();child.wait().unwrap();f.clear(&ready);
}
#[test]fn kernel_observed_dead_process_is_only_recovery_candidate(){
 let f=Fixture::new();let(mut child,ready)=f.start("hold");
 assert_eq!(qualify(&f.root).unwrap().os_observation,"ALIVE");
 child.kill().unwrap();child.wait().unwrap();
 let v=qualify(&f.root).unwrap();
 assert_eq!(v.os_observation,"DEAD");
 assert!(v.eligible_for_signed_review);
 assert!(!v.lock_cleared);
 f.clear(&ready);
}
#[test]fn normally_exited_owner_is_also_detected_dead(){
 let f=Fixture::new();let(mut child,ready)=f.start("exit");
 child.wait().unwrap();
 assert_eq!(qualify(&f.root).unwrap().os_observation,"DEAD");
 f.clear(&ready);
}
#[test]fn active_owner_blocks_duplicate_acquisition_from_another_process(){
 let f=Fixture::new();let(mut child,ready)=f.start("hold");
 let rejected=Command::new(BIN).arg("exit").arg(&f.root).arg("another-owner").arg(f.root.with_extension("second")).output().unwrap();
 assert!(!rejected.status.success());
 assert!(String::from_utf8_lossy(&rejected.stderr).contains("STORE_BUSY"));
 assert!(!qualify(&f.root).unwrap().eligible_for_signed_review);
 child.kill().unwrap();child.wait().unwrap();f.clear(&ready);
}
#[test]fn journal_change_after_acquisition_is_fenced(){
 let f=Fixture::new();let(mut child,ready)=f.start("hold");
 let file=f.root.join("journal.json"); let mut original=fs::read(&file).unwrap(); original.push(32); fs::write(&file,original).unwrap();
 assert_eq!(qualify(&f.root).unwrap_err().0,"OWNER_JOURNAL_CONFLICT");
 child.kill().unwrap();child.wait().unwrap();f.clear(&ready);
}
#[test]fn forged_pid_field_cannot_clear_lock_or_prove_death(){
 let f=Fixture::new();let(mut child,ready)=f.start("hold");
 let mut o=read_owner(&f.root).unwrap();
 o.pid=999_999_999;
 fs::write(owner_path(&f.root),serde_json::to_vec(&o).unwrap()).unwrap();
 let assessment=qualify(&f.root).unwrap();
 assert_eq!(assessment.decision,"HOLD");assert_eq!(assessment.os_observation,"DEAD");
 assert!(assessment.eligible_for_signed_review);
 assert!(!assessment.lock_cleared);
 // A forged marker can produce a dead observation. It is NOT authenticated
 // proof that this PID ever owned the lock, so no automatic clearance exists.
 child.kill().unwrap();child.wait().unwrap();f.clear(&ready);
}
#[test]fn missing_owner_marker_fails_closed(){
 let f=Fixture::new();let(mut child,ready)=f.start("hold");
 fs::remove_file(owner_path(&f.root)).unwrap();
 assert_eq!(qualify(&f.root).unwrap_err().0,"OWNER_MARKER_MISSING");
 child.kill().unwrap();child.wait().unwrap();
 fs::remove_dir(f.root.join(".exclusive-lock")).unwrap();fs::remove_file(ready).unwrap();
}
#[test]fn corrupted_owner_marker_fails_closed(){
 let f=Fixture::new();let(mut child,ready)=f.start("hold");
 fs::write(owner_path(&f.root),b"{broken").unwrap();
 assert_eq!(qualify(&f.root).unwrap_err().0,"OWNER_MARKER_CORRUPT");
 child.kill().unwrap();child.wait().unwrap();f.clear(&ready);
}
#[test]fn boot_id_mismatch_is_unknown_not_dead(){
 let f=Fixture::new();let(mut child,ready)=f.start("hold");
 let mut o=read_owner(&f.root).unwrap();
 o.boot_id="00000000-0000-0000-0000-000000000000".into();
 fs::write(owner_path(&f.root),serde_json::to_vec(&o).unwrap()).unwrap();
 let q=qualify(&f.root).unwrap();
 assert_eq!(q.os_observation,"UNKNOWN");assert!(!q.eligible_for_signed_review);
 child.kill().unwrap();child.wait().unwrap();f.clear(&ready);
}
#[test]fn process_start_tick_mismatch_is_not_same_owner(){
 let f=Fixture::new();let(mut child,ready)=f.start("hold");
 let mut o=read_owner(&f.root).unwrap();o.proc_start_ticks+=1;
 fs::write(owner_path(&f.root),serde_json::to_vec(&o).unwrap()).unwrap();
 assert_eq!(qualify(&f.root).unwrap().os_observation,"DEAD");
 child.kill().unwrap();child.wait().unwrap();f.clear(&ready);
}
#[test]fn linux_proc_stat_handles_spaced_parenthesized_process_name(){
 let mut fields=vec!["S".to_owned();50];
 fields[19]="123456".into();
 let line=format!("31 (my (strange) name) {}",fields.join(" "));
 assert_eq!(parse_linux_stat(&line).unwrap(),('S',123456));
}
#[test]fn malformed_proc_stat_fails_closed(){
 assert_eq!(parse_linux_stat("missing").unwrap_err().0,"PROC_STAT_INVALID");
 assert_eq!(parse_linux_stat("2 (short) S 0").unwrap_err().0,"PROC_STAT_INVALID");
}
#[test]fn fabricated_unknown_metadata_is_rejected(){
 let f=Fixture::new();let(mut child,ready)=f.start("hold");
 let mut v:serde_json::Value=serde_json::from_slice(&fs::read(owner_path(&f.root)).unwrap()).unwrap();
 v["confirmed_external_utc"]=serde_json::Value::Bool(true);
 fs::write(owner_path(&f.root),serde_json::to_vec(&v).unwrap()).unwrap();
 assert_eq!(qualify(&f.root).unwrap_err().0,"OWNER_MARKER_CORRUPT");
 child.kill().unwrap();child.wait().unwrap();f.clear(&ready);
}
#[test]fn owner_marker_is_observation_only_not_authorization(){
 let f=Fixture::new();let(mut child,ready)=f.start("hold");
 let q=qualify(&f.root).unwrap();
 assert_eq!(q.decision,"HOLD");
 assert_eq!(AUTHORITY,"HOLD");
 assert!(!q.external_authority);
 child.kill().unwrap();child.wait().unwrap();f.clear(&ready);
}
