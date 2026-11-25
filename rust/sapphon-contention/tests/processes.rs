use sapphon_contention::{pins, AUTHORITY};
use sapphon_journal::{inspect, initialize};
use std::{
    fs,
    path::{Path,PathBuf},
    process::{Command,Child,Output},
    sync::{Arc,Barrier,atomic::{AtomicU64,Ordering}},
    thread,
    time::Duration,
};
static NEXT: AtomicU64=AtomicU64::new(0);
const BIN:&str=env!("CARGO_BIN_EXE_sapphon-contention");
struct Fixture {root:PathBuf}
impl Fixture {
 fn new()->Self {
    let root=std::env::temp_dir().join(format!("sapphon130-{}-{}",std::process::id(),NEXT.fetch_add(1,Ordering::SeqCst)));
    initialize(&root,&pins()).unwrap();
    Self{root}
 }
 fn command(&self,args:&[&str])->Output {
    Command::new(BIN).arg(args[0]).arg(&self.root).args(&args[1..]).output().unwrap()
 }
 fn append(&self,rev:u64,source:&str,revoked:bool,fault:&str)->Output{
    self.command(&["append",&rev.to_string(),source,if revoked {"true"}else{"false"},fault])
 }
 fn current(&self)->sapphon_audit::Journal {inspect(&self.root,&pins()).unwrap()}
 fn holder(&self,mode:&str)->(Child,PathBuf){
    let ready=self.root.with_extension(format!("{}-ready",mode));
    let child=Command::new(BIN).arg(mode).arg(&self.root).arg(&ready).spawn().unwrap();
    for _ in 0..200 {
        if ready.exists(){return(child,ready);}
        thread::sleep(Duration::from_millis(10));
    }
    panic!("child failed to publish process-ready marker");
 }
}
impl Drop for Fixture {
 fn drop(&mut self){let _=fs::remove_dir_all(&self.root);}
}
fn succeeded(out:&Output)->bool{out.status.success()}
fn error(out:&Output)->String{String::from_utf8_lossy(&out.stderr).trim().into()}
fn output(out:&Output)->String{String::from_utf8_lossy(&out.stdout).trim().into()}
fn recover_stale_after_confirmed_exit(root:&Path,ready:&Path) {
 assert!(ready.exists());
 assert!(root.join(".exclusive-lock").exists());
 // Operator simulation only: test has already waited for the exact child
 // process to terminate. No code automatically steals live locks.
 fs::remove_dir(root.join(".exclusive-lock")).unwrap();
 fs::remove_file(ready).unwrap();
}
#[test] fn two_rust_executables_share_signed_journal_format(){
 let x=Fixture::new();
 assert!(succeeded(&x.append(0,"rust-worker-a",false,"none")));
 let out=x.command(&["inspect"]);
 assert!(succeeded(&out));
 assert!(output(&out).contains("REVISION=1"));
 assert!(output(&out).contains("AUTHORITY=HOLD"));
}
#[test] fn simultaneous_independent_processes_cannot_both_claim_same_revision(){
 let x=Fixture::new();let path=x.root.clone();
 let barrier=Arc::new(Barrier::new(8));
 let join:Vec<_>=(0..8).map(|index|{
    let barrier=barrier.clone();let path=path.clone();
    thread::spawn(move||{
       barrier.wait();
       Command::new(BIN).arg("append").arg(path)
          .arg("0").arg(format!("source-{index}"))
          .arg("false").arg("none").output().unwrap()
    })
 }).collect();
 let outputs:Vec<_>=join.into_iter().map(|j|j.join().unwrap()).collect();
 assert_eq!(outputs.iter().filter(|x|succeeded(x)).count(),1);
 for out in outputs.iter().filter(|x|!succeeded(x)) {
    assert!(["STORE_BUSY","REVISION_CONFLICT"].contains(&error(out).as_str()),"{}",error(out));
 }
 assert_eq!(x.current().revision,1);
 assert_eq!(x.current().observations.len(),1);
}
#[test] fn two_serial_processes_create_signed_fork_without_losing_evidence(){
 let x=Fixture::new();
 assert!(succeeded(&x.append(0,"worker-one",false,"none")));
 assert!(succeeded(&x.append(1,"worker-two",true,"none")));
 assert_eq!(x.current().revision,2);
 assert_eq!(x.current().conflicts.len(),1);
}
#[test] fn independent_process_duplicate_is_idempotent(){
 let x=Fixture::new();
 assert!(succeeded(&x.append(0,"worker-one",false,"none")));
 let out=x.append(1,"worker-one",false,"none");
 assert!(succeeded(&out));assert!(output(&out).contains("DUPLICATE_OBSERVATION"));
 assert_eq!(x.current().revision,1);
}
#[test] fn killed_rust_lock_owner_leaves_lock_and_blocks_all_writes(){
 let x=Fixture::new();let (mut child,ready)=x.holder("hold");
 assert_eq!(error(&x.append(0,"contender",false,"none")),"STORE_BUSY");
 child.kill().unwrap();child.wait().unwrap();
 assert_eq!(error(&x.append(0,"still-blocked",false,"none")),"STORE_BUSY");
 assert_eq!(fs::read(x.root.join("journal.json")).is_ok(),true);
 recover_stale_after_confirmed_exit(&x.root,&ready);
 assert!(succeeded(&x.append(0,"after-review",false,"none")));
}
#[test] fn killed_writer_before_rename_never_exposes_partial_journal(){
 let x=Fixture::new();
 let original=fs::read(x.root.join("journal.json")).unwrap();
 let (mut child,ready)=x.holder("stage");
 assert_eq!(error(&x.append(0,"blocked",true,"none")),"STORE_BUSY");
 child.kill().unwrap();child.wait().unwrap();
 assert_eq!(fs::read(x.root.join("journal.json")).unwrap(),original);
 recover_stale_after_confirmed_exit(&x.root,&ready);
 fs::remove_file(x.root.join(".journal-stage-aborted")).unwrap();
 assert_eq!(x.current().revision,0);
 assert!(succeeded(&x.append(0,"recovered",false,"none")));
}
#[test] fn before_rename_fault_preserves_previous_committed_bytes(){
 let x=Fixture::new();
 let before=fs::read(x.root.join("journal.json")).unwrap();
 let out=x.append(0,"fault-before",true,"before");
 assert_eq!(error(&out),"INJECTED_BEFORE_RENAME");
 assert_eq!(fs::read(x.root.join("journal.json")).unwrap(),before);
 assert_eq!(x.current().revision,0);
}
#[test] fn after_rename_fault_requires_readback_and_no_blind_retry(){
 let x=Fixture::new();
 let out=x.append(0,"fault-after",false,"after");
 assert_eq!(error(&out),"INJECTED_AFTER_RENAME");
 assert_eq!(x.current().revision,1);
 assert_eq!(error(&x.append(0,"blind-retry",false,"none")),"REVISION_CONFLICT");
 assert_eq!(x.current().observations.len(),1);
}
#[test] fn test_power_failure_is_not_claimed_by_software_injection(){
 let x=Fixture::new();
 assert_eq!(error(&x.append(0,"fault-before",false,"before")),"INJECTED_BEFORE_RENAME");
 assert_eq!(AUTHORITY,"HOLD");
}
#[test] fn corrupt_disk_state_blocks_other_processes(){
 let x=Fixture::new();fs::write(x.root.join("journal.json"),b"{incomplete").unwrap();
 assert_eq!(error(&x.command(&["inspect"])),"JOURNAL_CORRUPT");
 assert_eq!(error(&x.append(0,"try-append",false,"none")),"JOURNAL_CORRUPT");
}
#[test] fn independent_rust_processes_reject_forged_revision(){
 let x=Fixture::new();
 assert!(succeeded(&x.append(0,"worker-one",false,"none")));
 assert_eq!(error(&x.append(0,"other-worker",true,"none")),"REVISION_CONFLICT");
 assert_eq!(x.current().revision,1);
}
#[test] fn synthetic_journal_stays_hold_after_multiple_processes(){
 let x=Fixture::new();
 assert!(succeeded(&x.append(0,"first-worker",false,"none")));
 assert!(succeeded(&x.append(1,"second-worker",true,"none")));
 let out=x.command(&["inspect"]);
 assert!(output(&out).contains("CONFLICTS=1"));
 assert!(output(&out).contains("AUTHORITY=HOLD"));
}
