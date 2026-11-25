//! Separate executable process for SAPPHON-130 fault and contention trials.
//! Does not issue external authority. "hold"/"stage" are test-only kill targets.
use sapphon_contention::{pins, signed, AUTHORITY};
use sapphon_journal::{append, initialize, inspect, Fault};
use std::{env, fs, path::Path, process, thread, time::Duration};

fn run(args: &[String]) -> Result<String, String> {
    if args.len() < 3 { return Err("USAGE: <command> <journal-root> [arguments]".into()); }
    let root=Path::new(&args[2]);
    match args[1].as_str() {
        "init" => {
            initialize(root, &pins()).map_err(|e|e.0)?;
            Ok("INITIALIZED HOLD".into())
        }
        "inspect" => {
            let journal=inspect(root,&pins()).map_err(|e|e.0)?;
            Ok(format!("REVISION={} OBSERVATIONS={} CONFLICTS={} AUTHORITY={}",
                journal.revision,journal.observations.len(),journal.conflicts.len(),AUTHORITY))
        }
        "append" => {
            if args.len()!=7 { return Err("USAGE: append <root> <expected_revision> <source_id> <revoke:true|false> <fault>".into()); }
            let revision=args[3].parse::<u64>().map_err(|_|"REVISION_INVALID")?;
            let revoked=match args[5].as_str() {"true"=>true,"false"=>false,_=>return Err("REVOKE_INVALID".into())};
            let fault=match args[6].as_str() {
                "none"=>Fault::None,"before"=>Fault::BeforeRename,"after"=>Fault::AfterRename,
                _=>return Err("FAULT_INVALID".into())};
            let result=append(root,&pins(),revision,signed(revoked),&args[4],
                vec!["owned-root".into()],fault).map_err(|e|e.0)?;
            Ok(format!("{} AUTHORITY={}",result.decision,AUTHORITY))
        }
        "hold"|"stage" => {
            if args.len()!=4 {return Err("USAGE: hold|stage <root> <ready-file>".into());}
            let lock=root.join(".exclusive-lock");
            fs::create_dir(&lock).map_err(|_|"STORE_BUSY")?;
            if args[1]=="stage" {
                // Test interruption during temporary file assembly. Never rename it
                // into the signed journal. The deliberately partial file is untrusted.
                fs::write(root.join(".journal-stage-aborted"),b"{incomplete")
                    .map_err(|_|"STAGE_WRITE_FAILED")?;
            }
            fs::write(&args[3],format!("PID={} MODE={}",process::id(),args[1]))
                .map_err(|_|"READY_WRITE_FAILED")?;
            loop { thread::sleep(Duration::from_millis(100)); }
        }
        _ => Err("UNKNOWN_COMMAND".into())
    }
}
fn main(){
    let args:Vec<String>=env::args().collect();
    match run(&args) {
        Ok(line)=>println!("{line}"),
        Err(e)=>{eprintln!("{e}");process::exit(2);}
    }
}
