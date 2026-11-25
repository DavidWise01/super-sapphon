use sapphon_liveness::{acquire, qualify};
use std::{env, fs, process, thread, time::Duration};
fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 5 {
        eprintln!("usage: sapphon-liveness <hold|exit> <root> <who> <readyfile>");
        process::exit(2)
    }
    let result = (|| {
        let o = acquire(std::path::Path::new(&args[2]), &args[3]).map_err(|e| e.0)?;
        let f = qualify(std::path::Path::new(&args[2])).map_err(|e| e.0)?;
        if f.os_observation != "ALIVE" {
            return Err("OWNER_NOT_LIVE");
        }
        fs::write(
            &args[4],
            format!("PID={} START={}", o.pid, o.proc_start_ticks),
        )
        .map_err(|_| "READY_WRITE_FAILED")?;
        if args[1] == "exit" {
            return Ok(());
        }
        if args[1] != "hold" {
            return Err("COMMAND_INVALID");
        }
        loop {
            thread::sleep(Duration::from_millis(100));
        }
    })();
    if let Err(e) = result {
        eprintln!("{e}");
        process::exit(3);
    }
}
