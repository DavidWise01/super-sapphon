//! Read-only CLI over signed synthetic publication observations.
//! Usage:
//! cargo run -- <journal.json> <publisher-id> <generation> <control-root> <public-key-hex> [source-root...]
use sapphon_audit::{Journal, PinRegistry, PublisherPin};
use std::{collections::BTreeMap, env, fs, process};
fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 6 {
        return Err("usage: sapphon-audit <journal.json> <publisher-id> <generation> <control-root> <ed25519-public-key-hex> [source-root...]".into());
    }
    let journal: Journal = serde_json::from_slice(&fs::read(&args[1])?)?;
    let bytes = hex::decode(&args[5])?;
    let key: [u8; 32] = bytes.try_into().map_err(|_| "Ed25519 public key must be 32 raw bytes (64 hex chars)")?;
    let pins: PinRegistry = BTreeMap::from([(args[2].clone(), PublisherPin {
        control_root: args[4].clone(), public_key: key, revoked: false,
    })]);
    journal.validate(&pins)?;
    let generation = args[3].parse::<u64>()?;
    let result = journal.assess(&args[2], generation, &args[6..], &pins)?;
    println!("{}", serde_json::to_string_pretty(&result)?);
    Ok(())
}
fn main() {
    if let Err(e) = run() {
        eprintln!("SAPPHON Rust audit HOLD: {e}");
        process::exit(1);
    }
}
