# SAPPHON — Rust audit engine

**Status:** Rust migration baseline 0.1.0, first module: SAPPHON-127 signed publication equivocation and source-ancestry audit.

This is a *new*, versioned Rust crate alongside the frozen JavaScript lineage. The historic Phase VI–IX source files are not overwritten. The other SAPPHON engines (113–126 and earlier) have **not** yet been ported to Rust.

## Build and test

From `rust/sapphon-audit`:

```bash
cargo fmt --all -- --check
cargo test --all-targets
cargo doc --no-deps
```

The Rust crate verifies the SAPPHON-125 snapshot's **JavaScript-compatible canonical field array** with Ed25519, audits distinct signed digests for the same publisher and generation, records every fork instead of choosing a winner, and reports shared GitHub/Pages ancestry without creating phantom independent witnesses.

## Read-only CLI

```bash
cargo run -- <journal.json> <publisher-id> <generation> <control-root> <ed25519-public-key-hex> [source-root...]
```

The input is a SAPPHON-127 Rust journal JSON object, with `schema: "sapphon-127-rust-audit-v1"`, `revision`, `observations` and `conflicts`. Public key is the *raw 32-byte* Ed25519 verifying key represented as 64 hex characters; the CLI does not accept a private key. It validates all retained snapshots and required conflict links, then prints a read-only JSON assessment.

The CLI does not mutate its source journal, and it does not authenticate a third-party custodian merely because the issuer signed a snapshot.

## Invariants

- A snapshot signs `JSON.stringify(F.map(k => payload[k]))`, in the frozen SAPPHON-125 field order.
- All recorded signed forks remain present; same publisher/generation with distinct valid payload digests is equivocation.
- Two paths with one source ancestry are **one** provenance origin, not independent witnesses.
- Unknown, revoked or substituted publishing keys fail signature verification.
- Valid synthetic evidence returns **HOLD**. No cryptographic key used in local tests establishes physical time, remote custody, external authority or UTC.
- The current Rust journal is an in-memory audit type with JSON serialization. It **does not** yet implement the JavaScript engine's fsync + rename persistence or cross-process transaction locking. Do not substitute it for that durable component without completing the persistence port and crash tests.

## Verification

[GitHub Actions — SAPPHON Rust audit](https://github.com/DavidWise01/super-sapphon/actions/workflows/sapphon-rust-audit.yml)

**Next Rust port:** SAPPHON-126 verifier-specific freshness and SAPPHON-125 high-water snapshot admission, followed by durable append-only journal persistence and adversarial recovery tests.

`.dlw`
