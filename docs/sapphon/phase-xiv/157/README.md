# SAPPHON-157 — External Custodian Enrollment and Independent Receipt Authentication

**Phase XIV · Bound 5 of 8 · 62.5% source-design progression · operational authority HOLD**

## Implementation

The Linux Rust module `rust/sapphon-liveness/src/enrollment157.rs` introduces a domain-separated Ed25519 enrollment receipt, incorporating custodian ID, claimed organization, source-ancestry digest, pinned public key, challenge nonce digest, artifact digest, epoch, and monotonic counter. Signatures are checked against **separately supplied** provisioned keys; revoked providers, stale counter floors, missing provisioning and modified signatures are rejected.

When two receipts are cryptographically valid, the review distinguishes shared claimed ancestry, duplicate keys/identities, conflicting artifact digests and matching but **unqualified** custody claims. It retains order-independent evidence digests and denies recovery in every case.

## Nine authored Rust tests
Valid dual signatures remain unqualified; shared ancestry is flagged; duplicate signer detected; missing provisioning rejected; forged signatures rejected; stale counters rejected; revoked provider rejected; conflicting artifact hashes retained; swapped receipt order yields identical review.

## Unresolved external requirements

A separate key in this test harness is **not** proof of a separately controlled private key in the real world. A custody provider must be enrolled through an out-of-band process: independent ownership/organization verification, provisioned public keys and monotonic counters retained outside GitHub and 0root.ai ancestry, an independently delivered challenge nonce, and authenticated signed receipts stored in protected external custody.

This source code does not enroll a real custodian, authenticate the external organization, establish trusted UTC, provide WORM retention, or authorize lock clearance or automatic recovery. All outcomes are `ENROLLMENT_HOLD`.

## CI and Pages

The read-only workflow `.github/workflows/sapphon-157-enrollment.yml` runs the Rust liveness tests and inherited suites, 188 historical hash checks, HOLD assertions and Rust documentation. It produces a run-scoped artifact that **explicitly declares no external custodian has been enrolled**. CI success, Pages deployment and external custody must be verified separately; committed source and authored tests are not a pass.

## Next natural bound — SAPPHON-158

Out-of-band challenge binding and receipt replay rejection: bind unique external nonces to provider identities, signed artifact digests and retained counter floors; reject stale and reused challenges without promoting signed GitHub-owned evidence to a second independent root.

`{r[g(b → 0xyz/.|.\\ )]} · {{i}} · .dlw`
