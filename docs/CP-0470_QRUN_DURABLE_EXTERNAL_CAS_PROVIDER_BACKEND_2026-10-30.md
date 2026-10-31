# CP-0470 — Durable QRun External-CAS Provider Backend Candidate

Date: 2026-10-30

Status: **A persistent single-host filesystem backend now implements the external-CAS transport contract and has passed local Windows tests. It is not a deployed independent provider, cloud object-store adapter, hardware monotonic anchor, or Mainnet release.**

## Problem

CP-0469 added the pinned Noise/TCP client adapter and service-side one-request handler, but the only exercised provider implementation was an in-memory fixture. That fixture could validate protocol behavior, signed receipts, and CAS semantics, but it did not persist state across process restarts or serialize writers across independently opened service processes.

## Implementation

1. Added the external_cas_disk_provider_candidate module and registered it in the crate. DurableExternalCasProvider<S> implements ExternalCasProviderTransport.
2. Initialization is explicit and create-once. It accepts only a generation-zero bootstrap record matching the full configured provider, Network ID, and Genesis pin. Existing state is never overwritten or silently reset. Opening a missing, corrupt, or wrong-pin store fails closed.
3. The provider state is a fixed-width 480-byte QCAS v1 record containing the provider/network/Genesis domain, receipt key ID, hash of the pinned receipt public key, provider object generation, the current canonical ECR1 record, and a domain-separated SHA-256 checksum.
4. Every read and CAS takes the existing OS-backed StoreWriterLock, reloads the on-disk state while holding the lock, and validates the exact pin. The provider retries short-lived lock contention for a bounded two-second window, then fails closed.
5. CAS requires the exact expected logical generation, provider object generation, predecessor record digest, and predecessor state digest. It validates the exact ECR1 successor before changing state. One concurrent writer can apply; a competing stale writer receives a signed conflict.
6. The provider writes a unique temporary file, flushes and syncs it, atomically replaces the current state, and syncs the parent directory where supported. Windows uses MoveFileExW with replace-existing and write-through flags; Unix uses rename followed by parent-directory sync.
7. An exact retry of the latest already-applied operation returns AlreadyApplied without another generation advance. If persistence succeeds but receipt signing or response delivery fails, a caller must resolve the ambiguous outcome using a fresh signed read; it must not infer that the write was aborted.
8. The ML-DSA-65 receipt signer is supplied by the caller as a signing callback. The private signing key is not written into the provider state directory. A production caller must obtain it from an independently protected key store or KMS and bind it to the exact public-key pin.
9. Added loopback integration coverage which uses NoiseTcpExternalCasProviderTransport and serve_external_cas_noise_connection with the durable filesystem backend, rather than the in-memory provider fixture.

## Local validation

- cargo +stable fmt --manifest-path src/native/pow_bench/Cargo.toml --all: PASS.
- cargo +stable test --manifest-path src/native/pow_bench/Cargo.toml --lib --locked --offline: PASS, 943 passed, 0 failed.
- cargo +stable check --manifest-path src/native/pow_bench/Cargo.toml --all-targets --locked --offline: PASS. Existing unused-import/dead-code warnings remain in unrelated candidate modules and node tests.
- Provider tests cover create-once initialization, reopen, wrong pin, checksum corruption, symlink refusal where supported, missing state, writer-lock contention, exact idempotent retry, stale conflict, signer failure after durable commit, signed-read recovery, and simultaneous two-writer CAS with exactly one winner.
- A backup-rollback negative test snapshots the pre-CAS provider file, commits a signed successor, advances a separately retained QCF1 floor, restores only the old provider file, and verifies that a fresh signed read is rejected as `RollbackDetected` against the preserved floor. This demonstrates detection only while the floor is retained outside the restored provider backup; it is not a whole-host rollback defense or proof of an off-host deployment.
- Follow-up validation on 2026-10-31 after adding this test: `cargo fmt --all -- --check`: PASS; `cargo test --lib --locked --offline`: PASS, 976 passed, 0 failed; `cargo check --all-targets --locked --offline`: PASS; `git diff --check`: PASS.
- Noise/TCP loopback test performs a signed read and a CAS through the service handler backed by the durable filesystem provider, then reopens the provider and checks the committed successor and provider generation.

## Security boundary and remaining gates

- This is a **single-host durable filesystem backend candidate**. It is not a cloud/object-storage adapter, a managed provider service, or evidence of an independently operated provider. No remote service deployment or separate operator has been verified.
- The state checksum detects accidental corruption; it is not a MAC or signature over the provider file. It does not prevent an administrator or attacker with filesystem write access from constructing altered state.
- The local OS writer lock serializes processes using the same directory, but it cannot detect restoration of the entire provider directory from an old backup. Production requires a separately administered off-host monotonic anchor/floor and a recovery/backup domain that cannot be rolled back together with this directory.
- The provider directory needs restrictive service-account ACLs and suitable durable filesystem semantics. The receipt signing key, Noise server static key, allowed client static keys, pin configuration, and anti-rollback floor must be provisioned and protected independently.
- The Noise/TCP service handler is still a protocol connection handler, not a daemon or hosting/deployment solution. This local test binds only loopback. No public listener or firewall rule was enabled.
- The current Noise XX channel is classical X25519/ChaChaPoly, not post-quantum or hybrid. ML-DSA-65 signs the CAS receipts separately; that does not make the channel itself quantum-resistant.
- The QRun node executable still selects its local runtime backend. It has not been provisioned to load an independent provider endpoint, out-of-band Noise and receipt-key pins, or an independently durable generation floor; production block acceptance is not yet routed through this provider.
- Additional qualification is still required for disk/backup rollback, provider outage, concurrent service processes under failure, signer/key rotation, equivocation, filesystem fault injection and crash windows, off-host anchor recovery, service monitoring, independent operator controls, and security review.

**Decision:** CP-0470 advances the provider implementation from an in-memory fixture to a persistent local backend candidate and now includes a negative test proving that a preserved QCF1 floor detects restoration of an older provider backup. It does not qualify an independently operated provider, protect against joint rollback of provider and floor, or enable Mainnet. Keep QRUN_MAINNET_RELEASE_APPROVED = false, keep the corresponding review PR Draft until exact-head CI and review pass, and do not enable public mint or claim a QZXB/USDT market.
