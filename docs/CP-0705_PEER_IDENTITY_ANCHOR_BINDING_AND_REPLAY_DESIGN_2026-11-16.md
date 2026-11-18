# CP-0705 — Peer Identity Anchor Binding and Durable Replay Design

Date: 2026-11-16
Project: AI-NATIVE L1 / QRun / QZXB / QFP6
Branch: `feat/cp0704-dual-attestation-rotation-gate-20261116`
Worktree: `D:\Temp\ASUS\QRUN_CP0704_DUAL_ATTESTATION_20261116`
Base: `5aba5f69d24fce03af742fd1bebf13ad00e5d9c3`
Status: DESIGN / SOURCE AUDIT COMPLETE; IMPLEMENTATION NOT STARTED; NO COMMIT OR PUSH

## 1. Decision summary

The existing local Noise identity generation store and the QFP6 local dual-disk anchor are two distinct mechanisms. The first keeps a peer-identity high-water record under the node's `data_dir`; the second keeps QFP6 manifest generation/anchor commitments on the separate C: volume. The current code does not bind the peer-identity high-water state into the QFP6 anchor chain.

For the owner's documented one-laptop/local-first operating path, the next implementable assurance tier is a **separate C:-volume append-only Peer Identity Anchor Vault**, compared against the D:-volume `IdentityGenerationStateStore` during startup and rotation. This provides detection of D:-only rollback while the C: volume remains intact.

This is explicitly a local dual-physical-disk rollback detector, **not** a TPM monotonic counter, independent remote witness, or defense against a full-machine restore / simultaneous rollback of both disks / hostile local Administrator.

A higher assurance tier remains available later through a hardware monotonic facility (for example a qualified TPM NV counter) or an independently administered remote append-only witness. Neither is claimed available or configured by this checkpoint.

## 2. Source-of-truth findings

### 2.1 Existing peer identity high-water

Source: `src/native/pow_bench/src/identity_generation_store.rs`.

The module header explicitly says it detects peer-record rollback across process restarts while the state file and stable writer-lock sibling remain protected by operator-controlled ACLs; it is not hardware-backed against rollback/deletion of the entire protected directory.

The store is keyed to the identity tuple:
- network ID;
- issuer ID and issuer public key;
- credential ID;
- key ID;
- key purpose.

Its persisted state binds:
- highest accepted generation;
- exact issuer-signed record digest;
- identity projection digest;
- lifecycle state.

It rejects lower generations, same-generation record mutation except its explicit lifecycle transitions, terminal revocation reactivation, non-successor generation jumps, missing/malformed NRT1, and invalid issuer-signed transitions. It persists via a temporary file, flush/sync, atomic replacement, and a stable writer-lock sibling. The current peer-node integration places it under `config.data_dir\peer_identity_highwater\`, i.e. beside the node's data-volume state.

This is a useful local rollback control but is not an independent high-water copy.

### 2.2 Existing QFP6 local anchor

Historical design and implementation evidence: CP-0681 and CP-0682. The QFP6 Anchor Vault records sequence, network/profile IDs, QFP6 manifest generation, canonical manifest anchor, predecessor record digest, and its own record digest. CP-0682 integrates it with QFP6 commit acknowledgement and exact one-generation replay reconciliation.

Its owner path is on C::
`C:\Users\ASUS\AppData\Local\AI_NATIVE_L1\QFP6\anchor-vault\`

The QFP6 vault record schema does not currently include peer issuer/credential/key IDs, Noise public-key fingerprints, NPI1 record/artifact digests, NRT1 digest, dual-authorization digest, or authorization nonce. The QFP6 vault and `IdentityGenerationStateStore` are therefore not currently one integrated identity anchor.

### 2.3 Hardware and failure-domain boundary

CP-0681's physical inventory identifies C: as a Kingston SSD and D:/E: as partitions of a separate Toshiba HDD. C: and D: are different physical drives; D: and E: are not.

This protects against a D:-only rollback while C: remains intact. It does not protect against rollback of both physical disks, a full machine image restore, an administrator who can rewrite both volumes, firmware compromise, or deletion of both high-water copies.

A read-only TPM capability check was attempted in the current non-elevated Desktop Commander session. `Get-Tpm` reported that Administrator privilege is required; CIM access to `Win32_Tpm` was denied (HRESULT 0x80041003). Previous hardware inventory checkpoints say TPM 2.0 is present, but the current session cannot qualify NV-index permissions or provision a TPM counter. No TPM key, NV index, ownership state, or TPM configuration was changed.

## 3. Proposed local Peer Identity Anchor Vault

Create a dedicated vault namespace on C:, separate from the D: `peer_identity_highwater` files and separate from QFP6 manifest records:

`%LOCALAPPDATA%\AI_NATIVE_L1\QFP6\peer-identity-anchor-vault\`

Use an append-only record chain with bounded regular-file/no-symlink readers, stable OS writer lock, create-new records, flush/sync, full-chain reopen validation, and explicit ACL verification during provisioning. Do not place peer records inside the QFP6 `records\q6av-*.json` directory: its current parser expects only QFP6 manifest-anchor records there.

Each identity event should bind at minimum:
- schema and vault record sequence;
- network ID and QFP6 profile ID;
- immutable QFP6 genesis/root anchor identity;
- role, issuer ID, credential ID, key ID, and purpose;
- peer identity generation and lifecycle state;
- Noise public-key SHA-256 fingerprint;
- exact NPI1 artifact SHA-256 and canonical signed KeyRecord SHA-256;
- NRT1 transition digest (absent only for the initial enrolled generation);
- dual-attestation intent digest and nonce for every authorized rotation;
- owner signer pin fingerprint and independent operator signer pin fingerprint;
- previous identity generation and record digest;
- predecessor vault-record digest and this record's domain-separated digest.

The record chain must be scoped to one network/profile/role/issuer/credential/key tuple. The nonce index must reject a nonce already used by a different intent or artifact. Exact idempotent retries may return the already-recorded result only when nonce, intent digest, NPI1 digest, old generation and new generation all match.

## 4. Lifecycle and replay protocol

Use explicit append-only events; do not mutate or delete a prior event:
1. `ENROLLED_ACTIVE`: one-time initial identity baseline, established only by an explicit, separately reviewed enrollment ceremony. Never initialize a missing C: vault automatically from whatever D: currently presents.
2. `ROTATION_PREPARED`: records the exact verified dual-attestation intent, nonce, old/new generations, old/new fingerprints, NPI1 digest, NRT1 digest, and evidence digests. It does not make the new identity active.
3. `ROTATION_ACTIVE`: records the exact prepared artifact after the separately authorized activation/reload gate. This advances the C: high-water and consumes the nonce.
4. `RETIRED` / `REVOKED`: terminal or monotonic lifecycle transitions; revoked identities never reactivate.

The current CP-0704 `rotate-peer` command remains a prepare/sign operation only. Its successful NPI1 output is not proof of activation and must not cause the node to trust the new identity automatically.

The durable nonce/replay ledger lives in the C: append-only chain, not only in a D: state file. Persist each accepted authorization digest and nonce before treating its prepared rotation as durable. A duplicate nonce with changed intent, evidence, generation, key fingerprint, or artifact digest is a hard rejection.

Do not claim replay resistance until the persistent nonce ledger is implemented, reopened and checked at every startup, and tested across crash/restart boundaries. A nonce merely being syntactically nonzero is not replay protection.

## 5. Cross-volume ordering and crash recovery

There is no atomic filesystem transaction spanning C: and D:. Use an explicit, idempotent two-volume protocol and fail closed at every ambiguous point.

Required ordering for future implementation:
- Verify DPC1/IRG1/previous NPI1, prepared identity documents, evidence bytes, policy, independent signer pins, operator signature, and owner signature.
- Build and self-verify the exact successor NPI1 in memory.
- Create the candidate NPI1 at its D: destination using no-overwrite semantics and sync it. If the C: prepare record is not subsequently persisted, the file remains an untrusted orphan and cannot be loaded as active.
- Append `ROTATION_PREPARED` to C: using a create-new record and verify the entire chain/tip by reopening it.
- A retry with the same nonce is permitted only if every bound digest and generation is byte-for-byte identical; any conflicting reuse is rejected.
- A separate explicit activation procedure must append `ROTATION_ACTIVE` to C: only after the exact artifact is installed and reload/overlap policy has been reviewed. Startup may use only the identity matching an `ACTIVE` anchor record.
- The D: IdentityGenerationStateStore is then advanced from the exact predecessor to the exact successor using the issuer-signed NRT1 statement. Startup may reconcile exactly one C:-anchored successor into D: only after full NPI1/NRT1 verification. More than one generation of divergence is quarantined for manual audit.

Crash cases:
- Candidate NPI1 exists on D:, no C: `PREPARED`: candidate is not active; old identity remains the only trusted identity. Recovery may remove only a process-owned temp file, or leave the unanchored candidate quarantined.
- C: `PREPARED` exists, candidate NPI1 missing/tampered: fail closed; no implicit activation and no rewriting the record. Require exact same authorization/artifact for idempotent recovery or an explicitly signed abort event.
- C: `ACTIVE` exists, D: high-water is exactly one authorized generation behind: verify the full signed artifact and reconcile D: to the C:-anchored generation.
- D: state is ahead of C:, C: state is missing, or generations differ by more than one: fail closed; do not infer or recreate the C: anchor from D:.
- C: and D: disagree at the same generation, or any chain/ACL/file integrity check fails: quarantine and require full read-only audit.

The activation protocol must also define how established Noise sessions are drained or bounded. The trust reloader currently updates trust for new connection boundaries and does not terminate already-established sessions.

## 6. Startup integration requirements

At node startup, before opening any Noise listener or accepting peer connections:
- Resolve the C: vault path from an explicit configuration field with an absolute-path requirement; default only after validating it is on the expected physical volume and under the expected protected directory.
- Verify vault root, ACL expectations, stable writer lock, every record sequence, exact predecessor digest, domain-separated record hash, unique nonce index, and all identity tuple bindings.
- Verify the immutable network/profile/genesis-root binding.
- For each configured NPI1, verify issuer signature, NRT1 exact-successor transition, artifact digest, record digest, public-key fingerprint and lifecycle against the C: anchor.
- Compare the C: identity high-water with the D: `IdentityGenerationStateStore` exact generation and record digest.
- Reject missing C: anchor for an already-enrolled identity; never silently create a new empty anchor from D:.
- Reject PREPARED-but-not-ACTIVE identity as a trusted active identity.
- Do not open a listener on any disagreement.

The current CP-0704 isolated worktree includes `identity_generation_store.rs` but does not include the untracked QFP6 local-vault Rust module from the original checkout. Any future code reuse must be introduced deliberately with source review and tests; do not assume the existing local QFP6 vault API is already available in CP-0704.

## 7. Required test matrix before claiming completion

- Genesis enrollment requires explicit approved baseline; missing C: vault cannot self-initialize from D:.
- Valid dual-attested prepare creates exact NPI1 and one C: PREPARED event; active state remains unchanged.
- Duplicate nonce with identical intent is idempotent; same nonce with any changed binding is rejected.
- Missing/tampered operator signature, owner signature, pins, evidence, policy, DPC1, IRG1, previous NPI1, prepared files, or NRT1 leaves no active state.
- Same operator/owner public key rejected.
- D: high-water below C: high-water rejected.
- C: high-water below D: high-water rejected except exact one-generation verified C:→D: recovery protocol.
- More than one generation gap rejected.
- Same-generation record mutation, wrong network/profile/role/issuer/credential/key ID rejected.
- Symlink/reparse point, non-regular file, duplicate JSON key, trailing data, path swap, partial write, disk-full, and file-lock contention fail closed.
- Crash injection at every point in NPI1 create/sync, C: record create/write/sync/reopen, activation, D: high-water update, and session-drain must preserve the recovery rules.
- Full restart tests verify old and new identity activation state, nonce consumption, and the correct treatment of already-established Noise sessions.

## 8. Independent / higher-assurance tier

When authorized and when elevated administrative access is available, qualify TPM 2.0 NV monotonic-counter capabilities, policy/authorization model, anti-hammering behavior, clear/reprovision semantics, backup/recovery, and Windows Platform Crypto Provider constraints. Do not provision an index until the exact design and recovery procedure have been reviewed.

Alternatively, use an independently administered remote append-only witness. This is a separate deployment/trust domain; a second VM, Windows account, or disk on the same laptop is not independent.

Until one of those is provisioned and tested, call the local C:/D: design only a local dual-disk rollback detector. Do not describe it as hardware-backed, independent, or resistant to full-device rollback.

## 9. Signer pin trust and endpoint evidence

CP-0704 validates supplied owner/operator public-key fingerprints against supplied SHA-256 pins and signs the exact evidence/policy digests. This does not authenticate the provenance of the supplied pins. The initial owner and operator pin set must be delivered or confirmed out-of-band and stored in a separately protected trust configuration before any real use. A caller-supplied key, matching caller-supplied pin and valid signature do not independently prove the caller's identity.

Endpoint reachability and Noise fingerprint evidence remain assertions by the operator signer unless separately collected and verified through an independent mechanism. This must remain explicit in any acceptance report.

## 10. Current execution result / safety

- CP-0704 `rotate-peer` now has mandatory dual-attestation verification before writing the NPI1 output.
- The handler-level fixture uses deterministic synthetic keys and temporary Windows CurrentUser DPAPI ASK1 files only.
- Latest Provisioner suite: 20 passed, 0 failed (including missing operator signature, invalid operator signature, invalid owner signature, same signer key, changed NPI1 validity after signing, valid successor output and no-overwrite).
- Standalone owner-only verifier suite: 6 passed, 0 failed.
- `cargo check --bin devnet_trust_provisioner`, `cargo fmt --all -- --check`, and `git diff --check`: PASS.
- Authorization schema v3 binds NPI1 `not_before` and `not_after` into the canonical signed intent; the handler rejects a one-second post-signature change and writes no artifact.
- No production/user key was accessed, exported, or rotated; no owner authorization issued.
- The only NPI1 output was synthetic, created in a unique OS temp test directory, verified, and removed by the test.
- No node/listener/testnet/mainnet activation; no commit/push/PR update/merge.
- The original active checkout remains untouched.

## 11. Next engineering decision

Implement the local C:/D: Peer Identity Anchor Vault as a separate, explicitly scoped assurance tier only after reviewing this lifecycle and recovery contract. Keep activation disabled until startup gating, replay persistence, independent pin provenance, crash-injection tests, and session-lifetime controls are complete. TPM or remote witness work is a separate higher-assurance project and must not be represented as done.
