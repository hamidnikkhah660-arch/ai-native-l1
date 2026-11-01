# CP-0395 — PFM5 External-CAS durable intent journal

Date: 2026-11-01

Status: **A fixed-size, checksummed, file-backed replay journal is implemented and locally crash-tested. It is a durable local component only; it is not an independent anti-rollback trust domain and is not wired into a node or live provider.**

## Purpose

CP-0394 coordinates PFM5 immutable object publication and an exact signed ECR1 compare-and-swap. Its intent is deterministic and serializable, but a caller must persist that exact intent before any external side effect and retain it across process restart.

CP-0395 provides that local persistence primitive. It records the last finalized ECR1 predecessor, the provider object-generation observation, a monotonic journal sequence and (when active) the exact CP-0394 intent bytes.

## State machine and wire format

The fixed-size PFJ1 record has two states:

- **Ready:** contains the last locally finalized ECR1 record and its object generation; the intent slot is all zero.
- **Prepared:** contains the exact ECR1 predecessor and object generation plus the exact encoded CP-0394 intent. A second, different intent cannot replace it.

The format is fixed length, versioned, big-endian, reserved-byte checked and protected by a domain-separated SHA-256 checksum. Oversized, truncated, corrupt, wrong-domain and noncanonical records fail closed. Initialization is explicit and create-once; missing or corrupt journal state is never reset to a bootstrap record automatically.

## Required caller protocol

The journal file is not a trust anchor. The caller must maintain an independent monotonic high-water store that is outside the journal's local disk rollback domain.

Required order:

1. Obtain and verify a signed ECR1 read and the corresponding provider object-generation observation. Explicitly initialize the journal from that verified predecessor.
2. Persist the journal's initial sequence in the independent high-water store.
3. Prepare the exact PFM5 intent and call `stage_intent`. The method durably writes PFJ1 **Prepared** and returns the next journal sequence.
4. Persist that returned sequence to the independent high-water store. **Do not call CP-0394 or publish any remote object until this independent floor update succeeds.** A crash before this floor update is safe because no remote side effect has yet been initiated.
5. Execute CP-0394 using the exact same intent. On `RetrySameIntent`, leave the journal Prepared and retry only that intent. After a committed or already-committed result, call `mark_committed` with the exact ECR1 successor record and the signed/read-back object generation.
6. Persist the finalized sequence and the new record/object-generation floors in the independent high-water store. If the process crashes before local finalization, PFJ1 remains Prepared and CP-0394 can reconcile it by a fresh signed ECR1 read. If local finalization succeeded but this final floor update did not, replay may see the prior Prepared state only if the journal disk was restored; the signed ECR1 read will still reveal the exact committed successor.

A file checksum detects corruption, not rollback. If the independent high-water store is unavailable, stale, or behind the caller's required minimum, the caller must fail closed and must not execute an external operation.

## Durability and file safety

- Stable sibling writer lock serializes callers through the journal path.
- Existing symbolic-link paths and hard-link aliases are rejected. Hard-link count is checked using platform metadata; the data inode is not held open across atomic replacement on Windows.
- Updates use a unique create-new temp file, full write, flush, file sync, atomic replacement (Windows write-through), and parent-directory sync on Unix.
- Startup removes only orphan temp files matching this journal's exact generated filename pattern; it enforces a bounded cleanup count and syncs the directory after removal.
- Read-back verification is performed after every journal update.
- Temp files are never interpreted as committed state.

## Tests and local validation

The journal's eight tests cover:
- explicit create-once initialization and exact round trip;
- Prepared intent persistence, reopen and same-intent idempotency;
- rejection of a different intent while another is pending;
- commit finalization, pending-slot clearing and idempotent repeat finalization;
- independent sequence, record-generation and object-generation floor enforcement;
- checksum corruption, truncation and wrong provider pin rejection;
- hard-link alias rejection;
- actual child-process termination before and after atomic replacement, proving recovery sees either the prior complete Ready state or the complete Prepared state and cleans the orphan temp file.

The complete Rust library suite and all-target build are validated in the PR description after the final run. The crash tests ran on the Windows development machine. These tests do not establish independent anti-rollback storage, a real cloud provider, or two-host behavior.

## Explicitly not implemented

- No independent high-water store adapter or caller orchestration that atomically updates the independent floor.
- No DPAPI/HSM/remote witness configuration for journal floors.
- No concrete object-store or ECR1 provider implementation.
- No garbage collection for immutable objects left unreferenced by an interrupted publication.
- Not wired into `private_testnet_node`, default startup, Devnet or Mainnet.
- No Genesis, network ID, consensus/PoW, issuance, Mainnet approval or QZXB trading policy changed.

Next gate: bind this journal to an independently protected floor implementation and caller workflow, then test a real two-host provider adapter through restart, partition, stale writer, lost response and disk rollback before runtime wiring.

## Local validation

Observed on the Windows development machine:
- CP-0395 journal module tests: **8 passed, 0 failed**.
- Complete Rust library suite: `cargo test --lib --locked --offline -- --test-threads=4` — **807 passed, 0 failed**.
- `cargo check --all-targets --locked --offline`: passed (warnings remain in unrelated legacy modules and probe binaries; no CP-0395 warning).
- `cargo fmt --all -- --check`: passed.
- `git diff --check`: passed.

These are local candidate tests. They do not establish an independent high-water store, real provider integration, or multi-host operational readiness.
