# CP-0412 - QHWR Durable Operation Journal Candidate

**Date:** 2026-11-07
**Status:** Local single-host implementation candidate. Research-only; not production-wired.
**Parent:** CP-0411 durable operation journal design contract.

## 1. Scope

CP-0412 implements a versioned append-only journal for one QHWR operation identity. It is separate from CP-0405's fixed-width replay-reservation WAL. Its purpose is to retain the exact operation inputs, signer pins, signer artifact, and completed response across process restart.

The module is exported for tests and research use only. The live QHWR dispatcher does not open this journal and no production request can rely on it yet.

## 2. Persisted state and order

The state machine is:

**Absent -> Reserved -> Prepared -> Signed -> Completed**

- **Reserved:** operation key, QHWR identity digest, request digest, provider identity.
- **Prepared:** exact provider snapshot bytes, signer key ID, signer key generation, signing digest.
- **Signed:** exact signer artifact bytes and the CP-0410 artifact digest.
- **Completed:** exact encoded response bytes and SHA-256 response digest.

The operation key is recomputed from the QHWR identity digest using the CP-0410 domain-separated derivation. A changed reservation, provider snapshot, signer key pin, signing digest, artifact, or completed response is rejected. Exact retries are idempotent no-ops.

The required call order for a future dispatcher is reserve before provider access, prepare before sign_once, record_artifact after the signer result, and complete before any socket write. After restart, a Completed operation can return the retained response bytes. A Prepared operation is not permission to sign again: recovery must query the CP-0410 durable signer using the same operation key and exact pinned request, or fail closed.

## 3. Frame format and bounds

Each record contains a fixed header, bounded payload, and SHA-256 checksum:

- 8-byte magic QHWRJNL1;
- 1-byte format version;
- 1-byte transition kind;
- 4-byte big-endian payload length;
- 32-byte operation key;
- transition-specific payload;
- 32-byte domain-separated checksum over the complete header and payload.

Lengths are validated before payload allocation. The current candidate caps provider snapshots at 4 MiB, signer artifacts at 1 MiB, responses at 4 MiB, the journal at 128 MiB, and retained operations at 100,000. Exhaustion fails closed; this version has no compaction or deletion policy.

A partial final frame is truncated to the last valid offset during reopen. A complete frame with invalid magic/version/kind, impossible length, bad checksum, malformed payload, duplicate operation, or illegal transition fails closed. Append/write/sync uncertainty poisons the live handle; callers must close and reopen before reuse.

## 4. File and platform behavior

The candidate uses the repository's path lock and file-identity lock to enforce a single writer and reject aliases supported by those lock primitives. On Unix, creation of a new journal is followed by file sync and parent-directory sync. On Windows, the journal file must be pre-provisioned; this candidate does not claim that syncing the file alone makes a newly created directory entry durable.

The checksum detects accidental corruption, not a malicious local rewrite. A privileged local actor can rewrite the journal and recompute an unkeyed checksum. The file is not an independent rollback-resistant authority.

## 5. Local tests currently present

The module's focused unit tests cover:

- full lifecycle and byte-identical response after close/reopen;
- exact idempotent retries and immutable identity conflicts;
- illegal transition order;
- incomplete final header and partial payload truncation while retaining earlier acknowledged state;
- complete-record checksum corruption;
- oversized declared frame length rejected before allocation;
- completed-response digest and exact-byte retention;
- exclusive single-writer lock behavior.

The focused Windows local run passed all 9 tests at the time of this document. This is not a power-loss test, cross-host test, external signer qualification, or production integration test.

## 6. Explicit gaps before acceptance

1. Add deterministic fault injection for write, file-sync, and recovery I/O failures; prove the live instance poisons on uncertain append.
2. Add deeper malformed-payload, duplicate-transition, hard-link/symlink alias, and capacity-boundary tests.
3. Run full Rust tests and cargo check --all-targets on Windows and Unix CI for this commit.
4. Qualify actual power-loss and filesystem durability assumptions on supported filesystems.
5. Integrate only after the external CP-0406 replay authority and CP-0410 durable idempotent signer have conforming implementations.
6. Prove at the dispatcher boundary that no socket bytes are sent before Completed is durably committed, and that restart from Prepared uses signer lookup/exact same-key retry only.
7. Obtain independent security review and independent multi-host qualification.

Passing this candidate's unit tests does not establish exactly-once signing, multi-host linearizability, anti-rollback, consensus safety, production readiness, or public-mint readiness.
