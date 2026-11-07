# CP-0411 — QHWR Durable Operation Journal Design Contract

**Date:** 2026-11-07
**Status:** Design contract only. No implementation or production integration is claimed.

**Parent:** CP-0410 idempotent signer interface contract.

## 1. Purpose

CP-0407 defined an in-memory `Absent -> Reserved -> Prepared -> Completed` transition model. CP-0405 supplied a single-host append-only replay-reservation WAL, but that WAL stores only fixed-size replay keys. It cannot persist the full QHWR operation identity, immutable provider snapshot, signer pins, or exact completed response. CP-0411 defines the requirements for a separate durable operation journal candidate.

## 2. Required persisted state

Each journal entry is keyed by a 32-byte operation key and binds, without mutable substitution:

- operation key and QHWR identity digest;
- request digest and provider identity;
- exact canonical provider snapshot bytes;
- signer key ID, signer key generation, and signing digest;
- exact signed artifact bytes and artifact digest, once available;
- exact encoded response bytes and response digest, once completed.

The journal must reject a retry whose identity, provider snapshot, signer pins, signing digest, artifact, or response differs from the already persisted value. A completed retry returns the exact stored response bytes; it must not re-read the provider or re-sign.

## 3. WAL framing and recovery requirements

The implementation candidate should use versioned, domain-separated records with explicit bounded lengths, operation key, transition kind, payload, and a cryptographic checksum. Parsing must use checked arithmetic and enforce per-field, per-record, and total-journal limits before allocation.

- A partial final frame may be truncated only if it is demonstrably incomplete and was never acknowledged.
- A complete frame with bad magic, unsupported version, invalid transition, duplicate/conflicting identity, malformed lengths, or checksum failure must fail closed; do not silently skip or repair it.
- A successful transition is acknowledged only after the record is fully written and the required file sync succeeds.
- After uncertain write/sync errors, poison the live instance and require close/reopen recovery before reuse.
- Enforce one writer per canonical path and file identity; reject symlink/hard-link aliasing where supported.
- On Windows, pre-provision the journal file unless parent-directory entry durability is independently established. Do not claim directory-entry power-loss durability based on `sync_all` of the file alone.

## 4. Transition ordering

1. `reserve`: durably persist immutable operation identity before provider work.
2. `prepare`: durably persist the exact provider snapshot and signer key ID/generation/signing digest before invoking the signer.
3. `sign`: call only the CP-0410 `sign_once(operation_key, ...)` contract.
4. Resolve ambiguous signer outcomes only through authenticated durable `lookup_result(operation_key)` or an exact idempotent retry using the same key and same request.
5. Persist the exact returned signer artifact before constructing/completing the response.
6. `complete`: durably persist exact response bytes and digest before any socket write.
7. On restart, `Completed` replays exact bytes. `Prepared` must query the durable signer. If signer lookup is unavailable or not proven durable, quarantine/fail closed; never issue a fresh non-idempotent signature.

## 5. Explicit non-goals and limits

This journal is a local single-host durability candidate, not a distributed consensus log, not a linearizable multi-host replay authority, and not an independent anti-rollback anchor. A privileged local attacker may rewrite or roll back an unkeyed local journal. The CP-0406 external replay authority and CP-0410 durable signer idempotency remain separate dependencies. This journal does not make the current production QHWR dispatcher safe by itself.

No production signer, HSM/KMS adapter, key custody, external authority, or production dispatcher wiring is included in this contract.

## 6. Required test matrix before implementation acceptance

- all valid transitions and exact idempotent retries;
- changed identity, provider snapshot, signer key generation, signing digest, artifact, or response rejected;
- restart/reopen from each durable transition;
- partial-tail truncation and preservation of earlier acknowledged transitions;
- complete-frame checksum corruption and malformed length fail closed;
- duplicate operation records and illegal transition order fail closed;
- injected write and sync failures poison the instance;
- concurrent writer, hard-link alias, and symlink/path alias rejection where supported;
- capacity exhaustion fails closed without deleting retained operations;
- Windows and Unix behavior tested separately, with platform durability claims stated narrowly;
- crash-boundary test proving no socket response is emitted before `Completed` is durable;
- signer ambiguity test proving `Prepared` recovery performs lookup/same-key idempotent retry only, never a new operation key or changed signing digest.

## 7. Acceptance boundary

CP-0411 is complete only after a separately reviewed implementation, local restart/crash tests, Windows and Unix CI, and a documented integration review. Passing unit tests alone does not establish multi-host safety, anti-rollback, production signer conformance, or mainnet readiness.