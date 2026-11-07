# CP-0406 — QHWR External Replay Authority Contract

**Status:** design contract / candidate specification only
**Date:** 2026-11-07
**Depends on:** CP-0403 replay scope and challenge lifecycle; CP-0405 single-host durable replay ledger candidate
**Not a production approval:** this document defines a qualification target. It does not deploy an authority, wire production dispatch, or establish multi-host security.

## 1. Purpose and boundary

CP-0405 provides a conservative append-only replay ledger for one host and one local storage rollback domain. It is not a multi-host authority. The existing PFM5 external High-Water provider provides authenticated monotonic state and compare-and-advance semantics; it is not, by itself, an arbitrary-key membership registry. A rolling digest or sequence number cannot prove that an arbitrary prior QHWR challenge has not already been consumed unless the authority also retains/query-checks the relevant membership set under an atomic operation.

CP-0406 defines the minimum external authority contract needed before an implementation can be considered. It deliberately does not adapt the current High-Water API by pretending that a scalar high-water mark is a replay-key set.

## 2. Replay identity

The authority key MUST be domain-separated and bind the complete CP-0403 scope:

- protocol/domain tag and version;
- Network ID;
- authenticated Noise peer identity;
- operation identifier;
- 32-byte challenge.

The authority MUST derive the canonical replay key itself from these typed fields, or verify a canonical digest supplied by a trusted adapter. It MUST reject zero/invalid required identity fields and unknown protocol versions. A caller-supplied opaque key without verifiable scope binding is insufficient.

## 3. Required atomic operation

The minimum semantic operation is:

    reserve_once(scope, challenge) -> authenticated reservation receipt

For a given replay identity, all concurrent requests across all authority replicas MUST be linearizable: at most one logical reservation may be created. A successful response MUST mean the reservation is durably committed in an independent rollback domain before the response is emitted.

The authority MUST retain membership for every challenge that can still be replayed. QHWR v1 has no server-issued expiry lease, so the safe default is indefinite retention. Any future expiry/compaction requires a protocol revision with authority-issued expiry semantics, authenticated time/lease rules, and a proof that expired challenges cannot be replayed.

A rolling digest, sequence number, CAS generation, or hash-chain head without a retained membership index is NOT sufficient to answer arbitrary historical duplicate queries.

## 4. Ambiguous replies and idempotency

A transport timeout does not prove that a reservation failed. The authority MUST support an authenticated query/retry by the same replay identity that returns the same durable reservation receipt if the reservation committed, and returns an authenticated absence only if it did not commit. It MUST NOT create a second logical reservation or a second receipt identity for the same key.

The receipt MUST bind at least the authority identity, provider identity, Network ID, canonical replay-key digest, reservation generation/sequence, and protocol version. The receipt MUST be authenticated by a pinned authority key and verified before any provider/signer side effect.

**Important crash boundary:** a reservation service alone cannot guarantee exactly-once execution of a separate provider/signer side effect. If the process crashes after durable reservation but before the side effect, strict duplicate rejection can lose the operation. If a retry is allowed to repeat the side effect, it can duplicate it. Therefore production integration MUST choose and prove one of:
1. provider/signer accepts the same stable idempotency key and durably deduplicates the side effect; or
2. reservation and side effect are part of one transactional/outbox protocol with recoverable Pending/Committed states and authenticated completion receipts.

Until one is implemented and crash-tested, claims are limited to atomic replay reservation / at-most-once admission, not exactly-once business execution.

## 5. Failure semantics

The adapter and dispatcher MUST fail closed on:
- unavailable authority, timeout, malformed response, invalid signature, wrong authority/provider/network pin;
- stale, forked, rolled-back, or equivocal authority state;
- ambiguous result that cannot be resolved by authenticated read/retry;
- capacity/quota exhaustion or membership-retention uncertainty;
- unsupported protocol version or identity mismatch.

No provider/signer side effect may occur before the reservation gate has a verified success state. A failed or ambiguous call MUST NOT be converted into local-only success or silently fall back to CP-0405 storage.

## 6. Independence and rollback resistance

The authority MUST be outside the node's local disk, VM snapshot, host backup, and operator rollback domain. Replicas must not share a single administrative rollback point that defeats the claimed independence. The qualification package must document:
- authority operator and trust boundary;
- replication and quorum/consensus model;
- durable commit definition and acknowledgement point;
- backup/restore and disaster-recovery behavior;
- monotonicity/rollback detection and key-retention guarantees;
- signer key custody, rotation, revocation, and pin rollover;
- audit log and incident recovery process.

A second directory, disk, volume, or process on the same host is not an independent authority.

## 7. Qualification matrix required before production wiring

The implementation must pass, with at least two independent nodes and multiple authority replicas where applicable:

1. simultaneous same-key reservation race: exactly one logical reservation;
2. distinct scopes (network, peer, operation, challenge): no accidental collision;
3. lost response after commit: retry returns the same receipt;
4. lost response before commit: authenticated absence, then one successful reservation;
5. replica failover during reservation: no split-brain duplicate acceptance;
6. stale replica / rollback / restored backup: fail closed;
7. authority signature tampering and pin mismatch: reject before side effect;
8. authority outage and quota exhaustion: fail closed;
9. process crash between reservation and side effect;
10. process crash after side effect but before client response;
11. provider/signer idempotency or transactional outbox recovery;
12. key rotation and authority recovery without replay-window reopening;
13. membership retention and capacity boundary under QHWR v1 indefinite retention.

Every test must record the exact authority topology, fault injection point, expected durable state, observed side-effect count, and recovery result.

## 8. Integration gates

No production dispatcher wiring is authorized by this design document. The following remain separate gates:

- concrete external authority implementation and independently reviewable protocol;
- authenticated receipt verifier and pinned key lifecycle;
- proven linearizable unique reservation and durable membership;
- idempotent provider/signer operation or transactional outbox;
- independent multi-host and crash/failover qualification;
- capacity and retention operations plan;
- security review and explicit production approval.

CP-0405 remains a single-host candidate only. Its Windows parent-directory durability limitation remains open; CP-0406 does not resolve it. Public Mint and production activation remain disabled until all required gates are independently satisfied.
