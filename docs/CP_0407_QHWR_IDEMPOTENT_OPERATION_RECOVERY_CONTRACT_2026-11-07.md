# CP-0407 - QHWR Idempotent Operation and Crash-Recovery Contract

**Status:** engineering contract / candidate specification only  
**Date:** 2026-11-07  
**Depends on:** CP-0401 wire protocol; CP-0402 authenticated dispatcher; CP-0403 replay scope and v1 lifecycle; CP-0405 local ledger candidate; CP-0406 external replay authority contract  
**Not a production approval:** no external service, signer integration, or production dispatcher is implemented by this document.

## 1. Purpose

CP-0406 establishes that an atomic replay reservation is not equivalent to exactly-once execution. This contract specifies how a QHWR READ operation can resume after a process crash and return the same response after a lost client reply, without invoking an external signing side effect twice.

The current dispatcher performs, in order: durable replay reservation, authenticated provider read, response construction, signer call, response encoding, and socket write. The reservation is currently a terminal duplicate gate. A crash after reservation can therefore consume the challenge without leaving a recoverable response. CP-0407 defines the missing operation journal and signer idempotency boundary.

This is a READ-path recovery design. It does not authorize COMPARE_AND_ADVANCE, production exposure, or a change to the QHWR v1 wire format.

## 2. Operation identity and payload binding

The stable operation key MUST be derived by the authority from the complete CP-0403 replay identity: protocol/domain tag and version; Network ID; authenticated Noise peer; decoded operation; and challenge.

The operation record MUST additionally bind a canonical request digest. Reusing the same operation key with a different request digest, provider identity, response-signing domain, or incompatible signer-key generation MUST fail closed as an identity conflict. A caller-supplied idempotency key is not authoritative unless the service recomputes or verifies it from these fields.

The same operation key is used for the unique replay reservation, durable operation-journal row, signer idempotency key, and authenticated status/recovery queries. It MUST remain stable across process restart, connection retry, and authority replica failover.

## 3. Durable operation state machine

The authority MUST atomically create the unique replay reservation and its initial operation record in one serializable/linearizable transaction, or expose an equivalent protocol with a proof that no crash window can create a reservation without a recoverable operation identity.

Required states:

- **Absent** — no reservation or operation row exists.
- **Reserved** - the unique replay reservation and initial operation row are committed atomically; the request digest and all identity pins are fixed. No signer call is allowed.
- **Prepared** - exact provider snapshot bytes/digest, signer key ID, signer key generation, and signing digest are durably recorded.
- **Completed** - exact encoded response bytes and their digest are durably recorded and bound to the same operation identity.

Allowed transitions:

- Absent to Reserved: one atomic transaction; only one winner for the operation key.
- Reserved to Prepared: persist the exact provider snapshot and immutable signing parameters.
- Prepared to Completed: compare-and-set against the exact prepared record; completion is immutable.
- Reserved to Reserved and Prepared to Prepared: idempotent read/retry of the exact same record.
- Completed to Completed: idempotent retrieval of the exact cached response.

Forbidden transitions:

- Completed to Prepared or Absent.
- Reserved or Prepared to Absent by timeout, eviction, backup restore, or operator cleanup.
- Any same-key request with a different request digest or prepared payload.
- Replacing the provider snapshot or signer key identity after Prepared.
- Marking Completed before the response bytes are durably stored.
QHWR v1 has no authenticated expiry lease. Prepared and Completed records, and their replay identities, MUST NOT be automatically expired or evicted under v1. Capacity exhaustion fails closed.

## 4. Provider snapshot and signer idempotency

The provider READ is intended to be side-effect-free, but its returned state may change over time. Before signing, the operation authority MUST persist the exact canonical provider response bytes (or an unambiguous canonical snapshot from which those exact bytes are reconstructed), the pinned provider identity, and the signing digest in the Prepared record.

Once Prepared is committed, retries MUST NOT perform a fresh provider read and silently sign a different state for the same operation key. They MUST use the exact prepared snapshot and signing digest.

The signer interface required for recovery is semantically:

    sign_once(operation_key, signer_key_id, signer_key_generation, signing_digest)
        -> stable signed artifact

For the same operation key and exact signer identity/digest, the signer MUST durably return the same artifact on every retry, including after signer process restart and failover. Reusing the key with a different digest or key generation MUST be rejected. A local mutex or an in-memory cache is insufficient.

If the HSM/provider cannot provide durable idempotent signing or an authenticated result lookup by operation key, the system MUST NOT claim exactly-once signing. The operation remains Prepared and is quarantined for explicit recovery; it must not switch to a new idempotency key or sign a different digest.

## 5. Completion and response replay

After obtaining the stable signed artifact, the dispatcher constructs and encodes the complete QHWR response. It then atomically changes Prepared → Completed while storing the exact response bytes and response digest. Only after the Completed commit is acknowledged may the response be written to the client socket.

On retry:
- Completed: verify the stored record and return the exact cached response bytes; do not call provider or signer again.
- Prepared: verify the same request and pinned identities, call signer with the same idempotency key and digest, then attempt the same immutable completion transition.
- Ambiguous authority response: query the same operation key. Never create a second reservation or signer key.
- Authority unavailable, signature invalid, state conflict, or unresolved ambiguity: fail closed and perform no new provider/signer operation.

A socket write failure after Completed is not an operation failure. The client retry retrieves the already completed response.

## 6. Crash-window analysis

| Crash point | Durable state expected | Recovery action |
|---|---|---|
| Before reservation transaction | Absent | Retry may create the single reservation |
| After atomic reservation/Reserved commit, before provider work | Reserved | Resume the exact operation and perform the side-effect-free provider read |
| After provider read, before Prepared snapshot persistence | Reserved | No signer call; repeat the side-effect-free read, then persist one snapshot before signing |
| After Prepared payload commit, before signer call | Prepared | Call signer with the same operation key and digest |
| After signer completed, before authority completion commit | Prepared + signer has durable result | Retry signer with same key; signer returns same artifact; complete journal |
| After Completed commit, before socket write | Completed | Return exact cached response; no provider/signer call |
| During/after socket write with lost client reply | Completed | Return exact cached response on retry |

The Prepared boundary MUST be unambiguous. A partially written or partially replicated Prepared record is never treated as committed. The signer must not be called until the Prepared commit has a verified durable acknowledgement.

## 7. Transaction and topology requirements

Preferred topology: one independently administered authority database/service owns both the unique replay row and operation-journal row, committing them in one transaction. The signer is a separate service/HSM with durable idempotency keyed by the operation key.

If replay reservation and operation journal are separate services, the protocol MUST define an idempotent reservation receipt and a recoverable reconciliation state. It must demonstrate that a committed reservation can always be mapped to exactly one operation row after crashes and failover. Merely calling two services sequentially is insufficient.

A PostgreSQL implementation is a candidate, not a guarantee. Qualification must establish: unique constraint over the canonical operation key; transaction isolation and conflict behavior under simultaneous requests; synchronous/durable commit acknowledgement policy appropriate to the claimed failure domain; WAL/checkpoint and replica failover behavior; backup/restore rollback detection from a separately administered monotonic authority; idempotent status lookup and immutable completion; and independent operator, host, storage, and administrative credentials from node hosts.

An asynchronous replica or a database restored from a stale backup MUST NOT be allowed to accept a replay key whose committed reservation may have been lost.

## 8. Required qualification matrix

1. Concurrent same-key submissions against at least two service replicas: one Prepared row and one logical reservation.
2. Same key with changed request digest: conflict, no signer call.
3. Same key with changed Network ID, peer, operation, or challenge: distinct scope or explicit invalid identity as defined by CP-0403.
4. Crash immediately before and after the reservation/Prepared transaction.
5. Crash after provider read but before Prepared snapshot persistence.
6. Crash after Prepared commit but before signer invocation.
7. Signer commits but its reply is lost: retry returns identical artifact.
8. Signer key ID/generation/digest mismatch on retry: fail closed.
9. Crash after signer success but before Completed commit: one signer logical operation and one final response.
10. Crash after Completed commit but before socket write: retry returns byte-identical cached response.
11. Authority commit reply lost: authenticated lookup resolves exact state.
12. Replica failover and stale replica read: no duplicate reservation or stale completion.
13. Stale backup restore / rollback: fail closed before signer call.
14. Capacity exhaustion: fail closed, no eviction.
15. Corrupt/tampered operation record or response bytes: reject before returning response.
16. Authority/signing-key rotation: old records remain verifiable and no replay window reopens.

Each result must identify whether it is a pure model test, local database test, multi-process test, CI test, independently administered multi-host test, or production evidence.

## 9. Implementation sequence and non-claims

1. Review CP-0407 against CP-0402/0403/0405/0406 and settle the exact canonical request/response codecs.
2. Implement a pure transition model and adversarial crash-window tests.
3. Implement an external authority adapter and transactional operation journal; do not substitute an in-memory map or CP-0405 local WAL.
4. Specify and qualify signer idempotency or authenticated result lookup for the actual ML-DSA-65 key custody provider.
5. Run multi-replica, multi-host, failover, stale-backup, and signer crash tests.
6. Only then design production dispatcher integration behind an explicit feature/configuration gate and independent review.

This contract does not implement PostgreSQL, an external service, a signer/HSM idempotency API, a durable operation journal, multi-host linearizability, anti-rollback, or production recovery. It does not authorize deployment or production wiring. CP-0405 remains a single-host candidate; CP-0406 remains an external authority contract; Public Mint remains disabled.

## 10. CP-0407 pure model implementation evidence

The first implementation slice is `src/native/pow_bench/src/private_testnet_qhwr_operation_recovery_model.rs`, exported as `private_testnet_qhwr_operation_recovery_model`. It is deliberately an in-memory pure transition model, not an authority adapter.

The model exercises the Absent -> Reserved -> Prepared -> Completed sequence; idempotent same-state retries; immutable operation/request/provider pins; immutable provider snapshot and signer key ID/generation/signing digest after Prepared; completion only from Prepared; SHA-256 verification metadata for exact response bytes; and rejection of changed completion bytes or forbidden regression.

Five focused unit tests currently pass. Their evidence class is **local pure-model unit tests** only. The model has no disk/database persistence, no concurrent transaction semantics, no replica/failover behavior, no rollback protection, no real provider call, and no signer/HSM call. It therefore proves neither crash recovery nor exactly-once execution. The next implementation boundary remains an external transactional authority and a separately qualified durable-idempotency signer.
