# CP-0410 — Provider-Neutral QHWR Idempotent Signer Contract

**Date:** 2026-11-07  
**Status:** interface and value types implemented as a candidate contract; no signer implementation.  
**Depends on:** CP-0403 full replay identity, CP-0407 operation recovery, CP-0408 signer gap audit, CP-0409 in-memory transition model.

## 1. Purpose

CP-0409 models signer idempotency transitions in process memory. CP-0410 introduces a typed, provider-neutral Rust boundary for a future independently operated signer service or HSM adapter.

The contract deliberately does not retrofit the existing QHWR dispatcher trait. That trait still exposes non-idempotent sign_digest and has no production signer implementation.

## 2. Typed request identity

The interface pins:

- operation key: domain-separated SHA-256 over the canonical CP-0403 identity digest;
- the CP-0403 identity digest itself;
- signer key ID;
- signer key generation; and
- exact signing digest.

The canonical CP-0403 identity digest must be recomputed or verified by the trusted authority from domain/version, Network ID, authenticated Noise peer, decoded operation, and challenge. The helper in the Rust module accepts an already-computed digest; it does not encode or validate the CP-0403 structure.

The signer must reject an operation key that does not match the supplied identity digest, and reject any reuse with changed identity, key ID, generation, or signing digest.

## 3. Interface semantics

The candidate Rust trait exposes:

- sign_once(request) -> exact opaque signature artifact;
- lookup_result(request) -> NotFound, Pending, or Completed(exact artifact).

The artifact includes exact signature bytes and a domain-separated SHA-256 digest over its length and bytes. Consumers must validate the digest before using the artifact. This detects accidental or transport corruption; it is not an authentication mechanism.

Errors distinguish invalid requests, identity conflict, authority unavailability, ambiguous outcome, explicit rejection, and integrity failure.

## 4. Required implementation guarantees

Any implementation claiming conformance must provide:

1. Atomic first-writer binding of operation key and all request fields.
2. One logical signing operation for concurrent duplicate calls across all replicas in the claimed failure domain.
3. Exact artifact retention and byte-identical return on every retry.
4. Conflict on changed identity, key ID, generation, or digest.
5. Authenticated and strongly consistent result lookup.
6. Durable result lookup after restart and supported failover.
7. Rollback-resistant records and an independently qualified recovery/backup procedure.
8. Indefinite retention for QHWR v1 because there is no server-issued expiry lease.
9. Fail-closed behavior for unavailable, stale, ambiguous, or integrity-failed authority state.

NotFound is actionable only if the signer guarantees a strongly consistent lookup and no accepted operation can be lost or rolled back. A stale replica returning NotFound is not safe.

## 5. Required caller ordering

The QHWR authority must durably commit Prepared before calling sign_once. On timeout or lost reply it must use the same operation key and query/retry the same request. After obtaining the exact artifact it commits exact response bytes as Completed. It may write to the client socket only after Completed is durably acknowledged. Completed retries return cached response bytes without provider or signer calls.

If the signer cannot resolve an ambiguous outcome, the operation remains quarantined. The caller must not generate a new operation key or call legacy sign_digest as a fallback.

## 6. Test and qualification matrix

A conforming implementation needs tests for:

- same-key concurrent requests to two or more signer replicas;
- exact retry returns exact original signature bytes;
- same key with altered identity/key ID/generation/digest returns conflict;
- signer commit followed by dropped response;
- process kill immediately before and after durable commit;
- process restart and replica failover;
- stale lookup replica and stale backup restore;
- key rotation while old operation results remain retrievable;
- authority crash after Prepared and after signer commit but before Completed;
- authority crash after Completed but before socket write;
- unavailable signer and ambiguous lookup fail closed.

Evidence must be labeled by level: unit/model, single process, multi-process, multi-replica, independently administered multi-host, or production.

## 7. Current implementation status and non-claims

CP-0410 adds only typed request/artifact/lookup/error values, operation-key and artifact-digest helpers, and unit tests for those value semantics. It does not implement signing, durable storage, authenticated transport, a signer service, an HSM, key custody, or a production dispatcher adapter.

The existing QHWR signer remains non-idempotent. The in-memory CP-0409 model remains a model. Neither CP-0409 nor CP-0410 proves exactly-once signing across process restart, host failover, or rollback.

No production, mainnet, public-mint, or deployment approval is implied.
