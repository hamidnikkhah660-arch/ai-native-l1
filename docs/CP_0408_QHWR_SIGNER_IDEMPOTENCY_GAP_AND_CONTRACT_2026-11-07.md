# CP-0408 - QHWR Signer Idempotency Gap and Contract

**Status:** source-audited engineering contract / candidate specification only  
**Date:** 2026-11-07  
**Depends on:** CP-0402 authenticated dispatcher; CP-0403 replay identity; CP-0406 external replay authority; CP-0407 operation recovery model  
**Not a production approval:** no durable signer, HSM adapter, key-custody deployment, or production QHWR integration is implemented here.

## 1. Audit finding

The current QHWR dispatcher cannot meet CP-0407's signer recovery contract. The source-level findings are:

1. `QhwrResponseSigner` exposes `key_id()`, `key_generation()`, and `sign_digest(digest)`. Its signing call has no stable operation/idempotency key and no result-lookup method.
2. The only `QhwrResponseSigner` implementations found in the repository are test fixtures (`NeverSigner` and `FixedSigner`) in `private_testnet_pfm5_highwater_rpc_dispatch_candidate.rs`. No production QHWR signer implementation was found.
3. The dispatcher currently reserves the challenge, reads the provider, builds the signed response, calls `sign_digest`, and encodes the response. It has no CP-0407 operation journal, no Prepared snapshot persistence, and no durable Completed response cache.
4. `v4_fat1_mldsa65_candidate.rs` implements the ML-DSA-65 verifier interface. Its signing example is inside tests and generates a deterministic test key pair in-process; it is not a production signer or key-custody adapter.
5. The current source therefore supplies neither a durable signer-side idempotency boundary nor evidence that a real ML-DSA-65 signing key provider can retrieve a prior result after restart/failover.

Consequently, the current implementation cannot claim exactly-once QHWR signing. A successful signature followed by a lost reply or process crash can be ambiguous. Repeating `sign_digest` may perform another signing operation; a local mutex or process memory cannot resolve that ambiguity across restart.

## 2. Required signer interface semantics

The required semantic interface is:

```text
sign_once(
    operation_key,
    signer_key_id,
    signer_key_generation,
    signing_digest
) -> stable_signed_artifact

lookup_result(operation_key) -> authenticated status/result
```

The operation key MUST be recomputed or verified by the authority from the complete CP-0403 identity (domain/version, Network ID, authenticated Noise peer, decoded operation, challenge). It is not a client-selected arbitrary string.

For one operation key:

- the first accepted request binds the exact signer key ID, key generation, and signing digest;
- an exact retry returns the exact previously committed signature artifact;
- changed key ID, generation, or digest is an identity conflict and fails closed;
- concurrent same-key calls have one logical winner and all retries observe the same durable result;
- result lookup is authenticated and survives signer process restart and supported failover;
- the idempotency record and signature result are committed atomically within the signer's claimed failure domain, or the signer documents a stronger equivalent protocol with tested crash semantics.

A service that merely caches results in RAM, serializes calls with a process mutex, or regenerates a signature without retaining the original artifact does not satisfy this contract.

## 3. Ordering with the CP-0407 authority journal

The authority must commit `Prepared` (exact provider snapshot bytes/digest, provider identity, signer key ID/generation, signing digest, and operation key) before calling the signer.

After `Prepared` is durably acknowledged:

1. call `sign_once` using the unchanged operation key and exact pinned digest;
2. on timeout or lost reply, query/retry the same operation key; never create a new key;
3. after receiving the stable artifact, encode the complete response and commit exact response bytes plus digest as `Completed`;
4. write to the client socket only after `Completed` commit acknowledgement;
5. on a `Completed` retry, return the exact stored response bytes without provider or signer calls.

If the signer cannot provide durable idempotency/result lookup, the operation remains `Prepared` and is quarantined. It must not be silently re-signed under a new operation key, new key generation, or changed digest. The system must not claim exactly-once signing.

## 4. Key custody and ML-DSA-65 qualification

The existence of an ML-DSA-65 verifier and test-only signing calls does not establish production key custody. Before selecting an HSM or signer service, qualify:

- whether ML-DSA-65 private keys can be generated/imported and retained inside the intended security boundary;
- whether the device/service exposes stable key ID and monotonic key generation metadata;
- whether it supports durable operation-key idempotency and authenticated result lookup;
- whether a completed signature artifact survives restart, replica failover, firmware update, key rotation, and backup recovery;
- whether signing randomness and retry semantics are handled by returning the stored artifact rather than assuming a second signature will be byte-identical;
- whether signer audit logs and idempotency records are protected against rollback and unauthorized deletion;
- whether the signer operator, credentials, storage, and rollback authority are independent from QRun node hosts.

No assumption is made that a generic HSM, PostgreSQL, DPAPI store, or the current Libcrux test primitive automatically provides these properties.

## 5. Required adversarial qualification

1. Two signer replicas receive the same operation key concurrently: one durable result, same artifact returned to both callers.
2. Same operation key with changed digest, key ID, or generation: conflict, no second signature.
3. Signer commits signature but response is dropped: retry/lookup returns the exact stored artifact.
4. Signer process is killed immediately before and after durable result commit: recovery returns either no committed result or the exact committed result, never an ambiguous regenerated artifact.
5. Signer replica failover during signing: no duplicate logical operation and no result loss.
6. Authority process crashes after Prepared and before signer call: same key/digest resumes.
7. Authority process crashes after signer commit and before Completed: signer result is recovered and the same response is completed.
8. Authority process crashes after Completed and before socket write: cached bytes are replayed without signer call.
9. Key rotation does not invalidate old operation lookups or permit operation-key reuse under a new generation.
10. Stale backup restore, record tampering, signer unavailability, and ambiguous lookup all fail closed.

Every result must identify its evidence class: unit/model, local signer process, multi-process, multi-replica, independently administered multi-host, or production evidence. Model tests are not durability evidence.

## 6. Implementation gate and non-claims

The next implementation must begin with a provider-neutral signer adapter contract and test double that explicitly models durable result lookup, then a separately deployable signer service/HSM integration selected only after vendor capability evidence is obtained. Do not retrofit the current `sign_digest` method and label it idempotent.

This document does not implement a signer, HSM, key custody, durable signature-result journal, external authority, multi-host qualification, or production integration. It does not authorize deployment, Mainnet, or Public Mint. The current QHWR signer interface remains non-idempotent and test-only.
