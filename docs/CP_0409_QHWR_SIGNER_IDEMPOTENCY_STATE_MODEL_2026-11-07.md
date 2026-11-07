# CP-0409 — QHWR Signer Idempotency State Model

**Date:** 2026-11-07  
**Status:** candidate implementation on a stacked work branch; local formatting, all-target check, and all-target tests passed. Remote CI remains pending.  
**Scope:** provider-neutral, in-memory state-transition model only.

## Why this change exists

CP-0408 identified that the existing QHWR signer trait exposes key metadata and
`sign_digest`, but no stable operation key or authoritative result lookup.
Consequently, a signer that accepted a request followed by a lost reply leaves
the caller unable to distinguish “signature committed” from “signature never
happened”. Reissuing a plain `sign_digest` can create a second signing event.

## Pinned request identity

Every model record is keyed by a stable 32-byte signer operation key and pins:

- a domain-separated digest representing the complete canonical CP-0403/QHWR
  identity (including Network ID, peer, operation and challenge);
- signer key ID and key generation; and
- the exact signing digest.

Reusing an operation key with any changed field is rejected as an identity
conflict. This model accepts the already-computed QHWR identity digest; it does
not construct or validate the canonical encoding or its hash.

## State machine

`Absent -> Reserved -> Completed(exact artifact)`

`Reserved -> OutcomeUnknown -> Completed(exact artifact)`

Only the first in-process reserve caller receives `Acquired`. A retry observing
`Reserved` cannot obtain another signing claim. When the signer outcome is
ambiguous (for example, a timeout after a request may have committed), the
record moves to `OutcomeUnknown`; subsequent reservations remain quarantined.
The only modeled recovery path is to provide the exact artifact obtained from
an authoritative result lookup for the same pinned operation identity.

After `Completed`, retries return the exact stored artifact bytes. Repeating
completion with identical bytes is idempotent; attempting to replace the bytes
is rejected. Empty artifacts are rejected.

## Test coverage in this candidate

The unit tests cover exact retry behavior, identity/key/digest pinning, lost
reply quarantine and authoritative recovery, immutable completed artifacts,
independent operation keys, 16-thread in-process reservation contention, and
empty-artifact rejection.

## Explicit limitations

This is a process-local `Arc<Mutex<HashMap<...>>` model. It does **not** prove:

- durability across process restart, host failover, or power loss;
- linearizability across processes, machines, or signer replicas;
- authenticated provenance of lookup results;
- real signing, HSM custody, key rotation safety, or cryptographic validity;
- rollback resistance, external anti-rollback anchoring, or retention policy;
- integration into the production QHWR dispatcher or node startup.

The method named `complete_from_authoritative_result` is a model transition:
the caller must authenticate the authority's response. A production system
must not call it with an unverified result.

## Production contract required before exactly-once claims

A production signer must implement an atomic, durable
`sign_once(operation_key, full_identity, key_id, key_generation, signing_digest)`
and an authenticated `lookup_result(operation_key)`. It must retain and return
the exact artifact on retries, reject conflicting request identities, serialize
concurrent duplicates, and preserve state across restart/failover with
rollback-resistant durability. Unavailable or ambiguous authority state must
fail closed; it must never fall back to a fresh unkeyed signing attempt.

This CP-0409 candidate does not implement that production contract and must not
be represented as production signing or complete QHWR exactly-once protection.
