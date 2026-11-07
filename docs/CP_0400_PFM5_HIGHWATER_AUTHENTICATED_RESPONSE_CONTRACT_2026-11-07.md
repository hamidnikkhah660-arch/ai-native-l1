# CP-0400 — PFM5 High-Water authenticated response contract

Status: candidate implementation; not production approved.

## 1. Purpose and trust boundary

CP-0400 adds an authenticated response envelope around the CP-0400 v1 canonical High-Water state bytes. The node must receive the authority verification key through an independently reviewed, out-of-band provisioning path. A key returned by the same provider response is not a trust anchor.

The provider's private signing key must remain outside node storage and outside the provider's ordinary state database. This candidate carries only the authority ID, key ID, key generation, and public key in a local verifier pin.

## 2. Canonical state

The QHWA v1 fixed-width encoding binds:
- authority ID, provider ID, network ID, and Genesis digest;
- journal sequence;
- all ECR1 record fields; and
- immutable-object generation.

Integers are unsigned big-endian. Decoders require exact length, magic, supported version, valid domain bindings, valid ECR1 shape, and canonical re-encoding. The state digest uses SHA-256 with the dedicated QRun/PFM5/HighWater/StateDigest/v1 domain.

## 3. Authenticated response

The signed response contains:
- a caller-generated 32-byte challenge;
- authority key ID and key generation;
- exact QHWA v1 bytes; and
- an ML-DSA-65 signature.

The signature digest is SHA-256 over the response signing domain, challenge, key ID, key generation, encoded state length, and exact encoded state bytes. This binds the response to the outstanding request and to the full canonical state. The caller must generate a cryptographically secure, unpredictable challenge for each request and compare it with the outstanding request context. This module does not generate randomness, track outstanding requests, or maintain a network replay cache.

Verification rejects zero/mismatched challenges, authority mismatch, invalid pins, key ID mismatch, key generation mismatch, malformed or cross-domain state, and invalid ML-DSA-65 signatures. The public key is supplied by the verifier pin, not read from the response.

## 4. Algorithm and lifecycle caveats

This candidate reuses the repository's existing ML-DSA-65 verifier interface and Libcrux candidate implementation. It does not create a new cryptographic primitive or imply that all QRun network traffic is post-quantum.

The verifier pin currently represents one active key generation. Key rotation, revocation distribution, bootstrap ceremony, threshold/multi-operator authorization, recovery of lost authority keys, and rollback-resistant trust-store updates are not implemented here. They require a separate reviewed trust lifecycle before production use. In particular, changing a local pin is not itself secure key rotation.

## 5. Not implemented / non-goals

- no network transport, TLS/mTLS, RPC client, or request-challenge generator;
- no replay cache or distributed request coordination;
- no remote linearizable compare-and-advance provider;
- no independently operated authority or production key custody;
- no AWS/KMS/cloud resource, credentials, paid service, or deployment;
- no runtime/node callsite, consensus/Genesis/economics change, or release-gate change;
- no Devnet/Mainnet, public-launch, or full-network post-quantum approval.

## 6. Required follow-up qualification

Before any production consideration:
1. Define and review authority bootstrap and out-of-band pin distribution.
2. Specify key rotation/revocation with monotonic trust-store generations and recovery.
3. Qualify unpredictable challenge generation, expiration, outstanding-request binding, and replay handling in the actual client transport.
4. Implement remote compare-and-advance that conditionally compares the complete predecessor state and provides linearizable semantics.
5. Verify authenticated readback after every state transition and classify ambiguous write outcomes by fresh signed read.
6. Run adversarial tests and independent multi-host fault/rollback qualification under separate operators.
7. Obtain independent cryptographic and operational review.

This document and code are candidate engineering artifacts only.