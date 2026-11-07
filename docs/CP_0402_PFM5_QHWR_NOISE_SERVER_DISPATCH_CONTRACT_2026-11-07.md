# CP-0402 — PFM5 QHWR Noise Server Dispatcher Contract

Date: 2026-11-07
Status: Draft engineering contract; not an implementation, deployment approval, or security certification.
Parent: CP-0401 QHWR v1 wire contract and pinned Noise client.

## 1. Purpose and scope

Define the smallest safe server-side dispatcher for QHWR v1 over the existing pinned Noise transport. The dispatcher is a protocol boundary only. It MUST NOT manufacture persistence, anti-rollback guarantees, signer custody, or authorization by wrapping local state in a mutex or file.

The first implementation target is an opt-in loopback-only qualification harness. No public listener, node-runtime integration, firewall change, VPN/NetBird change, Genesis/consensus change, mint activation, or Mainnet approval is included.

## 2. Existing contracts and verified boundaries

- CP-0401 provides bounded QHWR v1 request/response codecs, strict lengths, operation tags, and a maximum 8192-byte plaintext envelope.
- CP-0401 client uses Noise_XX_25519_ChaChaPoly_SHA256, a Network-ID-bound prologue, and an out-of-band pinned responder static key.
- The responder handshake accepts only an explicitly configured set of initiator static public keys. A successful handshake authenticates a transport peer; it does not grant permission to mutate high-water state.
- Pfm5ExternalCasHighWaterProvider requires authenticated reads, state outside the node/journal rollback domain, linearizable atomic compare-and-advance across writers, rejection of stale/decreasing/skipped/identity-changing transitions, and durable success before return.
- Existing signed response verification binds authority ID, key ID, key generation, challenge, canonical QHWA bytes, and ML-DSA-65 signature. A test fixture signer is not an operational signer.
- Existing Noise uses classical X25519/ChaChaPoly. ML-DSA-65 receipts do not make the complete P2P network post-quantum.

## 3. Trust boundaries

Treat these as separate controls; none substitutes for another:

1. Network admission: Noise handshake, Network ID prologue, and pinned peer static key.
2. Operation authorization: explicit per-peer permissions (READ and COMPARE_AND_ADVANCE independently). Unknown peers and peers without the requested permission are denied. A Noise-authenticated peer is not automatically a CAS writer.
3. Request freshness: one-time challenge admission with bounded lifetime and durable replay state. An in-memory set or process-local cache is insufficient across restart, replicas, or rollback.
4. State authority: independently operated high-water provider with atomic compare-and-advance and a rollback domain separate from the node.
5. Response authenticity: isolated ML-DSA-65 signing interface and externally provisioned verifier pin lifecycle. Do not embed test seeds, deterministic test randomness, or private keys in the dispatcher.
6. Availability/resource limits: bounded frame size, handshake and record deadlines, connection concurrency cap, bounded queues, and deterministic shutdown.

## 4. Request processing order

For each accepted TCP connection:

1. Apply connection admission limits and handshake deadline before expensive work.
2. Complete Noise responder handshake using configured local static key, exact Network ID, and explicit trust set. On failure, close without QHWR response or plaintext fallback.
3. Compare the authenticated remote static key to the configured authorization map. Reject unknown identity.
4. Read exactly one bounded authenticated Noise record. The initial dispatcher is single-request-per-connection; no pipelining or multiplexing.
5. Decode QHWR strictly. On malformed frame, close the connection; do not attempt alternate parsing.
6. Check peer permission for the decoded operation.
7. Atomically reserve the challenge in the durable replay ledger, scoped at minimum by Network ID, authenticated peer identity, operation, and challenge. Enforce expiry and reject duplicates. Ledger reservation must be durable before provider or signer side effects.
8. Dispatch only to the corresponding provider operation. Never translate a failed/unknown provider result into a successful state response.
9. Validate returned state against authority/provider/network/Genesis pins and canonical QHWA v1 rules.
10. Obtain a signature through the signer interface only after the provider result is validated. The signer must sign the exact challenge/key metadata/wire-state digest defined by CP-0400/0401.
11. Encode one bounded QHWR response and write one Noise record. Close after response; close on any framing, authentication, provider, signer, or write error.

## 5. READ semantics

READ requires a fresh challenge and READ permission. The provider must return an authenticated state. The dispatcher validates all identity fields and canonical wire encoding before signing.

If the provider or signer is unavailable, return the corresponding bounded error only when the challenge reservation and response semantics remain unambiguous; otherwise close the connection. Never return a cached signed state for a new challenge.

## 6. COMPARE_AND_ADVANCE semantics

CAS requires a fresh challenge and explicit CAS permission. Decode and validate the exact 414-byte QHWA successor, including pinned authority/provider/network/Genesis identity and legal transition shape. Compare the supplied expected digest against the current authenticated provider state.

The only acceptable mutation path is the provider's atomic compare_and_advance(expected, next). A server-side read followed by an unconditional write is forbidden. A local mutex around a non-atomic remote operation is not a substitute for provider linearizability.

A successful response may be signed only after the provider reports durable success and an authenticated readback confirms the exact successor. If the provider reports an ambiguous outcome, the dispatcher must perform a fresh authenticated read and classify exact successor, unchanged predecessor, or conflicting state. If classification is unavailable, return DurableCommitOutcomeUnknown or close; never claim success.

Until a qualifying independent provider and durable replay ledger exist, CAS must be disabled by configuration and return ProviderUnavailable without mutation or success signature. The initial READ-only qualification mode must not expose CAS through a permissive default.

## 7. Replay ledger contract

The ledger must provide a durable atomic reserve_once(scope, challenge, expiry) operation. It must reject an existing challenge and must not lose committed reservations after process restart, replica failover, snapshot restore, or rollback of the node host.

A database on the same host or volume is not automatically an independent rollback domain. Ledger durability, consistency model, retention, clock assumptions, expiry behavior, replication, backup/restore, and disaster recovery require a separate threat model and independent qualification. No implementation may silently fall back to memory-only replay protection.

## 8. Signer interface and key custody

The dispatcher depends on an abstract signer that accepts only a validated response-signing digest and returns a fixed-size ML-DSA-65 signature. The interface must expose public key identity (key_id, key_generation) but not private key bytes.

Production key custody, provisioning, rotation, revocation, backup, operator separation, authorization policy, audit, and compromise response are out of scope and must be specified before production. Test-only deterministic seeds remain confined to tests.

## 9. Fail-closed status mapping

- Malformed/oversized/noncanonical request: close; optionally MalformedRequest only if framing remains trustworthy.
- Unsupported version/operation: UnsupportedVersionOrOperation.
- Unknown or unauthorized peer: close or UnauthorizedPeer; no state/signature side effect.
- Duplicate/expired challenge: ChallengeReplayOrExpired.
- Expected digest mismatch: StateConflict.
- Illegal successor: InvalidTransition.
- Provider or signer unavailable: ProviderUnavailable.
- Ambiguous durable write not resolved by authenticated readback: DurableCommitOutcomeUnknown.
- Internal errors must not leak secrets, private key material, raw provider credentials, or detailed filesystem/network topology.

## 10. Required qualification tests

### Noise and admission
- Correct pinned peer and Network ID succeeds.
- Wrong Network ID, unknown static key, malformed handshake, timeout, and trust-set misconfiguration fail closed.
- Authenticated but unauthorized READ/CAS peer is denied before provider/signer calls.
- Concurrent connection cap and shutdown behavior are deterministic.

### Framing and parser
- Truncated header/body, oversized length, trailing bytes, wrong magic/version/type/op, invalid fixed lengths, zero challenge, and invalid status fail closed.
- No plaintext fallback, no second request, no pipelining, no operation confusion.
- One request produces at most one response; errors close the session.

### Replay and authorization
- Duplicate challenge rejected under concurrent requests.
- Same challenge under a different peer or operation follows explicitly specified scope semantics.
- Restart, replica failover, stale snapshot restore, and ledger unavailability cannot silently permit replay.
- Expired challenge handling uses a documented clock model and bounded retention.

### Provider and CAS
- READ validates all identity pins and exact canonical state.
- CAS never invokes provider when permission, challenge, frame, or successor validation fails.
- Race between two writers yields exactly one linearized successor.
- Crash before commit, after durable commit but before reply, lost reply, provider timeout, and readback failure are classified.
- No signed success response before durable provider success and exact readback.

### Signer
- Signer unavailable, wrong key ID/generation, malformed signature length, and key rotation/revocation fail closed.
- Signed challenge and wire bytes are exactly those validated for the request/provider result.
- No private key material appears in logs, errors, process arguments, or dispatcher state.

### Operations
- Loopback-only bind enforced by the harness; no public bind path.
- Explicit opt-in; no node startup default change.
- Resource ceilings and deadlines tested.
- Reproducible test evidence tied to exact commit SHA.

## 11. Non-goals and release gates

This contract does not implement a production provider, replay ledger, signer service, trust-store lifecycle, public service, or runtime wiring. It does not qualify multi-host rollback resistance, disaster recovery, denial-of-service resistance, production key custody, or Mainnet readiness.

Before any public deployment: independent security review; independently operated provider and replay ledger; signer custody review; multi-host concurrency/crash/rollback qualification; authenticated monitoring/audit; operational incident and recovery runbooks; explicit release approval. No public mint or Mainnet release is authorized by this document.

## 12. Explicit change restrictions

No changes to Genesis, consensus, issuance/economics, public listener defaults, firewall, VPN, NetBird policy/routes, DNS, OpenVPN adapter/service, release gates, or website publication are authorized by this CP.

## CP-0402 initial READ-only dispatcher implementation

A first dispatcher core now exists in
src/native/pow_bench/src/private_testnet_pfm5_highwater_rpc_dispatch_candidate.rs.
It is a request handler, not a TCP listener or production service. It accepts only an already
Noise-authenticated peer identity supplied by its caller and performs one QHWR request dispatch.

The initial implementation is intentionally READ-only:
- malformed QHWR requests are rejected before any dependency is called;
- COMPARE_AND_ADVANCE is rejected before provider, replay-ledger, or signer side effects;
- peer authorization is checked against an explicit static-key allow-list before replay reservation;
- READ reserves the peer/challenge pair through a required replay-ledger interface before provider IO;
- provider state is validated and canonically encoded before signing;
- response signatures are produced only through an injected signer interface; no private key
  implementation or key custody is included here.

Three focused tests currently pass: malformed-request rejection, CAS rejection with no side
effects, and unauthorized-peer rejection with no side effects. These tests use panic-on-call
dependencies to prove the rejected paths do not invoke them.

The replay-ledger interface contract requires durable atomic cross-process reservation, but no
concrete implementation is supplied. The signer is also only an interface. A production service
must still provide and independently qualify both, along with an independent high-water provider,
Noise accept/connection lifecycle, bounded listener admission, operational limits, and multi-host
fault/replay testing. No runtime wiring, listener, public bind, CAS service, or launch approval is
introduced by this candidate.

## Dispatcher fault-path qualification update

The READ-only dispatcher now has eight focused tests. In addition to malformed request, unauthorized
peer, and CAS rejection, tests exercise replay rejection, replay-ledger failure, Provider failure,
Signer failure, and a successful READ envelope. The tests assert the order and absence of downstream
calls: replay/ledger failures do not call the Provider or Signer; Provider failure occurs only after
challenge reservation and never calls the Signer; Signer failure returns no unsigned state. The
successful-path test checks the exact challenge, key identity/generation, fixed wire length, and
that the signer receives the response's canonical signing digest.

All replay and provider/signer test implementations are in test code only; they are not production
storage, signer custody, or a deployed Provider. The production qualifications and non-goals above
remain unchanged.
