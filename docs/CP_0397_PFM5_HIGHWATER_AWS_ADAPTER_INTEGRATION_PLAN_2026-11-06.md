# CP-0397 - PFM5 independent High-Water AWS adapter integration plan

Date: 2026-11-06

Status: **Design and acceptance plan only. No AWS account, table, service, credential, key, or production adapter has been provisioned or exercised. No production-readiness claim.**

## 1. Decision boundary

CP-0396 defines the caller-side monotonic High-Water contract through `Pfm5ExternalCasHighWaterProvider`. CP-0483 separately defines an AWS DynamoDB candidate for the Off-host Anchor store (`ExternalCasOffhostAnchorStore`). CP-0485 separately defines an AWS KMS signer candidate for Anchor receipts.

These are three different security roles and must not be treated as interchangeable:

1. **Off-host Anchor store**: stores and conditionally advances the signed Anchor protocol state.
2. **Anchor receipt signer**: signs/verifies receipts for that Anchor protocol.
3. **PFM5 High-Water authority**: independently retains the monotonic journal sequence, exact ECR1 predecessor/successor and immutable-object generation that gate PFM5 publication/recovery.

The existing CP-0483 adapter does not implement `Pfm5ExternalCasHighWaterProvider`; the CP-0485 signer does not create an independent monotonic authority. Reusing either component without a distinct authority identity, state schema, trust pin, and administrative boundary would collapse security domains and is rejected.

## 2. Candidate deployment shape (not yet approved or provisioned)

A single-Region DynamoDB base table is a possible first implementation substrate for the High-Water state, provided it is operated by an independently administered authority in a separate account/recovery domain from the node and its local PFJ1 journal. This is a candidate, not a deployment decision.

The node-facing adapter would implement exactly:

- `read_authenticated(authority_pin, cas_pin)`: strongly consistent base-table `GetItem`; strict domain and canonical-state decoding; authenticate the authority response against an out-of-band pinned authority identity/key; reject missing, malformed, stale-domain or untrusted state.
- `compare_and_advance(authority_pin, cas_pin, expected, next)`: one server-side conditional write comparing the complete expected predecessor identity, sequence and state digest; never a read-then-unconditional-write sequence; then a fresh strongly consistent read to classify the result.

The stored canonical state must bind, at minimum:

- authority ID;
- External-CAS provider ID, network ID and Genesis digest;
- journal sequence;
- exact ECR1 record (or a canonical, collision-resistant digest plus a retrievable authenticated representation sufficient to compare it exactly);
- immutable-object generation;
- canonical schema/version and state digest;
- authority authentication material/key ID and a defined rotation/revocation policy.

A plain sequence counter, a node-local file, a second disk/volume on the same host, or a receipt signed only by the Anchor key is not an acceptable High-Water implementation.

## 3. Atomicity and regional constraints

The first candidate should use one DynamoDB Region and a conditional write on the authoritative base table. The implementation must prove that every writer targets the same authority item and that the conditional expression compares the complete expected predecessor (not sequence alone).

Do not assume default multi-Region Global Tables replication provides a globally linearizable compare-and-swap. Multi-Region strong consistency has separate topology, service, latency, recovery and cost constraints and requires its own design and qualification. It is outside this candidate.

A successful write must be durable before the service reports success. A timeout or lost acknowledgement must be classified only by a fresh authenticated read: exact `next` means committed; exact `expected` means not committed; any third state is a conflict and must fail closed.

## 4. Trust and administration separation

Before any live adapter test, define and review:

- independent authority owner/operator and account/recovery boundary;
- out-of-band authority identity/key pin and secure bootstrap ceremony;
- separate IAM roles for node runtime, authority service, table administration, backup/restore and key administration;
- denial of table deletion, point-in-time restore, item rollback, policy edits and key replacement to the node runtime;
- backup/restore procedure that cannot silently roll the monotonic floor backward;
- key rotation, revocation, compromise response and authority migration with explicit operator approval;
- audit retention and tamper-evident administrative event logging.

A second table or Region is not, by itself, an independent trust domain if the same administrator can restore both the node state and authority state to an earlier point.

## 5. Required conformance and adversarial acceptance matrix

The adapter is not eligible for integration until the following tests run against a provisioned staging service and at least two independently running hosts/processes:

| Case | Required result |
|---|---|
| Exact authenticated read | Return exact pinned authority/provider/network/Genesis/sequence/ECR1/object-generation state |
| Missing generation-zero item | Fail closed; never bootstrap from a node or Provider response |
| Wrong authority or domain | Reject before authorizing any PFM5 side effect |
| Stale expected sequence/digest | Conditional write rejected; fresh read identifies conflict |
| Two simultaneous writers, same predecessor | Exactly one advances; loser observes conflict; no lost update |
| Lost acknowledgement after commit | Authenticated reread recognizes exact `next` as committed |
| Timeout before commit | Authenticated reread recognizes unchanged `expected`; caller retries only the identical intent under CP-0396 rules |
| Read unavailable / partition | No publication or ECR1 CAS authorized |
| Malformed or non-successor state | Reject; never normalize or repair by guessing |
| Local PFJ1 disk-image rollback | Independent floor detects stale local state; fail closed or perform exact documented recovery |
| Authority backup/restore rollback | Detected by independent operational controls; no silent floor reset |
| Key rotation/revocation | Old key rejected after policy transition; migration is explicit and auditable |
| Process crash/power loss | Durable state and readback agree after restart |
| Region/service outage | No fallback to local state or eventually consistent replica |

Tests must capture request IDs, authority identity, before/after state digests and observed outcomes without logging credentials, private keys or sensitive authentication material.

## 6. Recovery invariant

The High-Water authority is not a journal backup and does not contain the full PFJ1 pending intent in CP-0396. If local PFJ1 is rolled back to `Ready` while the independent floor is ahead, the system must quarantine/fail closed; it must not synthesize a replacement intent, reset the floor, or infer success from sequence alone.

If PFJ1 remains `Prepared` and the floor indicates the exact finalized successor, recovery still requires validation of the retained exact pending intent, a fresh authenticated ECR1 read, and independent verification of the referenced immutable objects/generation before idempotently reconciling local journal and floor state. A greater object-generation number alone is not proof that the correct objects exist.

## 7. Contract-to-storage mapping and authentication boundary

The current CP-0396 Rust contract is the logical state boundary, not a finalized AWS wire format. `Pfm5ExternalCasHighWaterState` currently carries the authority ID, provider ID, network ID, Genesis digest, journal sequence, complete `ExternalCasRecord`, and object generation. The provider trait receives the authority pin and `ExternalCasPin` separately. The current authority pin contains an authority ID; it does not itself carry a public key, signature, schema version, or caller-supplied state digest.

Therefore the AWS adapter must define a separate, versioned storage/authentication envelope without pretending those fields already exist in the Rust state type. At minimum, the envelope design must specify:

- a canonical encoding/version for every logical state field, including the complete ECR1 record;
- a domain-separated digest computed by the adapter from the canonical bytes (never accepted as an unverified caller assertion);
- a key identifier and authenticated response proof, or an equivalently reviewed authenticated transport tied to an out-of-band authority pin;
- an explicit mapping from the pinned authority ID to the independently provisioned verification identity and its rotation/revocation policy;
- the exact DynamoDB key and conditional-expression attributes needed to compare the full expected predecessor, including sequence, state digest, provider/network/Genesis identity and object generation.

Private signing keys or other secret authentication material must remain outside DynamoDB items and outside node-readable configuration. A key ID is metadata, not a substitute for proof verification. `read_authenticated` must verify the envelope/proof and all domain bindings before constructing and returning the Rust state. `compare_and_advance` must independently validate both caller states, enforce the CP-0396 transition rules, compute canonical digests, perform the single conditional write, and authenticate the fresh readback before returning success or classifying an ambiguous outcome.

The exact canonical encoding, digest domain tag, proof mechanism, key bootstrap ceremony, and key-rotation state machine remain explicit design decisions to freeze before implementation. Until then, the document specifies acceptance properties, not a complete interoperable wire protocol. Conformance tests must include cross-version canonicalization rejection, tampered envelope/proof, wrong key ID, revoked key, and authority-key rotation.
## 8. Implementation sequence and gates

1. Review CP-0396 caller ordering and CP-0395 journal rollback semantics together.
2. Freeze the canonical High-Water wire schema, digest domain separation and authority authentication/rotation policy.
3. Decide whether the AWS authority is separately administered in a dedicated account and identify its recovery operator; do not provision resources before approval.
4. Implement a new adapter that directly implements `Pfm5ExternalCasHighWaterProvider`; do not silently repurpose the CP-0483 Anchor store type.
5. Add deterministic adapter contract tests using scripted AWS CLI responses, including exact conditional expressions and canonical decode/re-encode checks.
6. Run live staging qualification only after explicit account, cost, IAM, key and operator approval.
7. Run two-host concurrency, lost-ack, partition, crash, disk rollback and authority-restore drills.
8. Wire the qualified adapter into the PFM5 caller only after independent review; keep public launch and mint gates closed until all other launch criteria are independently satisfied.

## 9. Explicitly not completed / not authorized

- No AWS account, DynamoDB table, KMS key, IAM role, secret or credential was created or accessed.
- No cloud cost was incurred or authorized.
- No live AWS request or service-level linearizability claim was made.
- No production High-Water adapter exists as a result of this document.
- No PFM5 node runtime wiring, public listener, consensus, Genesis, supply, mining or release-gate change is included.
- No PR was merged, no deployment/publication was performed, and no Draft state was changed.

**Gate 8 remains OPEN.** This plan is a design artifact only and is not evidence of public Mainnet readiness.
