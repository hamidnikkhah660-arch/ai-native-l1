# CP-0398 - PFM5 crash-recovery orchestration contract and qualification matrix

Date: 2026-11-07

Status: **Design and acceptance contract only. No recovery orchestrator, production provider, node integration, or operational readiness is claimed.**

## Purpose and boundary

CP-0394 executes one immutable-object publication and exact signed ECR1 compare-and-swap intent. CP-0395 durably records that exact intent in the local PFJ1 journal. CP-0396 defines an independently authenticated monotonic high-water authority. Their component tests do not prove that a restarted caller correctly composes all three after every crash window. CP-0398 specifies that missing caller protocol and the tests required before any runtime wiring.

This document is deliberately provider-neutral. The repository currently has no deployed independent authority, no concrete production adapter, no production object-store/ECR1 endpoint, and no node caller. The in-memory high-water provider is a conformance double only. A second local file, volume, partition, or process is not an independent anti-rollback trust domain.

## Non-negotiable invariants

1. **One intent per prepared transition.** Recovery decodes and reuses the exact PFJ1 pending intent. It never creates a replacement operation ID, nonce, request digest, successor record, or bundle commitment.
2. **Independent authority first.** Every recovery begins with an authenticated high-water read pinned to the expected authority, provider, network, and Genesis. Authentication failure, unavailable authority, identity mismatch, malformed state, or an unexpected sequence is fail-closed.
3. **No local journal as trust anchor.** PFJ1 checksum and atomic durability detect corruption/torn writes; they do not detect a restored old disk image. A Prepared local record is not sufficient authorization for remote side effects.
4. **Exact ECR1 evidence.** The only accepted commit is the exact `intent.write_request.next_record` with object generation strictly greater than `intent.expected_object_generation`, proven by CP-0394's fresh authenticated/signed ECR1 read or a successful verified receipt followed by the required readback policy. A third state is a conflict, not a retry.
5. **Order the durable transitions.** PFJ1 Prepared must be durable before the independent Prepared floor; the Prepared floor must be confirmed before CP-0394 side effects. After exact commit evidence, PFJ1 is finalized; only then is the independent Finalized floor advanced and authenticated/read back.
6. **Idempotent retries only.** An ambiguous response is resolved by authenticated reread. Retry means the same exact intent and same expected predecessor. No blind write retry and no new intent.
7. **No launch claims.** Passing the proposed mock crash suite is not a real-provider, multi-host, public Devnet, Mainnet, consensus, or security-audit qualification.

## Recovery input validation

Before any provider side effect, the caller must:

- authenticate and validate the independent high-water state first, then load PFJ1 through a recovery-specific checked-read path. For ordinary Prepared/Prepared and Prepared/Ready reconciliation, `load_checked` may be used with floors that do not exceed the local snapshot. For the disk-rollback case where the authenticated floor is Finalized and PFJ1 is exactly one sequence behind, **do not call `load_checked` with the finalized sequence as its minimum**: that correctly rejects the stale local sequence before recovery can inspect its pending intent. A narrowly scoped recovery-load API must validate PFJ1 encoding, checksum, domain, intent, and file safety while allowing only this exact one-transition lag for subsequent independent-floor and fresh-ECR1 proof.
- require `snapshot.pending_intent` and validate that exact intent against the configured `ExternalCasPin`;
- require `snapshot.last_record == intent.expected_current` and `snapshot.object_generation == intent.expected_object_generation`;
- validate the pinned authority/provider/network/Genesis tuple and authenticated high-water response;
- fetch the immutable manifest and objects committed by `intent.write_request.next_record.next_state_digest`, validate their content and parent commitment against `intent.expected_current.next_state_digest`, and reconstruct the exact bundle required by CP-0394;
- reject any missing, substituted, malformed, or noncanonical input without mutating either floor.

The recovery implementation must not infer trust from a local sequence, a checksum, a key identifier alone, a transport connection alone, or an unauthenticated provider response.

## Required state machine

### A. PFJ1 Prepared; independent floor is Prepared at the same sequence

1. Confirm the authenticated floor equals the expected Prepared state: same authority/provider/network/Genesis, same journal sequence, exact predecessor ECR1 record, and exact predecessor object generation.
2. Fetch and validate the immutable bundle for the exact pending intent.
3. Call CP-0394 `execute_intent` with that same intent and bundle. CP-0394 must perform its fresh signed ECR1 read.
4. On `RetrySameIntent`, retain PFJ1 Prepared and the Prepared high-water floor. Return a retryable outcome; a later attempt may only reuse this intent.
5. On `Committed`, `AlreadyCommitted`, or `CommittedAfterAmbiguousReply`, require the exact successor record and strictly advanced object generation to be verified. Do not treat a generic success or a manifest upload report alone as commit evidence.
6. Call PFJ1 `mark_committed` with the exact successor and observed object generation. Then call CP-0396 `advance_finalized_snapshot` and resolve any ambiguous authority response with authenticated reread.
7. Report recovered/finalized only when the independent Finalized floor is authenticated and exactly matches the finalized PFJ1 state.

### B. PFJ1 Prepared; independent floor is already Finalized

This can occur when the local journal disk was restored to an earlier Prepared image after the independent authority had advanced.

1. Load PFJ1 using the narrowly scoped recovery-load API described above; require its pending intent and predecessor fields to match exactly. Require `observe_finalized_floor_for_prepared_intent` to return the exact next journal sequence, exact intended successor record, and advanced object generation under the pinned authority/domain. This is a single permitted lag (`prepared.sequence + 1`), not a general relaxation of floors.
2. **Do not finalize PFJ1 from the high-water record alone.** Fetch and validate the intent's immutable bundle and call CP-0394 with the same intent. Its fresh signed ECR1 read must independently confirm that the ECR1 record is the exact intended successor and the object generation is advanced. If the external ECR1 state is unavailable or disagrees, fail closed and raise an operator-visible integrity incident; never lower the authority floor.
3. Only after this fresh exact evidence may `mark_committed` reconcile PFJ1 to the successor. Re-read the authenticated high-water floor and require exact equality with the finalized journal state. Do not advance or rewrite an already-finalized authority state.

### C. Any other state

Examples: floor behind PFJ1; floor ahead by more than the single expected transition; competing successor; wrong authority/provider/network/Genesis; Prepared floor with a different predecessor; Finalized floor with a different record or non-advanced generation; failed authentication; unresolved ambiguous read; malformed journal or intent. The only valid result is fail-closed with no new intent and no authority rollback. Preserve evidence for diagnosis.

## Crash and fault-injection qualification matrix

The orchestrator implementation must expose deterministic fault points and use a fresh process for restart tests. Each row must assert exact journal bytes/state, authenticated floor, ECR1 record, object generation, operation ID, provider read/write counts, and that no second intent was generated.

| Crash/fault boundary | Expected restart observation | Required safe action |
|---|---|---|
| Before PFJ1 Prepared write | Ready journal + Ready floor | Start only through normal new-intent path after exact Ready equality |
| After PFJ1 Prepared, before Prepared-floor CAS | Prepared journal + old Ready floor | Do not execute CP-0394; reconcile only the exact Prepared-floor transition after authenticated predecessor checks |
| Prepared-floor CAS committed, reply lost | Prepared journal + Prepared floor after authenticated reread | Continue with the same intent only |
| After Prepared floor, before object publication | Prepared + Prepared | Execute exact same intent |
| During immutable-object publication | Prepared + Prepared; some immutable objects may exist | Revalidate content and idempotently publish only exact intent objects; never move ECR1 |
| After object publication, before ECR1 CAS | Prepared + Prepared; ECR1 still predecessor | CP-0394 may retry exact CAS for same intent |
| ECR1 CAS committed, response lost | Prepared + Prepared; ECR1 exact successor | Fresh signed read resolves committed; finalize exact journal |
| ECR1 CAS not committed, response lost | Prepared + Prepared; ECR1 exact predecessor | `RetrySameIntent`; no new intent |
| ECR1 reports competing/third state | Prepared + Prepared; ECR1 neither predecessor nor exact successor | Conflict; no overwrite, no new intent, no floor rollback |
| After exact ECR1 commit, before PFJ1 finalization | Prepared + Prepared; ECR1 exact successor | Fresh signed read; mark exact committed state |
| PFJ1 finalized, before Finalized-floor CAS | Finalized journal + Prepared floor | Authenticated floor check; advance exact Finalized successor only |
| Finalized-floor CAS committed, reply lost | Finalized journal + Finalized floor | Authenticated reread; classify already advanced; no duplicate transition |
| Disk restored to Prepared after Finalized floor | Prepared journal + Finalized floor | Validate exact finalized floor, then fresh signed ECR1 read and object validation before local reconciliation |
| Authority unavailable/authentication invalid at any point | State cannot be trusted | Fail closed; zero remote writes and zero new intents |
| Process restart at every injected boundary | State is one complete durable state, not partial bytes | Re-open through checked APIs; no silent initialization/reset |

## Required automated tests before implementation is considered qualified

- Add a narrowly scoped recovery-load API (or equivalent reviewed mechanism) that permits exactly the authenticated Finalized-floor / one-step-older Prepared-journal case without weakening normal `load_checked` semantics. It must still validate checksum, canonical encoding, domain, file safety, and the exact pending intent.
- A single integration harness composes the real PFJ1 journal module, CP-0396 contract functions, CP-0394 executor, and deterministic provider doubles; separate unit tests are insufficient.
- Child-process termination and restart at every matrix boundary, including after provider commit but before response delivery.
- Exact assertions for same operation ID, same nonce/request digest, exact predecessor/successor, sequence increments of exactly one, and strictly advanced object generation.
- Competing writer, stale response, false-success CAS, lost authenticated readback, corrupted/malformed journal, wrong domain, authority rollback, sequence skip, and authority outage.
- For every fail-closed case: assert no unauthorized ECR1 CAS, no authority rollback, no new intent, and no unverified journal finalization.
- Property/model-based transition tests over all allowed and forbidden journal/floor/ECR1 combinations.
- A real independently administered provider adapter and two-host partition/restart/backup-restore/whole-disk rollback tests are a separate mandatory gate after the mock integration suite.

## Implementation sequence and explicit gates

1. Define a narrow recovery coordinator API over existing components; avoid duplicating their validation or weakening their types.
2. Implement the deterministic integration harness and fault injection first. Tests must fail against an intentionally broken ordering (for example, CP-0394 called before Prepared floor confirmation).
3. Implement the recovery-load path and coordinator only when each matrix transition has a precise result type and no ambiguous boolean success. Keep normal `load_checked` strict; do not weaken its minimum-floor behavior globally.
4. Review provider authentication, canonical encoding, authority bootstrap/rotation/revocation, and linearizable compare-and-advance independently. The existing AWS adapter plan is design material only; **no AWS account, paid cloud resource, KMS, DynamoDB, or spend is authorized or required by this CP**.
5. Run all-target Rust validation and exact-head CI; retain Draft status pending review.
6. Do not wire into node startup, Devnet, or Mainnet until the independent provider adapter and multi-host rollback qualification pass and the project owner separately approves integration.

## Non-goals and unchanged gates

No changes to Genesis, Network ID, consensus, PoW, issuance, wallet allocation, fees, P2P transport, public mining, site publication, exchange listing, or QZXB/USDT market status. No paid services, cloud resources, credentials, secrets, network/firewall/VPN settings, or deployment actions. This contract does not close Gate 8 or approve public launch.

## Relationship to prior work

- CP-0394: exact External-CAS executor and fresh signed ECR1 recovery read.
- CP-0395: local PFJ1 durable intent journal.
- CP-0396: independent high-water state contract and transition checks.
- CP-0397: provider-adapter design; no production adapter is deployed.
- CP-0398: missing caller recovery composition and crash qualification requirements.
