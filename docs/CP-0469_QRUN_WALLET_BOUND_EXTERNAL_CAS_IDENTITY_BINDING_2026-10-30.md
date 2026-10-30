# CP-0469 ? Wallet-Bound QRun Genesis Identity Binding for External CAS

Date: 2026-10-30

Status: **Candidate identity/recovery correction, owner-bound checkpoint/CAS recovery, generic runtime backend, and pinned Noise/TCP CAS wire adapter validated locally; the node executable still selects the local backend and no independent durable provider has been deployed.** This record does not approve Mainnet or a public-value deployment.

## Problem found

The current wallet-bound candidate identity recorded by CP-0468 is:

- Network ID: 8b5d169205ac49cb9866a9d27ff1a6c3c2571fca65f634854c41c112e506aebb
- Owner account: a14d67bd195c6a0044bedac8532e742811f92501630764d73a98b2f0cc335fdd
- Genesis commitment: 91229b7d21b23cee83f00cec53a566ef1b30db70c644c1e9d05a431c1acf4dbc
- Genesis state root: a44e545c2cd8fa4e56e228f4f242cbf5445b1cc983c7b1f8fe89c5b42aef88d7

The first QRun external-CAS store open path was hard-coded to the older CP-0450 proposed network/owner/Genesis identity. This meant a CAS pin provisioned for the current wallet-bound identity could be rejected before store recovery, even if its provider pin and signed record were otherwise correct.

A second mismatch was in the node's profile/store selector: it recognized only the historical proposed identity, not the current wallet-bound identity. The current identity could therefore take the generic QRun store-directory branch instead of the dedicated QFP5 store-directory branch.

## Correction made

1. Added QRunV05ExternalCasForkStore::open_for_owner_genesis. It recomputes the full-supply Genesis from the supplied Network ID and owner account, then checks that the supplied ledger root, fixed supply, external-CAS pin domain, provider record domain and QFP5 profile agree. It still requires an independently provisioned provider pin, signed bootstrap record, verifier and nonzero object-generation floor; it does not create or simulate an independent provider.
2. Retained the old open convenience method for the historical proposed owner identity, so existing historical fixtures remain usable.
3. Updated the QRun node identity selector to recognize both the explicitly retained historical candidate and the current wallet-bound candidate. Arbitrary network/owner pairs are not accepted as either frozen identity.
4. Retained the owner account in the external-CAS store wrapper and made pending-commit recovery recompute the expected Genesis from that owner. This removes the second CP-0450 hard-coded commitment check that previously rejected a correctly pinned CP-0468 identity after a lost CAS response.
5. Added a statically dispatched QRunV05RuntimeStore backend contract implemented by both the local PFS2 store and the external-CAS wrapper. QRunV05PowForkRuntime is now generic over that backend and can be constructed from an already-open, profile-checked QFP5 store via from_fee_only_store; the existing local constructors retain their default local-store behavior.
6. Upgraded the end-to-end wallet-bound CAS regression to go through the runtime API: mine_candidate followed by submit_block, where the backend is the signed external-CAS store. The test also loses the first commit response after provider application, resolves by fresh signed read, closes the runtime, and reopens with the independently retained signed record.
7. Added NoiseTcpExternalCasProviderTransport and a one-request service-side Noise connection handler. The protocol uses mutually pinned Noise XX static keys, a prologue profile derived from provider/network/Genesis/receipt-key identity, versioned fixed-width read and CAS frames, and one connection per operation. The server handler delegates atomicity to its backend and never substitutes an unconditional write for CAS.
8. Added explicit owner-aware checkpoint PFS2 and external-CAS open APIs. The compatibility methods remain bound to the historical CP-0450 owner; wallet-bound callers pass the exact owner account. The checkpoint profile and fork-choice constructors carry the authenticated Genesis commitment explicitly instead of silently substituting CP-0450 constants.
9. Separated the original height-zero Genesis identity from the checkpoint's height-N state in QRunV05ExternalCasForkStore. Pending-CAS crash recovery now validates the pending record against the retained original Genesis and owner while independently checking the checkpoint-rooted profile fingerprint and tip. The checkpoint-to-QFP5 mode gate likewise requires the caller's explicit, previously authenticated Genesis commitment.
10. Added qrun_wallet_bound_external_cas_checkpoint_rollover_recovers_lost_receipt_and_reopens. The regression proves wrong-owner rejection occurs before local manifest creation/provider state change, opens a current-wallet checkpoint, submits a second block, loses the response after provider application, recovers by fresh signed read, and reopens the same checkpoint suffix at the committed height. The historical CP-0450 checkpoint/CAS compatibility test remains passing.


## External-CAS Noise wire profile

- Transport: TCP carrying the existing QRun v0.5 Noise XX record framing. The client pins the provider's Noise static public key; the service pins the allowed client static public keys.
- Prologue: the Noise profile ID is SHA-256 over a dedicated domain plus provider ID, Network ID, Genesis commitment, receipt key ID and ML-DSA receipt public key. A session cannot be reused across those pin domains.
- Request frame: QCRQ, version 1, kind (1 read / 2 compare-and-swap). Read payload is exactly 96 bytes. Write payload is exactly 448 bytes: request nonce, operation ID, request digest, expected logical generation, expected provider object generation, expected record digest, expected state digest, and fixed-width ECR1 successor record.
- Response frame: QCRS, version 1, matching kind, status (0 success / 1 provider rejected). A successful read returns one ECR1 record followed by one fixed-width ECRS receipt; a successful write returns one ECRS receipt. Rejected operations return no body.
- Connection lifecycle: one operation per connection. The client does not retry a write on the same connection after an ambiguous result; higher-level recovery opens a fresh session and performs a newly challenged signed read.
- The server connection handler is not a storage provider. Its backend must implement durable atomic server-side CAS. A filesystem read followed by an unconditional write, the in-memory test fixture, or a single mutable node data directory does not satisfy that requirement.

**Cryptographic boundary:** the current Noise XX transport uses classical X25519 and ChaChaPoly. It provides a pinned encrypted channel but is not post-quantum or hybrid. ML-DSA-65 protects the separately signed CAS receipts; that does not make the Noise channel itself quantum-resistant. Do not use quantum-safe/hybrid wording for this transport until a separately reviewed hybrid channel is implemented and tested.


## Validation performed

- cargo +stable fmt --manifest-path src/native/pow_bench/Cargo.toml --all: PASS.
- cargo +stable test --manifest-path src/native/pow_bench/Cargo.toml --bin qrun_v05_pow_local_node qrun_v05_identity_recognizes_current_wallet_bound_and_historical_candidate --locked --offline: PASS, 1/1.
- cargo +stable test --manifest-path src/native/pow_bench/Cargo.toml --lib wallet_bound_genesis_identity_matches_external_cas_pin_domain --locked --offline: PASS, 1/1.
- Wallet-bound end-to-end runtime-through-CAS lost-receipt/reopen regression qrun_wallet_bound_external_cas_store_resolves_lost_receipt_and_reopens: PASS, 1/1. It exercises the generic runtime's mine_candidate and submit_block methods with the CAS backend, validates the CP-0468 Genesis identity, signed CAS generation advance, ambiguous/lost response recovery, and reopen with the retained signed record.
- Runtime generic-backend compile validation: PASS via cargo check --all-targets; both local and external-CAS stores implement the same statically dispatched backend contract.
- Noise/TCP signed protocol regression noise_tcp_transport_verifies_signed_read_and_atomic_cas_receipts: PASS, 1/1. A loopback service handler and client exchange a signed read and a signed CAS receipt over independently authenticated Noise sessions; VerifiedExternalCasClient validates both ML-DSA-65 signatures and the object-generation advance.
- Wallet-bound checkpoint/CAS rollover regression qrun_wallet_bound_external_cas_checkpoint_rollover_recovers_lost_receipt_and_reopens: PASS, 1/1. It validates the explicit owner-bound Genesis commitment, parent-linked checkpoint, wrong-owner fail-before-write behavior, post-apply lost receipt recovery, and reopen at the exact committed height.
- Historical checkpoint/CAS compatibility regression qrun_external_cas_checkpoint_open_submit_and_reopens_qfp5_suffix: PASS, 1/1.
- Full library test suite: cargo +stable test --manifest-path src/native/pow_bench/Cargo.toml --lib --locked --offline: PASS, 934 passed, 0 failed. This includes the wallet-bound checkpoint rollover/lost-receipt recovery case and the retained historical CP-0450 checkpoint/CAS case.
- Wallet-bound Genesis-rooted runtime/CAS lost-receipt regression qrun_wallet_bound_external_cas_store_resolves_lost_receipt_and_reopens: PASS, 1/1.

- cargo +stable check --manifest-path src/native/pow_bench/Cargo.toml --all-targets --locked --offline: PASS. Existing unused/dead-code warnings remain in unrelated candidate modules and node tests.
- Exact-head GitHub CI has not yet run for this local checkpoint follow-up. The prior pushed head de7dbc2 is a different source tree and does not validate these changes; keep PR #87 Draft until the new pushed SHA completes every required check.

## Remaining integration gates ? still open

- A concrete pinned Noise/TCP client adapter and service-side connection handler now exist, but the handler still delegates to an ExternalCasProviderTransport backend. The only backend exercised here is an in-memory test fixture; no concrete independently operated persistent CAS backend or service deployment is verified. The Noise channel is classical X25519/ChaChaPoly, not post-quantum or hybrid.
- The node executable still uses the default local-store constructor QRunV05PowForkRuntime::open; it does not yet load an out-of-band Noise client key, pinned provider static key, receipt key pin, durable floor or provider endpoint and instantiate the generic runtime with QRunV05ExternalCasForkStore. Thus production node local/peer block acceptance is not yet routed through external CAS.
- The signed CAS record, receipt-key pin, Noise static-key pins and monotonic object-generation floor still need durable out-of-band provisioning and recovery that is independent of the mutable node data directory and its backup/rollback domain. The loopback provider regression exercises the transport/protocol contract only; it does not qualify a cloud service, persistent backend or operator.
- The owner-aware checkpoint open/rollover APIs now exist and their wallet-bound crash-recovery path passes locally. They remain candidate code: the executable node has not been wired to provision and select a deployed CAS provider for the checkpoint path.
- Required adversarial tests include provider outage, ambiguous/lost commit receipts, retry/idempotency, concurrent CAS conflicts, signed equivocation, stale object generations, local disk rollback, crash windows and checkpoint-parent rollback.
- Production consensus is still a candidate; the recorded calibration evidence represents two independent operators, below the three-operator evidence target. Full-history/recovery integration, external P2P reachability, independent security review and operations remain open.

**Decision:** this is an identity-binding correction, not CAS deployment and not a Mainnet release. Keep QRUN_MAINNET_RELEASE_APPROVED = false; do not advertise a public Mainnet, publicly spendable Genesis balance or QZXB/USDT market.
