# CP-0469 ? Wallet-Bound QRun Genesis Identity Binding for External CAS

Date: 2026-10-30

Status: **Candidate identity/recovery correction and generic runtime-backend integration validated locally; external CAS remains an interface/test-fixture path and is not selected by the node executable.** This record does not approve Mainnet or a public-value deployment.

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

## Validation performed

- cargo +stable fmt --manifest-path src/native/pow_bench/Cargo.toml --all: PASS.
- cargo +stable test --manifest-path src/native/pow_bench/Cargo.toml --bin qrun_v05_pow_local_node qrun_v05_identity_recognizes_current_wallet_bound_and_historical_candidate --locked --offline: PASS, 1/1.
- cargo +stable test --manifest-path src/native/pow_bench/Cargo.toml --lib wallet_bound_genesis_identity_matches_external_cas_pin_domain --locked --offline: PASS, 1/1.
- Wallet-bound end-to-end runtime-through-CAS lost-receipt/reopen regression qrun_wallet_bound_external_cas_store_resolves_lost_receipt_and_reopens: PASS, 1/1. It exercises the generic runtime's mine_candidate and submit_block methods with the CAS backend, validates the CP-0468 Genesis identity, signed CAS generation advance, ambiguous/lost response recovery, and reopen with the retained signed record.
- Runtime generic-backend compile validation: PASS via cargo check --all-targets; both local and external-CAS stores implement the same statically dispatched backend contract.
- cargo +stable check --manifest-path src/native/pow_bench/Cargo.toml --all-targets --locked --offline: PASS. Existing unused/dead-code warnings remain in unrelated candidate modules and node tests.
- Exact-head GitHub CI has not yet run for this follow-up branch.

## Remaining integration gates ? still open

- ExternalCasProviderTransport is still a trait boundary; the available in-memory provider is a test fixture. No concrete independently operated network provider/adapter or service deployment is verified.
- The node executable still uses the default local-store constructor QRunV05PowForkRuntime::open; it does not yet provision/configure an external-CAS client and instantiate the generic runtime with QRunV05ExternalCasForkStore. Thus production node local/peer block acceptance is not yet routed through external CAS.
- The signed CAS record, receipt-key pin and monotonic object-generation floor still need durable out-of-band provisioning and recovery that is independent of the mutable node data directory and its backup/rollback domain. The in-memory provider regression exercises the protocol contract only; it does not qualify a cloud service or operator.
- The checkpoint-rooted external-CAS open/rollover helpers still retain historical identity assumptions and require a wallet-bound owner-aware counterpart before they can serve the current identity.
- Required adversarial tests include provider outage, ambiguous/lost commit receipts, retry/idempotency, concurrent CAS conflicts, signed equivocation, stale object generations, local disk rollback, crash windows and checkpoint-parent rollback.
- Production consensus is still a candidate; the recorded calibration evidence represents two independent operators, below the three-operator evidence target. Full-history/recovery integration, external P2P reachability, independent security review and operations remain open.

**Decision:** this is an identity-binding correction, not CAS deployment and not a Mainnet release. Keep QRUN_MAINNET_RELEASE_APPROVED = false; do not advertise a public Mainnet, publicly spendable Genesis balance or QZXB/USDT market.
