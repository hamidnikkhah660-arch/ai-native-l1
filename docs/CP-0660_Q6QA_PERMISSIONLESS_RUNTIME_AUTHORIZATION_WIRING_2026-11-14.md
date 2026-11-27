# CP-0660 — Q6QA authorization wired through the permissionless QFP6 runtime

Date: 2026-11-14  
Branch: `feat/cp0600-bootstrap-sync-startup`  
State: locally implemented and tested; source changes remain uncommitted/unpushed.

## Founder and CP-0651 binding

The founder Account ID `b26ce4e019429ec524cb73d0464ec4c6a48d47ea8519b867d0374f07ab54b31d` was verified against the existing CP-0602/CP-0608 records and `release/qfp6-candidate/manifest.json`. The manifest already binds this exact ID as `owner_genesis_account`. CP-0651 owner allocation is 1,000,000,000 QZXB at Genesis. The six 1B accounting labels are non-circulating ceilings, not balances or transfer instructions. No Genesis signature or token transfer was created.

## Implementation

- Added a quote-aware combined Q6TI/Q6MO candidate builder. It requests authorization for the exact parent state, block height and quote asset ID. The legacy path passes no provider and fails closed for external quote assets.
- Added quote-aware market mempool admission, Q6MM restore, reorg reconciliation and deterministic block construction.
- Threaded the provider through Q6TI/Q6MO ingress, mining preview, durable mined-block admission (re-authorized at commit), Q6PB peer-block admission and branch-aware history import.
- Added quote-aware permissionless supervisor paths, including Q6AR and bootstrap variants. Startup restoration and post-canonical reconciliation use the same provider.
- Launcher supports Q6PN v2 quote pins with Q6QA bundle bytes, a dual-signed Q6TS envelope, independently pinned Ed25519/ML-DSA authority keys and keyset ID, plus a read-only DynamoDB Q6TS floor adapter. The local Q6TS envelope file is re-read and signature/floor checked for each authorized block.
- If Q6PN has no quote-asset trust pin, Q6QA/Q6TS quote configuration is rejected and external-quote admission is explicitly denied. Runtime output reports the actual enforcement state.

## Validation

- `cargo check --bins --locked --offline`: PASS.
- `cargo fmt -- --check` and `git diff --check`: PASS.
- Q6MO ingress/combined nonce/quote gate tests: 7/7 PASS, including no-provider rejection and exact-height Q6QA callback.
- Fresh Q6TS source/floor reload and revoke test: 1/1 PASS.
- Canonical external-quote pair plus persisted Q6QA snapshot test: 1/1 PASS.
- CP-0651 native-quote OrderBook supply/snapshot regression: 1/1 PASS.
- Permissionless runtime tests: 3/3 PASS; supervisor tests: 19/19 PASS; `qrun_v06_node` tests: 36/36 PASS.
- Candidate package self-test: PASS. Candidate validation remains correctly INCOMPLETE (exit 2): Genesis snapshot, Q6GD, Q6CP, Q6PN and bootstrap peers are still absent.

## Qualification boundary and next gates

These results are local deterministic tests and build checks. They do not establish a production-listener Q6QA session, a real independent-host Q6QA test, public inbound reachability, public seed diversity, external-asset custody/redemption, a USDT reserve/bridge, wallet/RPC order-entry integration, or live trading. Existing CP-0566C/CP-0587 two-host evidence remains valid for its earlier native-transfer scope; it is not a Q6QA qualification.

Required before external-quote/public qualification: independently provision the final Q6PN v2, matching signed Q6QA, current dual-signed Q6TS record, authority public keys/keyset and read-only trust floor; supply the canonical CP-0651 Genesis and QZXB founder allocation; then run production listener tests and a separately administered remote-host test. Ubuntu node key custody remains blocked on a Linux protected-credential provider; do not substitute plaintext keys. Public listener/seed and market/USDT remain candidate-only.

No private key, mnemonic, floor write, Genesis signing, push, public deployment or token transfer was performed.
