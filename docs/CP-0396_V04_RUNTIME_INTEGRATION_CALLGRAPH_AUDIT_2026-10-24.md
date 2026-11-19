# CP-0396 — v0.4 Runtime Integration Call-Graph Audit

**Audit baseline:** commit `96bf07806e32a9fa3ffbaeb025b6d4680c2c1c8c`
**Code baseline:** the Rust files were unchanged from `b99aae3789d18ed73ed576ff028b566d5dcb8f3f`; `96bf078` adds documentation only.
**Decision:** do not connect the v0.4 allocation candidate to a live producer/importer yet. The missing runtime transition and missing versioned issuance schedule are material consensus blockers.
**Gate status:** Gate 2 OPEN; Gate 8 OPEN.

## 1. Executive finding

A repository search for `MonetaryLedgerStateV04Candidate`, `monetary_ledger_v04_candidate`, and `from_genesis_manifest` found the v0.4 ledger candidate's declaration and its internal tests, but no production call from `private_testnet_node`, the fork-choice/store paths, or the generic `chain_import_node`. The module is exported from `lib.rs`, which makes it accessible as a library API; export is not runtime integration.

The production-like PMT3/PFM3 and PMT4/PFM4 code paths still create and transition the existing `state_machine::MonetaryLedgerState`. That state binds the prior issuance rules. The local PMT4 path is called “V4” because of its hybrid transaction/identity/wire protocol, but it is not the tokenomics allocation v0.4 ledger. Its local Genesis helper explicitly builds the older 4B founder + 3B public-goods setup. These versions must not be conflated.

## 2. Observed call graph

### A. v0.4 candidate boundary

- `monetary_allocation_v04_candidate.rs:18-25, 30-118`: declares the policy version, total supply ceiling, fixed eight-bucket budget table and accounting wire format. The budgets are ceilings/counters; the module has no block-height reward schedule.
- `monetary_allocation_v04_candidate.rs:148-294`: mutates and validates issuance/burn counters and computes the accounting commitment. A burn-recording call alone does not prove that a source account held funds, that a burn was authorized, or that the account ledger was debited.
- `monetary_genesis_v04_candidate.rs:44-88`: Genesis manifest constructor records the 1B owner allocation. Lines 123-145 derive the initial root from the ordinary account-ledger root and the accounting commitment.
- `monetary_ledger_v04_candidate.rs:42-110`: `from_genesis_manifest`, read-only accessors, validation and a v0.4 monetary root. Lines 183-324 implement QZL4 snapshot encode/decode and validate the restored ledger/accounting/root. The module comment explicitly says block transitions, issuance authorization, fork-choice/reorg, durable store and node-runtime integration are not implemented.

### B. Existing MBK3 / PMT3 / PFM3 path

```
private_testnet_node::build_next_monetary_candidate
  -> MonetaryLedgerState::expected_miner_reward
  -> MonetaryLedgerState::preview_state_root_after
  -> encode_candidate_monetary_network_block (PMT3)
  -> private_testnet_node::import_monetary_payload
  -> PrivateTestnetMonetaryForkStore::submit
  -> PrivateTestnetMonetaryForkChoice::insert_encoded
  -> PrivateTestnetChain::append_monetary_live / append_monetary_historical
  -> MonetaryLedgerState::apply_block / prepare_monetary_candidate
  -> PFM3 durable branch/manifest commit and publication
```

Relevant source locations:
- `state_machine.rs:950-1013`: existing `MonetaryLedgerState`, policy fingerprint, shared issuance parameters and height-derived reward function.
- `state_machine.rs:1015-1092`: MBK3 monetary codec and block ID.
- `state_machine.rs:1590-1679`: monetary root preview, timestamp-checked transition and atomic state publication after the candidate root is verified.
- `private_testnet_monetary_fork_choice.rs:171-270`: PMT3 decode, parent-chain selection, consensus admission, branch insertion and best-tip/reorg choice.
- `private_testnet_monetary_fork_store.rs:368-400`: durable PFM3 submit path.
- `private_testnet_node.rs:1502-1567`: explicit PMT3 importer checks network, protocol version, height/Genesis relationship and digest before store submission.
- `private_testnet_node.rs:4205-4267`: local PMT3 producer derives its claimed subsidy from the existing monetary state, previews the root, mines the PoW header and encodes the PMT3 envelope.
- `private_testnet_node.rs:4599-4705`: local-only PMT3 smoke creates the existing Genesis/store, builds and imports blocks, checks MTA3 acknowledgements and reopens the PFM3 store.

### C. Existing MBK4 / PMT4 / PFM4 hybrid path

```
private_testnet_node V4 hybrid profile
  -> existing MonetaryLedgerState Genesis
  -> encode/decode PMT4 envelope (TXN4 / hybrid identity binding)
  -> private_testnet_node::import_v4_hybrid_monetary_payload
  -> PrivateTestnetV4HybridForkStore::submit
  -> PrivateTestnetV4HybridForkChoice::insert_encoded
  -> existing PrivateTestnetChain monetary transition
  -> PFM4 manifest/branch commit, replay, and optional external-anchor APIs
```

Relevant source locations:
- `state_machine.rs:1094 onward`: MBK4 hybrid codec still checks the existing miner-budget constant; the checked transition uses `MonetaryLedgerState`, not `MonetaryLedgerStateV04Candidate`.
- `private_testnet_v4_hybrid_fork_choice_candidate.rs:185-270`: PMT4 decode, transaction manifest checks, PoW, parent-chain selection and hybrid monetary transition.
- `private_testnet_v4_hybrid_fork_store_candidate.rs:289-369`: API for opening after a verified external CAS read; lines 595 onward contain ordinary local submit and lines 678 onward an external-anchor submit API.
- `private_testnet_node.rs:4140-4203`: PMT4 importer checks network, protocol version, height/Genesis relationship and digest before PFM4 submission.
- `private_testnet_node.rs:4270-4305`: local PMT4 Genesis helper derives placeholder accounts and starts from the existing `MonetaryLedgerState` with the older founder/public-goods allocation.
- `private_testnet_node.rs:4401-4538` and `5684-5725`: local/peer PFM4 runtime paths build and reopen the existing hybrid store. The reviewed paths use local store open/reopen APIs; an external CAS capability in the store module is not proof that this node path is actively using it.

### D. Separate generic BLK2 importer

- `chain_import.rs:80-143`: `ChainImportService::open` restores an ordinary `LedgerState`; `import_bytes` decodes a BLK2 block, stages standard transaction admission, atomically saves the ordinary snapshot, then publishes memory state.
- `chain_import_node.rs` uses that service. It is a distinct import service, not an adapter for PMT3/PFM3, PMT4/PFM4 or the v0.4 monetary allocation state. Do not route v0.4 monetary blocks through it without a separately versioned service and explicit acceptance contract.

## 3. Concrete blockers before runtime integration

1. **No v0.4 height-based issuance schedule is defined in the candidate policy.** The current policy contains a 3B mining allocation ceiling but not an explicit initial subsidy, halving/decay rule, block-height convention, zero-reward termination rule, or treatment of the final remainder. The existing `MonetaryLedgerState::expected_miner_reward` derives rewards from the older schedule and must not be silently reused as v0.4.
2. **There is no v0.4 monetary block envelope/state-transition method.** QZL4 is a snapshot codec, not a block codec. PMT3/MBK3 and PMT4/MBK4 currently enter the existing state machine.
3. **Issuance accounting is not the account mutation.** A v0.4 transition must debit/credit the actual ledger and update allocation counters, miner counter, live supply and state root atomically. Peer-supplied reward fields cannot decide minting.
4. **The ledger's mutation boundary needs a trusted internal transition API.** `LedgerState` exposes no public arbitrary-credit/mint primitive, and the existing `prepare_monetary_candidate` is private and tied to the old policy. The v0.4 implementation should add a narrowly scoped internal transition that atomically changes account balances and v0.4 counters, not a public bypass around ledger invariants.
5. **Burn reserve accounting needs runtime authorization and balance proof.** The accounting counter alone cannot prove a source balance, signer/governance authority, replay protection or an account debit.
6. **Version selection/activation is not frozen.** A network ID, policy fingerprint, protocol version and activation rule must be bound together, with explicit rejection of unknown profiles, legacy downgrade and ambiguous migration.
7. **QZL4 is not anti-rollback.** The checksum and root detect corruption/inconsistency, not restoration of a previously valid snapshot. Gate 8 needs a separately operated CAS/anchor, verified receipts and runtime fail-closed invocation.

## 4. Safest next implementation sequence

1. Freeze a written v0.4 issuance schedule and activation/version-selection profile before inventing any consensus constants.
2. Add a separately named v0.4 monetary block type/codec and a pure expected-reward function driven only by that frozen profile and parent state. Add independent Python vectors, including boundary-height and exhaustion vectors.
3. Add a clone/stage/validate/commit state-transition candidate that derives the reward locally, applies account and allocation changes atomically, recomputes the exact v0.4 root, and leaves the prior state unchanged on all failures.
4. Add negative tests for peer-forged reward, wrong profile, legacy envelope, cap overflow, zero account/network, malformed bytes, replay, unauthorized burn and accounting/ledger mismatch.
5. Only then create a new PFM/QZL runtime adapter with explicit migration/downgrade rejection; test producer/importer parity, fork choice, reorg/replay, snapshot restore and crash around durable commit.
6. Wire a separately verified external CAS service and prove restore/race/crash behavior before considering Gate 8.

Do not change MBK3/MBK4 behavior as a side effect of these candidate steps. No public launch or financial activation follows from this audit.

## 5. Validation ledger for this workstream

Verified against the branch at the time of the audit:
- GitHub Actions run `40092772241` passed for the exact earlier SHA `b99aae3789d18ed73ed576ff028b566d5dcb8f3f`.
- The full local Rust library test run on `b99aae3` completed: 792 passed, 0 failed.
- The isolated Windows multi-process durable-store test passed 3/3 serial executions, then passed 10/10 additional serial stress runs and 12/12 runs across four concurrent parent processes. This did not reproduce the earlier `Access is denied (os error 5)`; the root cause is still unknown and the earlier failure remains an open diagnostic item.
- The targeted `monetary_ledger_v04_candidate` suite passed 5/5 tests on `96bf078`.
- The v0.4 Genesis and QZL4 Python oracle scripts reproduced the saved 450-byte QZL4 vector, with SHA-256 `47f76ecf7b81fa11e6868b865d214bcf1e9124f95f1bdc844df356719cec5826`.
- `cargo fmt --all -- --check` passed.
- GitHub Actions run `40094522914` completed with `success` for the exact SHA `96bf07806e32a9fa3ffbaeb025b6d4680c2c1c8c`. Both jobs passed: `Format, check, and test` (including independent Python oracles, formatting, all-target check and all-target tests) and `Windows PMT4 TXN4 two-node loopback` (signed transaction/replay and PFM4 paged archive reorg/stale-cursor checks). This green result is for `96bf078`; a later documentation-only commit has its own CI run.

These results validate the stated candidate surface; they do not close Gate 2 or Gate 8.
