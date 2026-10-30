# CP-0402 - Runtime Call-Site and Version-Compatibility Audit

**Date:** 2026-10-24
**Reviewed source baseline:** `5f256137b5e797f01ce81383a8916ee191f35d91`
**Status:** Source audit plus narrow PMT3/PMT4 no-cross-decode regression. No live dispatch, consensus activation, economic parameter selection, or production claim.

## Executive result

The concrete code paths are now mapped to line-level producer, decoder/importer, state transition, fork-choice, persistence, and runtime-selection points. They are separate candidate paths, not one canonical v0.4 producer/importer contract. Existing strict version encoders and stores already separate PTB2/PFS2, PMT3/PFM3, and PMT4/PFM4. This checkpoint adds explicit cross-family decoder assertions so a valid envelope from either PMT family is not accidentally accepted by the other decoder.

**Gate 2 remains OPEN.** The recently developed QZGM/QZCP/QZB4/QZP4 v0.4 candidate is a different monetary model from the older MBK3/MBK4/PFM3/PFM4 research paths: the former uses the owner-directed eight-bucket 10B policy and an explicitly supplied mining schedule; the latter's `MonetaryLedgerState` Genesis is 4B founder / 3B public-goods, and its legacy candidate reward schedule is fixed in `state_machine.rs`. Those models must not be combined or silently substituted. No production monetary profile, key ceremony, schedule, activation height, or migration policy is approved in this source baseline.

## Exact runtime call-site map

| Boundary | File and lines (reviewed baseline) | What the code actually does | Gap before production |
|---|---|---|---|
| Legacy block/state codec | `src/native/pow_bench/src/state_machine.rs:359-443`; state `apply_block` at `:822-887` | Canonical BLK2 block encode/decode/ID plus a `LedgerState` transition. | This does not carry the new v0.4 allocation counters/profile or select a production monetary version. |
| Default durable importer | `src/native/pow_bench/src/chain_import.rs:7-15, 61-143` | `ChainImportService::open` loads/initializes an ordinary `LedgerState`; `import_bytes` calls `decode_block`, stages `LedgerState`, uses the explicitly supplied legacy admission boundary, atomically saves its snapshot, then publishes state. | This is a legacy BLK2 importer, not an MBK3/MBK4 or QZB4 monetary importer. There is no common network/profile/activation dispatcher here. |
| Admission APIs | `src/native/pow_bench/src/chain_admission.rs:180-231, 235-286, 291-346, 350-403` | Separate explicit APIs exist for legacy blocks, `MonetaryBlock`, and `V4HybridMonetaryBlock`; live variants validate clock provenance/timestamp policy, replay variants avoid wall-clock dependence. | Callers select the API; a shared profile-derived wire dispatcher does not yet bind the API choice across producer, importer, fork choice, and restore. |
| PMT3 / MBK3 wire | `src/native/pow_bench/src/private_testnet_monetary_wire.rs:1-180`; MBK3 body at `state_machine.rs:962-1011, 1094-1169` | PMT3 has its own magic/version and strict canonical MBK3 decoder. The detached PoW header binds network, protocol version, height, timestamp, parent and state root. | Candidate-only; not the public Devnet canonical transaction/money profile. |
| PMT3 producer | `src/native/pow_bench/src/bin/private_testnet_node.rs:4205-4268` | `build_next_monetary_candidate` takes the `MonetaryLedgerState` from a PFM3-backed chain, derives `expected_miner_reward()`, previews the root, obtains target and emits PMT3. | Uses the older `MonetaryLedgerState` policy, not the CP-0397 schedule/profile or eight-bucket allocation counters. It is not the QZB4 producer. |
| PMT3 importer | `src/native/pow_bench/src/bin/private_testnet_node.rs:1502-1567` | `import_monetary_payload` requires PMT3 decoding, matches network and configured protocol version, checks height/Genesis-parent relation, then submits through `PrivateTestnetMonetaryForkStore`; duplicate/unknown-parent/rejection are explicit. | Isolated from the ordinary ChainImportService and the new QZP4 profile-bound snapshot candidate. |
| PMT3 fork/store | `src/native/pow_bench/src/private_testnet_monetary_fork_choice.rs` and `private_testnet_monetary_fork_store.rs`; called by the importer above | Candidate fork choice and durable archive/replay for MBK3/PMT3. | Does not constitute the production canonical state store or an approved version-activation boundary. |
| PMT4 / MBK4 wire | `src/native/pow_bench/src/private_testnet_monetary_wire.rs:180-370`; body at `state_machine.rs:1013-1024, 1171-1296` | PMT4 carries canonical MBK4/TXN4 plus a bound detached header. The PMT4 decoder requires its own magic/version and header/body consistency. | Candidate-only and intentionally distinct from PMT3. |
| PMT4 producer | `src/native/pow_bench/src/bin/private_testnet_node.rs:4054-4138` | `build_next_v4_hybrid_monetary_candidate_with_transactions` derives subsidy through the existing `MonetaryLedgerState`, previews the hybrid root and emits PMT4. | TXN4 authorization is a candidate path; this code does not use `MonetaryLedgerStateV04TransitionCandidate` or the QZCP/QZB4/QZP4 contract. |
| PMT4 importer | `src/native/pow_bench/src/bin/private_testnet_node.rs:4140-4203` | Requires PMT4, verifies network ID, configured protocol version and Genesis/height relationship, then calls the PFM4-backed store. | Isolated candidate; no production Genesis activation or downgrade/migration contract is established. |
| PMT4 fork choice/store | `src/native/pow_bench/src/private_testnet_v4_hybrid_fork_choice_candidate.rs:82-117, 185-240`; store at `private_testnet_v4_hybrid_fork_store_candidate.rs:226-305` | Separate PMT4 branch graph plus PFM4 durable store/replay. The store has explicit optional/external CAS interfaces. | Local interfaces do not prove an independently operated production anti-rollback provider. Gate 8 remains OPEN. |
| Runtime-mode selector | `src/native/pow_bench/src/bin/private_testnet_node.rs:6621-6675` | `run_with_runtime_profile` rejects multiple selected monetary smoke modes, routes a single CLI-selected mode, restricts candidate modes to `devnet_node`, and prevents reuse of profile-locked data directories. | This is **configuration-level smoke-mode selection**, not an incoming-block dispatcher activated by a frozen production network profile and block height. |
| PMT4 smoke limits | `src/native/pow_bench/src/bin/private_testnet_node.rs:4360-4417, 5649-5819, 6142` | Runtime explicitly logs offline/local research profile, local easy PoW, PFM4/PMT4, and `public_launch_approved=false`; local Genesis may use non-key placeholder accounts. | Not a public Mainnet or public value-bearing launch path. |
| Zero-value Devnet wrapper | `src/native/pow_bench/src/bin/devnet_node.rs:1-12` and `lib.rs:22-27` | Entry point shares the PTB2/PFS2 loop and selects a zero-balance profile candidate. The source says it remains loopback-only until authenticated peer transport is wired before PTB2 parsing/import. | Not a public multi-operator native monetary Devnet. |
| New CP-0391-0400 Genesis/profile/transition | `monetary_genesis_v04_candidate.rs:1-19, 53-88, 184-220`; `monetary_issuance_v04_candidate.rs:1-15, 49-76, 91-152`; `monetary_transition_v04_candidate.rs:132-261, 399-615`; QZP4 at `:617-700+` | QZGM binds the eight-bucket policy and initial accounting; QZCP binds explicit schedule and Genesis; QZB4 candidate derives reward from local state/profile and checks profile, height, reward, cap, and state root atomically; QZP4 snapshot embeds profile and verifies it on restore. | The new block candidate is mining-only, not a full transaction-bearing production block contract, and none of these APIs is wired to node producer/import, fork-choice, durable store, or activation. The vector schedule values are test fixtures, not approved economics. |

## Wire/profile compatibility matrix

This is the safe compatibility contract for the current candidates. It is not a decision that any candidate is activated on Mainnet.

| Selected state/runtime family | Input family | Required behavior | Current evidence / next requirement |
|---|---|---|---|
| Legacy BLK2 / PTB2 / PFS2 | Canonical BLK2 on its legacy path | Decode and apply only the legacy block/state contract; reject other magic/version families rather than converting their bodies. | `ChainImportService` only calls `decode_block`. Add/retain regression proving a candidate envelope cannot be accepted via an alternate path. |
| PMT3 / MBK3 / PFM3 candidate | Canonical PMT3 with MBK3, matching network/protocol and parent | Route only to PMT3/MBK3/PFM3 admission and replay; reject PMT4, PTB2 and QZB4. | Existing strict PMT3 decoder plus new cross-family assertion; runtime mode stays explicitly selected. |
| PMT4 / MBK4 / PFM4 candidate | Canonical PMT4 with MBK4/TXN4, matching network/protocol/manifest and parent | Route only to PMT4/MBK4/PFM4 admission and replay; reject PMT3, PTB2 and QZB4. | Existing strict PMT4 decoder plus new cross-family assertion; runtime logs local diagnostic scope. |
| QZGM + QZCP + QZB4 + QZP4 v0.4 candidate | Exact v0.4 Genesis and profile, profile-bound mining block, profile-bound snapshot | Validate exact network, Genesis, policy/schedule fingerprints, block height/parent/reward/root/cap and snapshot profile; on any mismatch fail closed without state mutation. | Unit tests and Python vectors exist, but no canonical node dispatch/store/reorg/recovery path yet. Must not fall through to PMT3/PMT4 or legacy. |
| Any family | Unknown magic, version, profile or network | Reject before applying or persisting state. | Strict codecs reject unknown format versions; common profile-based dispatcher and activation matrix remain to be implemented after production parameters are approved. |

## Important economics/profile mismatch found

1. The older `state_machine.rs` constants at `:962-999` specify the candidate 4B founder / 3B miner / 3B public-goods profile and hard-code the candidate initial subsidy and halving interval. `MonetaryLedgerState::genesis` at `:1298-1335` credits founder and public-goods at Genesis; `expected_miner_reward` at `:1380-1389` derives the next reward from that policy.
2. The owner-directed v0.4 policy under `monetary_allocation_v04_candidate.rs` / `monetary_genesis_v04_candidate.rs` represents an eight-bucket 10B ceiling: 30% mining/network security and seven 10% buckets. `GenesisManifestV04::new` at `monetary_genesis_v04_candidate.rs:53-88` initializes the owner-allocation bucket at Genesis; other buckets start at zero issuance in its validation rules.
3. CP-0397 deliberately has no default subsidy or halving interval (`monetary_issuance_v04_candidate.rs:49-76`); the profile fingerprint records the chosen values. CP-0400's cross-language vector uses a deliberately small test subsidy/interval only for fixture generation.
4. Therefore PMT3/PMT4 builder/importer code cannot be described as implementing the new QZGM/QZCP/QZB4 policy. A production selection must explicitly reconcile the policy, initial issuance, transaction/fee/burn semantics, reward beneficiary mapping and all-bucket state-root/accounting rules before it sets any activation height.

This is a consensus compatibility issue, not just a documentation rename. Do not silently copy old constants into QZCP or treat test vectors as live parameters.

## Narrow code improvement in this checkpoint

`private_testnet_monetary_wire.rs` now has explicit assertions in both valid round-trip tests:

- a valid PMT3 envelope is rejected by the PMT4 decoder with `BadMagic`;
- a valid PMT4 envelope is rejected by the PMT3 decoder with `BadMagic`.

This complements the existing unknown-version, malformed-length, detached-header/body binding, and round-trip tests. It is deliberately a codec-level guard and does not pretend to provide a runtime activation dispatcher.

Local validation performed:

- `cargo fmt --manifest-path src/native/pow_bench/Cargo.toml --all -- --check` — passed.
- `cargo test --manifest-path src/native/pow_bench/Cargo.toml --locked --offline --lib private_testnet_monetary_wire -- --nocapture --test-threads=1` — 4 passed, 0 failed.
- `git diff --check` — passed.

## Required sequence to close the canonical Genesis/reward/runtime contract

1. **Ratify the monetary specification first:** exact supply/allocation budget, whether Genesis pre-issues the owner bucket, real owner/miner/treasury account derivation through a reviewed key ceremony, reward subsidy and halving interval, fee allocation, burns, transaction admission, and migration/reorg semantics. Record the approval and profile fingerprint in a versioned manifest. No current fixture is an approved default.
2. **Implement the explicit version dispatcher** as a separate reviewed adapter. It must require a configured network + Genesis + policy/profile fingerprint + activation rule, classify a wire version once, route to exactly one decoder/state transition, and return hard errors for wrong-network/profile, unknown version, pre/post-activation mismatch and attempted downgrade. No decode-failure fallback.
3. **Build one transaction-bearing v0.4 block contract.** Current QZB4 candidate only performs a mining-only transition. Define how signed native transfers, fee accounting, burns and issuance are staged together under the same all-bucket root, then commit once.
4. **Integrate producer and importer symmetrically.** Producer derives reward locally; importer independently derives it and validates the same profile. Both must agree on accepted bytes, block ID, all account balances, bucket counters, mined counter, total/live supply and root. Reject a peer-claimed subsidy independently of the producer.
5. **Integrate fork-choice/reorg, durable storage, QZP4 restore and restart/replay.** Every branch must be staged against the same selected profile; old snapshots remain in their exact older decoder, never reinterpreted as QZP4. Add crash/recovery, conflicting branch, cap-boundary, wrong-profile, stale-generation and byte-for-byte legacy fixtures.
6. **Close Gate 8 and independently review.** Connect a real independent trust domain for anti-rollback, qualify on more than one host/OS and obtain consensus/cryptography review. Passing local tests or CI alone does not close these requirements.
7. **Only then decide activation.** The approved versioned manifest defines activation height and supported old/new history. Until that exists, a safe generic dispatcher can be unit-tested, but must not be wired to a value-bearing runtime or exposed as a production activation.

## Decision

This audit is complete for the inspected call sites and identifies the required integration boundary. The two narrow PMT cross-family assertions reduce one regression risk. **Gate 2 and Gate 8 remain OPEN; Gate 12 remains OPEN; no production Genesis, v0.4 activation height, public Mainnet, sale, listing or liquidity has been approved by this change.** The next implementation can safely proceed once the monetary and migration decisions are ratified; do not invent them in code.
