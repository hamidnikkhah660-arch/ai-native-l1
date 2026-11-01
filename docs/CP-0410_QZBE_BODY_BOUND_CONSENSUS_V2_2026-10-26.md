# CP-0410 — QZBE v2 Body-Bound Consensus Identity

Date: 2026-10-26

Status: **candidate protocol correction; not connected to the canonical node; not approved for public or value-bearing use**

## Finding

The earlier local QZBE candidate keyed fork-choice branches by a digest of the PoW header alone. QZB4 v2's execution state root commits to balances, account nonces, fees and monetary accounting, but it is calculated before the ledger tip is committed to the canonical execution-block ID. Therefore two different canonical transaction bodies can produce the same header and the same pre-tip state root while having different execution-block IDs.

In that case, a header-only digest is insufficient as a unique branch identity. One store could reject a different body as a digest conflict; independent peers could also agree on the header digest while retaining different execution-block tip hashes. A subsequent block's parent-ledger hash would then expose the divergence. This is a consensus correctness issue, not merely a storage naming concern.

## Protocol correction

QZBE envelope version is now **2** (distinct from the transaction-bearing **QZB4 body version 2**). The QZBE v2 proof/fork-choice digest is:

`SHA-256("QUANTUMZXB-QZBE-BODY-BOUND-POW-V2\\0" || header_pow_digest || qzb4_execution_block_id)`

where:

- `header_pow_digest` is the existing memory-hard digest of the canonical PoW header under the pinned PoW parameters;
- `qzb4_execution_block_id` is the domain-separated ID of the complete canonical QZB4 v2 body, including its ordered transactions and state root;
- the target comparison is applied to the final body-bound QZBE digest;
- branch graph keys, previous-consensus links, persistent branch filenames, and manifest entries all use the same body-bound digest.

The header/body binding checks still require the header and QZB4 body to agree on network, version, height, timestamp, ledger parent and state root. State execution, signature/authorization checks, rewards, target-history validation and cumulative-work fork choice remain required independently. The legacy PMT3/PMT4 PoW digest is unchanged.

Because the candidate consensus identity changes, QZBE v1 is intentionally rejected rather than implicitly upgraded. The PoW consensus fingerprint, persistent QZMF manifest format and local QZCA operational marker have corresponding version/domain separation updates. Old candidate data should not be reused; create a fresh dedicated directory for every new QZBE v2 development network.

## Regression coverage

- `body_permutations_with_same_state_root_have_distinct_pow_identity_and_replay`: creates two valid blocks with identical headers and equal state roots but different canonical body IDs; confirms the former header-only digests collide, the QZBE v2 digests differ, both branches can be retained, and replay reproduces a deterministic selected state.
- `independent_qzbe_stores_exchange_loopback_blocks_and_replay_identically`: transfers transaction-bearing QZBE envelopes over TCP loopback between two independent local stores, verifies receiver-side rejection is atomic for a bad signature, then confirms both stores converge and replay identically after reopen.
- Existing QZBE fork-choice, envelope parsing, store-manifest, CAS-receipt and recovery tests remain part of the focused validation set.
- The offline-only smoke executable was run twice against one unique temporary data directory: it advanced from height 0 to 3, then reopened and resumed from height 3 to 5. It reported replayed state roots, kept all network/service listeners disabled, and the temporary directory was deleted after success.
- Local validation passed: `cargo fmt --all -- --check`; `cargo check --all-targets --locked --offline`; and `cargo test --all-targets --locked --offline` with **828 library tests passed** and all binary/integration targets passing with zero failures. Both node test harnesses passed 36/36; the QZBE smoke binary passed 6/6. This is local validation; fresh GitHub CI on the candidate change is still pending.
- `python simulations/public_docs_refresh_checker.py` reported `PUBLIC_DOCS_PREFLIGHT=PASS`, 51 README relative links, and 381 Git-index checksums.

Test fixtures deliberately use an easy target and reduced memory cost. Those settings are test-only and are not recommended network parameters.

## Explicit limitations and next gates

This correction does not wire QZB4/QZBE into the canonical node's producer, importer, peer protocol, mempool or network fork choice. The offline smoke executable is still not a two-node production runtime. The external CAS implementation remains an injected test fixture; the QZCA local marker is not an independent anti-rollback authority. There is no independent security audit, no externally administered monotonic floor, and no production signature/key provisioning or approved issuance schedule.

The current `build_candidate_on` API explicitly accepts a caller-supplied nonce and does not mine for a valid body-bound target. Before networked QZBE staging, provide a bounded QZBE v2 mining/candidate-production loop that varies the nonce against the final body-bound digest, uses the correct branch-derived target, has cancellation/resource bounds, and is covered by non-MAX-target vectors.

Next engineering gates are: publish this correction for fresh exact-commit CI; add the bounded body-aware QZBE producer/miner; design a dedicated zero-value testnet node runtime wired through QZB4/QZBE producer, importer, fork choice, durable store, authenticated peer transport and transaction admission; validate hybrid transaction signing and replay protection; complete independent-provider/rollback tests; then conduct multi-host adversarial staging and independent security review. Public, exchange-tradable or otherwise value-bearing launch remains blocked until consensus runtime integration, security review, approved economic parameters and qualified jurisdictional advice are complete.

No public network has been launched, no value-bearing issuance has occurred, and no auditor, provider, node operator or legal adviser has been contacted or engaged through this work.
