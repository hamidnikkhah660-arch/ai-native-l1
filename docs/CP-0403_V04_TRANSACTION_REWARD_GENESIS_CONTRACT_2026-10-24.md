# CP-0403 — v0.4 Transaction + Reward + Genesis Contract

**Date:** 2026-10-24
**Base commit audited:** `880b642eb22e225343fd1c6141ad652754430e0b`
**Status:** Candidate implementation plus independent vector; deliberately not node-wired or Mainnet-activated.

## Outcome

CP-0403 extends the profile-bound candidate path with **QZB4 version 2**, a canonical transaction-bearing execution block. QZB4 v1 remains byte-for-byte unchanged as a mining-only candidate. The v2 candidate carries a bounded list of canonical `Transaction` envelopes alongside the selected profile fingerprint, parent, height/time, miner, claimed subsidy, and combined post-execution state root.

The producer derives the reward from its local parent state and explicit QZCP schedule. The importer independently derives the same reward and stages the transaction batch plus miner credit on a cloned ledger. It then updates the mining/network-security allocation counter, cumulative mined counter and the profile-bound state root. The canonical block ID is committed to the ledger tip only after the complete state transition validates; any failure leaves the previously published state unchanged.

This closes the *candidate-level execution contract* for native transfers plus mining issuance. It does **not** close production Gate 2, Gate 8, or network activation because the block/transition is not integrated with the node runtime, canonical fork choice, live durable store or external anti-rollback trust domain.

## Canonical Genesis and profile boundary

1. **QZGM v1** remains the owner-allocation Genesis manifest. Its bytes and legacy QZGM/QZL4 format are unchanged. The manifest fixes the network ID, owner Account ID, policy fingerprint, initial allocation accounting and initial root.
2. **QZCP v1** binds the exact QZGM hash/root and the explicitly selected mining subsidy/halving schedule. There is no default schedule. The profile fingerprint is included in every QZB4 block.
3. **QZP4 v1** remains the profile-bound snapshot envelope. Restore requires the expected Genesis and exact configured QZCP profile; an inner legacy snapshot is not reinterpreted as a QZP4 snapshot.
4. **QZB4 v1** remains a fixed-width, mining-only candidate (166 bytes).
5. **QZB4 v2** is the transaction-bearing extension. It preserves the `QZB4` family magic but has wire version 2 and a different canonical block-ID domain. Its variable-length TXN2 transaction entries are length-delimited and bounded. A v1 decoder rejects v2 and a v2 decoder rejects v1; no cross-version fallback is permitted.

### QZB4 v2 field order

| Field | Encoding |
|---|---|
| Magic / wire version | `QZB4` / u16 `2` |
| Profile fingerprint | 32 bytes |
| Height / timestamp | u64 / u64, big-endian |
| Parent block ID | 32 bytes |
| Miner Account ID | 32 bytes |
| Claimed subsidy | u128, big-endian; independently recomputed by importer |
| Transaction count | u32, big-endian; capped at `MAX_TRANSACTIONS_PER_BLOCK` |
| Transactions | repeated u32 length + canonical `encode_transaction` bytes; each entry bounded by `MAX_TRANSACTION_BYTES` |
| Post-execution state root | 32 bytes, commits to ledger root, allocation accounting and cumulative mined counter |

The outer length is bounded by `MAX_ENCODED_V04_EXECUTION_BLOCK_BYTES`. Unknown versions, malformed lengths, invalid nested transactions, trailing bytes and noncanonical re-encoding fail closed. The v2 block ID uses `QUANTUMZXB-V04-EXECUTION-BLOCK-ID-CANDIDATE-V1\0`, distinct from the v1 mining-only block ID domain.

## Atomic transition contract

For a parent state `S`, block `B`, and injected transaction authenticator, the importer performs these steps on temporary state only:

1. Validate canonical QZB4 v2 framing and the exact profile fingerprint.
2. Require the next height and matching parent; derive `expected_reward = schedule.reward_for_height(height, S.total_mined_atoms)` locally and reject a different claimed subsidy.
3. Validate every transaction using the existing transaction contract: canonical TXN2 fields, network ID, exclusive expiry, duplicate-ID check, signature verification through the injected authenticator, account nonce, balance, fee arithmetic and account limits.
4. Apply transfers/fees to a cloned ledger, then credit only the block's miner with the locally derived reward. The ordinary transfer fee remains in `fee_pool`; this candidate does not pay fees directly to the miner.
5. Record that same reward in `AllocationBucket::MiningNetworkSecurity`; update cumulative mined atoms; validate each budget, total-supply cap and equality between ledger total value and accounting live supply.
6. Recompute and compare the profile-bound post-state root. Only after it matches, derive the canonical block ID, commit the tip on the staged ledger, validate once more, and atomically publish the new wrapper state.

The `TransactionAuthenticator` is an explicit input; there is no permissive runtime default. The fixture authenticator in unit tests is deliberately permissive for a nonempty test signature and is **not** cryptographic launch evidence. Production account-key ceremony, signature policy and authenticator deployment still require review. This block candidate preserves the current TXN2 transaction envelope for this scoped experiment; it does not assert that the final production native-account signature scheme is settled.

## New regression and independent oracle coverage

- Producer and importer given the same Genesis/profile/transfer independently derive the same block ID, root, balances, fee pool, allocation accounting, mined counter and resulting QZP4 snapshot.
- The fixture transfer debits amount plus fee from the owner, credits the recipient amount, leaves the fee in the fee pool and separately credits the miner with the locally derived scheduled subsidy.
- Negative atomicity checks cover wrong profile, forged reward, forged state root, rejected transaction signature, wrong parent, and expiry-at-block-time. The original snapshot remains byte-identical after every failed import.
- Wire checks cover exact v2 round-trip, rejection of v2 by the v1 decoder, rejection of v1 by the v2 decoder, truncation, trailing bytes and excessive transaction count.
- The independent standard-library Python oracle now generates QZB4 v2 bytes, state root and block ID; Rust unit tests compare all three byte-for-byte.

Local validation on this working tree:

- `cargo fmt --manifest-path src/native/pow_bench/Cargo.toml --all -- --check` - passed.
- `python simulations/quantumzxb_v04_transition_profile_vectors.py --check` - passed; independent Python QZB4 v2 length (311 bytes), state root and block ID match the Rust candidate byte-for-byte.
- `cargo check --manifest-path src/native/pow_bench/Cargo.toml --all-targets --locked --offline` - passed with existing unused/dead-code warnings.
- `cargo test --manifest-path src/native/pow_bench/Cargo.toml --locked --offline --lib monetary_transition_v04_candidate -- --nocapture --test-threads=1` - 12 passed, 0 failed.
- `cargo test --manifest-path src/native/pow_bench/Cargo.toml --all-targets --locked --offline` - passed; 809 library tests, binary-target tests and integration/vector tests completed with 0 failures.
- The Genesis, ledger-snapshot, issuance-schedule and QZCP/QZB4/QZP4/QZB4-v2 oracle commands all completed successfully. Only the QZB4-v2 vector command prints an explicit PASS marker; the other legacy generator commands were run and produced the same expected fixtures.

## Explicit limitations — do not treat fixtures as economics

- The oracle values (`10,000` atoms initial subsidy and two blocks per halving) exist only to make deterministic vectors small. They are not approved production economics.
- QZGM initializes the owner-allocation bucket according to the candidate policy; only the mining/network-security bucket is issued by this block transition. The other six planned non-owner buckets are not automatically issued and do not represent Genesis balances.
- Burns, airdrop/treasury issuance, vesting/locks, governance-controlled bucket distribution, bridge assets, transaction pool policy, PoW validation, timestamp wall-clock admission, fork choice/reorg, durable-store integration and production P2P are not implemented by QZB4 v2 itself.
- The generic `LedgerState` and `TransactionAuthenticator` interfaces do not establish a deployed key registry or a production cryptographic policy. Independent consensus/security review remains required.
- Runtime dispatch must be based on a configured network + exact Genesis/profile + an explicitly approved activation/migration policy. It must not infer production version from the payload and must never downgrade after a decode failure.

## Next integration sequence

1. Reconcile the candidate profile with the existing node producer/importer/store and select the production transaction/key-authentication policy; resolve any difference between earlier 40/30/30 candidate code and the eight-bucket QZGM policy.
2. Add a separately reviewed profile-driven dispatch boundary and keep legacy BLK2 / PMT3 / PMT4 paths strict. Unknown version, network/profile mismatch, and pre/post-activation mismatches must reject without fallback.
3. Add the selected v0.4 transition to producer, importer, fork choice/reorg, durable persistence, QZP4 restore and historical replay, with identical state-root results across independent nodes.
4. Qualify restart/reorg/crash recovery plus independent external CAS rollback protection; close Gate 2 and Gate 8 only after evidence and independent review.
5. Only then create an approved production manifest/activation decision and plan value-bearing public Devnet/Mainnet releases.

**Decision:** CP-0403 provides a transaction-bearing, profile-bound candidate contract and independent regression vector. It is a substantive implementation milestone, not public-launch approval.
