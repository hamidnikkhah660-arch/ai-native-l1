# CP-0437 ? QRun full-supply owner Genesis direction

**Date:** 2026-10-28

**Status:** Latest owner direction recorded; production runtime integration is NOT complete. This is a specification, not a Mainnet-launch claim.

## Current requested QRun native-coin policy

- Native network name: **QRun (Quantum Run)**.
- Native asset symbol: **QZXB**. This is the native asset of the independent QZXB chain, not a wrapped asset on another chain.
- Maximum total supply and Genesis issuance: **10,000,000,000 QZXB**.
- Genesis beneficiary: one owner account produced by the QZXB Wallet; exact account ID must be read from the wallet and bound into the frozen Genesis manifest.
- Initial owner balance: **10,000,000,000 QZXB (100% of supply)**.
- Subsequent minting and miner subsidy: **zero**. If all coins are issued at Genesis, the protocol must not also issue block rewards. Block producers would need fee-only compensation under the published consensus rules.
- Other pre-issued buckets: **zero** under this direction. Transfers can redistribute existing supply but cannot increase gross issuance. Burns reduce live supply and never reopen mint headroom.
- The previous 1B-founder / category-envelope proposal in CP-0422 is superseded for the future QRun Genesis target by this latest instruction. The historical 4B founder profile is also retired and must never be selectable for the QRun Mainnet profile.

## Version and history boundary

Do not falsify old records, rewrite old snapshots, or erase Git history. Retain the 4B model only as explicitly labelled legacy test/replay material. The current release surface, wallet, Genesis profile, docs and Mainnet launch process must not select it. A legacy profile must be rejected by the QRun Mainnet runtime, not merely hidden in the interface.

## What the new candidate code proves today

The source file src/native/pow_bench/src/qrun_v05_genesis_candidate.rs builds a deterministic in-memory Genesis state whose single owner account is credited with exactly 10B QZXB and whose state root/commitment bind the network ID and owner account. Unit tests check the supply and reject zero identity inputs.

This does **not** mean 10B coins have been issued on a live network. The candidate is not yet connected to the QZBE node's canonical producer/importer, persistent store, fork choice, replay, anti-rollback or public peer runtime. No production Genesis commitment has been activated, and no Mainnet node is currently running.

## Launch gates before the 10B balance can be called real

1. The owner creates a QZXB Wallet and securely backs up the 12-word phrase. Only the public account ID is used to prepare Genesis; never paste the phrase into chat, source control or a web form.
2. Implement and freeze the QRun v0.5 consensus profile so the candidate Genesis is used by every producer, importer, restart/replay, fork-choice and durable-store path. Reject the historical 4B profile and all legacy downgrade attempts.
3. Enforce zero post-Genesis issuance and zero miner subsidy, with explicit fee-only block-production economics, while proving the total-supply invariant through transfers, forks, reorgs and restart.
4. Freeze network ID, Genesis commitment, proof-of-work and difficulty rules, peer identity ceremony, independent bootstrap operators and recovery procedures.
5. Run a fresh multi-node independent QRun devnet, verify the same Genesis, owner balance, invalid-signature rejection, transfers, peer propagation, restart and reorganization; then complete independent security review before Mainnet.
6. After the frozen production network is running, query the owner account from multiple independent nodes and verify the exact 10B Genesis balance. Until then, all amounts are candidate design/test state, not spendable mainnet coins.

The instruction is to build a self-contained L1. It does not authorize bridging to Ethereum, BNB Chain, TRON, Sepolia, or any other external network. Any future external asset route would be an optional, separate integration and is not a dependency for native QZXB transfers.
