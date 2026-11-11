# CP-0588 - QFP6 permissionless Genesis runtime integration gate

Date: 2026-11-11
Base: CP-0587 exact qualified Rust-validation head `a2c891bbed322236b4f9a38aec2a0bb5cf478aa`
Status: source audit and implementation boundary; no node activation or Mainnet authorization.

## Outcome

CP-0587 closes its stated cross-host Q6TI/Q6MJ transaction-admission and process-recovery qualification. It does not close the QFP6 base-node startup path. The next runtime must follow the permissionless-first architecture in CP-0443: the ordinary base node validates and replays the complete chain from an independently pinned immutable Genesis descriptor, uses the existing QFP6 durable fork store and cumulative-work fork choice, and does not require a third-party Provider, Q6EA Anchor, Q6TS remote floor, or checkpoint operator to join the base chain.

Q6EA/QAP1 and Q6TS remain optional, explicitly selected trust extensions for anchored/pruned/checkpoint operation. They must not silently become universal base-protocol dependencies.

## Exact source findings on CP-0587 base

1. `qrun_v06_node.rs` supports only `--preflight` and `--probe-qap1`; `--run` returns a deliberate nonzero refusal. No production lifecycle is started.
2. `QRunV06NodeRuntime<A>` in `qrun_v06_node_runtime_candidate.rs` requires a `QRunV06NodeAnchorGate` at construction and verifies an external anchor. It is therefore not the permissionless full-history base runtime.
3. `QRunV06DurableForkStore::open_with_expected_genesis_descriptor_commitment` already provides a Genesis-rooted local durable-store opening seam. `QRunV06PowForkChoice::new_with_expected_genesis_descriptor_commitment` already provides a pinned-descriptor fork-choice seam. Reuse these; do not create a second consensus/store implementation.
4. The current QFP6 time admission is strictly increasing timestamps (including Genesis lower-bound checks) but source inspection found no branch-local median-time-past rule or deterministic future-time bound in fork choice, canonical execution and checkpoint-history validation. This is a consensus safety blocker; CP-0578's SHA-256d selection is still a candidate profile and does not close timestamp/retarget safety.
5. CP-0573's complete preflight package is for the anchored Q6PN/Q6TS/Q6EA/Provider path. It is not a permissionless base-node config and must not be made mandatory for ordinary Genesis replay.
6. CP-0578 documents SHA-256d candidate parameters inherited from an easy candidate-testnet fixture, not independently calibrated production parameters. Its fingerprint/profile must not be called frozen Mainnet consensus.
7. Q6HA's ML-DSA-65 verifier remains candidate-only; Noise transport uses classical X25519. No post-quantum production security claim is justified.

## Required CP-0588 implementation sequence

### A. Freeze base-chain identity and consensus before enabling runtime

- Define one canonical QFP6 manifest and exact derivation/commitment rules for Network ID, Profile ID, Q6GD descriptor, Genesis package digest/state root, founder account and CP-0566D tokenomics policy.
- Reconcile the configured Genesis allocation with the owner's approved 10B supply / 10% founder direction. The preflight's 1B-Founder invariant is a candidate rule and must not be silently treated as final owner approval.
- Freeze a versioned deterministic branch-local MTP and retarget timestamp policy; specify endpoint selection, rounding, overflow and adversarial timestamp behavior. Apply the same policy to mining, import, fork choice, replay, checkpoint restore and restart.
- Freeze SHA-256d target, block interval, retarget bounds and all consensus parameters; replace candidate/easy fixture parameters only after reproducible calibration and cross-implementation vectors.
- Bind all consensus/time/tokenomics rules into the canonical consensus fingerprint and immutable profile manifest.

### B. Implement the permissionless base runtime

- Add a distinct base-runtime composition over the existing Genesis-rooted `QRunV06DurableForkStore` and `QRunV06PowForkChoice`; do not require Q6EA, Provider, Q6TS remote floor, or checkpoint trust for full-history mode.
- Require independently supplied expected manifest/config digest and Genesis descriptor commitment; never derive trust pins from the same untrusted files being checked.
- Validate/replay every block from Genesis before opening peer admission. Refuse missing, truncated, malformed, wrong-network, wrong-profile, wrong-consensus, invalid-PoW, invalid-time, invalid-state-root or invalid-cumulative-work history.
- Keep anchored/pruned startup as a separate explicit mode with its own trust assumptions and Q6EA/QAP1 preflight. Never silently fall back between modes.
- Wire the existing transaction ingress/mempool, peer listener, durable commit, fork-choice/reorg, QAP1 optional path, mining loop and orderly shutdown only after constructor/config seams are proven. Positive acknowledgements must follow durable canonical admission; pending Q6TI is not confirmation.

### C. Qualification

- Unit tests: missing/mismatched manifest pins, Genesis descriptor, network/profile, tokenomics, Q6CP, time policy, malformed archive, corrupt segment and invalid PoW must fail closed before listener bind.
- Restart/reorg: reopen full-history store, replay from Genesis, reject stale/invalid branches and select the greater valid cumulative-work branch; compare exact tip, height, work and state root.
- Two clean processes/hosts: start from the same published manifest and Genesis, synchronize complete history without private CAS/Anchor services, propagate a signed transaction, mine/import a block, restart and independently converge on identical canonical state.
- Optional anchored/checkpoint mode gets separate tests and must not be required for the base-mode acceptance test.
- Exact-head Rust CI and reproducible binary hashes are required. Do not merge or enable public binds as part of this candidate.

## Explicit non-claims

This CP does not create or approve a production Genesis, consensus profile, key, wallet, Provider, Anchor, trust floor, public peer endpoint, mining reward payout, public RPC/explorer, exchange market, or QZXB/USDT settlement. No Mainnet activation is authorized. A successful preflight or unit test is not a public network.

## Decision required before production parameters are frozen

The current repository contains a 1B QZXB Founder Genesis invariant (10% of the 10B cap) and candidate issuance parameters. The owner must approve the exact canonical manifest/Genesis allocation and timestamp/PoW rules before the immutable production identity and expected pins can be generated. Do not fabricate these values or reuse v0.5/test fixtures.
