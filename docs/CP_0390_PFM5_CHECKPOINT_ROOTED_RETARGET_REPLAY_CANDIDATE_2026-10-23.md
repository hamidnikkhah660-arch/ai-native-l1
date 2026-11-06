# CP-0390 ? checkpoint-rooted PMT4 replay and bounded branch fork choice (2026-10-23)

## Why this exists

The previous PMT4/PFM4 candidate rejected every block above logical height 1,024 while the default retarget window reaches its first boundary at height 2,017. Raising a global cap would not solve history authentication, recovery, archive size, or reorg correctness. This candidate adds a separate checkpoint-rooted replay entrypoint that treats a trusted PCP4/PFM5 checkpoint as the base of a bounded retained branch graph.

## Behavior implemented

- `PrivateTestnetChain::restore_pfm5_checkpoint_baseline_for_replay` verifies the exact PFM5 manifest commitment against a caller-provided external pin, enforces minimum generation and checkpoint-height floors, validates PCP4 against trusted Genesis/network/profile/manifest context, and restores monetary state, cumulative chainwork, consensus tip, and bounded target/timestamp history.
- `PrivateTestnetV4HybridForkChoice::rebuild_from_pfm5_checkpoint` recomputes each supplied PMT4 envelope's PoW digest, requires exact equality with the sorted PFM5 branch set, checks count/individual-envelope/aggregate-byte ceilings, and replays entries parent-first using cumulative-work fork choice.
- The replayed canonical height and digest must exactly match PFM5 before the fork-choice object is returned. A branch digest inventory alone is never accepted as ancestry proof.
- The previous 1,024 ceiling is now explicitly a maximum *reorgable branch depth from the trusted base*, not a lifetime logical-height ceiling. The retained graph remains capped at 4,096 envelopes and 64 MiB of aggregate envelope bytes. PFM4 Genesis-rooted callers retain the same 1,024-block branch-depth behavior.
- Reorgs below the authenticated checkpoint are not considered. The checkpoint is a trusted pruning/finality boundary; protocol governance must define who can authorize that boundary and how independent anti-rollback trust prevents a stale checkpoint from being selected.

## Boundary regression

The focused test constructs and replays a full 2,016-block candidate chain, encodes a non-Genesis PCP4 checkpoint with all 2,016 target/timestamp records, then replays two competing valid PMT4 blocks at height 2,017 from that checkpoint. It asserts exact retarget target agreement, deterministic sibling selection, cumulative-chainwork continuation, and fail-closed rejection when one retained envelope is missing.

The test uses a deliberately low-cost but structurally valid Argon2id profile confined to the test helper; it does not alter candidate/production defaults. Run from `src/native/pow_bench`:

```text
cargo test --locked --offline --lib pfm5_checkpoint_replay_crosses_default_retarget_and_reconciles_sibling_forks -- --nocapture
```

## Still not a gate closure

This code remains a candidate API and is not connected to the PFM4 durable-store commit protocol, a PFM5 durable branch store, node startup, checkpoint publication/rotation, the live `devnet_node`, or real external HTTPS CAS. The test builds its checkpoint directly in-process; it does not demonstrate independent-host operation, signed external checkpoint authorization, VM/disk restore resistance, or physical power-loss durability. The default first-halving height (4,204,800) needs repeated checkpoint publication/restore/reorg tests across multiple generations before Gate 2 can pass.

Gate 2 and Gate 8 remain OPEN. This does not claim Mainnet readiness, public mining, listing, liquidity, an independent audit, or revenue.
