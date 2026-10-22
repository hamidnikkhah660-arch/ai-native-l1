# CP-0389 ? externally anchored PFM5 checkpoint-baseline restore (2026-10-23)

## Scope

This candidate adds a fail-closed restore primitive for a canonical PFM5 manifest and its PCP4 checkpoint. It requires the exact PFM5 commitment to be supplied by a caller from an independently protected trust source, and it enforces caller-supplied monotonic lower bounds for manifest generation and checkpoint height. It validates PFM5/PCP4 binding against the trusted Genesis, network, selected consensus profile and transaction-manifest identity, decodes the monetary snapshot, restores the checkpoint's bounded target/timestamp history, and seeds cumulative work and the consensus tip from the anchored checkpoint record.

The primitive deliberately refuses manifests that name any post-checkpoint branch digests or whose canonical tip is above the checkpoint. Those envelopes must be loaded and consensus-replayed before canonical-tip selection; a digest inventory is not ancestry proof.

## Focused validation

Added tests verify baseline restore and exact tip/work/history recovery, missing or mismatched external anchor rejection, generation-floor rollback rejection, height-floor rollback rejection, and refusal to treat post-checkpoint branches as replayed state. Run from `src/native/pow_bench`:

```text
cargo test --locked --offline --lib pfm5_checkpoint_restore -- --nocapture
```

## Limits

This is a primitive, not complete PFM5 store migration. No current PFM4 manifest commit path, node startup, branch archive loading, reorg transition, external HTTPS CAS provider or separately pinned signer is changed by this candidate. The caller must protect the anchor and monotonic floors outside the node's rollback domain and authenticate the anchor source. A local checksum, caller-supplied untrusted hash, or a local high-water file restored with the node disk is not independent anti-rollback protection.

Gate 2 and Gate 8 remain open. No Mainnet readiness, public mining, liquidity, listing, independent audit or revenue is claimed.
