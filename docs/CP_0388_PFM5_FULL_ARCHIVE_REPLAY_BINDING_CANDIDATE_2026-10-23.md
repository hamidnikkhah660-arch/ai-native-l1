# CP-0388 ? PFM5 full-archive replay-binding candidate (2026-10-23)

## Scope

This candidate adds a narrowly scoped validator that checks a `Pfm5CheckpointManifest` against a PCP4 record validated under an explicitly supplied trusted Genesis, transaction-manifest identity, and consensus profile, plus a full `PrivateTestnetV4HybridForkChoice` archive already admitted through PMT4 validation/replay APIs.

The validator performs these checks before returning success:

- the PFM5 record passes canonical encoding/shape checks and binds the exact PCP4 encoded length, commitment, network, profile, Genesis fingerprint, monetary root, total mined amount, checkpoint tip, and checkpoint chainwork;
- the checkpoint height is exactly zero, the archive uses the same transaction-manifest ID and Genesis tip, and the replayed archive profile matches the trusted context;
- each archive envelope is decoded and its PoW digest is recomputed under the configured consensus parameters; the sorted set must match the PFM5 `branch_digests` exactly;
- the PFM5 canonical tip height and digest match the tip selected by the replayed cumulative-work fork-choice archive.

Focused local verification passed:

```text
cargo test --locked --offline --lib private_testnet_pfm5_archive_binding_candidate -- --nocapture
3 passed; 0 failed
```

Run that command from `src/native/pow_bench`.

## Deliberate limits

This is a validation primitive, **not** end-to-end PFM5 durable-store integration. The verifier is not yet wired into the PFM4 store's manifest commit point, checkpoint-file durability, node startup, archive import, replay/reorg publication, or external CAS receipt flow. It accepts only a Genesis checkpoint with the complete unpruned archive; a checkpoint above height zero is rejected because a digest set does not prove a retained suffix's ancestry.

The function requires an archive whose branch entries were validated by the PMT4 fork-choice/replay API; the PFM5 branch digest list alone is never considered proof of ancestry. The generation field, parent-manifest commitment and local checksums do not independently prevent rollback. A separately pinned, authenticated monotonic trust source and qualified compare-and-swap/recovery path remain required.

This work does not close Gate 2 or Gate 8. It does not establish production readiness, a public Mainnet, mining availability, listing/liquidity, external funding, or revenue. Those claims require separate live evidence and independent qualification.
