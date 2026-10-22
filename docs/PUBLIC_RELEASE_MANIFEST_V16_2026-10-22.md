# QuantumZXB Public Release Manifest v1.6

Prepared: 2026-10-22
Validated source tree: `52eea860ad2be244ad883a755277cef8691e2377` (PR #51 merge; includes PR #50)
Release type: implementation and engineering-evidence checkpoint only; limited candidate-code changes, no production consensus-profile activation and no Mainnet release.
Repository: https://github.com/hamidnikkhah660-arch/ai-native-l1
Website: https://hamidnikkhah660-arch.github.io/ai-native-l1/

## What changed from v1.5

Version 1.6 records two merged, test-qualified candidate changes that followed the v1.5 documentation baseline:

- **CP-0381 / PR #50** (`446666d57fe3453ecd4d70eddee0d5c0b75a1984`): the private-testnet driver now has a bounded in-memory target/timestamp-history snapshot and restore model. It tracks logical height separately from retained `VecDeque` offsets, caps the retained history and checks canonical ranges, and validates genesis-prefix target history by replay. It does not implement PCP4 bytes, PFM5, durable checkpoint publication, checkpoint-aware replay/reorg, or independent trust.
- **CP-0382 / PR #51** (`52eea860ad2be244ad883a755277cef8691e2377`): `Uint256::checked_add` and `ConsensusError::ChainworkOverflow` make cumulative work fail closed when a 256-bit sum overflows. The private-testnet driver computes the next total before admission/state mutation, and the synthetic CP-0132 branch exporter no longer silently saturates. This does not authenticate a restored chainwork value.
- The README and this manifest index both changes. `RELEASE_SHA256SUMS.txt` is regenerated from canonical Git-index blob bytes; it is a reproducibility/integrity aid, not a trust or anti-rollback mechanism.

The design document [CP-0380](CP_0380_GATE2_CHECKPOINT_SCHEMA_THREAT_MODEL_2026-10-22.md) remains a proposal, not a runtime schema. **PCP4 canonical encoding, PFM5 persistence integration, and checkpoint trust verification are not implemented by v1.6.**

## Key public evidence files

- `docs/CP_0380_GATE2_CHECKPOINT_SCHEMA_THREAT_MODEL_2026-10-22.md`: proposed PCP4 and PFM5 contract, trust boundary and adversarial criteria.
- `docs/CP_0381_BOUNDED_TARGET_HISTORY_SNAPSHOT_2026-10-22.md`: in-memory target-history snapshot/restore change, local all-target Windows evidence and remaining limits.
- `docs/CP_0382_GATE2_CHAINWORK_OVERFLOW_FAIL_CLOSED_2026-10-22.md`: checked chainwork arithmetic, atomicity regression and unresolved checkpoint/reorg requirements.
- `docs/CP_0379_GATE2_PFM4_BOUNDED_CHECKPOINT_DESIGN_2026-10-22.md`: difference between logical lifetime height and retained-record limits, and the default retarget/halving reachability gap.
- `docs/CP_0373_GATE2_PFM4_RUNTIME_PRODUCTION_BOUNDARY_2026-10-22.md`: candidate runtime boundaries and why loopback tests are not proof of a production node.
- `docs/LIQUIDITY_MARKET_DATA_AND_PUBLIC_LAUNCH_READINESS_V01.md`: market-data, liquidity and public launch prerequisites.
- `docs/OWNER_DIRECTIVE_ZERO_BUDGET_LAUNCH_AND_LIQUIDITY_GATE_V01_2026-10-21.md`: owner instruction that spend from the owner remains USD 0; external spend requires actual third-party support.

## Validation provenance

### PR #50 / CP-0381

- Merge commit: `446666d57fe3453ecd4d70eddee0d5c0b75a1984`.
- GitHub Actions run: https://github.com/hamidnikkhah660-arch/ai-native-l1/actions/runs/39778051416 (format/check/test and Windows PMT4/TXN4 two-node loopback both passed).
- Local Windows run: `cargo test --all-targets --locked --offline -- --test-threads=1` exited 0; 758 library tests passed, and `devnet_node` and `private_testnet_node` each reported 36/36. Remaining binary, integration/vector and example targets completed successfully.
- Focused snapshot tests and `cargo fmt --all -- --check` passed on the rebased branch before merge.

### PR #51 / CP-0382

- Merge commit and validated source tree: `52eea860ad2be244ad883a755277cef8691e2377`.
- GitHub Actions run: https://github.com/hamidnikkhah660-arch/ai-native-l1/actions/runs/39779771542 (format/check/test and Windows PMT4/TXN4 two-node loopback both passed).
- Focused local tests passed for checked 256-bit addition, cumulative chainwork overflow rejection, normal work accumulation and atomic driver rejection at overflow. `cargo check --all-targets --locked --offline` exited 0 with existing unused/dead-code warnings in other modules.
- The Windows GitHub Actions test matrix is the full-suite evidence for PR #51; a separate local full all-target run was not performed after that change.

These checks establish only behavior in the candidate source and test environments. They are not an independent protocol/security audit, formal consensus proof, external implementation conformance result, or production deployment test.

## Current gate and launch status

- **Gate 2: OPEN.** CP-0381 provides bounded in-memory history only; CP-0382 provides checked accumulation only. PCP4 canonical encoding/decoding, PFM5 manifest and durable storage integration, checkpoint-bound archive replay and fork/reorg, independent cross-client target/issuance vectors, frozen production Genesis/profile, and independent protocol/economic review remain outstanding.
- **Reachability remains unresolved.** Current PFM4 candidate limits are 1,024 logical block heights / 4,096 retained records. The default retarget needs height 2,017 and the first halving boundary is 4,204,800. These changes do not raise those limits or prove the boundaries are reachable.
- **Gate 8: OPEN.** There is no independently operated production HTTPS/CAS service with server-side atomic generation compare-and-swap, no separate pinned receipt signer trust and monotonic high-water source, and no qualified multi-host disk-loss, crash, race, restore and rollback operation.
- **Mainnet and public release:** no native QZXB Mainnet, public mining, native exchange listing, genuine market liquidity/volume, or value-bearing production deployment is claimed as live.
- **G0: OPEN.** The live donation campaign, wallet control, actual receipt, payout/conversion route and tax treatment are not independently verified by this manifest. It is not a legal/compliance determination.
- **G1: OPEN.** The engineering offer is public; no signed customer engagement or actual revenue is claimed.
- **Owner-funded spend: USD 0.** No paid infrastructure, independent review or liquidity is claimed. Production costs require real sponsors/customers or explicit third-party credits, not assumed future token revenue.

## Historical v1.5

`PUBLIC_RELEASE_MANIFEST_V15_2026-10-22.md` remains as a dated snapshot of the PR #48 / `1bc6008` documentation baseline. It is not the current code baseline after PR #50 and PR #51. Do not use its historical validation paragraph as evidence for the v1.6 source tree.