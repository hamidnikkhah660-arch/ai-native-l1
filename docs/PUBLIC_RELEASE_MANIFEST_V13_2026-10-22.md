# QuantumZXB Public Documentation Release Manifest v1.3

Prepared: 2026-10-22
Release type: current public documentation and validation-provenance index; no production consensus/runtime/economic profile is changed.
Repository: https://github.com/hamidnikkhah660-arch/ai-native-l1
Website: https://hamidnikkhah660-arch.github.io/ai-native-l1/

## Public baseline

This manifest supersedes v1.2 as the current curated public-documentation index; v1.2 remains a dated historical snapshot. Version 1.3 clarifies CP-0378 validation provenance: the 756-test, 553.93-second result is the separately recorded local Windows run, while GitHub Actions on Ubuntu recorded 753 library tests on the code baseline and on the later documentation-only main commit. The candidate retarget behavior and the unresolved retarget-window versus branch-height-cap incompatibility remain unchanged. No protocol or economic runtime behavior is changed by this release.

Key files:

- `README.md` and `index.html`: public project overview, candidate halving chart/data, fixed-scope engineering offer, G0 compliance and donation/payout disclosures, runtime limits, and explicit non-launch status.
- `docs/ENGINEERING_SERVICE_OFFER_V01.md`: bounded Rust/protocol reproducibility or AI/ML feasibility engagement with deliverables and acceptance conditions. No customer, signed engagement, payment or revenue is claimed.
- `docs/CP_0372_G0_PUBLIC_LAUNCH_COMPLIANCE_CHECKLIST_2026-10-22.md`: source-linked AFM/MiCAR, donation status, owner-wallet and payout checks; not legal advice or a compliance determination.
- `docs/CP_0373_GATE2_PFM4_RUNTIME_PRODUCTION_BOUNDARY_2026-10-22.md`: source-verified runtime boundary and why current PMT4/PFM4 smoke tests are not a production node.
- `docs/CP_0374_GATE2_PFM4_INVALID_POW_ATOMICITY_2026-10-22.md`: PFM4 rejection of insufficient-work candidates without durable mutation and Windows stale-cursor test-harness fix.
- `docs/CP_0375_GATE2_PFM4_INVALID_REWARD_ATOMICITY_2026-10-22.md`: valid-PoW block with an overstated subsidy is rejected without changing branch/archive/manifest/tip.
- `docs/CP_0376_GATE2_PFM4_EXPECTED_TARGET_ATOMICITY_2026-10-22.md`: a peer-selected easier target, even with a digest that meets that easier target, is rejected without durable state mutation.
- `docs/CP_0377_GATE2_PFM4_ARCHIVE_REPLAY_TARGET_BINDING_2026-10-22.md`: fork-choice archive reconstruction rejects a block whose PoW meets a peer-forged easier target but not the expected chain target.
- `docs/CP_0378_GATE2_BRANCH_DERIVED_RETARGET_2026-10-22.md`: candidate retarget timing is derived from accepted branch timestamps, caller overrides must match, and target-history validation runs before state mutation. It also records that production retarget/window/resource parameters remain unfrozen.
- `docs/CP_0349_REPRODUCIBLE_CANDIDATE_HALVING_VISUALIZATION_2026-10-21.md`, `simulations/candidate_halving_curve.py` and `simulations/candidate_halving_curve.csv`: reproducible integer-only candidate emission chart/data.
- `docs/MINING_HALVING_PERFORMANCE_AND_SCALING_V01.md`: candidate mining parameters, benchmark methodology and constraints.
- `docs/LIQUIDITY_MARKET_DATA_AND_PUBLIC_LAUNCH_READINESS_V01.md`: real-market, market-data and cash-flow prerequisites.
- `docs/QUANTUMZXB_NATIVE_COIN_WHITEPAPER_V02.md` and `docs/QUANTUMZXB_MASTER_ROADMAP_V02.md`: project concept and proposed engineering roadmap, not proof of deployed future functionality.

## Candidate halving arithmetic

The chart generator uses integer atomic units and models 36 eras. Inputs include initial subsidy of 35,673,515,981 atoms, 4,204,800 blocks per halving, eight decimals, and a 30-second target-time equivalent. Modelled total mining subsidy is 299,999,999,913,926,400 atoms (2,999,999,999.139264 coins), leaving 86,073,600 atoms (0.860736 coins) unused from the 3B mining/security allocation envelope due to integer halving. The remainder is not topped up.

This is candidate arithmetic only. The 30-second interval is a target, not observed cadence; it does not prove issued or mined supply, miner profitability, price, liquidity or investment returns. Gate 2 remains OPEN until the production monetary profile and canonical runtime path are frozen, integrated and independently reviewed.

## Runtime and launch status

- Native QZXB Mainnet and a liquid native-coin market have not launched.
- The default `devnet_node` profile is zero-value PTB2/PFS2. The PMT4/PFM4 peer smoke is loopback-only and deliberately uses `Uint256::MAX` target and 8 MiB Argon2 for fast integration testing. These are not production mining settings.
- The legacy `chain_import_node` still uses BLK2/`LedgerState`. The separate MCS4 linear importer proposal remains Draft because its raw-body API does not enforce that header/PoW verification and canonical fork-choice happened first.
- **Retarget reachability gap:** the candidate profile uses `difficulty_window_blocks = 2,016`, so the first retarget applies for block height 2,017; the PMT4 fork-choice candidate caps branch height at 1,024. Therefore the current archive-backed candidate path cannot reach its first default retarget boundary. The CP-0378 end-to-end archive/replay test uses a test-only 32-block window to respect that cap, while a separate TargetHistory arithmetic test covers the default 2,016-block boundary. Gate 2 stays OPEN until the reviewed production profile reconciles retarget window, maximum branch height, archive block/byte budgets and replay resource ceilings. Do not silently weaken the cap or claim Mainnet readiness.
- Gate 2 is **OPEN**: a frozen production network/Genesis/fee/reward/retarget/migration/trust profile, canonical production submit/import/reorg/snapshot path, independent cross-client vectors and independent protocol/economic review remain outstanding.
- Gate 8 is **OPEN**: the repository contains external-CAS protocol/client contracts and in-memory test fixtures, not a deployed HTTPS/cloud transport or independent provider. Server-side atomic generation CAS, an out-of-band pinned receipt-signing key, separate trust domain and whole-disk anti-rollback qualification remain outstanding.
- G0 is **OPEN**: the current Giveth campaign status, wallet control, actual donation receipt, payout/conversion route and tax treatment are not independently verified by this repository. Check the live project page directly.
- G1 is **OPEN**: a fixed-scope engineering offer is public, but no client engagement, signed contract or paid milestone is claimed.
- Brand and market-data gate remains **OPEN**: no trademark clearance, native trading pair, tracked exchange volume, listing or market-data symbol is claimed.

This document is not legal advice, a security audit, Mainnet approval, a MiCAR compliance determination, or an offer to sell an investment.

## Validation provenance

**CP-0378 local Windows validation (as recorded in the checkpoint):** `cargo fmt --all -- --check` and `cargo check --all-targets --locked --offline` passed. The local Windows `cargo test --all-targets --locked --offline -- --test-threads=1` run recorded 756 library tests passed, zero failed/ignored, `devnet_node` 36/36 and `private_testnet_node` 36/36; all remaining binary, example and integration-vector targets passed, exit code 0 in 553.93 seconds. These are local-host results, not the GitHub Actions Linux test count.

**GitHub Actions on code baseline `4e800b63e57757bb8523317d62d6a904f69c2c95` (PR #45 merge):** Rust validation run https://github.com/hamidnikkhah660-arch/ai-native-l1/actions/runs/39753706387 completed successfully. The Ubuntu `Test every target` log reports 753 library tests passed, zero failed/ignored, in 361.77 seconds. Its Windows PMT4/TXN4 two-node integration job also passed. Pages run https://github.com/hamidnikkhah660-arch/ai-native-l1/actions/runs/39753705913 completed successfully.

**Latest validated main snapshot before this documentation correction:** `4ad68e8f8edbea2ca32bfde9f77c66c64b1e84db` (PR #46, documentation-only relative to the above code baseline). Rust validation run https://github.com/hamidnikkhah660-arch/ai-native-l1/actions/runs/39758520511 completed successfully; the Ubuntu test log reports 753 library tests passed, zero failed/ignored, in 360.92 seconds, and the Windows PMT4/TXN4 two-node job passed. Pages build and deployment run https://github.com/hamidnikkhah660-arch/ai-native-l1/actions/runs/39758519746 completed successfully.

The two reported library-test counts are preserved with their correct execution environments. CI success and local tests qualify only the candidate implementation and configured test targets; they are not an independent security audit, a production consensus specification, or Mainnet approval. Public documentation preflight and release checksums are rerun for this v1.3 change; prior CP-0378 preflight counts are historical and are not claimed as the v1.3 output.

`RELEASE_SHA256SUMS.txt` is regenerated from canonical Git-index blob bytes and excludes its own hash.
