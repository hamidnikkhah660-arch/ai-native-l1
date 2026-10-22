# QuantumZXB Public Documentation Release Manifest v1.1

Prepared: 2026-10-22
Release type: current public documentation and test-evidence index; no production consensus/runtime/economic profile is changed.
Repository: https://github.com/hamidnikkhah660-arch/ai-native-l1
Website: https://hamidnikkhah660-arch.github.io/ai-native-l1/

## Public baseline

This manifest supersedes v1.0 as the current curated public-documentation index. The v1.0 manifest remains as a dated historical snapshot. Version 1.1 adds CP-0377, which checks expected-target enforcement during PFM4 archive replay, separately from live store admission, and consolidates the public launch boundaries and candidate mining arithmetic.

Key files:

- `README.md` and `index.html`: public project overview, candidate halving chart/data, fixed-scope engineering offer, G0 compliance and donation/payout disclosures, runtime limits, and explicit non-launch status.
- `docs/ENGINEERING_SERVICE_OFFER_V01.md`: bounded Rust/protocol reproducibility or AI/ML feasibility engagement with deliverables and acceptance conditions. No customer, signed engagement, payment or revenue is claimed.
- `docs/CP_0372_G0_PUBLIC_LAUNCH_COMPLIANCE_CHECKLIST_2026-10-22.md`: source-linked AFM/MiCAR, donation status, owner-wallet and payout checks; not legal advice or a compliance determination.
- `docs/CP_0373_GATE2_PFM4_RUNTIME_PRODUCTION_BOUNDARY_2026-10-22.md`: source-verified runtime boundary and why current PMT4/PFM4 smoke tests are not a production node.
- `docs/CP_0374_GATE2_PFM4_INVALID_POW_ATOMICITY_2026-10-22.md`: PFM4 rejection of insufficient-work candidates without durable mutation and Windows stale-cursor test-harness fix.
- `docs/CP_0375_GATE2_PFM4_INVALID_REWARD_ATOMICITY_2026-10-22.md`: valid-PoW block with an overstated subsidy is rejected without changing branch/archive/manifest/tip.
- `docs/CP_0376_GATE2_PFM4_EXPECTED_TARGET_ATOMICITY_2026-10-22.md`: a peer-selected easier target, even with a digest that meets that easier target, is rejected without durable state mutation.
- `docs/CP_0377_GATE2_PFM4_ARCHIVE_REPLAY_TARGET_BINDING_2026-10-22.md`: fork-choice archive reconstruction rejects a block whose PoW meets a peer-forged easier target but not the expected chain target.
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
- Gate 2 is **OPEN**: a frozen production network/Genesis/fee/reward/retarget/migration/trust profile, canonical production submit/import/reorg/snapshot path, independent cross-client vectors and independent protocol/economic review remain outstanding.
- Gate 8 is **OPEN**: the repository contains external-CAS protocol/client contracts and in-memory test fixtures, not a deployed HTTPS/cloud transport or independent provider. Server-side atomic generation CAS, an out-of-band pinned receipt-signing key, separate trust domain and whole-disk anti-rollback qualification remain outstanding.
- G0 is **OPEN**: the current Giveth campaign status, wallet control, actual donation receipt, payout/conversion route and tax treatment are not independently verified by this repository. Check the live project page directly.
- G1 is **OPEN**: a fixed-scope engineering offer is public, but no client engagement, signed contract or paid milestone is claimed.
- Brand and market-data gate remains **OPEN**: no trademark clearance, native trading pair, tracked exchange volume, listing or market-data symbol is claimed.

This document is not legal advice, a security audit, Mainnet approval, a MiCAR compliance determination, or an offer to sell an investment.

## Validation provenance

Parent `main` baseline `0d773559c93ddc6744e0cdef4aa85481221eb43c` includes the v1.0 release manifest and the live PFM4 expected-target-binding regression. Post-merge Rust validation, Windows PMT4/TXN4 two-node tests and Pages deployment all passed on that exact SHA:

- Rust validation: https://github.com/hamidnikkhah660-arch/ai-native-l1/actions/runs/39736980359
- GitHub Pages: https://github.com/hamidnikkhah660-arch/ai-native-l1/actions/runs/39736980107

The CP-0377 archive-replay target-binding regression passed the focused test and the full locked/offline all-target command on the authorized Windows host: 753 library tests passed with 0 failures/ignored; `devnet_node` passed 36/36; `private_testnet_node` passed 36/36; all remaining binary, example and integration-vector targets passed; command exit 0 in 557.76 seconds. The companion PR's own Rust and Windows CI checks are still required for this exact commit before merge. All of this is candidate-path negative-test evidence, not approval of production difficulty rules.

`RELEASE_SHA256SUMS.txt` is regenerated from canonical Git-index blob bytes and excludes its own hash.

No public listener, production key, native issuance, public value transfer, liquidity operation, paid service, or owner-funded spending is created by this documentation/test release. Owner-funded spend remains USD 0.
