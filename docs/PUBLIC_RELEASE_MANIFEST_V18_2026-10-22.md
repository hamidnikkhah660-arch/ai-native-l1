# QuantumZXB Public Release Manifest v1.8

Prepared: 2026-10-22
Validated public source tree: `451555f88cd03f05f2090e4df43213cc8d35e6a3` (PR #55 merge)
Previous manifest: [v1.7](PUBLIC_RELEASE_MANIFEST_V17_2026-10-22.md)
Release type: candidate checkpoint-manifest engineering evidence only. No production consensus-profile activation, Mainnet launch, public mining, or value-bearing deployment is claimed.
Repository: https://github.com/hamidnikkhah660-arch/ai-native-l1
Website: https://hamidnikkhah660-arch.github.io/ai-native-l1/

## Changes since v1.7

### CP-0386 / PR #55: PFM5 manifest codec candidate

- Merge commit: `451555f88cd03f05f2090e4df43213cc8d35e6a3`; tested PR head: `87f376e17dd15649c03a4c90c1bafd2b6894f4b4`.
- Adds a standalone PFM5 v1 canonical encoder/decoder, bounded sorted branch-digest set, PCP4 metadata binding, generation/parent-link structural rules, and distinct checksum/content-commitment domains.
- Five focused Rust tests pass; `python simulations/verify_cp0386_pfm5_manifest_vector.py` independently reproduces the 412-byte golden manifest and verifies the PCP4 reference commitment plus PFM5 checksum/commitment.
- GitHub Actions run `39821573441` passed both required jobs before merge. The Linux all-target job reported 769/769 library tests, `devnet_node` 36/36, and `private_testnet_node` 36/36. Windows PMT4/TXN4 two-node loopback passed in 3m38s.
- Local `cargo check --all-targets --locked --offline` passed; existing unused/dead-code warnings remain in unrelated modules.

The updated [CP-0386 report](CP_0386_PFM5_CHECKPOINT_MANIFEST_CODEC_CANDIDATE_2026-10-22.md) explains the codec and its trust boundary. PFM5 remains **candidate-only**: it is not wired into PFM4 or node startup and does not publish durable checkpoints, replay/authenticate ancestry, implement fork choice/reorg, deploy CAS, or provide anti-rollback protection. A sorted set of branch digests is not ancestry proof.

### CP-0384 / PR #53: PCP4 record codec candidate

- Merge commit: `663de9c176947cfb76dde18854f0a582a495173f`.
- The canonical PCP4 v1 codec binds records to caller-supplied network, trusted Genesis, configured profile and active transaction-manifest context, with bounded target history and snapshot-metadata consistency checks.
- Six focused Rust tests and `python simulations/verify_cp0384_pcp4_golden_vector.py` pass; the independent PCP4 golden record is 737 bytes.
- GitHub Actions run `39813210390` passed before merge. Linux all-target validation reported 764/764 library tests, `private_testnet_node` 36/36, and the Windows PMT4/TXN4 two-node loopback passed.
- The reported local Windows all-target run (766 library tests) predates the sixth, non-Genesis focused test and is historical; the final-head CI evidence above includes that test. Counts vary across OS/`cfg`-gated targets.

## Security and trust boundary

Canonical encodings, checksums and content commitments detect mismatch/corruption; they do not independently authorize checkpoints, prove pruned ancestry or establish rollback-resistant freshness. Non-Genesis PCP4 chainwork/parent fields receive candidate shape checks only; PFM5's digest set likewise does not establish ancestry. A safe restore still needs authenticated ancestry or an independent authorization/freshness trust path, and durable publication must preserve crash consistency, canonical fork choice and reorg semantics.

## Gate and public-launch status

- **Gate 2: OPEN.** Integrated durable PCP4/PFM5 checkpoint storage; crash-safe publication; checkpoint-aware replay, fork choice and reorg; authenticated pruned ancestry and cumulative work; retarget-history continuity and reachable retarget/halving boundaries; independent target/issuance vectors; frozen production Genesis/profile; and independent protocol/economic review remain outstanding.
- **Reachability remains unresolved.** Candidate PFM4 still caps logical height at 1,024 and retained archive records at 4,096. Default first retarget height is 2,017; first halving is 4,204,800. These codec changes do not alter those limits.
- **Gate 8: OPEN.** Independently operated production HTTPS/CAS with atomic generation compare-and-swap, separately pinned receipt-signer trust, monotonic high-water/anti-rollback protection, and multi-host crash/race/restore qualification remain outstanding.
- **Mainnet/public launch:** no native QZXB Mainnet, public mining, native listing, genuine market liquidity/volume or value-bearing production deployment is claimed as live. Sepolia test assets are not native QZXB.
- **G0: OPEN in the gate ledger.** The owner states legal/regulatory obstacles have been resolved; this manifest does not issue an independent legal opinion. The live support campaign, wallet authority, receipt/payout/conversion route and tax treatment have not been independently verified here.
- **G1: OPEN.** The public engineering offer exists; no signed customer engagement or actual revenue is claimed.
- **Owner-funded spend: USD 0.** No paid production infrastructure, independent review or liquidity is claimed. Production costs require real sponsors/customers or explicit third-party credits, not assumed future token revenue.

## Historical v1.7

`PUBLIC_RELEASE_MANIFEST_V17_2026-10-22.md` is preserved as the source-evidence snapshot after PR #53 and before PR #55. Do not use it as the current baseline after PFM5 candidate source changes merged.