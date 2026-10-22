# QuantumZXB Public Release Manifest v1.7

Prepared: 2026-10-22
Validated public source tree: `663de9c176947cfb76dde18854f0a582a495173f` (PR #53 merge)
Previous manifest: [v1.6](PUBLIC_RELEASE_MANIFEST_V16_2026-10-22.md)
Release type: candidate checkpoint-codec engineering evidence only. No production consensus-profile activation, Mainnet launch, public mining, or value-bearing production deployment.
Repository: https://github.com/hamidnikkhah660-arch/ai-native-l1
Website: https://hamidnikkhah660-arch.github.io/ai-native-l1/

## What changed from v1.6

PR #53 merged a standalone candidate-only PCP4 v1 record codec, strict decoder, six focused tests, and a cross-language golden-vector checker.

- Source PR head: `f25ff2b5a1dd32dfdbd71743ff251ee45b8cd576`; merge commit: `663de9c176947cfb76dde18854f0a582a495173f`.
- The codec binds the record to a caller-supplied network ID, trusted Genesis snapshot, validated consensus/monetary-profile fingerprint, and active transaction-manifest ID. It cross-checks monetary snapshot metadata, enforces canonical target-history ranges before entry allocation, and uses distinct domain-separation strings for checksum and commitment.
- Six focused Rust PCP4 tests pass, including Genesis and non-Genesis encode/decode, embedded snapshot metadata consistency, invalid byte layouts/checksums, network/profile/manifest/Genesis binding, and rejection of noncanonical history ranges.
- `python simulations/verify_cp0384_pcp4_golden_vector.py` independently encodes the deterministic synthetic fixture and reproduces the 737-byte Rust golden record byte-for-byte.
- The final-head GitHub Actions run `39813210390` passed both required jobs before merge: `Format, check, and test` (Linux; `cargo +stable test --all-targets --locked -- --test-threads=1`, library 764/764, including the non-Genesis PCP4 test, and `private_testnet_node` 36/36) and Windows PMT4/TXN4 two-node loopback. The Windows loopback completed in 3m55s; the Linux validation job completed successfully.
- The Windows local all-target run reported in CP-0384 is historical and predates the sixth focused non-Genesis test; it reported 766 library tests. The final six-test candidate is covered by the successful final-head CI run above. Test counts may differ across operating systems/`cfg`-gated modules.

The new [CP-0384 report](CP_0384_PCP4_CANONICAL_RECORD_CODEC_CANDIDATE_2026-10-22.md) describes the codec contract, test coverage, and trust boundary. PCP4 remains a candidate record codec: it is **not integrated** with PFM4/PFM5 durable storage, node startup, canonical fork choice, or reorg.

## Security and trust boundary

A canonical encoding, checksum, or domain-separated commitment is not a signature, proof of ancestry, proof of cumulative work, or anti-rollback freshness. Non-Genesis records only receive shape checks for parent commitment/work; this codec does not authenticate pruned ancestry, reconstruct it, or independently authorize a checkpoint. It does not add checkpoint receipts, a signer trust domain, a monotonic high-water anchor, durable checkpoint publication, or an external production CAS provider.

## Current gate and launch status

- **Gate 2: OPEN.** Remaining work includes PFM5 integration and crash-safe durable checkpoint storage; integrated checkpoint-aware archive replay, fork choice and reorg; authenticated ancestry and chainwork for restored checkpoints; independent target/issuance boundary vectors; a frozen production Genesis/profile; and independent protocol/economic review.
- **Checkpoint reachability remains unresolved.** The existing candidate PFM4 limits remain 1,024 logical block heights and 4,096 retained archive records. The first default retarget is at height 2,017 and the first halving at 4,204,800. PCP4 does not raise these limits or make those boundaries reachable.
- **Gate 8: OPEN.** A real independently operated production HTTPS/CAS provider with server-side atomic generation compare-and-swap, separately pinned receipt-signer trust, anti-rollback high-water protection, and qualified multi-host disk-loss/crash/race/restore operations remains outstanding.
- **Mainnet/public launch:** no native QZXB Mainnet, public mining, native exchange listing, genuine market liquidity/volume, or value-bearing production deployment is claimed as live. Sepolia test assets are not native QZXB.
- **G0: OPEN in the project gate ledger.** The owner states legal/regulatory obstacles have been resolved; this manifest does not issue an independent legal opinion. The live support campaign, wallet control, actual receipt, payout/conversion route and tax treatment have not been independently verified here.
- **G1: OPEN.** The public engineering offer exists; no signed customer contract or actual revenue is claimed.
- **Owner-funded spend: USD 0.** No paid production hosting, independent review, or liquidity is claimed. Production costs require real sponsors/customers or explicit third-party credits, not assumed future token revenue.

## Historical v1.6

`PUBLIC_RELEASE_MANIFEST_V16_2026-10-22.md` is preserved as the source-evidence snapshot after PR #52 and before PCP4/PR #53. Do not treat it as the current source baseline after PR #53.