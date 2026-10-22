# CP-0386 - PFM5 Checkpoint Manifest Codec Candidate

Date: 2026-10-22
Base: `fe2ea145e7ca1bfd649c7731099fd72e133837da` (main after v1.7 manifest PR #54).
Scope: standalone canonical PFM5 v1 manifest encoder/decoder and a checkpoint-metadata binding method for the PCP4 candidate record. This PR does not add durable storage or connect checkpoint manifests to PFM4 runtime behaviour.

## Record contract

- `PFM5` magic, version 1, zero reserved flags, big-endian fixed-width fields, declared total byte length, bounded sorted branch-digest set and a domain-separated checksum.
- Records bind network, configured consensus-profile fingerprint and Genesis fingerprint to a PCP4 checkpoint commitment, serialized checkpoint length, checkpoint height/tip/root, total mined atoms, cumulative chainwork, canonical tip and branch-digest set.
- Generation 1 must have a zero parent-manifest commitment; later generations must name a nonzero parent commitment. This is a structural lineage rule, not a trusted monotonic high-water mark.
- `validate_checkpoint` compares the manifest metadata with a PCP4 record encoded and committed under the caller-supplied network, trusted Genesis, profile and active transaction-manifest context.
- The branch digest list must be sorted and unique before any binary-search membership test. Count and serialized-size ceilings are checked before allocating the branch vector.
- PFM5 checksum and content commitment have separate domain strings.

## Test and vector evidence

- Five focused Rust tests pass: Genesis manifest encode/decode and PCP4 binding; canonical-tip listing plus generation/parent linkage; truncation/trailing data/version/flags/checksum rejection; branch-set/count limit rejection; and checkpoint root/issuance/record-commitment mismatch rejection.
- `python simulations/verify_cp0386_pfm5_manifest_vector.py` independently re-encodes the deterministic synthetic manifest and reproduces the 412-byte Rust fixture byte-for-byte. It also verifies the PCP4 source fixture checksum, computes the PCP4 checkpoint commitment, then computes and checks the PFM5 checksum and commitment.
- `cargo fmt --all -- --check`: PASS.
- `cargo check --all-targets --locked --offline`: PASS; the checkout emits existing unused/dead-code warnings in unrelated modules.
- A full all-target test run and GitHub Actions validation are required for this candidate before merge. A passing focused suite is not equivalent to an all-target run or independent protocol review.

## Explicit trust boundary

The manifest codec proves canonical byte structure and correspondence of its summary fields to a supplied PCP4 record. It does **not** prove that retained branch digests descend from the checkpoint or that their bodies/PoW/issuance replay to the claimed tip; the digest list is a bounded set, not ancestry proof. It also does not make a locally stored checksum or content commitment resistant to rollback. A future PFM5 store must validate/replay the referenced branches, atomically publish checkpoint plus manifest, preserve crash/reorg semantics, and use an independently provisioned monotonic high-water or signed external anchor before it treats generations as trusted.

This candidate is not wired into the PFM4 store, node startup, canonical fork choice, or reorg. It does not implement an external CAS service, independent receipt-signer trust, anti-rollback storage, or operational recovery.

- **Gate 2: OPEN.** Integrated checkpoint-aware durable storage/replay/fork choice/reorg, authenticated ancestry and cumulative-work validation, retarget history continuity and reachability, independent target/issuance vectors, frozen production Genesis/profile and independent review remain outstanding.
- **Gate 8: OPEN.** Production CAS, separate pinned receipt trust, monotonically retained rollback protection, and multi-host power-loss/race/restore qualification remain outstanding.
- **No Mainnet/production launch is claimed.** The PFM4 candidate height ceiling remains 1,024 while the default retarget is at 2,017 and the first halving at 4,204,800; this manifest codec does not change those limits.
- **Owner-funded spend: USD 0.** No third-party production infra or liquidity funding is claimed.