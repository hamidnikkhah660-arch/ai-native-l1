# CP-0677 - QFP6 Canonical Manifest-Chain Audit; Out-of-Band Pin Still Required

Date: 2026-11-15
Project: AI-NATIVE L1 / QRun / QZXB / QFP6
Worktree: D:\Temp\ASUS\QRUN_QFP6_CP0596_20261111
Scope: LOCAL SINGLE-OPERATOR LOOPBACK ONLY.
Status: CANONICAL LOCAL AUDIT PASSED; INDEPENDENT PIN NOT YET RECORDED; NODE RESTART BLOCKED.

## 1. Exact QFP6 manifest-anchor algorithm located

The relevant implementation is:
- src/native/pow_bench/src/qrun_v06_pow_fork_store_candidate.rs
- `MANIFEST_COMMITMENT_DOMAIN = b"QRUN-V06-DURABLE-FORK-STORE-COMMITMENT-V1\0"`
- `manifest_commitment(bytes) = SHA-256(MANIFEST_COMMITMENT_DOMAIN || complete_raw_manifest_bytes)`

This is not the ordinary SHA-256 of the file. The ordinary file hash and protocol manifest anchor are different values.

The chain loader validates the Q6FS v1 manifest header, declared length, checksum, generation/index continuity, parent-anchor continuity, stable network/profile/consensus/base identity and manifest entry structure. The checksum uses the separate `QRUN-V06-DURABLE-FORK-STORE-CHECKSUM-V1\0` domain over all bytes preceding the final 32-byte checksum.

Other similarly named anchor functions in PFM3/PFM4/PFM5 or other stores are not interchangeable with this QFP6 store algorithm.

## 2. Read-only local chain audit - passed

Data directory:
`release/qfp6-local-single-operator-devnet-2026-11-15/runtime/after-fix/data`

Read-only audit results:
- Manifest files: 1,025
- Generation range: 0 through 1,024, contiguous
- Latest file: `qfp6-manifest-00000000000000001024.q6mf`
- Latest generation: 1,024
- Latest manifest entries: 1,024
- Referenced branch files: 1,024
- Actual branch entries: 1,024
- Missing/extra/malformed/mismatched branch files: 0
- Manifest-chain, header, length, parent-link, generation, stable-identity, checksum and entry-order problems: 0
- Total audit problems: 0

Every branch referenced by the latest manifest was read and checked as a regular file; its exact byte length and SHA-256 matched the corresponding manifest entry. The branch directory contained exactly the 1,024 referenced entries.

Canonical latest manifest anchor, calculated with the QFP6 protocol domain:
`652ad475a0646e285329d690f493b9b10bf89d44f6ff1cf381c96b7d83ed25b0`

Ordinary SHA-256 of that same latest manifest file (NOT the trusted anchor):
`29e3a69735cf0a1bfdc355b03e96b333868c279e2f0cebd833293e9f7a06401c`

Do not substitute the ordinary SHA-256 for the canonical manifest anchor.

## 3. Independent trust-source reconciliation

A text-file scan of local docs and the local package found no prior occurrence of the exact canonical anchor. The local permissionless config has no `trusted_manifest_anchor` value. The package has no configured Provider/Q6EA/Q6TS/Q6QA external trust source; its Q6PN legacy external-CAS fields are explicitly inert local-only placeholders.

Therefore, the audit proves that the local chain is internally consistent and recovers its canonical tip. It does NOT by itself establish freshness or an independent rollback trust anchor. A hash calculated from the same local files cannot be promoted to independent trust merely by copying it into the config.

The owner must preserve the exact canonical anchor in a separate protected/off-host trust record (for example, a dedicated Google Docs record or another independent protected location) and retain enough provenance to distinguish this record from a value copied out of the local runtime during a later recovery. The one-time QZKW2 confirmation phrase is unrelated to this manifest anchor.

Exact record to preserve:
- Network: local QFP6 candidate (do not imply Public Testnet/Mainnet)
- Manifest file: `qfp6-manifest-00000000000000001024.q6mf`
- Generation: `1024`
- Canonical QFP6 manifest anchor: `652ad475a0646e285329d690f493b9b10bf89d44f6ff1cf381c96b7d83ed25b0`
- Ordinary file SHA-256 (reference only): `29e3a69735cf0a1bfdc355b03e96b333868c279e2f0cebd833293e9f7a06401c`

A Google Docs copy of the old one-time confirmation phrase does not constitute this independent manifest pin. Do not claim that the pin has been stored in Google Docs until the owner confirms that the exact record has been entered there.

## 4. No unsafe state transition performed

- No manifest, branch file, Genesis artifact, Q6GA sidecar or runtime data was changed by this audit.
- `permissionless-config.json` was not modified.
- `local-devnet-manifest.json` was not modified.
- No node process is running.
- No TCP listener is bound to port 30333.
- No public listener, peer, firewall/router change, Public Testnet launch or Mainnet action occurred.

## 5. Controlled next step

After the canonical anchor is stored in an independent protected/off-host record and the owner confirms it:
1. Add exactly this 64-character lowercase hex value to `permissionless_runtime.trusted_manifest_anchor`.
2. Recompute the exact SHA-256 of `permissionless-config.json` and update `local-devnet-manifest.json` using the package's integrity procedure. Do not alter the Genesis/Q6GA signed artifacts or their bound hashes.
3. Recheck all artifact/config/manifest bindings and the local-only scope.
4. Run the Release `--permissionless-run` path with the newly computed config hash.
5. Require the node to compare the externally supplied anchor with its own QFP6 canonical anchor, then replay and validate the full durable history. Record the exact outcome; do not claim startup unless the process and loopback listener are actually observed.

If the external pin is absent or differs, retain the fail-closed refusal. Never delete/recreate the data directory, invent a value, substitute the ordinary file hash, or bypass the anti-rollback gate.

## 6. Relationship to prior checkpoint

CP-0676 records the node-side Q6GA signature verification and the initial missing-anchor refusal. This CP-0677 supersedes only the investigation status: it identifies the exact QFP6 algorithm, passes the local manifest/branch integrity audit, and records the remaining independent-pin requirement. It does not certify successful node startup or Public Testnet readiness.
