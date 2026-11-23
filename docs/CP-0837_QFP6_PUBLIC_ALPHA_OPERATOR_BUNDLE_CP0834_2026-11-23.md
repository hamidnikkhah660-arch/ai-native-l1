# CP-0837 — QFP6 CP-0834 Public Alpha Operator Bundle

Date: 2026-11-23
Scope: ZERO_VALUE_PUBLIC_TESTNET_CANDIDATE_ONLY
Status: local Windows x64 operator bundle built and statically verified; external-host execution not yet recorded.

## Exact package artifact

- Local ZIP: `D:\QJ6\QFP6_PUBLIC_ALPHA_NODE_CP0834_20261123.zip`
- ZIP size: 57,173,664 bytes
- ZIP SHA-256: `5e4808765d4e5714b3446389e6cb5db0810d0273904a223622d335f7ce537d0c`
- Sidecar: `QFP6_PUBLIC_ALPHA_NODE_CP0834_20261123.zip.sha256`
- ZIP entry count reported by bsdtar: 22,652 (includes directory entries)
- Package `SHA256SUMS.txt`: 22,637 file entries; SHA-256 `f80c7eaa2d3f10c98377fb2b54996864fb41b1dae03cbfbb341955dbf55e02ba`
- Package default verifier: PASS; package coverage count 22,637.
- PowerShell parser: PASS for verify, preflight, setup, start, and local TPM root scripts.
- JSON parse: PASS for config template, bootstrap peer list, and manifest.

## Included runtime/identity components

- CP-0834 QFP6 node binary SHA-256: `c457ce91773d5b6e5fe5b4f392556f05d4f5a647314ffcb35541cb7c5fcc5e14`
- Windows DPAPI Noise key provisioner SHA-256: `379b85301a607e0894d57b617d1bfaec156142adc44371ba5f411f6cc2fd57b1`
- TPM-to-Noise binding utility SHA-256: `739fefa8870f3667062aa24b0ee52540bbc2606ab1b1f56683399cfa8e46ce3b`
- TPM-bound Q6PD Ed25519 identity provisioner SHA-256: `36d9a709247a5bc64a06c1ea861716c45cc969fb1c6587f2c3401b97f776d58a`
- Device Root initializer SHA-256: `197e75bc75ea45f38dcc76a6d4f38a422d31d2b0295eca98d00d450103eef9ea`

For each joining host, the scripts locally create a CurrentUser-DPAPI protected Noise key, a non-exportable TPM Device Root or verify the existing local one, a separate CurrentUser-DPAPI Ed25519 Q6PD identity, and TPM bindings to the exact Noise/network/profile. No per-node private key, DPAPI file, TPM metadata, owner Vault, or live Seed store is included in the ZIP.

## Bootstrap/network identity

- Seed: `heymed.tail2a756d.ts.net:443`
- TLS SNI: `heymed.tail2a756d.ts.net`
- Noise static-key pin: `9899d6d17d1659df8befcca2bf3ebe19ebe106a8c3d9bd0a4f06d141db3af508`
- Bootstrap peer-file SHA-256: `2305ca15acda495960f1e84f4f3f2a7d5b20e279a58953bbc6328e9b16b15e07`
- Network ID: `633b5dfc16fb2ec1825baf924ae7f7f16bf2006f8b64441a57692a3531722712`
- Profile ID: `a0a057d72c11253386bfe90d428bccbc44ebc86fc84e04e3682193a99d8805c4`

The config enables signed Q6PD discovery, pull, and self-announcement, requires the local TPM/Noise and Ed25519 identity bindings, and keeps candidate auto-trust disabled. Public announcements require an operator-supplied numeric globally routable endpoint. Hosts behind NAT may dial outbound but must not advertise private/unreachable endpoints as relay destinations.

## Baseline/state payload

- Anchor baseline contains 20,501 hash-chain records; not the owner's live Seed Vault and contains no signing keys.
- Checkpoint segment bundle contains 2,096 files; Segment 20 base checkpoint SHA-256 is `53440ca17dea342ef5af1adf73539452162fe4c3a452b203b1e4f5eed51ba296`.
- Bootstrap file has one Seed identity only; DNS routes do not count as separate peers.

## Safety/qualification boundary

- Installer setup does not start the node, open firewall/router/NAT ports, create a tunnel, Windows service, or scheduled task.
- `start-node.ps1` requires two explicit acknowledgements for the zero-value candidate and anonymous inbound Noise XX.
- Inbound Noise XX is anonymous before Q6PD application checks. Transport uses classical X25519 and is not post-quantum.
- This package is not code-signed, independently audited, or reproducible from the public branch head alone (local source worktree had 103 dirty entries at build time).
- This laptop's local Root/Backup/Joiner are not independent hosts. No external operator identity has yet been received, and no real multi-host mesh is claimed.
- Mainnet, real-value transfers, issuance/rewards, and market activity are not authorized.

## Public review

- Bootstrap PR: https://github.com/hamidnikkhah660-arch/ai-native-l1/pull/205
- Operator intake: https://github.com/hamidnikkhah660-arch/ai-native-l1/issues/204
- A GitHub Draft Release exists and its `.sha256` sidecar is uploaded. The 57 MB ZIP asset upload did not complete and is **not attached** to the Release; the verified ZIP remains local at the path above. Do not treat the Release page as a package download. No public binary download/release is claimed until upload, review, and a separate publication authorization are complete.