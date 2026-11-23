# PACKAGE-METADATA — QFP6 CP-0834 Public Alpha Operator Candidate

**Package scope:** ZERO_VALUE_PUBLIC_TESTNET_CANDIDATE_ONLY  
**Build date:** 2026-11-23  
**Platform package:** Windows x64 / PowerShell 5.1+ / TPM 2.0  
**Release class:** Experimental candidate; not a signed production installer.

## Source and build provenance

- Repository: `hamidnikkhah660-arch/ai-native-l1`
- Local source branch: `feat/qfp6-p2p-liveness-discovery-20261121`
- Local source HEAD at build time: `e73cfa4079da56b4f309ff61bb6318cbbeb37749`
- Source worktree was intentionally dirty and contained uncommitted/untracked CP-0801 through CP-0835 work. Do **not** infer that the public branch HEAD alone reproduces these binaries.
- Cargo build used `--locked --offline`, Windows local toolchain, `-j 1`.
- Node executable: CP-0834 DNS seed failover candidate, SHA-256 `c457ce91773d5b6e5fe5b4f392556f05d4f5a647314ffcb35541cb7c5fcc5e14`.
- Noise key provisioner: SHA-256 `379b85301a607e0894d57b617d1bfaec156142adc44371ba5f411f6cc2fd57b1`.
- TPM-to-Noise binding utility: SHA-256 `739fefa8870f3667062aa24b0ee52540bbc2606ab1b1f56683399cfa8e46ce3b`.
- Q6PD Ed25519 identity/TPM binding provisioner: SHA-256 `36d9a709247a5bc64a06c1ea861716c45cc969fb1c6587f2c3401b97f776d58a`.
- TPM Device Root initializer: SHA-256 `197e75bc75ea45f38dcc76a6d4f38a422d31d2b0295eca98d00d450103eef9ea`.

These file digests identify the exact packaged artifacts; they are not a cryptographic publisher signature or reproducible-build attestation.

## Network pin

- Seed endpoint: `heymed.tail2a756d.ts.net:443`
- TLS SNI: `heymed.tail2a756d.ts.net`
- Noise static public key: `9899d6d17d1659df8befcca2bf3ebe19ebe106a8c3d9bd0a4f06d141db3af508`
- Published bootstrap peer file SHA-256: `2305ca15acda495960f1e84f4f3f2a7d5b20e279a58953bbc6328e9b16b15e07`
- Network ID: `633b5dfc16fb2ec1825baf924ae7f7f16bf2006f8b64441a57692a3531722712`
- Profile ID: `a0a057d72c11253386bfe90d428bccbc44ebc86fc84e04e3682193a99d8805c4`

DNS is transport routing only. The exact Noise key pin remains the Seed identity anchor. Candidate records are accepted only after Q6PD signature/network/profile/expiry/sequence/replay validation; dialling then verifies the live Noise static key against the signed record. Discovered peers are not auto-trusted.

## Included state baseline

- Anchor Vault bootstrap chain: 20,501 records. This is a hash-chained bootstrap state baseline only, not the owner's live Seed Vault, not a key store, and not a separately administered monotonic trust service.
- Checkpoint segment data: 2,096 files across the supplied segment folders; includes the hash-pinned Segment 20 base checkpoint (SHA-256 `53440ca17dea342ef5af1adf73539452162fe4c3a452b203b1e4f5eed51ba296`).
- Public Genesis snapshot, consensus profile, Genesis descriptor, Q6PN profile pin, and zero-value Q6GA authorization are individually SHA-256 checked.
- Bootstrap peer list contains one Seed identity. Multiple DNS A/AAAA routes are not multiple independent peers.

## Per-operator identity lifecycle

On a joining Windows host, `setup-node.ps1` generates or verifies that host's own:
1. Noise XX static key, saved under CurrentUser DPAPI;
2. non-exportable TPM 2.0 Device Root (Microsoft Platform Crypto Provider);
3. Ed25519 Q6PD peer-node identity, separately protected with CurrentUser DPAPI;
4. TPM-signed binding of the peer-node identity and exact Noise key to the device/network/profile.

No per-node secret, TPM metadata, DPAPI key, generated runtime config, or owner private key is included in this package. Local generated keys are not portable backups. TPM clear/motherboard replacement requires explicit reenrollment; no silent identity replacement is allowed.

The installer requires an operator-supplied numeric globally-routable endpoint and explicit acknowledgement that it is reachable from a separate network. A node behind NAT may connect outbound, but must not publish an unreachable private address as a relay endpoint. No firewall, router, NAT mapping, tunnel, service, or scheduled task is configured by these scripts.

## Operational security limits

- The runtime listens on `0.0.0.0:<port>` when started, exposing a service on all local interfaces.
- Current inbound transport is Noise XX over classical X25519. Incoming Noise XX is anonymous/unauthenticated before application-layer Q6PD verification; the package does not claim mutual authenticated inbound transport.
- P2P transport is not post-quantum.
- No independent-host execution has been performed from this package; this laptop's Seeds/Joiner are not counted as external operators.
- Package verification and PowerShell parsing are local static checks, not an independent security audit.
- The node is not auto-started and no public listener is enabled during setup. `start-node.ps1` requires explicit zero-value and inbound-Noise acknowledgements.
- Mainnet, real-value transfers, issuance/rewards, and market/trading activity are not authorized.

## Verification

Run `verify-package.ps1` after extraction. The default mode checks exact binary and trust-artifact hashes, exact Seed pin/digest, NetworkId/ProfileId binding, no auto-trust/Mainnet/market flag, Anchor Vault record count, checkpoint base hash, absence of private/local key artifacts, and complete SHA256SUMS file coverage. Use `verify-package.ps1 -FullIntegrity` to recompute the hash of every listed file; this takes longer because the package contains more than 22,000 small baseline files.

`SHA256SUMS.txt` lists every package file except itself. It is an integrity checksum list, not a digital signature. Obtain the ZIP hash via the separately distributed `.sha256` sidecar and compare it to the publisher's separately communicated value.

Independent operator intake: https://github.com/hamidnikkhah660-arch/ai-native-l1/issues/204