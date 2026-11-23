# PACKAGE-METADATA â€” QFP6 CP-0848 Public Alpha Operator Candidate

Package scope: ZERO_VALUE_PUBLIC_TESTNET_CANDIDATE_ONLY
Package date: 2026-11-23
Platform: Windows x64 / PowerShell 5.1+
Release class: experimental review candidate; not a signed production installer.

## Node roles

- Default outbound-only client: loopback listener, pinned outbound Seed connection, signed Q6PD record pull/gossip, and verified candidate auto-dial. No TPM, public IP, port-forward, firewall change or public endpoint is required. No self-announcement is made.
- Optional public relay: public wildcard listener and signed Q6PD self-announcement. Requires a globally reachable endpoint verified from another network plus a TPM Device Root, Ed25519 Q6PD identity and binding to the local Noise key.

## Binary and package integrity

- Node executable: CP-0843 candidate, SHA-256 519e695aed1a0b68195f841c167c06e4fe23176eb50cd96476a34113233c0470.
- The launcher pins the same digest that verify-package.ps1 checks.
- The exact packaged digest identifies this binary; it is not by itself a publisher signature or proof of whole-file source reproducibility.
- The associated CP-0843 source-review branch and CP-0847 history-sync correction are under review. Whole-file reproducibility and independent security audit are not claimed.
- SHA256SUMS.txt is an integrity manifest, not a publisher digital signature.

## Network identity

- Seed endpoint/SNI: heymed.tail2a756d.ts.net:443
- Noise static public-key pin: 9899d6d17d1659df8befcca2bf3ebe19ebe106a8c3d9bd0a4f06d141db3af508
- Bootstrap peer-file SHA-256: 2305ca15acda495960f1e84f4f3f2a7d5b20e279a58953bbc6328e9b16b15e07
- Network ID: 633b5dfc16fb2ec1825baf924ae7f7f16bf2006f8b64441a57692a3531722712
- Profile ID: a0a057d72c11253386bfe90d428bccbc44ebc86fc84e04e3682193a99d8805c4

The bootstrap list contains one Seed identity. Multiple DNS routes to that hostname are not multiple independent peers.

## Identity lifecycle

All operators create a unique local Noise key protected by Windows CurrentUser DPAPI. Outbound-only clients do not self-announce and omit Device Root/Q6PD public identity binding paths. Public relays additionally create or verify a non-exportable TPM 2.0 Device Root, Ed25519 Q6PD identity, and TPM binding over the local Noise key and network/profile.

No owner private key, Seed private key, TPM private material, local runtime state or generated node config is packaged.

## Security and qualification limits

- Current inbound P2P transport is anonymous Noise XX over classical X25519 until Q6PD application checks; not mutual transport authentication and not post-quantum.
- Candidate Q6PD records are route hints only. The software verifies signature, network/profile, TTL, sequence and endpoint, then checks the live Noise static key against the signed pin before dialing. Auto-trust remains disabled.
- Public inbound service is optional and is not exposed by default outbound-only clients.
- No independent multi-host QFP6 mesh, production security audit, Mainnet, real-value transfers, issuance/rewards, exchange listing or market authorization is claimed.
- Per-node peer/session resource bounds are not a global network-node cap.