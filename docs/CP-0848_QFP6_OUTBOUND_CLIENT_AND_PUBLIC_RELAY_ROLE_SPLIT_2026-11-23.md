# CP-0848 â€” QFP6 outbound-only client and optional public relay role split

Date: 2026-11-23
Source baseline: CP-0847, commit fffb5b2de40ffbf5db55ee4eaf0587e04709f648
Status: source/package-script review candidate; not a binary release and not a live-network mesh qualification.

## Why this change exists

The CP-0843 Q6PD discovery and signed-record gossip path is already integrated into the current Seed runtime. Live inspection on the single Seed host showed:

- the primary Seed publishes its signed Q6PD self-record and accepts Q6PD gossip pushes;
- the outbound-only local Joiner reaches the Seed using the pinned DNS/SNI + Noise key, completes the Noise session and receives the signed Seed record;
- the Seed and Joiner stores contain the same single Seed identity;
- the scheduler skips dialing when the only eligible candidate is the local Seed identity itself.

That last skip is expected with only one currently known public identity. It is not evidence that peer discovery needs to be rewritten. A node cannot discover a new QFP6 peer identity unless another participant actually runs QFP6 and, to be publicly dialable, advertises a reachable relay endpoint.

## Role policy

### Outbound-only client â€” default

- Q6PD discovery and signed-record pull enabled.
- Q6PD self-announcement disabled.
- Listener bound only to 127.0.0.1.
- Requires only a fresh local Noise static key protected by Windows CurrentUser DPAPI.
- No TPM, public endpoint, public IP, port-forward or inbound firewall configuration required.
- Discovered public candidates are dialed only after signed record validation and exact live Noise static-key pin comparison.
- Auto-trust remains disabled.

This is the low-friction path for ordinary participants behind NAT. They can join the existing Seed, receive signed peer records and relay third-party records; they do not advertise their unreachable private address.

### Optional public relay

- Requires an independently verified globally routable numeric endpoint.
- Listener binds to 0.0.0.0 and self-announcement is enabled.
- Requires a non-exportable TPM Device Root, an Ed25519 Q6PD identity and TPM binding to the exact local Noise key.
- The existing warning about inbound anonymous Noise XX remains explicit and must be acknowledged before start.

The relay identity and TPM policy are therefore retained where a node is actually advertising a public endpoint. The change does not remove signature checks, Noise key pinning, TTL/sequence checks or replay protection.

## Package corrections

- Launcher binary hash now matches the CP-0843 node executable hash pinned by verify-package.ps1: 519e695aed1a0b68195f841c167c06e4fe23176eb50cd96476a34113233c0470. The earlier local launcher hash was stale and rejected this packaged binary.
- Config template now defaults to an outbound-only client.
- setup-node.ps1 provisions TPM root/bindings only for the public-relay role.
- start-node.ps1 has role-specific fail-closed validation. A client cannot be configured with a wildcard listener or public self-announcement; a relay cannot start without TPM binding and endpoint fields.
- Setup never changes firewall, router, NAT, tunnel, Windows service or scheduled-task configuration.
- README describes both roles and makes outbound-only client the default.
- SHA256SUMS.txt was regenerated for all package files; the full rehash verification passed.

## Exact validation performed on the CP-0848 staging package

- PowerShell 5.1 parser across all packaged .ps1 files: PASS.
- Launcher/package node-binary digest parity: PASS.
- Default template policy (Q6PD discovery/pull on, self-announcement off, TPM requirement off, loopback listener): PASS.
- Outbound-only client launcher config validation using an isolated temporary LOCALAPPDATA: PASS.
- Public-relay launcher policy validation using isolated placeholder local identity files: PASS. This is a structural config check only; it did not provision or verify a real TPM identity.
- Package verification: PASS.
- Full SHA-256 rehash and exact 22,638-file manifest coverage: PASS.
- Neither validation path started a node.

## What this does not claim

- No independent external operator joined during this validation.
- No new public Q6PD identity has been observed; the live store remains a single Seed identity.
- This does not claim an unlimited number of active connections per individual node. Resource and peer-session limits remain bounded per node; there is no fixed global network-node ceiling in this discovery design.
- This does not scan the entire Internet. Nodes learn peers from pinned bootstrap identities and QFP6 participants that actually run the software and share valid records.
- The CP-0843 executable digest is pinned for package integrity, but whole-file source-to-binary reproducibility remains unproven. The staging ZIP has not been published. Do not treat this source PR as an approved release.
- Inbound Noise XX remains anonymous before Q6PD application checks; independent security audit, Mainnet, real-value transfer, issuance/rewards and market activity are not authorized.

## Operational safety

Only a new staging directory and source-review branch were used for this work. The live Seed, backup Seed, QA Joiner, firewall rules, runtime configuration, keys and live data directories were not changed or restarted.