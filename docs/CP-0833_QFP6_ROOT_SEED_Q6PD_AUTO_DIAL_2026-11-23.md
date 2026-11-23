# CP-0833 — QFP6 Genesis Root Seed Q6PD Auto-Dial

Date: 2026-11-23
Scope: ZERO_VALUE_PUBLIC_TESTNET_CANDIDATE_ONLY
Status: SOURCE IMPLEMENTED; FOCUSED TEST PASS; BINARY BUILT AND DEPLOYED; PRIMARY ROOT LISTENER READY

## Defect corrected

The Genesis-root Seed had Q6PD candidate serving and inbound signed announcements enabled, but the outbound candidate-discovery switch was ineffective:
- launcher validation rejected Q6PD pull for a Seed with an empty upstream bootstrap list;
- the Genesis-root supervisor wrapper hard-coded q6pd_pull_enabled=false when entering the shared supervisor.

## Implementation

- Added q6pd_peer_pull_requires_operator_pinned_seed: joining roles still require at least one operator-pinned Q6PD-capable seed; a genesis-root Seed may have zero upstream peers.
- Propagated the actual enable_q6pd_peer_pull setting through the Genesis-root Q6PD supervisor wrapper to the common scheduled discovery/auto-dial loop.
- Root with zero upstream peers serves and receives signed Q6PD records, then runs the 30-second signed-candidate auto-dial scheduler as records arrive.
- Candidate records are not auto-trusted. The record store enforces Ed25519 signature, network/profile, endpoint, TTL and replay/high-water checks; outbound Noise handshake pins the exact Noise public key declared by the signed record.
- Successful candidate exchange starts the bounded persistent Q6PD session worker and remains separate from chain consensus authority/history validation.
- Root does not self-bootstrap or dial itself. The root's static bootstrap peers file remains empty, as required by the genesis-root topology.
- Existing joining-node bootstrap remains anchored to the QFP6 root DNS endpoint plus exact Noise static-key pin. No addresses from other networks were introduced.
- CP-0831 already covers store-level three-hop signed-record relay; it does not establish an independent public mesh.

## Focused verification

- rustfmt --edition 2021: PASS for permissionless.rs and qrun_v06_node_supervisor_candidate.rs.
- git diff --check: PASS for both changed files.
- Unit test genesis_root_seed_may_auto_dial_signed_records_without_upstream_seed: 1 passed, 0 failed.
- cargo build --locked --offline --bin qrun_v06_node: PASS.
- Existing unrelated warnings in other library modules remain.

## Source and artifact hashes (SHA-256)

- permissionless.rs: 8C6064A9802A2B7450C03988371C16BE5155BBD53E570AEB5121501698A71588
- qrun_v06_node_supervisor_candidate.rs: 33545858B169EEF729416218BDA21301371343A99ECCC3E930AAE23A115259E0
- CP-0833 binary: EF85974E10A431335B74BA10503D4724B49E106A287FB4D3C6DC37FD96D0153E
- Primary config: A7FC3639E7B9A1EED4EAC5C3B9AF5A9CCC2E459ACE3D8DE09AC1E6096798255B

## Rollout controls

- Only primary Seed 30336 is upgraded by the launcher.
- Backup Seed 30337 and same-host Joiner 31434 are left unchanged.
- TPM/device-root binding, Noise key, Q6PD identity, public endpoint, Funnel mapping, genesis/profile pins and root empty-bootstrap file are unchanged.
- Config sidecar and the one primary launcher executable/hash reference were updated consistently.
- Launcher PowerShell parse and scheduled-task action validation: PASS.
- Deployed process: CP-0833 PID 7088; listener 0.0.0.0:30336 verified READY by launcher at 2026-11-23T03:03:24.011+03:30.
- Launcher completed with exit code 0; backup PID 5800/30337 and Joiner PID 19720/31434 were already listening and remained unchanged.
- Startup log confirmed automatic_peer_discovery=Q6PD_SIGNED_RECORD_GOSSIP; AUTO_DIAL_1_PER_30S; automatic_peer_dial=Q6PD_SIGNED_RECORDS_NOISE_KEY_PINNED_AUTO_DIAL_1_PER_30S; q6pd_peer_pull=ON_ROOT_SEED_INBOUND_SIGNED_RECORDS_PLUS_AUTO_DIAL_30S; q6pd_candidate_auto_dial=true; q6pd_candidate_auto_trust=false.
- Root startup announced its existing signed public endpoint 176.58.88.82:443 with SNI heymed.tail2a756d.ts.net and sequence 30.
- Runtime scheduler event observed: QFP6_Q6PD_AUTO_DIAL_SKIPPED reason=no_eligible_signed_candidates stored_candidates=1. This confirms the outbound 30-second candidate scheduler is executing; it correctly skips the root's own record.
- Durable Q6PD store currently contains one candidate/watermark only: the root's own peer ID. No foreign-network address was inserted and no external peer is being represented as connected.
- A local same-host Joiner successfully opened Noise to the root and received a Q6PD pull response. This is local interoperability only, not an independent public peer; the local Joiner does not announce a publicly reachable self-record.
- No independent remote QFP6 identity has been observed. Local loopback sessions are not independent peers.
- Public mesh qualification, mainnet and market authorization are NOT_GRANTED.
