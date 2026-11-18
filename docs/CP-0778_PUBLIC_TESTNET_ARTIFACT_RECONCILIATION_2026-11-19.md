# CP-0778 ? Public Testnet Artifact Reconciliation
Date: 2026-11-19

## Objective
Attach the already-existing CP-0651 Genesis inputs and owner-signed Q6GA v2 zero-value Public Testnet authorization to the unified CP-0777 candidate without regenerating Genesis, repeating Gate 2/Gate 8, or touching the live node.

## Source and preservation
Source package:
D:\Temp\ASUS\QRUN_QFP6_CP0596_20261111\release\qfp6-local-single-operator-devnet-2026-11-15

Destination:
release/qfp6-candidate/artifacts/ in the unified worktree.

Only public artifact files were copied byte-for-byte. The local-only Q6GA v1 file, DPAPI-protected Noise credentials, runtime databases and anchor-vault state were not copied.

## Exact artifact inventory

| Component | SHA-256 | Bytes | Result |
|---|---|---:|---|
| genesis-snapshot.q6sn | 6961e7517adcb66c04a3c566ec8c5cba398940eb273eabd082b706bb32a4f757 | 1,280 | Attached, hash verified |
| genesis-descriptor.q6gd | e5bbd024511f907d1e9bf3c1d4004d05851cd96c79eebd0f1ce446aee15a1888 | 206 | Attached, hash verified |
| consensus-profile.q6cp | 0ff4786c2b62228883699c687b34d57a85f3bcddde9a545c95f5515a388c516f | 294 | Attached, hash verified |
| q6pn-profile.q6pn | bb3d1e5710827afd8248292f9c19ab250dcdc8e508711597dd049c77a6ec8233 | 2,294 | Attached, hash verified |
| bootstrap-peers.json | 37517e5f3dc66819f61f5a7bb8ace1921282415f10551d2defa5c3eb0985b570 | 3 | Attached; content is [] |
| public-testnet-authorization.q6ga | 72d58ef455d9b6f6ab9a5514f5f0fb40f333d347af288363b3897b5584c2f169 | 5,685 | Attached; Q6GA v2 |

## Q6GA v2 authorization
The existing authorization is Q6GA version 2, Ed25519 + ML-DSA-65, scope ZERO_VALUE_PUBLIC_TESTNET_ONLY. The original CP-0676 Release runtime verified both signatures and the authorization bindings. The unified package validator independently checks:
- envelope magic, length, version, suite and scope;
- exact SHA-256 bindings to Genesis snapshot, Q6GD, Q6CP and Q6PN;
- exact owner account and founder public-key bindings;
- CP-0651 economics: 7B gross ceiling, 1B owner Genesis, zero subsidy, fee-only producer compensation.

The Python validator does not perform cryptographic signature verification. It records the prior original-runtime verification and does not misrepresent structural checks as a new signature verification. Q6GA v2 deliberately has a zero bootstrap-peer hash field; peer endpoints/pins are bound through the network profile and peer configuration.

The authorization does not grant Mainnet, real-value transfers, public mining rewards, exchange listing or market activity.

## Candidate validation
- python tools/qfp6_candidate_package.py self-test: PASS, exit 0.
- python tools/qfp6_candidate_package.py validate release/qfp6-candidate: exit 2 / INCOMPLETE as intended.
- Five required component files: 5/5 present and SHA-256 verified.
- Q6GA v2 structure and artifact/founder-key bindings: valid.
- Candidate manifest JSON parse: PASS.
- git diff --check: PASS.

The validator reports these current package-level readiness gaps:
1. public_testnet_launch_ready=false
2. public_peer_discovery_qualified=false
3. inbound_peer_identity_authenticated=false
4. public_seed_endpoint_attested=false

These are not framed as a request to repeat Gate 2 or Gate 8. The owner reports both gates completed in prior sessions; the existing external receipts and approved Seed endpoint/Noise pins must be attached to this unified package.

## Live node protection
PID 20244 remains the pre-existing CP-0596 process. Its executable and config path are unchanged. The node and port 30333 were not stopped, restarted, replaced or reconfigured.

The existing seed config has an empty bootstrap peer array, outbound peer sync disabled, Q6AR address book disabled, and anonymous Noise XX inbound acknowledgement. Its public listener is not proof of a connected or authenticated multi-peer network. The current unified package does not yet contain the independent Seed endpoint/Noise pin records required to bind the public peer topology.

## CP-0651 economics retained
- Maximum gross supply: 7,000,000,000 QZXB.
- Owner Genesis allocation: 1,000,000,000 QZXB.
- Six separate 1B accounting labels are ceilings only, not issued/spendable balances or mint authority.
- Block subsidy and mining issuance: zero.
- Producer compensation: canonical transaction fees only.

## Next action
Import the existing independently qualified Seed endpoint(s), Noise public-key fingerprints and operator receipts; bind them to the Q6PN/Q6AR peer configuration; prepare a new unified runtime config; and review/approve the exact CP-0778 release candidate. Do not repeat Gate 2 or Gate 8. If Q6PN changes, renew Q6GA v2 locally over the exact new Q6PN hash; do not expose wallet secrets.
