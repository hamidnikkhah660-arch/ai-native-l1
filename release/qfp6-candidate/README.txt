QFP6 UNIFIED CANDIDATE PACKAGE

Status: CP-0651 GENESIS INPUTS ATTACHED ? PUBLIC PEER TOPOLOGY NOT CONNECTED.
This is a zero-value Public Testnet candidate package, not Mainnet and not a production release.

Canonical CP-0651 inputs attached byte-for-byte from the preserved CP-0596 workspace:
- artifacts/genesis-snapshot.q6sn
- artifacts/genesis-descriptor.q6gd
- artifacts/consensus-profile.q6cp
- artifacts/q6pn-profile.q6pn
- artifacts/bootstrap-peers.json
- artifacts/public-testnet-authorization.q6ga (Q6GA v2, Ed25519 + ML-DSA-65)

The Q6GA v2 owner authorization is scoped only to ZERO_VALUE_PUBLIC_TESTNET_ONLY.
It was verified by the original CP-0676 Release runtime and is hash-pinned here.
It does NOT authorize Mainnet, real-value transfers, public mining rewards, market
activity, exchange listing, or liquidity. The local-only Q6GA v1 file is intentionally
not copied into this package.

Active economics are CP-0651:
- Maximum gross supply ceiling: 7,000,000,000 QZXB.
- Owner Genesis allocation: 1,000,000,000 QZXB.
- Six 1B accounting labels: ceilings only, not issued balances or mint authority.
- Block subsidy / mining issuance: exactly zero.
- Producers receive canonical transaction fees only.

Important release boundary:
- The bootstrap-peers.json file is present and hash-verified, but its array is empty.
- The prior seed config had outbound peer sync disabled and Q6AR address-book discovery disabled.
- The candidate runtime manifest records unauthenticated inbound Noise XX and unqualified
  public peer discovery. A public listener alone is not a connected public P2P network.
- The owner reports Gate 2 and Gate 8 complete and has instructed that those qualifications
  must not be repeated. Their external receipts are not attached to this package yet.
- No external Seed endpoint / approved peer-pin set is attached to this unified package.
- The existing live PID 20244 / port 30333 was not stopped, reconfigured, or replaced.

Do not treat this package as launch-ready. Do not copy DPAPI credentials, local-only
Q6GA v1 approval, runtime databases, private keys, or local anchor-vault state.
Do not invent endpoints or peer identities. Public Testnet activation remains gated
on attaching the already-qualified external operator/Seed records and completing the
specific public-peer runtime binding.

Run:
  python tools/qfp6_candidate_package.py self-test
  python tools/qfp6_candidate_package.py validate release/qfp6-candidate
