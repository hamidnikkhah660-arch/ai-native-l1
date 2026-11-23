# CP-0834 — QFP6 DNS Bootstrap Multi-Route Failover

Date: 2026-11-23
Scope: ZERO_VALUE_PUBLIC_TESTNET_CANDIDATE_ONLY
Status: SOURCE IMPLEMENTED; 3 DNS TESTS PASS; ROOT REGRESSION PASS; BUILD PASS; JOINER DEPLOYED AND LISTENING

## Objective

Make the existing pinned QFP6 DNS seed resilient to an unavailable first DNS route without changing the seed identity or trusting DNS as an identity source.

## Implementation

- Added a strict Q6PD public-endpoint predicate for DNS routes.
- Added bounded DNS seed resolver: public lowercase FQDN, TCP 443, 1..=16 distinct globally routable unicast routes, sorted and deduplicated; the resolver rejects a mixed set if any route is private, invalid or wrong-port.
- Added Q6PD DNS-seed pull with failover: each route uses the same configured TLS SNI and exact out-of-band pinned Noise static key. Only a completed Noise handshake with that exact key may deliver signed Q6PD records.
- Wired DNS failover into initial Q6PD bootstrap and periodic refresh for configured DNS bootstrap peers.
- Signed Q6PD candidate dialing remains separate: Ed25519 signature, network/profile, endpoint, TTL, sequence/replay and exact Noise key pin remain required. DNS IP count is never treated as peer count.
- Genesis-root Seed topology and CP-0833 auto-dial behavior are unchanged. Joiner still requires a pinned root seed and does not self-announce without a public endpoint.
- No unrelated-network addresses, invented seed records, new identities, or new keys were added.

## Verification

- rustfmt --edition 2021: PASS for all four changed Rust files.
- git diff --check: PASS.
- cargo test --locked --offline --lib q6pd_dns_seed_failover_tests -j 1: 3 passed, 0 failed.
- cargo test --locked --offline --bin qrun_v06_node genesis_root_seed_may_auto_dial_signed_records_without_upstream_seed -j 1: 1 passed, 0 failed.
- cargo build --locked --offline --bin qrun_v06_node -j 1: PASS.
- Launcher PowerShell parse: PASS; scheduled task remains Ready.

## Live rollout

- Primary Seed: CP-0833 PID 7088, listener 30336 — unchanged and listening.
- Backup Seed: PID 5800, listener 30337 — unchanged and listening.
- Same-host Joiner: CP-0834 PID 12808, listener 31434 — deployed and listening.
- Launcher completed with exit code 0 at 2026-11-23T03:29:55+03:30.
- Joiner executable SHA-256: C457CE91773D5B6E5FE5B4F392556F05D4F5A647314FFCB35541CB7C5FCC5E14
- Joiner config SHA-256 (unchanged): 63F56E1322BCC2D9EBD98563FBB7EA8EB69D0AF68BC61CC6769839A035FD1509
- Root CP-0833 executable SHA-256 (unchanged): EF85974E10A431335B74BA10503D4724B49E106A287FB4D3C6DC37FD96D0153E
- Root config, Joiner config, DNS bootstrap file, Noise/TPM bindings, Q6PD identities, root Funnel and backup Seed configuration were not changed.

## Runtime DNS / Noise evidence

- Joiner log: QFP6_Q6PD_DNS_SEED_RESOLVED hostname=heymed.tail2a756d.ts.net port=443 public_routes=3.
- First route 176.58.88.82:443 succeeded with TLS SNI heymed.tail2a756d.ts.net.
- Noise handshake completed using the already configured pinned root key.
- Q6PD pull completed: 1 signed record received, 0 inserted, 1 updated, 0 rejected. The record is the existing root record, not a new peer.
- History fast-resume confirmed the existing local tip at height 21531; root source height was 21530 and no blocks needed importing.
- Q6PD persistent session manager correctly logged SKIPPED reason=no_public_signed_self_record for this local-only Joiner.

## Source hashes (SHA-256)

- qrun_v06_peer_discovery_candidate.rs: 9DEF59E0E18C5366E86C854E548FDD90B0C7745AACB54E4996A72365DE9F48F8
- qrun_v06_history_sync_service_candidate.rs: B942033CCF4BC20E665213A6D68BBF20DAC215CF506DEB26AE603CE52B3D5EDD
- qrun_v06_node_supervisor_candidate.rs: DE8265A9F770AA947D0621422A57C9F4459EB7035FFB91A9BC08B0A075CF6214
- permissionless.rs: 3BE61694819DF6C53C3303C0DD5248452CA74F59C3658BF6B4BAC3AF9F120B78

File-specific pre-change backups use suffix .pre-20261123-cp0834-q6pd-dns-seed-failover.bak. The launcher backup is QFP6_LOCAL_SEEDS_ON_LOGON_20261122.ps1.pre-cp0834-joiner-dns-failover-20261123.bak.

## Qualification limits

- The Windows runtime resolver returned three usable public routes in this run. A separate DNS query displayed both A and AAAA records; no claim is made that all six were used in this runtime run.
- A local same-host Joiner is not an independently operated external peer.
- Root Q6PD store still contains only the root's own signed record. No independent QFP6 identity has joined.
- CP-0831 covers store-level three-hop signed-record relay; live independent-host multi-hop qualification is still pending.
- Network remains ZERO_VALUE_PUBLIC_TESTNET_CANDIDATE_ONLY. Mainnet and market authorization are NOT_GRANTED.
