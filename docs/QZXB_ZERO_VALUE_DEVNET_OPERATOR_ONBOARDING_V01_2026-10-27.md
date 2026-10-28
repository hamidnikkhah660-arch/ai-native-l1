# QZXB Zero-Value Devnet Operator Onboarding Packet — V01

Date: 2026-10-27
Project: QuantumZXB / QZXB native L1 (candidate runtime)
Reference source commit: `06d2f7802111cdd7b1f93ca2fb53c46a57911635`
Reference CI: [GitHub Actions run 40433578254](https://github.com/hamidnikkhah660-arch/ai-native-l1/actions/runs/40433578254) — completed successfully for the candidate source.

## Purpose and current status

This packet is for recruiting and qualifying independent operators for a future **zero-value public devnet**. It is not a production release, deployment instruction, or promise of an immediate public endpoint. The current QZBE node path is an isolated candidate/test runtime; a green CI run does not approve mainnet or value-bearing public transactions.

As of this packet's date, Gate 2 (production Genesis/monetary policy freeze and canonical runtime integration), Gate 8 (deployed independent anti-rollback CAS/anchor), Gate 13 (qualified multi-operator public devnet), and Gate 14 (independent security/provenance/compliance review) remain OPEN. No native QZXB Mainnet, verified QZXB/USDT pair, or genuine QZXB market-data feed is established by this packet.

## What participation means

The initial request is for expressions of interest only. It does not ask participants to run the present candidate as an internet-facing service, supply funds, provide custody, or disclose sensitive information. A reviewed onboarding bundle and explicit configuration will be published only after the public-devnet boundary and safety checks are ready.

The target is at least three independently administered operators. Three processes, containers, or VMs controlled by one administrator do not count as three independent operators. Each operator should be able to explain who administers the host, how it is isolated from the other operators, and how logs and test outcomes can be reproduced.

## Minimum operator readiness

Please confirm only the following non-secret information:

1. Platform family and version (Linux or Windows; exact patch level optional).
2. Whether the host, administrator, and network are independently controlled from the other participants.
3. Whether the host can run a Rust-based candidate node and preserve test logs/artifacts.
4. Approximate availability for a zero-value test cycle and a contact method you choose to share publicly.
5. Agreement that no private keys, seed phrases, account passwords, production credentials, or funds will be shared.

Do not post public IPs, credentials, private keys, wallet recovery words, private contact details, or identifying documents in GitHub issues. Do not run any command copied from an unreviewed issue comment as an administrator.

## Acceptance plan before a public devnet is announced

The maintainers must complete and record each item below. Interest responses alone are not acceptance evidence.

- [ ] Three operators confirmed as separately administered, with distinct hosts and network paths.
- [ ] Exact source commit, reproducible build instructions, binary hashes, dependency inventory, and test configuration published.
- [ ] Public P2P protocol and peer discovery reviewed; authentication, replay protection, connection limits, rate limits, input-size limits, and abuse response demonstrated.
- [ ] Test-only transaction RPC designed and explicitly separated from production/value-bearing settings; no silent profile downgrade.
- [ ] Native test wallet/address/signing flow and test-only faucet qualified; zero-value test assets clearly labeled and not redeemable.
- [ ] Explorer/indexer and machine-readable status/health data available with network identity, chain ID/network ID, height, canonical tip, state root, software version, and last update time.
- [ ] Independent-node tests cover valid signed transfer, invalid signature atomic rejection, peer gossip, wrong-network rejection, restart/replay, fork/reorg, malformed peers, rate limiting, and matching canonical tip/state roots.
- [ ] Backup/restore, rollback, incident response, key lifecycle, operator contact/escalation and stop procedures documented.
- [ ] External security review scope and findings recorded. A self-review, CI pass, or informal community comment is not an independent audit.
- [ ] Launch decision and limitations explicitly recorded; no value-bearing mainnet claim until separate production gates are closed.

## Stop conditions

Keep the candidate off public interfaces if the configuration cannot clearly prove test-only mode, if peer authentication is not enabled, if the operator cannot isolate the test data directory, if the external trust/rollback design is unresolved for the test being run, or if test outputs disagree across nodes. Do not work around a failed guard by disabling signature, replay, network-identity, profile-lock, or persistence checks.

Do not send USDT or other real assets, generate/store production keys in the test environment, fund an exchange listing, seed a liquidity pool, or claim market readiness. The currently recorded new-spend budget is USD 0 unless the owner explicitly changes it.

## What to post in response

Use this minimal public template; omit anything you do not want public:

- Platform family: Linux / Windows / other
- Independent administration: yes / no / needs discussion
- Can run a reviewed zero-value test package: yes / no / needs details
- Availability: approximate window
- Relevant public protocol/operations experience: optional

No money or secrets are requested. A response means interest, not a commitment or verification of independence.

## Linked tracking items

- [Recruit independent operators — Issue #72](https://github.com/hamidnikkhah660-arch/ai-native-l1/issues/72)
- [Seek independent protocol and anti-rollback review — Issue #73](https://github.com/hamidnikkhah660-arch/ai-native-l1/issues/73)
- [Owner directive and launch/liquidity gates — Issue #12](https://github.com/hamidnikkhah660-arch/ai-native-l1/issues/12)
- [CP-0409 independent-security-audit scope and RFP](CP-0409_INDEPENDENT_SECURITY_AUDIT_SCOPE_2026-10-25.md)
- [CP-0401 launch and liquidity fast path](CP-0401_GLOBAL_NATIVE_COIN_LAUNCH_AND_LIQUIDITY_FASTPATH_2026-10-24.md)

This packet improves onboarding clarity only. It does not close any launch gate or establish that an independent operator, reviewer, provider, market, liquidity source, or audit exists.
