# CP-0465 — QRun Mainnet and Public-Trading Go/No-Go

Date: 2026-10-29

Status: **NO-GO for value-bearing public Mainnet and QZXB/USDT trading.** The source release gate is deliberately closed in this candidate. This document records verified blockers and exit criteria; it is not a security certificate, listing approval, or claim of market value.

## 1. Decision in one page

Do not promote the current single-machine public-alpha process to Mainnet, do not publish it as a live value-bearing network, and do not invent a QZXB price or a QZXB/USDT pool. The checked-out candidate has a Genesis identity and a wallet balance, but it still lacks the distributed operators, production-history recovery guarantees, final consensus calibration, and market counterparties required for the requested outcome.

A focused source change in this work session adds a compile-time release gate to `qrun_v05_pow_local_node`. `QRUN_MAINNET_RELEASE_APPROVED` is deliberately `false`; the `--mainnet` parser fails closed before it reads protected keys, creates node data, or opens sockets. There is no CLI flag to bypass this. This is a safety stop, not a claim that the missing protocol work has been completed. The already-running process was not replaced and continues to report its explicitly experimental `--public-alpha` mode until deliberately stopped or replaced.

## 2. Observed runtime and host state

- Current working branch before this change: `work/qzbe-v04-persistent-mining-20261026`; baseline remote head: `b3851fa91db0f15d7b6b1843dbf6caf534712da2`.
- The running executable is named `qrun_v05_pow_local_node.exe` and was launched with `--public-alpha`, not `--mainnet`.
- Its block/P2P socket is bound to `0.0.0.0:49341`; read-only RPC and transaction ingress are bound only to `127.0.0.1:49339` and `127.0.0.1:49340`.
- An HTTP GET to the local RPC root returned an unsupported-endpoint response with `mainnet=false`. The earlier audit recorded height zero and no configured peers. An all-interface listener does not prove router/NAT/ISP reachability or independent network participation.
- Windows Firewall profile query: Domain enabled; Private and Public disabled. No broad inbound rule or router port-forward was created. Firewall restoration requires an elevated PowerShell session.
- Current Genesis intent: 10,000,000,000 QZXB at Genesis to the owner; zero subsequent minting and zero block subsidy. This means block producers do not mine new QZXB subsidy. A local Genesis balance is not a public transferable balance and is not evidence of a market price.
- No externally reachable, independently operated seed was configured or verified, and no public price, public explorer endpoint, confirmed QZXB/USDT pool, reserve balance, or exchange listing was verified.

The detailed prior audit is [CP-0463 — Repository Audit and Release Decision](CP-0463_QRUN_REPOSITORY_AUDIT_AND_RELEASE_DECISION_2026-10-29.md). The older launch gate and Genesis freeze packet remain historical evidence of design intent, not proof of activation: [CP-0447](CP-0447_QRUN_MAINNET_10B_RELEASE_GATE_2026-10-28.md), [CP-0436](CP-0436_MAINNET_GENESIS_PROFILE_FREEZE_PACKET_2026-10-27.md).

## 3. Technical blockers that still require implementation/evidence

1. **Production consensus is not frozen.** The selected PoW profile is still a calibrated candidate. The available benchmark record had 4 benchmark hosts but only 2 of the required 3 independent operators. Timestamp/retarget extremes, high hash-rate changes, restart and reorg behavior need independent evidence.
2. **Full history and recovery are incomplete.** Current authenticated catch-up is bounded by candidate archive/range limits. Full-history validation/replay or an independently verifiable checkpoint-rollover and monotonic anti-rollback trust model is not yet integrated end-to-end. Increasing caps is not a substitute.
3. **There is no independent network.** At least one public seed with a different operator and host is needed to begin external integration testing; a production launch should have multiple independently operated nodes across providers/networks. Their network ID, Genesis ID, consensus/profile identity and Noise static public keys must be verified out-of-band and pinned.
4. **Public reachability is unproven.** External inbound P2P must be tested from a separate network after host firewall protection is restored and a specific seed endpoint is ready. RPC and transaction ingress must remain private or be served through a separately hardened, authenticated/rate-limited gateway.
5. **Local software tests pass, but release validation is still incomplete.** In this work session, `cargo test --all-targets --locked --offline` completed with exit code 0 across all Cargo targets (89 test-result sections; zero failed-result markers). The focused node suite passed 17/17, and the explicit `--mainnet` guard test confirmed rejection before data-directory creation. This is local test evidence only, not a public-network soak test, reproducible third-party build attestation, independent security review, or a multi-operator release approval. Adversarial multi-host testing and independent review remain required.
6. **Operational recovery and users' access are incomplete.** Publish reproducible build hashes, node instructions, an independently operated read-only explorer/indexer, health monitoring, transaction inclusion/confirmation guidance, wallet recovery compatibility information and a documented incident/reorg procedure before promoting value-bearing use.

## 4. QZXB/USDT is a separate market-integration problem

There are three different things; they must not be conflated:

- **Native QZXB transfer:** requires a live, converged QRun network, a correctly derived QZXB wallet, verified recipient identity and an independently checked confirmed transaction. This is not ready on a public network today.
- **Native USDT on QRun:** Tether's official [supported-protocols list](https://tether.to/en/supported-protocols/) names supported protocols, but not QRun. QRun cannot create authentic Tether USD₮ by copying a ticker, deploying an arbitrary token, or naming an asset “USDT”. Native support requires Tether to accept/integrate the protocol and issue/support real USD₮ on it; approval is not under this project's control.
- **A QZXB/USDT trading pool or exchange market:** a pool needs an actual supported quote asset, a technically sound settlement/bridge path, independently verifiable reserves and real counterparties. The repository's EVM launch-asset experiment is a separate test asset on Sepolia; it is not native QZXB, not a bridge and not a mainnet USDT reserve. A bridge-wrapped QZXB route would need a separately designed, reviewed bridge/custody model and must not be described as trustless until it is proved so.

Possible real-market routes, in order of technical independence: (a) once QRun is live, an explicitly disclosed direct peer-to-peer sale with a buyer and agreed settlement steps; (b) an audited bridge/wrapped-asset deployment into an existing USDT-supported EVM network, with explicit bridge and custody risks; (c) official Tether integration into QRun, if accepted; or (d) a centralized exchange application and its technical, compliance, demand and liquidity review. A listing is not guaranteed; for example, [Coinbase's official process](https://www.coinbase.com/exchange/asset-listings) includes legal/compliance and technical security review. None of these routes can truthfully be called a currently active QZXB/USDT market.

Do not seed an AMM using fabricated USDT, a self-issued token labelled USDT, or a made-up price. A liquidity pool starts with real token reserves; its initial reserve ratio sets the initial pool price, and a pool with no reserves cannot execute a meaningful trade. See [Uniswap's pool explanation](https://developers.uniswap.org/docs/protocols/v2/concepts/pools).

## 5. Release exit criteria (all must be evidenced)

- [ ] **Independent operators:** at least three independently operated benchmark/node operators across separate hosts or providers, with signed/dated profile-calibration evidence and no shared single point of failure.
- [ ] **Genesis/profile conformance:** independently reproduce the frozen Network ID, Genesis ID, profile fingerprint, height-zero root, owner allocation and total supply; ensure every runtime, importer, replay and fork-choice path enforces the same profile.
- [ ] **History and fork recovery:** validate from Genesis or publish and independently verify the full checkpoint manifest/rollover/anti-rollback model; exercise long catch-up, interruption, restart, competing forks, reorg, state-root equality and invalid/old checkpoints.
- [ ] **Multi-host transactions:** demonstrate authenticated pinned P2P, propagation, transaction admission, inclusion, confirmations, independently queried balances and wallet restoration on separate hosts; test partition recovery, peer loss, malformed frames and resource/DoS limits.
- [x] **Local all-target Rust tests:** `cargo test --all-targets --locked --offline` completed with exit code 0 on this checkout; focused QRun node tests also passed 17/17. This does not certify production readiness.
- [ ] **Independent release validation:** run relevant contract tests and reproducible builds on an independent host; obtain an independent protocol/security review, fix all critical/high findings, and publish the exact source SHA and binary hashes.
- [ ] **Host and network security:** restore Windows Firewall profiles in an elevated session; add only a narrow inbound P2P rule for the chosen port after peer information is verified; do not expose RPC/TX. Confirm reachability from an unrelated external network and document the observed test result.
- [ ] **Public operations:** run independent nodes long enough to establish that height/state roots converge and stay converged; publish network/Genesis/profile hashes, software hashes, bootstrap peers, known limitations, operator instructions, explorer/API availability, monitoring and incident policy.
- [ ] **Market route:** choose either direct OTC, Tether protocol integration, a properly reviewed bridge route, or an exchange application. Verify the real counterparties/reserves/contract addresses on the actual network; disclose risks and fees. Never imply liquidity or a USD price before real swaps exist.
- [ ] **Release promotion:** after every prior item has evidence, update the source-level release gate in a new reviewed commit, rebuild reproducibly, run the full suite, and only then activate a coordinated multi-node launch. Do not enable it just to make a status field say `mainnet=true`.

## 6. What “do it like Bitcoin” actually implies

Bitcoin's January 2009 public release distributed open-source software that connected to a peer-to-peer network and invited others to run inbound-capable nodes; it explicitly described the software as experimental. The original design used proof of work and cumulative work to maintain a shared history. See the [original v0.1 release announcement](https://satoshi.nakamotoinstitute.org/emails/cryptography/16/) and [Bitcoin paper](https://nakamotoinstitute.org/library/bitcoin/).

The relevant lesson is to publish reproducible software, let independently operated nodes validate the same rules, maintain a genuinely peer-to-peer network, and communicate the experimental risks honestly. The mechanics of QRun are not identical: the requested QZXB economic rule pre-allocates all 10B units to one owner at Genesis and pays no block subsidy. Calling fee-only block production “mining” does not create a new 10B distribution or the same security incentives as Bitcoin's block subsidy. The protocol needs a documented, tested fee-only security/economic analysis rather than marketing equivalence.

## 7. Immediate operational actions

1. Keep the source-level `QRUN_MAINNET_RELEASE_APPROVED = false` until all release exit criteria are met.
2. Run `Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True` from **elevated PowerShell** to restore firewall protection. Do not attempt to work around Windows access controls. Keep RPC and transaction ingress loopback-only.
3. Provision or designate an independent seed host/operator; provide its public numeric IP/port and Noise static public key only after verifying the key through a separate authenticated channel. The local node cannot invent these.
4. Do not try to trade through the current wallet as if it had public Mainnet settlement. First complete the external multi-host transaction proof and select a real USDT integration/market route.
5. Keep the default `main` branch/site separate from this work branch until a reviewed release is explicitly promoted.

**Decision:** the current candidate is not ready for value-bearing public Mainnet or QZXB/USDT trading. The source gate added in this work session prevents a future build from accidentally advertising the candidate as Mainnet merely because a pinned peer is supplied. This is an intentional protection; it is not a reason to claim that the network has launched.
