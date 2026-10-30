# CP-0463 — QRun / QZXB Repository Audit and Release Decision
Date: 2026-10-29

Status: **Engineering audit completed on the active work branch; public Mainnet and public trading remain not activated.** This record is not a security audit certificate, exchange listing, or claim of market value.

## 1. Scope and source baseline

Reviewed the active checkout at `work/qzbe-v04-persistent-mining-20261026`, baseline commit `61e6950`, including Git history and tracked-file inventory, README and launch-gate documents, the QRun v0.5 native node, wallet derivation/restore path, Genesis/profile constants, P2P and startup-sync guards, market indexers, candidate AMM and EVM launch-asset documentation. Applied two focused corrections to `src/native/pow_bench/src/bin/qrun_v05_pow_local_node.rs` and added regression tests.

Inventory at audit time: 485 tracked files, 250 commits from the first repository commit on 2026-10-20 through 2026-10-29, 134 documents, 68 Rust binary entrypoints, 31 Python/PowerShell simulation scripts, and 9 QZXB market-tool files. The repository is a research/engineering ecosystem with several historical and candidate protocol paths, not one universally production-ready binary.

## 2. Current wallet-bound QZXB candidate identity

- Network ID: `8b5d169205ac49cb9866a9d27ff1a6c3c2571fca65f634854c41c112e506aebb`
- Genesis ID: `91229b7d21b23cee83f00cec53a566ef1b30db70c644c1e9d05a431c1acf4dbc`
- Profile ID: `75596fa188dc308088efc6b138e9fcd50be6de82ec2bc117c13e81d7eebfdb09`
- Height-zero state root: `a44e545c2cd8fa4e56e228f4f242cbf5445b1cc983c7b1f8fe89c5b42aef88d7`
- Supply policy: 10,000,000,000 QZXB with 8 decimals, all allocated to the owner at Genesis; no post-Genesis minting and zero block subsidy in this QRun direction.

The running node's loopback RPC reported that exact identity, height 0, the frozen state root, `mainnet=false`, and no configured peers. Its owner-balance query returned 1,000,000,000,000,000,000 atoms (10 billion QZXB). This proves the candidate's local Genesis state; it does **not** prove that the same balance is present on an independently operated public blockchain or is currently transferable to a buyer.

## 3. Capabilities found in the repository

- Native ledgers, versioned monetary/genesis rules, Ed25519 transaction signing, fee-only QRun block candidates, proof-of-work/fork-choice code, persistent candidate stores, state-root and replay validation.
- QRun Noise-based peer transport, static-key pins, bounded block/range exchange, startup synchronization, and local two-node signed-transfer tests.
- A native Windows QZXB wallet CLI with address inspection, masked recovery-phrase input, signed transfer creation/submission and loopback-only read queries.
- Older QZBE v0.4 issuance/monetary experiments, hybrid signature/post-quantum research, checkpoint/anti-rollback candidates, EVM/contract research, native AMM candidates, and EVM/native market-candle indexers.
- Market tools validate canonical log ordering, confirmation depth and agreement between independent RPC providers. They index swaps; they do not create an exchange, quote asset, reserve, or liquidity.
- `contracts/launch-asset` describes a separate QX EVM test asset on Sepolia. It is not the native QZXB coin and is not a live QZXB mainnet pool.

These are real source/test capabilities. They must be described as candidate/testnet functionality unless a given path has also been integrated, deployed and independently verified in the production network.

## 4. Source defects corrected in this audit

### 4.1 Public P2P listener policy

The runtime previously accepted a non-loopback listener during configuration validation for Mainnet, but a later `run()` guard rejected non-loopback block listeners whenever `public_alpha` was false. That made the Mainnet bind path internally inconsistent. A dedicated listener-policy function now permits public P2P only when `--public-alpha` or `--mainnet` is explicit. RPC and transaction ingress remain loopback-only.

### 4.2 Mainnet consensus profile selection

The runtime previously chose the calibrated QRun v0.5 consensus parameters only when `public_alpha` was true. A `--mainnet` configuration incorrectly selected the easy local smoke-test PoW parameters, which would not match the frozen Mainnet profile. The new mode selector uses the calibrated candidate profile for both public-alpha and Mainnet; the maximum-target/reduced-memory parameters stay in explicit local smoke-test mode.

Regression tests now require the Mainnet profile fingerprint to equal the public-alpha fingerprint for the same locked Genesis identity, require the local smoke profile to differ, permit public Mainnet P2P while keeping RPC/transaction ports on loopback, and reject public P2P in local-test mode.

## 5. Wallet recovery and Trust Wallet compatibility

The QZXB wallet format is `QZKW1_Windows_CurrentUser_DPAPI`: the file is protected for the current Windows user. Its recovery implementation validates a 12-word English BIP39 mnemonic and then applies the QZXB-specific derivation domain `QUANTUMZXB-ED25519-SEED-FROM-BIP39-V1` before creating the Ed25519 signing key. The QZXB wallet test suite includes deterministic derivation/checksum coverage, and the owner wallet address command matched the expected public owner account during this audit.

This is not the same as proving that the same words will produce the same QZXB owner address inside Trust Wallet. Trust Wallet's documented derivation paths are coin-specific, and support for a new native blockchain requires chain-specific address/signing integration in Wallet Core and acceptance by Trust Wallet; adding a custom EVM network does not by itself add support for this native QZXB protocol. See [Trust Wallet: Wallet Core usage/derivation](https://developer.trustwallet.com/developer/wallet-core/integration-guide/wallet-core-usage) and [adding a new blockchain](https://developer.trustwallet.com/developer/wallet-core/newblockchain).

**Do not paste the recovery phrase into an unsupported wallet to experiment.** Preserve it offline. To recover this account, use a QZXB implementation that reproduces this exact derivation and verify the resulting public account ID before attempting any transfer. The existing DPAPI file alone is not portable to a different Windows user/machine; the phrase-based restore path creates a fresh protected file on the destination Windows system.

## 6. Remaining public Mainnet gates

1. An independently operated seed node must be reachable from outside this machine and configured with the exact same network, Genesis and consensus profile. Its Noise static public key must be verified and pinned. No such peer was configured during this audit.
2. External P2P reachability remains unverified. A listener bound to `0.0.0.0:49341` is not proof that router/NAT/ISP forwarding permits inbound connections. No inbound firewall rule was created. At audit start, Windows Firewall showed Domain enabled but Private/Public disabled; restore firewall protection and only add a narrow inbound P2P rule after an actual peer endpoint and operator are ready. Do not expose the loopback-only RPC or transaction ingress.
3. A successful authenticated multi-host startup/sync/restart/reorg/transaction-relay exercise is still required. Loopback integration tests do not prove real Internet reachability, independent operation, partition recovery or resistance to adversarial peer behaviour.
4. Full public history validation/replay or a production-trustworthy checkpoint rollover and independent monotonic anti-rollback anchor service still need end-to-end integration and operational evidence. Candidate bounded archive/checkpoint components are not the same as a deployed independent trust domain.
5. The production consensus profile is not frozen. The calibration oracle reports 4 benchmark hosts out of 3, but only 2 of the required 3 independent operators, and calls the profile `production_consensus_profile_frozen=false`. Additional timestamp/retarget extremes, large hash-rate shifts, restart/reorg and multi-operator testing remain.
6. There is no confirmed public explorer/RPC service for arbitrary outside users, no independent public-node balance verification, and no real QZXB/USDT reserve or public AMM market. A real trade needs a counterparty and an on-chain transfer or a separately implemented pool with a real quote asset, actual reserves and confirmed swaps.
7. The active work branch is not yet merged into the repository's default `main` branch; the checkout's local ref showed `main` behind this work branch by 24 commits. Treat this as a work-branch candidate until a separate release/promotion decision is made.

## 7. Validation executed for this audit

| Check | Result |
|---|---|
| `cargo fmt --all -- --check` on the modified source | PASS |
| `cargo check --all-targets --locked` on the modified source | PASS |
| Isolated locked Release build of `qrun_v05_pow_local_node` and `qzxb_wallet` | PASS; output under `C:\QRun\qrun-audit-release-target-20261029` |
| `cargo test --locked --bin qrun_v05_pow_local_node` | PASS (exit 0); includes both new regression tests and authenticated/loopback sync tests |
| `cargo test --locked --bin qzxb_wallet` | PASS, 6/6 |
| Wallet-bound 10B Genesis test | PASS, 1/1 |
| QZXB market indexer/candle tests (EVM and native) | PASS, 28/28 |
| QRun identity, consensus calibration, full-supply Genesis direction, historical tokenomics oracles | PASS, 4/4 |
| Release CLI guard without `--sync-on-start` | Correctly rejected with exit 2; no data directory created |
| Release CLI guard with sync enabled but no peer | Correctly rejected with exit 2; no data directory created |
| Owner wallet address/public account validation | PASS; output matched the expected owner account |
| Exhaustive `cargo test --all-targets --locked` | **Not completed**; interrupted during lengthy legacy v4 persistence tests so the post-fix targeted tests and isolated Release build could be run. No full-suite pass is claimed. |
| `npm test` under `contracts/launch-asset` | Not run; `node_modules` was absent and no dependencies were installed. |

Release compilation still prints existing dead-code/unused-helper warnings in unrelated candidate test modules; they did not prevent the build.

## 8. Release decision

The two discovered runtime-path defects are corrected and the affected node target, wallet, Genesis, market tools and independent policy oracles passed their focused validations. **Do not set or report `mainnet=true` on the current single-node instance.** The honest next milestone is to provision one independently operated and externally reachable seed, verify its static key and exact profile, then prove authenticated synchronization between separate hosts while keeping RPC/transaction services private. Only after that should a reproducible multi-node release be considered; real market trading and Trust Wallet integration are separate follow-on milestones.
