# CP-0414 - QZBE authenticated transaction loopback candidate

Date: 2026-10-26
Status: **local transaction/consensus integration checkpoint; isolated harness only; not canonical-node integration or launch authorization**

## What changed

Builds on the isolated two-node QZBE runner from CP-0413 and replaces its reject-all transaction policy with a single explicitly configured Ed25519 public-key registry. The Genesis owner ID is checked against the domain-separated account ID derived from that configured public key; the test signer never supplies a private key to either node. This fixture only supports one registered transaction sender and one pre-signed transfer in the first locally mined block; it is not the production mempool/admission service.

Adds `qzbe_v04_test_tx_signer`, a local-only helper that reads a short-lived 32-byte seed file, signs a canonical `Transaction` through the existing production signing-digest/signer API and returns the public key, sender account ID and signature (never the seed). The Windows integration script generates an ephemeral seed, signs a transfer of 2,500 atoms with a 7-atom fee and deletes the seed file before starting either node.

Before the valid transfer is mined, node A constructs a valid QZBE candidate, corrupts one byte in its transaction signature, recomputes the PoW nonce against the candidate's body-bound digest, and sends this adversarial envelope over a network-bound, peer-pinned Noise session. Node B's real QZBE store rejects the candidate through the configured transaction authenticator, sends an encrypted rejection ACK, and reports the exact unchanged genesis snapshot (`height=0`, tip/root and generation unchanged). The same two nodes then transfer the valid signed transaction and a successor block. Both independently persisted stores reopen and replay to height 2 with identical canonical tip/state root and the observed recipient balance exactly 2,500 atoms.

The local node remains bound to `127.0.0.1`; the harness positively asserts that `0.0.0.0` is rejected before startup. PoW remains deliberately easy and memory-hard (8 MiB) for test execution. The issuance schedule is an explicit test input. Neither value represents production economics or production mining settings.

## Local evidence

- `cargo +stable fmt --manifest-path src/native/pow_bench/Cargo.toml --all -- --check`: passed after the candidate changes.
- `cargo +stable check --manifest-path src/native/pow_bench/Cargo.toml --bin qzbe_v04_peer_node --bin qzbe_v04_test_tx_signer --locked --offline`: passed; repository has pre-existing warnings in unrelated candidate modules.
- `cargo +stable test --manifest-path src/native/pow_bench/Cargo.toml --all-targets --locked --offline`: **passed, exit code 0**. The library suite reported **831 passed, 0 failed**; `devnet_node` tests 36/36, `private_testnet_node` tests 36/36, QZBE smoke 6/6, the new peer runtime 2/2, the signing helper 1/1, and every remaining binary/integration target passed.
- `simulations/cp0414_qzbe_authenticated_transaction_loopback.ps1`: **passed on Windows release binaries, exit code 0**. Final output: `CP-0414 PUBLIC_BIND_GUARD_PASS` and `CP-0414 QZBE_AUTHENTICATED_TXN_TWO_NODE_PASS height=2 state_root=0792a6e8e784489dbb578d15bd37348153a1fc22a98a5e0a1dab33eb853649ba tip=4292e82673812674a4cdbed49e96184c13511bf3026a22fc8e251d3df5ac5400 recipient=4444444444444444444444444444444444444444444444444444444444444444 balance_atoms=2500 invalid_signature=atomically_rejected replay=matched public_bind=denied`.
- Public docs/checksum preflight passed against the staged Git index: **55 README-relative links** and **388 checksum entries**, with all other documentation guards passing.
- Parent code commit `6784f14b0d28bcfd8946dc9cc4d30a526ca2c218` passed exact-head CI run [40277316899](https://github.com/hamidnikkhah660-arch/ai-native-l1/actions/runs/40277316899). CP-0414 still needs its own fresh exact-head GitHub Actions run; the parent run is not evidence for the new changes.

## Explicit limitations / no-go boundary

This is still an isolated local test runtime, not QZBE dispatch in the actual `devnet_node`/`private_testnet_node` producer/importer path. The registry contains only one explicitly trusted Ed25519 key; there is no public transaction service, mempool policy, rate limiting, nonce-gap/replacement policy, multi-account registry management, wallet integration, peer discovery or long-lived peer/session lifecycle. The signer helper and ephemeral file belong to the test script only, not a production key-management workflow.

The local fork store provides persistence/replay, not an independently operated monotonic anti-rollback anchor. A production CAS provider, host-separated failure/restore tests, canonical monetary Genesis/schedule finalization, compatibility/downgrade tests, a reproducible public zero-value devnet, independent security audit and operating procedures are still missing. Noise remains classical X25519/ChaChaPoly; no post-quantum/hybrid claim is made.

Gates 2 (frozen canonical monetary Genesis and schedule integration), 8 (independent durable CAS/anti-rollback), 12 (EVM/RPC if retained in scope), 13 (three or more independently operated zero-value public-devnet nodes) and 14 (independent security/release/compliance qualification) remain open. This checkpoint authorizes no public bind, production issuance, sale, value transfer, exchange/liquidity claim, Mainnet activation or merge.

## Next required work

1. Re-run the complete locked/offline all-target test suite, format/check, documentation/checksum preflight and the Windows transaction loopback on this exact candidate SHA; keep CI evidence keyed to that SHA.
2. Implement QZBE dispatch in the canonical producer/importer lifecycle behind an explicit, immutable chain profile, with no fallback or reinterpretation of legacy PMT/PTB profiles. Reuse the existing transaction admission and real fork-choice/persistence machinery instead of creating a second source of truth; test valid/invalid signatures, body mutation, competing forks/reorg, restart/replay and incompatible-profile rejection.
3. Complete a separate integration design for reconciling fork choice with a durable monotonic anchor; choose/deploy an independent operator-controlled CAS and test stale restores/writers, split-brain and crash/storage failures on separate hosts.
4. Only after the canonical runtime and Gate 8 are independently verified, run a public **zero-value** devnet with at least three independent operators, bounded public ingress, safe observability/RPC, reproducible release artifacts, incident response and upgrade/rollback procedures. Mainnet/value-bearing activation is a later explicit go/no-go decision.
