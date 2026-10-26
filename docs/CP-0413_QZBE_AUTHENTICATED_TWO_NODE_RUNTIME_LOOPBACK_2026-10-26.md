# CP-0413 - QZBE authenticated two-node runtime loopback candidate

Date: 2026-10-26
Status: **local integration candidate; isolated harness only; not canonical-node integration or public-launch authorization**

## What changed

Adds the dedicated `qzbe_v04_peer_node` binary and `simulations/cp0413_qzbe_authenticated_two_node_loopback.ps1` integration harness. The binary is intentionally isolated from the existing `devnet_node` and `private_testnet_node`. It requires an explicit Network ID, Genesis owner/miner identifiers, local issuance-schedule inputs, data directory, a Windows DPAPI-protected NPK1 Noise private-key file, and a pinned peer static public key. It refuses all non-loopback listen and peer addresses, rejects a non-dedicated store directory, limits this local run to 32 mined blocks/512 accepted TCP connections/one hour, and does not expose HTTP, RPC, wallet or market endpoints.

For this diagnostic candidate only, transactions are rejected, the issuance schedule is an explicit test input, and the PoW parameters use a deliberately easy 8 MiB local profile. The local QZBE block is produced and submitted through the candidate fork-store API; the recipient submits the encrypted envelope through the same validation/fork-choice/persistent-store interface. Both sides use `Noise_XX_25519_ChaChaPoly_SHA256`, network-bound prologue and operator-pinned peer identity. QZA4 application acknowledgements bind network/profile, the submitted block digest and the recipient's canonical height, tip, state root and store generation. The sender requires the peer to converge on exactly those fields. On shutdown, each independent store is dropped and reopened, and its recovered snapshot must exactly match the pre-reopen snapshot.

The shared Noise record limit is raised to the maximum of the old PTB2 and QZBE envelope bounds. This fixes a concrete 114-byte gap caused by QZBE's larger fixed header while preserving a strict upper bound; a regression test locks the relationship in place.

## Local evidence

- `cargo +stable fmt --manifest-path src/native/pow_bench/Cargo.toml --all`: passed.
- `cargo +stable check --manifest-path src/native/pow_bench/Cargo.toml --bin qzbe_v04_peer_node --locked --offline`: passed; existing warnings in other candidate modules remain.
- `cargo +stable test --manifest-path src/native/pow_bench/Cargo.toml --bin qzbe_v04_peer_node --locked --offline`: **2 passed, 0 failed**, including exact fail-closed loopback-address policy and ACK profile/width tests.
- `cargo +stable test --manifest-path src/native/pow_bench/Cargo.toml --lib devnet_noise_transport_candidate::tests --locked --offline`: **6 passed, 0 failed**, including the QZBE record-cap regression, peer-key pinning, network-prologue mismatch and tampered-record rejection.
- `simulations/cp0413_qzbe_authenticated_two_node_loopback.ps1`: **passed on Windows against release binaries**. It first verified `0.0.0.0` bind denial, provisioned two independent DPAPI-protected Noise keys, sent two QZBE blocks, confirmed peer ACK/state convergence, verified matching height-2 state root/tip on both separately persisted stores after reopen/replay, and cleaned temporary stores. Observed height-2 state root: `82fd7ac091f460860d99fdecc33f4f77f70c3e4ccefbd88410d86b15cd5056bf`; tip: `79d18d6ac273318f500e41e00f012475cd1400aa0f1b4f05e3159338b4a6b3cf`.
- Parent checkpoint commit `cd4ad167cab270eca2e621242752a92f6d6563cd` passed exact-head GitHub Actions run [40273947731](https://github.com/hamidnikkhah660-arch/ai-native-l1/actions/runs/40273947731). This evidence is for the parent, not the new CP-0413 changes. Fresh full-suite and exact-head CI evidence for CP-0413 must be recorded separately before considering this checkpoint validated.

## Explicit limitations / no-go boundary

This binary is a separate integration harness, not QZBE dispatch in the canonical node's actual producer/importer/runtime. Its easy PoW profile, no-transaction authenticator, locally supplied schedule and manually pinned loopback peers are exclusively test facilities. It does not implement transaction admission or signatures, peer discovery, long-lived peer/session management, identity rotation/revocation, public ingress budgets, public safe RPC, wallet/indexer/explorer, monitoring, canonical migration/upgrade or deployment automation. Noise uses classical X25519/ChaChaPoly; there is no post-quantum or hybrid-security claim. The local persistent store is not an independent anti-rollback trust anchor; production CAS provider and its operator are absent.

Gate 2 (frozen canonical monetary Genesis and schedule integration), Gate 8 (independent durable CAS/anti-rollback), Gate 12 (native EVM/RPC where it remains in product scope), Gate 13 (three or more independently operated zero-value public-devnet nodes) and Gate 14 (independent security/release/compliance qualification) remain open. This checkpoint authorizes no public bind, production issuance, sale, transfer of value, exchange/liquidity claim, Mainnet activation or merge. Passing this test is a prerequisite-sized integration result, not a security audit or a launch decision.

## Next required steps

1. Run the new Windows scenario in CI alongside the complete Rust format/check/all-target test suite; review and fix every failure on the exact candidate SHA.
2. Independently review this runtime design and then plan its integration with the canonical producer, importer, transaction admission, fork-choice, durable store and replay path, with compatibility tests proving legacy profiles cannot be silently reinterpreted or downgraded.
3. Select and deploy a genuinely independent, operator-controlled CAS/monotonic trust anchor; test stale restores, stale writers, split brain, lost writes, crash recovery and storage faults across separate hosts.
4. Only after Gates 2/8 are closed and external review is accepted, qualify a reproducible public zero-value devnet with independently operated nodes, safe observability/RPC, incident and upgrade procedures. Mainnet/value-bearing launch is a later explicit go/no-go decision.
