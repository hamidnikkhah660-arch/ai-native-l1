# CP-0468 — Current Wallet-Bound Identity Manifest Reconciliation

Date: 2026-10-29

Status: **Identity documentation reconciled for the current source candidate; public Mainnet remains NO-GO.** This record does not authorize deployment, certify production consensus, or claim market value.

## Why this record exists

The active QRun v0.5 work branch and the earlier CP-0450 identity artifact describe different candidate identities. The earlier manifest was not silently overwritten because it is an auditable historical record used by its own independent SHA-256 checker. Current operator/release material must distinguish it from the wallet-bound identity encoded by the current runtime.

## Current runtime identity

The new machine-readable snapshot is [qrun_v05_wallet_bound_mainnet_identity_candidate.json](../profiles/qrun_v05_wallet_bound_mainnet_identity_candidate.json). It records the following constants from `src/native/pow_bench/src/bin/qrun_v05_pow_local_node.rs`:

- Network ID: `8b5d169205ac49cb9866a9d27ff1a6c3c2571fca65f634854c41c112e506aebb`
- Genesis ID: `91229b7d21b23cee83f00cec53a566ef1b30db70c644c1e9d05a431c1acf4dbc`
- Profile ID: `75596fa188dc308088efc6b138e9fcd50be6de82ec2bc117c13e81d7eebfdb09`
- Genesis state root: `a44e545c2cd8fa4e56e228f4f242cbf5445b1cc983c7b1f8fe89c5b42aef88d7`
- Genesis owner account ID: `a14d67bd195c6a0044bedac8532e742811f92501630764d73a98b2f0cc335fdd`
- Public owner key: `fca65e26f596fa60674f5ec35808ec80b317a701e97feee343d85007713bd93f`

This is a fixed-supply candidate identity: 10,000,000,000 QZXB at Genesis, zero post-Genesis minting and zero block subsidy. The manifest parity checker compares every identity field to the source constants, checks the fixed-supply invariants, and fails if the source-level Mainnet release gate is opened. It is deliberately labelled a parity check, not an independent security audit or an independent recomputation of the full protocol.

## Historical identity retained

The prior [CP-0450 identity candidate](CP-0450_QRUN_V05_IDENTITY_CANDIDATE_2026-10-28.md) and its manifest use network ID `70fdcdbe6f0afa1edb0c4fb4a85252831376f7b9ecf2a13a86dcf61979cdcad7`, owner account ID `eee2e72882d770ab6fd7815c905b49e39650c74e8f121b26cbd49e333a3715c8`, and a different Genesis root/commitment. Those values are historical and must not be mixed with the current wallet-bound runtime identity.

## Validation performed

- `cargo test --all-targets --locked --offline` on the active work candidate completed with exit code 0.
- `cargo build --release --locked --offline --bin qrun_v05_pow_local_node --bin qrun_v05_noise_keygen` completed with exit code 0.
- Invoking the newly built release node with `--mainnet` was rejected with exit code 2 before key reads, data-directory creation, or socket binding. The error named the unresolved production blockers.
- No QRun node was listening on TCP ports 49339–49341 during the live host check. No independent peer, external P2P reachability, independent security review, or public market is claimed.

The full test suite and release build are necessary engineering checks but do not close release gates.

## Remaining hard blockers

1. Freeze and independently calibrate production consensus across at least three genuinely independent operators.
2. Complete full-history validation/recovery or an independently verifiable checkpoint-rollover and monotonic anti-rollback system.
3. Complete multi-host transaction, restart, reorg, partition/rejoin and adversarial peer tests.
4. Obtain independent protocol/security review and publish reproducible source/binary provenance.
5. Verify public P2P reachability and independent monitoring/recovery on the selected, explicitly test-only devnet configuration before any public-devnet launch.
6. Establish a real settlement path and actual market counterparties/reserves before claiming QZXB/USDT trading.

**Decision:** preserve `QRUN_MAINNET_RELEASE_APPROVED = false`. Do not advertise a value-bearing QRun Mainnet, claim the 10B local Genesis balance is publicly spendable, or invent a QZXB/USDT price/pool.
