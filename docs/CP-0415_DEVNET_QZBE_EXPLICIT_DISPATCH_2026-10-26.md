# CP-0415 - explicit QZBE v2 dispatch in devnet_node

Date: 2026-10-26
Status: **Devnet executable entrypoint dispatch verified; QZBE store/consensus remains isolated; no public launch authorization**

## Scope

The `devnet_node` binary now recognizes exactly one opt-in leading subcommand, `--qzbe-v04-peer-smoke`, and dispatches only that command's remaining arguments into the same strict QZBE v2 peer runtime exercised in CP-0414. With no exact leading token, the binary continues to call the pre-existing `private_testnet_node::main_devnet()` path. The old PTB2/PFS2 mode is not reinterpreted as QZBE, its flags are not silently accepted by the QZBE parser, and there is no fallback from a failed QZBE initialization into the legacy runtime.

The shared QZBE parser now accepts an explicit token vector as well as the standalone binary's process arguments, avoiding argument rewriting or duplicated argument validation between the two entrypoints. The `devnet_node` dispatch emits a fail-closed error and exits nonzero if the explicit QZBE candidate fails to initialize.

## Local evidence

- `cargo +stable fmt --manifest-path src/native/pow_bench/Cargo.toml --all`: passed.
- `cargo +stable check --manifest-path src/native/pow_bench/Cargo.toml --bin devnet_node --bin qzbe_v04_peer_node --locked --offline`: passed; pre-existing warnings from unrelated node candidate modules remain.
- `cargo +stable test --manifest-path src/native/pow_bench/Cargo.toml --bin devnet_node dispatch_tests::qzbe_mode_requires_the_exact_leading_subcommand --locked --offline`: **1 passed, 0 failed**. The selector recognizes only the exact leading subcommand and preserves ordinary options/other modes.
- `simulations/cp0415_devnet_qzbe_dispatch_transaction_loopback.ps1`: **passed against the Windows release `devnet_node.exe`, exit code 0**. The script invokes `devnet_node --qzbe-v04-peer-smoke` for both nodes, confirms public bind denial, sends a valid Ed25519-signed 2,500-atom transfer, verifies the receiver rejects a valid-PoW envelope with a tampered signature without mutating the height-0 snapshot, and confirms both independent stores reopen/replay to height 2 with identical root/tip and recipient balance 2,500 atoms. Output: `CP-0415 QZBE_DEVNET_ENTRYPOINT_SIGNED_TXN_TWO_NODE_PASS height=2 state_root=2c76f4f35b6835b1618747e8b3ae478bae30ad15bbe395b51a04d797c694f540 tip=679c83cb900358e2b9e860e5e88c408e7b3a89de5662130fbef4e8ced3b55ff2 recipient=4444444444444444444444444444444444444444444444444444444444444444 balance_atoms=2500 invalid_signature=atomically_rejected replay=matched public_bind=denied`.
- The parent CP-0414 code commit `dc39c3fdd12eae4e5534a4abaf86f5846e63272b` passed exact-head CI run [40278927677](https://github.com/hamidnikkhah660-arch/ai-native-l1/actions/runs/40278927677). CP-0415 exact-head GitHub Actions run [40281745961](https://github.com/hamidnikkhah660-arch/ai-native-l1/actions/runs/40281745961) then completed with **success** for `d9b1635c011e7faad2ed4eb53ea286a412fef969`: both full Rust validation and Windows (TXN4, PFM4, CP-0414 transaction integration, and CP-0415 `devnet_node` entrypoint dispatch) passed. This is evidence for CP-0415 only; CP-0416 profile-lock changes must run their own all-target and exact-head validation.

## Important boundaries

This is a controlled entrypoint integration, **not yet canonical QZBE state-machine integration**. The subcommand deliberately delegates to its isolated QZBE store and explicit local test profile; it does not integrate QZBE producer/importer dispatch into the existing PTB2/PFS2 or PMT4/PFM4 stores, and it does not unify the existing runtimes into one state source. The transfer registry still has one explicit test key, all listener/peer addresses must be loopback, local PoW and issuance inputs are test-only, and transactions outside the signed fixture are not exposed through a production mempool/API. The existing default `devnet_node` path is deliberately unchanged.

The runtime still lacks an independently operated production CAS/monotonic anti-rollback provider, multi-account key-registry management, public peer lifecycle/discovery, production ingress budgets, safe public RPC/observability, externally reviewed upgrade/migration and incident-response processes. Noise remains classical X25519/ChaChaPoly; no post-quantum/hybrid claim is made. Gates 2/8/12/13/14 remain open. This subcommand is not a public devnet, not a value-bearing release, and not Mainnet approval.

## Next required checkpoint

1. Run the complete locked/offline all-target suite and all three existing Windows loopbacks plus CP-0414 and CP-0415 against the exact new SHA in CI.
2. Before promoting this entrypoint beyond a loopback diagnostic, separate the immutable chain-profile dispatcher from the node runtime, then integrate QZBE's producer/importer into the canonical lifecycle with explicit profile-bound fork choice, transaction admission, durable storage and replay; no legacy-profile fallback or reinterpretation is allowed.
3. Design and qualify the production rollback boundary: independent operator-controlled CAS/monotonic anchor plus host-separated stale-restore/writer, split-brain, crash and storage-fault tests.
4. Only after canonical integration and Gate 8 verification, qualify a reproducible zero-value public devnet across at least three independent operators and independent security/release review. Mainnet/value-bearing activation is a later go/no-go decision.
