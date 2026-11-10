# CP-0585 — Q6TI transaction ingress into the supervised QFP6 mining lifecycle

**Date:** 2026-11-10  
**Parent:** CP-0584 / Q6TI-Q6TA wallet submission over authenticated QFP6 Noise  
**Status:** Implemented locally; targeted tests and all-target compile passed; pending exact-head GitHub CI and review. Candidate service integration only.

## Scope

CP-0584 introduced Q6TI/Q6TA framing and a bounded process-local QFP6 native-transfer mempool. The authenticated listener could recognize Q6TI frames, but the mining supervisor still routed every application frame through the Q6PB block-admission handler. As a result, the supervised ingress/mining lifecycle did not yet join wallet submissions to block-template selection.

CP-0585 closes that integration gap within the existing supervisor seam.

## Changes

- Adds application-frame dispatch in the QAP1 mining supervisor: Q6TI frames are sent to the transaction ingress handler; Q6PB frames continue through durable QAP1 block admission.
- Shares the Noise-session replay guard across application messages and retains the existing request-ID binding and Q6TA response validation.
- Creates a bounded default QFP6 transaction mempool for the supervisor lifetime.
- Uses the current canonical state to validate Q6TI submission and derives a candidate timestamp from wall-clock time, never earlier than the canonical parent timestamp plus one.
- Reconciles pending transactions after Q6PB canonical changes/reorgs and before template assembly.
- Appends ordered pending native transfers to the caller-provided mining template, respecting the QFP6 block-operation limit.
- Extends the mining-supervisor report with pending transaction count and byte totals at shutdown.
- Adds a regression test proving a valid Q6HA-signed NativeTransfer is selected into a mining template and is removed after canonical execution makes it non-pending.

## Local verification on heymed

Using the locked offline Cargo dependency set:

- `cargo fmt --check`: passed.
- `cargo check --all-targets --locked --offline`: passed.
- `git diff --check`: passed.
- QFP6 supervisor tests: **9 passed**.
- QFP6 Noise listener Q6HA-to-mempool integration test: **1 passed**.
- Q6TI/Q6TA ingress tests: **4 passed**.
- New mempool-to-mining-template regression test is included in the 9 supervisor tests and passed.

## Semantics and limitations

- Q6TA **Accepted** means only that the signed transaction is pending in this process-local mempool. It is not a mined block, confirmation, durable settlement or external finality.
- The mempool is **not persistent**. Pending transactions are lost on process shutdown/restart. A durable transaction journal, replay/recovery and idempotent reconciliation remain open work.
- The supervisor still requires an already bootstrapped and QAP1-recovered runtime, pinned Provider/Q6EA transports and verifiers, Q6PN/Q6TS/Q6CP/Genesis trust material, wallet/node identities and a caller-supplied protocol/system block-template policy. CP-0585 does not compose those dependencies into the `qrun_v06_node` executable.
- `qrun_v06_node` remains a preflight/read-only probe executable; this change does not enable `--run`, create or activate Mainnet, or start a public service.
- The Noise transport remains `Noise_XX_25519_ChaChaPoly_SHA256` (classical X25519), not post-quantum transport security. The ML-DSA-65 verifier path still requires independent cryptographic/security review.
- No public Devnet/Mainnet, genesis issuance, public QZXB balance, public value-bearing transfer, miner payout, public explorer history or QZXB/USDT liquidity is enabled or verified by this change.

## Next production gates

1. Persist the Q6TI mempool (or reconstruct it safely from an independently verifiable durable transaction journal) across restart and reorg.
2. Build a fail-closed production bootstrap that verifies external Q6PN/Q6TS/Q6CP/Genesis/Q6EA inputs, opens/recoveries the QFP6 durable store and QAP1 coordinator, loads protected node identities and invokes the supervisor.
3. Wire transaction fees, mining rewards, coin issuance and supply-cap enforcement through the same canonical durable path.
4. Add independently operated node qualification for the CP-0585 Q6TI path, fresh-node synchronization and crash/restart recovery.
5. Complete independent cryptographic review and post-quantum transport design before claiming quantum-secure networking.
6. Only after those gates: public Devnet, production security review, public Mainnet launch, wallet/RPC/explorer publication, then real market-maker and exchange liquidity work.

