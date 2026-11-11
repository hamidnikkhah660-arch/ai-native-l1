# CP-0587 - Q6TI cross-host admission and Q6MJ restart recovery
Date: 2026-11-11

## Objective

Extend the existing QFP6/QAP1 NetBird qualification so it tests the CP-0586 durable Q6TI pending-transaction journal across two independent processes on separate hosts. The test must not equate Q6TA Accepted with mining, confirmation, QAP1 finality, or a production transaction.

## Exact scope

- Base revision: CP-0586, `83185d4a243be83503321228d75f9c797f796e0e`.
- Node A runs the existing local QFP6 Provider and Q6EA test services and acts as the pinned Noise peer.
- Node B is an ephemeral Windows GitHub Actions runner enrolled into the private NetBird overlay.
- Node A sends one Q6PB block admission and a replay, then sends a signed Q6HA native-transfer transaction over the same pinned Noise session using Q6TI/Q6TA.
- Node B uses the actual Q6TI application dispatcher, hybrid transaction authenticator and Q6MJ journal. It must persist the accepted pending transaction before returning Q6TA Accepted.
- A second independent Node B process reopens the same local QFP6 store and Q6MJ journal, first recovers the canonical QAP1 state, then restores/revalidates the pending transfer against that recovered state.
- The second process must report the exact same TXID and one pending transaction. The journal generation must advance exactly once during startup reconciliation.
- The QAP1 canonical height, state root, manifest anchor and generation must remain identical before and after process restart.

## Expected evidence markers

Node A:
- `QFP6_QAP1_NODE_A_Q6TI_ACCEPTED=PASS`
- `QFP6_QAP1_NODE_A_Q6TI_DUPLICATE=PASS`
- `QFP6_QAP1_NODE_A_Q6TI_TXID=<64 hex>`

Node B before restart:
- `QFP6_Q6MJ=PASS`
- `QFP6_Q6MJ_PENDING_COUNT=1`
- `QFP6_Q6MJ_GENERATION=4`
- `QFP6_Q6MJ_TXID=<same 64 hex>`

Node B after restart:
- `QFP6_Q6MJ_RESTART=PASS`
- `QFP6_Q6MJ_RESTART_PENDING_COUNT=1`
- `QFP6_Q6MJ_RESTART_TXID=<same 64 hex>`
- Journal generation advances from 4 to 5 after revalidation/persistence.

## Security and interpretation

- Test-only deterministic Q6HA seeds and candidate testnet Genesis are used only as isolated qualification fixtures. They are not wallet credentials and do not create QZXB mainnet value.
- The Node B listener is reached over the private NetBird overlay and a pinned Noise XX identity. Noise currently uses classical X25519; this is not post-quantum transport.
- Provider/Q6EA pins and ML-DSA-65 receipt keys are ephemeral test-service material for this run, not externally governed production trust.
- Q6TA Accepted means the signed transaction is pending and journaled only. It is not mined, confirmed, finalized, or tradeable.
- The Q6MJ checksum is local integrity evidence, not an external anti-rollback anchor.
- This qualification does not enable `qrun_v06_node --run`, public Devnet/Mainnet, public issuance, production mining/payouts, RPC/explorer publication, or QZXB/USDT settlement.

## Release gate

This branch remains a Draft engineering candidate until exact-head CI and the updated two-host NetBird run pass with the Q6TI/Q6MJ markers above. Missing Actions secrets, unavailable second-host connectivity, or any marker mismatch must fail closed. Do not merge or describe the result as Mainnet readiness.
