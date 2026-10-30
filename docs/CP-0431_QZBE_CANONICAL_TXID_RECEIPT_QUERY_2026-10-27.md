# CP-0431 — QZBE canonical TXID receipt query

**Date:** 2026-10-27

**Status:** Implemented and Windows Release integration-tested for the isolated QZBE candidate. Not a public RPC deployment, irreversible finality guarantee, or Mainnet approval.

## Scope

The loopback-only read-only RPC adds GET /v1/transaction/{64-hex-TXID}. It reports one of three explicit states:

- confirmed: the transaction ID was found in an envelope on the current canonical parent-linked branch suffix, with the inclusion height and current confirmation depth.
- pending: the transaction remains in the validated local mempool and was not found in the current canonical suffix.
- not_found_in_retained_suffix: the TXID is absent from the searchable canonical suffix and mempool. The response includes search_floor_height, because a checkpointed node cannot claim that transactions earlier than its retained base never existed.

The lookup decodes retained envelopes under the active QZBE consensus profile and traverses ancestry from the selected canonical tip toward the trusted base checkpoint. It does not label a transaction found only in an orphaned branch as confirmed. Response metadata includes the observed canonical height, tip and state root plus mainnet:false and read_only:true.

Confirmation depth is an observation of the currently selected candidate chain. It is not a promise of irreversible settlement; a valid higher-work reorganization can reduce or remove those confirmations. The handler is still loopback-only and bounded. It is not meant to be exposed publicly.

## Validation evidence

- QZBE focused unit suite: 12/12 passed.
- Transaction signer test suite: 1/1 passed; test signing helper emits the canonical TXID derived by the native transaction-ID function.
- Repeatable Windows Release integration simulations/cp0414_qzbe_authenticated_transaction_loopback.ps1 passed:
  - CP-0414 PUBLIC_BIND_GUARD_PASS
  - CP-0414 READ_ONLY_RPC_GENESIS_PASS
  - CP-0414 READ_ONLY_RPC_SETTLED_STATE_PASS height=2 balance_atoms=2500
  - CP-0414 READ_ONLY_RPC_CANONICAL_TXID_RECEIPT_PASS ... block_height=1 confirmations=2 (the integration now uses a fresh native-wallet TXID per run; see CP-0433)
  - CP-0414 QZBE_AUTHENTICATED_TXN_TWO_NODE_PASS ... invalid_signature=atomically_rejected replay=matched public_bind=denied

The scenario verifies initial zero balance, canonical inclusion and confirmation calculation, matching tip/state-root views, invalid-signature atomic rejection, two-node propagation, durable reopen/replay and non-loopback bind rejection.

## Remaining release gates

The queried chain is a disposable local candidate network. The monetary Genesis/runtime is not yet activated as the canonical production runtime. Gate 8 external CAS/anti-rollback, independently operated nodes, fresh-node synchronization and recovery, public RPC hardening, wallet confirmation UX, explorer, independent security audit and launch/legal review remain open. There is no native QZXB/USDT market or two-sided liquidity from this work.
