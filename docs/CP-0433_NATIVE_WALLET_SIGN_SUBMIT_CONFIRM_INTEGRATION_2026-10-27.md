# CP-0433 — Native-wallet signed transaction over QZTS/1, canonical receipt and replay

**Date:** 2026-10-27

**Status:** Local Windows Release integration passed against two QZBE runtime candidates. These are disposable candidate balances; this does not mean Mainnet, public RPC or market liquidity is live.

## What the test now proves

The repeatable runner simulations/cp0414_qzbe_authenticated_transaction_loopback.ps1 no longer injects the successful transaction into the sender's mempool at startup. It creates a fresh QZKW1 Windows CurrentUser DPAPI wallet, derives its account and public key, signs a transfer, starts the node with an explicit candidate-only bounded ingress wait, and submits the signed wire transaction through the actual QZTS/1 transaction listener.

The test requires all of the following:

1. The node's explicit loopback transaction-ingress listener is ready before wallet submission.
2. The native wallet's tx_id_hex matches the canonical TXID in the QZTS/1 admission acknowledgement, and the returned status is accepted.
3. A deliberately invalid signature is still rejected atomically.
4. The transaction appears in the receiver's canonical branch; the read-only receipt reports inclusion at height 1 and 2 current confirmations at height 2.
5. The wallet's own rpc-status, balance, and tx-status commands read back the candidate chain and the recipient's 2,500 atoms.
6. Both peers converge on the same tip and state root, and the restart/replay checks match.

The fixture uses a fresh random wallet, so TXID and state root intentionally change between runs. The last successful local run emitted:

- CP-0433 NATIVE_WALLET_SIGN_AND_QZTS_SUBMIT_PASS txid=11adeb5bc9e19f98271c402af7f0d1fac31fbc08bd22f3b144a3be038c570c7b status=accepted
- CP-0414 READ_ONLY_RPC_CANONICAL_TXID_RECEIPT_PASS ... block_height=1 confirmations=2
- CP-0432 NATIVE_WALLET_READ_ONLY_RPC_PASS height=2 balance_atoms=2500 ... confirmations=2 mainnet=false
- CP-0414 QZBE_AUTHENTICATED_TXN_TWO_NODE_PASS ... invalid_signature=atomically_rejected replay=matched public_bind=denied

The run completed with exit code 0 in 26.76 seconds.

## Safety and scope

This adds a test-only bounded wait flag that is accepted only with the isolated easy-PoW profile, a configured transaction, a transaction listener and a positive timeout capped at 30 seconds. It exists to make ingress testing deterministic; it is not a production consensus parameter or mining policy.

The QZBE node and its read-only RPC still bind loopback only. The transaction receipt is a report of the current candidate chain and may change after a reorg. It does not create an irreversible-finality guarantee, public Mainnet balances, or a transferable QZXB/USDT asset.

## Remaining release gates

Canonical production monetary Genesis and block-processing integration, independent external CAS/anti-rollback, independently hosted public nodes and fresh-node sync/recovery, public RPC hardening, wallet recovery/backup, explorer, independent security audit and legal/launch review remain open. No native QZXB/USDT pool or two-sided liquidity was created.
