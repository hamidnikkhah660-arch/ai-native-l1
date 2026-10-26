# CP-0432 — Native wallet read-only RPC query commands

**Date:** 2026-10-27

**Status:** Implemented and Windows Release integration-tested on the isolated QZBE candidate. Not public wallet/RPC availability or Mainnet approval.

## Wallet CLI behavior

The Windows native wallet now offers three read-only query commands:

- rpc-status --rpc 127.0.0.1:PORT
- balance --rpc 127.0.0.1:PORT --account-id-hex HEX64
- tx-status --rpc 127.0.0.1:PORT --txid-hex HEX64

These commands accept numeric loopback socket addresses only; hostnames and public IPs are rejected. The HTTP client bounds the response to 16 KiB, enforces HTTP 200, JSON content type and exact Content-Length, rejects duplicate Content-Length and transfer-encoding, and requires a JSON response with ok=true, mainnet=false and read_only=true. Balance and transaction queries verify that the node returned the exact requested account or TXID.

The wallet derives and prints the canonical TXID before submission, then compares the QZTS/1 admission ACK TXID with the signed transaction's independently derived ID. An ACK mismatch is an error. The CLI distinguishes the observed candidate-chain status (confirmed, pending, or not found in the retained suffix) and explicitly notes that confirmations can change after a reorganization.

This is a loopback-only candidate diagnostic. It does not expose private keys, does not turn the existing DPAPI wallet into a portable/recoverable Mainnet wallet, and does not make candidate coin balances spendable or market-valued.

## Validation

- Windows native wallet unit tests: 5/5 passed, including loopback scope, response bounds/framing, candidate identity checks and malformed HTTP/JSON rejection.
- Windows Release two-node scenario simulations/cp0414_qzbe_authenticated_transaction_loopback.ps1 passed:
  - CP-0414 READ_ONLY_RPC_GENESIS_PASS
  - CP-0414 READ_ONLY_RPC_SETTLED_STATE_PASS height=2 balance_atoms=2500
  - CP-0414 READ_ONLY_RPC_CANONICAL_TXID_RECEIPT_PASS txid=f394ee64df4b8cd8f03be6fb34baa3460ef2fc1e50d2a978862570258aac959a block_height=1 confirmations=2
  - CP-0432 NATIVE_WALLET_READ_ONLY_RPC_PASS height=2 balance_atoms=2500 txid=f394ee64df4b8cd8f03be6fb34baa3460ef2fc1e50d2a978862570258aac959a confirmations=2 mainnet=false
  - CP-0414 QZBE_AUTHENTICATED_TXN_TWO_NODE_PASS ... invalid_signature=atomically_rejected replay=matched public_bind=denied

The local scenario performs signed transaction creation, invalid-signature rejection, propagation, canonical inclusion, wallet-side receipt query, balance query and two-node replay. All amounts and receipts are disposable candidate state.

## Remaining release gates

QZXB is not yet ready for a real-money buy/sell. The monetary Genesis/issuance and production consensus path still need canonical runtime activation; Gate 8 external CAS/anti-rollback requires independent durable infrastructure and multi-host attack/recovery tests. Three independently operated nodes, public secured RPC, production wallet recovery, explorer, external security audit, legal/launch decisions and real two-sided market reserves remain open. No QZXB/USDT pool or real liquidity is created by this change.
