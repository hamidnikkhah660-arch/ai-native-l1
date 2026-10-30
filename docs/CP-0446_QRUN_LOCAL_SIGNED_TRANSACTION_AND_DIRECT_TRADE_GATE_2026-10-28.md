# CP-0446 - QRun local signed-transaction acceptance and two-node test (2026-10-28)

Status: candidate integration tests pass; no public network or value-bearing market is claimed.

## Validation performed on Windows stable Rust

Commands run from `src/native/pow_bench`:

```powershell
cargo +stable test --locked --bin qrun_v05_pow_local_node tx_ingress_tests::qzts_signed_wallet_request_executes_and_persists_canonical_receipt -- --exact --nocapture
cargo +stable test --locked --bin qrun_v05_pow_local_node tests::two_pow_nodes_sync_signed_transfer_over_real_loopback_socket -- --exact --nocapture
```

Results: both tests passed. The single-node test submitted a signed TXN2 request via QZTS/1, admitted and mined a candidate block at height 1, persisted a canonical transaction receipt, and verified that the transaction was canonically included. Example test-run transaction ID: `84f71a2c3122dbc70b7182fd180bc6093c612585878df3fbe70b473c99b63e79`; test identities/IDs are fixture-generated and are not a public transaction hash. The second test passed the signed transfer over a real loopback TCP socket between two independent candidate runtimes and completed its assertions.

## What this does and does not prove

This validates a QRun candidate wallet-signature / transaction-ingress / block / receipt code path, not a transaction on a public Mainnet. The node still advertises `mainnet=false`, uses a deliberately trivial `MAX` PoW smoke target, and restricts RPC, transaction ingress and block peers to loopback. The existing tests use isolated fixture keys; this is not a transfer broadcast from the owner's persistent wallet and must not be described as such.

## Direct P2P trade requirements

Bitcoin-like direct trading does not require a centralized exchange, but it does require independently reachable and independently operated validating peers, secure peer authentication and chain sync, a frozen production Genesis/profile, defensible PoW retargeting and timestamp policy, production wallet recovery, public explorer/receipt verification, and a reliable fee/confirmation policy. Buyer and seller must agree separately on the fiat/other-asset payment terms; a chain transfer by itself does not create or prove a USD payment. QRun's current isolated candidate does not satisfy those launch requirements.

The current CP-0437 policy is the full 10B-at-Genesis owner allocation, zero later subsidy/issuance and no extra pre-issued category envelopes. Do not combine that with the superseded founder-1B split without a new reviewed policy and a different Genesis commitment. No actual buyer, fiat payment, two-sided market reserve, public QZXB trade or market price was created by these tests.
