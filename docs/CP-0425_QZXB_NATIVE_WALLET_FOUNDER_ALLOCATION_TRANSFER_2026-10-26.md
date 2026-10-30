# CP-0425 — QZXB Native Wallet and Founder Allocation Candidate Transfer (2026-10-26)

## Scope

This change adds a Windows-local native QZXB wallet CLI and a repeatable two-node test that uses the wallet to sign a transaction against the QZBE v0.4 candidate Genesis owner account. It is an engineering gate, not a Mainnet launch or a claim that real coins have been issued.

## Wallet implementation

- Binary source: `src/native/pow_bench/src/bin/qzxb_wallet.rs`.
- Format: QZKW1, with a versioned header binding the Ed25519 public key and domain-separated account ID to a Windows CurrentUser DPAPI-protected 32-byte seed.
- Key generation uses the operating system's `getrandom` API. The secret is not accepted via command-line arguments and is not printed.
- `create --output ABSOLUTE_PATH` refuses to overwrite an existing wallet; it persists a protected payload via a temporary file and an atomic create-if-absent hard link.
- `address --wallet ABSOLUTE_PATH` unprotects and validates the key locally, then verifies the stored public key and account ID are derived from the seed.
- `sign-transfer` signs the existing Ed25519 TXN2 encoding for an explicit network ID, recipient, nonce, amount, fee, and expiry. It emits the signed transaction bytes but does not submit or broadcast them.
- The seed is cleared from the wrapper-owned buffers on scope exit. DPAPI is Windows-user/profile-bound protection at rest, not an HSM and not protection against compromise of that logged-in user or a running process.

## Reproducible integration test

Run on Windows with stable Rust:

```powershell
cargo +stable fmt --manifest-path .\src\native\pow_bench\Cargo.toml --all -- --check
cargo +stable test --manifest-path .\src\native\pow_bench\Cargo.toml --bin qzxb_wallet --locked
./simulations/cp0425_qzxb_founder_wallet_local_transfer.ps1
```

The script creates an ephemeral QZKW1 wallet and DPAPI-backed Noise peer keys under a fresh system temporary directory, and removes the directory in its `finally` block. It runs two independent local-only QZBE nodes on loopback with the default `QZXB_V04_ARGON2ID_64MIB` profile (no `--test-easy-pow`), mines to height 2, and checks that both nodes converge on the same tip/state-root after replay. It signs and includes a transfer of 100,000,000 candidate QZXB (10% of the 1,000,000,000-coin Founder allocation cap) and verifies that the receiver and sender-side node both report the expected recipient balance.

Success markers:

- `CP-0425 FOUNDER_GENESIS_ALLOCATION_AND_LOCAL_TRANSFER_PASS`
- `CP-0425 CONTINUOUS_MINING_HEIGHT_2_PASS`
- `CP-0425 TWO_NODE_RESTART_REPLAY_CONVERGENCE_PASS`

## Tokenomics and custody boundaries

The allocation policy caps total supply at 10,000,000,000 QZXB and the Founder allocation at 1,000,000,000 QZXB (10%). Those values are policy/Genesis-candidate parameters. The integration above exercises that candidate allocation and transaction execution in a disposable local test chain only; it does not credit the persistent wallet with a Mainnet balance and does not create a redeemable asset.

The persistent developer-host wallet, when provisioned explicitly, is outside the repository at `%LOCALAPPDATA%\QuantumZXB\wallets\founder.qzw1`. Its protected blob is tied to the current Windows user; it has no portable recovery/seed-backup workflow yet. Do not use it as a production custody solution without a reviewed backup/recovery design and independent key-management review.

## Public launch blockers remain open

- `devnet_node` still defaults to the legacy PTB2/PFS2 Devnet path; QZBE v0.4 is dispatched through an opt-in diagnostic subcommand with a dedicated candidate store.
- QZBE peer networking remains loopback-only and configured around statically pinned trusted peer keys.
- The native wallet signs TXN2 transactions locally but has no public RPC, untrusted-peer discovery, broadcast, fee-market, or confirmed production-network connection.
- The candidate mempool/Genesis/fork-choice/checkpoint work is not yet a single public canonical runtime with externally anchored anti-rollback/finality.
- No production Mainnet launch, issued Founder balance, independent external CAS deployment, external security audit, or real QZXB trading market is verified by this work.

No liquidity pool, bridge, ERC-20 proxy, or QZXB/USDT, QZXB/USDC, QZXB/BTC, QZXB/ETH, QZXB/SOL, QZXB/ADA, or QZXB/BNB market is created by this change.
