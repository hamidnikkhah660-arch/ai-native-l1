# CP-0412 - Real Ed25519 Transaction Through QZBE v2

Date: 2026-10-26

Status: **candidate-only integration regression; no production node runtime or public network change**

## Gap closed

The CP-0410/CP-0411 QZBE loopback and store tests used an injected test authenticator. They proved body-bound PoW, framing, persistent submission, atomic rejection and replay, but did not prove that the repository's real Ed25519 TXN2 signing/verifying adapters work end-to-end inside QZB4 v2/QZBE.

## Test added

qzbe_v2_real_ed25519_transaction_mines_transfers_rejects_bad_signature_and_replays uses a deterministic test-only Ed25519 seed and derives the sender account from its public key. It explicitly constructs a QZGM Genesis manifest and QZCP issuance profile, then configures the existing Ed25519TransactionAuthenticator with the matching account/public-key binding.

Two independent local QZBE persistent stores use the same Genesis/profile and a non-MAX target ([0xEF; 32]). The test:

1. signs a normal transaction with the repository's Ed25519TransactionSigner;
2. builds a valid QZBE v2 envelope with the body-aware bounded miner and checks the final body-bound digest against the derived target;
3. sends only the framed envelope bytes through TCP loopback and lets the second store decode, verify the real signature and commit it independently;
4. constructs a second-height body with a deliberately invalid short signature using a permissive test-only producer verifier, transfers it over loopback, and confirms the receiving store rejects it without changing tip, height, state root, generation or archive length;
5. sends a correctly signed nonce-2 successor and confirms both stores converge; and
6. closes/reopens both data stores and confirms replay reproduces the same canonical tip and state root.

The test-only signer seed and permissive producer verifier are fixtures only. The receiving node always uses the real configured Ed25519 verifier.

## Validation and remaining gates

Local validation passed on this exact working tree: `cargo +stable fmt --all -- --check`; `cargo +stable check --all-targets --locked --offline`; and `cargo +stable test --all-targets --locked --offline` with **831 library tests passed**, both node harnesses **36/36**, the QZBE smoke binary **6/6**, and all other binary/integration targets passing with zero failures. The focused CP-0412 regression passed, the offline persistence/restart smoke passed, and the public-docs/checksum preflight passed (**53 README-relative links, 383 Git-index checksum entries**). Fresh GitHub Actions CI on the exact CP-0412 commit remains pending.

This is a TCP-loopback test helper, not the production peer transport or authentication handshake. It does not connect QZBE to canonical node listeners, mempool or runtime fork choice. The external CAS provider remains a fixture, and there is no independently administered monotonic anti-rollback floor or independent security audit.

The QZGM Genesis used here is the existing candidate Genesis and includes its proposed one-billion-coin owner allocation. The local test harness has no public listener, no market or external value, and no production issuance; this regression must not be described as a zero-balance QVDN devnet or as mainnet launch approval. A separately versioned, fully bound QZBE zero-value profile/runtime remains a distinct design gate.

No email has been sent and no auditor, provider, node operator or legal adviser has been contacted or engaged.