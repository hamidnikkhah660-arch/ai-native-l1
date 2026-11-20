# CP-0580 - QFP6 hybrid transaction-authentication candidate

**Date:** 2026-11-10
**Status:** Candidate implementation and focused test evidence; not runtime activation, production cryptographic approval, or Mainnet authorization
**Parent:** CP-0579 / SHA-256d cross-client conformance candidate

## Purpose

The existing QFP6 execution API accepts an injected \`TransactionAuthenticator\`, but the available wallet and default TXN2 signer use Ed25519-only account identities. CP-0580 adds a QFP6-specific self-contained envelope requiring both Ed25519 and ML-DSA-65 signatures over the same existing TXN2 signing digest.

This is a candidate authentication primitive. It is not yet selected by the QFP6 node executable, wallet, Genesis descriptor, or a frozen production identity policy.

## Q6HA v1 / suite 1 envelope

The signature envelope is exactly 5,365 bytes:

| Field | Size | Encoding |
|---|---:|---|
| Magic | 4 | ASCII \`Q6HA\` |
| Version | 2 | Unsigned big-endian, value 1 |
| Suite | 2 | Unsigned big-endian, value 1 |
| Ed25519 public key | 32 | Raw bytes |
| ML-DSA-65 public key | 1,952 | Raw bytes |
| Ed25519 signature | 64 | Raw bytes |
| ML-DSA-65 signature | 3,309 | Raw bytes |

Both signatures cover the same SHA-256 TXN2 signing digest, which commits the network ID, sender, recipient, nonce, amount, fee, and exclusive expiry. The transaction's sender account is derived under the domain \`AIN1-QFP6-ACCOUNT-ID-HYBRID-V1\\0\` from the suite ID and both public keys.

The verifier refuses:
- any missing, truncated, oversized, trailing, wrong-magic, wrong-version, or wrong-suite envelope;
- zero public keys or an account ID that does not bind both embedded keys;
- any invalid Ed25519 signature;
- any invalid ML-DSA-65 signature.

There is no Ed25519-only fallback in this authenticator. Legacy Ed25519-only addresses therefore do not silently become QFP6 hybrid addresses.

## Code and verification

- \`qrun_v06_hybrid_auth_candidate.rs\` contains the signer, self-contained envelope, dual verifier, domain-separated account ID and unit tests.
- \`lib.rs\` exports the module as a candidate.
- The common/legacy TXN2 signature ceiling remains **4 KiB**. Only QFB6 v0.6 \`NativeTransfer\` uses the explicit QFP6-specific 8 KiB encode/decode/transaction-ID bound. The legacy encoder and decoder continue to reject the 5,365-byte hybrid envelope, preserving their prior wire limit. QFB6 retains its separate 8 MiB encoded-block cap.
- Focused tests exercise real Libcrux ML-DSA-65 signatures alongside strict Ed25519 verification, QFP6-versioned TXN2 encode/decode and transaction-ID round-trip, a QFB6 block round-trip containing the hybrid transfer, rejection by the legacy 4 KiB codec, tamper rejection for both signatures, key/account binding, digest replay rejection, and rejection of legacy Ed25519-only envelopes.

## Security and compatibility limits

- \`LibcruxMlDsa65VerifierCandidate\` is still a candidate adapter and has not received an independent production cryptographic review. This CP does not claim a formally approved end-to-end post-quantum wallet or network.
- SHA-256d is a PoW hash selection, not a post-quantum signature scheme.
- The signer API currently takes two distinct 32-byte seeds. No production seed derivation, recovery phrase migration, hardware wallet, HSM/KMS transaction signer, or secure cross-device recovery ceremony is approved here.
- The existing QZKW1 Windows DPAPI wallet still signs Ed25519-only TXN2. It is not yet integrated with Q6HA and should not be used to claim compatibility with this hybrid account-ID domain.
- QFP6 canonical execution can accept an injected authenticator, but this module is not yet wired into the production node binary, transaction RPC, public mempool, peer ingress configuration, Genesis founder account, or a frozen Q6PN profile.
- No Genesis, node runtime, public P2P, mining, issuance, public balance, or value-bearing transaction is created or enabled by this change.

A later activation must freeze the account-ID/suite and wallet-derivation choices, migrate or re-provision the founder identity deliberately, qualify an independently reviewed verifier, and test cross-client vectors before any production consensus change.
