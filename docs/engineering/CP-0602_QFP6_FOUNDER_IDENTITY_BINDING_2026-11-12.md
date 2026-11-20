# CP-0602 - QFP6 founder identity binding

Date: 2026-11-12  
Branch: `feat/cp0600-bootstrap-sync-startup`  
Status: candidate tooling implemented; local founder binding verified; Genesis remains incomplete.

## Scope

CP-0602 adds a fail-closed public-identity binding step to the QFP6 candidate package tool. It consumes a JSON file containing only the wallet's public account ID, Ed25519 public key, and ML-DSA-65 public key. It never reads a wallet file, mnemonic, DPAPI blob, or private key.

The account ID is independently recomputed using the QFP6 hybrid identity rule:

`SHA-256("AIN1-QFP6-ACCOUNT-ID-HYBRID-V1\\0" || suite_u16_be(1) || ed25519_public_key || mldsa65_public_key)`

The implementation checks the public-key lengths (32 and 1952 bytes), the supplied 32-byte account ID, and the candidate manifest state before binding. The manifest records the founder account and public keys with explicit candidate-only status, no private-key material, and no Genesis signature.

## Local verification

The original QFP6 wallet and the restored wallet were compared on the authorized Windows host; account identity and both public keys match.

The public identity was exported from the wallet's address command and bound into a local-only candidate copy at `%USERPROFILE%\\QZXB-QFP6-Candidate-Local`. The public identity JSON is stored outside the Git repository. No public key material was committed.

Observed results:
- `founder_identity_binding=VALID`
- Account ID: `b26ce4e019429ec524cb73d0464ec4c6a48d47ea8519b867d0374f07ab54b31d`
- `private_key_material_included=false`
- `genesis_signature_present=false`
- Candidate package validation correctly remains `INCOMPLETE` because all six required network artifacts are still absent.

## Safety boundary

This does not create or sign Genesis, authorize the 10B supply, activate mining, approve a trust floor, publish endpoints, or authorize Mainnet. The founder public-key binding is a candidate input only. Independent trust-root custody and review remain mandatory before any production Genesis signature.

## Validation

- Python bytecode compilation: pass.
- Candidate package self-test: pass, including rejection of a mismatched founder account ID.
- Real founder public-key binding against the local QFP6 wallet output: pass.
- Local candidate package remains fail-closed with six missing required artifacts.
