# CP-0671 — Owner Wallet DPAPI Identity Reconciliation

Date: 2026-11-15  
Project: AI-NATIVE L1 / QRun-QFP6  
Status: **legacy owner wallet verified locally; QFP6 hybrid owner identity not yet reconciled; no transfer performed**

## 1. Discovered protected wallet

A historical owner handover file D:\Projects\Digital_Currency_Identity_Notes\0f521debfc16bd0fa2cbe44be3968757027.txt names this wallet path:

%LOCALAPPDATA%\QuantumZXB\wallets\founder.qzw1

Resolved path on the connected Windows profile:

C:\Users\ASUS\AppData\Local\QuantumZXB\wallets\founder.qzw1

Observed metadata:
- File size: 336 bytes.
- Last-write time: 2026-10-26 23:39:17.
- Header: QZKW, version 1.
- ACL lists SYSTEM, local Administrators and the current Windows account.
- The official local qzxb_wallet address --wallet <path> loader opened the file successfully under the current Windows user and returned only public identity fields.
- Public key: 191198b57767857789f9b2bda709cce5991e55431b1650cedb4ffae324060c59
- Account ID: 0f521debfc16bd0fa2cbe44be396875702750fb3baed3720f18bd0ad8bc74c88
- The emitted output explicitly stated private_key_output=none.

The account ID exactly matches the old owner handover note. This proves the local DPAPI-protected QZKW1 wallet can be opened by this Windows profile and that its public identity matches that handover note. It does not prove this is the newer file the owner described by the alternate name QZXB-founder.qzw; that exact filename was not found in the targeted wallet/project locations checked.

## 2. Identity mismatch with current QFP6 candidate manifest

The current candidate manifest release/qfp6-candidate/manifest.json records a different owner identity:
- Candidate account ID: b26ce4e019429ec524cb73d0464ec4c6a48d47ea8519b867d0374f07ab54b31d
- Derivation: AIN1-QFP6-ACCOUNT-ID-HYBRID-V1
- Candidate Ed25519 public key begins 3aaf5221...
- Candidate ML-DSA-65 public key is bound.
- genesis_signature_present=false.

The discovered QZKW1 account ID 0f521... and public key 191198... do not match the QFP6 candidate owner account/public-key binding. These must not be treated as the same identity or used interchangeably. No owner Genesis allocation was reassigned and no signature was produced.

## 3. DPAPI keys that are not owner wallets

The separate C:\Users\ASUS\AppData\Local\AI-NATIVE-L1\operator-vault inventory explicitly identifies keys\noise-static-devnet.npk as a LOCAL-DEVNET-ONLY Noise transport key protected by CurrentUser DPAPI. The sealed owner-wallet folder states that no owner key has been generated there. That Noise key is not a wallet key and must never authorize owner funds.

## 4. QFP6-compatible local wallet restoration path

The candidate wallet binary has a separate QZKW2 hybrid path:
- restore-qfp6-hybrid --output ABSOLUTE_PATH
- address-qfp6-hybrid --wallet ABSOLUTE_PATH

The restore command reads a 12-word English BIP39 phrase via masked console input, derives domain-separated Ed25519 and ML-DSA-65 seeds, and writes a QZKW2 hybrid wallet using Windows CurrentUser DPAPI. It reports public identifiers only and does not save the recovery phrase to disk. QZKW2 is not a QZKW1 upgrade in place; it is a distinct derivation/account identity. Existing QZKW1 must remain untouched.

Suggested new file path (must not already exist):
%LOCALAPPDATA%\QuantumZXB\wallets\QZXB-founder.qzw

The exact restore command must be executed by the owner in a local PowerShell console; the phrase must never be sent through chat, command-line arguments, files, screenshots or logs. After restoration, run address-qfp6-hybrid on the new file and share only the returned public account ID and public keys.

The resulting public identity must be compared with the existing CP-0651 manifest candidate identity. If they match, the owner key binding can proceed to independent review. If they differ, the owner must explicitly choose/confirm the intended owner account before any manifest change or Genesis signing. Never silently replace the owner's identity.

## 5. Transfer / chain status

No transfer was attempted:
- CP-0651 Genesis snapshot remains MISSING.
- Q6GD descriptor, Q6CP consensus profile, Q6PN network profile and bootstrap peers remain MISSING.
- Owner Genesis signature remains absent.
- production_authorized=false, mainnet_status=NOT_AUTHORIZED.
- No active listener on TCP 30333 was found at the last host inspection.
- The native QZXB network is not available as a live value-bearing chain; the existing wallet is local key custody only, not proof of an on-chain balance.

No transaction hash or balance is claimed.

## 6. Public website / PR status

PR #195 remains OPEN and BLOCKED by the repository's one-approval rule. All three required CI checks passed. The repository currently has only the owner as an authorized collaborator and disallows auto-merge. The public GitHub Pages homepage/economics/status were still serving old content during the last HTTP check (HTTP 200, CP-0651 absent from homepage/economics). The site update is not live until an independent approving review, merge and a successful Pages deployment are observed.

Decision: preserve QZKW1; do not sign or transfer using it against the current candidate owner identity. Restore the same owner-held mnemonic to a separate QZKW2 file locally, compare public outputs to the CP-0651 owner binding, and only then proceed to owner Genesis signing after the final chain artifacts are frozen and independently reviewed.