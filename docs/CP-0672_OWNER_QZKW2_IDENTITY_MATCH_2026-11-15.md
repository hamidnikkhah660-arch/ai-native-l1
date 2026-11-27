# CP-0672 — Owner QZKW2 Identity Match
Date: 2026-11-15
Project: AI-NATIVE L1 / QRun / QFP6
Repository: `D:\Temp\ASUS\QRUN_QFP6_CP0596_20261111`
Branch at verification: `feat/cp0600-bootstrap-sync-startup`

## Result

**PASS — the restored QZKW2 owner wallet's complete public identity exactly matches the CP-0651 candidate manifest.**

The local read-only command `qzxb_wallet.exe address-qfp6-hybrid --wallet <wallet>` successfully opened:

`%LOCALAPPDATA%\QuantumZXB\wallets\QZXB-founder.qzw`

Wallet metadata reported:

- Format: `QZKW2_QFP6_HYBRID_Windows_CurrentUser_DPAPI`
- Account ID: `b26ce4e019429ec524cb73d0464ec4c6a48d47ea8519b867d0374f07ab54b31d`
- `private_key_output=none`

## Exact manifest comparison

The CLI's public output was compared locally, field-for-field, with `release/qfp6-candidate/manifest.json` → `founder_identity`.

| Field | Result |
|---|---|
| Public account ID | Exact match |
| Ed25519 public key | Exact match |
| ML-DSA-65 public key | Exact match |
| Ed25519 public-key SHA-256 | `596b575481854d9d00392875b559329c00f1a00fc251ae9b033acecb9538721f` |
| ML-DSA-65 public-key SHA-256 | `0b5367bc290d3dc70a63fb3a070748e775dc1478c43bde7f9bbd6fab0ad72239` |
| ML-DSA-65 public-key hex length | 3,904 characters |

All three exact-equality assertions returned `True`. The SHA-256 values above are fingerprints of the public-key hex strings as stored in the manifest.

## Security and release boundaries

- The restore and address inspection were performed locally on the owner's Windows profile. The recovery phrase was not requested in chat and must never be pasted into chat, logs, or project documents.
- This verification read public identity only. No private key, seed, or DPAPI plaintext was requested or displayed.
- The verification did not modify, replace, or migrate the legacy QZKW1 wallet.
- No Genesis signature was created.
- Manifest state remains: `genesis_signature_present=false`, `production_authorized=false`, `mainnet_status=NOT_AUTHORIZED`.
- No QZXB was minted, transferred, or credited; no transaction was submitted.
- This identity match clears the owner-wallet identity reconciliation item only. It does **not** authorize Genesis signing, Public Testnet, Mainnet, or any transfer.

## Next controlled work

Keep the matched QZKW2 wallet as the identified owner wallet. Before any Genesis signing or value-bearing operation, complete and independently review the remaining release artifacts and gates (including Q6GD, Q6CP, Q6PN, bootstrap peer configuration, final Genesis digest, and required consensus/cryptography/economic reviews). Only then may the owner be asked to sign the final, frozen digest through a protected local signer.

## Evidence commands

Read-only public-identity inspection:

```powershell
& $bin address-qfp6-hybrid --wallet $wallet
```

The local comparison parsed the CLI fields `account_id_hex`, `ed25519_public_key_hex`, and `mldsa65_public_key_hex`, then compared each complete value against the corresponding `founder_identity` manifest field.
