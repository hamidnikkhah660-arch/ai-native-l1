# CP-0458 ? Align Candidate QRun Genesis with the Installed Owner Wallet

Date: 2026-10-28

Status: **candidate identity corrected before activation; Mainnet remains not activated**

## Finding

A read-only call to the Windows DPAPI wallet CLI (qzxb_wallet address --wallet ...) returned the active wallet public account ID eee2e72882d770ab6fd7815c905b49e39650c74e8f121b26cbd49e333a3715c8 and public key 42a45fd22f7483fc75f6c30fc25f156ab958e6eaec7eb683b5badcc90f4f5131. The previously proposed candidate Genesis owner account ID (0f521debfc16bd0fa2cbe44be396875702750fb3baed3720f18bd0ad8bc74c88) did not match the installed wallet. Wallet files were queried only through the public address command; wallet secrets were not read or output.

Keeping the old candidate would credit the fixed 10B Genesis allocation to an account that the active local wallet cannot sign for.

## Correction

Because no Mainnet had been activated and the candidate had no public value-bearing history, the candidate owner account was aligned to the active wallet public account ID. The domain-separated QRun network ID is unchanged:

- Network ID: 70fdcdbe6f0afa1edb0c4fb4a85252831376f7b9ecf2a13a86dcf61979cdcad7
- Candidate owner account ID: eee2e72882d770ab6fd7815c905b49e39650c74e8f121b26cbd49e333a3715c8
- Maximum Genesis supply and owner balance: 10,000,000,000 QZXB = 1,000,000,000,000,000,000 atoms
- New independently computed Genesis state root: 4064e1dafec1c18ed5fb035f17b515e11d5ab314dea0a20e2294f230470ff440
- New independently computed Genesis commitment: 613bb4f36c8e57e73dd04308809b9decdd1b4411e0838f948ee2aa7eaacbab97
- Post-Genesis minting: disabled; block subsidy: zero.

The profile JSON, Rust identity constants, CP-0450 identity packet, and its independent Python oracle are the canonical candidate artifacts. Changing the owner ID changed the Genesis root and commitment; nodes built with the older candidate commitment are not compatible with this corrected candidate. No already-launched chain was migrated.

## Verification and boundary

The Python oracle computes the one-account canonical ledger state root and commitment independently from the owner account ID and supply. The Rust Genesis vector must agree exactly before this profile can proceed. No wallet private key, seed phrase, or mnemonic was generated, exported, or committed.

This is only an owner/Genesis candidate correction. It does not activate a public node, create spendable Mainnet coins, establish a market price, or close the production difficulty, full-history/checkpoint-rollover, real external-CAS-provider, public peer-bootstrap, and persistent-host launch gates.
