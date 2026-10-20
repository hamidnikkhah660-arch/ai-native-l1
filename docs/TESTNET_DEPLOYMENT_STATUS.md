# Testnet Deployment Status — EVM Asset Candidate

Last verified by project checkpoint: 2026-10-19 (CP-0280). This record is for reproducibility and disclosure; it is not an endorsement or a production launch.

## Network and contract

- Network: Ethereum Sepolia testnet.
- Chain ID: 11155111.
- Deployment transaction: `0x8828f2e6aef3d7b6ddab583a41e2322a62c8961adf62188634dbcd3e634b0814`.
- Contract address: `0x7f144fe3dcfbe36ed17ef6c60ea3913179dcf4af`.
- Block in the deployment checkpoint: 11,944,792.
- Reported receipt status: success (`0x1`).
- Verified contract reads: name `Qanvoryx Launch Candidate`, symbol `QX`, 18 decimals, and total supply of 10,000,000,000 QX.

## Allocation and design limits

The constructor allocated 4,000,000,000 QX (40%) to the founder allocation, 3,000,000,000 QX (30%) to the security reserve, and 3,000,000,000 QX (30%) to public goods. The deployed token is a separate EVM ERC-20 candidate, not the native AI_NATIVE_L1 coin. In the deployed candidate, all allocations are transferable; vesting, a sale mechanism, liquidity pool, exchange listing, or stable market price is not implied.

The testnet transaction and contract are public-chain records. The public-source wallet console template intentionally no longer pre-fills the owner's allocation addresses; users must enter and independently verify their own destinations before any wallet signature. Automated UI tests use synthetic fixture addresses.

## What this does not establish

This deployment is on a test network and has no claim to production value. It does not establish a public native-L1 mainnet, public zero-value native devnet, independent security audit, legal clearance, exchange listing, live liquidity, a public offer, or revenue. The native L1 Gate 2, independent anti-rollback Gate 8, and public-offer Gate S1 remain open according to the authoritative gate ledger. Do not send valuable assets or use this candidate for a sale.

For the internal historical execution evidence, use the owner's local working tree. This public status summary intentionally omits owner-controlled allocation wallet addresses; they are not needed to identify the contract/transaction on the public testnet. The underlying deployment transaction is public-chain data, so its sender and constructor arguments are discoverable to anyone inspecting the transaction; omitting them from the source text does not make those addresses private.
