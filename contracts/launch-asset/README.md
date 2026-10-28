# Fixed-Supply EVM Launch Asset Candidate

**Status (updated 2026-10-19, CP-0280): local tests pass; a separate Qanvoryx Launch Candidate (QX) ERC-20 is deployed on Ethereum Sepolia at `0x7f144fe3dcfbe36ed17ef6c60ea3913179dcf4af` (tx `0x8828f2e6aef3d7b6ddab583a41e2322a62c8961adf62188634dbcd3e634b0814`). Read-only RPC confirmed 10B total supply and initial 4B/3B/3B balances. This is testnet-only, not the native AI_NATIVE_L1 coin; no Mainnet deployment, sale or liquidity pool exists. Not independently audited and not approved for real-value use. See `checkpoints/CP_0280_SEPOLIA_ERC20_DEPLOYMENT_VERIFIED_2026-10-19.md`.

This package is a deliberately separate EVM asset route intended for early technical/economic validation. It is **not** the native AI_NATIVE_L1/Qanvoryx L1 coin, does not redeem for that coin, and has no guaranteed migration or conversion.

## Contract model

Source: `contracts/FixedSupplyLaunchAsset.sol`

- ERC-20 inherited from pinned `@openzeppelin/contracts@5.6.1`; compiler pinned by package lock to Solidity 0.8.37.
- EVM bytecode compiled with optimizer (200 runs), Shanghai EVM target, and Solidity metadata bytecode hash disabled for reproducibility.
- 18 decimals, hard fixed total supply: 10,000,000,000 tokens.
- Constructor mints once to three distinct, non-zero addresses: 4,000,000,000 (40%) founder treasury, 3,000,000,000 (30%) security allocation, 3,000,000,000 (30%) public-goods allocation.
- No privileged mint, owner, pause, blacklist, fee/tax, rescue, or upgrade entrypoint exists in the ABI. The supply is established in the constructor; transfers cannot increase it.

**Critical allocation disclosure:** all three allocation tranches are transferred to their specified addresses immediately and are freely transferable. This contract does not enforce vesting/escrow, distinguish a liquid float, or restrict the security/public-goods wallets. The 40% founder balance is controlled only if the owner independently controls the private key of the supplied founder address. Do not imply that treasury tokens are locked or non-circulating without separate on-chain controls and truthful disclosure.

The contract's constructor accepts token name/symbol arguments. `Qanvoryx / QANV` remains an uncleared working identity; do not deploy those names in public until branding/ticker/domain review is documented. The local test uses `Qanvoryx Launch Candidate / QX`, not an approved ticker.

## Run reproducible local tests

Requires Node.js and npm:

```powershell
Set-Location .\contracts\launch-asset
npm ci
npm run compile
npm test
```

The test starts an ephemeral Hardhat 3/EDR local JSON-RPC node bound only to 127.0.0.1 (chain ID 31337; no public network) and uses its unlocked development accounts. It verifies exact fixed supply, all three initial balances, 40/30/30 arithmetic, ERC-20 transfer and allowance flow, constant supply after transfers, absence of privileged mint/admin functions, and rejection of zero or duplicate allocation addresses. On 2026-10-29, a clean locked install, compilation, all three test suites and npm audit passed with zero reported vulnerabilities using Hardhat 3.21.1, Zod 4.6.7 and Undici 7.30.1. The explicit Zod/Undici resolutions address the current npm advisories; re-run npm audit on every dependency refresh and review these overrides when upstream peer requirements change.

## Browser wallet and testnet deployment console (CP-0253)

After running npm ci, run npm run build:wallet and npm run wallet:serve, then open http://127.0.0.1:8765/ in a browser that has a supported wallet extension. The server binds only to loopback and serves the one wallet page with GET only; it is not accessible over a public network. The page can deploy this fixed-supply candidate to Base Sepolia or Ethereum Sepolia using eth_sendTransaction through the extension; it never reads or saves the wallet's private key/seed phrase. It verifies the compiled runtime bytecode, reads the current token/founder balances, computes the actual founder share and supports standard ERC-20 transfers after the wallet confirms them. The page refuses Mainnet and local-chain IDs. It is not a native L1 wallet or native coin.

The constructor requires three distinct, nonzero public destination addresses. The founder field defaults to the designated founder treasury; verify all three destinations before any deployment. Security and public-goods tranches are immediately transferable and are not contract-enforced locks. CP-0280 records one completed Ethereum Sepolia deployment of the QX candidate; this does not authorize a Mainnet deployment, offer, sale or liquidity pool. Detailed scope/test notes: docs/CPW_TESTNET_WALLET_CONSOLE_V01.md.

## Testnet-only deploy runner

`scripts/deploy-testnet.mjs` refuses every chain ID except Base Sepolia (84532) and Ethereum Sepolia (11155111), then checks the RPC reports the expected chain ID. The script is not a Mainnet deployer. Base documents those chain IDs as 8453 Mainnet / 84532 Base Sepolia; see the official Base RPC reference: https://docs.base.org/base-chain/api-reference/ethereum-json-rpc-api/eth_chainId.

Set environment variables in a private shell session, never in Git or chat:

- `RPC_URL`: RPC URL for a testnet you control.
- `DEPLOYER_PRIVATE_KEY`: throwaway testnet deployer key only; never use a treasury/founder production key for deployment.
- `EXPECTED_CHAIN_ID`: 84532 or 11155111.
- `TOKEN_NAME`, `TOKEN_SYMBOL`: test labels only until brand/ticker review.
- `FOUNDER_TREASURY`, `SECURITY_RESERVE`, `PUBLIC_GOODS_TREASURY`: three distinct destination addresses; ensure the founder address belongs to the owner-controlled self-custody wallet.

Run `npm run deploy:testnet`. It prints contract and transaction addresses only after deployment and checks code plus total supply. This runner does not verify source on a block explorer, create a DEX pool, or import a wallet into an app. Do not enter any real/private treasury key. Environment variables must be removed when finished.

## Before real value or customers

This package is not an authorization to sell or create a market. Before Mainnet use: independently audit the contract and deployment process; verify brand/ticker collisions; complete qualified legal review for distribution jurisdictions; review treasury-address custody; publish token/native-coin distinction; publish the full immediate 40/30/30 allocation and any sale/lockup rules; test deployment/verification; prepare incident disclosure. The reference price of $0.01 belongs only in an openly labelled plan: it is not enforceable once normal on-chain trading begins. Do not manufacture volume, promise returns, or describe hypothetical reserves as existing liquidity.

For an actual pool, token deployment and liquidity provision are separate operations; pool reserves and real trades determine executable spot price and price impact. A chart should not be called live until it is sourced from the deployed contract's real market pair and an independently queried data source.
