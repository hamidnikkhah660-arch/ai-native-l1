# CP-0467 — EVM Toolchain Dependency Hardening and Validation

**Date:** 2026-10-29  
**Scope:** contracts/launch-asset only; the EVM asset is a separate test package, not native QZXB.  
**Status:** Local verification passed; CI coverage is added in the associated change. No Mainnet, sale, liquidity or native-chain integration is implied.

## Changes

- Updated the exact development-tool pin from Hardhat 3.19.0 to 3.21.1, including the matching EDR and transitive dependencies.
- Resolved the October 2026 Zod advisory by pinning Zod to patched version 4.6.7 through npm overrides.
- Resolved the Undici advisories by pinning Undici to 7.30.1 through npm overrides.
- Retained the existing tmp override at 0.2.7.
- Added an automated GitHub Actions job for clean npm ci, contract compilation, all local EVM/wallet/server tests, and npm audit. Node.js 24 and the setup action are pinned/configured explicitly.
- Updated the public status and technology pages to distinguish EVM-lab test evidence from canonical EVM integration into native QRun.

## Validation performed on 2026-10-29

Exact commands, in contracts/launch-asset:

1. npm ci — PASS; 75 packages installed, zero vulnerabilities reported during install.
2. npm run compile — PASS with Solidity 0.8.37, optimizer settings from the package, Shanghai EVM target; compiled creation bytecode 3,627 bytes and deployed bytecode 1,970 bytes.
3. npm test — PASS for:
   - fixed-supply local EVM asset: exact 10B test supply, 40/30/30 tranches, ERC-20 transfers/allowance, unchanged supply, no privileged mint/admin methods, invalid allocation rejection and testnet chain allowlist;
   - browser wallet console: signer preflight, bytecode match, gas estimate, mainnet rejection, extension-signed transfer and receipt confirmation;
   - wallet local server: loopback-only binding, GET-only page serving, CSP/CORS policy and no-secret logs.
4. npm audit — PASS; zero known vulnerabilities reported for the locked dependency tree.

The local test RPC is bound to 127.0.0.1 and uses chain ID 31337. The tests do not contact a public network, deploy a new contract, create a trading pool, prove native QZXB interoperability, or replace an independent smart-contract security review.

## Dependency maintenance note

The patched Zod and Undici versions are pinned in package.json overrides as well as the lockfile so normal lock refreshes do not silently restore the audited vulnerable versions. Re-run a clean install, compilation, all tests and npm audit after each dependency change. Review upstream compatibility and overrides at every scheduled dependency refresh.

## Release boundary

The QX ERC-20 contract remains a separate test asset associated with Ethereum Sepolia. It is not native QZXB and is not approved for production sale, public liquidity or real-value use. Native QRun Mainnet remains NO-GO pending its own consensus/Genesis integration, independent operators, complete history/recovery validation and independent protocol/security review.

See also CP-0465 — Mainnet/Public Trading No-Go and CP-0447 — Mainnet release gates.
