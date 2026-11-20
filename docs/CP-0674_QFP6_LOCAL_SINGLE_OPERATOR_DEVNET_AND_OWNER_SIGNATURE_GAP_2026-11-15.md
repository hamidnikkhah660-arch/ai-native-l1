# CP-0674 — QFP6 Local Single-Operator Devnet Package and Startup Recovery Fix
Date: 2026-11-15
Scope: engineering candidate only; local single-operator loopback Devnet; NOT Public Testnet / NOT Mainnet.

## 1. Package generated from real protocol constructors
Package directory:
`release/qfp6-local-single-operator-devnet-2026-11-15/`

Artifacts:
- Q6GD descriptor: 206 bytes; SHA-256 `e5bbd024511f907d1e9bf3c1d4004d05851cd96c79eebd0f1ce446aee15a1888`
- Q6CP consensus profile: 294 bytes; SHA-256 `0ff4786c2b62228883699c687b34d57a85f3bcddde9a545c95f5515a388c516f`
- Genesis snapshot: 1,280 bytes; SHA-256 `6961e7517adcb66c04a3c566ec8c5cba398940eb273eabd082b706bb32a4f757`
- Q6PN v1 profile bundle: 2,294 bytes; SHA-256 `bb3d1e5710827afd8248292f9c19ab250dcdc8e508711597dd049c77a6ec8233`
- Bootstrap peers: exact empty JSON array; SHA-256 `37517e5f3dc66819f61f5a7bb8ace1921282415f10551d2defa5c3eb0985b570`
- Permissionless config SHA-256: `3aa5c730cfc756fa76f39908f1988f18f8b469f762da980c489cb002d2020af1`
- DPAPI protected local Noise credential: 304 bytes; SHA-256 `a7743aa6c17b7cfeb008d8ef568a4a813fe218bd80f529c327b65284c1a5b584`
- Rebuilt Release node: 3,016,192 bytes; SHA-256 `1cf43b6329cec2322816a1a9775fd22bdbeb5819246063215ff7513ade75cd94`

The generator used OS CSPRNG-derived nonzero local network/profile IDs, actual CP-0651 constructors, a canonical descriptor, consensus profile, full Genesis state and encoded snapshot. No production release manifest was changed.

## 2. Economics and owner identity binding
Network ID: `633b5dfc16fb2ec1825baf924ae7f7f16bf2006f8b64441a57692a3531722712`
Profile ID: `a0a057d72c11253386bfe90d428bccbc44ebc86fc84e04e3682193a99d8805c4`
Owner QZKW2 account ID: `b26ce4e019429ec524cb73d0464ec4c6a48d47ea8519b867d0374f07ab54b31d`
Genesis descriptor commitment: `5657561cdc3200e295a4902c64ce366ff71b32c7e1b8d67123522e0963e0451e`
Consensus fingerprint: `fdf24d7916fc6cefd2851e9f3c4c2ebb04decba2e760bf4d5d5ba4660f425bac`
Tokenomics fingerprint: `66fcdb45cd6ec7d4b987dd78a4bcfbd99ee83c252554c1723a7aaf04b7342f97`
Genesis state root: `bf1e109e3901ca9524b6c8f615bef7476cce486abcc3262c0f1e9866ccddd19f`

CP-0651 Genesis allocates 1,000,000,000 QZXB to the exact verified owner account ID. Gross accounting ceiling is 7,000,000,000; six 1B labels remain non-circulating accounting ceilings; subsidy is zero and producer compensation is canonical transaction fees only. This allocation exists only in this local candidate snapshot and is not a publicly transferable Mainnet balance.

## 3. Q6PN and topology limitation
The configured local listener is exactly `127.0.0.1:30333`; bootstrap peer count is zero; address book and approved outbound peer sync are disabled. No firewall/router/public listener change was made.

Q6PN v1 keeps legacy external-CAS fields as inert, shape-valid local placeholders. No Provider/Q6EA/Q6TS/Q6QA trust services are configured. Its self-pin commitment is kept in the same config that the local CLI hash-pins; this is not an independent trust domain. Thus this package is intentionally not eligible as a public multi-operator release.

The NPK1 node Noise credential is protected by Windows CurrentUser DPAPI. Public-key fingerprint only:
`3bb2100354aea0f82d7f5281574a0a8acbaa12dc7c7def11a341ec72a6068066`.
No plaintext private key was emitted.

## 4. Startup defect found and fixed
The first local run passed Q6GD/Q6CP/Q6PN, Genesis, CP-0651 and protected-key preflight, then failed with journal error `AlreadyRestored`.
Trace showed launcher restored Q6MJ/Q6MM, then supervisor repeated the same one-time recovery. The launcher-level duplicate recovery block was removed from:
`src/native/pow_bench/src/bin/qrun_v06_node_runtime_launch/permissionless.rs`
The supervisor remains the sole startup recovery owner.

The generator and startup patch were formatted. `cargo fmt -- --check` and targeted `git diff --check` passed.
Post-fix binary tests:
`cargo test --bin qrun_v06_node --locked --offline -- --test-threads=1`
Result: **37 passed, 0 failed**.
Q6GD/Q6CP candidate validator passed and printed `q6gd_q6cp_binding=VALID`, `qualification=CANDIDATE_ONLY_NOT_MAINNET_APPROVED`, `mainnet_authorized=false`.
The previous full library suite result of 1,459/1,459 remains from the prior Q6MO patch; it was not rerun after this focused launcher recovery edit.

## 5. Runtime currently active
Release command:
`qrun_v06_node.exe --permissionless-run --config permissionless-config.json --config-sha256 3aa5c730cfc756fa76f39908f1988f18f8b469f762da980c489cb002d2020af1`

Observed PID: 12000.
Observed TCP listener: `127.0.0.1:30333`, owning PID 12000.
Startup output confirms:
- CP-0651 owner allocation target 1B
- accounting labels not circulating; block subsidy 0
- Genesis-rooted, no seed peers
- Q6TS/Q6QA not configured; external quote-asset admission denied fail-closed
- Provider/Q6EA/QAP1 not required for this local profile.

At last filesystem observation, local candidate data contained 623 files / 3,883,778 bytes and mempool journal 17 files / 906 bytes. These are local runtime artifacts under the ignored `runtime/` directory.

## 6. Owner Genesis signature is not yet a valid protocol operation
Inspection of `QRunV06GenesisDescriptor` confirms Q6GD v1 has fields for network, profile, founder/owner account, timestamp, consensus fingerprint, tokenomics fingerprint and commitment only. It has no signature field. The current node runtime has no recognized Q6GD owner-signature sidecar or mandatory verifier. A detached signature made outside a defined, enforced protocol would not be a valid Genesis authorization.

Required engineering step before owner signing: specify a versioned owner-genesis-approval envelope; bind exact Q6GD/Q6CP/Q6PN/Genesis snapshot hashes and CP-0651 economics; implement QZKW2 local hybrid signing with explicit local owner confirmation; make node preflight reject absent/invalid signatures; add adversarial tests; then obtain independent crypto/consensus/economics review. Do not ask the owner to sign until this protocol and verifier exist.

## 7. External release status unchanged
PR #195 remains open and unmerged; GitHub review list is empty. The three CI checks previously passed, but no independent approving reviewer has reviewed the PR. Public Pages publication remains pending.
Official `release/qfp6-candidate/manifest.json` was not changed. It still marks production/Mainnet/public mining unauthorized; public Genesis/profile/bootstrap assets missing; independent consensus/cryptography/economics reviews pending.
No Public Testnet, Mainnet, real-value issuance or transfer is claimed.

## 8. Git preservation
Engineering worktree branch remains `feat/cp0600-bootstrap-sync-startup`; no commit, reset, clean, stash or push was performed. This checkpoint is a local file and has not been committed or pushed.
