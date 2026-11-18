# CP-0684 — Q6GA v2 Zero-Value Public Testnet Owner Authorization

Date: 2026-11-15
Project: AI-NATIVE L1 / QRun / QZXB / QFP6
Worktree: D:\Temp\ASUS\QRUN_QFP6_CP0596_20261111
Branch: feat/cp0600-bootstrap-sync-startup
Scope: candidate engineering only; no authorization signed and no listener started.

## 1. Objective

The existing Q6GA v1 approval is deliberately restricted to the single-operator loopback Devnet. The node already exposed a separate `--public-testnet-run` entry point, but that path had no distinct owner authorization envelope. Reusing Q6GA v1 would violate the existing local-only scope and is explicitly rejected.

This checkpoint adds a separate Q6GA v2 scope for a zero-value Public Testnet only. Q6GA v1 remains unchanged in meaning and remains local-only.

## 2. Q6GA v2 format and cryptographic scope

`src/native/pow_bench/src/qrun_v06_genesis_approval_candidate.rs` now supports:
- Version 1 / scope 1: existing local-only approval; original V1 signing domain and all-seven-zero reserved bytes retained.
- Version 2 / scope 2: zero-value Public Testnet authorization; a distinct domain-separated signing digest and explicit scope byte in the reserved area.
- Both versions require dual Ed25519 and ML-DSA-65 signatures and exact CP-0651 economics: 7B gross accounting ceiling, 1B owner Genesis allocation, zero block subsidy, canonical transaction-fee-only producer compensation.
- V2 binds network ID, profile ID, owner account, Q6GD descriptor commitment, and exact SHA-256 hashes of Q6GD, Q6CP, Q6PN and Genesis snapshot.
- V2 deliberately does not bind a node-specific bootstrap peer file. Each node must independently pin its own config bytes and bootstrap peer-set hash; the network-wide owner authorization remains reusable only for the same exact Genesis/profile artifacts.
- V2 requires the bootstrap hash field to be zero in the authorization envelope; V1 retains its exact bootstrap hash binding.
- Local verification rejects V2; Public Testnet verification rejects V1. Version/scope substitution is rejected before use.

## 3. Node launcher integration

`src/native/pow_bench/src/bin/qrun_v06_node_runtime_launch/permissionless.rs` now branches by the explicit CLI mode:
- `--permissionless-run` continues to require `owner_genesis_approval_path` and `owner_genesis_approval_sha256`, and verifies Q6GA v1 local-only bindings.
- `--public-testnet-run` requires `public_testnet_authorization_path` and `public_testnet_authorization_sha256`, and verifies Q6GA v2 public-testnet bindings.
- The local-only Q6GA v1 scope validator is not used to authorize Public Testnet; instead the distinct v2 verifier is mandatory.
- Existing public-mode checks remain mandatory: exact zero-value mode, public listener opt-in, both explicit acknowledgement strings, role seed/joining, publicly routable bind address, seed empty peer set or joining node with pinned public peers.
- Successful public authorization prints explicit `ZERO_VALUE_PUBLIC_TESTNET_ONLY`, `mainnet_authorization=NOT_GRANTED`, and `market_authorization=NOT_GRANTED`.

## 4. Owner-controlled signing command

`qzxb_wallet approve-public-testnet-genesis --wallet ABSOLUTE_QZKW2_PATH --package-dir ABSOLUTE_QFP6_PACKAGE_DIR` is now available in the wallet CLI.

Before it can create a signature, the command:
- Requires a real, non-symlink local package directory.
- Requires the existing local-only package manifest to remain non-public and non-Mainnet.
- Checks exact CP-0651 economics and the exact Q6GD/Q6CP/Q6PN/Genesis/bootstrap bytes against the package manifest.
- Requires the source package to have an already-present, valid local Q6GA v1 approval.
- Verifies the source config remains the original loopback-only profile.
- Confirms the protected QZKW2 wallet account equals the Q6GD owner account.
- Displays the exact network/profile/owner/Genesis commitment, artifact hashes, economic terms, and the anonymous inbound Noise XX limitation.
- Requires a commitment-specific confirmation phrase that explicitly includes acknowledgement of anonymous unauthenticated Noise XX and its active-MITM limitation.
- Writes `public-testnet-authorization.q6ga` with create-new semantics and flushes it; it never overwrites an existing authorization.
- Does not modify the existing local config or local manifest and never emits private signing material.

The signing command was NOT run. No Q6GA v2 signature has been created. Owner confirmation remains an explicit local action.

## 5. Verification results

- Q6GA approval module suite: 4 passed, 0 failed.
- QRun node launcher suite: 44 passed, 0 failed.
- QZXB wallet suite: 13 passed, 0 failed.
- `cargo fmt --check`: PASS.
- `git diff --check`: PASS (only existing LF/CRLF normalization warnings).
- Release build:
  `cargo build --release --bin qrun_v06_node --bin qzxb_wallet --locked --offline -j 1`
  exit code 0.
- Both Release `--help` commands exited 0 and the wallet help lists the new explicit owner authorization command.
- Release negative integration test: a disposable copy of the package was configured for `--public-testnet-run` but deliberately pointed at its existing local Q6GA v1 file. The launcher refused with `Q6GA public-testnet owner/artifact/economics binding failed: WrongScope`, exit code 1.
- After that negative test: qrun node process count 0; TCP 30333 listener count 0.
- Release binary SHA-256:
  - qrun_v06_node.exe: `cd7965e2ff486d558f694da2e83336cc0fcf11ae7de9c7178f3aaa05f82059c0`
  - qzxb_wallet.exe: `5f4ccc5e51e84ff17029f5d9c19b885bdcec10a29113d689e1443022f72e35a1`

## 6. What this closes and what it does not

Closed by this checkpoint: the code-level owner-authorization gap between the existing local-only Q6GA v1 and the separate zero-value Public Testnet CLI path. The node now has a versioned, dual-signature, scope-separated public-testnet authorization verifier and a local owner-signing command.

Not closed:
- No Q6GA v2 owner signature has been produced.
- No public seed host or independent operator has been provisioned.
- No public endpoint, public Noise static-key fingerprint or independently pinned bootstrap peer set exists yet.
- The current public inbound Noise XX transport remains anonymous and unauthenticated; the new command requires explicit owner acknowledgement but does not change the transport.
- Public Internet inbound reachability, multi-host full-history convergence and independent operator operation remain unqualified.
- Public Testnet has NOT launched. Mainnet, public mining and value-bearing transfer remain unauthorized.
- Website PR #195 remains open and unmerged pending a genuine independent approval.
- No commit, push, merge, firewall change, router/port-forward change or node startup was performed.

## 7. Next execution path

1. Preserve this Q6GA v2 implementation and build.
2. Prepare a separate Public Testnet seed/joining profile from the exact signed Genesis artifacts, with each host's own protected Noise key and independently pinned config/peer set.
3. Obtain the required independent public seed hosts/operators and their actual routable endpoints; do not fabricate addresses or fingerprints.
4. Once the owner has reviewed the displayed risk statement and is ready, run the new wallet command locally and type its exact confirmation phrase. Do not share wallet secrets or recovery material.
5. Run the Release public-testnet path only on the explicitly provisioned test host(s), with the exact Q6GA v2 authorization and per-host pinned configuration.

Decision: Q6GA v2 code path is implemented and its focused tests/build pass. Public Testnet is still NOT LAUNCHED; the remaining work is now concrete provisioning and owner authorization rather than reusing or repeatedly retesting the local-only approval.
