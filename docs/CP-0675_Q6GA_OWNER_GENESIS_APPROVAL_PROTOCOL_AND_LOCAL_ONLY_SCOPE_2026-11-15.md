# CP-0675 — Q6GA Owner Genesis Approval Protocol and Local-Only Scope Hardening

Date: 2026-11-15
Project: AI-NATIVE L1 / QRun / QZXB / QFP6
Worktree: D:\Temp\ASUS\QRUN_QFP6_CP0596_20261111
Branch: feat/cp0600-bootstrap-sync-startup
Scope: engineering candidate; LOCAL SINGLE-OPERATOR LOOPBACK ONLY.

## 1. Protocol implemented

Added qrun_v06_genesis_approval_candidate.rs and exported it from the crate.

Q6GA v1 is a detached owner-approval envelope using dual Ed25519 and ML-DSA-65 signatures. Its domain-separated signing digest binds:
- network ID and profile ID;
- owner account ID and Q6GD descriptor commitment;
- SHA-256 hashes of Q6GD, Q6CP, Q6PN, Genesis snapshot and bootstrap-peer bytes;
- CP-0651 gross accounting ceiling, owner Genesis allocation, zero block subsidy and fee-only producer compensation.

The decoder rejects malformed/truncated/extended input, unsupported version/suite, nonzero reserved bytes, wrong owner, invalid Ed25519 or ML-DSA-65 signature, economics substitution and any artifact-hash or descriptor mismatch.

## 2. Owner wallet operation

Added qzxb_wallet approve-local-genesis --wallet ABSOLUTE_QZKW2_PATH --package-dir ABSOLUTE_LOCAL_DEVNET_DIR.

The command:
- reads only the local DPAPI-protected QZKW2 wallet;
- verifies the wallet account equals the Q6GD owner;
- checks the local manifest pins the original config bytes;
- checks the local-only notice, CP-0651 values, empty bootstrap list and exact artifact hashes;
- requires 127.0.0.1:30333, allow_public_listener=false, outbound peer sync false and Q6AR false;
- checks producer account equals the Q6GD owner;
- prints the network, profile, owner, descriptor commitment, five artifact hashes, economic terms and disabled public/value-transfer flags;
- prompts for an exact commitment-specific phrase typed in the local terminal;
- creates genesis-owner-approval.q6ga using create-new semantics, self-verifies it and updates the local runtime config/manifest hashes.

Existing approval bytes are never overwritten. Recovery words and private key material are not emitted or requested in chat. This operation has not been run automatically; the owner's explicit local confirmation remains required.

## 3. Mandatory node-side enforcement

The permissionless preflight now requires and verifies the Q6GA file before durable-store opening or listener exposure. It verifies the envelope SHA-256, both signature algorithms, Q6GD commitment, owner, all five artifact hashes and CP-0651 economics.

Added validate_q6ga_local_devnet_scope: Q6GA v1 is accepted only for the exact 127.0.0.1:30333 listener, zero bootstrap peers, allow_public_listener=false, outbound peer sync false, Q6AR false, and non-Public-Testnet CLI mode. Any deviation fails closed.

This is intentionally a local-only approval profile. It cannot be reused as approval for Public Testnet or Mainnet.

## 4. Local verification

Post-hardening checks on the exact current source:
- cargo fmt -- --check: PASS.
- git diff --check: PASS.
- cargo test --lib qrun_v06_genesis_approval_candidate --locked --offline -- --test-threads=1: 3 passed, 0 failed.
- cargo test --bin qzxb_wallet --locked --offline -- --test-threads=1: 13 passed, 0 failed.
- cargo test --bin qrun_v06_node --locked --offline -- --test-threads=1: 38 passed, 0 failed.

The new wallet tests reject non-loopback listeners, public listener opt-in, enabled outbound sync, enabled Q6AR and a config whose bytes do not match the manifest pin. The new node test rejects changed listener address, nonempty bootstrap peers, enabled outbound sync, enabled Q6AR and public Testnet mode.

The targeted optimized Release build completed successfully on the post-hardening source:
- Command: cargo build --release --bin qzxb_wallet --bin qrun_v06_node --bin qfp6_local_devnet_package --locked --offline -j 1
- Result: exit code 0; optimized Release profile completed.
- qzxb_wallet.exe SHA-256: 15669bb68b8bfcbfe8de9f00f577783eae03bc7e816dc75d63fa1d6727ca604e
- qrun_v06_node.exe SHA-256: aea1f65ce9918cc9a0183c89a03b86284779ab332c0107d3d5a0cb6c24519298
- qfp6_local_devnet_package.exe SHA-256: da910d7997cd66a656023dc4d91c4924fdcaa6cd0e6f44b497a3f81666e75af1

Both qzxb_wallet.exe --help and qrun_v06_node.exe --help exited 0. The wallet help displays approve-local-genesis and its local-only confirmation requirement; the node help keeps permissionless candidate and Public Testnet invocation paths distinct. Help mode did not load wallet secrets or start a node/listener.

Warnings from unrelated legacy/candidate code remain limited to existing unused imports/dead code; no warning is treated as a security review.

## 5. Package and authorization status

The pre-existing local package contains real generated Q6GD/Q6CP/Genesis/Q6PN artifacts, a zero-peer bootstrap file and a DPAPI-protected local Noise credential. Its scope remains single-operator Loopback only.

At checkpoint creation:
- Q6GA source implementation and node enforcement are present;
- targeted Q6GA/wallet/node test results above are PASS;
- owner QZKW2 public identity was previously matched to the candidate manifest in CP-0672;
- owner Q6GA signature has NOT been produced by this checkpoint;
- no node restart with a signed config is claimed;
- no Public Testnet or Mainnet is launched or authorized;
- no public issuance, real-value transfer, market liquidity or exchange listing is claimed;
- independent consensus, cryptography and economics reviews remain PENDING;
- PR #195 remains OPEN and unmerged pending genuine independent review and protected merge.

## 6. Next controlled step

After Release build verification and binary hashing, the owner may run the documented approve-local-genesis command in a local PowerShell terminal and review the displayed fields before typing its exact confirmation phrase. The owner must not share recovery words or signing secrets in chat. After a valid local signature, verify the Q6GA bytes/config digest and run the local node with the newly printed config digest. The resulting balance remains a local Devnet candidate balance, not a public or Mainnet QZXB asset.
