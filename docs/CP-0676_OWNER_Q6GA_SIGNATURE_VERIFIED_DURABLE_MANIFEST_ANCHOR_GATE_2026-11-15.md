# CP-0676 — Owner Q6GA Signature Verified; Durable Manifest Anchor Blocks Local Restart

Date: 2026-11-15
Project: AI-NATIVE L1 / QRun / QZXB / QFP6
Worktree: D:\Temp\ASUS\QRUN_QFP6_CP0596_20261111
Scope: LOCAL SINGLE-OPERATOR LOOPBACK ONLY.

## 1. Owner confirmation completed

The owner executed the QZKW2 approve-local-genesis command and entered the commitment-specific confirmation phrase locally. The phrase itself is not a secret and does not need to be retained.

The command produced:
- File: release/qfp6-local-single-operator-devnet-2026-11-15/genesis-owner-approval.q6ga
- File size: 5,685 bytes
- SHA-256: ef1aa62babdb48eda020ba0d3e0bbece0292c8a17cf5c5afa2f2fd68f14bc834
- Signature format: Q6GA_V1_ED25519_MLDSA65
- Manifest status: SIGNED_BY_OWNER_LOCAL_ONLY
- genesis_owner_signature_present: true
- public_testnet_authorized: false
- mainnet_authorized: false

No recovery phrase, private key or DPAPI plaintext was requested or exposed.

## 2. Config / Manifest byte-level verification

The updated permissionless-config.json SHA-256 is:
ea5961cdaa9b68af1208abda437b4047a84fd8ea381598f0dd93978ce0fd0f83

Verified:
- actual permissionless-config.json SHA-256 equals local-devnet-manifest.permissionless_config_sha256;
- actual Q6GA file SHA-256 equals permissionless_runtime.owner_genesis_approval_sha256;
- actual Q6GA file SHA-256 equals manifest.genesis_owner_signature_sha256;
- config references genesis-owner-approval.q6ga;
- listener remains 127.0.0.1:30333;
- bootstrap_peer_count remains 0;
- approved outbound peer sync remains false;
- Q6AR candidate address book remains false;
- Public Testnet and Mainnet authorization remain false.

## 3. Node-side cryptographic verification

The optimized Release node was invoked using --permissionless-run with the updated config digest above.

The node emitted:
- owner_genesis_approval=Q6GA_ED25519_MLDSA65_VERIFIED
- owner_genesis_approval_scope=LOCAL_CANDIDATE_ONLY_NOT_MAINNET_AUTHORIZATION

This is direct runtime evidence that the node decoded Q6GA and accepted its dual signatures and bound artifacts/economics. It then failed closed at the existing-history trust gate, before runtime/listener startup.

The separate generic --preflight flag was also tried, but that flag enters the QAP1 bootstrap-config parser, not the Permissionless local path; it refused because its separate schema requires a root network_id field. Do not use that generic preflight result to judge Q6GA.

## 4. Current startup blocker — trusted manifest anchor

The Permissionless launcher checks data_directory/manifests. Existing durable history is present and contains 1,025 QFP6 manifest files, generations 0 through 1024. The config currently has no independently pinned permissionless_runtime.trusted_manifest_anchor.

Node refusal:
"existing durable history requires independently pinned permissionless_runtime.trusted_manifest_anchor; refusing local-only rollback trust"

This is the intended fail-closed rollback protection. The latest manifest file's ordinary SHA-256 is not automatically an independently trusted anchor. Do not invent an anchor, copy an arbitrary file checksum into the config, delete/recreate the existing data directory, or bypass the guard.

Next engineering action: inspect the Q6MF manifest encoding and the canonical store's manifest_anchor() algorithm; recover the exact committed chain tip from the actual store; independently pin that value in a protected/out-of-band local operator record; then update the config and Manifest hash atomically without changing the Q6GA-signed Genesis artifact bindings. Add a regression test for the restart path before starting the node again.

## 5. Runtime status

The --permissionless-run attempt stopped at the trusted-manifest-anchor gate. No successful node startup is claimed. Recheck process/listener status before any later restart.

No public listener, public peer, router/firewall change or public Testnet/Mainnet launch was performed. No public issuance or real-value transfer is claimed.

## 6. Retained records

- Q6GA approval file remains in the local package; do not delete or overwrite it.
- Current post-signature config hash: ea5961cdaa9b68af1208abda437b4047a84fd8ea381598f0dd93978ce0fd0f83
- Q6GA SHA-256: ef1aa62babdb48eda020ba0d3e0bbece0292c8a17cf5c5afa2f2fd68f14bc834
- CP-0675 documents the protocol implementation, test results and Release binary hashes.
- This checkpoint records owner approval and the next startup blocker; it does not certify Public Testnet readiness.
