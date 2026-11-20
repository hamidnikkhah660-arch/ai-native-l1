# CP-0702 — Noise Identity, Anchor Vault, and Independent Authorization Gap Audit — 2026-11-16

## Scope and preservation
- Project: AI-NATIVE L1 / QRun Blockchain.
- Worktree: `D:\Temp\ASUS\QRUN_QFP6_CP0596_20261111`.
- Branch: `feat/cp0600-bootstrap-sync-startup`.
- HEAD observed: `5aba5f69d24fce03af742fd1bebf13ad00e5d9c3`.
- This is a read-only code and checkpoint audit. No runtime source, key, identity, config, peer pin, Anchor Vault record, or deployment artifact was changed.
- Existing dirty/untracked worktree is preserved. No Git mutation, node startup, listener, or network setting change was performed.

## 1. Confirmed architecture boundary: QFP6 Anchor Vault does not anchor Noise peer-identity high-water

### Evidence
- `src/native/pow_bench/src/identity_generation_store.rs` documents that its high-water detects record rollback across restarts only while the state file and stable writer-lock sibling remain protected; it explicitly does not protect against rollback/deletion of the entire protected directory (lines 1–5).
- `IdentityGenerationStateStore::open` detects a missing state file when the sibling writer-lock file remains (lines 182–214). If both state and lock are restored/deleted together, this local sentinel cannot independently prove the former high-water existed.
- `private_testnet_node.rs::resolve_trusted_peer_keys` stores peer identity high-water under `config.data_dir/peer_identity_highwater` (around lines 1113–1155).
- `chain_import_node.rs` accepts a separately configured `--peer-noise-identity-state-file` and opens `IdentityGenerationStateStore` for that path (around lines 1400–1440).
- QFP6's local Anchor Vault is separately configured via `trusted_manifest_anchor_vault_path`; its verification binds the append-only witness chain to QFP6 manifest network/profile/generation/anchor (permissionless.rs around lines 764–1089).
- The QFP6 Anchor Vault comments explicitly scope it to detecting D:-only rollback while the C: vault remains intact, not full-machine/two-disk rollback. No production code reference was found that binds `IdentityGenerationStateStore`'s peer-key generation digest/high-water into this QFP6 Anchor Vault chain.

### Finding
The existing QFP6 Anchor Vault evidence must not be interpreted as protecting Noise peer-identity revocation/rotation high-water. These are separate persistence domains. If the entire peer identity high-water directory and its lock sibling are rolled back or lost together, the local store alone cannot distinguish a first initialization from a prior deleted state. The current code comments acknowledge this limitation.

## 2. Confirmed gap: owner-signed JSON does not cryptographically prove independent-operator attestation

### Evidence
- `noise_identity_rotation_authorization_verify.rs::verify_authorization` verifies one Ed25519 signature over the raw authorization JSON using the supplied/pinned owner-authority key (around lines 66–109).
- It checks `independent_operator_id != owner_authorization_id` and requires two evidence SHA-256 strings (around lines 220–260).
- It does not accept an independent operator public key, verify an operator signature, or read/verify the evidence files themselves.
- The positive unit fixture `signed_exact_generation_authorization_passes_without_activation` constructs and verifies only the owner signature; the independent-operator fields are owner-signed assertions (around lines 312–368).

### Finding
The preflight proves that the owner-authority key signed a JSON document claiming independent verification. It does not prove that the named independent operator signed or endorsed those claims. The field names and checkpoint wording must not be presented as cryptographically verified independent attestation until a separate operator signature and out-of-band operator-key pin are implemented.

## 3. Owner authorization preflight is not enforced by the peer-rotation artifact command

### Evidence
- The `rotate-peer` command in `devnet_trust_provisioner.rs` reads DPC1 deployment config, deployment-authority key, IRG1 registry, issuer key, previous NPI1 identity, and the new Noise public key (around lines 707–756).
- It calls `build_rotated_peer_identity_artifact(...)` and writes the resulting NPI1 artifact (around lines 757–779).
- This command path does not invoke `noise_identity_rotation_authorization_verify`, does not take an owner authorization JSON/signature, and does not verify an independent-operator signature.
- The owner authorization verifier is a separate preflight-only binary and explicitly does not install pins, update peers, activate keys, or start a node (CP-0696 and verifier source).

### Finding
The owner authorization verifier currently provides a standalone preflight proof, not a mandatory control in the actual peer-rotation artifact workflow. DPC1/IRG1/issuer authorization remains a distinct governance chain; it must not be conflated with the separate owner + independent-operator approval gate described by CP-0696.

## 4. Session overlap boundary

`SignedPeerTrustReloader` in `private_testnet_node.rs` re-reads and verifies signed trust files at each new connection boundary. Its source comment explicitly states that this does not tear down a Noise connection whose handshake was already accepted. Therefore a rotation/revocation policy must define existing-session draining or a bounded session lifetime, not only new-connection pin replacement.

## 5. Required closure gates before any identity activation

1. Define a durable peer-identity high-water anchor that is independently protected from the mutable peer-state/data directory. Bind the exact network, issuer, credential, key ID, generation, record digest, and lifecycle state. Startup must fail closed if the independent anchor is missing, behind, inconsistent, or cannot be authenticated. Do not claim the QFP6 manifest Anchor Vault already provides this binding.
2. Add a separately signed operator-attestation object. Verify its Ed25519 signature against an operator public-key fingerprint supplied/pinned through an independent channel. Bind the attestation to the exact network/profile, role, issuer/credential/key IDs, from/to generation, old/new public fingerprints, manifest hash, endpoint, evidence hashes, and bounded issue/expiry interval.
3. Bind the owner's signature to the exact operator-attestation digest and the exact overlap/rollback policy content hash; a non-empty policy ID alone is insufficient evidence that a reviewed policy exists.
4. Make the actual `rotate-peer` artifact path require and verify the owner authorization plus independent-operator attestation before writing an artifact. Keep the standalone verifier useful for preflight, but do not leave it optional relative to the operational command.
5. Specify and test the transition behavior for already-established Noise sessions: maximum session age, drain/reconnect procedure, overlap start/end, old-key rejection boundary, and rollback floor.
6. Add negative tests for full peer-state-directory rollback/deletion, missing or mismatched independent anchor, absent/invalid operator signature, wrong operator key pin, replay across network/role/generation/manifest/endpoint, changed policy content, and attempted artifact generation without the required authorization.

## 6. Current status and safety boundary

- This checkpoint records verified gaps; it does not claim they are fixed.
- CP-0694 to CP-0696 work remains valid: staged keys, fresh-process reload tests, and owner-signature preflight remain inactive and are not production rotation authorization.
- No owner authority key was generated or pinned. No operator key or attestation was generated. No production key was read, replaced, or rotated.
- No QRun node was started; no TCP listener was opened; no Public Testnet or Mainnet deployment was authorized.
- PR #196 remains open and requires independent review. These findings should be added to its reviewer acceptance criteria before any approval of identity rotation.

## Next engineering step
Design the independent peer-identity high-water anchor and dual-signature authorization format first. Then implement the verifier and wire it into `rotate-peer` with negative tests. Keep all current identities and staged bundles untouched until the design has independent review and a separately approved activation plan.
