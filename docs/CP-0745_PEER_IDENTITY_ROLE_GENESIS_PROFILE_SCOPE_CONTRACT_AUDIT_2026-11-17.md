# CP-0745 — Peer identity role and genesis/profile scope contract audit

Date: 2026-11-17
Project: QRun Blockchain / QFP6 / QZXB
Branch: `feat/cp0704-dual-attestation-rotation-gate-20261116`
Worktree: `D:\Temp\ASUS\QRUN_CP0704_DUAL_ATTESTATION_20261116`
Base HEAD observed: `5aba5f69d24fce03af742fd1bebf13ad00e5d9c3`
Disposition: READ-ONLY SOURCE AUDIT COMPLETE; PROTOCOL SEMANTICS NOT APPROVED; NO RUNTIME SOURCE CHANGES.

## 1. Executive result

CP-0745 confirms the two CP-0741 gaps remain real in the current source. The repository contains textual `seed` / `joining` roles in the dual-attestation flow, and QVDN contains a genesis-state-root field. However, no authoritative contract currently connects either fact to the numeric peer-anchor role byte or to `PeerIdentityAnchorScope.genesis_root`.

Therefore:
- Do not infer numeric PeerIdentity roles from test fixture value `1`.
- Do not reuse transport client/server role bytes.
- Do not equate `genesis_root` to QVDN `genesis_state_root` in production code without an explicitly versioned scope contract and independently trusted expected-profile inputs.
- Do not change or reinterpret PIV1 anchor records.
- Do not wire the composite proof into node startup or activate any identity.

The safe result of this checkpoint is a verified contract gap and a concrete V2 proposal for review, not an unsafe code patch.

## 2. Repository evidence rechecked

### 2.1 Peer-anchor role

Current source:
- `peer_identity_anchor_vault.rs`: `PeerIdentityAnchorScope.role` is a raw `u8`; its byte is incorporated directly into the scope digest. Open rejects zero but does not decode a role enum.
- `noise_identity_rotation_authorization.rs`: dual-attestation fixtures and intent construction use textual `seed` role values. The authorization verifier supports the textual roles `seed` and `joining`.
- `noise_identity_rotation_authorization_verify.rs`: preflight parsing accepts the text values `seed` and `joining`; this is not a numeric anchor-scope codec.
- Recursive source search in the active `src/native/pow_bench/src` tree found the scope struct plus three concrete initializers, all in test/fixture contexts and all using `role: 1`. No production peer-identity scope constructor or canonical numeric decoder was found.

### 2.2 Transport role bytes are a different namespace

`auth_transport.rs::role_byte` accepts byte values 1 and 2 for authenticated transport client/server direction. Its consumers include node/sync/import transport paths. Those meanings are not peer identity classes and must not be reused to infer Seed/Joining.

The separate `offline_signing_key_store::SigningKeyRole` enum describes signing-key custody duties (for example deployment authority, governance root, recovery, and peer issuer). It is also not a node identity role.

### 2.3 Genesis and profile scope

`devnet_profile_candidate.rs` constructs a QVDN profile manifest whose core binds:
- network ID;
- profile ID;
- consensus-parameter digest;
- genesis state root;
- zero account count and explicit zero-value mode.

The manifest's final digest is an unkeyed SHA-256 integrity digest. `DevnetProfileCandidate::verify_manifest` checks exact equality to a locally constructed expected candidate. This can verify that supplied bytes match caller-provided expected values; it does not by itself authenticate the origin of the expected profile or provide an independent signature.

Current source search found:
- QVDN uses `genesis_state_root` in its own profile-manifest encoding and verification.
- Peer-anchor scope uses `genesis_root` only as an opaque 32-byte scope field and includes it in the scope digest.
- No source call compares `PeerIdentityAnchorScope.genesis_root` with `VerifiedDevnetManifest::genesis_state_root()`.
- DPC1 and IRG1 trust artifacts bind deployment/governance/issuer information and sequence floors but do not supply the missing genesis-root meaning.
- The QFP6 manifest Anchor Vault is a separate anchor domain; CP-0705 documents that it is not yet the peer-identity generation anchor.

Consequently, a nonzero 32-byte value in the scope is not evidence that it is the correct genesis root for the selected profile.

## 3. Cross-check against prior design and implementation

CP-0703 requires the signed rotation intent to bind the textual Seed/Joining role, network/profile, issuer/credential/key, generations, fingerprints, DPC1/IRG1 digests, evidence, policy, and nonce. It explicitly requires independent signer pins and a deterministic versioned encoding.

CP-0704 implements the dual-signature authorization and the mandatory `rotate-peer` gate. Its latest superseding status confirms targeted tests, while durable nonce replay protection, independently protected monotonic identity anchoring, signer-pin provenance, endpoint/fingerprint evidence qualification, session drain, and independent review remain open.

CP-0705 proposes a local C:-volume peer identity anchor compared with D:-volume identity generation state. It explicitly limits that assurance to D:-only rollback detection while C: remains intact; it is not a TPM monotonic counter, independent remote witness, or defense against whole-machine rollback.

CP-0741 already identified that neither numeric role mapping nor genesis/profile semantic provenance exists. This CP-0745 re-search confirms no intervening implementation has closed either gap.

CP-0742 and CP-0743 establish durable DPC1/IRG1 high-water stores and exact-current checks against already-open store objects. Those checks validate current accepted trust state; they do not define role codes or genesis semantics.

CP-0744 confirms there is still no production caller of `verify_anchored_successor_proof`. The current preflight CLI is not that caller and does not authorize rotation activation.

## 4. Proposed V2 scope contract — REVIEW REQUIRED, NOT IMPLEMENTED

The following is a proposal to make the next decision concrete. It is not an assertion that the protocol has already adopted these values.

### 4.1 Role namespace

Introduce a dedicated peer-identity enum with an explicit versioned codec. A reasonable candidate mapping is:
- `0x01 = SEED`
- `0x02 = JOINING`
- `0x00 = invalid`
- all other values = unsupported/invalid unless a later schema version explicitly assigns them.

The mapping must be defined by the peer-identity protocol itself. It must have no semantic dependency on transport client/server direction or signing-key custody roles. Textual `seed` / `joining` in the signed intent must map through one canonical encoder/decoder to the dedicated enum; unknown strings and bytes must fail closed.

### 4.2 Genesis/profile provenance

A V2 scope must distinguish at least:
- network ID;
- profile ID;
- profile family/mode (including normal versus test-PoW or zero-value public-testnet mode);
- consensus-parameter digest;
- the specifically defined genesis commitment;
- a digest identifying the trusted profile descriptor/configuration used to derive those values.

Candidate semantics for a QVDN-backed devnet are that the scope's genesis commitment equals the expected QVDN `genesis_state_root`. This equality is only valid after the protocol explicitly adopts it and the caller supplies a locally constructed expected profile from independently trusted configuration. The QVDN bytes and their unkeyed digest alone are not an independent trust source.

For profiles beyond that QVDN devnet family, do not silently reuse the same interpretation. A separate signed/versioned profile descriptor or another explicitly trusted genesis/profile source may be required. DPC1/IRG1 as currently defined do not fill this gap.

### 4.3 Versioning and migration

Do not reinterpret PIV1 role bytes in place. The current PIV1 domain/version commits a digest built from the raw role byte; changing its meaning retroactively could make an old anchor appear to belong to a different identity class.

After protocol approval, introduce a new scope schema and domain-separated V2 digest (and a separately versioned on-disk anchor format or equivalent explicit schema discriminator). Existing PIV1 records must remain readable only under their original semantics. Any PIV1-to-V2 migration must be a separate reviewed, explicit operation that binds the old chain tip, the new V2 scope, the trusted expected profile, and the approved role conversion. No automatic bootstrap or reinterpretation is permitted.

## 5. Required tests before V2 implementation can be accepted

Role tests:
- positive canonical Seed and Joining encodings;
- unknown, zero, reserved, malformed, and unsupported-version values rejected;
- textual intent role and numeric V2 scope role must agree exactly;
- role confusion across two scopes must fail.

Profile/genesis tests:
- exact network/profile/profile-family/consensus/genesis match succeeds;
- wrong network, profile, family/mode, consensus digest, genesis root, descriptor digest, and QVDN bytes fail closed;
- the unkeyed QVDN digest is never treated as an issuer signature;
- missing or untrusted expected-profile configuration fails closed;
- a test-PoW profile cannot be silently accepted where the selected profile requires normal PoW, and vice versa.

Version/migration tests:
- PIV1 records are never decoded as V2;
- PIV1 scope digest remains byte-for-byte stable;
- unsupported schema versions fail closed;
- explicit migration requires the exact old chain tip and independently trusted V2 inputs;
- interrupted migration never leaves two competing active scopes.

Integration tests:
- composite proof receives the validated typed scope and the already-open C/D/DCS1/IRH1 stores;
- no proof path observes/accepts trust state, creates missing state, repairs files, or activates an identity;
- no listener or node starts from an evidence-only proof result.

## 6. Worktree, validation, and safety

- This checkpoint used read-only searches and reads of the isolated CP-0704 source/docs.
- Recursive search found no production scope constructor or canonical peer-role decoder.
- No Rust source, test, key, anchor, identity, deployment config, node, listener, public network, or website was changed or accessed for mutation.
- No tests were run because no code changed in this checkpoint.
- No file was staged; no commit, push, PR update, merge, reset, checkout, clean, stash, or worktree cleanup was performed.
- Before CP-0745, the isolated worktree had 7 modified tracked files and 52 untracked files (59 status entries). All pre-existing changes were preserved.
- The protected `AI_NATIVE_L1_G2_G8_20261024` worktree remains on `feat/qrun-qvap-offline-prototype-20261030` at `801471c90b307a5c12f6785173d2d8986ffb74d3`, clean at the time checked. It is not the `main` branch.
- The root checkout `C:\Users\ASUS\Desktop\AI_NATIVE_L1` is on `work/cp0390-pfm5-checkpoint-fork-choice` at `69eb732d2672f5b9aa1bc4ee9c3c80402cff8a47` with four pre-existing untracked private/handoff files. They were not opened or modified.
- The local `origin/main` remote-tracking ref observed in the isolated repo is `7160f5364d610152c16626c187f03f9f870fd0bb`; this is a local cached ref, not a live GitHub verification.
- The connected GitHub API returned HTTP 403 with the message `Your account was suspended`; therefore remote branch/PR/CI state could not be verified in this session. Do not infer from this response alone that the repository itself is suspended or unavailable.

## 7. Exact continuation point

CP-0745 closes the source audit, not the protocol decision.

Next safe sequence:
1. Owner/reviewer approves or changes the peer-identity numeric role mapping and the semantic source of genesis/profile scope.
2. Freeze a versioned V2 scope specification, trust-input provenance, and explicit PIV1 migration policy.
3. Implement the pure V2 codec and negative/positive vectors in a fresh isolated checkpoint without touching PIV1 semantics.
4. Implement a dedicated read-only anchored-proof caller using already-open stores and trusted launch inputs.
5. Only after independent review and separate recovery/activation gates, consider any startup integration. This checkpoint does not authorize identity activation, peer trust changes, or node startup.

Current disposition: CP-0745 audit complete; V2 contract pending explicit protocol approval; Mainnet and public-network readiness are not affected or advanced by this checkpoint.
