# CP-0749 — Signer trust bundle and independent governance-root floor design

Date: 2026-11-17
Project: QRun Blockchain / QFP6 / QZXB
Branch: `feat/cp0704-dual-attestation-rotation-gate-20261116`
Worktree: `D:\Temp\ASUS\QRUN_CP0704_DUAL_ATTESTATION_20261116`
Base HEAD observed: `5aba5f69d24fce03af742fd1bebf13ad00e5d9c3`
Status: DESIGN ONLY; NO SOURCE CHANGE; NO REAL SIGNER ENROLLMENT; NO KEY GENERATION/PROVISIONING.

## 1. Purpose and decision

CP-0748 established that the existing `rotate-peer` dual-signature verifier validates supplied public keys, their caller-supplied SHA-256 pins, and both signatures, but does not authenticate the provenance of the owner/operator pins.

CP-0749 defines a candidate trust path and a new versioned Signer Trust Bundle (STB1) contract. It is not a deployed or implemented registry. No real owner/operator key, identity, fingerprint, or independent operator is available from this audit.

Two separate security problems must be fixed:
1. **Identity provenance:** the expected owner and independent-operator fingerprints must come from an already trusted registry, not from the same `rotate-peer` invocation that supplies the signatures.
2. **Root rollback:** the governance root epoch floor must be supplied independently to DPC1/GRC1 verification rather than being accepted only from a value embedded inside the DPC1 file.

Neither problem can be solved by generating another key pair inside the same provisioner or by declaring the signer IDs in JSON.

## 2. Existing trust path — verified facts

### 2.1 Bootstrap roles

`devnet_trust_provisioner::build_bootstrap_artifacts` constructs four distinct key roles:
- deployment authority;
- governance root;
- offline recovery;
- peer issuer.

The initial GRC1 chain is created as a zero-transition chain whose anchor is the governance root. DPC1 is signed by the deployment authority and carries governance, root-anchor, recovery, minimum-root-epoch, and minimum-registry-sequence fields. IRG1 is signed by the governance root.

The bootstrap function verifies the newly constructed DPC1 and IRG1 against those same in-memory key pairs. This is a construction self-check, not the out-of-band trust ceremony. The bootstrap function does not enroll owner or operator signer identities.

### 2.2 Out-of-band deployment authority

The current node configuration requires:
- DPC1 file path;
- deployment-authority public key supplied through a runtime option;
- minimum DPC1 sequence supplied through a separate runtime option.

The DPC1 verifier checks the signature against that externally supplied public key, checks network and minimum sequence, and returns a typed `VerifiedDeploymentConfig`. The DPC1 signature covers the entire encoded GRC1 root chain and all DPC1 fields. It requires deployment, governance, anchor, and recovery public keys to be distinct.

The node then persists the highest accepted DPC1 sequence and exact signed DPC1 digest in DCS1 (`DeploymentConfigStateStore`) under its configured trust-state directory. DCS1 rejects sequence rollback, same-sequence/different-digest conflicts, missing state after a lock file exists, and non-consecutive sequence jumps.

This is a plausible trust chain for a future signer registry:
1. Independently pinned deployment-authority public key and minimum DPC1 sequence.
2. Verify the complete DPC1 signature and DPC1 sequence.
3. Verify the GRC1 chain carried inside the authenticated DPC1.
4. Resolve the current governance root from that verified GRC1 chain.
5. Verify an STB1 bundle signed under a dedicated domain by the authorized signer-registry authority.

The current code has no STB1 type or API and does not apply this chain to owner/operator keys.

### 2.3 Governance-root epoch-floor gap

GRC1's module contract states that the first root is pinned out of band and that the operator supplies a minimum root epoch independently of writable registry state.

However, the current `verify_signed_deployment_config` signature accepts:
- expected network ID;
- deployment-authority public key;
- minimum DPC1 sequence.

It parses `minimum_root_epoch` from the DPC1 bytes and passes that embedded value to `verify_governance_root_chain_with_recovery`. The current node call sites do not pass a separate externally configured minimum root epoch into this DPC1 verifier.

DCS1 persists the exact signed DPC1 digest and highest DPC1 sequence, so it indirectly detects a replayed older DPC1 while that DCS1 state and the configured external sequence floor remain trusted. DCS1 does not persist a separately named root-epoch high-water. It is stored under the runtime-configured state path and is not hardware- or remote-witness-backed against rollback of that entire state volume.

Required correction:
- Add a strict DPC1 verification API that takes an independently supplied `minimum_root_epoch` (or a typed immutable trust-floor object).
- Verify the embedded DPC1 floor is nonzero and is not below the external floor.
- Verify the GRC1 tip epoch is at least the external floor, not merely the DPC1-embedded floor.
- Pass this independent floor at every production/testnet node call site and document where it is stored and how it is recovered.
- Preserve DCS1 sequence/digest monotonicity; do not treat DCS1 as an independent physical witness.
- Add tests showing that a valid signed DPC1 carrying a too-low embedded root epoch is rejected when the external floor is higher, even if its DPC1 sequence is otherwise acceptable.

The existing verifier must not be described as already accepting an independently supplied GRC1 minimum epoch at its DPC1 boundary.

## 3. STB1 — proposed canonical wire contract

STB1 is a proposed separate signed registry. It does not exist in the current source tree. The exact schema below is a design proposal that must receive source review before implementation.

### 3.1 Header and domain

Proposed:
- magic: `STB1`;
- version: `1`;
- dedicated signature domain: `QFP6-SIGNER-TRUST-BUNDLE\0v1`;
- bounded fixed-order binary encoding; no JSON canonicalization in the signed preimage;
- SHA-256 digest over the complete canonical signed bundle for chain-linking and receipts;
- one bundle per network and QFP6 profile.

The STB1 signing domain must be distinct from DPC1, GRC1, IRG1, NPI1, NRT1, and the QFP6 rotation-authorization domains.

### 3.2 Bundle-level fields

Minimum proposed fields:
- magic, version, reserved bytes with required zero values;
- network ID (32 bytes);
- profile ID (32 bytes);
- bundle sequence (nonzero u64);
- previous bundle digest (32 bytes; all zero only for explicitly approved first enrollment);
- current governance-root epoch (u64);
- governance-root public-key fingerprint (32 bytes);
- signer record count (bounded, nonzero);
- signer records in canonical deterministic order;
- issuing governance-root signature (64 bytes).

The verifier must receive a cryptographically verified DPC1/GRC1 context and must compare the STB1 network, profile and governance-root epoch/fingerprint to that context. A bundle must not choose its own trusted network/profile/root context.

### 3.3 Signer record fields

Each signer record binds:
- signer ID (strict bounded ASCII identifier with canonical normalization rules);
- role code: `0x01 = OWNER_AUTHORIZER`, `0x02 = INDEPENDENT_OPERATOR`;
- generation (nonzero u64);
- Ed25519 public key (32 bytes);
- SHA-256 public-key fingerprint (32 bytes), required to equal SHA-256 of the exact public-key bytes;
- lifecycle: `ACTIVE`, `RETIRED`, or `REVOKED`;
- activation epoch/sequence;
- optional retirement/revocation epoch/sequence, with strict field consistency;
- bounded purpose/scope code identifying peer-identity rotation authorization only.

No record may carry private key bytes. Unknown role, lifecycle, reserved bit, noncanonical identifier, duplicate signer ID, duplicate fingerprint, invalid key, zero generation, or noncanonical record order must fail closed.

### 3.4 Required role constraints

Before a production `rotate-peer` authorization can be accepted:
- exactly one active `OWNER_AUTHORIZER` key is required for the relevant project/network/profile/scope;
- at least one active `INDEPENDENT_OPERATOR` key is required;
- owner and operator IDs and public-key fingerprints must differ;
- the same key may never satisfy both roles;
- the owner signature is verified only against the active owner record;
- the operator signature is verified only against an active operator record;
- revoked/retired records never become active again under the same generation;
- role reassignment or key replacement requires a new monotonic bundle sequence and signer generation.

A distinct key is not automatically an independent operator. Independence is an operational/social fact that requires a real separate custodian and explicit evidence of control; code can verify distinct keys and signed receipts but cannot prove that two keys are controlled by different humans or organizations.

## 4. Enrollment and rotation ceremony

### 4.1 Initial trust enrollment

Do not enroll real signers until:
1. The deployment-authority fingerprint and initial minimum DPC1 sequence are confirmed through an independently controlled channel.
2. The initial GRC1 trust anchor/current governance root and offline-recovery fingerprint are authenticated through the DPC1/GRC1 trust process.
3. The proposed signer registry authority is explicitly authorized by the project's governance policy. This authority is not currently defined in DPC1/IRG1.
4. The proposed owner authorizer public-key fingerprint is independently confirmed by the owner.
5. A genuinely separate operator supplies and confirms their public-key fingerprint and signs an acceptance receipt for the assigned role/scope.
6. Both role assignments and their scope are reflected in the initial STB1, signed by the authorized governance-root key and countersigned/accepted by each signer.
7. The bundle digest, sequence, network, profile, root epoch, and signer records are exported as a human-verifiable receipt and stored through the separately reviewed trust-bundle storage policy.

If an independent operator is not yet available, production dual-attestation is not ready. Do not substitute the project owner, a synthetic test key, a second key controlled by the same owner, or a bot that does not constitute an independent custody domain.

### 4.2 Routine signer rotation

A normal signer-key rotation should require:
- current STB1 sequence and digest;
- current governance-root authorization under the verified GRC1 tip;
- signature/consent by the signer being replaced where that signer is available;
- acceptance receipt signed by the new key;
- no key reuse across owner and operator roles;
- exactly one bundle-sequence increment;
- a signed predecessor digest link;
- a monotonic signer generation increment;
- append-only audit receipt.

If the old signer is unavailable/compromised, use a separately documented governance recovery path. Never silently replace the key or lower the generation.

### 4.3 Revocation

Revocation is monotonic and terminal for a given signer generation. A revoked signer record remains in the bundle history or a verifiable append-only history; a new key must use a new generation and separately authorized enrollment. An issuer or governance-root rotation does not by itself prove owner/operator continuity.

## 5. Provisioner API changes required later

The current `rotate-peer` CLI pin arguments are not trust anchors. A future implementation should:
- consume a previously verified `VerifiedSignerTrustBundle` (or equivalent opaque verified context);
- take signer IDs/roles and the candidate public-key/signature files as inputs;
- resolve expected keys and fingerprints only from the verified active STB1 records;
- reject any caller-provided pin that differs from the registry (or remove pin arguments entirely);
- bind the STB1 bundle digest/sequence, signer IDs, signer generations, owner/operator fingerprints, and both signatures into the rotation intent;
- emit a receipt containing the STB1 digest/sequence and the exact signer identities used;
- keep NPI1 preparation separate from PIV2 `ROTATION_PREPARED` and from any later `ROTATION_ACTIVE` operation.

The STB1 verifier must not accept a caller-created object that merely claims to be verified. It must be constructed only after DPC1/GRC1 and STB1 signatures, domain, profile, epoch, sequence, predecessor digest, signer roles, and signer acceptance receipts have all been checked.

No changes to `SigningKeyRole`, ASK1, DPAPI custody, or the live provisioner are part of CP-0749.

## 6. Storage and rollback requirements

STB1 and its monotonic high-water must not be stored only beside writable DPC1/IRG1 files. At minimum:
- use a separately controlled trust directory with reviewed Windows DACL and explicit path/volume validation;
- persist the highest accepted STB1 sequence and exact digest;
- keep its writer-lock state and bundle state under the same reviewed ACL policy;
- fail closed if a prior lock/high-water artifact exists but the state file is missing;
- reject rollback, gaps, same-sequence digest conflict, duplicate signers, and reused generations;
- independently preserve the last accepted bundle digest in a second trust domain or witness before claiming stronger rollback resistance;
- distinguish local C:/D: dual-disk detection from TPM-backed, remote-witness, or hostile-administrator resistance.

The existing C QFP6 manifest anchor directory must not be repurposed without a separate format, ACL, and namespace review. The proposed PIV2 directory is currently absent.

## 7. Required tests before implementation acceptance

- Valid DPC1 signed by the independently configured deployment authority verifies.
- Wrong deployment-authority key, network, signature, minimum config sequence, and truncated DPC1 reject.
- Validly signed DPC1 whose embedded `minimum_root_epoch` is below the independent external root epoch floor rejects.
- GRC1 wrong anchor, wrong current tip, insufficient epoch, wrong recovery key, discontinuous epoch, wrong signature, and network mismatch reject.
- STB1 wrong magic/version/domain, trailing data, reserved bits, field lengths, duplicated ID/fingerprint, noncanonical order, unsupported roles/lifecycle, and malformed keys reject.
- STB1 wrong network/profile/root epoch/governance fingerprint or invalid governance signature reject.
- First bundle requires an explicit enrollment policy; it cannot self-enroll merely because a directory is empty.
- Owner/operator identity and fingerprint collision rejects.
- Same key used under both roles rejects.
- Missing/invalid owner or operator acceptance receipt rejects.
- Caller-supplied pin conflict with the trusted STB1 record rejects.
- Revoked/retired signer, stale signer generation, old bundle sequence, changed bundle digest at same sequence, predecessor mismatch, and sequence gaps reject.
- DCS1/STB1 rollback, missing-state-after-lock, and cross-store mismatch reject.
- Crash/restart and file replacement tests preserve the exact accepted bundle and sequence.
- Windows ACL, reparse-point ancestry, file-handle identity, volume identity, path-swap, and physical power-loss tests qualify the actual storage boundary.

Tests must begin with deterministic synthetic test keys under unique temporary directories. Synthetic success is never reported as production owner/operator enrollment.

## 8. Recommended engineering sequence

1. **CP-0750 — strict DPC1/GRC1 root-floor API:** add an independently supplied minimum root epoch to the verified DPC1 trust context, retain compatibility only through clearly labeled non-production legacy APIs, and add direct/host-level tests for rollback floors.
2. **CP-0751 — STB1 codec and verifier:** implement only the canonical signed wire format and pure verification against a fully verified DPC1/GRC1 context; no key storage, enrollment, CLI integration, or startup activation.
3. **CP-0752 — signer acceptance and sequence state:** implement deterministic, append-only bundle chain and high-water using disposable test roots; verify exact owner/operator acceptance receipts.
4. **CP-0753 — trust-bundle storage qualification:** Windows path/reparse/ACL/volume binding and crash/recovery design; do not use live C/D paths until separately approved.
5. **CP-0754 — provisioner read-only integration:** consume a verified STB1 object and bind the exact signer generations/digests; still no node activation.
6. **Only after independent review:** read-only PIV2/D-side reconciliation caller before listeners, then explicitly gated activation and session lifecycle handling.

## 9. Current disposition and safety

- Existing dual-attestation cryptographic verification: implemented.
- Independent signer-pin provenance: not implemented.
- STB1 signer trust bundle: design only, not implemented.
- External root epoch floor at DPC1 verification boundary: not currently an explicit input; correction designed, not implemented.
- DPC1 deployment authority and minimum config sequence are runtime inputs; DCS1 tracks DPC1 sequence/digest on the configured local state path.
- PIV2 runtime caller and C/D production reconciliation: absent.
- No real owner/operator keys or pins were read, generated, stored, or rotated.
- No source, runtime configuration, C/D state, ACL, volume, wallet, node, listener, or network state was changed.
- No commit, push, PR update, merge, reset, checkout, clean, stash, or worktree cleanup was performed.

Gate 8 remains OPEN. Owner/operator trust enrollment, production peer-identity activation, mainnet readiness, token release, liquidity, public trading, and mining readiness remain NO-GO until their separate evidence gates pass.

[executed on device: heymed (de0adbe3-6583-4775-a26e-c479a62aa941)]
