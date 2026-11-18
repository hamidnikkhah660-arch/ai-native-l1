# CP-0703 — Dual Attestation and Peer Identity Anchor Design — 2026-11-16

## Purpose
Convert the CP-0702 audit findings into a reviewable implementation contract. This checkpoint is a design artifact only. It does not change runtime behavior, create keys, authorize rotation, or qualify a host.

## Design A — two independent signatures over one immutable rotation intent

### A1. Objects and signing order
1. Construct an immutable `RotationIntent` from the exact prepared rotation manifest and the independently reviewed policy/evidence references.
2. Serialize it using one deterministic encoding. Preferred initial implementation: a versioned, length-delimited binary wire format with fixed field order and explicit integer widths; do not sign an arbitrary reserialized `serde_json::Value`.
3. Compute `intent_digest = SHA-256(domain || encoded_intent)` where the domain is a new, versioned constant such as `QFP6-NOISE-ROTATION-INTENT-V2\0`.
4. The independent operator signs `operator_domain || intent_digest` using their own Ed25519 key. The verifier must compare the operator public-key fingerprint against an operator pin delivered out-of-band and independently of the owner authorization file.
5. The owner signs `owner_domain || intent_digest || operator_key_fingerprint || operator_signature_digest`, using the existing pinned owner authority. This proves the owner approved this exact intent and this exact operator attestation, without a circular signature dependency.
6. The final envelope carries the encoded intent, operator public key or key identifier (not trusted merely because it is included), operator signature, owner signature, and required pin identifiers. The verifier validates both signatures and both independently supplied pins before accepting.

### A2. Mandatory intent bindings
The encoded intent must bind, at minimum:
- schema/version and explicit `ZERO_VALUE_PUBLIC_TESTNET_ONLY` scope;
- network ID and consensus/profile ID;
- Seed or joining role;
- deployment-config digest and issuer-registry digest;
- issuer ID, credential ID, and key ID;
- previous and next identity generation, with `next > previous` and no generation wrap;
- old and new Noise public-key fingerprints;
- exact prepared-manifest digest;
- exact Seed endpoint and expected remote Seed fingerprint where applicable;
- endpoint-verification and fingerprint-verification evidence digests;
- exact overlap/rollback policy content digest (not a human-readable policy ID alone);
- issued-at and expires-at bounds, with short maximum lifetime and bounded clock skew;
- unique authorization nonce / intent ID to support replay detection.

A human-readable operator ID, owner approval ID, policy ID, or evidence filename is metadata only. None substitutes for a signature, independently provisioned key pin, or content digest.

### A3. Verification rules
- Verify the owner public-key fingerprint against the owner pin supplied independently of the envelope.
- Verify the operator public-key fingerprint against a distinct operator pin supplied independently of the envelope. Reject equal owner/operator fingerprints even if IDs differ.
- Verify both signatures over the same exact intent digest and reject malformed/non-canonical wire encodings, unknown critical fields, trailing bytes, duplicate fields, zero IDs, invalid key material, and unsupported versions.
- Recompute all manifest/config/registry/policy/evidence digests from the actual bounded regular files. A supplied digest without the corresponding file or independently trusted digest source is not evidence verification.
- Enforce exact network, profile, role, issuer, credential, key, generation, endpoint and old/new fingerprint equality against the inputs to `rotate-peer`.
- Reject stale generation, wrong previous identity, expired/future-dated authorization, replayed nonce, wrong scope, changed policy bytes, or mismatched operator pin.
- Verification must be read-only and must not install pins, activate a key, modify the peer registry, start a node, or open a listener.

## Design B — mandatory gate in `rotate-peer`

The artifact-generation path must not accept an authorization verifier's previous success as an unbound Boolean or console message. It must receive the immutable intent and both signatures/pins as explicit inputs and call the same in-process verifier immediately before artifact construction and output creation.

Required order:
1. Read and validate all bounded regular input files.
2. Verify DPC1 and IRG1 using the existing deployment/issuer trust roots.
3. Decode previous NPI1 and derive its network, issuer, credential, key, generation, and public fingerprint.
4. Derive the proposed next generation and new public fingerprint from the actual command inputs.
5. Recompute the exact intent digest from those derived values and the exact prepared manifest/policy/evidence files.
6. Verify operator signature and out-of-band operator pin.
7. Verify owner signature and out-of-band owner pin, including the operator-signature digest.
8. Only then construct NRT1/NPI1 and create the new output file atomically with create-new semantics.
9. On any failure, leave no output artifact and no mutation to active identity, peer trust, or runtime state.

The existing standalone preflight may remain as a convenience, but it must call the same verifier library and must never be treated as authorization by itself.

## Design C — peer-identity monotonic anchor

### C1. State record
Define a versioned record bound to `(network_id, profile_id, role, issuer_id, credential_id, key_id)` and containing:
- highest accepted identity generation;
- current and previous public-key fingerprints;
- lifecycle state (`PREPARED`, `ACTIVE`, `REVOKED`, `RETIRED`);
- exact accepted NPI1/NRT1 digest;
- last owner/operator intent digest and nonce;
- monotonic sequence and previous-record digest.

### C2. Trust boundary
The peer high-water store under the mutable node `data_dir` is not an independent anchor. The QFP6 manifest Anchor Vault is also not an identity anchor unless the implementation explicitly commits and verifies the peer-identity record digest and sequence. Merely placing a second copy on another directory or disk does not protect against an attacker who can roll back both.

Before implementation, select and document a trust anchor with a distinct failure/rollback domain, such as a remote independently administered append-only witness or a hardware-backed monotonic facility with a documented recovery and replacement model. A local second disk may improve accidental-loss recovery but must not be described as protection against whole-host compromise or coordinated rollback.

### C3. Startup and transition behavior
- Startup must compare local identity state with the independently authenticated high-water record before accepting any peer connection.
- Missing, stale, conflicting, unverifiable, or unreachable required anchor means fail closed for the affected identity; no silent reinitialization at generation zero.
- A new identity is first `PREPARED`; owner + operator authorization and the anchor's accepted transition move it to `ACTIVE`.
- Revocation/retirement advances the monotonic sequence and must make the old fingerprint unacceptable for new handshakes.
- Existing Noise sessions need an explicit bounded drain/reconnect policy. Updating trust files alone does not retroactively terminate established sessions.
- Recovery after TPM clear/replacement or host loss must use a separately protected recovery authority and must preserve or explicitly advance the anchored generation. No automatic fallback to an old private key or lower generation.

## Required tests before code can be considered complete

### Dual-signature tests
- valid operator + valid owner signatures pass;
- missing, malformed, modified, or wrong-key operator signature fails;
- operator key included in the envelope but not matching the independent pin fails;
- owner/operator same public key fails;
- owner signature over another operator signature or another intent fails;
- replayed nonce and changed manifest/policy/evidence digest fail;
- wrong network/profile/role/issuer/credential/key/generation/endpoint/fingerprint fails;
- expiry, future timestamp, excessive lifetime, unknown schema and malformed encoding fail.

### Mandatory-path tests
- `rotate-peer` without both signatures/pins fails before output creation;
- `rotate-peer` with a valid standalone preflight output but mismatched command inputs fails;
- a valid authorization succeeds only for the exact prepared artifact it signed;
- output path already exists, symlink, or write failure does not replace existing data or mutate active state.

### Anchor tests
- local state behind anchor fails closed;
- local state ahead of anchor fails pending explicit reconciliation;
- missing local state with an existing anchor cannot reset generation;
- deleted/rolled-back local directory cannot lower generation;
- missing/unavailable/unverifiable anchor fails closed according to the selected availability policy;
- old key is rejected after revocation at new-connection boundary;
- established session lifetime/drain behavior matches the signed policy;
- TPM clear/replacement and host-loss recovery cannot silently lower sequence or restore retired identity.

## Implementation decision gates
1. Independent review of this wire contract and trust-anchor choice.
2. Confirm the exact DPC1/IRG1/NPI1 fields available for binding; do not invent missing identifiers.
3. Implement a pure verifier library and deterministic wire vectors.
4. Integrate mandatory verification into `rotate-peer` and prove no output on every negative case.
5. Implement the independently protected monotonic anchor adapter and startup fail-closed check.
6. Run targeted tests, then full CI on an isolated feature branch/worktree. No activation or deployment is part of these steps.

## Current safety status
- Design only; no code or runtime behavior changed in this checkpoint.
- No private key was created, read, exported, or rotated.
- No owner or operator authorization was issued.
- No node, listener, Public Testnet, or Mainnet was started or deployed.
- The active working tree and all existing uncommitted/untracked artifacts remain preserved.
