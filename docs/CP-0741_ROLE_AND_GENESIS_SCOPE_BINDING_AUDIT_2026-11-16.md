# CP-0741 — Identity role and genesis scope binding audit

Date: 2026-11-16
Disposition: read-only contract audit; no runtime source changes.

## Purpose

Close the two explicit CP-0740 proof-boundary questions without inventing a protocol mapping:
1. Does an existing signed trust artifact bind PeerIdentityAnchorScope.genesis_root?
2. Is there an authoritative mapping from the scope numeric role byte to the dual-authorization role string (seed / joining)?

## Findings

### A. QVDN profile manifest

devnet_profile_candidate.rs defines a canonical fixed-length QVDN manifest. Its core contains:
- network ID;
- profile ID;
- consensus parameter digest;
- genesis state root;
- zero account count;
- explicit zero-value mode byte.

The final 32 bytes are SHA-256(MANIFEST_DOMAIN || manifest_core). This is an unkeyed integrity digest, not a digital signature or independently authenticated attestation.

DevnetProfileCandidate::verify_manifest compares the exact bytes with a locally constructed expected profile and checks network, profile, consensus, genesis state root, zero premine/value flags, and digest. Thus it can establish equality to a caller's locally constructed candidate profile. It does not establish the origin or independent authorization of a QVDN file.

The source has no proven contract stating that PeerIdentityAnchorScope.genesis_root is semantically identical to VerifiedDevnetManifest::genesis_state_root, or that every peer-identity proof must use the default (rather than test-PoW) DevnetProfileCandidate. Accordingly, CP-0741 does not equate those fields or silently force a particular Devnet profile into the proof API.

DPC1 contains network, sequence, Governance/anchor/recovery keys, root and registry floors, and a verified GRC1 chain. IRG1 contains network, sequence, issuer IDs, keys and statuses. Neither schema includes a genesis state root.

### B. Numeric role byte

PeerIdentityAnchorScope.role is an opaque nonzero byte included in the C scope digest. Current concrete scope initializers found in the active source are test fixtures and use value 1; there is no production enum or documented mapping for peer identity roles.

auth_transport.rs::role_byte accepts only bytes 1 and 2. Its consumers use those values for authenticated transport client/server direction (auth_node, auth_sync_node, chain_import_node); the ACK is fixed to role 2. This is a transport-level role, not evidence that 1 means seed or 2 means joining.

offline_signing_key_store::SigningKeyRole is a separate enumeration of signing-key custodial roles (DeploymentAuthority, GovernanceRoot, OfflineRecovery, PeerIssuer, etc.) and is also not a node identity role.

The dual-attestation intent and prepared identity use textual seed / joining values, but CP-0703/0704 do not define the numeric C-scope encoding. Mapping the byte based on current test fixture value 1 or on either unrelated role enumeration would be guesswork and could cause a scope-confusion bug.

## Decision

No role mapping and no genesis-root equality assertion are added in this checkpoint. The proof remains fail-closed on its current exact scope comparison, but these two dimensions are still only bound to C's stored scope digest, not cross-validated against signed identity-profile metadata.

## Required contract before implementation

1. Define a versioned peer-identity scope schema with explicit stable numeric role codes and a single canonical decoder/encoder. Specify seed and joining values in the protocol contract; do not reuse transport client/server codes or signing-key custody role codes.
2. Specify the semantic source of genesis_root (including whether it is exactly the QVDN genesis state root), profile family (normal/test-PoW), and the trusted construction/verification path.
3. If QVDN remains the source, require the caller to supply a locally constructed expected DevnetProfileCandidate from independently trusted configuration, then compare verified network/profile/genesis outputs to the anchor scope. Document that QVDN's unkeyed digest is not an external signature.
4. Add positive and fail-closed tests for each supported role, unknown role values, wrong profile, wrong genesis root, wrong network, altered manifest and profile-mode mismatch.
5. Version/migrate the C anchor scope digest only through an explicit reviewed migration; never reinterpret existing role bytes in place.

## Scope and safety

- Read-only source and checkpoint review only.
- No peer identity, C/D state, key material, node, listener, network endpoint, deployment artifact, public site or runtime configuration was touched.
- No tests were run because no code changed; CP-0740 test/build results remain as recorded in its own checkpoint.
- No file staging, commit, push, merge, reset, or cleanup was performed.

## Resume point

CP-0740 DPC1/IRG1 verification is complete. The next safe engineering task is to agree and encode the peer-identity scope contract (role values and genesis/profile provenance) before changing proof semantics.
