# CP-0744 — Production anchored-proof caller integration audit

Date: 2026-11-16
Disposition: read-only caller audit; no runtime source changes.

## Findings

1. Repository-wide source search finds no production call to verify_anchored_successor_proof. Its only current callers are the synthetic unit-test cases in noise_identity_rotation_authorization.rs.
2. private_testnet_node opens and retains DCS1, verifies/observes DPC1, opens IRH1 under the verified DPC1 root chain, and accepts IRG1 before it opens peer identity generation state. These are real startup trust-state paths, but they do not construct the CP-0739/0740/0743 composite proof evidence.
3. chain_import_node likewise opens and retains DCS1/IRH1 and accepts DPC1/IRG1 before identity state. Its provider-bound Noise startup path does not call the composite anchored successor proof.
4. noise_identity_rotation_authorization_verify is not the composite proof caller. It verifies the owner-signed preflight authorization and explicitly reports independent operator signature as NOT_VERIFIED and ROTATE_PEER_AUTHORIZED=FALSE. It has no C anchor, D generation store, NPI1/NRT1 or DPC1/IRG1 high-water proof inputs.

## Integration decision

Do not silently wire the new proof into ordinary node startup. The current CLI and startup paths do not carry the full exact evidence bundle needed by the composite proof, and CP-0741's numeric identity-role and genesis/profile provenance contract remains unresolved.

The next implementation should be a separately scoped, read-only proof-verification entrypoint or a clearly isolated library caller that:
- receives explicit paths for the already-protected C, D, DCS1 and IRH1 stores;
- opens each store exactly once and retains its writer lock for the entire proof;
- receives bounded, regular-file evidence for previous/successor NPI1, NRT1, dual authorization and signed DPC1/IRG1;
- receives independent network, deployment-authority key/floor, root-chain and issuer pins from trusted configuration;
- calls the pure proof only after the caller has opened and validated all stores;
- never calls observe/accept during proof verification, never creates or repairs missing state, and never starts a node or listener;
- emits a machine-readable evidence-only result and never labels it activation/recovery authorization.

Before adding role/genesis checks, define the versioned peer-identity scope contract from CP-0741. The production caller must not invent a role-byte mapping or equate genesis_root with QVDN genesis_state_root without a signed/independently trusted schema contract.

## Validation and scope

- Read-only source/call-site audit; no runtime source changes.
- The CP-0743 focused proof test and module regressions passed.
- Full parallel library run: 1479 passed, 2 failed; both unrelated tests passed individually on immediate sequential rerun. The full run is not reported as wholly passing.
- No live node, listener, network, keys, deployment artifacts, production trust stores or public website were touched.
- No staging, commit, push, merge, reset or cleanup was performed.

## Resume point

CP-0743 exact-current DCS1/IRH1 proof binding is implemented and tested. CP-0744 establishes that no production composite-proof caller exists yet. Next safe task: formalize CP-0741 role/genesis scope contract, then implement a dedicated read-only proof-verification caller; do not add recovery or activation behavior.
