# CP-0742 — DPC1 / IRG1 durable high-water integration audit

Date: 2026-11-16
Disposition: read-only source audit; no runtime source changes.

## Purpose

Determine whether the DPC1/IRG1 artifacts independently verified by CP-0740 are also checked against the currently accepted durable trust-state stores used by node startup.

## Findings

### A. DCS1 deployment-config high-water

noise_deployment_config.rs documents DCS1 as persisting the highest accepted DPC1 sequence and exact digest behind a stable writer lock.

DeploymentConfigStateStore::open:
- validates the nonzero minimum sequence and deployment-authority public key;
- binds the state to network ID and deployment-authority fingerprint;
- acquires SnapshotWriterLock;
- for an existing file, rejects symlinks/non-regular files/wrong size and verifies the checksum and identity fields;
- if the lock sibling existed but the state file is missing, returns StateMissing;
- only when both are absent does it create an empty bootstrap state.

observe(VerifiedDeploymentConfig):
- verifies network and deployment-authority identity and the configured minimum sequence;
- accepts the first signed manifest into an empty state;
- permits an idempotent restart only for the exact same sequence and digest;
- rejects lower sequences, same-sequence digest conflicts, and sequence jumps (subsequent updates must advance exactly one).

### B. IRH1 issuer-registry high-water

noise_issuer_registry.rs implements IssuerRegistryStateStore under a verified Governance root chain.

open_with_root_chain:
- validates network, current Governance key and minimum registry sequence;
- loads and decodes existing state against the verified root chain, allowing the persisted document's historical Governance key only when it is present in that verified chain;
- rejects a missing state when its stable lock sibling already exists;
- initializes an empty state only when both are absent.

accept_signed_registry:
- verifies the incoming IRG1 under the current Governance key and enforces the DPC1 minimum registry sequence;
- checks sequence rollback, same-sequence digest conflict, and permitted issuer lifecycle transitions;
- durably persists the accepted signed registry before selecting the requested issuer's active key;
- deliberately persists a revocation even when selected-issuer selection then returns IssuerInactive.

### C. Production-path call sites found

1. private_testnet_node.rs:
   - obtains deployment authority and minimum DPC1 sequence from its configuration;
   - verifies the signed DPC1;
   - opens DCS1 at data_dir/signed_trust_state/deployment-config.dcs1 and calls observe();
   - then opens the IRH1 registry state and accepts the signed IRG1 before proceeding to peer identity verification.

2. chain_import_node.rs provider-bound Noise XX path:
   - requires deployment config, DCS1 state path, out-of-band deployment-authority public key, and nonzero minimum DPC1 sequence;
   - parses the minimum from --peer-noise-deployment-min-sequence;
   - verifies DPC1, opens DCS1, and calls observe();
   - opens IRH1 under the verified DPC1 root chain and accepts IRG1 before proceeding to identity-generation state.

The repository therefore has runtime DPC1 and IRG1 anti-rollback enforcement in these two paths; it is not merely an unused storage primitive.

## CP-0740 boundary

verify_anchored_successor_proof currently:
- verifies DPC1 with a caller-supplied deployment-authority key and minimum DPC1 sequence;
- verifies IRG1 using the DPC1 Governance key;
- enforces DPC1 minimum_registry_sequence and the selected issuer's Active status/key.

It does not receive or query the already-accepted DCS1 / IRH1 state. Consequently, its result proves the supplied DPC1 and IRG1 artifacts are internally valid and meet the caller/DPC1 floors; it does not prove they are the exact currently accepted durable trust-state versions when a later DPC1 or IRG1 has already been accepted by a node.

The DCS1 and IRH1 store objects already hold their writer locks while open. A safe read-only proof integration should query already-open, initialized store objects rather than reopening paths inside the proof builder. This avoids accidental bootstrap writes from open() when both the state and lock files are absent.

## Next engineering step (CP-0743)

Add non-mutating exact-current checks to the existing store APIs:
- DCS1: require nonzero initialized high-water and exact equality of DPC1 sequence and manifest digest (plus existing network/authority binding).
- IRH1: require initialized accepted wire, verify it through the store's verified historical/current Governance root chain, and require exact equality of IRG1 sequence and digest to the proof's registry (plus network/issuer and current active-key equality).
- Pass references to the already-open stores into the pure proof builder. It must not call observe(), accept_signed_registry(), create state, or write either store.
- Test stale-but-valid DPC1 and IRG1 against a newer accepted store state, exact current success, uninitialized/missing states, same-sequence digest conflict, and persisted revocation.
- Keep the read-only proof and any future recovery writer separate.

## Scope and safety

- Read-only source inspection only.
- No DCS1/IRH1 file or production state was opened or modified.
- No keys, node processes, network listeners, endpoints, deployment, public website, or real identity were touched.
- No code changed in this checkpoint. Existing DCS1/IRH1 tests were run as a focused regression audit; results are below.
- No staging, commit, push, merge, reset, or cleanup was performed.

## Resume point

CP-0740 DPC1/IRG1 signature and sequence validation is implemented and tested. CP-0741 records role/genesis schema gaps. CP-0742 establishes the next concrete integration task: make the pure anchored proof check the exact current DCS1 and IRH1 high-water without mutating either store.


## Validation

- cargo test --manifest-path src/native/pow_bench/Cargo.toml --lib noise_deployment_config::tests:: -- --nocapture: PASS ? 3 passed, 0 failed.
- cargo test --manifest-path src/native/pow_bench/Cargo.toml --lib noise_issuer_registry::tests:: -- --nocapture: PASS ? 5 passed, 0 failed.
- git diff --check: PASS (exit code 0; existing LF/CRLF notices only).
