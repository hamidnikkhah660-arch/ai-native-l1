# CP-0645 — Explicit Fail-Closed Trust-Registry Rotation

Date: 2026-11-14  
Project: AI-NATIVE L1 / QRUN-QFP6  
Depends on: CP-0640B  
Status: implementation and targeted validation complete; local working tree only

## Finding

Q6PA V4 persisted the full trust-registry fingerprint and ordinary startup correctly rejected any changed registry. However, even after every old unapproved Q6AR candidate expired, there was no explicit operator-controlled route to replace that fingerprint. This made registry/key rotation permanently fail closed without a migration path.

## Implementation

Added QRunV06PeerAddressBookCandidate::rotate_trust_domain_registry.

- Rotation requires an existing registry fingerprint; an unbound V1–V3 store must use first-bind migration instead.
- If the supplied fingerprint is unchanged, the method delegates to ordinary binding and is idempotent.
- On a changed fingerprint, it transactionally reclaims only expired, unapproved Q6AR Gossip candidate records.
- Any remaining live attributable candidate returns TrustDomainRotationBlockedByLiveCandidates.
- Any incomplete/unattributable legacy Gossip record returns UnattributableCandidate.
- Explicitly operator-approved/manual peer pins are retained; their outbound trust is separate from Q6AR relay attribution.
- A successful rotation persists the new fingerprint in Q6PA V4. On any failure, in-memory records and the previous fingerprint are restored.

Runtime startup uses the new rotation path only when the config field q6ar_trust_domains_rotation_authorized is explicitly true. The field defaults to false, requires a boolean, is valid only when Q6AR Address Book mode is enabled, and is covered by the independently pinned permissionless config SHA-256. With the default false value, changed fingerprints continue to fail closed.

## Regression evidence

Address Book tests:

```powershell
cargo test --manifest-path src/native/pow_bench/Cargo.toml --lib explicit_registry_rotation --locked --offline
```

Result: **2 passed, 0 failed**. The tests cover:
- unbound stores cannot invoke rotation;
- live old candidates block rotation without changing the old binding or records;
- expired candidates are reclaimed during explicit rotation;
- a new relay key can ingest under the new registry;
- after reopening Q6PA, the new fingerprint is accepted and the previous registry is rejected.

Runtime configuration test:

```powershell
cargo test --manifest-path src/native/pow_bench/Cargo.toml --bin qrun_v06_node q6ar_registry_rotation_requires_explicit_boolean_operator_authorization --locked --offline
```

Result: **1 passed, 0 failed**. Missing configuration defaults to false; true/false booleans are accepted; non-boolean values are rejected.

Also passed:
- cargo fmt --manifest-path src/native/pow_bench/Cargo.toml -- --check
- git diff --check

## Operational procedure

For a planned relay-key change:
1. Keep old and new relay static keys mapped to the same operator-verified trust domain while old unapproved Q6AR candidates remain live.
2. Wait until those candidate records expire, or remove them through an approved maintenance procedure.
3. Update the operator registry file and its SHA-256 in the permissionless config.
4. Set q6ar_trust_domains_rotation_authorized: true in that same independently SHA-pinned config.
5. Start the node through the ordinary guarded launcher. Startup rotates only if the old Q6PA fingerprint differs and no live candidate blocks it.
6. Return the flag to false in the next normally pinned config revision.

## Security boundary

The rotation authorization is an operator action, not a remote protocol operation. This does not prove domain ownership independence or justify Public Testnet deployment. No node was started, no listener was opened, and no commit or push was made.
