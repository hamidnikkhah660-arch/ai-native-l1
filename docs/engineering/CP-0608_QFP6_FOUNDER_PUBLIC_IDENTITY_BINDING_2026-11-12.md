# CP-0608 — Bind the verified QFP6 founder public identity to the candidate package

Date: 2026-11-12
Branch: `feat/cp0600-bootstrap-sync-startup`

## Change

The QFP6 candidate manifest now binds the founder's public identity exported from the existing Windows DPAPI-protected QZKW2 wallet using the read-only `address-qfp6-hybrid` command. The export contains only the public account identifier, Ed25519 public key, and ML-DSA-65 public key. No mnemonic, private seed, private key, DPAPI payload, or Genesis signature was exported or added to the repository.

The public identity was checked for exact key lengths (32-byte Ed25519 and 1,952-byte ML-DSA-65), and the package tool re-derived the hybrid account identifier before writing the manifest. The account identifier is:

`b26ce4e019429ec524cb73d0464ec4c6a48d47ea8519b867d0374f07ab54b31d`

Manifest state is `PUBLIC_KEYS_BOUND_CANDIDATE_ONLY`. This binds the intended founder account identity; it does not create or sign Genesis, allocate the 7B founder balance, authorize issuance, or enable Mainnet.

## Validation

- Wallet public-identity export: successful; `private_key_output=none`.
- `python tools/qfp6_candidate_package.py self-test`: passed.
- `python tools/qfp6_candidate_package.py validate release/qfp6-candidate`: correctly returns `INCOMPLETE` (exit 2), because six required canonical artifacts remain missing.
- `qrun_v06_node --run` remains fail-closed; no runtime or mining activation was attempted.

## Remaining release inputs

1. Canonical height-zero Genesis snapshot with the final Q6GD descriptor and founder allocation policy.
2. Independently reviewed Q6CP consensus profile and Q6PN network profile, with out-of-band digests/commitments.
3. Q6TS trust bundle with independently controlled signing authorities, current trust-floor provisioning, and verified signatures.
4. Authenticated bootstrap peer identities/endpoints.
5. Independent consensus, cryptography, and economics reviews; full-history replay and public-listener qualification.

The candidate package must remain non-production until those inputs and qualifications are independently supplied and verified. No values or credentials are synthesized by this change.