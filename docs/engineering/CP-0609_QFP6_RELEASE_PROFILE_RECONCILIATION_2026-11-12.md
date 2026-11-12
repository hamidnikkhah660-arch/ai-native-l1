# CP-0609 - QFP6 release-profile reconciliation and Mainnet artifact gate

Date: 2026-11-12
Status: audit/documentation reconciliation only; no Mainnet identity, Genesis, signing, or activation.

## Verified source-of-truth boundaries

- CP-0604 is the current founder-controlled monetary execution candidate: 10,000,000,000 QZXB gross cap; 7,000,000,000 QZXB credited once to the founder at Genesis; at most 3,000,000,000 QZXB released through mining. Six 1B planning labels remain off-chain earmarks inside the founder's 7B balance; transfers do not mint.
- The founder's QFP6 public identity is now bound in `release/qfp6-candidate/manifest.json` as `PUBLIC_KEYS_BOUND_CANDIDATE_ONLY`. The binding is to the public account ID and Ed25519/ML-DSA-65 public keys. No private key, seed phrase, DPAPI payload, or Genesis signature is included.
- Q6CP is only the fixed-width consensus-parameter artifact. The current source defines Q6CP version 2 and 294 bytes; accepted profiles are SHA-256d only. Its monetary schedule is checked against the 10B maximum, 35,673,515,981 atom initial mining subsidy, and 4,204,800-block halving interval. The 7B founder Genesis credit is a separate CP-0604 execution-policy invariant and is not encoded by Q6CP alone.
- The current `qrun_v06_sha256d_candidate()` inherits candidate/testnet target and retarget parameters. It is not a calibrated or approved Mainnet profile. Q6CP v2 validity and matching fingerprints prove structural consistency, not production safety.

## Documentation reconciliation

CP-0575's original draft described Q6CP v1/Argon2id and a 1B Founder Genesis invariant. Those statements are superseded by the implemented Q6CP v2 SHA-256d-only validator and the separate CP-0604 7B-founder/3B-mining policy. Q6CP does not itself encode the founder split. The old CP-0436 freeze packet remains a historical 1B-founder v0.4 candidate and must not be reused as the current Genesis specification.

## Exact release-package status

The candidate package validator was run after the public identity binding. It reports `CANDIDATE_SCAFFOLD_ONLY`, `mainnet_authorized=false`, `runtime_wired=false`, and `public_mining_authorized=false`. Six canonical artifacts are absent:

1. Canonical Genesis snapshot.
2. Q6GD Genesis descriptor.
3. Q6CP consensus profile.
4. Q6PN network profile.
5. Q6TS trust bundle.
6. Authenticated bootstrap peer set.

The absence is intentional. These values cannot be safely generated from test fixtures or guessed identifiers. In particular, the immutable network/profile IDs, Genesis timestamp and bytes, production PoW target/retarget and timestamp rules, and independent trust commitments are not yet frozen and approved. The Q6CP profile must be built against the final Q6GD commitment; it cannot be produced correctly before that descriptor is frozen.

## Remaining production blockers

- Freeze and independently review the complete Mainnet consensus profile, including branch-local median-time-past/future-time rules and retarget behavior across production, import, replay, fork choice, checkpoint and restart. CP-0588 records this as an open safety blocker.
- Calibrate SHA-256d target and difficulty parameters from reproducible benchmarks and independent implementation vectors; current easy/candidate fixtures are not Mainnet values.
- Generate canonical Q6GD/Q6CP/Q6PN and the Genesis snapshot only after the final network identity, profile, Genesis timestamp, founder account and CP-0604 policy are fixed. Independently pin the resulting digests.
- Provision independently administered Q6TS/trust-floor authority and authenticated bootstrap peers. Do not invent signatures, public endpoints, keys or peer identities.
- Wire the ordinary executable to the permissionless base runtime and qualify full-history sync, transaction admission, mining, fork choice/reorg, persistent restart and anti-rollback across independently operated hosts. `qrun_v06_node --run` remains disabled.
- Complete independent security/cryptographic/economic review and explicit release authorization.

## Validation record

- Git HEAD was verified as `c94d15d02546a275a000bbaeb0ac5956ee6e1e21`; branch `feat/cp0600-bootstrap-sync-startup` matched origin and had no working-tree changes before this reconciliation.
- Candidate package self-test passed. Its negative malformed-identity fixture emitted an expected `INVALID` diagnostic before the final `SELF-TEST PASSED` result.
- Candidate package validation correctly exited 2 (`INCOMPLETE`) with the six artifacts listed above.
- This CP changes documentation only. It does not create artifacts, approve parameters, sign Genesis, issue QZXB, enable public mining/listeners, merge PR #194, or create QZXB/USDT liquidity.
