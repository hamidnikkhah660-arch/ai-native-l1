# CP-0620 — QFP6 Mainnet artifact production gate

Status: implementation note; candidate-only. No production artifact is minted by this change.

## Objective

Make the release dependency order explicit and prevent candidate defaults, local test keys, empty peer lists, or unsigned trust material from being mistaken for a public Mainnet package. The permissionless launcher already requires CP-0604 Genesis (7B founder Genesis credit, no pre-mined 3B; the mining schedule can issue at most the remaining 3B). The historical CP-0528 reader remains available only for compatibility and is not a valid permissionless QFP6 Genesis.

## Artifact dependency order

1. **Q6CP consensus profile** — freeze protocol version, PoW algorithm, target block time, retarget window/clamps, initial target, PoW limit, timestamp/MTP rules, and the CP-0604 issuance schedule. The current `qrun_v06_sha256d_candidate()` inherits an intentionally easy candidate target and is not a production profile. Do not copy it into Mainnet.
2. **Q6GD Genesis descriptor** — bind the selected network ID, profile ID, founder account, Genesis timestamp, Q6CP consensus fingerprint, and CP-0604 policy fingerprint. Its commitment must be pinned by Q6PN and independently verified.
3. **Q6PN network profile** — bind the final network/profile identifiers and exact Q6GD/Q6CP commitments. IDs must be frozen before any public node is invited.
4. **Genesis snapshot** — construct the canonical empty-state Genesis using the CP-0604 policy, credit exactly 7,000,000,000 QZXB to the founder account, leave the 3,000,000,000 QZXB mining ceiling unissued, and bind the descriptor. The snapshot must pass the strict permissionless CP-0604 gate and the exact Q6CP validation.
5. **Q6TS trust bundle** — provision trust keys and signatures from independently controlled authorities. A founder key alone or a locally generated self-signed bundle does not establish independent trust.
6. **Bootstrap peers** — obtain independently operated public endpoints and their actual Noise static public keys. An empty list is acceptable only for a fresh isolated node; it cannot provide public network discovery or synchronize a shared public tip. Unauthenticated inbound Noise XX is not peer authentication.

## Inputs that must be real

- Final network ID and profile ID, each 32 bytes, nonzero and globally fixed.
- A production-reviewed Q6CP parameter set and its canonical fingerprint.
- A chosen Genesis timestamp and the resulting CP-0604 policy fingerprint.
- A canonical Genesis state snapshot whose descriptor, founder, supply counters, and ledger total all agree.
- Independent Q6TS trust authorities, public keys, signature threshold, and signatures.
- At least independently operated bootstrap nodes with reachable addresses and matching Noise static public keys; public peer admission/discovery and DoS protections must be reviewed.

## Safe local work vs. external dependencies

Q6GD, Q6CP, Q6PN, and the Genesis snapshot are locally buildable only after the above immutable consensus/network choices are approved and the canonical state constructor is used. Q6TS cannot be made independently trustworthy by generating keys on the founder's machine. Bootstrap peers cannot be manufactured without operators, endpoints, and keys. Mainnet signing must occur locally with the founder's protected wallet key; never export or paste the seed/private key.

## Required release checks

- `python tools/qfp6_candidate_package.py self-test`
- `python tools/qfp6_candidate_package.py validate release/qfp6-candidate`
- `cargo test --bin qrun_v06_node --locked --offline`
- `cargo check --all-targets --locked --offline`
- `cargo fmt --check`
- `git diff --check`
- After artifact creation: verify every SHA-256, decode Q6GD/Q6CP/Q6PN, cross-check all IDs/fingerprints, decode and replay the Genesis snapshot, verify founder account and exact 7B/3B supply, verify Q6TS signatures against independently provisioned trust keys, and prove bootstrap peer key/endpoint reachability from a second independent host.

## Release prohibition

Until all checks and independent reviews pass, `production_authorized=false`, `mainnet_status=NOT_AUTHORIZED`, and `public_mining_authorized=false` must remain unchanged. Do not create placeholder binary artifacts merely to make the six-file counter reach zero.
