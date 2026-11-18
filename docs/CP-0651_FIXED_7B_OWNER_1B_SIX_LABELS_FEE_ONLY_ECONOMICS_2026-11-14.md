# CP-0651 — Fixed 7B Supply, 1B Owner Genesis, Six Accounting Labels, Fee-Only Mining

Date: 2026-11-14  
Project: AI-NATIVE L1 / QFP6  
Branch at implementation: `feat/cp0600-bootstrap-sync-startup`  
Implementation base HEAD: `df673d07050688a64b26822d97e6ea609b68ce88`  
Status: **implemented in candidate code; local targeted verification passed; public Testnet not launched**

## 1. Locked economics decision

The user-directed QZXB monetary policy is fixed as follows:

- Maximum gross supply ceiling: **7,000,000,000 QZXB**.
- Owner Genesis allocation: **1,000,000,000 QZXB**.
- Six accounting labels: **1,000,000,000 QZXB per label**, totaling **6,000,000,000 QZXB**.
- Block subsidy / mining issuance: **0 QZXB at every height**.
- Producers/miners receive only canonical transaction fees paid by transactions.
- There is no independent 3B mining/security issuance budget under CP-0651.

The six accounting labels preserve the earlier CP-0566D category meanings:

1. Community airdrop.
2. Exchange, market and liquidity partnerships.
3. Marketing partners.
4. Developers and security contributors.
5. Financial and strategic supporters.
6. Protocol burn reserve.

The six labels are accounting ceilings, **not Genesis balances, not immediately spendable accounts, and not automatic mint authority**. They do not add to the ledger's 1B Genesis balance. Any future release or reclassification requires a separately versioned, independently authorized consensus/governance policy. CP-0651 itself has no reserve-release operation.

## 2. Why zero subsidy is part of the decision

The 7B ceiling is fully accounted for by 1B owner allocation plus six 1B labels. Retaining the old 3B mining issuance as an additional budget would exceed the requested 7B total. CP-0651 therefore makes block subsidy exactly zero and pays producers only fees from existing balances.

The old 10B/3B-mining and earlier 1B-owner reserve models remain historical compatibility candidates. They are **not** permitted to initialize the CP-0651 permissionless runtime.

## 3. Implementation

### Supply policy module

Added `qrun_v06_cp0651_supply_candidate.rs`:

- Exact 7B cap, 1B owner Genesis allocation, six one-billion accounting labels, zero block subsidy.
- Fingerprint commits to network, owner, all totals, zero subsidy, six label identifiers and their budgets.
- State root commits to the fingerprint and sequential block height.
- Snapshot codec is versioned and checksummed; wrong network, modified fields, noncanonical labels, and altered checksums fail closed.
- Ledger-supply invariant holds at exactly 1B QZXB throughout the CP-0651 execution path. Transactions transfer existing value; fees do not mint.
- Every block advances a sequential CP-0651 height with zero subsidy.

### Canonical execution and persistence

- CP-0651 Genesis constructors create exactly the 1B owner Ledger balance.
- Canonical block execution settles fees to the producer, adds no mining reward, and keeps total Ledger value unchanged.
- CP-0651 policy identity and state root are included in canonical execution commitment.
- Q6SN snapshot version 7 appends the CP-0651 component after prior fields, preserving the version 4, 5 and 6 layouts for legacy decoding.
- Old CP-0528 and CP-0604 candidates remain decodable and testable but cannot silently initialize the CP-0651 runtime.

### Q6CP consensus-profile admission

- Added an exact QFP6 monetary compatibility validator for CP-0651: maximum supply 7B, initial subsidy 0, halving interval 1.
- Existing historical 10B issuance compatibility is left unchanged for historical/legacy candidates.
- Other fee-only caps or altered schedules are not accepted as CP-0651.

### Permissionless launcher and preflight

- Permissionless launcher now requires CP-0651 Genesis and checks the owner, fingerprint, 1B owner allocation, six-label total, zero subsidy, height-zero state and exact Ledger supply before opening durable runtime stores/listeners.
- CP-0528 and CP-0604 Genesis are explicitly rejected by the new permissionless gate.
- Read-only Genesis preflight validates CP-0651 descriptor/fingerprint and the full Q6SN v7 snapshot.

## 4. Focused verification recorded

The following local, offline tests passed during this checkpoint:

- CP-0651 supply module: **3 passed**.
- CP-0651 canonical execution: fee-only block production, zero subsidy, fee paid to producer, unchanged Ledger supply and Q6SN v7 restart/replay: **1 passed**.
- Q6SN v5 compatibility after v7 upgrade: **1 passed**.
- Q6CP acceptance of exact CP-0651 fee-only monetary parameters and encode/decode: **1 passed**.
- CP-0651/CP-0528/CP-0604 Genesis economic identity coverage: **1 passed**.
- Permissionless Genesis gate: accepts CP-0651 only and rejects CP-0528/CP-0604: **1 passed**.
- Full Genesis snapshot preflight against descriptor/fingerprint: CP-0651 case passed in the enclosing test.
- CP-0604 legacy mining/snapshot regression: **1 passed**.
- Existing Q6QA external quote-asset authorization and snapshot-persistence regression: **1 passed**.

The library and binary builds emit existing warnings in unrelated candidate modules; no warning is recorded here as a CP-0651 correctness failure.

## 5. Scope and non-claims

This checkpoint records a code-level economic policy and local verification. It does **not** claim that a public Testnet is running or that deployment is complete.

Not performed in this checkpoint:

- No public listener or node process was launched.
- No port 30333 listener was opened.
- No commit, push, merge, tag, or release was created.
- No production or Testnet credentials, private keys, seed endpoints, or external trust roots were provisioned.
- No cross-client network-wide consensus qualification, independent security audit, or live multi-operator Testnet was performed.

Public Testnet activation remains gated on generating and independently pinning the actual network/profile/Genesis/Q6CP artifacts, protected operator and Noise keys, externally administered bootstrap peers across independent trust domains, approved topology and listener/network settings, and a separate explicit deployment authorization. The previous source-level status that production authorization is false remains in force.

### Explicit public-testnet blockers at this checkpoint

The candidate release manifest `release/qfp6-candidate/manifest.json` is aligned to CP-0651 but remains deliberately unauthorized:

- `production_authorized=false`, `mainnet_status=NOT_AUTHORIZED`, and `public_mining_authorized=false`.
- Genesis snapshot, Q6GD descriptor, Q6CP consensus profile, Q6PN network profile, and bootstrap peer set remain **MISSING**. The current full-history release profile does not require Q6TS; the manifest marks it `NOT_REQUIRED_FOR_PERMISSIONLESS_FULL_HISTORY`.
- Consensus, cryptography, and economics independent reviews remain **PENDING**. No Genesis signature exists in the candidate manifest and no private key material is included.
- No externally controlled seed/joining hosts, public IP:port endpoints, protected Noise private keys, or out-of-band verified remote static-key pins were provisioned.
- Public inbound Noise XX is anonymous and unauthenticated; its X25519 key agreement is classical, not post-quantum. The remote static key does not establish an independently verified operator identity for anonymous inbound sessions.
- The QFP6 listener still performs Noise handshake synchronously in a single accept/session path. Source-prefix/global rate limiting exists, but a slow handshake can hold the serial path until its deadline. A bounded worker/queue design and adversarial slow-handshake/multi-source load qualification remain required before broad public exposure.
- Public peer discovery is not implemented/qualified. Outbound bootstrap synchronization uses explicitly pinned peers; trust-domain labels are operator-provisioned assertions and do not independently prove unrelated ownership or no collusion.
- CP-0649 proves local two-server Noise sync/import and agreement-gate behavior on loopback only; it is not physical multi-host Internet reachability or a sustained public-network qualification.
- Full-history replay qualification and public-listener qualification remain false in the release manifest. Firewall/router exposure, external reachability, public operations/monitoring, and independent release review have not been performed.

The branch-local MTP rule (last up to 11 ancestor timestamps) and live two-hour future-time admission guard are present in QFP6 source and connected to fork-choice/live-runtime paths; they are not represented here as open timestamp blockers. Production difficulty/retarget parameter calibration and adversarial consensus review remain pending.

## 6. Relevant files

- `src/native/pow_bench/src/qrun_v06_cp0651_supply_candidate.rs`
- `src/native/pow_bench/src/qrun_v06_canonical_execution_candidate.rs`
- `src/native/pow_bench/src/qrun_v06_consensus_profile_candidate.rs`
- `src/native/pow_bench/src/consensus.rs`
- `src/native/pow_bench/src/bin/qrun_v06_node.rs`
- `src/native/pow_bench/src/bin/qrun_v06_node_runtime_launch/permissionless.rs`
- `src/native/pow_bench/src/lib.rs`
- `release/qfp6-candidate/manifest.json` (CP-0651 economics and permissionless-genesis gate aligned; release remains unauthorized)

