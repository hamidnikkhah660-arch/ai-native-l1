# CP-0652 — Public Testnet Readiness Reconciliation After CP-0651

Date: 2026-11-14  
Project: AI-NATIVE L1 / QRUN-QFP6  
Branch: `feat/cp0600-bootstrap-sync-startup`  
Observed base HEAD: `df673d07050688a64b26822d97e6ea609b68ce88`  
Status: **candidate code and local checks advanced; PUBLIC TESTNET NOT READY / NOT LAUNCHED**

## 1. Economic-policy resolution

CP-0651 is now the active candidate policy:

- 7,000,000,000 QZXB maximum accounting ceiling.
- 1,000,000,000 QZXB owner Genesis allocation.
- Six non-circulating accounting labels, each with a 1B QZXB ceiling.
- Zero block subsidy. Producers are compensated only by canonical transaction fees.
- Six label budgets are not Genesis balances or automatic mint authority.

The candidate release manifest has been updated to record CP-0651 and to require CP-0651 Genesis for permissionless startup. CP-0528 and CP-0604 remain historical compatibility formats but are rejected by the CP-0651 permissionless startup gate.

## 2. Local engineering evidence

The following checks were observed during the CP-0651 implementation session:

- CP-0651 supply tests: 3 passed.
- CP-0651 canonical execution / fee-only block / zero subsidy / v7 snapshot replay: passed.
- Q6SN v5 compatibility after v7 upgrade: passed.
- Q6CP exact CP-0651 fee-only profile encode/decode: passed.
- Genesis economic identity for CP-0528/CP-0604/CP-0651: passed.
- Permissionless Genesis gate accepts CP-0651 and rejects CP-0528/CP-0604: passed.
- Full Genesis snapshot preflight against Q6GD descriptor/fingerprint with CP-0651: passed.
- CP-0604 legacy mining/snapshot regression: passed.
- Q6QA authorization/persistence regression: passed.
- `cargo check --bins --locked --offline`: passed.
- `cargo fmt --check`: passed.
- `git diff --check`: passed.
- Candidate manifest parsed as JSON after the policy update.

This is local code-level evidence. It is not a cross-client network qualification or independent audit.

## 3. Candidate release-manifest state

File: `release/qfp6-candidate/manifest.json`

Confirmed current values:

- `production_authorized=false`
- `mainnet_status=NOT_AUTHORIZED`
- `public_mining_authorized=false`
- `permissionless_requires_cp0651_genesis=true`
- `permissionless_requires_cp0604_genesis=false`
- `permissionless_legacy_cp0528_genesis_allowed=false`
- `permissionless_legacy_cp0604_genesis_allowed=false`
- CP-0651 economics: 7B cap / 1B owner / six 1B labels / zero subsidy / transaction-fee-only producer compensation.

Artifacts still marked missing:

- Genesis execution snapshot (no final canonical Genesis package or signature).
- Q6GD descriptor.
- Q6CP consensus profile artifact.
- Q6PN network profile/pin.
- Bootstrap peer set and out-of-band verified Noise static-key pins.

The full-history permissionless profile does not require Q6TS; its status is marked `NOT_REQUIRED_FOR_PERMISSIONLESS_FULL_HISTORY`, rather than treating it as a missing dependency.

Independent consensus, cryptography, and economics reviews remain pending. Private signing material is not in the candidate manifest.

## 4. Source-level public-exposure blockers

These are current source/document findings, not assumptions:

1. **Inbound resource scheduling — partially addressed by CP-0653/0654.** CP-0653 adds four fixed Noise handshake workers, an eight-job bounded queue, a four-result completion queue, cancellation-aware eight-second deadlines and joined shutdown. CP-0654 bounds each established session to 30 seconds and each record read to five seconds. Local tests prove valid peers can complete while another handshake stalls, queue overflow is rejected, shutdown cancellation is prompt, and session deadlines are enforced. Canonical application callbacks remain serial; public listener/DoS qualification, multi-prefix Internet load tests, NAT fairness, concurrent-session fairness and callback-stage resource qualification remain open.
2. **Anonymous inbound Noise XX.** The Public Testnet CLI explicitly requires acknowledgement that inbound Noise XX is anonymous and unauthenticated. The current transport is X25519-based and classical, not post-quantum. A remote static key is not proof of real-world operator identity unless independently pinned. This is not a claim that encryption alone authenticates peers.
3. **Peer discovery/admission.** Public peer discovery is not implemented/qualified. Outbound bootstrap sync depends on explicitly pinned peers. Trust-domain IDs are operator-supplied labels; they do not prove separate ownership or eliminate hidden coordination.
4. **Network-wide replay and multi-host operation.** CP-0649 runs two separate Noise servers and the exact agreement gate, but uses loopback ephemeral listeners. It does not establish Internet reachability or independent physical-host operation. Manifest flags `full_history_replay_qualified=false` and `public_listener_qualified=false` remain unchanged.
5. **Independent reviews and production consensus.** Difficulty/retarget calibration, adversarial consensus qualification, independent cryptography review, economics review, reproducible release verification, and operator runbooks remain pending.
6. **Operator-controlled artifacts.** No final protected owner signing key, node Noise private key, independent seed hosts, public endpoints, or their independently verified public-key pins were provisioned in this work session.

The source has a branch-local median-time-past rule (up to 11 ancestors) and a live two-hour future-time guard connected to fork-choice/runtime paths. These are not listed as missing timestamp implementations here. Production calibration and adversarial validation of the exact final profile remain pending.

## 5. Operational state at last audit

- No `qrun_v06_node` node process was running.
- No TCP listener on port 30333 was open.
- No public listener was bound.
- No firewall/router/port-forward change was performed.
- No deployment or public Testnet launch occurred.
- No commit, push, merge, tag, or release was created.
- Branch and upstream were at the same base SHA before the CP-0651/manifest working-tree changes; all changes remain local and uncommitted.
- Existing user worktree changes and prior CP-0632–CP-0654 checkpoints were preserved.

## 6. Next safe gate

CP-0653/0654 now bound pre-authentication handshakes and the lifetime/read budget of established application sessions in candidate code. The next code gate is not to add concurrent canonical-state writers; it is to qualify fairness and resource budgets under adversarial load, including slow record senders, many valid sessions, queue saturation, shutdown during active callbacks and NAT sharing. In parallel, provision two independently administered seed hosts and the owner-controlled CP-0651 signing path using the requirements in CP-0655. Hashes, addresses, public keys and signatures must come from the actual hosts/signer and must not be fabricated.

Only after those gates have evidence should the exact Genesis/Q6GD/Q6CP/Q6PN/peer configuration be signed, independently reviewed, checked on separate hosts, and used for a separately authorized zero-value Public Testnet launch.

**Decision:** CP-0651 economics and local implementation are advanced and verified to the extent stated above. Public Testnet is still **NO-GO** at this checkpoint. Mainnet/value-bearing deployment remains unauthorized.
