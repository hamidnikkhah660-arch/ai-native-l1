# CP-0614 - Permissionless base-runtime versus anchored QAP1 launch boundary

Date: 2026-11-12
Base: CP-0613 / current `feat/cp0600-bootstrap-sync-startup` head
Status: architecture audit and release-gate correction; no Mainnet activation.

## Finding

CP-0613 wires `qrun_v06_node --run` to the QAP1-aware private-candidate launcher. That launcher deliberately requires the Q6TS trust floor, Provider/Q6EA services, QAP1 journal recovery, pinned overlay peers and the QAP1 mining handoff. It is useful for an explicitly anchored candidate mode, but it is **not** the permissionless base-chain runtime required by CP-0588.

The existing `QRunV06PermissionlessNodeRuntime::open` is a separate Genesis-rooted API. It replays the durable local history without mandatory Q6EA, Provider, Q6TS or QAP1 dependencies and supports bounded contiguous history-batch import. However, source inspection shows it is not yet composed into the executable's full peer listener, transaction ingress/mempool, mining supervisor, shutdown and restart lifecycle. The existing supervisor accepts the anchor-gated `QRunV06NodeRuntime` and QAP1 coordinator; its function signature cannot be substituted with the permissionless runtime without a deliberate refactor.

## Required architecture

1. Keep `--run --mode private-candidate-anchored` as a separate optional QAP1 mode. It must never be represented as permissionless Mainnet.
2. Add a distinct `--mode permissionless-full-history` path using `QRunV06PermissionlessNodeRuntime::open` and the existing Genesis-rooted durable fork store. It must not construct or require Provider, Q6EA, Q6TS remote floor or QAP1 coordinator.
3. Authenticate Q6GD/Q6CP/Q6PN and the profile pin out-of-band before opening/replaying the store. A local manifest checksum is not an independent freshness/trust root.
4. Add a peer protocol adapter that obtains bounded parent-first history batches, resumes from the durable local tip, and verifies network/profile, PoW, branch-local MTP, retarget, execution state root, cumulative work and canonical fork choice during replay/import.
5. Refactor the supervisor behind a narrow runtime trait or provide a permissionless-specific supervisor. It must durably admit transactions/blocks, refresh canonical fork choice after peer windows, mine only on the current canonical state, and never claim global finality from local durable acceptance.
6. Qualify full-history genesis replay, restart, interruption/resume, competing branches/reorg and two-host convergence using the new permissionless executable path. Earlier CP-0566C/CP-0572/CP0587 cross-host results remain valid for their stated scope and are not repeated as substitutes.
7. Only after consensus/time/PoW calibration, independent review, canonical artifacts and operational peer readiness may a separate production release authorization be considered.

## Consensus blockers remain

- `qrun_v06_sha256d_candidate()` inherits the easy `candidate_testnet()` target and retarget defaults.
- CP-0575/Q6CP structural encoding does not approve production target, block interval, retarget bounds or timestamp rules.
- Branch-local MTP exists in QFP6 fork-choice code, but CP-0588 still requires one frozen, versioned policy consistently applied to mining, import, replay, fork choice, checkpoint restore and restart, plus deterministic future-time limits.
- The 7B founder Genesis / 3B mining ceiling is the current execution-policy candidate; it is not a signed Genesis or independently reviewed economic release.

## Manifest semantics

The candidate manifest now distinguishes `anchored_qap1_candidate_wired` from `permissionless_base_runtime_wired`. `runtime.wired` remains a compatibility summary meaning only that the private-candidate QAP1 executable entry point exists. It must not be interpreted as public base-runtime readiness. `full_history_replay_qualified=false`, `public_listener_qualified=false`, and `production_authorized=false` remain mandatory.

## Explicit non-claims

No production Genesis, canonical network/profile IDs, Q6TS authority, peer identities, public endpoints, production mining schedule, public RPC/explorer, public Mainnet activation, or QZXB/USDT liquidity is created or claimed by this audit.
