# CP-0404 — QZB4 v2 profile dispatch and anchored persistence candidate

Date: 2026-10-24

Status: **candidate-level implementation; not canonical-node or Mainnet activation**

## Scope

CP-0404 adds an explicit-profile execution dispatcher and a durable import-service candidate for the CP-0403 QZB4 v2 transaction-bearing block. The caller must supply both the QZGM Genesis manifest and the exact QZCP profile, including a mining schedule. No default reward or halving schedule is selected.

The dispatcher accepts only QZB4 version 2 and checks its profile fingerprint against the configured profile. QZB4 v1, BLK2, MBK3, MBK4, unknown versions, and profile mismatches are rejected; the importer never retries a rejected payload through a different codec. QZB4 v1 remains the earlier mining-only candidate, not a fallback for QZB4 v2.

## Commit and recovery protocol

For each accepted block, the service first validates and executes a staged state clone. It then creates the exact profile-bound QZP4 snapshot and follows a two-phase commit:

1. Atomically write the staged snapshot to a separate pending path.
2. Compare-and-set an external monotonic anchor from the prior record to a record binding sequence, network, Genesis manifest hash, profile fingerprint, height, tip hash, state root, and exact snapshot digest.
3. Atomically replace the canonical snapshot path.
4. Publish the in-memory state last.

On startup, the service accepts a canonical snapshot only when it matches the external anchor. If a crash happened after the external anchor commit but before canonical replacement, a pending snapshot is promoted only when its bytes and decoded state match that anchor. An unanchored local snapshot, anchor mismatch, unsupported profile or stale local snapshot is not silently accepted.

The commit sequence is independent of chain height so a future legitimate reorg can lower the canonical height without lowering the storage sequence. A production anchor implementation must provide durable, atomic compare-and-set semantics that remain authoritative if the node's local files are rolled back.

## Tests and current limitations

Tests cover explicit QZB4 v2 dispatch, rejection of QZB4 v1 and legacy-family payloads without downgrade, profile mismatch, invalid authorization, canonical import/reopen, replay rejection, pending-snapshot recovery after the anchor commit, and local snapshot rollback detection.

The test anchor is an in-memory mock. It demonstrates the service protocol and does **not** constitute a production anti-rollback provider. No external provider implementation is selected or integrated. The service is deliberately not wired into `chain_import_node`, the canonical network listener, PoW verification, canonical fork choice, or the existing MBK3/MBK4 stores.

QZB4 v2 presently encodes the execution block body but does not itself commit a verified PoW header or cumulative chainwork. Selecting a fork based on this body alone would invent consensus. Reorg support therefore remains open until an authenticated canonical envelope binds the QZB4 v2 body to the existing PoW/header verification and branch-work rules. A future branch store must replay each branch from a common ancestor and atomically commit the selected branch plus its anchored snapshot.

The existing signature authenticator is injected, and the test authenticator is a fixture only. The production key/signature policy, economics and approved Mainnet schedule are still unspecified. The subsidy and halving values in tests are test fixtures, not Mainnet parameters.

## Gate status

- Gate 2: **open** — canonical profile/runtime integration and production consensus binding remain incomplete.
- Gate 8: **open** — persistent external anti-rollback provider, production recovery and canonical fork/reorg integration remain incomplete.
- Gate 12: **unchanged/open** — this change does not implement smart-contract execution or contract transition validation.

Next milestone: define the verified PoW/header envelope for QZB4 v2, bind it to the explicit profile, then integrate branch replay and canonical fork-choice/reorg under fault-injection tests. Do not select unapproved economics or activate this candidate automatically.
