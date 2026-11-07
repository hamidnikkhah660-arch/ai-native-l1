# CP-0405 — QHWR Single-Host Durable Replay Ledger Candidate

Date: 2026-11-07
Status: engineering candidate; not production-qualified
Base: CP-0403 branch `work/cp0403-replay-scope-challenge-lifecycle-20261107`

## 1. Purpose and boundary

CP-0405 adds a concrete append-only implementation of `QhwrDurableReplayLedger` for one host. It is intended to replace test-only ledger mocks in controlled integration tests and to establish a reviewable persistence contract.

This candidate is **not** a distributed replay authority, multi-host linearizable store, production service deployment, or mainnet approval. The QHWR listener/dispatcher is not automatically wired to this store by this change; an integrator must explicitly construct the store and pass it to the dispatcher. Provider and signer qualification remain separate gates.

## 2. Replay identity

A reservation is keyed by the complete authenticated request scope:

- `network_id` from the completed authenticated Noise session;
- `authenticated_peer` from the authenticated Noise static identity;
- decoded `operation`;
- the 32-byte client challenge.

The canonical key is:

```text
SHA256(
  "AIN1-QHWR-REPLAY-KEY-V1\0" ||
  network_id[32] || authenticated_peer[32] || operation_tag[1] || challenge[32]
)
```

Operation tags are fixed in this candidate: `Read = 1`, `CompareAndAdvance = 2`. The dispatcher currently rejects `CompareAndAdvance`; the ledger's operation tag prevents accidental cross-operation key collisions if that operation is enabled later.

## 3. WAL record format

Each record is fixed-width (73 bytes), big-endian-independent, and append-only:

| Offset | Size | Field |
|---:|---:|---|
| 0 | 8 | Magic `QHWRRPL1` |
| 8 | 1 | Record version `1` |
| 9 | 32 | Replay key digest |
| 41 | 32 | SHA-256 record checksum |

The checksum is:

```text
SHA256("AIN1-QHWR-REPLAY-RECORD-V1\0" || record[0..41])
```

The ledger caps the file at 64 MiB. It never evicts old reservations: QHWR v1 has no server-issued expiry lease, so deriving expiry from client time would be unsafe. Capacity exhaustion returns an error and fails closed.

## 4. Reservation and recovery semantics

1. Opening acquires a stable sibling-path OS lock before opening the WAL, then a second OS lock bound to the opened file identity to reject hard-link aliases.
2. Recovery scans every complete fixed-width record, checks magic, version, checksum, and duplicate key digests, and rebuilds the in-memory lookup set.
3. A final incomplete record is truncated to the last complete offset and `sync_all` is requested. A complete record with bad magic/version/checksum, or a duplicate key already present in the journal, fails closed; it is not silently skipped or truncated.
4. `reserve_once` rejects a previously recorded key. For a new key it appends one complete record and returns `Ok(true)` only after `write_all`, `sync_all`, and the platform's parent-directory sync hook return successfully.
5. Any uncertain write/sync outcome poisons the in-memory instance. The caller must close and reopen it so the WAL, not stale memory, determines whether the reservation committed.

The dispatcher reserves before calling the provider or signer. A ledger error therefore prevents provider/signer side effects. A later provider or signer failure does not release the reservation; retrying the same challenge is rejected, which is the conservative anti-replay behavior.

## 5. Concurrency and platform limits

The OS locks serialize access to one WAL on one host. A second process cannot open the same ledger while the first process owns it; it may reopen after the owner exits and recovery completes. This deliberately favors safety over concurrent multi-process availability.

This is not multi-host coordination. Separate machines can each hold independent local WALs and accept the same challenge. Production multi-host operation requires one independently qualified shared atomic authority (or a consensus-backed provider) and a defined failover/replication model.

On Windows, the candidate requests `File::sync_all` for the WAL, but this implementation does not independently establish parent-directory entry durability under power loss. Windows power-loss qualification and any required platform-specific directory flush behavior remain release blockers. A successful local test is not proof against storage-controller lies, filesystem bugs, sudden power loss, or malicious rollback of the entire host volume.

## 6. Test evidence

Focused tests currently cover:

- duplicate rejection across reopen and full-scope separation;
- incomplete-tail recovery while preserving committed reservations;
- complete-record checksum corruption failing closed;
- abrupt child-process exit after a committed reservation plus a torn tail;
- same-process competing writer rejection;
- separate-process writer exclusion until the owner exits.

These are local candidate tests. They do not constitute independent multi-host qualification, external-provider anti-rollback proof, production deployment evidence, or an independent security audit.

## 7. Remaining gates

- Review record format, key-domain separation, crash semantics, and retention policy.
- Decide whether the 64 MiB hard cap is operationally acceptable; do not add eviction until a server-issued authenticated lease/expiry protocol exists.
- Wire the candidate only behind explicit deployment configuration and fail-closed startup checks.
- Run the full CI workflow on the CP-0405 branch, including Windows jobs.
- Test on independent hosts against a single shared atomic authority; verify duplicate races, restart, rollback, backup restore, and provider outage behavior.
- Obtain independent security review before any production or public-mint enablement.
