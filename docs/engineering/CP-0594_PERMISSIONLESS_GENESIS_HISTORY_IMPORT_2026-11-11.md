# CP-0594 - Permissionless Genesis-rooted history import

Date: 2026-11-11
Status: implementation candidate; not a public sync service or Mainnet release.

## Scope

CP-0594 adds a bounded history-batch import seam to `QRunV06PermissionlessNodeRuntime`.
The caller must obtain the batch from an already authenticated peer/session. This change does
not discover peers, authenticate a peer directory, open public listeners, define a public sync
wire protocol, or fetch pages from the network.

## Import contract

- Each batch contains 1-128 QFP6 envelopes and at most 16 MiB in total.
- Each envelope is bounded by the existing QFP6 maximum envelope size.
- All envelopes are decoded before any write. Network ID, profile ID, height, consensus-parent
  chain and header/body parent binding are checked against the local canonical tip and preceding
  envelope. The first execution parent is pinned to the local canonical execution state.
- The durable fork store remains authoritative for consensus, target, PoW, branch-time, execution,
  state-root, signature and persistence checks, including each execution-parent transition.
- Commits are sequential and durable. If commit `i` fails, the error reports `i` and the durable
  prefix length; the caller must query local status and resume from that point.
- The import API only accepts a canonical continuation from the current canonical tip. It is
  not a substitute for side-branch/reorg exchange; individual peer block admission remains
  responsible for branch candidates and cumulative-work fork choice.

## Qualification boundary

This is a runtime import primitive, not proof of Genesis-to-tip network synchronization.
A later stage must implement authenticated peer bootstrap, request/response pagination over
QFP6 Noise sessions, immutable remote snapshot commitments, timeout/retry/resume behavior,
independent-host qualification, and partition/reorg recovery. Genesis/profile identity and
production consensus parameters remain externally pinned and unfrozen until separately approved.

## Validation

- `cargo fmt -- --check`: passed.
- `cargo check --all-targets --locked --offline`: passed.
- `python simulations/qfp6_mtp_reference.py`: passed.
- Focused `permissionless_history_batch_import_is_bounded_contiguous_and_durable` test: passed;
  covers empty/reordered-batch rejection before writes and durable import of a two-block history.
- QFP6 local-node binary suite: 43/43 passed with `--test-threads=1`.
- Full library run: 1,341 passed; one unrelated Windows concurrent-CAS test hit a transient
  file-sharing violation under parallel load. Its isolated rerun passed.
- A prior all-target run encountered a transient Noise handshake deadline in a QFP5 local-node
  integration test under parallel load; the 43-test QFP5 local-node suite passed serially.
- CP-0593 parent exact-head CI is green (run `43056181488`); CP-0594 still requires its own
  exact-head GitHub Actions run before qualification.

No Genesis, network key, public endpoint, miner payout or Mainnet activation is created by this
change. No PR is merged and no Mainnet is activated.