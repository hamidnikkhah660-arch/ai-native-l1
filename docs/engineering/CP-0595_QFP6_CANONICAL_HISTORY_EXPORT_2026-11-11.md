# CP-0595 - Bounded canonical QFP6 history export

Date: 2026-11-11
Status: implementation candidate; not network synchronization or Mainnet activation.

## Purpose

CP-0595 pairs with the CP-0594 bounded history importer by exposing parent-first pages from
a pinned canonical QFP6 fork-choice snapshot. This is a local export primitive for the next
authenticated sync protocol stage; it does not open a listener or send data over the network.

## Contract

- The caller obtains an immutable graph clone through the permissionless runtime's
  `fork_choice_snapshot` API and retains it for the entire sync session.
- Pages are selected from the canonical path only, in ascending block-height order.
  Side branches are never mixed into a canonical history response.
- Each page is bounded to at most 128 envelopes and 16 MiB.
- The exporter retains at most the requested page count while traversing the pinned chain.
  It does not clone the entire canonical archive to return a small page.
- The response binds every page to the snapshot's exact canonical height and tip hash.
- `next_height` is the next requested block height. `complete` is true only when the
  returned page reaches the pinned snapshot height.
- The receiver must still validate/import every envelope through CP-0594 and the durable
  fork store. Export metadata is not consensus authority.

## Validation

A focused regression test creates a five-block canonical chain, exports it in 2/2/1 pages,
checks parent-first height continuity, checks the pinned tip/height and completion flag, and
rejects invalid page limits and a start height before the archive base.

## Explicit non-goals

This change does not implement peer discovery, public bootstrap seeds, authenticated history
request/response frames, cursor authentication, timeouts/retries, persistent sync progress,
cross-host recovery, side-branch exchange, finalized Mainnet Genesis, public mining, RPC,
Explorer, wallet release, or QZXB/USDT liquidity. The immutable Mainnet profile and production
difficulty calibration remain unapproved.
