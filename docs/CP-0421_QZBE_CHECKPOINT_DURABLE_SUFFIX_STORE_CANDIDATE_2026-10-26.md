# CP-0421 ? QZBE checkpoint-base durable suffix store candidate

Date: 2026-10-26

Status: **local durable-store candidate and focused tests pass; wired to the explicit loopback QZBE runtime candidate; exact-head CI pending; no external anti-rollback provider**

## Scope

CP-0421 introduces a separate checkpoint-base store candidate rather than changing the legacy QZBE archive manifest. Opening it requires a caller-supplied checkpoint record every time. The store validates the checkpoint against an explicit Genesis/profile/PoW context, derives its domain-separated commitment, persists the canonical checkpoint bytes under that commitment, and binds a new versioned QZCS manifest to the exact commitment, base tip/height, profile, consensus parameters, canonical tip/height/root, total mined atoms, cumulative chainwork and a sorted list of immutable suffix-envelope digests/hashes.

Submitting a new block writes immutable branch bytes first, then commits an incremented manifest generation. On reopen the store refuses a checkpoint different from the trusted caller input, verifies all committed branch file hashes, rebuilds the bounded suffix through normal QZBE decoding/PoW/transition/fork choice, and compares the reconstructed canonical metadata with the manifest. The lock is an OS-backed exclusive writer lock. Resource bounds cover encoded envelope size, block count, aggregate suffix bytes and manifest size.

## Local evidence

- The focused checkpoint-store tests passed **4/4** after the height-2,017 extension was added. They verify checkpoint-base open, durable suffix commit/restart replay at Genesis, durable suffix commit/restart replay from a supplied height-2,016 checkpoint to height 2,017, rejection of a changed supplied checkpoint, rejection of a manifest with a broken checksum, and rejection of branch bytes that no longer match the committed branch hash.
- The focused checkpoint-record/fork-choice tests passed 7/7, including restoring the configured 2,016-block target history, producing a checkpoint-based QZBE block at logical height 2,017, replaying the suffix, and constructing the next checkpoint from the live canonical branch.
- Rust formatting and cargo check --all-targets --locked passed locally; existing unrelated warnings remain.
- The independent CP-0419 checkpoint-byte oracle passed, and the tokenomics/runtime preflight passed.
- Parent commit 9c78832123e37b5ccb646ee7cb0756c542ead155 passed exact-head CI run 40377595429. CP-0421 requires its own fresh exact-head CI; parent CI is not a substitute.

The height-2,017 storage test uses a synthetic, explicitly supplied trusted checkpoint whose state and target history are transition-built; it does not mine or prove that the prior 2,016 QZBE PoW blocks existed. It verifies that the store persists and replays the successor block *from that supplied trust base*. The exact-head CI run started before this additional test was added; a follow-up commit must carry this test and obtain fresh CI.

## Security boundary

The checkpoint is **not trusted because it exists in this directory or has a valid checksum**. The caller must provide a currently trusted checkpoint obtained outside the directory's rollback domain. This component does not yet connect an independent CAS provider; a whole-directory restore can roll its local manifests back unless the external caller detects that its checkpoint commitment is stale. The local store therefore does not claim Gate 8 anti-rollback closure.

The checkpoint is also the root of this bounded suffix. Reorganizations that diverge below that root cannot be evaluated by this graph alone. A finality depth/rollback policy and persistent checkpoint transition protocol are not selected here. No automatic pruning of old branch data or checkpoint advancement is enabled.

## Local validation target

The focused store tests open a Genesis checkpoint and a synthetic height-2,016 checkpoint, commit blocks including height 2,017, and reopen/replay to matching canonical tip and state root. They also reject a mutated supplied checkpoint, a manifest with bad checksum, and tampered branch bytes. The full locked/offline all-target suite and exact-head GitHub Actions are required before the change is promoted. The QZBE loopback runtime now starts from a locally generated canonical Genesis checkpoint and uses this store for ingress, local block commit and restart/replay; it does not select a non-Genesis checkpoint from a local file.

## Still missing

- Integration into the default PTB2/PFS2 node lifecycle and acceptance of an independently certified non-Genesis checkpoint; the store is only wired into the explicit loopback QZBE runtime candidate.
- Independent durable provider-side compare-and-swap anchor, signed receipts, crash/timeout/lost-response and multi-host stale-restore tests.
- A production reorg/checkpoint finality policy and tests with real competing branches around checkpoint boundaries.
- Mainnet wallet/custody, transaction API/mempool, public ingress/discovery, multi-operator public devnet, observability and independent release/security qualification.

This is an isolated engineering candidate, not a public network or value-bearing launch. Gate 2 and Gate 8 remain open, and the legacy QZBE store's absolute logical-height cap remains unchanged.
