# CP-0421 ? QZBE checkpoint-base durable suffix store candidate

Date: 2026-10-26

Status: **local durable-store candidate and focused tests pass; exact-head CI pending; not integrated with the live QZBE node**

## Scope

CP-0421 introduces a separate checkpoint-base store candidate rather than changing the legacy QZBE archive manifest. Opening it requires a caller-supplied checkpoint record every time. The store validates the checkpoint against an explicit Genesis/profile/PoW context, derives its domain-separated commitment, persists the canonical checkpoint bytes under that commitment, and binds a new versioned QZCS manifest to the exact commitment, base tip/height, profile, consensus parameters, canonical tip/height/root, total mined atoms, cumulative chainwork and a sorted list of immutable suffix-envelope digests/hashes.

Submitting a new block writes immutable branch bytes first, then commits an incremented manifest generation. On reopen the store refuses a checkpoint different from the trusted caller input, verifies all committed branch file hashes, rebuilds the bounded suffix through normal QZBE decoding/PoW/transition/fork choice, and compares the reconstructed canonical metadata with the manifest. The lock is an OS-backed exclusive writer lock. Resource bounds cover encoded envelope size, block count, aggregate suffix bytes and manifest size.

## Local evidence

- The focused checkpoint-store tests passed 3/3. They verify checkpoint-base open, one QZBE block's durable suffix commit and restart/replay equality; reject a changed supplied checkpoint; reject a manifest with a broken checksum; and reject branch bytes that no longer match the committed branch hash.
- The focused checkpoint-record/fork-choice tests passed 7/7, including restoring the configured 2,016-block target history, producing a checkpoint-based QZBE block at logical height 2,017, replaying the suffix, and constructing the next checkpoint from the live canonical branch.
- Rust formatting and cargo check --all-targets --locked passed locally; existing unrelated warnings remain.
- The independent CP-0419 checkpoint-byte oracle passed, and the tokenomics/runtime preflight passed.
- Parent commit 9c78832123e37b5ccb646ee7cb0756c542ead155 passed exact-head CI run 40377595429. CP-0421 requires its own fresh exact-head CI; parent CI is not a substitute.

## Security boundary

The checkpoint is **not trusted because it exists in this directory or has a valid checksum**. The caller must provide a currently trusted checkpoint obtained outside the directory's rollback domain. This component does not yet connect an independent CAS provider; a whole-directory restore can roll its local manifests back unless the external caller detects that its checkpoint commitment is stale. The local store therefore does not claim Gate 8 anti-rollback closure.

The checkpoint is also the root of this bounded suffix. Reorganizations that diverge below that root cannot be evaluated by this graph alone. A finality depth/rollback policy and persistent checkpoint transition protocol are not selected here. No automatic pruning of old branch data or checkpoint advancement is enabled.

## Local validation target

The focused store test opens a Genesis checkpoint, mines and commits one QZBE envelope, closes the store, confirms a mutated checkpoint is refused, then reopens with the exact original trusted checkpoint and asserts matching height, canonical tip and state root after durable replay. The full locked/offline all-target suite and exact-head GitHub Actions are required before the change is promoted.

## Still missing

- Integration of checkpoint manifests into the running QZBE peer node and its startup/recovery life cycle.
- Independent durable provider-side compare-and-swap anchor, signed receipts, crash/timeout/lost-response and multi-host stale-restore tests.
- A production reorg/checkpoint finality policy and tests with real competing branches around checkpoint boundaries.
- Mainnet wallet/custody, transaction API/mempool, public ingress/discovery, multi-operator public devnet, observability and independent release/security qualification.

This is an isolated engineering candidate, not a public network or value-bearing launch. Gate 2 and Gate 8 remain open, and the legacy QZBE store's absolute logical-height cap remains unchanged.
