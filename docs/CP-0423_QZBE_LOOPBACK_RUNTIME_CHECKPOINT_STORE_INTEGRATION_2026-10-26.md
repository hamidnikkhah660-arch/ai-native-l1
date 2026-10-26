# CP-0423 ? QZBE loopback runtime checkpoint-store integration

Date: 2026-10-26

Status: **local Windows runtime integrations passed; exact-head GitHub Actions pending**

## What changed

The explicit QZBE v0.4 diagnostic command now builds a canonical Genesis checkpoint record from its frozen Network ID, Genesis manifest, monetary profile, subsidy schedule, PoW parameters and initial target history. It opens the checkpoint-rooted durable suffix store with that specific record. This replaces the previous full-archive store backend inside the explicit QZBE loopback runtime only.

Local mining, inbound peer candidates, transaction-signature rejection, persistent manifests, immutable branch bytes and shutdown/reopen now use the same checkpoint-rooted store. The startup profile lock remains enabled. The QZBE subcommand remains explicit; the ordinary default devnet_node invocation still uses the legacy PTB2/PFS2 route.

## Local evidence

After the backend replacement, these Windows Release integration scripts passed, each with exit code 0:

- CP-0414 two-node authenticated transfer: a signed 2,500-atom transaction was accepted, a tampered-signature envelope was rejected atomically, and the independent stores reopened/replayed to matching canonical state.
- CP-0415 QZBE dispatch through devnet_node: the same transfer path passed through the actual explicit QZBE entrypoint; profile-lock downgrade and public-bind guards remained effective.
- CP-0418 three-node static multi-peer propagation: two blocks reached both independent receiver stores, the tampered signature was rejected atomically, and all three stores matched after replay.

The focused CP-0421 store suite passes locally 4/4, including restart/replay at height 2,017 from an explicit height-2,016 checkpoint fixture, manifest checksum rejection, branch byte/digest rejection, and refusal to open against a changed supplied checkpoint. Rust formatting, the devnet_node cargo check, the canonical tokenomics checker, and the independent CP-0419 checkpoint-vector oracle pass locally.

## Boundaries

This is a durable-store integration inside the loopback-only QZBE candidate, not activation of QZBE for public Mainnet or for the default node. The runtime constructs the Genesis checkpoint itself from its local explicit profile; it does not yet accept a separately certified height-2,016 checkpoint from an independent source. The height-2,017 storage test uses a synthetic trusted checkpoint fixture; it does not mine or independently prove the preceding 2,016 QZBE proof-of-work blocks.

The store has no independent external compare-and-swap/monotonic anchor. Local manifests and checksums detect corruption, but do not prevent whole-directory rollback. A checkpoint is a trust base; production reorganization/finality rules below that base are not selected. The running candidate remains bounded to a suffix and does not implement production checkpoint advancement/pruning.

There is still no public peer discovery/ingress, native wallet/RPC/indexer/explorer, public zero-value multi-operator devnet, production owner-key ceremony, founder mint/transfer, independent security review, or live QZXB/USDT market. Gate 2, Gate 8, the public-devnet gate and independent release/security qualification remain open. This checkpoint is a material runtime/storage integration, not a public launch.
