# CP-0616 — Open Inbound Peer Candidate and Long-Running Listener

Date: 2026-11-12

## What changed

- The permissionless Genesis-rooted executable now supports an explicitly opted-in wildcard/public listener through `permissionless_runtime.allow_public_listener=true`. A private/loopback bind does not require that flag. This is an operator opt-in for the candidate executable, not Mainnet activation.
- The pinned Noise path remains unchanged for outbound bootstrap sync and the anchored QAP1 candidate mode.
- The permissionless combined history/transaction/block ingress path accepts inbound sessions with an empty remote-static-key pin list. It uses Noise XX with the QFP6 network/profile prologue. The remote static key is retained for diagnostics but is marked `remote_static_key_pinned=false` and is not counted as authenticated.
- Listener statistics distinguish `authenticated_sessions` from `unverified_peer_sessions`.
- An empty, SHA-256-pinned bootstrap peer array (`[]`) is now accepted for a fresh Genesis-rooted node. With no outbound seed peers, the node starts from Genesis but does not synchronize an existing public chain or discover peers automatically.
- The open permissionless Supervisor now rotates finite accepted-session windows without closing the TCP listener, clearing the durable runtime, or discarding Q6MJ. A node can remain running until Ctrl-C/SIGTERM rather than exiting after one session-budget window. A bootstrapped node uses the same long-running open inbound Supervisor after its pinned outbound sync completes.

## Security model — important limitation

Open inbound Noise XX is **not peer authentication**. There is no out-of-band pin for the remote static key, so the remote identity is self-asserted; an active man-in-the-middle can terminate and re-encrypt the transport. At best, this protects against passive eavesdropping. Do not use this mode for privileged secrets or treat the remote static key as a trusted identity. This is not a post-quantum transport.

Application integrity remains separately enforced: bounded QFP6 frame decoding, replay guards, Q6TI hybrid transaction signature validation, block PoW and consensus validation, state-root checks, and canonical fork choice remain mandatory. A transport peer cannot gain authority to mint, confirm, or override chain state merely by opening a session. Anonymous peers can still cause censorship, delay, partitioning, and denial-of-service; the listener and session budgets remain important defenses.

## Bootstrap and discovery boundary

- Outbound history sync still uses operator-pinned Noise static keys and endpoints from the hash-pinned peer-set file.
- A non-empty peer set performs pinned outbound history synchronization before the long-running open inbound Supervisor begins.
- An empty `[]` peer set is only suitable for a fresh Genesis-rooted node or an isolated candidate. It does not provide a route to the current tip of an existing network.
- Public peer discovery, authenticated peer advertisements, address gossip, independent public seed operators, and Sybil/DoS review are not implemented or qualified by this change.

## Validation added

- Unpinned Noise XX session test: encrypted records work while the responder reports the remote key as unpinned.
- Open combined listener test: an anonymous peer reaches the wildcard-bound candidate listener, submits a Q6PB request, and receives Q6PA without being mislabeled as an authenticated peer.
- Launcher tests: a public/wildcard bind requires the explicit `allow_public_listener=true` candidate opt-in; a private bind does not; an empty bootstrap seed array is accepted only when its exact SHA-256 is pinned.
- Supervisor stats test keeps pinned and unverified peer session counts separate.
- Previously verified CP-0566C/0572/0587 two-host and transaction evidence is not repeated.

## Not a Mainnet claim

No final production Genesis, canonical public network/profile identity package, production Q6CP calibration, authenticated public discovery/bootstrap infrastructure, public RPC/explorer, independent multi-operator qualification, or production security review is created here. Mainnet remains unauthorized and unsigned. Public mining is not qualified. QZXB/USDT still requires a real exchange/counterparty or on-chain liquidity; no pair or liquidity is created by this code change.

## Candidate validation results

- `cargo test --bin qrun_v06_node --locked --offline`: 26 passed, 0 failed.
- Unpinned Noise session round-trip test: passed.
- Anonymous peer Q6PB/Q6PA integration test against wildcard bind: passed.
- Supervisor pinned/unverified metrics aggregation test: passed.
- Candidate public-bind opt-in, empty hash-pinned seed list, and existing Manifest Anchor tests: passed.
- The previous two-host CP-0566C/0572/0587 experiments were not repeated.
