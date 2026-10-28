# CP-0456 ? QRun v0.5 QFP5 Node Integration (Loopback Candidate)

Date: 2026-10-28

Status: **local candidate integration only; not a public Mainnet activation**

Source base before this change: 00a05b7705c433e0ae57174c2b4806e1b6b6b785 (feat: persist QFP5 suffix from anchored checkpoints).

## Implemented in this checkpoint

- The QRun v0.5 fork runtime selects the separate QFP5 fee-only persistent store only when the exact proposed QRun network ID, Genesis owner account, and protocol version 5 are present. Version 5 with a different candidate identity is rejected; older fixture profiles retain their legacy envelope mode.
- QRun v0.5 block production creates the producer-bound QFB5/QFP5 envelope. The PoW header commits to the QFP5 block commitment, and the deterministic execution path pays only fees from transactions included in that block; it does not add a block subsidy.
- The local QRun node path uses a dedicated QFP5 store directory, allows the producer account to be configured, and requires QFP5 envelopes when its runtime is in the QRun v0.5 fee-only profile.
- Authenticated Noise peer gossip and bounded startup catch-up can process QFP5 blocks. Receive, relay, and sync paths compare the envelope type with the local store profile so a legacy PTB2 node cannot silently accept a QFP5 block, or vice versa.
- A focused runtime test mines, commits, closes, and reopens a QFP5 block while asserting the exact full-supply total and unchanged canonical tip/state root.
- A focused node integration test sends a QFP5 block over authenticated Noise, then serves the block through an authenticated sync request to a fresh node; all three candidate states converge to the same tip and state root while preserving the exact 10B atom-denominated supply.

## Validation run for this change

- cargo fmt --all -- --check ? passed.
- cargo test qrun_v05_pow_fork_runtime_candidate::tests --lib ? 4 passed.
- cargo test --bin qrun_v05_pow_local_node ? 10 passed.
- cargo check --all-targets ? passed.
- git diff --check ? passed.

These results establish candidate-code integration, not production network qualification.

## Intentional boundary that remains

The executable is still qrun_v05_pow_local_node, explicitly requires --local-testnet, rejects non-loopback sockets/peers, and reports mainnet=false. Its smoke profile deliberately overrides the target to Uint256::MAX and reduces Argon2 memory to 8 MiB. Those settings are unsuitable for a value-bearing public network and must not be exposed as Mainnet settings.

The integration does not close the remaining production engineering gates: a calibrated/frozen production difficulty and timestamp profile, full-history verification or a verifiable automatic checkpoint rollover beyond the bounded 1,024-block catch-up path, a genuinely independent and monotonic external CAS anchor, public peer bootstrap/reconnect/churn, end-to-end permissionless wallet submission on the fixed profile, independently operated multi-host recovery, and a release built from a single finalized production configuration. The external CAS provider in tests is not a deployed independent service. No public QRun Mainnet endpoint or live trade is asserted here.

The owner-directed candidate Genesis still specifies 10,000,000,000 QZXB at Genesis, with zero post-Genesis minting and zero block subsidy. That fixed-supply candidate is not evidence that 10B QZXB are already spendable on a public Mainnet or have market value. Exchange listing and legal approval are not treated as protocol software prerequisites.
