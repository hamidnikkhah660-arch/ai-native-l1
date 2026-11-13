# CP-0615 — Permissionless Base Runtime CLI Wiring

Date: 2026-11-12

## Change

Added a distinct `qrun_v06_node --permissionless-run` launch path. It composes the already-existing Genesis-rooted `QRunV06PermissionlessNodeRuntime`, durable fork store, Q6MJ mempool journal, pinned-peer full-history bootstrap sync, Noise listener, and permissionless mining supervisor. It does not call the QAP1 private-candidate launcher and does not load Q6TS, Provider, Q6EA, or QAP1 services.

The new path requires an independently supplied CLI config SHA-256. Inside that digest-bound config it separately pins the Q6PN commitment, Q6CP SHA-256, Genesis snapshot SHA-256, and bootstrap peer-set SHA-256. It verifies Q6GD/Q6PN identity, Q6CP profile binding, complete height-zero Genesis invariants and the current founder allocation before opening the durable runtime. The mempool journal is restored/revalidated before network supervision begins. The local Noise key is loaded through the protected-key provider and zeroized after the supervisor exits.

## Candidate configuration

The config root must contain `permissionless_runtime` with:

- `mode`: `permissionless-full-history-candidate`
- `allow_candidate_runtime`: `true`
- `q6pn_profile_pin_path`, `q6pn_profile_pin_commitment`
- `q6cp_profile_path`, `q6cp_profile_sha256`
- `genesis_snapshot_path`, `genesis_snapshot_sha256`
- `data_directory`, `mempool_directory`
- `node_noise_private_key_path`
- `listen_address` (numeric unicast bind; `0.0.0.0:PORT` is permitted)
- `bootstrap_peers_path`, `bootstrap_peers_sha256`
- `producer_account`
- optional `max_nonce_attempts_per_block`

Bootstrap peer file is a JSON array of `{ "address": "IP:PORT", "noise_static_public_key": "64-lowercase-hex" }` records. All referenced paths resolve relative to the config file and must be absolute after resolution. The peer set is bounded and hash-pinned.

Invocation:

`qrun_v06_node --permissionless-run --config <path> --config-sha256 <64-hex>`

The supplied config digest must be obtained/pinned independently of the config file itself.

## Important limits / not a Mainnet claim

- This is candidate runtime wiring, not Mainnet authorization.
- The supervisor currently authenticates peers against the configured pinned Noise static-key set. A public socket bind alone does not make peer admission fully open/permissionless; an independently reviewed public peer-admission/discovery policy remains required.
- The current Q6CP profile still inherits candidate/testnet PoW target/retarget settings; production consensus calibration, timestamp/future-time rules, and independent review remain open.
- No final production Genesis, production trust/identity package, public operator/bootstrap set, RPC/explorer, public mining qualification, or QZXB/USDT market/liquidity is created by this change.
- QAP1 private-candidate mode remains separate and unchanged.

## Validation

Targeted `qrun_v06_node` unit tests include public wildcard listener parsing and strict specific unicast peer endpoints. Full `cargo check --all-targets --locked --offline`, `cargo fmt --check`, and `git diff --check` are required before commit. No prior CP-0566C/0572/0587 two-host/transaction tests are repeated.

For an existing `data_directory` with a non-empty `manifests` directory, the config must additionally include `trusted_manifest_anchor` (64 lowercase hex) obtained from an independent protected source. The launcher refuses to reopen existing history without it. Omit this field only for a fresh Genesis-only store.

The candidate manifest now records `permissionless_base_runtime_wired=true` because the executable has a distinct CLI path into this runtime. `full_history_replay_qualified=false`, `public_listener_qualified=false`, and `production_authorized=false` remain unchanged; the manifest also marks candidate-only and pinned peer admission explicitly.
