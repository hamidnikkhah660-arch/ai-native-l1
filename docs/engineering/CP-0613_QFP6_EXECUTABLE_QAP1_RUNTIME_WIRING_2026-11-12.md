# CP-0613 — QFP6 executable-level QAP1 runtime wiring

**Date:** 2026-11-12
**Base:** CP-0612 / `5e41fe0156eb9e6a992ed7fccf37ae2ba3055a3a`
**Scope:** private-candidate executable integration only. This is not a Mainnet release or public-network authorization.

## Delivered

The `qrun_v06_node` binary now exposes a `--run` path that calls the CP-0612 QAP1 bootstrap supervisor from the actual executable. The new launcher lives in `src/bin/qrun_v06_node_runtime_launch/mod.rs`; the standalone `src/bin/qrun_v06_node.rs` remains the CLI entry point.

Startup is candidate-only and fail-closed. It requires all of the following:

- A configuration digest supplied independently via `--config-sha256`.
- `runtime.mode = "private-candidate"` and `runtime.allow_candidate_runtime = true`.
- The existing preflight-valid Genesis snapshot, Q6GD/Q6CP/Q6PN/Q6TS, independent monotonic Q6TS floor, Q6EA state and separate Provider/Anchor pins/endpoints.
- A protected, network-bound local Noise key plus separately protected Provider and Q6EA client Noise keys. The three identities must be distinct.
- An operator-pinned set of 1–64 bootstrap peers, each with a private/overlay address and a 32-byte Noise static public-key pin.
- A nonzero producer account, a persistent QFP6 data directory and a separate durable Q6MJ journal directory.

The launcher verifies the exact Q6TS/Q6PN identity against the existing read-only trust-floor adapter. It does not provision or advance the Q6TS floor. It validates peer pins, listener endpoint separation and disjoint Q6MJ/QFP6 storage paths before Q6TS network reads. After Genesis/profile validation, it acquires the local Q6MJ writer lock and private listener before any QAP1 recovery transition, so local resource failures cannot strand a remote transition. It opens the QFP6 store with the trust-authorized profile pin and height-correct Q6QA authorization, recovers the QAP1 journal, performs the CP-0612 pinned-peer history synchronization and only then hands control to the QAP1 mining supervisor.

### Crash-window recovery

A QAP1 commit can be interrupted after the independent Provider/Anchor has recorded the successor but before the local Manifest has advanced, or after the local Manifest has advanced but before QAP1 finalization. The launcher now loads and verifies the durable QAP1 journal before opening the store. It accepts the local Manifest generation only when it matches that journal's authenticated predecessor or successor, and only when the configured independent Q6EA state equals one of those two states. With no pending journal, the live Provider and Q6EA must directly match the independent state. With a pending journal, startup does not demand premature equality between the two services; CP-0612 recovery reconciles the recorded intermediate phase and verifies the successor before mining. Any unrelated generation or state refuses startup. There is no legacy-anchor or non-QAP1 fallback.

## CLI

```text
qrun_v06_node --preflight --config <path> --config-sha256 <64-hex>
qrun_v06_node --probe-qap1 --config <path> --config-sha256 <64-hex>
qrun_v06_node --run --config <path> --config-sha256 <64-hex>
```

The config hash must be supplied out-of-band and must match the exact config bytes. `--run` does not make a candidate into Mainnet: it is restricted to private/loopback/LAN/overlay addresses. Public IPs, unspecified addresses, multicast addresses and DNS peer endpoints are rejected.

## Runtime configuration

Add this object to the existing, independently pinned top-level JSON configuration. The values below are schema placeholders, not provisioned paths, keys or network endpoints.

```json
{
  "runtime": {
    "mode": "private-candidate",
    "allow_candidate_runtime": true,
    "data_directory": "<absolute QFP6 store directory>",
    "node_noise_private_key_path": "<protected network-bound Node Noise key file>",
    "listen_address": "<private-or-overlay-IP:port>",
    "bootstrap_peers_path": "<absolute pinned-peers JSON path>",
    "transaction_journal_directory": "<absolute separate Q6MJ directory>",
    "producer_account": "<64 lowercase hex characters: producer account ID>",
    "max_blocks_per_run": 1,
    "max_nonce_attempts_per_block": 1000000
  }
}
```

The peer file is a JSON array. Each entry supplies an operator-provided address and pinned Noise static public key; the example values are illustrative only.

```json
[
  {
    "address": "<private-or-overlay-IP:port>",
    "noise_static_public_key": "<64 lowercase hex characters>"
  }
]
```

The existing root config must also provide the QAP1 inputs already used by `--probe-qap1`: Provider and Q6EA endpoints and server-key pins, the protected Provider/Anchor client-key paths, the existing Provider floor path, the independently hashed Q6EA expected-state path, Q6PN/Q6TS artifacts, the authority public keys and the configured AWS CLI/region/table used for the read-only Q6TS floor. No private key material belongs in JSON or command-line arguments.

## Fail-closed boundaries

- No Genesis, Q6GD, Q6CP, Q6PN, Q6TS, Q6EA expected state, Provider floor, bootstrap peer or Noise identity is generated by this launcher.
- No public listener, DNS discovery, exchange integration, Mainnet signing or Mainnet activation is enabled.
- A Q6PN quote-asset trust pin requires its matching Q6QA bundle. Without a current height-valid authorization, external quote-asset operations are rejected.
- The bundled Libcrux ML-DSA-65 verifier remains candidate-grade; executable wiring does not constitute independent cryptographic approval or production qualification.
- `--run` can mutate the private candidate's local QFP6/QAP1 and Q6MJ stores and can issue QAP1 transitions while mining. It must only be used with the independently provisioned candidate environment, never with fabricated or copied test fixtures.

## Validation performed

- `cargo test --bin qrun_v06_node --locked --offline`: **20 passed, 0 failed**. This includes CLI refusal, private/overlay bind policy, Mainnet-mode refusal and selection of authenticated QAP1 predecessor/successor Manifest generations.
- `cargo check --all-targets --locked --offline`: passed.
- `cargo fmt --all -- --check`: passed.
- `git diff --check`: passed.
- CLI `--help`: passed.
- CLI `--run` against a deliberately missing config file: refused before any network or store access, as expected.

The local `release/qfp6-candidate/manifest.json` still lists the six canonical release inputs as missing and marks production authorization false. Therefore no real candidate node was started in this work session and no end-to-end QAP1 history sync or mining result is claimed. The historical CP-0566C/CP-0572/CP0587 multi-host tests remain credited and were not repeated.
