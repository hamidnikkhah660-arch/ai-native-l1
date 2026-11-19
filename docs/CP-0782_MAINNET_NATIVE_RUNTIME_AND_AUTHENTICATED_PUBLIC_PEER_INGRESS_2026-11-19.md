# CP-0782 — Mainnet-Native Runtime Path and Authenticated Public Peer Ingress

Date: 2026-11-19
Worktree: D:\Temp\ASUS\QRUN_QFP6_UNIFIED_20261118
Branch: feat/q6ga-v3-mainnet-scope-20261119
Base checkpoint: CP-0781 / 3ea839eca0b12e97a8dd9323ac1327b1b123cb7a

## Objective

Continue the Bitcoin-like bootstrapping sequence by separating a Mainnet-native candidate runtime path from the zero-value Public Testnet path. The Mainnet-native path is intended for native QZXB transactions only; external quote assets, markets, exchanges, custody and listings remain separate authorization decisions.

## Implementation

### Dedicated CLI and runtime mode

- Added `qrun_v06_node --mainnet-run --config <path> --config-sha256 <64-hex>`.
- Added a dedicated `mainnet-native-value-candidate` runtime mode and `run_mainnet_native_node` dispatch.
- The Mainnet-native path is mutually exclusive with Public Testnet mode and the local-only candidate mode.
- Mainnet-native configuration requires `allow_candidate_runtime=true`, `allow_public_listener=true`, the exact `QZXB_MAINNET_NATIVE_VALUE_OWNER_AUTHORIZATION_REQUIRED` acknowledgement, and `PINNED_NOISE_STATIC_KEY_ALLOWLIST_REQUIRED` for inbound security. A Public Testnet acknowledgement is rejected in this mode.

### Q6GA v3 authorization binding

- Mainnet-native startup reads the separately configured `mainnet_native_authorization_path` and `mainnet_native_authorization_sha256`.
- The authorization must decode and pass both Ed25519 and ML-DSA-65 verification, and `verify_mainnet_native_bindings` must match the exact Q6GD, Q6CP, Q6PN, Genesis snapshot and non-empty bootstrap-peer-set SHA-256.
- V1 local-only and V2 zero-value Public Testnet approvals are rejected by the V3 verifier.
- The Q6GA v3 scope authorizes only native Mainnet operation within those exact bindings. It does not authorize a market, quote asset, exchange, custody, listing, public mining subsidy or any additional issuance.

### Public ingress with mandatory Noise key allow-list

- The QFP6 listener can now bind a globally routable address or wildcard when a non-empty trusted remote static-key allow-list is supplied.
- A public listener without a non-empty allow-list is still not the Mainnet-native path; anonymous Noise XX remains confined to the explicit zero-value Public Testnet candidate path.
- Public bind checks reject private, loopback, link-local, shared-CGNAT, multicast, broadcast and documented special-use IP ranges; IPv4-mapped IPv6 addresses are normalized and checked against the corresponding IPv4 policy.
- Mainnet-native topology requires at least one non-empty, valid bootstrap peer with a globally routable endpoint and a pinned Noise static public key. The same configured peer set is used by the supervisor for pinned peer admission and is hash-bound by Q6GA v3.
- Peer discovery remains operator-pinned. This checkpoint does not implement automatic discovery or self-authenticating owner attestations.

## Validation

On the Windows owner workstation, using locked offline dependencies:

- `cargo +stable fmt --manifest-path src/native/pow_bench/Cargo.toml --all -- --check`: PASS.
- `cargo test --manifest-path src/native/pow_bench/Cargo.toml --bin qrun_v06_node --locked --offline -- --test-threads=1`: 48 passed, 0 failed.
- `cargo test --manifest-path src/native/pow_bench/Cargo.toml --lib qrun_v06_peer_listener_candidate::tests::public_pinned_bind_policy_requires_global_unicast_or_wildcard --locked --offline -- --nocapture`: 1 passed, 0 failed.
- `cargo build --manifest-path src/native/pow_bench/Cargo.toml --bin qrun_v06_node --locked --offline`: PASS.
- The built `target/debug/qrun_v06_node.exe --help` prints the `--mainnet-run` entry and explicitly states its v3, pinned-peer and candidate-qualification requirements.
- Built debug executable SHA-256: `25D85A1213E3EF5E4541C765C159A8EDA4D1F27785469864E1A678F6D1204194`.
- Existing warnings from unrelated modules remain; no new compile errors were observed in the tested targets.

## Remaining prerequisites — no production claim

- No Mainnet v3 owner authorization has been generated or signed. The wallet CLI still needs a dedicated owner-local `approve-mainnet-genesis` flow that reviews the exact package and requires explicit confirmation.
- No final Mainnet package has yet been produced with its final non-empty, independently approved bootstrap peer file, endpoint records and operator receipts. Any peer-set change requires a new hash-bound v3 signature.
- No independent public operator nodes have yet been started on this exact candidate or shown to complete history synchronization with one another.
- No two-node Mainnet-native value-transfer test, canonical inclusion, restart/replay or double-spend/reorg qualification has yet been completed with this exact runtime.
- The existing 1B QZXB owner allocation is still only verified in the height-0 Genesis snapshot; this checkpoint does not prove that balance spendable on a live public network.
- Q6GA v3 does not authorize a market. Quote-asset backing, external liquidity, pricing and trading are not part of this change.

## Preservation

- Existing CP-0596 PID 20244 / TCP 30333 was not stopped, restarted, replaced or reconfigured.
- No runtime database, Genesis artifact, existing Q6GA approval, owner wallet, private key, DPAPI file or local Noise secret was opened or changed.
- No Mainnet authorization was created; no real funds were moved; no public listener was started.
- No external host, DNS record, firewall, VPN, exchange or payment service was modified.

Disposition: a dedicated Mainnet-native candidate CLI/runtime path and pinned public Noise ingress policy are implemented and compile/test successfully. The project is not thereby launched: final owner authorization, approved independent peers, and end-to-end multi-node value-transfer qualification remain open.