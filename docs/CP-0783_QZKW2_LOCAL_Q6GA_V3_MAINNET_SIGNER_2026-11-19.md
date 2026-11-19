# CP-0783 — QZKW2 Local Q6GA v3 Mainnet Owner Signer

Date: 2026-11-19
Base: CP-0782 — `c8f054200b9d04b3ff34766c58213492c97c536c`
Branch: `feat/q6ga-v3-mainnet-scope-20261119`

## Implementation

- Added `qzxb_wallet approve-mainnet-genesis --wallet <absolute-QZKW2-path> --package-dir <absolute-mainnet-package-dir>`.
- The command is Windows-only and reuses the existing QZKW2 CurrentUser-DPAPI custody path. It does not accept seed/private-key input on the command line, write secrets, export a seed, or send signing material to a remote service.
- It invokes the existing Q6GA v3 `sign_mainnet_native` implementation, then decodes and verifies the completed signature against the same exact artifact hashes before writing it.
- It prints the full scope, owner, Genesis commitment, artifact hashes, peer count and economics, then requires a typed confirmation that includes the first 16 hex characters of both the Genesis commitment and peer-set hash.
- It re-reads every package file after confirmation and refuses to sign if any bytes changed during the review.
- It rejects an existing output signature, zero or empty peer sets, duplicate endpoints, duplicate or zero Noise keys, hostnames, private/shared-CGNAT/link-local/documentation/reserved/multicast endpoints, mixed testnet scope, anonymous inbound transport, mismatched artifact hashes, invalid Q6GD/Q6CP, nonzero Genesis height, broken Genesis invariants, a non-CP-0651 owner amount, or a mismatched QZKW2 owner account.
- It also requires `q6pn_profile_pin_commitment` in the Mainnet runtime config, decodes Q6PN with `QRunV06VerifiedProfilePin::decode` against that commitment, and checks that the embedded Q6GD descriptor is byte-identical to the package's Q6GD. The Q6PN file SHA-256 and the explicit profile-pin commitment are both bound into the config review. The command checks byte/commitment consistency; the operator must still obtain that commitment through a separately reviewed trust channel. The signer cannot independently prove the provenance of a value supplied inside the package.
- After a successful signature it writes `mainnet-native-authorization.q6ga`, adds its digest to `permissionless-config.json`, updates the manifest, and keeps `market_authorized=false`. File/config/manifest update failures attempt rollback and return an explicit do-not-launch error.

## Required unsigned Mainnet package layout

The signer deliberately does not convert the current `release/qfp6-candidate` directory in place. Build a separate package directory with these regular, non-symlink files:

- `mainnet-native-manifest.json` — schema `qfp6-mainnet-native-package/v1`, scope `MAINNET_NATIVE_VALUE_ONLY`, and pre-sign flags `mainnet_authorized=false`, `public_testnet_authorized=false`, `market_authorized=false`, `owner_genesis_signature_present=false`.
- `genesis-descriptor.q6gd`, `consensus-profile.q6cp`, `q6pn-profile.q6pn`, and `genesis-snapshot.q6sn` — the exact reviewed release artifacts.
- `mainnet-bootstrap-peers.json` — 1..=64 rows; each row contains exactly `address` (numeric public `IP:port`) and `noise_static_public_key` (64 lowercase hex characters). No placeholder, DNS name, private address, duplicate endpoint or duplicate static key is accepted.
- `permissionless-config.json` — complete node runtime config, not merely the fields checked by the wallet. Its `permissionless_runtime` object must use `mainnet-native-value-candidate`, `allow_candidate_runtime=true`, `allow_public_listener=true`, the exact Mainnet owner acknowledgement, and `PINNED_NOISE_STATIC_KEY_ALLOWLIST_REQUIRED`; it must bind the exact peer/artifact file names and digests, include `q6pn_profile_pin_commitment` obtained through the separately reviewed trust channel, and set `mainnet_native_authorization_path=mainnet-native-authorization.q6ga`. The authorization digest is absent until the owner signs.

The manifest must carry exact hashes under `q6gd_sha256`, `q6cp_sha256`, `q6pn_sha256`, `genesis_snapshot_sha256`, `bootstrap_peers_sha256`, plus `network_id_hex`, `profile_id_hex`, `owner_account_id_hex`, `genesis_descriptor_commitment_hex`, `bootstrap_peer_count`, CP-0651 economics fields and `permissionless_config_sha256`.

## Scope and limits

- Q6GA v3 authorizes only the exact native Mainnet Genesis and peer-set bytes shown to the owner. It does not authorize a market, external quote asset, USDT, an exchange, custody, listing, token sale, or any further issuance.
- The signer validates that peer endpoints and Noise static keys are distinct and globally routable. It does not prove that their operators are independently controlled or authenticate a legal entity behind each key. Independent-operator identity/ownership receipts and multi-operator runtime qualification remain external evidence that must be checked separately.
- A distinct peer pin authenticates the remote Noise static key, not automatically a human or company identity. Do not describe peer operators as independently verified from this signature alone.
- The wallet command does not start a node, open a listener, migrate data, stop the existing PID 20244, or modify an existing Q6GA v1/v2 signature.

## Existing release package assessment

The current `release/qfp6-candidate` package is not signable as Mainnet: its `bootstrap-peers.json` is an empty array, its attached authorization is Q6GA v2 with `ZERO_VALUE_PUBLIC_TESTNET_ONLY`, and its release manifest says `mainnet_status=NOT_AUTHORIZED`, `inbound_peer_identity_authenticated=false`, and public peer topology unqualified. The new command must reject that directory; do not rename its v2 signature or edit its manifest flags to make it appear Mainnet-ready.

## Validation

- `cargo +stable fmt --manifest-path src/native/pow_bench/Cargo.toml --all -- --check`: PASS.
- `cargo test --manifest-path src/native/pow_bench/Cargo.toml --bin qzxb_wallet --locked --offline -- --test-threads=1`: 17 passed, 0 failed (including Mainnet peer-set, IP filter, runtime-scope, Q6PN commitment-config and manifest/hash tests).
- `cargo build --manifest-path src/native/pow_bench/Cargo.toml --bin qzxb_wallet --locked --offline`: PASS.
- Built `src/native/pow_bench/target/debug/qzxb_wallet.exe --help` prints `approve-mainnet-genesis` and its Q6GA v3 scope.
- Built debug executable SHA-256: `D218282AAA388DAF089BBAEE4F0585993E1948C0BEFD5AF618E7EF1944995E2A`.
- Fail-closed runtime check against the existing zero-value `release/qfp6-candidate` package: command exited `2` because `mainnet-native-manifest.json` is absent; no `mainnet-native-authorization.q6ga` file was created.
- Existing unrelated warnings remain in other modules; the wallet target compiled and its 17 tests passed.

Disposition: local Q6GA v3 owner-signing code and package contract are implemented and built. No QZKW2 wallet was opened for signing in this work, no Q6GA v3 authorization was generated, no Mainnet package with actual approved peers exists yet, and no Mainnet node was started.