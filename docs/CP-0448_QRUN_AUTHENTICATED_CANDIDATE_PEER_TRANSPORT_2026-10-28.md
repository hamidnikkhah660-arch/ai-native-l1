# CP-0448 — QRun v0.5 domain-separated authenticated candidate peer transport

Date: 2026-10-28

Status: implemented and locally tested as a candidate transport integration. Not a Mainnet release or authorization for public bind.

## Changes

- Added `qrun_v05_noise_transport_candidate.rs`, a QRun-specific Noise XX domain separated from the zero-value Devnet transport. It pins the remote static key and binds the handshake to the configured network ID, a fingerprint of all consensus parameters, and the Genesis commitment; it encrypts bounded records and fails closed on wrong-network, unknown-key, malformed or tampered records.
- Wired optional authenticated peer sessions into `qrun_v05_pow_local_node` block exchange and canonical-sync request/response handling. A node configured with an NPK1 protected private key requires the configured pinned-key trust set on inbound connections and refuses plaintext fallback if an outbound peer's key pin is missing. Block acknowledgments and bounded history pages use the same encrypted session.
- Added absolute-height canonical range export with block/byte budgets and a fail-closed error when a checkpoint-rooted segment is asked for history at or before its trusted base. Added bounded catch-up across multiple authenticated pages; every downloaded PTB2 block must extend the local canonical tip and pass local consensus validation, and an ahead/untrusted checkpoint is never adopted automatically. The candidate binary now exposes an explicit `--sync-on-start true` option that performs this catch-up from a pinned peer before binding its loopback listeners; it requires an NPK1 key and peer pins, and fails startup if every pinned peer fails.
- Added `qrun_v05_noise_keygen`, which creates a Noise static keypair, stores the private key using Windows CurrentUser DPAPI bound to the supplied network ID, and prints only the public key. The utility refuses to overwrite an existing key file.
- In-memory node and ephemeral copies of Noise private keys are explicitly zeroed on drop/after use where the code controls their lifecycle.
- Added an authenticated two-node integration test that propagates an empty block and a signed transfer and verifies matching canonical tip/state root, recipient balance and receipt. A canonical consensus-profile fingerprint covers all parameters plus the Genesis commitment, with a regression test that changing PoW parameters or Genesis changes the fingerprint. Added a regression test proving an authenticated outbound peer with a missing pin fails without sending plaintext, and a separate test confirming non-loopback binds remain rejected; the parser also rejects duplicate peer sockets.

## Validation

The following passed on Windows stable Rust with locked dependencies:

- `cargo +stable fmt --all -- --check`
- Eight unit tests for the QRun-domain Noise transport, including wrong-network and wrong-profile handshake rejection, mutual static-key pinning, unknown-key rejection, trust-set bounds, tamper rejection and record-size limits.
- `tests::consensus_profile_fingerprint_changes_when_pow_parameters_change`
- `tests::two_qrun_nodes_sync_signed_transfer_over_authenticated_noise_xx`
- `tests::bounded_sync_wire_rejects_bad_versions_trailing_bytes_and_budget_overruns`
- `tests::fresh_node_catches_up_canonical_signed_transfer_over_authenticated_sync_page`
- `tests::fresh_node_catches_up_multiple_pages_through_authenticated_sync_handler` (18 blocks across 3 authenticated pages)
- `private_testnet_fork_choice::tests::canonical_range_export_is_ordered_bounded_and_respects_checkpoint_base`
- `tests::authenticated_mode_refuses_unpinned_peer_instead_of_plaintext_fallback`
- `tests::smoke_node_public_listener_guard_remains_fail_closed`
- `tests::two_pow_nodes_sync_signed_transfer_over_real_loopback_socket`
- `tx_ingress_tests::qzts_signed_wallet_request_executes_and_persists_canonical_receipt`
- `cargo +stable check --all-targets --locked`

## Security boundary

The candidate process still hard-rejects every non-loopback address and still uses the trivial maximum-target PoW profile. The authenticated transport uses classical X25519/ChaChaPoly and statically provisioned pins; it is not a reviewed public discovery/rotation/revocation system, nor a post-quantum hybrid protocol. No public node was started, no firewall or router was changed, and no value-bearing transaction was broadcast.

This candidate change does not implement a frozen production consensus profile, robust difficulty/timestamp retargeting, unbounded/full-history public sync, production checkpoint rollover/external anti-rollback provider, public peer bootstrap, independent security review, public explorer or actual liquidity/counterparty. All remain mandatory before calling the 10B Genesis a spendable Mainnet supply. No price or completed trade is claimed.
