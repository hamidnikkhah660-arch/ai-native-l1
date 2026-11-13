# QFP6 peer candidate review and explicit trust pins

The Q6AR address book is a candidate directory, not a trust store. A relay's signature/Noise pin authenticates the relay only; it does not authenticate the peer keys the relay advertises. Candidate keys are never promoted automatically.

## Inspect candidates

Run the peer-book utility against the same address-book file, network ID, and profile ID used by the node:

```powershell
cargo run --locked --offline --bin qrun_v06_peer_book -- list <address-book-path> <network-id-64-lowercase-hex> <profile-id-64-lowercase-hex>
```

Review the advertised endpoint and its 32-byte Noise static public key through an independent trusted channel before approval. Do not use the advertising relay alone as proof of the advertised peer identity.

## Approve a peer

```powershell
cargo run --locked --offline --bin qrun_v06_peer_book -- approve <address-book-path> <network-id> <profile-id> <numeric-ip:port> <noise-static-public-key-64-lowercase-hex>
```

For an existing Q6AR candidate, approval succeeds only if the exact advertised key matches and the advertisement has not expired. For a manually sourced endpoint, the operator-provided address/key pair is stored as an explicit pin. This command does not connect to the peer.

## Revoke approval

```powershell
cargo run --locked --offline --bin qrun_v06_peer_book -- revoke <address-book-path> <network-id> <profile-id> <numeric-ip:port>
```

Revocation removes only the operator-approved key. The historical candidate/advertisement metadata remains for audit.

## Enable bounded outbound history sync

The Permissionless launcher keeps outbound use of discovered peers disabled unless both settings are explicit in `permissionless_runtime`:

```json
{
  "enable_q6ar_candidate_address_book": true,
  "q6ar_candidate_address_book_path": "./peer-state/q6pa-address-book.json",
  "enable_approved_peer_outbound_sync": true,
  "max_approved_peer_sync_attempts": 2
}
```

Before enabling this switch, use the `approve` command above for each independently verified endpoint/key pair. The actual configuration must also contain its normal required Genesis/Q6PN/Q6CP/data/listener fields, and its full SHA-256 must be pinned out of band as required by the launcher. Keep the address-book path separate from both `data_directory` and `mempool_directory`. `max_approved_peer_sync_attempts` is bounded to 1..=4. Only eligible operator-approved pins are selected; the bounded attempts run a pinned Noise handshake and complete Q6HI/Q6HS history sync before mining. Failed peers receive persisted exponential backoff; startup fails closed when outbound sync was explicitly enabled but no approved peer is currently eligible. The node does not auto-trust Q6AR keys, auto-approve peers, auto-connect to candidates, open a public listener, or authorize Mainnet.

## Bitcoin-inspired operational rule

Keep discovery, explicit peer authentication, and consensus validation separate. A peer's advertisement is not proof of its identity; a successful pinned handshake is not proof that its chain is canonical. QFP6 still validates imported blocks, PoW, cumulative-work fork choice, and Genesis-rooted state locally.
