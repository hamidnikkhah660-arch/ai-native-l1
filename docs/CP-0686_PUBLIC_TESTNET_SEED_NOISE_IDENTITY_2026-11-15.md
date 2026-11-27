# CP-0686 — Public Testnet Seed Noise Identity

Date: 2026-11-15
Project: AI-NATIVE L1

## Scope

Derive and publish only the public static Noise identity corresponding to the already-provisioned Windows CurrentUser DPAPI-protected seed key. The private key is never printed, exported, or written to a new file. The existing protected key file is not modified.

## Verified derivation

- Source config: `release/qfp6-local-single-operator-devnet-2026-11-15/public-testnet-seed-config-ipv6.json`
- Network ID: `633b5dfc16fb2ec1825baf924ae7f7f16bf2006f8b64441a57692a3531722712`
- Profile ID: `a0a057d72c11253386bfe90d428bccbc44ebc86fc84e04e3682193a99d8805c4`
- Noise pattern: `Noise_XX_25519_ChaChaPoly_SHA256`
- Seed public static key: `3bb2100354aea0f82d7f5281574a0a8acbaa12dc7c7def11a341ec72a6068066`
- Public-key SHA-256 fingerprint: `9407504ce70ddf91478a82143195fffa6fd3375c52c0776ef223dff1a559ec48`
- Derivation output explicitly reported `private_key_material=NEVER_EXPORTED`.
- Loader source uses Windows CurrentUser DPAPI, network-bound entropy, validates the protected envelope, and zeroizes its plaintext buffer after copying the key into a zeroizing owner.

## Published identity artifact

- `release/qfp6-local-single-operator-devnet-2026-11-15/seed-noise-identity.json`
- Schema: `qfp6-public-testnet-seed-noise-identity/v1`
- The artifact contains only public network/profile identity, the Noise public key and fingerprint, and hashes binding the existing Q6GA authorization and IPv6 seed config.
- It explicitly declares `OUT_OF_BAND_PIN_REQUIRED` and `self_authenticating=false`. A Joining operator MUST verify the fingerprint with the project owner through a separate trusted channel. The JSON file or its download location alone is not an authenticated identity proof.

## Security and launch boundary

- This step did not start the blockchain node, open a listener, change the firewall, router, NAT, VPN, adapter, or DNS, or alter the protected Noise key.
- No owner wallet key or seed phrase was accessed.
- No Git commit, push, or merge was performed.
- The active public launcher still requires a separate integration and tests proving that the Joining client consumes the pinned Seed key on the live history-sync/bootstrap path. Do not treat this identity artifact as evidence that runtime pin enforcement is complete.
- Public Testnet remains NOT LAUNCHED. Independent operator/reviewer and README/CP-0652 launch gates remain.
- Mainnet, market, public mining, and value-bearing transfers remain unauthorized.

## Result

Public Seed Noise identity successfully derived and emitted as a public-only artifact. Next engineering task: trace and wire the existing pinned `QRunV06NoiseSession::connect` API into the actual Joining bootstrap/history-sync path, with wrong-key and MITM relay rejection tests, before building a Joining config generator.
## Live-key pin proof and runtime-path test addendum - 2026-11-15

### DPAPI-to-public-identity verification

- A temporary one-shot Rust probe used the existing CurrentUser DPAPI-protected key loader and the IPv6 seed config's Q6GD network binding. It never printed, persisted, or transmitted private-key material.
- Local loopback positive test: the actual protected Seed key completed Noise XX with a Joining-side `QRunV06NoiseSession::connect` configured with the published public key. Encrypted application-record request/response succeeded.
- Local loopback negative test: an impostor responder with a different static key was rejected by the same published pin with `UntrustedPeer`.
- Probe result: `DPAPI_SEED_PUBLIC_KEY_MATCH=PASS`, `PINNED_NOISE_XX_HANDSHAKE=PASS`, `WRONG_RESPONDER_KEY_REJECTED=PASS`, `NETWORK_AND_PROFILE_BOUND=PASS`, `PRIVATE_KEY_MATERIAL=NEVER_PRINTED`.
- Probe source and standalone executables were removed after execution. The protected key file and seed config were not modified.

### Existing production-path integration evidence

- Runtime `load_peers` requires each bootstrap row to contain a numeric `address` and a 32-byte `noise_static_public_key`; it validates the peer-set SHA-256 against the pinned config.
- The active history-sync client invokes `QRunV06NoiseSession::connect` with the selected peer's `noise_static_public_key`. The remote static key is compared before application records are exchanged.
- Existing tests passed:
  - `qfp6_noise_xx_pins_both_peers_and_encrypts_bounded_records`
  - `qfp6_noise_prologue_mismatch_rejects_handshake`
  - `qfp6_noise_rejects_unpinned_and_duplicate_peer_keys`
  - `qfp6_noise_responder_rejects_unpinned_initiator_before_session_exposure`
  - `pinned_noise_sync_imports_a_heavier_competing_branch_and_recovers_after_restart`
- All five selected tests passed; no failures.

### Security interpretation

- The Seed's permissionless inbound listener can accept anonymous Joining clients. This means the Seed does not authenticate every client's identity; it does not mean a Joining client that pins the Seed can be impersonated by a network MITM.
- A Joining client authenticates the Seed by pinning the responder's static key in Noise XX. A pure TCP relay can forward packets but cannot decrypt or re-encrypt the pinned end-to-end session as the Seed.
- The public identity JSON is not self-authenticating. Joining operators must verify fingerprint `9407504ce70ddf91478a82143195fffa6fd3375c52c0776ef223dff1a559ec48` with the owner over a separate trusted channel before using it.
- The Seed does not, by this mechanism alone, authenticate joining clients. Permissionless inbound policy, Sybil resistance, independent operator diversity, and independent security review remain separate requirements.

### Durable artifact integrity

- Identity artifact: `release/qfp6-local-single-operator-devnet-2026-11-15/seed-noise-identity.json`
- Identity artifact SHA-256: `28178575dc5cf5947245308e78d90e1d0ee33704b7714f522c202f1b9738c3d5`
- Size: 1174 bytes.
- The artifact binds the network ID, profile ID, public Noise key/fingerprint, Q6GA authorization hash, and IPv6 seed-config hash. It explicitly sets `self_authenticating=false` and `OUT_OF_BAND_PIN_REQUIRED`.
- Temporary probe executables/source were removed. No node process, TCP 30333 listener, or temporary diagnostic firewall rule remains.
- No firewall/router/NAT/VPN/adapter/DNS change, node launch, Git commit, push, or merge occurred.

### Next engineering step

Build the dedicated Joining config generator around the existing pinned bootstrap-peer schema. It must require a separately provisioned protected Joining Noise key, a numeric publicly routable Seed endpoint, an independently confirmed Seed fingerprint, separate data/mempool/anchor state, and a CreateNew output path. Do not launch the Seed or Joining node until the remaining CP-0652 independent operator/reviewer gates and explicit launch approval are satisfied.