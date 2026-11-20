# CP-0640B — Runtime Trust-Registry Binding and Q6AR Enforcement

Date: 2026-11-14  
Project: AI-NATIVE L1 / QRUN-QFP6  
Branch: `feat/cp0600-bootstrap-sync-startup`  
Checkpoint status: implementation and targeted validation complete; working-tree only

## Objective

Turn the CP-0639 operator-provisioned trust-domain policy and CP-0640A transactional Q6AR ingestion into an enforced startup/runtime path. This checkpoint does not claim that trust-domain ownership is cryptographically proven or that the network is ready for Public Testnet.

## Runtime registry format

When `enable_q6ar_candidate_address_book=true`, the launcher requires both:

- `q6ar_trust_domains_path`: local JSON registry path, resolved relative to the runtime config directory when applicable.
- `q6ar_trust_domains_sha256`: 32-byte SHA-256 hex digest pinned inside the independently SHA-pinned permissionless runtime config.

The registry is bounded to 64 KiB and must be JSON schema version 1. Unknown top-level or assignment fields are rejected. There must be 1–256 assignments, and every active pinned Q6AR relay key must appear.

Example shape (illustrative IDs only; not production trust data):

```json
{
  "version": 1,
  "max_candidates_per_domain": 32,
  "max_relays_per_domain": 8,
  "assignments": [
    {
      "relay_static_public_key": "<64 lowercase or uppercase hex characters>",
      "trust_domain_id": "<64 lowercase or uppercase hex characters>"
    }
  ]
}
```

The policy constructor rejects zero keys/domain IDs, duplicate relay keys, and limits outside 1–256 candidates or 1–32 relay keys per domain. Registry rows and the quota limits are included in a deterministic fingerprint.

If Q6AR is disabled, supplying either registry setting is rejected. No remote advertisement field can assign or change a trust domain.

## Persistent binding and migration

- Q6PA persistent Address Book format is now V4; its payload contains the bound trust-registry fingerprint.
- V1, V2 and V3 stores remain readable and migrate to V4 on open. Existing records are retained by the migration.
- First binding validates all live, unapproved Q6AR Gossip records as a complete set: relay attribution must be pinned and complete, every relay must exist in the local registry, and per-domain candidate/relay quotas must hold.
- Expired, unapproved Gossip entries may be reclaimed as part of the binding transaction.
- A different registry fingerprint after binding fails closed with `TrustDomainRegistryMismatch` during ordinary startup. There is no silent re-attribution or automatic rotation.
- Explicit rotation is available only when the independently SHA-pinned runtime config contains `q6ar_trust_domains_rotation_authorized: true`; the setting defaults to false and is rejected unless Q6AR Address Book mode is enabled.
- Rotation reclaims expired, unapproved Q6AR Gossip candidates, but fails with `TrustDomainRotationBlockedByLiveCandidates` while any attributable live candidate remains. Unattributable legacy Gossip records fail closed. The full Address Book state and old fingerprint are restored if persistence fails.
- Therefore, during relay-key rotation, keep old and new keys assigned to the same domain until the old candidate records expire. Then explicitly authorize registry rotation in the SHA-pinned config. The new fingerprint is persisted in Q6PA V4 and is enforced after restart.
- Strict ingestion checks the same persisted fingerprint before accepting any Q6AR batch.

## Atomic ingestion and runtime path

The runtime launcher loads and validates the registry before it opens the P2P listener. It binds the registry to the persistent Address Book before proceeding to listener creation. The supervisor's Q6AR callback receives the exact policy object and calls `ingest_pinned_q6ar_with_trust_domains`; the legacy policy-free ingestion path is retained only for compatibility and is not used by this strict runtime callback.

Each batch counts one trust-domain candidate entry per live Q6AR Gossip record, while the existing per-relay and global candidate caps remain in force. Expiry reclamation, record changes, quota checks and persistence share a rollback boundary; failure restores the complete pre-call in-memory record set. The store persists by checksum-protected atomic replacement.

## Validation evidence

Commands run on the local working tree with `--locked --offline`:

- `cargo test --manifest-path src/native/pow_bench/Cargo.toml --bin qrun_v06_node q6ar_trust_domain_registry --locked --offline`: **2 passed, 0 failed**.
- `cargo test --manifest-path src/native/pow_bench/Cargo.toml --lib qrun_v06_bootstrap_trust_domain_candidate::tests --locked --offline`: **7 passed, 0 failed**.
- `cargo test --manifest-path src/native/pow_bench/Cargo.toml --lib qrun_v06_peer_address_manager_candidate::tests --locked --offline`: **19 passed, 0 failed**.
- `cargo fmt --manifest-path src/native/pow_bench/Cargo.toml -- --check`: passed.
- `git diff --check`: passed.
- Earlier in this integration sequence, `cargo check --manifest-path src/native/pow_bench/Cargo.toml --bins --locked --offline`: passed.

Warnings reported during Cargo builds are pre-existing unused-import/dead-code warnings in unrelated modules; no warnings were promoted to errors.

## Explicit limitations and remaining gates

1. A trust-domain ID is an operator assertion, not proof of independent ownership. The operator must verify administrative control out-of-band; multiple IDs controlled by one actor remain one Sybil source in reality.
2. This work is not an independent Sybil/eclipse/poisoning assessment, cryptographic audit, or consensus/economic audit.
3. The public-testnet executable path has not been launched. No port/listener or node process was started for this checkpoint.
4. PQ transport key agreement, Libcrux review, independent audits, deployment/release artifacts, and end-to-end multi-node adversarial tests remain separate gates.
5. No commit or push was made. All changes remain local in the existing dirty working tree; preserve its pre-existing edits and untracked checkpoint files.

## Repository state at checkpoint

- HEAD: `df673d07050688a64b26822d97e6ea609b68ce88`
- Upstream SHA at the time of verification: same as HEAD.
- Branch: `feat/cp0600-bootstrap-sync-startup`
- Local listener check: no TCP listener on port `30333`.
- Public Testnet: **NOT AUTHORIZED**.
