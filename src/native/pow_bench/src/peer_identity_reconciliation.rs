//! Read-only comparison of the C-side peer identity anchor and D-side generation high-water.
//! This module performs no reconciliation writes; mismatches must be quarantined.
use crate::{
    identity_generation_store::{IdentityGenerationError, IdentityGenerationStateStore},
    peer_identity_anchor_vault::{PeerAnchorRotationActiveBinding, PeerIdentityAnchorVault},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerIdentityReconciliationError {
    AnchorNotEnrolled,
    GenerationStoreUninitialized,
    IdentityGenerationMismatch,
    RecordDigestMismatch,
    LifecycleMismatch,
    DAdvancedBeforeAnchorActivation,
    /// C has an exact one-generation successor bound to D's prior record, but NPI1/NRT1
    /// and dual-attestation evidence still require independent verification before recovery.
    AnchorAheadOfGenerationStoreUnverified {
        anchor_sequence: u64,
        anchor_generation: u32,
        generation_store_generation: u32,
        anchor_event_digest: [u8; 32],
        predecessor_event_digest: [u8; 32],
        previous_record_digest: [u8; 32],
        successor_record_digest: [u8; 32],
        noise_fingerprint: [u8; 32],
        npi1_digest: [u8; 32],
        nrt1_digest: [u8; 32],
        intent_digest: [u8; 32],
        nonce: [u8; 32],
        owner_pin_fingerprint: [u8; 32],
        operator_pin_fingerprint: [u8; 32],
    },
    GenerationStore(IdentityGenerationError),
}

impl From<IdentityGenerationError> for PeerIdentityReconciliationError {
    fn from(value: IdentityGenerationError) -> Self {
        Self::GenerationStore(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerIdentityReconciliation {
    Synchronized {
        generation: u32,
        record_digest: [u8; 32],
    },
    RotationPrepared {
        active_generation: u32,
        prepared_generation: u32,
        active_record_digest: [u8; 32],
    },
}

type Binding = (u32, [u8; 32], u8);

/// Compare exact generation, canonical KeyRecord digest, and lifecycle.
/// A PREPARED successor is acceptable only while D still equals the prior ACTIVE event.
/// This function never writes either store or authorizes activation.
pub fn compare_peer_identity_state(
    vault: &PeerIdentityAnchorVault,
    generation_store: &IdentityGenerationStateStore,
) -> Result<PeerIdentityReconciliation, PeerIdentityReconciliationError> {
    compare_bindings_with_rotation(
        vault.active_record_binding(),
        generation_store.high_water_binding()?,
        vault.pending_generation(),
        vault.latest_rotation_active_binding(),
    )
}

fn compare_bindings(
    active: Option<Binding>,
    high_water: Option<Binding>,
    pending_generation: Option<u32>,
) -> Result<PeerIdentityReconciliation, PeerIdentityReconciliationError> {
    compare_bindings_with_rotation(active, high_water, pending_generation, None)
}

fn compare_bindings_with_rotation(
    active: Option<Binding>,
    high_water: Option<Binding>,
    pending_generation: Option<u32>,
    latest_rotation_active: Option<PeerAnchorRotationActiveBinding>,
) -> Result<PeerIdentityReconciliation, PeerIdentityReconciliationError> {
    let active = active.ok_or(PeerIdentityReconciliationError::AnchorNotEnrolled)?;
    let high_water =
        high_water.ok_or(PeerIdentityReconciliationError::GenerationStoreUninitialized)?;

    if high_water.0 != active.0 {
        if pending_generation == Some(high_water.0) {
            return Err(PeerIdentityReconciliationError::DAdvancedBeforeAnchorActivation);
        }
        if let Some(event) = latest_rotation_active {
            let exact_one_step_successor = active.0 > high_water.0
                && high_water.0.checked_add(1) == Some(active.0)
                && event.generation == active.0
                && event.previous_generation == high_water.0
                && event.previous_key_record_digest == high_water.1
                && event.key_record_digest == active.1
                && event.lifecycle == active.2
                && high_water.2 == 1
                && event.lifecycle == 1;
            if exact_one_step_successor {
                return Err(
                    PeerIdentityReconciliationError::AnchorAheadOfGenerationStoreUnverified {
                        anchor_sequence: event.sequence,
                        anchor_generation: event.generation,
                        generation_store_generation: high_water.0,
                        anchor_event_digest: event.event_digest,
                        predecessor_event_digest: event.predecessor_event_digest,
                        previous_record_digest: event.previous_key_record_digest,
                        successor_record_digest: event.key_record_digest,
                        noise_fingerprint: event.noise_fingerprint,
                        npi1_digest: event.npi1_digest,
                        nrt1_digest: event.nrt1_digest,
                        intent_digest: event.intent_digest,
                        nonce: event.nonce,
                        owner_pin_fingerprint: event.owner_pin_fingerprint,
                        operator_pin_fingerprint: event.operator_pin_fingerprint,
                    },
                );
            }
        }
        return Err(PeerIdentityReconciliationError::IdentityGenerationMismatch);
    }
    if high_water.1 != active.1 {
        return Err(PeerIdentityReconciliationError::RecordDigestMismatch);
    }
    if high_water.2 != active.2 {
        return Err(PeerIdentityReconciliationError::LifecycleMismatch);
    }

    if let Some(prepared_generation) = pending_generation {
        if active.0.checked_add(1) != Some(prepared_generation) {
            return Err(PeerIdentityReconciliationError::IdentityGenerationMismatch);
        }
        return Ok(PeerIdentityReconciliation::RotationPrepared {
            active_generation: active.0,
            prepared_generation,
            active_record_digest: active.1,
        });
    }

    Ok(PeerIdentityReconciliation::Synchronized {
        generation: active.0,
        record_digest: active.1,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        identity_generation_store::encode_signed_rotation_statement,
        identity_policy::{self, KeyAlgorithm, KeyPurpose, KeyRecord, KeyState},
        peer_identity_anchor_vault::{
            PeerAnchorEvent, PeerAnchorEventKind, PeerIdentityAnchorScope,
        },
    };
    use ed25519_dalek::SigningKey;
    use sha2::{Digest, Sha256};
    use std::{
        fs,
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };

    static NEXT: AtomicU64 = AtomicU64::new(1);

    struct Fixture {
        root: PathBuf,
        issuer: SigningKey,
        network: [u8; 32],
        old_record: Vec<u8>,
        new_record: Vec<u8>,
        scope: PeerIdentityAnchorScope,
    }

    impl Fixture {
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!(
                "peer-reconcile-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir_all(root.join("anchor-c")).unwrap();
            fs::create_dir_all(root.join("highwater-d")).unwrap();
            let issuer = SigningKey::from_bytes(&[0x91; 32]);
            let network = [0x42; 32];
            let old_record = identity_policy::encode(&KeyRecord {
                key_id: 700,
                generation: 2,
                algorithm: KeyAlgorithm::NoiseX25519,
                purpose: KeyPurpose::PeerAuth,
                state: KeyState::Active,
                not_before: 100,
                not_after: 900,
                public_key: vec![0x21; 32],
            })
            .unwrap();
            let new_record = identity_policy::encode(&KeyRecord {
                key_id: 700,
                generation: 3,
                algorithm: KeyAlgorithm::NoiseX25519,
                purpose: KeyPurpose::PeerAuth,
                state: KeyState::Active,
                not_before: 100,
                not_after: 900,
                public_key: vec![0x22; 32],
            })
            .unwrap();
            let issuer_fingerprint = Sha256::digest(issuer.verifying_key().to_bytes()).into();
            let scope = PeerIdentityAnchorScope {
                network_id: network,
                profile_id: [0x51; 32],
                genesis_root: [0x61; 32],
                role: 1,
                issuer_id: 17,
                issuer_public_key_fingerprint: issuer_fingerprint,
                key_purpose: KeyPurpose::PeerAuth as u8,
                credential_id: 9001,
                key_id: 700,
            };
            Self {
                root,
                issuer,
                network,
                old_record,
                new_record,
                scope,
            }
        }

        fn open_store(&self) -> IdentityGenerationStateStore {
            IdentityGenerationStateStore::open(
                self.root.join("highwater-d").join("identity.highwater"),
                &self.network,
                700,
                KeyPurpose::PeerAuth,
                9001,
                17,
                self.issuer.verifying_key().to_bytes(),
            )
            .unwrap()
        }

        fn open_vault(&self) -> PeerIdentityAnchorVault {
            PeerIdentityAnchorVault::open(self.root.join("anchor-c"), self.scope.clone()).unwrap()
        }

        fn enroll(&self, vault: &mut PeerIdentityAnchorVault) {
            let digest: [u8; 32] = Sha256::digest(&self.old_record).into();
            self.enroll_binding(vault, digest, 1);
        }

        fn enroll_binding(
            &self,
            vault: &mut PeerIdentityAnchorVault,
            key_record_digest: [u8; 32],
            lifecycle: u8,
        ) {
            vault
                .enroll_genesis(PeerAnchorEvent {
                    kind: PeerAnchorEventKind::EnrolledActive,
                    generation: 2,
                    previous_generation: 0,
                    lifecycle,
                    noise_fingerprint: [0x21; 32],
                    npi1_digest: [0x71; 32],
                    key_record_digest,
                    previous_key_record_digest: [0; 32],
                    nrt1_digest: [0; 32],
                    intent_digest: [0; 32],
                    nonce: [0; 32],
                    owner_pin_fingerprint: [0xa1; 32],
                    operator_pin_fingerprint: [0xb2; 32],
                })
                .unwrap();
        }

        fn prepare(&self, vault: &mut PeerIdentityAnchorVault) {
            let old_digest: [u8; 32] = Sha256::digest(&self.old_record).into();
            let new_digest: [u8; 32] = Sha256::digest(&self.new_record).into();
            vault
                .prepare_rotation(PeerAnchorEvent {
                    kind: PeerAnchorEventKind::RotationPrepared,
                    generation: 3,
                    previous_generation: 2,
                    lifecycle: 1,
                    noise_fingerprint: [0x22; 32],
                    npi1_digest: [0x72; 32],
                    key_record_digest: new_digest,
                    previous_key_record_digest: old_digest,
                    nrt1_digest: [0x73; 32],
                    intent_digest: [0x74; 32],
                    nonce: [0x75; 32],
                    owner_pin_fingerprint: [0xa1; 32],
                    operator_pin_fingerprint: [0xb2; 32],
                })
                .unwrap();
        }

        fn observe_old(&self, store: &IdentityGenerationStateStore) {
            let record = identity_policy::decode(&self.old_record).unwrap();
            store
                .observe_signed_record(&self.old_record, &record, None)
                .unwrap();
        }

        fn advance_d(&self, store: &IdentityGenerationStateStore) {
            let rotation = encode_signed_rotation_statement(
                self.network,
                9001,
                17,
                &self.old_record,
                &self.new_record,
                &self.issuer,
            )
            .unwrap();
            let record = identity_policy::decode(&self.new_record).unwrap();
            store
                .observe_signed_record(&self.new_record, &record, Some(&rotation))
                .unwrap();
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    #[test]
    fn actual_c_anchor_and_d_highwater_reconcile_and_fail_closed_across_restart() {
        let f = Fixture::new();
        {
            let store = f.open_store();
            f.observe_old(&store);
            let mut vault = f.open_vault();
            f.enroll(&mut vault);

            let expected_digest: [u8; 32] = Sha256::digest(&f.old_record).into();
            assert_eq!(
                compare_peer_identity_state(&vault, &store),
                Ok(PeerIdentityReconciliation::Synchronized {
                    generation: 2,
                    record_digest: expected_digest,
                })
            );

            f.prepare(&mut vault);
            assert_eq!(
                compare_peer_identity_state(&vault, &store),
                Ok(PeerIdentityReconciliation::RotationPrepared {
                    active_generation: 2,
                    prepared_generation: 3,
                    active_record_digest: expected_digest,
                })
            );

            f.advance_d(&store);
            assert_eq!(
                compare_peer_identity_state(&vault, &store),
                Err(PeerIdentityReconciliationError::DAdvancedBeforeAnchorActivation)
            );
        }

        // Reopen both stores: the mismatch remains detectable and is never auto-repaired.
        let store = f.open_store();
        let vault = f.open_vault();
        assert_eq!(
            compare_peer_identity_state(&vault, &store),
            Err(PeerIdentityReconciliationError::DAdvancedBeforeAnchorActivation)
        );
    }

    #[test]
    fn c_active_exact_successor_ahead_of_d_is_classified_unverified_across_restart() {
        let f = Fixture::new();
        {
            let store = f.open_store();
            f.observe_old(&store);
            let mut vault = f.open_vault();
            f.enroll(&mut vault);
            f.prepare(&mut vault);
            assert!(vault.latest_rotation_active_binding().is_none());
            vault.activate_prepared([0x75; 32]).unwrap();
            let mut mismatched_predecessor = vault.latest_rotation_active_binding().unwrap();
            mismatched_predecessor.previous_key_record_digest[0] ^= 1;
            assert_eq!(
                compare_bindings_with_rotation(
                    vault.active_record_binding(),
                    store.high_water_binding().unwrap(),
                    None,
                    Some(mismatched_predecessor),
                ),
                Err(PeerIdentityReconciliationError::IdentityGenerationMismatch)
            );
            let old_digest: [u8; 32] = Sha256::digest(&f.old_record).into();
            let new_digest: [u8; 32] = Sha256::digest(&f.new_record).into();

            assert!(matches!(
                compare_peer_identity_state(&vault, &store),
                Err(
                    PeerIdentityReconciliationError::AnchorAheadOfGenerationStoreUnverified {
                        anchor_generation: 3,
                        generation_store_generation: 2,
                        previous_record_digest,
                        successor_record_digest,
                        npi1_digest,
                        nrt1_digest,
                        intent_digest,
                        ..
                    }
                ) if previous_record_digest == old_digest
                    && successor_record_digest == new_digest
                    && npi1_digest == [0x72; 32]
                    && nrt1_digest == [0x73; 32]
                    && intent_digest == [0x74; 32]
            ));
        }

        // The typed quarantine classification survives reopening both persisted stores.
        let store = f.open_store();
        let vault = f.open_vault();
        assert!(matches!(
            compare_peer_identity_state(&vault, &store),
            Err(
                PeerIdentityReconciliationError::AnchorAheadOfGenerationStoreUnverified {
                    anchor_generation: 3,
                    generation_store_generation: 2,
                    npi1_digest,
                    nrt1_digest,
                    intent_digest,
                    ..
                }
            ) if npi1_digest == [0x72; 32]
                && nrt1_digest == [0x73; 32]
                && intent_digest == [0x74; 32]
        ));
    }

    #[test]
    fn actual_persisted_stores_reject_same_generation_record_digest_mismatch() {
        let f = Fixture::new();
        let store = f.open_store();
        f.observe_old(&store);
        let mut vault = f.open_vault();
        f.enroll_binding(&mut vault, [0x99; 32], 1);

        assert_eq!(
            compare_peer_identity_state(&vault, &store),
            Err(PeerIdentityReconciliationError::RecordDigestMismatch)
        );
    }

    #[test]
    fn actual_persisted_stores_reject_same_generation_lifecycle_mismatch() {
        let f = Fixture::new();
        let store = f.open_store();
        f.observe_old(&store);

        let retired_record = identity_policy::encode(&KeyRecord {
            key_id: 700,
            generation: 2,
            algorithm: KeyAlgorithm::NoiseX25519,
            purpose: KeyPurpose::PeerAuth,
            state: KeyState::Retired,
            not_before: 100,
            not_after: 900,
            public_key: vec![0x21; 32],
        })
        .unwrap();
        let decoded_retired = identity_policy::decode(&retired_record).unwrap();
        store
            .observe_signed_record(&retired_record, &decoded_retired, None)
            .unwrap();

        let retired_digest: [u8; 32] = Sha256::digest(&retired_record).into();
        let mut vault = f.open_vault();
        // Keep C-side ACTIVE lifecycle while binding the exact retired D-side digest,
        // isolating the lifecycle comparison itself.
        f.enroll_binding(&mut vault, retired_digest, 1);

        assert_eq!(
            compare_peer_identity_state(&vault, &store),
            Err(PeerIdentityReconciliationError::LifecycleMismatch)
        );
    }
    fn active() -> Binding {
        (7, [0x31; 32], 1)
    }

    #[test]
    fn exact_active_binding_is_synchronized() {
        assert_eq!(
            compare_bindings(Some(active()), Some(active()), None),
            Ok(PeerIdentityReconciliation::Synchronized {
                generation: 7,
                record_digest: [0x31; 32],
            })
        );
    }

    #[test]
    fn exact_prepared_successor_keeps_previous_generation_active() {
        assert_eq!(
            compare_bindings(Some(active()), Some(active()), Some(8)),
            Ok(PeerIdentityReconciliation::RotationPrepared {
                active_generation: 7,
                prepared_generation: 8,
                active_record_digest: [0x31; 32],
            })
        );
    }

    #[test]
    fn missing_anchor_or_uninitialized_d_store_fails_closed() {
        assert_eq!(
            compare_bindings(None, Some(active()), None),
            Err(PeerIdentityReconciliationError::AnchorNotEnrolled)
        );
        assert_eq!(
            compare_bindings(Some(active()), None, None),
            Err(PeerIdentityReconciliationError::GenerationStoreUninitialized)
        );
    }

    #[test]
    fn d_ahead_to_prepared_generation_is_rejected() {
        assert_eq!(
            compare_bindings(Some(active()), Some((8, [0x42; 32], 1)), Some(8)),
            Err(PeerIdentityReconciliationError::DAdvancedBeforeAnchorActivation)
        );
    }

    #[test]
    fn generation_gap_or_unexpected_pending_generation_is_rejected() {
        assert_eq!(
            compare_bindings(Some(active()), Some((9, [0x42; 32], 1)), None),
            Err(PeerIdentityReconciliationError::IdentityGenerationMismatch)
        );
        assert_eq!(
            compare_bindings(Some(active()), Some(active()), Some(9)),
            Err(PeerIdentityReconciliationError::IdentityGenerationMismatch)
        );
    }

    #[test]
    fn same_generation_digest_or_lifecycle_mutation_is_rejected() {
        assert_eq!(
            compare_bindings(Some(active()), Some((7, [0x99; 32], 1)), None),
            Err(PeerIdentityReconciliationError::RecordDigestMismatch)
        );
        assert_eq!(
            compare_bindings(Some(active()), Some((7, [0x31; 32], 2)), None),
            Err(PeerIdentityReconciliationError::LifecycleMismatch)
        );
    }
}
