//! CP-0394 candidate orchestration for PFM5 immutable objects and signed ECR1 anchoring.
//!
//! This module coordinates an independently supplied immutable-object transport with the
//! existing pinned/receipt-verifying External-CAS client. It prepares a deterministic,
//! serializable intent, reads the exact ECR1 predecessor, publishes and reads back every
//! PCP4/PMT4/PFM5 object, and only then attempts the exact ECR1 successor CAS.
//!
//! Ambiguous CAS results are never guessed: a fresh signed read classifies the exact successor,
//! unchanged predecessor (safe same-intent retry), or a competing successor. Callers must persist
//! the encoded intent and their anti-rollback floors outside the provider/local rollback domain.
//!
//! No concrete provider, cloud credentials, provider identity authentication for object storage,
//! live CAS endpoint, runtime wiring or independent-host deployment is implemented here.

use crate::{
    external_cas_anchor_candidate::{
        ExternalCasPin, ExternalCasProviderTransport, ExternalCasReceipt, ExternalCasRecord,
        ExternalCasWriteRequest, VerifiedExternalCasClient,
    },
    private_testnet_checkpoint_candidate::Pcp4ValidationContext,
    private_testnet_pfm5_immutable_object_candidate::{
        Pfm5ImmutableObjectBundle, Pfm5ImmutableObjectClient, Pfm5ImmutableObjectProviderTransport,
        Pfm5ObjectError, Pfm5ObjectPublishReport,
    },
    private_testnet_v4_hybrid_fork_store_candidate::derive_external_cas_genesis_digest,
    v4_fat1_trust_candidate::MlDsa65Verifier as CasMlDsa65Verifier,
};
use sha2::{Digest, Sha256};
use std::fmt;

const INTENT_MAGIC: &[u8; 4] = b"PFI1";
const INTENT_VERSION: u16 = 1;
const WRITE_OPERATION_DOMAIN: &[u8] = b"AIN1-PFM5-ECR1-WRITE-OPERATION-V1\0";
const READ_REQUEST_DOMAIN: &[u8] = b"AIN1-PFM5-ECR1-READ-REQUEST-V1\0";
const WRITE_NONCE_DOMAIN: &[u8] = b"AIN1-PFM5-ECR1-WRITE-NONCE-V1\0";
const INTENT_CHECKSUM_DOMAIN: &[u8] = b"AIN1-PFM5-ECR1-INTENT-CHECKSUM-V1\0";
const INTENT_PAYLOAD_BYTES: usize = 736;
const INTENT_CHECKSUM_BYTES: usize = 32;
pub const PFM5_EXTERNAL_CAS_INTENT_BYTES: usize = INTENT_PAYLOAD_BYTES + INTENT_CHECKSUM_BYTES;

fn digest_parts(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

/// Durable replay input for one PFM5 manifest transition.
///
/// Persist this exact encoding, together with independently protected predecessor and object
/// generation floors, before calling execute_intent. Reconstructing a new intent after an
/// ambiguous reply is not permitted; retry the exact serialized intent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pfm5ExternalCasIntent {
    pub expected_current: ExternalCasRecord,
    pub expected_object_generation: u64,
    pub write_request: ExternalCasWriteRequest,
}

impl Pfm5ExternalCasIntent {
    pub fn prepare(
        pin: &ExternalCasPin,
        context: &Pcp4ValidationContext<'_>,
        expected_current: ExternalCasRecord,
        expected_object_generation: u64,
        bundle: &Pfm5ImmutableObjectBundle,
    ) -> Result<Self, Pfm5ExternalCasError> {
        pin.validate()
            .map_err(|error| Pfm5ExternalCasError::Cas(error.to_string()))?;
        expected_current
            .validate_shape()
            .map_err(|error| Pfm5ExternalCasError::Cas(error.to_string()))?;
        if expected_object_generation == 0 {
            return Err(Pfm5ExternalCasError::InvalidObjectGenerationFloor);
        }
        let ecr_genesis_digest = derive_external_cas_genesis_digest(
            context.trusted_genesis,
            context.params,
            *context.active_transaction_manifest_id,
        )
        .map_err(|error| Pfm5ExternalCasError::GenesisPin(error.to_string()))?;
        if pin.network_id != *context.network_id
            || pin.genesis_digest != ecr_genesis_digest
            || expected_current.provider_id != pin.provider_id
            || expected_current.network_id != pin.network_id
            || expected_current.genesis_digest != pin.genesis_digest
        {
            return Err(Pfm5ExternalCasError::PinMismatch);
        }
        if bundle.manifest().network_id != *context.network_id
            || bundle.manifest().parent_manifest_commitment != expected_current.next_state_digest
        {
            return Err(Pfm5ExternalCasError::ParentManifestMismatch);
        }
        let target_commitment = bundle.manifest_commitment();
        if target_commitment == expected_current.next_state_digest {
            return Err(Pfm5ExternalCasError::NoStateChange);
        }
        let expected_record_digest = expected_current
            .digest()
            .map_err(|error| Pfm5ExternalCasError::Cas(error.to_string()))?;
        let generation = expected_current
            .generation
            .checked_add(1)
            .ok_or(Pfm5ExternalCasError::GenerationOverflow)?;

        let operation_id = digest_parts(&[
            WRITE_OPERATION_DOMAIN,
            &pin.provider_id,
            &pin.network_id,
            &pin.genesis_digest,
            &expected_record_digest,
            &expected_current.next_state_digest,
            &target_commitment,
            &bundle.manifest().generation.to_be_bytes(),
            &bundle.manifest().canonical_tip_height.to_be_bytes(),
            &bundle.manifest().canonical_tip_digest,
            &expected_object_generation.to_be_bytes(),
        ]);
        let request_nonce = digest_parts(&[
            WRITE_NONCE_DOMAIN,
            &operation_id,
            &expected_object_generation.to_be_bytes(),
        ]);
        let next_record = ExternalCasRecord {
            generation,
            provider_id: pin.provider_id,
            network_id: pin.network_id,
            genesis_digest: pin.genesis_digest,
            previous_record_digest: expected_record_digest,
            previous_state_digest: expected_current.next_state_digest,
            next_state_digest: target_commitment,
            operation_id,
            request_digest: [0; 32],
        };
        let mut write_request = ExternalCasWriteRequest {
            request_nonce,
            operation_id,
            request_digest: [0; 32],
            expected_generation: expected_current.generation,
            expected_object_generation,
            expected_record_digest,
            expected_state_digest: expected_current.next_state_digest,
            next_record,
        };
        write_request
            .bind_request_digest(pin)
            .map_err(|error| Pfm5ExternalCasError::Cas(error.to_string()))?;

        let intent = Self {
            expected_current,
            expected_object_generation,
            write_request,
        };
        intent.validate(pin)?;
        Ok(intent)
    }
    pub fn validate(&self, pin: &ExternalCasPin) -> Result<(), Pfm5ExternalCasError> {
        self.expected_current
            .validate_shape()
            .map_err(|error| Pfm5ExternalCasError::Cas(error.to_string()))?;
        self.write_request
            .validate(pin)
            .map_err(|error| Pfm5ExternalCasError::Cas(error.to_string()))?;
        if self.expected_object_generation == 0
            || self.write_request.expected_object_generation != self.expected_object_generation
            || self.write_request.expected_generation != self.expected_current.generation
            || self.write_request.expected_record_digest
                != self
                    .expected_current
                    .digest()
                    .map_err(|error| Pfm5ExternalCasError::Cas(error.to_string()))?
            || self.write_request.expected_state_digest != self.expected_current.next_state_digest
        {
            return Err(Pfm5ExternalCasError::InvalidIntent);
        }
        self.expected_current
            .validate_successor(&self.write_request.next_record)
            .map_err(|error| Pfm5ExternalCasError::Cas(error.to_string()))?;
        if self.write_request.next_record.provider_id != pin.provider_id
            || self.write_request.next_record.network_id != pin.network_id
            || self.write_request.next_record.genesis_digest != pin.genesis_digest
        {
            return Err(Pfm5ExternalCasError::PinMismatch);
        }
        Ok(())
    }

    /// Fixed-width, checksummed encoding suitable for persisting before remote side effects.
    pub fn encode(
        &self,
        pin: &ExternalCasPin,
    ) -> Result<[u8; PFM5_EXTERNAL_CAS_INTENT_BYTES], Pfm5ExternalCasError> {
        self.validate(pin)?;
        let mut bytes = Vec::with_capacity(PFM5_EXTERNAL_CAS_INTENT_BYTES);
        bytes.extend_from_slice(INTENT_MAGIC);
        bytes.extend_from_slice(&INTENT_VERSION.to_be_bytes());
        bytes.extend_from_slice(&0u16.to_be_bytes());
        bytes.extend_from_slice(&self.expected_object_generation.to_be_bytes());
        bytes.extend_from_slice(
            &self
                .expected_current
                .encode()
                .map_err(|error| Pfm5ExternalCasError::Cas(error.to_string()))?,
        );
        bytes.extend_from_slice(&self.write_request.request_nonce);
        bytes.extend_from_slice(&self.write_request.operation_id);
        bytes.extend_from_slice(&self.write_request.request_digest);
        bytes.extend_from_slice(&self.write_request.expected_generation.to_be_bytes());
        bytes.extend_from_slice(&self.write_request.expected_object_generation.to_be_bytes());
        bytes.extend_from_slice(&self.write_request.expected_record_digest);
        bytes.extend_from_slice(&self.write_request.expected_state_digest);
        bytes.extend_from_slice(
            &self
                .write_request
                .next_record
                .encode()
                .map_err(|error| Pfm5ExternalCasError::Cas(error.to_string()))?,
        );
        if bytes.len() != INTENT_PAYLOAD_BYTES {
            return Err(Pfm5ExternalCasError::InvalidIntent);
        }
        let checksum = digest_parts(&[INTENT_CHECKSUM_DOMAIN, &bytes]);
        bytes.extend_from_slice(&checksum);
        bytes
            .try_into()
            .map_err(|_| Pfm5ExternalCasError::InvalidIntent)
    }

    pub fn decode(bytes: &[u8], pin: &ExternalCasPin) -> Result<Self, Pfm5ExternalCasError> {
        if bytes.len() != PFM5_EXTERNAL_CAS_INTENT_BYTES
            || &bytes[..4] != INTENT_MAGIC
            || u16::from_be_bytes([bytes[4], bytes[5]]) != INTENT_VERSION
            || bytes[6..8] != [0, 0]
        {
            return Err(Pfm5ExternalCasError::InvalidIntent);
        }
        let expected_checksum =
            digest_parts(&[INTENT_CHECKSUM_DOMAIN, &bytes[..INTENT_PAYLOAD_BYTES]]);
        if bytes[INTENT_PAYLOAD_BYTES..] != expected_checksum {
            return Err(Pfm5ExternalCasError::IntentChecksumMismatch);
        }
        let expected_object_generation = u64::from_be_bytes(bytes[8..16].try_into().unwrap());
        let expected_current = ExternalCasRecord::decode(&bytes[16..288])
            .map_err(|error| Pfm5ExternalCasError::Cas(error.to_string()))?;
        let request_nonce = bytes[288..320].try_into().unwrap();
        let operation_id = bytes[320..352].try_into().unwrap();
        let request_digest = bytes[352..384].try_into().unwrap();
        let expected_generation = u64::from_be_bytes(bytes[384..392].try_into().unwrap());
        let request_object_generation = u64::from_be_bytes(bytes[392..400].try_into().unwrap());
        let expected_record_digest = bytes[400..432].try_into().unwrap();
        let expected_state_digest = bytes[432..464].try_into().unwrap();
        let next_record = ExternalCasRecord::decode(&bytes[464..736])
            .map_err(|error| Pfm5ExternalCasError::Cas(error.to_string()))?;
        let intent = Self {
            expected_current,
            expected_object_generation,
            write_request: ExternalCasWriteRequest {
                request_nonce,
                operation_id,
                request_digest,
                expected_generation,
                expected_object_generation: request_object_generation,
                expected_record_digest,
                expected_state_digest,
                next_record,
            },
        };
        intent.validate(pin)?;
        Ok(intent)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Pfm5ExternalCasOutcome {
    Committed {
        receipt: ExternalCasReceipt,
        objects: Pfm5ObjectPublishReport,
    },
    AlreadyCommitted {
        object_generation: u64,
        objects: Pfm5ObjectPublishReport,
    },
    CommittedAfterAmbiguousReply {
        object_generation: u64,
        objects: Pfm5ObjectPublishReport,
    },
    RetrySameIntent {
        objects: Pfm5ObjectPublishReport,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Pfm5ExternalCasError {
    Cas(String),
    Objects(Pfm5ObjectError),
    GenesisPin(String),
    PinMismatch,
    ParentManifestMismatch,
    InvalidObjectGenerationFloor,
    InvalidIntent,
    IntentChecksumMismatch,
    GenerationOverflow,
    NoStateChange,
    ConcurrentSuccessor,
    ObjectGenerationChanged {
        expected: u64,
        observed: u64,
    },
    UnresolvedAmbiguousCas {
        commit_error: String,
        read_error: String,
    },
}

impl fmt::Display for Pfm5ExternalCasError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for Pfm5ExternalCasError {}

/// Orchestrate object publication and an exact signed ECR1 successor update.
///
/// Expected record and object-generation floors must come from independently protected durable
/// state. Persist this intent before calling execute_intent so an ambiguous result can be retried
/// with exactly the same operation ID, nonce, and CAS request digest.
pub fn execute_intent<PO, PC, VC>(
    object_client: &mut Pfm5ImmutableObjectClient<PO>,
    cas_client: &mut VerifiedExternalCasClient<PC, VC>,
    pin: &ExternalCasPin,
    context: &Pcp4ValidationContext<'_>,
    intent: &Pfm5ExternalCasIntent,
    bundle: &Pfm5ImmutableObjectBundle,
) -> Result<Pfm5ExternalCasOutcome, Pfm5ExternalCasError>
where
    PO: Pfm5ImmutableObjectProviderTransport,
    PC: ExternalCasProviderTransport,
    VC: CasMlDsa65Verifier,
{
    intent.validate(pin)?;
    let reconstructed = Pfm5ExternalCasIntent::prepare(
        pin,
        context,
        intent.expected_current.clone(),
        intent.expected_object_generation,
        bundle,
    )?;
    if reconstructed != *intent {
        return Err(Pfm5ExternalCasError::InvalidIntent);
    }
    if !cas_client.is_pinned_to(pin) {
        return Err(Pfm5ExternalCasError::PinMismatch);
    }
    let ecr_genesis_digest = derive_external_cas_genesis_digest(
        context.trusted_genesis,
        context.params,
        *context.active_transaction_manifest_id,
    )
    .map_err(|error| Pfm5ExternalCasError::GenesisPin(error.to_string()))?;
    if pin.network_id != *context.network_id
        || pin.genesis_digest != ecr_genesis_digest
        || bundle.manifest().network_id != *context.network_id
        || bundle.manifest().parent_manifest_commitment != intent.expected_current.next_state_digest
        || bundle.manifest_commitment() != intent.write_request.next_record.next_state_digest
    {
        return Err(Pfm5ExternalCasError::ParentManifestMismatch);
    }

    let read_request_digest = digest_parts(&[
        READ_REQUEST_DOMAIN,
        &intent.write_request.operation_id,
        &intent.write_request.request_digest,
        &intent.expected_object_generation.to_be_bytes(),
    ]);
    let read_request = cas_client
        .fresh_read_request(intent.write_request.operation_id, read_request_digest)
        .map_err(|error| Pfm5ExternalCasError::Cas(error.to_string()))?;
    let observed = cas_client
        .read_current(
            &read_request,
            intent.expected_current.generation,
            intent.expected_object_generation,
            Some(&intent.expected_current),
        )
        .map_err(|error| Pfm5ExternalCasError::Cas(error.to_string()))?;

    if observed.record == intent.write_request.next_record {
        if observed.object_generation <= intent.expected_object_generation {
            return Err(Pfm5ExternalCasError::ObjectGenerationChanged {
                expected: intent.expected_object_generation.saturating_add(1),
                observed: observed.object_generation,
            });
        }
        let objects = object_client
            .publish_bundle(bundle, context)
            .map_err(Pfm5ExternalCasError::Objects)?;
        return Ok(Pfm5ExternalCasOutcome::AlreadyCommitted {
            object_generation: observed.object_generation,
            objects,
        });
    }

    if observed.record != intent.expected_current {
        return Err(Pfm5ExternalCasError::ConcurrentSuccessor);
    }
    if observed.object_generation != intent.expected_object_generation {
        return Err(Pfm5ExternalCasError::ObjectGenerationChanged {
            expected: intent.expected_object_generation,
            observed: observed.object_generation,
        });
    }

    let objects = object_client
        .publish_bundle(bundle, context)
        .map_err(Pfm5ExternalCasError::Objects)?;
    if objects.manifest_commitment != intent.write_request.next_record.next_state_digest {
        return Err(Pfm5ExternalCasError::ParentManifestMismatch);
    }

    match cas_client.compare_and_swap(&intent.write_request) {
        Ok(receipt) => Ok(Pfm5ExternalCasOutcome::Committed { receipt, objects }),
        Err(commit_error) => {
            let recovery_request = cas_client
                .fresh_read_request(intent.write_request.operation_id, read_request_digest)
                .map_err(|read_error| Pfm5ExternalCasError::UnresolvedAmbiguousCas {
                    commit_error: commit_error.to_string(),
                    read_error: read_error.to_string(),
                })?;
            let recovered = cas_client
                .read_current(
                    &recovery_request,
                    intent.expected_current.generation,
                    intent.expected_object_generation,
                    Some(&intent.expected_current),
                )
                .map_err(|read_error| Pfm5ExternalCasError::UnresolvedAmbiguousCas {
                    commit_error: commit_error.to_string(),
                    read_error: read_error.to_string(),
                })?;
            if recovered.record == intent.write_request.next_record
                && recovered.object_generation > intent.expected_object_generation
            {
                Ok(Pfm5ExternalCasOutcome::CommittedAfterAmbiguousReply {
                    object_generation: recovered.object_generation,
                    objects,
                })
            } else if recovered.record == intent.expected_current
                && recovered.object_generation == intent.expected_object_generation
            {
                Ok(Pfm5ExternalCasOutcome::RetrySameIntent { objects })
            } else {
                Err(Pfm5ExternalCasError::ConcurrentSuccessor)
            }
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        chain_admission::{
            ReferenceTimeError, ReferenceTimeProvenance, ReferenceTimeProvider, ReferenceTimeSample,
        },
        consensus::{ConsensusParameters, PowHeader, Uint256},
        external_cas_anchor_candidate::{
            ExternalCasReadRequest, ExternalCasReceiptKind, ExternalCasReceiptOutcome,
        },
        private_testnet_checkpoint_candidate::{
            consensus_profile_fingerprint, trusted_genesis_fingerprint, Pcp4CheckpointRecord,
        },
        private_testnet_driver::PrivateTestnetChain,
        private_testnet_monetary_wire::encode_candidate_v4_hybrid_monetary_network_block,
        private_testnet_pfm5_external_cas_coordinator_candidate::{
            execute_ready_intent, resume_prepared_intent, Pfm5ExternalCasCoordinatorError,
        },
        private_testnet_pfm5_external_cas_highwater_candidate::{
            advance_finalized_snapshot, advance_prepared_snapshot,
            authorize_prepared_journal_recovery, verify_ready_snapshot,
            Pfm5ExternalCasHighWaterAdvance, Pfm5ExternalCasHighWaterAuthorityPin,
            Pfm5ExternalCasHighWaterProvider, Pfm5ExternalCasHighWaterState,
        },
        private_testnet_pfm5_external_cas_journal_candidate::{
            Pfm5ExternalCasJournalSnapshot, Pfm5ExternalCasJournalStore,
        },
        private_testnet_pfm5_fork_store_candidate::PrivateTestnetPfm5ForkStoreCandidate,
        private_testnet_pfm5_immutable_object_candidate::{
            Pfm5ImmutableObjectKey, Pfm5ImmutableObjectKind, Pfm5ImmutableObjectProviderTransport,
            Pfm5ImmutablePutOutcome,
        },
        state_machine::{
            MonetaryLedgerState, V4HybridMonetaryBlock, MONETARY_PUBLIC_GOODS_BUDGET_ATOMS,
        },
        v4_fat1_mldsa65_candidate::LibcruxMlDsa65VerifierCandidate,
        v4_fat1_trust_candidate::ML_DSA_65_SIGNATURE_BYTES,
    };
    use libcrux_ml_dsa::ml_dsa_65::portable;
    use std::{
        collections::BTreeMap,
        path::PathBuf,
        sync::{
            atomic::{AtomicBool, AtomicUsize, Ordering},
            Arc, Mutex,
        },
    };

    const NETWORK: [u8; 32] = [0x81; 32];
    const TX_MANIFEST: [u8; 32] = [0x44; 32];
    static NEXT_DIR: AtomicUsize = AtomicUsize::new(1);

    struct TestDirectory(PathBuf);
    impl TestDirectory {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "ain1-pfm5-ecr1-{}-{}",
                std::process::id(),
                NEXT_DIR.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir_all(&path).unwrap();
            Self(path)
        }
        fn path(&self) -> &std::path::Path {
            &self.0
        }
    }
    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    struct FixedClock;
    impl ReferenceTimeProvider for FixedClock {
        fn sample(&self) -> Result<ReferenceTimeSample, ReferenceTimeError> {
            Ok(ReferenceTimeSample {
                unix_seconds: 200,
                provenance: ReferenceTimeProvenance::ConfiguredProvider,
                source_id: "pfm5-ecr1-test-clock",
            })
        }
    }

    struct Fixture {
        network: [u8; 32],
        genesis: MonetaryLedgerState,
        params: ConsensusParameters,
        tx_manifest: [u8; 32],
        checkpoint: Pcp4CheckpointRecord,
    }

    impl Fixture {
        fn new() -> Self {
            let network = NETWORK;
            let genesis = MonetaryLedgerState::genesis(
                network,
                [0x11; 32],
                vec![([0x22; 32], MONETARY_PUBLIC_GOODS_BUDGET_ATOMS as u64)],
            )
            .unwrap();
            let mut params = ConsensusParameters::candidate_testnet().unwrap();
            params.initial_target = Uint256::MAX;
            params.pow_limit = Uint256::MAX;
            params.pow.memory_kib = 8;
            params.pow.iterations = 1;
            params.pow.lanes = 1;
            let tx_manifest = TX_MANIFEST;
            let context = Pcp4ValidationContext {
                network_id: &network,
                trusted_genesis: &genesis,
                params: &params,
                active_transaction_manifest_id: &tx_manifest,
            };
            let chain = PrivateTestnetChain::new_monetary(genesis.clone(), params.clone()).unwrap();
            let state = chain.monetary_state().unwrap();
            let checkpoint = Pcp4CheckpointRecord {
                network_id: network,
                genesis_fingerprint: trusted_genesis_fingerprint(&context).unwrap(),
                consensus_profile_fingerprint: consensus_profile_fingerprint(&params).unwrap(),
                transaction_manifest_id: tx_manifest,
                logical_height: state.height(),
                consensus_tip_digest: chain.chain_tip().tip_hash,
                ledger_tip_hash: state.tip_hash(),
                monetary_state_root: state.state_root(),
                total_mined_atoms: state.total_mined_atoms(),
                cumulative_chainwork: chain.cumulative_work(),
                parent_checkpoint_commitment: [0; 32],
                monetary_snapshot: state.encode_snapshot().unwrap(),
                target_history: chain.target_history().checkpoint_snapshot().unwrap(),
            };
            Self {
                network,
                genesis,
                params,
                tx_manifest,
                checkpoint,
            }
        }

        fn context(&self) -> Pcp4ValidationContext<'_> {
            Pcp4ValidationContext {
                network_id: &self.network,
                trusted_genesis: &self.genesis,
                params: &self.params,
                active_transaction_manifest_id: &self.tx_manifest,
            }
        }
        fn bundle_and_anchor(
            &self,
            verifier: &LibcruxMlDsa65VerifierCandidate,
            key_seed: u8,
        ) -> (Pfm5ImmutableObjectBundle, ExternalCasRecord, ExternalCasPin) {
            let context = self.context();
            let directory = TestDirectory::new();
            let mut store = PrivateTestnetPfm5ForkStoreCandidate::initialize(
                directory.path(),
                self.checkpoint.clone(),
                &context,
                verifier,
            )
            .unwrap();
            let initial_anchor = store.manifest_anchor().unwrap();

            let chain =
                PrivateTestnetChain::new_monetary(self.genesis.clone(), self.params.clone())
                    .unwrap();
            let state = chain.monetary_state().unwrap();
            let mut block = V4HybridMonetaryBlock {
                height: state.height() + 1,
                timestamp: 100 + state.height(),
                parent_hash: state.tip_hash(),
                state_root: [0; 32],
                transactions: Vec::new(),
                miner: [0x33; 32],
                claimed_subsidy_atoms: state.expected_miner_reward().unwrap(),
            };
            block.state_root = state
                .preview_v4_hybrid_state_root_after(&block, &self.tx_manifest, verifier)
                .unwrap();
            let header = PowHeader {
                protocol_version: self.params.protocol_version,
                network_id: self.network,
                height: block.height,
                timestamp: block.timestamp,
                parent_hash: block.parent_hash,
                previous_consensus_hash: chain.chain_tip().tip_hash,
                state_root: block.state_root,
                target: chain.expected_target(None).unwrap(),
                nonce: 0x0102_0304_0506_0708,
            };
            let envelope =
                encode_candidate_v4_hybrid_monetary_network_block(&header, &block).unwrap();
            store
                .submit_local(&envelope, verifier, &FixedClock)
                .unwrap();
            let branches = store
                .archive()
                .archive_envelopes_bounded(
                    crate::private_testnet_v4_hybrid_fork_choice_candidate::MAX_V4_HYBRID_FORK_ARCHIVE_BLOCKS,
                    crate::private_testnet_v4_hybrid_fork_choice_candidate::MAX_V4_HYBRID_FORK_ARCHIVE_BYTES,
                )
                .unwrap();
            let bundle = Pfm5ImmutableObjectBundle::from_parts(
                store.manifest().encode().unwrap(),
                self.checkpoint.encode(&context).unwrap(),
                branches,
                &context,
                store.manifest().generation,
                store.manifest().checkpoint_height,
                verifier,
            )
            .unwrap();

            let key_pair = portable::generate_key_pair([key_seed; 32]);
            let pin = ExternalCasPin {
                provider_id: [0x51; 32],
                network_id: self.network,
                genesis_digest: derive_external_cas_genesis_digest(
                    &self.genesis,
                    &self.params,
                    self.tx_manifest,
                )
                .unwrap(),
                receipt_key_id: [0x61; 32],
                receipt_public_key: *key_pair.verification_key.as_ref(),
            };
            let current = ExternalCasRecord {
                generation: 0,
                provider_id: pin.provider_id,
                network_id: pin.network_id,
                genesis_digest: pin.genesis_digest,
                previous_record_digest: [0; 32],
                previous_state_digest: [0; 32],
                next_state_digest: initial_anchor,
                operation_id: [0x71; 32],
                request_digest: [0x72; 32],
            };
            (bundle, current, pin)
        }
    }

    #[derive(Default)]
    struct MemoryObjectProvider {
        objects: BTreeMap<Vec<u8>, Vec<u8>>,
    }

    #[derive(Debug)]
    struct MemoryObjectError;
    impl fmt::Display for MemoryObjectError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("memory object provider error")
        }
    }
    impl Pfm5ImmutableObjectProviderTransport for MemoryObjectProvider {
        type Error = MemoryObjectError;

        fn put_immutable(
            &mut self,
            key: &[u8],
            bytes: &[u8],
        ) -> Result<Pfm5ImmutablePutOutcome, Self::Error> {
            match self.objects.get(key) {
                Some(_) => Ok(Pfm5ImmutablePutOutcome::AlreadyPresent),
                None => {
                    self.objects.insert(key.to_vec(), bytes.to_vec());
                    Ok(Pfm5ImmutablePutOutcome::Created)
                }
            }
        }

        fn get(&mut self, key: &[u8]) -> Result<Vec<u8>, Self::Error> {
            self.objects.get(key).cloned().ok_or(MemoryObjectError)
        }
    }

    #[derive(Clone)]
    struct CasState {
        current: ExternalCasRecord,
        object_generation: u64,
        force_conflict: bool,
    }

    struct MemoryCasProvider<F> {
        pin: ExternalCasPin,
        state: Arc<Mutex<CasState>>,
        sign: F,
        lose_next_reply: Arc<AtomicBool>,
        cas_calls: Arc<AtomicUsize>,
    }

    fn receipt_for(
        pin: &ExternalCasPin,
        record: &ExternalCasRecord,
        kind: ExternalCasReceiptKind,
        outcome: ExternalCasReceiptOutcome,
        object_generation: u64,
        nonce: [u8; 32],
        operation_id: [u8; 32],
        request_digest: [u8; 32],
    ) -> ExternalCasReceipt {
        ExternalCasReceipt {
            kind,
            outcome,
            generation: record.generation,
            object_generation,
            provider_id: pin.provider_id,
            network_id: pin.network_id,
            genesis_digest: pin.genesis_digest,
            receipt_key_id: pin.receipt_key_id,
            request_nonce: nonce,
            record_digest: record.digest().unwrap(),
            previous_record_digest: record.previous_record_digest,
            previous_state_digest: record.previous_state_digest,
            state_digest: record.next_state_digest,
            operation_id,
            request_digest,
            signature: [0; ML_DSA_65_SIGNATURE_BYTES],
        }
    }
    impl<F> ExternalCasProviderTransport for MemoryCasProvider<F>
    where
        F: Fn(ExternalCasReceipt) -> ExternalCasReceipt,
    {
        type Error = String;

        fn read_current(
            &mut self,
            request: &ExternalCasReadRequest,
        ) -> Result<(ExternalCasRecord, ExternalCasReceipt), Self::Error> {
            let state = self.state.lock().unwrap().clone();
            let receipt = receipt_for(
                &self.pin,
                &state.current,
                ExternalCasReceiptKind::Read,
                ExternalCasReceiptOutcome::Observed,
                state.object_generation,
                request.request_nonce,
                request.operation_id,
                request.request_digest,
            );
            Ok((state.current, (self.sign)(receipt)))
        }

        fn compare_and_swap(
            &mut self,
            request: &ExternalCasWriteRequest,
        ) -> Result<ExternalCasReceipt, Self::Error> {
            request
                .validate(&self.pin)
                .map_err(|error| error.to_string())?;
            self.cas_calls.fetch_add(1, Ordering::SeqCst);
            let mut state = self.state.lock().unwrap();
            let can_apply = state.current.generation == request.expected_generation
                && state.current.digest().map_err(|error| error.to_string())?
                    == request.expected_record_digest
                && state.current.next_state_digest == request.expected_state_digest
                && state.object_generation == request.expected_object_generation
                && !state.force_conflict;
            let outcome = if can_apply {
                state.current = request.next_record.clone();
                state.object_generation = state
                    .object_generation
                    .checked_add(1)
                    .ok_or_else(|| "provider object generation overflow".to_string())?;
                ExternalCasReceiptOutcome::Applied
            } else {
                ExternalCasReceiptOutcome::Conflict
            };
            let receipt = receipt_for(
                &self.pin,
                &state.current,
                ExternalCasReceiptKind::Commit,
                outcome,
                state.object_generation,
                request.request_nonce,
                request.operation_id,
                request.request_digest,
            );
            let signed = (self.sign)(receipt);
            drop(state);
            if self.lose_next_reply.swap(false, Ordering::SeqCst) {
                return Err("simulated lost CAS response after commit".to_string());
            }
            Ok(signed)
        }
    }

    fn signed_cas_provider(
        pin: ExternalCasPin,
        current: ExternalCasRecord,
        key_seed: u8,
        lose_next_reply: bool,
    ) -> (
        MemoryCasProvider<impl Fn(ExternalCasReceipt) -> ExternalCasReceipt>,
        Arc<Mutex<CasState>>,
        Arc<AtomicUsize>,
    ) {
        let key_pair = portable::generate_key_pair([key_seed; 32]);
        let signing_key = key_pair.signing_key;
        let sign = move |mut receipt: ExternalCasReceipt| {
            let digest = receipt.signing_digest().unwrap();
            receipt.signature = *portable::sign(&signing_key, &digest, &[], [0x73; 32])
                .unwrap()
                .as_ref();
            receipt
        };
        let state = Arc::new(Mutex::new(CasState {
            current,
            object_generation: 40,
            force_conflict: false,
        }));
        let calls = Arc::new(AtomicUsize::new(0));
        (
            MemoryCasProvider {
                pin,
                state: state.clone(),
                sign,
                lose_next_reply: Arc::new(AtomicBool::new(lose_next_reply)),
                cas_calls: calls.clone(),
            },
            state,
            calls,
        )
    }

    fn prepare_intent(
        fixture: &Fixture,
        bundle: &Pfm5ImmutableObjectBundle,
        current: ExternalCasRecord,
        pin: &ExternalCasPin,
    ) -> Pfm5ExternalCasIntent {
        Pfm5ExternalCasIntent::prepare(pin, &fixture.context(), current, 40, bundle).unwrap()
    }
    #[test]
    fn intent_is_fixed_width_checksummed_and_reconstructs_exact_request() {
        let fixture = Fixture::new();
        let verifier = LibcruxMlDsa65VerifierCandidate;
        let (bundle, current, pin) = fixture.bundle_and_anchor(&verifier, 0x31);
        let intent = prepare_intent(&fixture, &bundle, current, &pin);
        let encoded = intent.encode(&pin).unwrap();
        assert_eq!(encoded.len(), PFM5_EXTERNAL_CAS_INTENT_BYTES);
        assert_eq!(
            Pfm5ExternalCasIntent::decode(&encoded, &pin).unwrap(),
            intent
        );

        let mut tampered = encoded;
        tampered[400] ^= 0x80;
        assert_eq!(
            Pfm5ExternalCasIntent::decode(&tampered, &pin),
            Err(Pfm5ExternalCasError::IntentChecksumMismatch)
        );
        let mut wrong_pin = pin.clone();
        wrong_pin.provider_id[0] ^= 1;
        assert!(Pfm5ExternalCasIntent::decode(&encoded, &wrong_pin).is_err());
    }

    struct MemoryHighWater(Pfm5ExternalCasHighWaterState);
    impl Pfm5ExternalCasHighWaterProvider for MemoryHighWater {
        type Error = &'static str;
        fn read_authenticated(
            &mut self,
            _authority: &Pfm5ExternalCasHighWaterAuthorityPin,
            _pin: &ExternalCasPin,
        ) -> Result<Pfm5ExternalCasHighWaterState, Self::Error> {
            Ok(self.0.clone())
        }
        fn compare_and_advance(
            &mut self,
            _authority: &Pfm5ExternalCasHighWaterAuthorityPin,
            _pin: &ExternalCasPin,
            expected: &Pfm5ExternalCasHighWaterState,
            next: &Pfm5ExternalCasHighWaterState,
        ) -> Result<(), Self::Error> {
            if self.0 != *expected {
                return Err("high-water compare conflict");
            }
            self.0 = next.clone();
            Ok(())
        }
    }

    struct RefusingAdvanceHighWater {
        state: Pfm5ExternalCasHighWaterState,
        writes: usize,
    }
    impl Pfm5ExternalCasHighWaterProvider for RefusingAdvanceHighWater {
        type Error = &'static str;
        fn read_authenticated(
            &mut self,
            _authority: &Pfm5ExternalCasHighWaterAuthorityPin,
            _pin: &ExternalCasPin,
        ) -> Result<Pfm5ExternalCasHighWaterState, Self::Error> {
            Ok(self.state.clone())
        }
        fn compare_and_advance(
            &mut self,
            _authority: &Pfm5ExternalCasHighWaterAuthorityPin,
            _pin: &ExternalCasPin,
            _expected: &Pfm5ExternalCasHighWaterState,
            _next: &Pfm5ExternalCasHighWaterState,
        ) -> Result<(), Self::Error> {
            self.writes += 1;
            Err("injected High-Water write failure")
        }
    }

    #[test]
    fn coordinator_never_calls_cas_when_prepared_highwater_advance_fails() {
        let fixture = Fixture::new();
        let verifier = LibcruxMlDsa65VerifierCandidate;
        let (bundle, current, pin) = fixture.bundle_and_anchor(&verifier, 0x31);
        let intent = prepare_intent(&fixture, &bundle, current.clone(), &pin);
        let authority = Pfm5ExternalCasHighWaterAuthorityPin {
            authority_id: [0xA3; 32],
        };
        let directory = TestDirectory::new();
        let journal = Pfm5ExternalCasJournalStore::new(directory.path().join("coordinator.pfj1"));
        let ready = journal.initialize(&pin, current.clone(), 40).unwrap();
        let mut highwater = RefusingAdvanceHighWater {
            state: Pfm5ExternalCasHighWaterState::from_snapshot(&authority, &pin, &ready).unwrap(),
            writes: 0,
        };
        let (provider, _remote_state, cas_calls) =
            signed_cas_provider(pin.clone(), current, 0x31, false);
        let mut cas =
            VerifiedExternalCasClient::new(pin.clone(), provider, LibcruxMlDsa65VerifierCandidate)
                .unwrap();
        let mut objects = Pfm5ImmutableObjectClient::new(MemoryObjectProvider::default());

        let result = execute_ready_intent(
            &journal,
            &mut highwater,
            &authority,
            &pin,
            &fixture.context(),
            &intent,
            &bundle,
            &mut objects,
            &mut cas,
            1,
            0,
            40,
        );

        assert!(matches!(
            result,
            Err(Pfm5ExternalCasCoordinatorError::HighWater(_))
        ));
        assert_eq!(highwater.writes, 1);
        assert_eq!(cas_calls.load(Ordering::SeqCst), 0);
        let prepared = journal.load_checked(&pin, 2, 0, 40).unwrap();
        assert_eq!(prepared.pending_intent, Some(intent));
        assert_eq!(prepared.sequence, 2);
    }
    #[test]
    fn coordinator_resumes_same_intent_after_prepared_highwater_write_failure() {
        let fixture = Fixture::new();
        let verifier = LibcruxMlDsa65VerifierCandidate;
        let (bundle, current, pin) = fixture.bundle_and_anchor(&verifier, 0x31);
        let intent = prepare_intent(&fixture, &bundle, current.clone(), &pin);
        let authority = Pfm5ExternalCasHighWaterAuthorityPin {
            authority_id: [0xA5; 32],
        };
        let directory = TestDirectory::new();
        let journal =
            Pfm5ExternalCasJournalStore::new(directory.path().join("coordinator-retry.pfj1"));
        let ready = journal.initialize(&pin, current.clone(), 40).unwrap();
        let ready_state =
            Pfm5ExternalCasHighWaterState::from_snapshot(&authority, &pin, &ready).unwrap();
        let mut refusing = RefusingAdvanceHighWater {
            state: ready_state.clone(),
            writes: 0,
        };
        let (provider, _remote_state, cas_calls) =
            signed_cas_provider(pin.clone(), current, 0x31, false);
        let mut cas =
            VerifiedExternalCasClient::new(pin.clone(), provider, LibcruxMlDsa65VerifierCandidate)
                .unwrap();
        let mut objects = Pfm5ImmutableObjectClient::new(MemoryObjectProvider::default());

        let first = execute_ready_intent(
            &journal,
            &mut refusing,
            &authority,
            &pin,
            &fixture.context(),
            &intent,
            &bundle,
            &mut objects,
            &mut cas,
            1,
            0,
            40,
        );
        assert!(matches!(
            first,
            Err(Pfm5ExternalCasCoordinatorError::HighWater(_))
        ));
        assert_eq!(cas_calls.load(Ordering::SeqCst), 0);
        let prepared = journal.load_checked(&pin, 1, 0, 40).unwrap();
        assert_eq!(prepared.pending_intent, Some(intent.clone()));

        // Restart with the authority still at Ready. Recovery must advance only this exact
        // pending intent, then execute it once; it must not try to stage a replacement.
        let mut recovered_highwater = MemoryHighWater(ready_state);
        let resumed = resume_prepared_intent(
            &journal,
            &mut recovered_highwater,
            &authority,
            &pin,
            &fixture.context(),
            &bundle,
            &mut objects,
            &mut cas,
            1,
            0,
            40,
        )
        .unwrap();
        assert!(matches!(
            resumed,
            crate::private_testnet_pfm5_external_cas_coordinator_candidate::Pfm5ExternalCasCoordinatorOutcome::Finalized { .. }
        ));
        assert_eq!(cas_calls.load(Ordering::SeqCst), 1);
        let finalized = journal.load_checked(&pin, 3, 0, 41).unwrap();
        assert!(finalized.pending_intent.is_none());
        assert_eq!(finalized.last_record, intent.write_request.next_record);
        verify_ready_snapshot(&mut recovered_highwater, &authority, &pin, &finalized).unwrap();
    }

    #[test]
    fn coordinator_recovers_finalized_highwater_without_repeating_cas() {
        let fixture = Fixture::new();
        let verifier = LibcruxMlDsa65VerifierCandidate;
        let (bundle, current, pin) = fixture.bundle_and_anchor(&verifier, 0x31);
        let intent = prepare_intent(&fixture, &bundle, current.clone(), &pin);
        let authority = Pfm5ExternalCasHighWaterAuthorityPin {
            authority_id: [0xA6; 32],
        };
        let directory = TestDirectory::new();
        let journal =
            Pfm5ExternalCasJournalStore::new(directory.path().join("coordinator-recover.pfj1"));
        let ready = journal.initialize(&pin, current.clone(), 40).unwrap();
        let mut highwater = MemoryHighWater(
            Pfm5ExternalCasHighWaterState::from_snapshot(&authority, &pin, &ready).unwrap(),
        );
        let prepared = journal.stage_intent(&pin, &intent, 1, 0, 40).unwrap();
        assert_eq!(
            advance_prepared_snapshot(&mut highwater, &authority, &pin, &prepared).unwrap(),
            Pfm5ExternalCasHighWaterAdvance::Advanced
        );
        let (provider, _remote_state, cas_calls) =
            signed_cas_provider(pin.clone(), current, 0x31, false);
        let mut cas =
            VerifiedExternalCasClient::new(pin.clone(), provider, LibcruxMlDsa65VerifierCandidate)
                .unwrap();
        let mut objects = Pfm5ImmutableObjectClient::new(MemoryObjectProvider::default());

        // Simulate a crash after the remote CAS and independent floor commit, before PFJ1
        // finalization. Restart must authorize the exact one-step stale journal.
        let first = execute_intent(
            &mut objects,
            &mut cas,
            &pin,
            &fixture.context(),
            &intent,
            &bundle,
        )
        .unwrap();
        assert!(matches!(first, Pfm5ExternalCasOutcome::Committed { .. }));
        assert_eq!(cas_calls.load(Ordering::SeqCst), 1);
        let finalization_candidate = Pfm5ExternalCasJournalSnapshot {
            sequence: prepared.sequence + 1,
            last_record: intent.write_request.next_record.clone(),
            object_generation: 41,
            pending_intent: None,
        };
        assert_eq!(
            advance_finalized_snapshot(
                &mut highwater,
                &authority,
                &pin,
                &intent,
                &finalization_candidate,
            )
            .unwrap(),
            Pfm5ExternalCasHighWaterAdvance::Advanced
        );
        assert_eq!(journal.load_checked(&pin, 2, 0, 40).unwrap(), prepared);

        let resumed = resume_prepared_intent(
            &journal,
            &mut highwater,
            &authority,
            &pin,
            &fixture.context(),
            &bundle,
            &mut objects,
            &mut cas,
            1,
            0,
            40,
        )
        .unwrap();
        assert!(matches!(
            resumed,
            crate::private_testnet_pfm5_external_cas_coordinator_candidate::Pfm5ExternalCasCoordinatorOutcome::Finalized {
                highwater: Pfm5ExternalCasHighWaterAdvance::AlreadyAdvanced,
                ..
            }
        ));
        assert_eq!(cas_calls.load(Ordering::SeqCst), 1);
        let finalized = journal.load_checked(&pin, 3, 0, 41).unwrap();
        assert_eq!(finalized.last_record, intent.write_request.next_record);
        assert!(finalized.pending_intent.is_none());
        verify_ready_snapshot(&mut highwater, &authority, &pin, &finalized).unwrap();
    }
    #[test]
    fn coordinator_runs_ordered_ready_to_finalized_transition() {
        let fixture = Fixture::new();
        let verifier = LibcruxMlDsa65VerifierCandidate;
        let (bundle, current, pin) = fixture.bundle_and_anchor(&verifier, 0x31);
        let intent = prepare_intent(&fixture, &bundle, current.clone(), &pin);
        let authority = Pfm5ExternalCasHighWaterAuthorityPin {
            authority_id: [0xA4; 32],
        };
        let directory = TestDirectory::new();
        let journal =
            Pfm5ExternalCasJournalStore::new(directory.path().join("coordinator-success.pfj1"));
        let ready = journal.initialize(&pin, current.clone(), 40).unwrap();
        let mut highwater = MemoryHighWater(
            Pfm5ExternalCasHighWaterState::from_snapshot(&authority, &pin, &ready).unwrap(),
        );
        let (provider, remote_state, cas_calls) =
            signed_cas_provider(pin.clone(), current, 0x31, false);
        let mut cas =
            VerifiedExternalCasClient::new(pin.clone(), provider, LibcruxMlDsa65VerifierCandidate)
                .unwrap();
        let mut objects = Pfm5ImmutableObjectClient::new(MemoryObjectProvider::default());

        let result = execute_ready_intent(
            &journal,
            &mut highwater,
            &authority,
            &pin,
            &fixture.context(),
            &intent,
            &bundle,
            &mut objects,
            &mut cas,
            1,
            0,
            40,
        )
        .unwrap();

        match result {
            crate::private_testnet_pfm5_external_cas_coordinator_candidate::Pfm5ExternalCasCoordinatorOutcome::Finalized {
                snapshot,
                highwater: Pfm5ExternalCasHighWaterAdvance::Advanced,
            } => {
                assert_eq!(snapshot.sequence, 3);
                assert_eq!(snapshot.last_record, intent.write_request.next_record);
                assert_eq!(snapshot.object_generation, 41);
                assert!(!snapshot.is_prepared());
            }
            other => panic!("unexpected coordinator result: {other:?}"),
        }
        assert_eq!(cas_calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            remote_state.lock().unwrap().current,
            intent.write_request.next_record
        );
        verify_ready_snapshot(
            &mut highwater,
            &authority,
            &pin,
            &journal.load_checked(&pin, 3, 0, 41).unwrap(),
        )
        .unwrap();
    }
    #[test]
    fn crash_recovery_reopens_prepared_journal_and_reconciles_real_signed_ecr1_successor() {
        let fixture = Fixture::new();
        let verifier = LibcruxMlDsa65VerifierCandidate;
        let (bundle, current, pin) = fixture.bundle_and_anchor(&verifier, 0x31);
        let intent = prepare_intent(&fixture, &bundle, current.clone(), &pin);

        let authority = Pfm5ExternalCasHighWaterAuthorityPin {
            authority_id: [0xA1; 32],
        };
        let directory = TestDirectory::new();
        let journal_path = directory.path().join("intent.pfj1");
        let journal = Pfm5ExternalCasJournalStore::new(&journal_path);
        let ready = journal.initialize(&pin, current, 40).unwrap();
        let mut highwater = MemoryHighWater(
            Pfm5ExternalCasHighWaterState::from_snapshot(&authority, &pin, &ready).unwrap(),
        );
        verify_ready_snapshot(&mut highwater, &authority, &pin, &ready).unwrap();

        let prepared = journal.stage_intent(&pin, &intent, 1, 0, 40).unwrap();
        assert_eq!(prepared.sequence, 2);
        assert_eq!(
            advance_prepared_snapshot(&mut highwater, &authority, &pin, &prepared).unwrap(),
            Pfm5ExternalCasHighWaterAdvance::Advanced
        );

        let (provider, remote_state, cas_calls) =
            signed_cas_provider(pin.clone(), intent.expected_current.clone(), 0x31, false);
        let mut cas =
            VerifiedExternalCasClient::new(pin.clone(), provider, LibcruxMlDsa65VerifierCandidate)
                .unwrap();
        let mut objects = Pfm5ImmutableObjectClient::new(MemoryObjectProvider::default());

        // First execution commits ECR1. Simulate process loss before PFJ1 mark_committed.
        let first = execute_intent(
            &mut objects,
            &mut cas,
            &pin,
            &fixture.context(),
            &intent,
            &bundle,
        )
        .unwrap();
        assert!(matches!(first, Pfm5ExternalCasOutcome::Committed { .. }));
        assert_eq!(cas_calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            remote_state.lock().unwrap().current,
            intent.write_request.next_record
        );

        // Independent High-Water reaches Finalized, while the durable local file remains Prepared.
        let finalized = Pfm5ExternalCasJournalSnapshot {
            sequence: 3,
            last_record: intent.write_request.next_record.clone(),
            object_generation: 41,
            pending_intent: None,
        };
        assert_eq!(
            advance_finalized_snapshot(&mut highwater, &authority, &pin, &intent, &finalized)
                .unwrap(),
            Pfm5ExternalCasHighWaterAdvance::Advanced
        );

        // Restart: ordinary loading rejects the stale file; authenticated bounded recovery loads
        // only the exact Prepared intent authorized by the independently finalized floor.
        let reopened = Pfm5ExternalCasJournalStore::new(&journal_path);
        assert!(reopened.load_checked(&pin, 3, 0, 40).is_err());
        let authorization =
            authorize_prepared_journal_recovery(&mut highwater, &authority, &pin, &prepared)
                .unwrap();
        let recovered = reopened
            .load_prepared_for_recovery(&pin, authority.authority_id, &authorization)
            .unwrap();
        assert_eq!(recovered, prepared);

        // CP-0394 performs a fresh signed ECR1 read and confirms the exact successor. It must not
        // issue a second CAS; then the local journal can be finalized idempotently.
        let second = execute_intent(
            &mut objects,
            &mut cas,
            &pin,
            &fixture.context(),
            &intent,
            &bundle,
        )
        .unwrap();
        assert!(matches!(
            second,
            Pfm5ExternalCasOutcome::AlreadyCommitted {
                object_generation: 41,
                ..
            }
        ));
        assert_eq!(cas_calls.load(Ordering::SeqCst), 1);
        let local_finalized = reopened
            .mark_committed(
                &pin,
                &intent,
                intent.write_request.next_record.clone(),
                41,
                2,
                0,
                40,
            )
            .unwrap();
        assert_eq!(local_finalized.sequence, 3);
        assert_eq!(local_finalized.last_record, finalized.last_record);
        assert_eq!(local_finalized.object_generation, 41);
        verify_ready_snapshot(&mut highwater, &authority, &pin, &local_finalized).unwrap();
    }

    #[test]
    fn crash_after_local_finalization_reconciles_prepared_highwater_on_restart() {
        let fixture = Fixture::new();
        let verifier = LibcruxMlDsa65VerifierCandidate;
        let (bundle, current, pin) = fixture.bundle_and_anchor(&verifier, 0x31);
        let intent = prepare_intent(&fixture, &bundle, current.clone(), &pin);
        let authority = Pfm5ExternalCasHighWaterAuthorityPin {
            authority_id: [0xA2; 32],
        };
        let directory = TestDirectory::new();
        let journal_path = directory.path().join("intent.pfj1");
        let journal = Pfm5ExternalCasJournalStore::new(&journal_path);
        let ready = journal.initialize(&pin, current, 40).unwrap();
        let mut highwater = MemoryHighWater(
            Pfm5ExternalCasHighWaterState::from_snapshot(&authority, &pin, &ready).unwrap(),
        );
        let prepared = journal.stage_intent(&pin, &intent, 1, 0, 40).unwrap();
        assert_eq!(
            advance_prepared_snapshot(&mut highwater, &authority, &pin, &prepared).unwrap(),
            Pfm5ExternalCasHighWaterAdvance::Advanced
        );

        let (provider, remote_state, cas_calls) =
            signed_cas_provider(pin.clone(), intent.expected_current.clone(), 0x31, false);
        let mut cas =
            VerifiedExternalCasClient::new(pin.clone(), provider, LibcruxMlDsa65VerifierCandidate)
                .unwrap();
        let mut objects = Pfm5ImmutableObjectClient::new(MemoryObjectProvider::default());
        let outcome = execute_intent(
            &mut objects,
            &mut cas,
            &pin,
            &fixture.context(),
            &intent,
            &bundle,
        )
        .unwrap();
        assert!(matches!(outcome, Pfm5ExternalCasOutcome::Committed { .. }));
        assert_eq!(cas_calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            remote_state.lock().unwrap().current,
            intent.write_request.next_record
        );

        // Persist local Finalized first, then simulate a crash before advancing independent High-Water.
        let finalized = Pfm5ExternalCasJournalSnapshot {
            sequence: 3,
            last_record: intent.write_request.next_record.clone(),
            object_generation: 41,
            pending_intent: None,
        };
        let local_finalized = journal
            .mark_committed(&pin, &intent, finalized.last_record.clone(), 41, 2, 0, 40)
            .unwrap();
        assert_eq!(local_finalized, finalized);

        // Restart sees a valid local journal, but it must not be treated as ready against seq-2 floor.
        let reopened = Pfm5ExternalCasJournalStore::new(&journal_path);
        let loaded = reopened.load_checked(&pin, 2, 0, 40).unwrap();
        assert_eq!(loaded, finalized);
        assert!(verify_ready_snapshot(&mut highwater, &authority, &pin, &loaded).is_err());

        // Reconcile only the exact Prepared -> Finalized transition; no second ECR1 CAS is issued.
        assert_eq!(
            advance_finalized_snapshot(&mut highwater, &authority, &pin, &intent, &finalized)
                .unwrap(),
            Pfm5ExternalCasHighWaterAdvance::Advanced
        );
        verify_ready_snapshot(&mut highwater, &authority, &pin, &loaded).unwrap();
        assert_eq!(cas_calls.load(Ordering::SeqCst), 1);
    }
    #[test]
    fn object_readback_precedes_signed_ecr1_commit() {
        let fixture = Fixture::new();
        let verifier = LibcruxMlDsa65VerifierCandidate;
        let (bundle, current, pin) = fixture.bundle_and_anchor(&verifier, 0x31);
        let intent = prepare_intent(&fixture, &bundle, current.clone(), &pin);
        let (provider, state, calls) = signed_cas_provider(pin.clone(), current, 0x31, false);
        let mut cas =
            VerifiedExternalCasClient::new(pin.clone(), provider, LibcruxMlDsa65VerifierCandidate)
                .unwrap();
        let mut objects = Pfm5ImmutableObjectClient::new(MemoryObjectProvider::default());

        let outcome = execute_intent(
            &mut objects,
            &mut cas,
            &pin,
            &fixture.context(),
            &intent,
            &bundle,
        )
        .unwrap();
        match outcome {
            Pfm5ExternalCasOutcome::Committed { receipt, objects } => {
                assert_eq!(receipt.outcome, ExternalCasReceiptOutcome::Applied);
                assert_eq!(receipt.generation, 1);
                assert_eq!(objects.object_count, 3);
            }
            other => panic!("unexpected outcome: {other:?}"),
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        let state = state.lock().unwrap();
        assert_eq!(state.current, intent.write_request.next_record);
        assert_eq!(state.object_generation, 41);
    }

    #[test]
    fn lost_cas_reply_is_resolved_by_fresh_signed_read_as_committed() {
        let fixture = Fixture::new();
        let verifier = LibcruxMlDsa65VerifierCandidate;
        let (bundle, current, pin) = fixture.bundle_and_anchor(&verifier, 0x31);
        let intent = prepare_intent(&fixture, &bundle, current.clone(), &pin);
        let (provider, state, calls) = signed_cas_provider(pin.clone(), current, 0x31, true);
        let mut cas =
            VerifiedExternalCasClient::new(pin.clone(), provider, LibcruxMlDsa65VerifierCandidate)
                .unwrap();
        let mut objects = Pfm5ImmutableObjectClient::new(MemoryObjectProvider::default());

        let outcome = execute_intent(
            &mut objects,
            &mut cas,
            &pin,
            &fixture.context(),
            &intent,
            &bundle,
        )
        .unwrap();
        assert!(matches!(
            outcome,
            Pfm5ExternalCasOutcome::CommittedAfterAmbiguousReply {
                object_generation: 41,
                ..
            }
        ));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            state.lock().unwrap().current,
            intent.write_request.next_record
        );
    }
    #[test]
    fn signed_conflict_with_unchanged_predecessor_retries_only_the_same_intent() {
        let fixture = Fixture::new();
        let verifier = LibcruxMlDsa65VerifierCandidate;
        let (bundle, current, pin) = fixture.bundle_and_anchor(&verifier, 0x31);
        let intent = prepare_intent(&fixture, &bundle, current.clone(), &pin);
        let (provider, state, calls) =
            signed_cas_provider(pin.clone(), current.clone(), 0x31, false);
        state.lock().unwrap().force_conflict = true;
        let mut cas =
            VerifiedExternalCasClient::new(pin.clone(), provider, LibcruxMlDsa65VerifierCandidate)
                .unwrap();
        let mut objects = Pfm5ImmutableObjectClient::new(MemoryObjectProvider::default());

        let first = execute_intent(
            &mut objects,
            &mut cas,
            &pin,
            &fixture.context(),
            &intent,
            &bundle,
        )
        .unwrap();
        assert!(matches!(
            first,
            Pfm5ExternalCasOutcome::RetrySameIntent { .. }
        ));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        {
            let remote = state.lock().unwrap();
            assert_eq!(remote.current, current);
            assert_eq!(remote.object_generation, 40);
        }

        // The retry reuses the same persisted intent; the immutable objects are idempotent.
        state.lock().unwrap().force_conflict = false;
        let second = execute_intent(
            &mut objects,
            &mut cas,
            &pin,
            &fixture.context(),
            &intent,
            &bundle,
        )
        .unwrap();
        assert!(matches!(second, Pfm5ExternalCasOutcome::Committed { .. }));
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(
            state.lock().unwrap().current,
            intent.write_request.next_record
        );
    }

    #[test]
    fn competing_signed_successor_is_not_overwritten_or_uploaded() {
        let fixture = Fixture::new();
        let verifier = LibcruxMlDsa65VerifierCandidate;
        let (bundle, current, pin) = fixture.bundle_and_anchor(&verifier, 0x31);
        let intent = prepare_intent(&fixture, &bundle, current.clone(), &pin);
        let (provider, state, calls) =
            signed_cas_provider(pin.clone(), current.clone(), 0x31, false);
        {
            let mut remote = state.lock().unwrap();
            remote.current = ExternalCasRecord {
                generation: current.generation + 1,
                provider_id: pin.provider_id,
                network_id: pin.network_id,
                genesis_digest: pin.genesis_digest,
                previous_record_digest: current.digest().unwrap(),
                previous_state_digest: current.next_state_digest,
                next_state_digest: [0xA9; 32],
                operation_id: [0xAA; 32],
                request_digest: [0xAB; 32],
            };
            remote.object_generation = 41;
        }
        let mut cas =
            VerifiedExternalCasClient::new(pin.clone(), provider, LibcruxMlDsa65VerifierCandidate)
                .unwrap();
        let mut objects = Pfm5ImmutableObjectClient::new(MemoryObjectProvider::default());
        assert_eq!(
            execute_intent(
                &mut objects,
                &mut cas,
                &pin,
                &fixture.context(),
                &intent,
                &bundle
            ),
            Err(Pfm5ExternalCasError::ConcurrentSuccessor)
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert!(objects.into_inner().objects.is_empty());
    }

    #[test]
    fn immutable_object_conflict_prevents_any_ecr1_cas_call() {
        let fixture = Fixture::new();
        let verifier = LibcruxMlDsa65VerifierCandidate;
        let (bundle, current, pin) = fixture.bundle_and_anchor(&verifier, 0x31);
        let intent = prepare_intent(&fixture, &bundle, current.clone(), &pin);
        let (provider, _, calls) = signed_cas_provider(pin.clone(), current, 0x31, false);
        let mut cas =
            VerifiedExternalCasClient::new(pin.clone(), provider, LibcruxMlDsa65VerifierCandidate)
                .unwrap();
        let first_key = Pfm5ImmutableObjectKey {
            kind: Pfm5ImmutableObjectKind::Checkpoint,
            network_id: bundle.manifest().network_id,
            genesis_fingerprint: bundle.manifest().genesis_fingerprint,
            digest: bundle.manifest().checkpoint_record_commitment,
        };
        let encoded_key = first_key.encode().unwrap();
        let mut object_provider = MemoryObjectProvider::default();
        object_provider
            .objects
            .insert(encoded_key, b"conflicting old bytes".to_vec());
        let mut objects = Pfm5ImmutableObjectClient::new(object_provider);

        assert_eq!(
            execute_intent(
                &mut objects,
                &mut cas,
                &pin,
                &fixture.context(),
                &intent,
                &bundle
            ),
            Err(Pfm5ExternalCasError::Objects(
                Pfm5ObjectError::ReadbackMismatch
            ))
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn exact_previously_committed_successor_is_idempotently_verified() {
        let fixture = Fixture::new();
        let verifier = LibcruxMlDsa65VerifierCandidate;
        let (bundle, current, pin) = fixture.bundle_and_anchor(&verifier, 0x31);
        let intent = prepare_intent(&fixture, &bundle, current.clone(), &pin);
        let (provider, state, calls) = signed_cas_provider(pin.clone(), current, 0x31, false);
        {
            let mut remote = state.lock().unwrap();
            remote.current = intent.write_request.next_record.clone();
            remote.object_generation = 41;
        }
        let mut cas =
            VerifiedExternalCasClient::new(pin.clone(), provider, LibcruxMlDsa65VerifierCandidate)
                .unwrap();
        let mut objects = Pfm5ImmutableObjectClient::new(MemoryObjectProvider::default());

        let outcome = execute_intent(
            &mut objects,
            &mut cas,
            &pin,
            &fixture.context(),
            &intent,
            &bundle,
        )
        .unwrap();
        assert!(matches!(
            outcome,
            Pfm5ExternalCasOutcome::AlreadyCommitted {
                object_generation: 41,
                ..
            }
        ));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(objects.into_inner().objects.len(), 3);
    }

    #[test]
    fn genesis_pin_and_parent_manifest_are_checked_before_provider_calls() {
        let fixture = Fixture::new();
        let verifier = LibcruxMlDsa65VerifierCandidate;
        let (bundle, current, pin) = fixture.bundle_and_anchor(&verifier, 0x31);
        let mut wrong_pin = pin.clone();
        wrong_pin.genesis_digest[0] ^= 1;
        assert!(matches!(
            Pfm5ExternalCasIntent::prepare(
                &wrong_pin,
                &fixture.context(),
                current.clone(),
                40,
                &bundle
            ),
            Err(Pfm5ExternalCasError::PinMismatch)
        ));

        let mut wrong_parent = current;
        wrong_parent.next_state_digest[0] ^= 1;
        assert!(matches!(
            Pfm5ExternalCasIntent::prepare(&pin, &fixture.context(), wrong_parent, 40, &bundle),
            Err(Pfm5ExternalCasError::ParentManifestMismatch)
        ));
    }
}
