//! QRun v0.5 candidate PoW integration node for local-testnet and experimental public-alpha.
//!
//! This executable integrates the Genesis-bound candidate runtime with QZXB wallet TXN2/QZTS/1
//! and read-only HTTP RPC. Local-testnet uses a deliberately trivial smoke target and is loopback-only.
//! Public-alpha permits a public P2P listener, but is experimental and is not Mainnet. The `--mainnet`
//! path has additional P2P/identity guards and a source-level release gate that MUST remain closed
//! until production consensus, full-history recovery and adversarial multi-host operations are proven.
//! This binary is not a production-certified public-network release.
use ai_native_l1_pow_bench::chain_admission::{
    ReferenceTimeError, ReferenceTimeProvenance, ReferenceTimeProvider, ReferenceTimeSample,
    SystemClockReferenceTime,
};
use ai_native_l1_pow_bench::consensus::{ConsensusParameters, PowAlgorithm, Uint256};
use ai_native_l1_pow_bench::external_cas_anchor_candidate::{
    ExternalCasPin, ExternalCasRecord, VerifiedExternalCasClient, EXTERNAL_CAS_RECORD_BYTES,
};
use ai_native_l1_pow_bench::external_cas_floor_store_candidate::{
    ExternalCasFloorError, ExternalCasFloorStore,
};
use ai_native_l1_pow_bench::external_cas_noise_transport_candidate::NoiseTcpExternalCasProviderTransport;
use ai_native_l1_pow_bench::external_cas_offhost_anchor_node_lifecycle_candidate::OffhostAnchorNodeServiceOwner;
use ai_native_l1_pow_bench::external_cas_offhost_anchor_noise_daemon_candidate::OffhostAnchorNoiseDaemonTask;
use ai_native_l1_pow_bench::noise_key_provisioning::load_protected_noise_private_key;
use ai_native_l1_pow_bench::private_testnet_fork_choice::ForkChoiceOutcome;
use ai_native_l1_pow_bench::private_testnet_fork_store::{
    qrun_v05_genesis_checkpoint_parent_commitment, ForkStoreError, PrivateTestnetForkStore,
    QRunV05ExternalCasForkStore,
};
use ai_native_l1_pow_bench::private_testnet_wire::decode_candidate_network_block;
use ai_native_l1_pow_bench::qrun_node_shutdown_signal_candidate::QRunNodeShutdownSignalCandidate;
use ai_native_l1_pow_bench::qrun_v05_checkpoint_migration_recovery_candidate::recover_qrun_v05_checkpoint_migration;
use ai_native_l1_pow_bench::qrun_v05_genesis_candidate::QRunGenesisV05;
use ai_native_l1_pow_bench::qrun_v05_noise_transport_candidate::{
    QRunV05NoiseSession, MAX_NOISE_APPLICATION_RECORD_BYTES,
};
use ai_native_l1_pow_bench::qrun_v05_pow_fork_runtime_candidate::{
    QRunV05PowForkRuntime, QRunV05PowRuntimeError, QRunV05RuntimeStore,
};
use ai_native_l1_pow_bench::qzbe_tx_ingress_candidate::{
    decode_request_header, encode_ack, TxIngressAck, TxIngressStatus, ACK_BYTES,
    REQUEST_HEADER_BYTES,
};
use ai_native_l1_pow_bench::reference_time::{
    AuthenticatedReferenceTimeProvider, VerifiedReferenceTimePolicy, POLICY_WIRE_LEN,
};
use ai_native_l1_pow_bench::reference_time_store::ReferenceTimeStateStore;
use ai_native_l1_pow_bench::reference_time_tcp::TcpReferenceTimeExchange;
use ai_native_l1_pow_bench::state_machine::{
    decode_transaction, transaction_id, AccountId, NetworkId, MAX_TRANSACTIONS_PER_BLOCK,
    MAX_TRANSACTION_BYTES,
};
use ai_native_l1_pow_bench::state_machine::{LedgerState, TransactionAuthenticator};
use ai_native_l1_pow_bench::transaction_auth::{
    account_id_from_public_key, AccountPublicKey, Ed25519TransactionAuthenticator,
    TransactionAuthenticatorKind,
};
use ai_native_l1_pow_bench::v4_fat1_mldsa65_candidate::LibcruxMlDsa65VerifierCandidate;
use ed25519_dalek::VerifyingKey;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::Duration;
#[cfg(test)]
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_HTTP_REQUEST: usize = 4096;
const MAX_HTTP_RESPONSE: usize = 16 * 1024;
const PROFILE_DOMAIN: &[u8] = b"QUANTUMZXB-QRUN-V05-CONSENSUS-PROFILE\0";
const BLOCK_MAGIC: &[u8; 4] = b"QRB5";
const BLOCK_ACK_MAGIC: &[u8; 4] = b"QRA5";
const BLOCK_PROTOCOL_VERSION: u16 = 2;
const BLOCK_FRAME_HEADER_BYTES: usize = 10;
const BLOCK_ACK_BYTES: usize = 47;
const MAX_BLOCK_FRAME_BYTES: usize = 8 * 1024 * 1024;
const SYNC_REQUEST_MAGIC: &[u8; 4] = b"QRS5";
const SYNC_RESPONSE_MAGIC: &[u8; 4] = b"QRR5";
const SYNC_PROTOCOL_VERSION: u16 = 2;
const SYNC_REQUEST_BYTES: usize = 61;
const SYNC_RESPONSE_HEADER_BYTES: usize = 120;
const MAX_SYNC_PAGE_BLOCKS: usize = 16;
// Refresh the authenticated timestamp every bounded Argon2id nonce slice. This keeps a
// successfully mined header comfortably inside the 300-second live-admission past window.
const PUBLIC_ALPHA_POW_NONCE_SLICE_ATTEMPTS: u64 = 16;

// Fixed wallet-bound Genesis identity for the first QZXB Mainnet.
const QZXB_MAINNET_NETWORK_ID: NetworkId = [
    0x8b, 0x5d, 0x16, 0x92, 0x05, 0xac, 0x49, 0xcb, 0x98, 0x66, 0xa9, 0xd2, 0x7f, 0xf1, 0xa6, 0xc3,
    0xc2, 0x57, 0x1f, 0xca, 0x65, 0xf6, 0x34, 0x85, 0x4c, 0x41, 0xc1, 0x12, 0xe5, 0x06, 0xae, 0xbb,
];
const QZXB_MAINNET_OWNER_ACCOUNT_ID: AccountId = [
    0xa1, 0x4d, 0x67, 0xbd, 0x19, 0x5c, 0x6a, 0x00, 0x44, 0xbe, 0xda, 0xc8, 0x53, 0x2e, 0x74, 0x28,
    0x11, 0xf9, 0x25, 0x01, 0x63, 0x07, 0x64, 0xd7, 0x3a, 0x98, 0xb2, 0xf0, 0xcc, 0x33, 0x5f, 0xdd,
];
const QZXB_MAINNET_OWNER_PUBLIC_KEY: [u8; 32] = [
    0xfc, 0xa6, 0x5e, 0x26, 0xf5, 0x96, 0xfa, 0x60, 0x67, 0x4f, 0x5e, 0xc3, 0x58, 0x08, 0xec, 0x80,
    0xb3, 0x17, 0xa7, 0x01, 0xe9, 0x7f, 0xee, 0xe3, 0x43, 0xd8, 0x50, 0x07, 0x71, 0x3b, 0xd9, 0x3f,
];
const QZXB_MAINNET_GENESIS_ID_HEX: &str =
    "91229b7d21b23cee83f00cec53a566ef1b30db70c644c1e9d05a431c1acf4dbc";
const QZXB_MAINNET_PROFILE_ID_HEX: &str =
    "75596fa188dc308088efc6b138e9fcd50be6de82ec2bc117c13e81d7eebfdb09";
const QZXB_MAINNET_STATE_ROOT_HEX: &str =
    "a44e545c2cd8fa4e56e228f4f242cbf5445b1cc983c7b1f8fe89c5b42aef88d7";

// Keep production activation disabled until concrete protocol/operations gates have evidence.
// Exchange listings, a minimum operator count, and the availability of a third-party auditor are
// not permission gates for publishing a permissionless protocol; CP-0443 keeps those as disclosed
// evidence/recruitment work. This is intentionally not a CLI flag: an operator must not bypass
// unfinished consensus, history/recovery, peer-network, or transaction-safety guarantees.
const QRUN_MAINNET_RELEASE_APPROVED: bool = false;
const QRUN_MAINNET_RELEASE_BLOCKERS: &[&str] = &[
    "production consensus profile and difficulty/retarget policy are not frozen and reproducibly validated",
    "full-history validation/recovery and safe checkpoint rollover/rebase are not integrated",
    "multi-host restart/reorg/partition/transaction-relay and independently queried receipt/balance behavior are incomplete",
    "external Mainnet P2P reachability, authenticated bootstrap, and monitored recovery have not been verified",
];

#[derive(Clone)]
struct Receipt {
    height: u64,
}

type ExternalCasNodeStore = QRunV05ExternalCasForkStore<
    NoiseTcpExternalCasProviderTransport,
    LibcruxMlDsa65VerifierCandidate,
>;

/// Runtime storage adapter. Every node operation still goes through the same validated
/// QRunV05PowForkRuntime; only the durable commit backend differs.
enum NodeForkStore {
    Local(PrivateTestnetForkStore),
    ExternalCas(ExternalCasNodeStore),
}

impl QRunV05RuntimeStore for NodeForkStore {
    fn archive(
        &self,
    ) -> &ai_native_l1_pow_bench::private_testnet_fork_choice::PrivateTestnetForkChoice {
        match self {
            Self::Local(store) => store.archive(),
            Self::ExternalCas(store) => store.archive(),
        }
    }

    fn genesis_state(&self) -> &LedgerState {
        match self {
            Self::Local(store) => store.genesis_state(),
            Self::ExternalCas(store) => store.genesis_state(),
        }
    }

    fn is_qrun_v05_fee_only(&self) -> bool {
        match self {
            Self::Local(store) => store.is_qrun_v05_fee_only(),
            Self::ExternalCas(store) => store.is_qrun_v05_fee_only(),
        }
    }

    fn matches_qrun_v05_genesis_and_profile(
        &self,
        genesis: &LedgerState,
        params: &ConsensusParameters,
    ) -> bool {
        match self {
            Self::Local(store) => store.matches_qrun_v05_genesis_and_profile(genesis, params),
            Self::ExternalCas(store) => store.matches_qrun_v05_genesis_and_profile(genesis, params),
        }
    }

    fn canonical_height(&self) -> u64 {
        match self {
            Self::Local(store) => store.canonical_height(),
            Self::ExternalCas(store) => store.canonical_height(),
        }
    }

    fn canonical_tip(&self) -> [u8; 32] {
        match self {
            Self::Local(store) => store.canonical_tip(),
            Self::ExternalCas(store) => store.archive().canonical_chain().chain_tip().tip_hash,
        }
    }

    fn manifest_anchor(&self) -> Result<[u8; 32], ForkStoreError> {
        match self {
            Self::Local(store) => store.manifest_anchor(),
            Self::ExternalCas(store) => store.manifest_anchor(),
        }
    }

    fn submit<A: TransactionAuthenticator>(
        &mut self,
        envelope: &[u8],
        authenticator: &A,
        clock: &dyn ai_native_l1_pow_bench::chain_admission::ReferenceTimeProvider,
    ) -> Result<ForkChoiceOutcome, ForkStoreError> {
        match self {
            Self::Local(store) => store.submit(envelope, authenticator, clock),
            Self::ExternalCas(store) => store.submit(envelope, authenticator, clock),
        }
    }

    fn submit_historical<A: TransactionAuthenticator>(
        &mut self,
        envelope: &[u8],
        authenticator: &A,
        clock: &dyn ai_native_l1_pow_bench::chain_admission::ReferenceTimeProvider,
    ) -> Result<ForkChoiceOutcome, ForkStoreError> {
        match self {
            Self::Local(store) => store.submit_historical(envelope, authenticator, clock),
            Self::ExternalCas(store) => store.submit_historical(envelope, authenticator, clock),
        }
    }
}

type NodeRuntime = QRunV05PowForkRuntime<NodeForkStore>;

fn read_exact_regular_file(
    path: &std::path::Path,
    expected_len: usize,
    label: &str,
) -> Result<Vec<u8>, String> {
    let metadata =
        fs::symlink_metadata(path).map_err(|error| format!("inspect {label}: {error}"))?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() != expected_len as u64
    {
        return Err(format!(
            "{label} must be a regular non-symlink file of exactly {expected_len} bytes"
        ));
    }
    let bytes = fs::read(path).map_err(|error| format!("read {label}: {error}"))?;
    if bytes.len() != expected_len {
        return Err(format!("{label} changed size while being read"));
    }
    Ok(bytes)
}

fn read_bounded_regular_file(
    path: &std::path::Path,
    maximum_len: usize,
    label: &str,
) -> Result<Vec<u8>, String> {
    let metadata =
        fs::symlink_metadata(path).map_err(|error| format!("inspect {label}: {error}"))?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() == 0
        || metadata.len() > maximum_len as u64
    {
        return Err(format!(
            "{label} must be a regular non-symlink file between 1 and {maximum_len} bytes"
        ));
    }
    let bytes = fs::read(path).map_err(|error| format!("read {label}: {error}"))?;
    if bytes.len() as u64 != metadata.len() || bytes.len() > maximum_len {
        return Err(format!("{label} changed size while being read"));
    }
    Ok(bytes)
}

fn open_verified_external_cas_client(
    external: &ExternalCasNodeConfig,
    network_id: &NetworkId,
    pin: ExternalCasPin,
) -> Result<
    VerifiedExternalCasClient<
        NoiseTcpExternalCasProviderTransport,
        LibcruxMlDsa65VerifierCandidate,
    >,
    String,
> {
    let mut local_noise_private_key =
        load_protected_noise_private_key(&external.noise_private_key_file, network_id).map_err(
            |error| format!("load DPAPI-protected external-CAS Noise client key: {error}"),
        )?;
    let transport_result = NoiseTcpExternalCasProviderTransport::new(
        external.endpoint,
        local_noise_private_key,
        external.noise_server_static_public_key,
        pin.clone(),
    );
    local_noise_private_key.fill(0);
    let transport = transport_result
        .map_err(|error| format!("configure pinned external-CAS Noise/TCP transport: {error:?}"))?;
    VerifiedExternalCasClient::new(pin, transport, LibcruxMlDsa65VerifierCandidate)
        .map_err(|error| format!("configure verified external-CAS client: {error:?}"))
}

#[cfg(test)]
fn open_local_node_runtime<A: TransactionAuthenticator>(
    directory: &std::path::Path,
    network_id: NetworkId,
    owner_account: AccountId,
    params: ConsensusParameters,
    authenticator: &A,
    clock: &dyn ai_native_l1_pow_bench::chain_admission::ReferenceTimeProvider,
) -> Result<NodeRuntime, String> {
    open_node_runtime(
        directory,
        network_id,
        owner_account,
        params,
        authenticator,
        clock,
        None,
    )
}

#[cfg(test)]
fn open_node_runtime<A: TransactionAuthenticator>(
    directory: &std::path::Path,
    network_id: NetworkId,
    owner_account: AccountId,
    params: ConsensusParameters,
    authenticator: &A,
    clock: &dyn ai_native_l1_pow_bench::chain_admission::ReferenceTimeProvider,
    external_config: Option<&ExternalCasNodeConfig>,
) -> Result<NodeRuntime, String> {
    open_node_runtime_with_genesis_timestamp(
        directory,
        network_id,
        owner_account,
        params,
        authenticator,
        clock,
        None,
        external_config,
    )
}

fn open_node_runtime_with_genesis_timestamp<A: TransactionAuthenticator>(
    directory: &std::path::Path,
    network_id: NetworkId,
    owner_account: AccountId,
    params: ConsensusParameters,
    authenticator: &A,
    clock: &dyn ai_native_l1_pow_bench::chain_admission::ReferenceTimeProvider,
    genesis_timestamp: Option<u64>,
    external_config: Option<&ExternalCasNodeConfig>,
) -> Result<NodeRuntime, String> {
    let genesis = match genesis_timestamp {
        Some(timestamp) => {
            QRunGenesisV05::new_with_genesis_timestamp(network_id, owner_account, timestamp)
        }
        None => QRunGenesisV05::new(network_id, owner_account),
    }
    .map_err(|error| format!("construct wallet-bound QRun Genesis: {error:?}"))?;

    let Some(external) = external_config else {
        let runtime = match genesis_timestamp {
            Some(timestamp) => QRunV05PowForkRuntime::open_with_genesis_timestamp(
                directory,
                network_id,
                owner_account,
                params.clone(),
                authenticator,
                clock,
                timestamp,
            ),
            None => QRunV05PowForkRuntime::open(
                directory,
                network_id,
                owner_account,
                params.clone(),
                authenticator,
                clock,
            ),
        }
        .map_err(|error| format!("open local QRun runtime backend: {error:?}"))?;
        return QRunV05PowForkRuntime::from_store_with_genesis(
            network_id,
            owner_account,
            params,
            NodeForkStore::Local(runtime.into_store()),
            genesis,
        )
        .map_err(|error| format!("bind local QRun runtime backend: {error:?}"));
    };

    if params.protocol_version != 5 {
        return Err("external-CAS backend is supported only for the QFP5 fee-only profile".into());
    }
    if genesis.commitment() != external.genesis_commitment {
        return Err("external-CAS Genesis pin differs from the node's wallet-bound Genesis".into());
    }

    // Validate the first-checkpoint parent before reading bootstrap material, initializing QCF1,
    // opening a Noise/TCP session, touching the PFS2 store or contacting the provider. The Store
    // executor repeats this check after opening to protect callers that use the API directly.
    if external.migrate_genesis_checkpoint {
        let expected_parent = qrun_v05_genesis_checkpoint_parent_commitment(
            network_id,
            genesis.commitment(),
            genesis.ledger(),
            &params,
        )
        .map_err(|error| format!("derive deterministic Genesis QRCP parent commitment: {error}"))?;
        if external.checkpoint_parent_commitment != Some(expected_parent) {
            return Err(format!(
                "Genesis checkpoint parent commitment mismatch; expected {}",
                hex(&expected_parent)
            ));
        }
    }

    // Authenticate the exact checkpoint and its parent before initializing the independent floor,
    // opening local storage, or making any provider request.
    let mut checkpoint_bytes = if let Some(checkpoint) = &external.checkpoint {
        let bytes = read_bounded_regular_file(
            &checkpoint.record_file,
            ai_native_l1_pow_bench::qrun_v05_checkpoint_candidate::MAX_QRCP_BYTES,
            "external-CAS QRCP checkpoint",
        )?;
        ai_native_l1_pow_bench::qrun_v05_checkpoint_candidate::QRunV05PowCheckpoint::decode_anchored_with_parent(
            &bytes,
            &network_id,
            &external.genesis_commitment,
            &params,
            checkpoint.expected_commitment,
            checkpoint.minimum_height,
            checkpoint.expected_parent_commitment,
        )
        .map_err(|error| format!("validate independently anchored QRCP checkpoint: {error}"))?;
        Some(bytes)
    } else {
        None
    };

    let mut checkpoint_commitment = external
        .checkpoint
        .as_ref()
        .map(|checkpoint| checkpoint.expected_commitment);
    let mut checkpoint_minimum_height = external
        .checkpoint
        .as_ref()
        .map(|checkpoint| checkpoint.minimum_height);
    let mut checkpoint_parent_commitment = external
        .checkpoint
        .as_ref()
        .map(|checkpoint| checkpoint.expected_parent_commitment);

    let receipt_key_bytes = read_exact_regular_file(
        &external.receipt_public_key_file,
        ai_native_l1_pow_bench::v4_fat1_trust_candidate::ML_DSA_65_PUBLIC_KEY_BYTES,
        "external-CAS ML-DSA-65 receipt public key",
    )?;
    let mut receipt_public_key =
        [0u8; ai_native_l1_pow_bench::v4_fat1_trust_candidate::ML_DSA_65_PUBLIC_KEY_BYTES];
    receipt_public_key.copy_from_slice(&receipt_key_bytes);
    if receipt_public_key.iter().all(|byte| *byte == 0) {
        return Err("external-CAS ML-DSA-65 receipt public key must be nonzero".into());
    }
    let pin = ExternalCasPin {
        provider_id: external.provider_id,
        network_id,
        genesis_digest: external.genesis_commitment,
        receipt_key_id: external.receipt_key_id,
        receipt_public_key,
    };
    pin.validate()
        .map_err(|error| format!("validate external-CAS provider pin: {error:?}"))?;

    let bootstrap_bytes = read_exact_regular_file(
        &external.bootstrap_record_file,
        EXTERNAL_CAS_RECORD_BYTES,
        "external-CAS ECR1 bootstrap record",
    )?;
    let bootstrap = ExternalCasRecord::decode(&bootstrap_bytes)
        .map_err(|error| format!("decode external-CAS ECR1 bootstrap: {error:?}"))?;
    if bootstrap.generation != 0
        || bootstrap.provider_id != pin.provider_id
        || bootstrap.network_id != pin.network_id
        || bootstrap.genesis_digest != pin.genesis_digest
    {
        return Err(
            "external-CAS bootstrap record does not match the pinned provider/network/Genesis"
                .into(),
        );
    }

    let floor_directory = &external.floor_directory;

    // Only a first boot without an existing QCF1 floor needs to stage the checkpoint-rooted empty
    // suffix manifest here. A failed first boot may leave that manifest behind; on retry, ECR1
    // must still match it before QCF1 is initialized. Once QCF1 exists, leave PFS2 inspection and
    // any pending CAS recovery to the external-CAS store opener so a crash between remote CAS,
    // local manifest replacement and floor advancement can be reconciled in its journal.
    if let (Some(checkpoint), Some(checkpoint_bytes)) =
        (external.checkpoint.as_ref(), checkpoint_bytes.as_deref())
    {
        if !floor_directory.exists() {
            let expected_manifest_anchor =
                directory.exists().then_some(bootstrap.next_state_digest);
            let staged =
                PrivateTestnetForkStore::open_qrun_v05_fee_only_from_checkpoint_for_owner_genesis(
                    directory,
                    genesis.ledger().clone(),
                    owner_account,
                    params.clone(),
                    authenticator,
                    clock,
                    checkpoint_bytes,
                    checkpoint.expected_commitment,
                    checkpoint.minimum_height,
                    expected_manifest_anchor,
                )
                .map_err(|error| {
                    format!("stage/open checkpoint-rooted QFP5 manifest: {error:?}")
                })?;
            let staged_anchor = staged.manifest_anchor().map_err(|error| {
                format!("read checkpoint-rooted PFS2 manifest anchor: {error:?}")
            })?;
            drop(staged);
            if bootstrap.next_state_digest != staged_anchor {
                return Err(
                    "external-CAS ECR1 bootstrap does not anchor the exact checkpoint-rooted PFS2 manifest"
                        .into(),
                );
            }
        }
    }

    // The explicit initialize switch is safe to keep enabled across restarts:
    // AlreadyInitialized opens the existing floor; MissingState after initialization stays fatal.
    let mut floor = if external.initialize_floor {
        match ExternalCasFloorStore::initialize(&floor_directory, pin.clone(), bootstrap, 1) {
            Ok(floor) => floor,
            Err(ExternalCasFloorError::AlreadyInitialized) => {
                ExternalCasFloorStore::open(floor_directory, pin.clone())
                    .map_err(|error| format!("open existing external-CAS QCF1 floor: {error}"))?
            }
            Err(error) => return Err(format!("initialize external-CAS QCF1 floor: {error}")),
        }
    } else {
        ExternalCasFloorStore::open(floor_directory, pin.clone())
            .map_err(|error| format!("open external-CAS QCF1 floor: {error}"))?
    };

    let mut client = open_verified_external_cas_client(external, &network_id, pin.clone())?;

    if external.recover_qrm1 {
        let archive_root = external
            .history_archive_root
            .as_ref()
            .ok_or("--external-cas-history-archive-root is required for QRM1 recovery")?;
        let report = recover_qrun_v05_checkpoint_migration(
            directory,
            archive_root,
            genesis.ledger(),
            owner_account,
            &params,
            &pin,
            &mut client,
            &floor,
            authenticator,
            clock,
        )
        .map_err(|error| {
            format!("explicit QRM1 checkpoint migration recovery failed closed: {error}")
        })?;
        checkpoint_bytes = Some(report.checkpoint_bytes);
        checkpoint_commitment = Some(report.checkpoint_commitment);
        checkpoint_minimum_height = Some(report.minimum_checkpoint_height);
        checkpoint_parent_commitment = Some(report.expected_parent_checkpoint_commitment);
        println!(
            "qrun_v05_qrm1_recovery_complete height={} checkpoint_commitment={} manifest_anchor={} provider_generation={} object_generation={} archive_id={} archive_commitment={}",
            report.minimum_checkpoint_height,
            hex(&report.checkpoint_commitment),
            hex(&report.manifest_anchor),
            report.provider_record.generation,
            report.provider_object_generation,
            hex(&report.archive_id),
            hex(&report.archive_commitment),
        );
    }

    if external.migrate_genesis_checkpoint {
        let archive_root = external.history_archive_root.as_ref().ok_or(
            "--external-cas-history-archive-root is required for Genesis checkpoint migration",
        )?;
        let checkpoint_output_file = external.checkpoint_output_file.as_ref().ok_or(
            "--external-cas-checkpoint-output-file is required for Genesis checkpoint migration",
        )?;
        let expected_parent_commitment = external
            .checkpoint_parent_commitment
            .ok_or("--external-cas-migration-parent-commitment-hex is required for Genesis checkpoint migration")?;

        // The migration API consumes the open PFS2/CAS owner so it can keep the writer lock
        // through QRA1 replay and durable QRM1 publication. It never bootstraps/replaces the
        // provider pin; the exact generation-zero ECR1/QCF1 trust tuple was checked above.
        let migration_store = QRunV05ExternalCasForkStore::open_for_owner_genesis_with_floor(
            directory,
            genesis.ledger().clone(),
            owner_account,
            params.clone(),
            authenticator,
            clock,
            pin.clone(),
            client,
            floor,
        )
        .map_err(|error| {
            format!("open Genesis-rooted QRun external-CAS migration store: {error:?}")
        })?;
        let report = migration_store
            .migrate_genesis_rooted_store_to_checkpoint(
                archive_root,
                checkpoint_output_file,
                expected_parent_commitment,
                authenticator,
                clock,
            )
            .map_err(|error| {
                format!("explicit Genesis-to-checkpoint migration failed closed: {error}")
            })?;
        let persisted_checkpoint = read_bounded_regular_file(
            &report.checkpoint_record_file,
            ai_native_l1_pow_bench::qrun_v05_checkpoint_candidate::MAX_QRCP_BYTES,
            "migrated QRun QRCP checkpoint",
        )?;
        if persisted_checkpoint != report.recovery.checkpoint_bytes {
            return Err(
                "persisted QRCP checkpoint differs from the recovered QRM1 commitment".into(),
            );
        }
        checkpoint_bytes = Some(persisted_checkpoint);
        checkpoint_commitment = Some(report.recovery.checkpoint_commitment);
        checkpoint_minimum_height = Some(report.recovery.minimum_checkpoint_height);
        checkpoint_parent_commitment = Some(report.recovery.expected_parent_checkpoint_commitment);
        println!(
            "qrun_v05_genesis_checkpoint_migration_complete height={} checkpoint_commitment={} manifest_anchor={} provider_generation={} object_generation={} archive_id={} archive_commitment={} checkpoint_file={}",
            report.recovery.minimum_checkpoint_height,
            hex(&report.recovery.checkpoint_commitment),
            hex(&report.recovery.manifest_anchor),
            report.recovery.provider_record.generation,
            report.recovery.provider_object_generation,
            hex(&report.recovery.archive_id),
            hex(&report.recovery.archive_commitment),
            report.checkpoint_record_file.display(),
        );

        // The migration store is consuming by design. Reopen both independent trust inputs
        // (QCF1 from disk and a new authenticated Noise/TCP session) before ordinary node startup.
        floor = ExternalCasFloorStore::open(&floor_directory, pin.clone())
            .map_err(|error| format!("reopen QCF1 floor after checkpoint migration: {error}"))?;
        client = open_verified_external_cas_client(external, &network_id, pin.clone())?;
    }

    let external_store = match (
        checkpoint_bytes.as_deref(),
        checkpoint_commitment,
        checkpoint_minimum_height,
        checkpoint_parent_commitment,
    ) {
        (Some(checkpoint_bytes), Some(expected_commitment), Some(minimum_height), Some(expected_parent_commitment)) => {
            QRunV05ExternalCasForkStore::open_from_checkpoint_with_parent_for_owner_genesis_and_floor(
                directory,
                genesis.ledger().clone(),
                owner_account,
                params.clone(),
                authenticator,
                clock,
                checkpoint_bytes,
                expected_commitment,
                minimum_height,
                expected_parent_commitment,
                pin,
                client,
                floor,
            )
            .map_err(|error| {
                format!("open checkpoint-rooted QRun external-CAS fork store: {error:?}")
            })?
        }
        (None, None, None, None) => {
            QRunV05ExternalCasForkStore::open_for_owner_genesis_with_floor(
                directory,
                genesis.ledger().clone(),
                owner_account,
                params.clone(),
                authenticator,
                clock,
                pin,
                client,
                floor,
            )
            .map_err(|error| format!("open QRun external-CAS fork store: {error:?}"))?
        }
        _ => return Err("incomplete recovered/external checkpoint trust tuple".into()),
    };
    QRunV05PowForkRuntime::from_store_with_genesis(
        network_id,
        owner_account,
        params,
        NodeForkStore::ExternalCas(external_store),
        genesis,
    )
    .map_err(|error| format!("bind external-CAS QRun runtime backend: {error:?}"))
}

struct NodeState {
    runtime: NodeRuntime,
    public_alpha: bool,
    mainnet: bool,
    authenticator: Ed25519TransactionAuthenticator,
    clock: NodeReferenceTime,
    receipts: BTreeMap<[u8; 32], Receipt>,
    profile_id: [u8; 32],
    block_peers: Vec<SocketAddr>,
    noise_private_key: Option<[u8; 32]>,
    trusted_peer_static_keys: Vec<[u8; 32]>,
    peer_static_keys_by_addr: BTreeMap<SocketAddr, [u8; 32]>,
    d1_evidence: bool,
    d2_partition_qualification: bool,
    offhost_anchor_service: OffhostAnchorNodeServiceOwner,
}

impl Drop for NodeState {
    fn drop(&mut self) {
        if let Err(error) = self.shutdown_offhost_anchor_service() {
            eprintln!(
                "qrun_offhost_anchor_lifecycle_shutdown_failed reason={}",
                error.to_string().replace(['\r', '\n'], "_")
            );
        }
        if let Some(private_key) = self.noise_private_key.as_mut() {
            private_key.fill(0);
        }
    }
}

impl NodeState {
    /// Attach a daemon task that was independently configured, bound and spawned by an explicit
    /// provisioner. Ordinary node startup never calls this method.
    #[allow(dead_code)] // Future provisioner hook; normal startup deliberately leaves this disabled.
    fn attach_offhost_anchor_task(
        &mut self,
        task: OffhostAnchorNoiseDaemonTask,
    ) -> Result<(), OffhostAnchorNoiseDaemonTask> {
        self.offhost_anchor_service.try_attach(task)
    }

    fn shutdown_offhost_anchor_service(&mut self) -> Result<(), String> {
        self.offhost_anchor_service
            .shutdown_and_join()
            .map(|_| ())
            .map_err(|error| format!("join off-host Anchor daemon: {error}"))
    }

    fn refresh_receipts(&mut self) -> Result<(), String> {
        let locations = self
            .runtime
            .canonical_transaction_locations()
            .map_err(|error| format!("rebuild canonical transaction index: {error:?}"))?;
        self.receipts.clear();
        for (txid, height) in locations {
            self.receipts.insert(txid, Receipt { height });
        }
        Ok(())
    }
}

#[derive(Clone)]
struct Config {
    public_alpha: bool,
    mainnet: bool,
    network_id: NetworkId,
    owner_account: AccountId,
    producer_account: AccountId,
    owner_public_key: [u8; 32],
    genesis_timestamp: Option<u64>,
    data_dir: PathBuf,
    rpc_listen: SocketAddr,
    tx_listen: SocketAddr,
    block_listen: SocketAddr,
    peers: Vec<SocketAddr>,
    noise_private_key_file: Option<PathBuf>,
    peer_static_public_keys: Vec<[u8; 32]>,
    sync_on_start: bool,
    d1_evidence: bool,
    d2_partition_qualification: bool,
    external_cas: Option<ExternalCasNodeConfig>,
    reference_time: Option<ReferenceTimeNodeConfig>,
}

#[derive(Clone, Debug)]
struct ReferenceTimeNodeConfig {
    policy_file: PathBuf,
    admin_public_key: [u8; 32],
    address: SocketAddr,
    state_file: PathBuf,
}

enum NodeReferenceTime {
    SystemClock,
    Authenticated {
        provider: AuthenticatedReferenceTimeProvider<TcpReferenceTimeExchange>,
        policy_digest: [u8; 32],
    },
}

impl NodeReferenceTime {
    fn policy_digest(&self) -> Option<[u8; 32]> {
        match self {
            Self::SystemClock => None,
            Self::Authenticated { policy_digest, .. } => Some(*policy_digest),
        }
    }

    fn source_label(&self) -> &'static str {
        match self {
            Self::SystemClock => "os-system-clock-local-only",
            Self::Authenticated { .. } => "ed25519-attested-time-v1",
        }
    }
}

impl ReferenceTimeProvider for NodeReferenceTime {
    fn sample(&self) -> Result<ReferenceTimeSample, ReferenceTimeError> {
        match self {
            Self::SystemClock => SystemClockReferenceTime.sample(),
            Self::Authenticated { provider, .. } => provider.sample(),
        }
    }
}

#[derive(Clone, Debug)]
struct ExternalCasNodeCheckpointConfig {
    record_file: PathBuf,
    expected_commitment: [u8; 32],
    minimum_height: u64,
    expected_parent_commitment: [u8; 32],
}

#[derive(Clone, Debug)]
struct ExternalCasNodeConfig {
    endpoint: SocketAddr,
    provider_id: [u8; 32],
    genesis_commitment: [u8; 32],
    receipt_key_id: [u8; 32],
    noise_server_static_public_key: [u8; 32],
    noise_private_key_file: PathBuf,
    receipt_public_key_file: PathBuf,
    bootstrap_record_file: PathBuf,
    floor_directory: PathBuf,
    initialize_floor: bool,
    recover_qrm1: bool,
    history_archive_root: Option<PathBuf>,
    migrate_genesis_checkpoint: bool,
    checkpoint_output_file: Option<PathBuf>,
    checkpoint_parent_commitment: Option<[u8; 32]>,
    checkpoint: Option<ExternalCasNodeCheckpointConfig>,
}

fn parse_hex32(value: &str, name: &str) -> Result<[u8; 32], String> {
    if value.len() != 64 || !value.is_ascii() {
        return Err(format!("{name} must be 64 hex characters"));
    }
    let mut output = [0; 32];
    for (index, byte) in output.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| format!("{name} contains a non-hex character"))?;
    }
    Ok(output)
}

fn parse_external_cas_config(
    values: &BTreeMap<String, String>,
    allow_public_endpoint: bool,
) -> Result<Option<ExternalCasNodeConfig>, String> {
    const REQUIRED: [&str; 9] = [
        "--external-cas-endpoint",
        "--external-cas-provider-id-hex",
        "--external-cas-genesis-id-hex",
        "--external-cas-noise-server-static-public-key-hex",
        "--external-cas-noise-private-key-file",
        "--external-cas-receipt-key-id-hex",
        "--external-cas-receipt-public-key-file",
        "--external-cas-bootstrap-record-file",
        "--external-cas-floor-dir",
    ];
    const CHECKPOINT_REQUIRED: [&str; 4] = [
        "--external-cas-checkpoint-file",
        "--external-cas-checkpoint-commitment-hex",
        "--external-cas-checkpoint-min-height",
        "--external-cas-checkpoint-parent-commitment-hex",
    ];
    let present = REQUIRED
        .iter()
        .filter(|key| values.contains_key(**key))
        .count();
    let checkpoint_present = CHECKPOINT_REQUIRED
        .iter()
        .filter(|key| values.contains_key(**key))
        .count();
    let initialize_requested = values.contains_key("--external-cas-initialize-floor");
    let recovery_options_present = values.contains_key("--external-cas-recover-qrm1")
        || values.contains_key("--external-cas-history-archive-root")
        || values.contains_key("--external-cas-migrate-genesis-checkpoint")
        || values.contains_key("--external-cas-checkpoint-output-file")
        || values.contains_key("--external-cas-migration-parent-commitment-hex");
    if present == 0 {
        if initialize_requested || recovery_options_present {
            return Err(
                "external-CAS initialization/recovery requires the complete external-CAS pin set"
                    .into(),
            );
        }
        if checkpoint_present != 0 {
            return Err(
                "checkpoint bootstrap options require the complete external-CAS pin and floor configuration".into(),
            );
        }
        return Ok(None);
    }
    if present != REQUIRED.len() {
        let missing = REQUIRED
            .iter()
            .filter(|key| !values.contains_key(**key))
            .copied()
            .collect::<Vec<_>>()
            .join(", ");
        return Err(format!(
            "external-CAS configuration is all-or-none; missing: {missing}"
        ));
    }
    if values.contains_key("--mainnet") {
        return Err("internal external-CAS parser received an invalid mode map".into());
    }
    let required = |key: &str| {
        values
            .get(key)
            .map(String::as_str)
            .ok_or_else(|| format!("required external-CAS option missing: {key}"))
    };
    let endpoint = parse_socket(
        required("--external-cas-endpoint")?,
        "--external-cas-endpoint",
        allow_public_endpoint,
    )?;
    let provider_id = parse_hex32(
        required("--external-cas-provider-id-hex")?,
        "external-CAS provider ID",
    )?;
    let genesis_commitment = parse_hex32(
        required("--external-cas-genesis-id-hex")?,
        "external-CAS Genesis commitment",
    )?;
    let noise_server_static_public_key = parse_hex32(
        required("--external-cas-noise-server-static-public-key-hex")?,
        "external-CAS Noise server static public key",
    )?;
    let receipt_key_id = parse_hex32(
        required("--external-cas-receipt-key-id-hex")?,
        "external-CAS receipt key ID",
    )?;
    if provider_id == [0; 32]
        || genesis_commitment == [0; 32]
        || noise_server_static_public_key == [0; 32]
        || receipt_key_id == [0; 32]
    {
        return Err(
            "external-CAS provider, Genesis, Noise and receipt pins must be nonzero".into(),
        );
    }
    let absolute_file_path = |key: &str| -> Result<PathBuf, String> {
        let path = PathBuf::from(required(key)?);
        if !path.is_absolute() || path.file_name().is_none() {
            return Err(format!("{key} must be an absolute file path"));
        }
        Ok(path)
    };
    let floor_directory = PathBuf::from(required("--external-cas-floor-dir")?);
    if !floor_directory.is_absolute() || floor_directory.file_name().is_none() {
        return Err("--external-cas-floor-dir must be an absolute directory path".into());
    }
    let initialize_floor = match values
        .get("--external-cas-initialize-floor")
        .map(String::as_str)
        .unwrap_or("false")
    {
        "true" => true,
        "false" => false,
        _ => return Err("--external-cas-initialize-floor must be exactly true or false".into()),
    };
    let recover_qrm1 = match values
        .get("--external-cas-recover-qrm1")
        .map(String::as_str)
        .unwrap_or("false")
    {
        "true" => true,
        "false" => false,
        _ => return Err("--external-cas-recover-qrm1 must be exactly true or false".into()),
    };
    let migrate_genesis_checkpoint = match values
        .get("--external-cas-migrate-genesis-checkpoint")
        .map(String::as_str)
        .unwrap_or("false")
    {
        "true" => true,
        "false" => false,
        _ => {
            return Err(
                "--external-cas-migrate-genesis-checkpoint must be exactly true or false".into(),
            )
        }
    };
    if recover_qrm1 && migrate_genesis_checkpoint {
        return Err(
            "QRM1 recovery and Genesis-to-checkpoint migration are separate maintenance operations; choose exactly one".into(),
        );
    }
    let history_archive_root = values
        .get("--external-cas-history-archive-root")
        .map(PathBuf::from);
    if (recover_qrm1 || migrate_genesis_checkpoint) && history_archive_root.is_none() {
        return Err(
            "QRM1 recovery or Genesis checkpoint migration requires --external-cas-history-archive-root".into(),
        );
    }
    if !recover_qrm1 && !migrate_genesis_checkpoint && history_archive_root.is_some() {
        return Err(
            "--external-cas-history-archive-root is valid only with explicit QRM1 recovery or Genesis checkpoint migration".into(),
        );
    }
    if recover_qrm1 && initialize_floor {
        return Err(
            "QRM1 recovery requires an existing QCF1 floor; it cannot initialize or reset the floor".into(),
        );
    }
    if (recover_qrm1 || migrate_genesis_checkpoint) && checkpoint_present != 0 {
        return Err(
            "QRM1 recovery and Genesis checkpoint migration derive the checkpoint internally; do not pass checkpoint bootstrap options".into(),
        );
    }
    let migration_output_present = values.contains_key("--external-cas-checkpoint-output-file");
    let migration_parent_present =
        values.contains_key("--external-cas-migration-parent-commitment-hex");
    let (checkpoint_output_file, checkpoint_parent_commitment) =
        match (migrate_genesis_checkpoint, migration_output_present, migration_parent_present) {
            (true, true, true) => {
                let output = PathBuf::from(required("--external-cas-checkpoint-output-file")?);
                if !output.is_absolute() || output.file_name().is_none() {
                    return Err(
                        "--external-cas-checkpoint-output-file must be an absolute file path".into(),
                    );
                }
                let parent = parse_hex32(
                    required("--external-cas-migration-parent-commitment-hex")?,
                    "Genesis QRCP parent checkpoint commitment",
                )?;
                if parent == [0; 32] {
                    return Err("Genesis QRCP parent checkpoint commitment must be nonzero".into());
                }
                if paths_overlap(&floor_directory, &output) {
                    return Err(
                        "checkpoint output file must remain outside the independent QCF1 floor directory".into(),
                    );
                }
                (Some(output), Some(parent))
            }
            (true, _, _) => {
                return Err(
                    "Genesis checkpoint migration requires both --external-cas-checkpoint-output-file and --external-cas-migration-parent-commitment-hex".into(),
                )
            }
            (false, false, false) => (None, None),
            (false, _, _) => {
                return Err(
                    "checkpoint output and parent commitment options require --external-cas-migrate-genesis-checkpoint true".into(),
                )
            }
        };
    if let Some(root) = &history_archive_root {
        if !root.is_absolute() || root.file_name().is_none() {
            return Err(
                "--external-cas-history-archive-root must be an absolute existing directory path"
                    .into(),
            );
        }
    }
    let checkpoint = match checkpoint_present {
        0 => None,
        count if count != CHECKPOINT_REQUIRED.len() => {
            let missing = CHECKPOINT_REQUIRED
                .iter()
                .filter(|key| !values.contains_key(**key))
                .copied()
                .collect::<Vec<_>>()
                .join(", ");
            return Err(format!(
                "checkpoint bootstrap configuration is all-or-none; missing: {missing}"
            ));
        }
        _ => {
            let expected_commitment = parse_hex32(
                required("--external-cas-checkpoint-commitment-hex")?,
                "QRCP checkpoint commitment",
            )?;
            let expected_parent_commitment = parse_hex32(
                required("--external-cas-checkpoint-parent-commitment-hex")?,
                "QRCP parent checkpoint commitment",
            )?;
            let minimum_height = required("--external-cas-checkpoint-min-height")?
                .parse::<u64>()
                .map_err(|_| {
                    "--external-cas-checkpoint-min-height must be an unsigned integer".to_string()
                })?;
            if expected_commitment == [0; 32]
                || expected_parent_commitment == [0; 32]
                || minimum_height == 0
            {
                return Err(
                    "QRCP commitment, parent commitment and minimum height must be nonzero".into(),
                );
            }
            Some(ExternalCasNodeCheckpointConfig {
                record_file: absolute_file_path("--external-cas-checkpoint-file")?,
                expected_commitment,
                minimum_height,
                expected_parent_commitment,
            })
        }
    };
    Ok(Some(ExternalCasNodeConfig {
        endpoint,
        provider_id,
        genesis_commitment,
        receipt_key_id,
        noise_server_static_public_key,
        noise_private_key_file: absolute_file_path("--external-cas-noise-private-key-file")?,
        receipt_public_key_file: absolute_file_path("--external-cas-receipt-public-key-file")?,
        bootstrap_record_file: absolute_file_path("--external-cas-bootstrap-record-file")?,
        floor_directory,
        initialize_floor,
        recover_qrm1,
        history_archive_root,
        migrate_genesis_checkpoint,
        checkpoint_output_file,
        checkpoint_parent_commitment,
        checkpoint,
    }))
}

fn parse_reference_time_node_config(
    values: &BTreeMap<String, String>,
    public_network: bool,
) -> Result<Option<ReferenceTimeNodeConfig>, String> {
    const REQUIRED: [&str; 4] = [
        "--reference-time-policy-file",
        "--reference-time-admin-public-key-hex",
        "--reference-time-address",
        "--reference-time-state-file",
    ];
    let present = REQUIRED
        .iter()
        .filter(|key| values.contains_key(**key))
        .count();
    if present == 0 {
        if public_network {
            return Err(
                "public network modes require the complete authenticated reference-time configuration"
                    .into(),
            );
        }
        return Ok(None);
    }
    if present != REQUIRED.len() {
        let missing = REQUIRED
            .iter()
            .filter(|key| !values.contains_key(**key))
            .copied()
            .collect::<Vec<_>>()
            .join(", ");
        return Err(format!(
            "authenticated reference-time configuration is all-or-none; missing: {missing}"
        ));
    }
    let required = |key: &str| {
        values
            .get(key)
            .map(String::as_str)
            .ok_or_else(|| format!("required reference-time option missing: {key}"))
    };
    let absolute_path = |key: &str| -> Result<PathBuf, String> {
        let path = PathBuf::from(required(key)?);
        if !path.is_absolute() || path.file_name().is_none() {
            return Err(format!("{key} must be an absolute file path"));
        }
        if !path.parent().is_some_and(|parent| parent.is_dir()) {
            return Err(format!("{key} parent directory must already exist"));
        }
        Ok(path)
    };
    let admin_public_key = parse_hex32(
        required("--reference-time-admin-public-key-hex")?,
        "reference-time policy admin public key",
    )?;
    if admin_public_key == [0; 32] {
        return Err("reference-time policy admin public key must be nonzero".into());
    }
    let admin = VerifyingKey::from_bytes(&admin_public_key)
        .map_err(|_| "reference-time policy admin public key is invalid".to_string())?;
    if admin.is_weak() {
        return Err("reference-time policy admin public key must not be weak".into());
    }
    let address = required("--reference-time-address")?
        .parse::<SocketAddr>()
        .map_err(|_| {
            "--reference-time-address must be a numeric IP:PORT socket address".to_string()
        })?;
    if address.port() == 0 || address.ip().is_unspecified() || address.ip().is_multicast() {
        return Err(
            "--reference-time-address must use a nonzero port and a unicast, specified IP".into(),
        );
    }
    let policy_file = absolute_path("--reference-time-policy-file")?;
    let state_file = absolute_path("--reference-time-state-file")?;
    if paths_overlap(&policy_file, &state_file) {
        return Err(
            "reference-time high-water state file must be separate from the signed policy file"
                .into(),
        );
    }
    Ok(Some(ReferenceTimeNodeConfig {
        policy_file,
        admin_public_key,
        address,
        state_file,
    }))
}

fn build_authenticated_node_reference_time(
    reference_time: &ReferenceTimeNodeConfig,
    network_id: &NetworkId,
) -> Result<NodeReferenceTime, String> {
    let file = fs::File::open(&reference_time.policy_file)
        .map_err(|error| format!("open signed reference-time policy: {error}"))?;
    let length = file
        .metadata()
        .map_err(|error| format!("inspect signed reference-time policy: {error}"))?
        .len();
    if length != POLICY_WIRE_LEN as u64 {
        return Err(format!(
            "signed reference-time policy must be exactly {POLICY_WIRE_LEN} bytes"
        ));
    }
    let mut policy_bytes = Vec::with_capacity(POLICY_WIRE_LEN);
    file.take((POLICY_WIRE_LEN + 1) as u64)
        .read_to_end(&mut policy_bytes)
        .map_err(|error| format!("read signed reference-time policy: {error}"))?;
    if policy_bytes.len() != POLICY_WIRE_LEN {
        return Err("signed reference-time policy changed length while being read".into());
    }
    let store = ReferenceTimeStateStore::open(&reference_time.state_file, network_id)
        .map_err(|error| format!("open durable reference-time high-water state: {error:?}"))?;
    let trust_state = store
        .policy_trust_state()
        .map_err(|error| format!("restore reference-time policy rollback floor: {error:?}"))?;
    let policy = VerifiedReferenceTimePolicy::verify(
        &policy_bytes,
        network_id,
        &reference_time.admin_public_key,
        &trust_state,
    )
    .map_err(|error| format!("signed reference-time policy rejected: {error:?}"))?;
    let policy_digest = *policy.digest();
    let provider = AuthenticatedReferenceTimeProvider::new_persistent(
        policy,
        TcpReferenceTimeExchange::new(reference_time.address),
        store,
    )
    .map_err(|error| format!("initialize authenticated reference-time provider: {error:?}"))?;
    Ok(NodeReferenceTime::Authenticated {
        provider,
        policy_digest,
    })
}

fn build_node_reference_time(config: &Config) -> Result<NodeReferenceTime, String> {
    let Some(reference_time) = config.reference_time.as_ref() else {
        if config.public_alpha || config.mainnet {
            return Err(
                "public QRun mode cannot fall back to the local operating-system clock".into(),
            );
        }
        return Ok(NodeReferenceTime::SystemClock);
    };
    build_authenticated_node_reference_time(reference_time, &config.network_id)
}

fn next_live_block_timestamp(reference_time: u64, previous_timestamp: u64) -> Result<u64, String> {
    let next_after_previous = previous_timestamp
        .checked_add(1)
        .ok_or_else(|| "canonical block timestamp is exhausted".to_string())?;
    let candidate = reference_time.max(next_after_previous);
    let latest_allowed = reference_time.saturating_add(120);
    if candidate > latest_allowed {
        return Err(format!(
            "local chain timestamp {} is more than 120 seconds ahead of authenticated reference time {}",
            candidate, reference_time
        ));
    }
    Ok(candidate)
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        result.push(DIGITS[(byte >> 4) as usize] as char);
        result.push(DIGITS[(byte & 15) as usize] as char);
    }
    result
}

fn parse_socket(value: &str, name: &str, allow_public: bool) -> Result<SocketAddr, String> {
    let address = value
        .parse::<SocketAddr>()
        .map_err(|_| format!("{name} must be a numeric IP:PORT socket address"))?;
    if !allow_public && !address.ip().is_loopback() {
        return Err(format!(
            "{name} must be loopback-only outside explicit public-alpha mode"
        ));
    }
    Ok(address)
}

/// Startup synchronization is security-sensitive: never accept a seed's chain response unless
/// its Noise static key is pinned. Public-alpha may use unpinned peers for block gossip, but not
/// for deciding the chain tip during startup.
fn validate_sync_start_config(
    sync_on_start: bool,
    has_noise_private_key: bool,
    peer_count: usize,
    pinned_peer_count: usize,
) -> Result<(), String> {
    if !sync_on_start {
        return Ok(());
    }
    if !has_noise_private_key {
        return Err("--sync-on-start requires --noise-private-key-file".into());
    }
    if peer_count == 0 {
        return Err("--sync-on-start requires at least one --peer".into());
    }
    if pinned_peer_count != peer_count {
        return Err(
            "--sync-on-start requires exactly one --peer-static-public-key-hex pin for every --peer"
                .into(),
        );
    }
    Ok(())
}

fn validate_mainnet_release_gate(enabled: bool) -> Result<(), String> {
    if !enabled || QRUN_MAINNET_RELEASE_APPROVED {
        return Ok(());
    }
    Err(format!(
        "--mainnet is disabled by the QRun production release gate; do not bypass it. Unresolved: {}",
        QRUN_MAINNET_RELEASE_BLOCKERS.join("; ")
    ))
}

fn validate_mainnet_p2p_requirements(
    enabled: bool,
    sync_on_start: bool,
    peers: &[SocketAddr],
    pinned_peer_count: usize,
    block_listener: SocketAddr,
) -> Result<(), String> {
    if !enabled {
        return Ok(());
    }
    // Do not claim Mainnet from a local Genesis alone: require an independently operated,
    // non-loopback seed whose identity is pinned and whose chain successfully syncs at startup.
    if !sync_on_start {
        return Err("--mainnet requires --sync-on-start true".into());
    }
    if peers.is_empty() {
        return Err("--mainnet requires at least one independently configured seed peer".into());
    }
    if peers.iter().any(|peer| peer.ip().is_loopback()) {
        return Err("--mainnet seed peers must be non-loopback addresses".into());
    }
    if pinned_peer_count != peers.len() {
        return Err("--mainnet requires a static-key pin for every configured seed peer".into());
    }
    if block_listener.ip().is_loopback() {
        return Err("--mainnet requires a non-loopback P2P block listener".into());
    }
    Ok(())
}

/// Keep administrative interfaces on loopback while allowing explicit public P2P in either
/// public-alpha or a Mainnet configuration. Mainnet's seed/sync/pin requirements are enforced
/// separately by validate_mainnet_p2p_requirements before runtime startup.
fn validate_listener_bind_policy(
    public_alpha: bool,
    mainnet: bool,
    rpc_listen: SocketAddr,
    tx_listen: SocketAddr,
    block_listen: SocketAddr,
    peers: &[SocketAddr],
) -> Result<(), String> {
    if !rpc_listen.ip().is_loopback() || !tx_listen.ip().is_loopback() {
        return Err("RPC/transaction interfaces stay loopback-only".into());
    }
    let public_p2p_enabled = public_alpha || mainnet;
    if !public_p2p_enabled
        && (!block_listen.ip().is_loopback() || peers.iter().any(|peer| !peer.ip().is_loopback()))
    {
        return Err("non-loopback P2P requires explicit --public-alpha or --mainnet".into());
    }
    Ok(())
}

fn is_qrun_v05_identity(network_id: &NetworkId, owner_account: &AccountId) -> bool {
    let historical_candidate = *network_id
        == ai_native_l1_pow_bench::qrun_v05_profile_identity_candidate::PROPOSED_QRUN_V05_NETWORK_ID
        && *owner_account
            == ai_native_l1_pow_bench::qrun_v05_profile_identity_candidate::PROPOSED_OWNER_ACCOUNT_ID;
    let current_wallet_bound_candidate =
        *network_id == QZXB_MAINNET_NETWORK_ID && *owner_account == QZXB_MAINNET_OWNER_ACCOUNT_ID;
    historical_candidate || current_wallet_bound_candidate
}

fn consensus_parameters_for_mode(
    public_alpha: bool,
    mainnet: bool,
    qrun_v05_identity: bool,
) -> Result<ConsensusParameters, String> {
    // Production-intent modes must use the calibrated candidate profile. Only the explicit
    // loopback smoke-test mode gets maximum-target PoW and reduced Argon2 memory.
    if public_alpha || mainnet {
        return ConsensusParameters::qrun_v05_calibrated_candidate()
            .map_err(|error| format!("load calibrated QRun v0.5 consensus candidate: {error:?}"));
    }

    let mut local = ConsensusParameters::candidate_testnet()
        .map_err(|error| format!("load local smoke PoW profile: {error:?}"))?;
    if qrun_v05_identity {
        local.protocol_version = 5;
    }
    local.initial_target = Uint256::MAX;
    local.pow_limit = Uint256::MAX;
    local.pow.memory_kib = 8 * 1024;
    local.pow.iterations = 1;
    local.pow.lanes = 1;
    Ok(local)
}

fn validate_frozen_mainnet_genesis(
    enabled: bool,
    genesis_id: &[u8; 32],
    profile_id: &[u8; 32],
    state_root: &[u8; 32],
    owner_balance: u128,
    total_supply: u128,
    account_count: usize,
    canonical_height: u64,
) -> Result<(), String> {
    if !enabled {
        return Ok(());
    }
    if hex(genesis_id) != QZXB_MAINNET_GENESIS_ID_HEX
        || hex(profile_id) != QZXB_MAINNET_PROFILE_ID_HEX
    {
        return Err(
            "--mainnet refuses to start: computed Genesis ID or profile ID differs from the frozen QZXB identity"
                .into(),
        );
    }
    let expected_supply = ai_native_l1_pow_bench::state_machine::MAX_TOTAL_SUPPLY_ATOMS;
    if total_supply != expected_supply {
        return Err(
            "--mainnet refuses to start: total supply differs from the fixed 10B cap".into(),
        );
    }
    // The current canonical state root and owner's balance legitimately change after transfers.
    // Validate the frozen root and single-account allocation only while the canonical tip is Genesis.
    if canonical_height == 0
        && (hex(state_root) != QZXB_MAINNET_STATE_ROOT_HEX
            || owner_balance != expected_supply
            || account_count != 1)
    {
        return Err(
            "--mainnet refuses to start: the height-zero Genesis root or single-account supply allocation differs from the frozen QZXB identity"
                .into(),
        );
    }
    Ok(())
}

fn paths_overlap(left: &std::path::Path, right: &std::path::Path) -> bool {
    let normalize = |path: &std::path::Path| {
        let raw = path
            .to_string_lossy()
            .replace('/', "\\")
            .to_ascii_lowercase();
        let (prefix, remainder, protected_components, rooted) =
            if raw.len() >= 3 && raw.as_bytes()[1] == b':' && raw.as_bytes()[2] == b'\\' {
                (raw[..3].to_string(), &raw[3..], 0usize, true)
            } else if raw.starts_with("\\\\") {
                ("\\\\".to_string(), &raw[2..], 2usize, true)
            } else if raw.starts_with('\\') {
                ("\\".to_string(), &raw[1..], 0usize, true)
            } else if raw.len() >= 2 && raw.as_bytes()[1] == b':' {
                (raw[..2].to_string(), &raw[2..], 0usize, false)
            } else {
                (String::new(), raw.as_str(), 0usize, false)
            };
        let mut components: Vec<&str> = Vec::new();
        for component in remainder.split('\\') {
            match component {
                "" | "." => {}
                ".." if components.len() > protected_components => {
                    components.pop();
                }
                ".." if !rooted => components.push(".."),
                ".." => {}
                value => components.push(value),
            }
        }
        if components.is_empty() {
            if rooted {
                prefix
            } else {
                prefix.trim_end_matches('\\').to_string()
            }
        } else {
            format!("{}{}", prefix, components.join("\\"))
        }
    };
    let left = normalize(left);
    let right = normalize(right);
    left == right
        || left.starts_with(&(right.trim_end_matches('\\').to_string() + "\\"))
        || right.starts_with(&(left.trim_end_matches('\\').to_string() + "\\"))
}

fn parse_genesis_timestamp_option(
    values: &BTreeMap<String, String>,
    public_alpha_mode: bool,
    mainnet_mode: bool,
) -> Result<Option<u64>, String> {
    let genesis_timestamp = values
        .get("--genesis-time-unix-secs")
        .map(|value| {
            let timestamp = value.parse::<u64>().map_err(|_| {
                "--genesis-time-unix-secs must be an unsigned Unix timestamp".to_string()
            })?;
            if timestamp == 0 {
                return Err("--genesis-time-unix-secs must be nonzero".to_string());
            }
            Ok::<u64, String>(timestamp)
        })
        .transpose()?;
    if (public_alpha_mode || mainnet_mode) && genesis_timestamp.is_none() {
        let mode = if mainnet_mode {
            "--mainnet"
        } else {
            "--public-alpha"
        };
        return Err(format!(
            "{mode} requires an explicit --genesis-time-unix-secs shared by every node"
        ));
    }
    Ok(genesis_timestamp)
}

fn parse_config() -> Result<Config, String> {
    let args = env::args().skip(1).collect::<Vec<_>>();
    if args.iter().any(|arg| arg == "--help" || arg == "-h") {
        println!(
            "QRun v0.5 node modes\n\
Local test: qrun_v05_pow_local_node --local-testnet --network-id-hex HEX64 --owner-account-id-hex HEX64 --owner-public-key-hex HEX64 --data-dir ABSOLUTE_PATH\n\
Public alpha: qrun_v05_pow_local_node --public-alpha --network-id-hex HEX64 --owner-account-id-hex HEX64 --owner-public-key-hex HEX64 --genesis-time-unix-secs UNIX_SECONDS --data-dir ABSOLUTE_PATH --noise-private-key-file NPK1 --reference-time-policy-file RTP1_FILE --reference-time-admin-public-key-hex HEX64 --reference-time-address IP:PORT --reference-time-state-file ABSOLUTE_FILE\n\
Mainnet: qrun_v05_pow_local_node --mainnet --network-id-hex HEX64 --owner-account-id-hex HEX64 --owner-public-key-hex HEX64 --genesis-time-unix-secs UNIX_SECONDS --data-dir ABSOLUTE_PATH --noise-private-key-file NPK1 --reference-time-policy-file RTP1_FILE --reference-time-admin-public-key-hex HEX64 --reference-time-address IP:PORT --reference-time-state-file ABSOLUTE_FILE --peer IP:PORT --peer-static-public-key-hex HEX64 --sync-on-start true\n\
Authenticated public time: every public node must use the same signed RTP1 policy bytes, policy-admin key and numeric authority IP:PORT. Keep the --reference-time-state-file outside --data-dir and the External-CAS floor; it stores a durable sequence rollback floor. The signed TMA1 authority sample is a configured time oracle, not a Byzantine consensus clock. Local-testnet may omit these options and use its OS clock.\n\
External CAS (QFP5 only): add --external-cas-endpoint IP:PORT --external-cas-provider-id-hex HEX64 --external-cas-genesis-id-hex HEX64 --external-cas-noise-server-static-public-key-hex HEX64 --external-cas-noise-private-key-file NPK1 --external-cas-receipt-key-id-hex HEX64 --external-cas-receipt-public-key-file RAW_MLDSA65_PUBLIC_KEY --external-cas-bootstrap-record-file ECR1_FILE --external-cas-floor-dir ABSOLUTE_SEPARATE_DIRECTORY. Keep the floor directory outside --data-dir and back it up separately. On first install, set --external-cas-initialize-floor true to create the QCF1 floor from the out-of-band generation-zero bootstrap; keep it true on later starts (existing floors are reopened, missing-after-initialization remains fatal). External-CAS options are all-or-none; no local fallback occurs after provider config is supplied. Optional checkpoint bootstrap requires all four: --external-cas-checkpoint-file QRCP_FILE --external-cas-checkpoint-commitment-hex HEX64 --external-cas-checkpoint-min-height HEIGHT --external-cas-checkpoint-parent-commitment-hex HEX64. The ECR1 bootstrap must already anchor the exact checkpoint-rooted PFS2 manifest; this does not perform a live CAS manifest rebase/rollover. Explicit operator recovery is opt-in only: add --external-cas-recover-qrm1 true --external-cas-history-archive-root ABSOLUTE_EXISTING_DIRECTORY. Recovery requires an existing QCF1 floor and derives the replacement checkpoint from the verified QRM1/QRA1 journal; do not pass --external-cas-initialize-floor true or checkpoint bootstrap options in this mode. Ordinary startup never runs QRM1 recovery.\nMainnet also requires --sync-on-start true, non-loopback pinned peers, and frozen identity checks. RPC/transaction ingress stay loopback-only. Optional first migration from an existing Genesis-rooted QFP5 PFS2 store: add --external-cas-migrate-genesis-checkpoint true --external-cas-history-archive-root ABSOLUTE_EXISTING_DIRECTORY --external-cas-checkpoint-output-file ABSOLUTE_QRCP_FILE --external-cas-migration-parent-commitment-hex HEX64. The independent provider and matching generation-zero ECR1/QCF1 bootstrap must already be provisioned. This is a one-time explicit operation; repeated checkpoint rollover is not supported by this command. If recovery is needed after an ambiguous failure, rerun with --external-cas-recover-qrm1 true and the same archive root instead of the migration flag. IMPORTANT: this candidate build keeps --mainnet blocked until production consensus, full-history and repeated-checkpoint recovery, authenticated external peer reachability, and adversarial multi-host transaction/reorg/restart tests are complete."
        );
        return Err("__help__".into());
    }
    let local_testnet = args.iter().any(|arg| arg == "--local-testnet");
    let public_alpha_mode = args.iter().any(|arg| arg == "--public-alpha");
    let mainnet = args.iter().any(|arg| arg == "--mainnet");
    let mode_count = u8::from(local_testnet) + u8::from(public_alpha_mode) + u8::from(mainnet);
    if mode_count != 1 {
        return Err(
            "choose exactly one mode: --local-testnet, --public-alpha, or --mainnet".into(),
        );
    }
    // Run before parsing paths, reading protected keys, creating data directories, or binding sockets.
    validate_mainnet_release_gate(mainnet)?;
    let public_network = public_alpha_mode || mainnet;
    if args
        .iter()
        .filter(|arg| {
            !matches!(
                arg.as_str(),
                "--local-testnet" | "--public-alpha" | "--mainnet"
            )
        })
        .count()
        % 2
        != 0
    {
        return Err("options must be --name value pairs".into());
    }
    let mut values = BTreeMap::<String, String>::new();
    let mut peers = Vec::new();
    let mut peer_static_public_keys = Vec::new();
    let mut index = 0;
    while index < args.len() {
        let key = &args[index];
        if key == "--local-testnet" || key == "--public-alpha" || key == "--mainnet" {
            index += 1;
            continue;
        }
        if !key.starts_with("--") {
            return Err(format!("unexpected argument {key}"));
        }
        let value = args
            .get(index + 1)
            .ok_or_else(|| format!("missing value for {key}"))?;
        if value.starts_with("--") {
            return Err(format!("missing value for {key}"));
        }
        if key == "--peer" {
            peers.push(parse_socket(value, "--peer", public_network)?);
        } else if key == "--peer-static-public-key-hex" {
            peer_static_public_keys.push(parse_hex32(value, "peer static public key")?);
        } else if values.insert(key.clone(), value.clone()).is_some() {
            return Err(format!("duplicate option {key}"));
        }
        index += 2;
    }
    let allowed = [
        "--network-id-hex",
        "--owner-account-id-hex",
        "--producer-account-id-hex",
        "--owner-public-key-hex",
        "--genesis-time-unix-secs",
        "--data-dir",
        "--rpc-listen",
        "--tx-listen",
        "--block-listen",
        "--noise-private-key-file",
        "--sync-on-start",
        "--d1-evidence",
        "--d2-partition-qualification",
        "--external-cas-endpoint",
        "--external-cas-provider-id-hex",
        "--external-cas-genesis-id-hex",
        "--external-cas-noise-server-static-public-key-hex",
        "--external-cas-noise-private-key-file",
        "--external-cas-receipt-key-id-hex",
        "--external-cas-receipt-public-key-file",
        "--external-cas-bootstrap-record-file",
        "--external-cas-floor-dir",
        "--external-cas-initialize-floor",
        "--external-cas-recover-qrm1",
        "--external-cas-history-archive-root",
        "--external-cas-migrate-genesis-checkpoint",
        "--external-cas-checkpoint-output-file",
        "--external-cas-migration-parent-commitment-hex",
        "--external-cas-checkpoint-file",
        "--external-cas-checkpoint-commitment-hex",
        "--external-cas-checkpoint-min-height",
        "--external-cas-checkpoint-parent-commitment-hex",
        "--reference-time-policy-file",
        "--reference-time-admin-public-key-hex",
        "--reference-time-address",
        "--reference-time-state-file",
    ];
    if let Some(key) = values.keys().find(|key| !allowed.contains(&key.as_str())) {
        return Err(format!("unknown option {key}"));
    }
    let required = |key: &str| {
        values
            .get(key)
            .map(String::as_str)
            .ok_or_else(|| format!("required option missing: {key}"))
    };
    let network_id = parse_hex32(required("--network-id-hex")?, "network ID")?;
    let owner_account = parse_hex32(required("--owner-account-id-hex")?, "owner account ID")?;
    let producer_account = values
        .get("--producer-account-id-hex")
        .map(|value| parse_hex32(value, "producer account ID"))
        .transpose()?
        .unwrap_or(owner_account);
    let owner_public_key = parse_hex32(required("--owner-public-key-hex")?, "owner public key")?;
    if network_id.iter().all(|byte| *byte == 0)
        || owner_account.iter().all(|byte| *byte == 0)
        || producer_account.iter().all(|byte| *byte == 0)
        || owner_public_key.iter().all(|byte| *byte == 0)
    {
        return Err("network, owner, and producer identifiers must be nonzero".into());
    }
    // Mainnet remains release-gated above, but its parser contract must already require the
    // exact shared epoch so opening the release gate cannot silently select legacy Genesis.
    let genesis_timestamp = parse_genesis_timestamp_option(&values, public_alpha_mode, mainnet)?;
    if account_id_from_public_key(&owner_public_key) != owner_account {
        return Err("owner account ID does not match owner public key".into());
    }
    VerifyingKey::from_bytes(&owner_public_key)
        .map_err(|_| "owner public key is invalid".to_string())?;
    if mainnet
        && (network_id != QZXB_MAINNET_NETWORK_ID
            || owner_account != QZXB_MAINNET_OWNER_ACCOUNT_ID
            || owner_public_key != QZXB_MAINNET_OWNER_PUBLIC_KEY)
    {
        return Err(
            "--mainnet requires the frozen wallet-bound QZXB network ID, owner account and public key"
                .into(),
        );
    }
    let data_dir = PathBuf::from(required("--data-dir")?);
    if !data_dir.is_absolute() || data_dir.file_name().is_none() {
        return Err("--data-dir must be an absolute path with a final directory name".into());
    }
    let rpc_listen = parse_socket(
        values
            .get("--rpc-listen")
            .map(String::as_str)
            .unwrap_or("127.0.0.1:49339"),
        "--rpc-listen",
        false,
    )?;
    let tx_listen = parse_socket(
        values
            .get("--tx-listen")
            .map(String::as_str)
            .unwrap_or("127.0.0.1:49340"),
        "--tx-listen",
        false,
    )?;
    let default_block_listen = if public_network {
        "0.0.0.0:49341"
    } else {
        "127.0.0.1:49341"
    };
    let block_listen = parse_socket(
        values
            .get("--block-listen")
            .map(String::as_str)
            .unwrap_or(default_block_listen),
        "--block-listen",
        public_network,
    )?;
    if rpc_listen == tx_listen || rpc_listen == block_listen || tx_listen == block_listen {
        return Err(
            "RPC, transaction ingress, and block listeners must use different sockets".into(),
        );
    }
    if peers.iter().any(|peer| *peer == block_listen) {
        return Err("a node cannot list its own block listener as a peer".into());
    }
    for (index, peer) in peers.iter().enumerate() {
        if peers.iter().skip(index + 1).any(|other| other == peer) {
            return Err("peer socket list must be duplicate-free".into());
        }
    }
    let noise_private_key_file = values.get("--noise-private-key-file").map(PathBuf::from);
    let sync_on_start = match values
        .get("--sync-on-start")
        .map(String::as_str)
        .unwrap_or("false")
    {
        "true" => true,
        "false" => false,
        _ => return Err("--sync-on-start must be exactly true or false".into()),
    };
    let d1_evidence = match values
        .get("--d1-evidence")
        .map(String::as_str)
        .unwrap_or("false")
    {
        "true" => true,
        "false" => false,
        _ => return Err("--d1-evidence must be exactly true or false".into()),
    };
    let d2_partition_qualification = match values
        .get("--d2-partition-qualification")
        .map(String::as_str)
        .unwrap_or("false")
    {
        "true" => true,
        "false" => false,
        _ => return Err("--d2-partition-qualification must be exactly true or false".into()),
    };
    if d1_evidence
        && (!public_alpha_mode
            || noise_private_key_file.is_none()
            || peers.len() != 1
            || peer_static_public_keys.len() != 1)
    {
        return Err(
            "--d1-evidence is restricted to one mutually Noise-authenticated, statically pinned Public Alpha peer".into(),
        );
    }
    if d2_partition_qualification
        && (!d1_evidence
            || !public_alpha_mode
            || noise_private_key_file.is_none()
            || peers.len() != 1
            || peer_static_public_keys.len() != 1)
    {
        return Err(
            "--d2-partition-qualification requires D1 evidence and one pinned Noise peer in Public Alpha".into(),
        );
    }
    validate_sync_start_config(
        sync_on_start,
        noise_private_key_file.is_some(),
        peers.len(),
        peer_static_public_keys.len(),
    )?;
    validate_mainnet_p2p_requirements(
        mainnet,
        sync_on_start,
        &peers,
        peer_static_public_keys.len(),
        block_listen,
    )?;
    if public_network && noise_private_key_file.is_none() {
        return Err(
            "--public-alpha requires --noise-private-key-file; plaintext public peer transport is forbidden".into(),
        );
    }
    if noise_private_key_file.is_some() {
        let pin_count_mismatch = if public_network {
            !peer_static_public_keys.is_empty() && peer_static_public_keys.len() != peers.len()
        } else {
            peer_static_public_keys.len() != peers.len() || peers.is_empty()
        };
        if pin_count_mismatch {
            return Err("local-testnet requires one static-key pin for every configured peer; public-alpha may omit all outbound pins or provide one for every peer".into());
        }
        if peer_static_public_keys
            .iter()
            .any(|key| key.iter().all(|byte| *byte == 0))
        {
            return Err("peer static public keys must be nonzero".into());
        }
        for (index, key) in peer_static_public_keys.iter().enumerate() {
            if peer_static_public_keys
                .iter()
                .skip(index + 1)
                .any(|other| other == key)
            {
                return Err("peer static public keys must be unique".into());
            }
        }
    } else if !peer_static_public_keys.is_empty() {
        return Err("--peer-static-public-key-hex requires --noise-private-key-file".into());
    }
    let external_cas = parse_external_cas_config(&values, public_network)?;
    let reference_time = parse_reference_time_node_config(&values, public_network)?;
    if let Some(reference_time) = &reference_time {
        if paths_overlap(&data_dir, &reference_time.state_file) {
            return Err(
                "--reference-time-state-file must be outside --data-dir so chain rollback cannot roll back the reference-time high-water"
                    .into(),
            );
        }
        if let Some(external) = &external_cas {
            if paths_overlap(&external.floor_directory, &reference_time.state_file) {
                return Err(
                    "--reference-time-state-file must be separate from the External-CAS QCF1 floor"
                        .into(),
                );
            }
        }
    }
    if mainnet && external_cas.is_none() {
        return Err("--mainnet requires an explicitly pinned external-CAS provider".into());
    }
    if let Some(external) = &external_cas {
        if paths_overlap(&data_dir, &external.floor_directory) {
            return Err(
                "--external-cas-floor-dir must not overlap --data-dir; keep the floor in a separately managed directory"
                    .into(),
            );
        }
    }
    Ok(Config {
        public_alpha: public_network,
        mainnet,
        network_id,
        owner_account,
        producer_account,
        owner_public_key,
        genesis_timestamp,
        data_dir,
        rpc_listen,
        tx_listen,
        block_listen,
        peers,
        noise_private_key_file,
        peer_static_public_keys,
        sync_on_start,
        d1_evidence,
        d2_partition_qualification,
        external_cas,
        reference_time,
    })
}

fn profile_id(
    network_id: &NetworkId,
    params: &ConsensusParameters,
    genesis_commitment: &[u8; 32],
) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(PROFILE_DOMAIN);
    hash.update(network_id);
    hash.update(genesis_commitment);
    hash.update(params.protocol_version.to_be_bytes());
    hash.update(params.target_block_time_secs.to_be_bytes());
    hash.update(params.difficulty_window_blocks.to_be_bytes());
    hash.update(params.difficulty_min_ratio_divisor.to_be_bytes());
    hash.update(params.difficulty_max_ratio.to_be_bytes());
    hash.update(params.pow_limit.to_be_bytes());
    hash.update(params.initial_target.to_be_bytes());
    hash.update(match params.pow.algorithm {
        PowAlgorithm::Argon2id => [1u8],
        PowAlgorithm::Sha256d => [2u8],
    });
    hash.update(params.pow.memory_kib.to_be_bytes());
    hash.update(params.pow.iterations.to_be_bytes());
    hash.update(params.pow.lanes.to_be_bytes());
    hash.update([params.pow.output_bytes]);
    hash.update(params.issuance.maximum_supply().to_be_bytes());
    hash.update(params.issuance.initial_subsidy().to_be_bytes());
    hash.update(params.issuance.blocks_per_halving().to_be_bytes());
    hash.finalize().into()
}

fn profile_id_with_reference_time_policy(
    network_id: &NetworkId,
    params: &ConsensusParameters,
    genesis_commitment: &[u8; 32],
    reference_time_policy_digest: Option<[u8; 32]>,
) -> [u8; 32] {
    let base_profile = profile_id(network_id, params, genesis_commitment);
    let Some(policy_digest) = reference_time_policy_digest else {
        return base_profile;
    };
    let mut hash = Sha256::new();
    hash.update(b"QUANTUMZXB-QRUN-V05-TIME-POLICY-BOUND-PROFILE-V1\0");
    hash.update(base_profile);
    hash.update(policy_digest);
    hash.finalize().into()
}

#[cfg(test)]
fn now_unix() -> Result<u64, String> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "system clock is before Unix epoch".to_string())?
        .as_secs())
}

fn response_json(value: &Value) -> Vec<u8> {
    let body = serde_json::to_vec(value).unwrap_or_else(|_| b"{\"ok\":false}".to_vec());
    let header = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let mut bytes = Vec::with_capacity(header.len() + body.len());
    bytes.extend_from_slice(header.as_bytes());
    bytes.extend_from_slice(&body);
    bytes
}

fn handle_rpc(stream: &mut TcpStream, state: &Arc<Mutex<NodeState>>) -> Result<(), String> {
    // Listener sockets are nonblocking for the node poll loop. On Windows an accepted
    // stream can retain that mode, so normalize it before synchronous request reads.
    stream
        .set_nonblocking(false)
        .map_err(|error| error.to_string())?;
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .map_err(|error| error.to_string())?;
    stream
        .set_write_timeout(Some(Duration::from_secs(3)))
        .map_err(|error| error.to_string())?;
    let mut request = vec![0u8; MAX_HTTP_REQUEST];
    let count = stream
        .read(&mut request)
        .map_err(|error| error.to_string())?;
    if count == 0 || count == MAX_HTTP_REQUEST {
        return Err("empty or oversized HTTP request".into());
    }
    let text = std::str::from_utf8(&request[..count]).map_err(|_| "HTTP request is not UTF-8")?;
    let line = text.lines().next().ok_or("missing HTTP request line")?;
    let mut parts = line.split_whitespace();
    let method = parts.next();
    let path = parts.next().unwrap_or("/");
    let version = parts.next();
    if method != Some("GET") || version != Some("HTTP/1.1") {
        return Err("only HTTP/1.1 GET is supported by read-only RPC".into());
    }
    if path.contains('?') || path.contains('#') || path.contains("..") || path.contains('%') {
        return Err("invalid RPC path".into());
    }
    let locked = state
        .lock()
        .map_err(|_| "node state lock poisoned".to_string())?;
    let height = locked.runtime.canonical_height();
    let tip = hex(&locked.runtime.canonical_tip());
    let root = hex(&locked.runtime.canonical_state_root());
    let network = hex(&locked.runtime.network_id());
    let genesis = hex(&locked.runtime.genesis_commitment());
    let profile = hex(&locked.profile_id);
    let mainnet = locked.mainnet;
    let network_class = if mainnet {
        "qzxb_mainnet"
    } else if locked.public_alpha {
        "public_alpha_experimental_not_mainnet"
    } else {
        "local_loopback_pow_testnet_not_public"
    };
    let value = if path == "/v1/status" {
        json!({
            "ok": true, "mainnet": mainnet, "read_only": true,
            "network_id": network, "genesis_id": genesis, "profile_id": profile,
            "height": height, "tip": tip, "state_root": root, "generation": 0,
            "network_class": network_class,
            "consensus": "candidate_argon2id_pow_pfs2_persistent_fork_choice"
        })
    } else if let Some(account_text) = path.strip_prefix("/v1/balance/") {
        match parse_hex32(account_text, "account ID") {
            Ok(account) => json!({
                "ok": true, "mainnet": mainnet, "read_only": true,
                "account_id": hex(&account),
                "balance_atoms": locked.runtime.canonical_state().account(&account).map_or(0, |a| a.balance),
                "nonce": locked.runtime.canonical_state().account(&account).map_or(0, |a| a.nonce),
                "height": height, "tip": tip, "state_root": root,
                "network_id": network, "genesis_id": genesis,
                "network_class": network_class
            }),
            Err(_) => {
                json!({"ok": false, "mainnet": mainnet, "read_only": true, "error": "invalid account ID"})
            }
        }
    } else if let Some(txid_text) = path.strip_prefix("/v1/transaction/") {
        match parse_hex32(txid_text, "transaction ID") {
            Ok(txid) => {
                if let Some(receipt) = locked.receipts.get(&txid) {
                    json!({
                        "ok": true, "mainnet": mainnet, "read_only": true, "txid": hex(&txid),
                        "status": "confirmed", "confirmations": height.saturating_sub(receipt.height) + 1,
                        "block_height": receipt.height, "search_floor_height": 0,
                        "height": height, "tip": tip, "state_root": root, "network_class": network_class
                    })
                } else {
                    json!({
                        "ok": true, "mainnet": mainnet, "read_only": true, "txid": hex(&txid),
                        "status": "not_found_in_canonical_chain", "confirmations": 0,
                        "block_height": Value::Null, "search_floor_height": 0,
                        "height": height, "tip": tip, "state_root": root, "network_class": network_class
                    })
                }
            }
            Err(_) => {
                json!({"ok": false, "mainnet": mainnet, "read_only": true, "error": "invalid transaction ID"})
            }
        }
    } else {
        json!({"ok": false, "mainnet": mainnet, "read_only": true, "error": "unsupported endpoint"})
    };
    if serde_json::to_vec(&value).map_or(MAX_HTTP_RESPONSE + 1, |bytes| bytes.len())
        > MAX_HTTP_RESPONSE
    {
        return Err("RPC response exceeded size cap".into());
    }
    stream
        .write_all(&response_json(&value))
        .map_err(|error| error.to_string())
}

fn poll_rpc_listener(
    listener: &TcpListener,
    state: &Arc<Mutex<NodeState>>,
) -> Result<bool, String> {
    match listener.accept() {
        Ok((mut stream, _)) => {
            if let Err(error) = handle_rpc(&mut stream, state) {
                eprintln!(
                    "qrun_pow_local_rpc_request_rejected reason={}",
                    error.replace(['\r', '\n'], "_")
                );
            }
            Ok(true)
        }
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => Ok(false),
        Err(error) => Err(format!("RPC listener accept failed: {error}")),
    }
}

fn block_id(envelope: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"QRUN-LOCAL-POW-ENVELOPE-ID-V1\0");
    hash.update(envelope);
    hash.finalize().into()
}

fn encode_block_frame(envelope: &[u8]) -> Result<Vec<u8>, String> {
    if envelope.is_empty()
        || envelope.len() > MAX_BLOCK_FRAME_BYTES
        || envelope.len() > u32::MAX as usize
    {
        return Err("QRun PTB2 envelope exceeds bounded gossip frame".into());
    }
    let mut frame = Vec::with_capacity(BLOCK_FRAME_HEADER_BYTES + envelope.len());
    frame.extend_from_slice(BLOCK_MAGIC);
    frame.extend_from_slice(&BLOCK_PROTOCOL_VERSION.to_be_bytes());
    frame.extend_from_slice(&(envelope.len() as u32).to_be_bytes());
    frame.extend_from_slice(envelope);
    Ok(frame)
}

fn decode_block_frame(frame: &[u8]) -> Result<Vec<u8>, String> {
    if frame.len() < BLOCK_FRAME_HEADER_BYTES {
        return Err("truncated QRun PoW frame".into());
    }
    let header = &frame[..BLOCK_FRAME_HEADER_BYTES];
    if &header[..4] != BLOCK_MAGIC
        || u16::from_be_bytes([header[4], header[5]]) != BLOCK_PROTOCOL_VERSION
    {
        return Err("invalid QRun PoW frame magic/version".into());
    }
    let payload_len = u32::from_be_bytes(header[6..10].try_into().unwrap()) as usize;
    if payload_len == 0
        || payload_len > MAX_BLOCK_FRAME_BYTES
        || frame.len() != BLOCK_FRAME_HEADER_BYTES + payload_len
    {
        return Err("invalid or oversized QRun PTB2 frame".into());
    }
    Ok(frame[BLOCK_FRAME_HEADER_BYTES..].to_vec())
}

#[derive(Debug)]
struct CanonicalSyncResponse {
    base_height: u64,
    height: u64,
    base_tip: [u8; 32],
    canonical_tip: [u8; 32],
    state_root: [u8; 32],
    envelopes: Vec<Vec<u8>>,
}

fn max_sync_response_block_bytes(max_blocks: usize) -> Result<usize, String> {
    if max_blocks == 0 || max_blocks > MAX_SYNC_PAGE_BLOCKS {
        return Err("canonical sync page block count is outside the allowed range".into());
    }
    MAX_NOISE_APPLICATION_RECORD_BYTES
        .checked_sub(SYNC_RESPONSE_HEADER_BYTES + 4 * max_blocks)
        .ok_or_else(|| "canonical sync page budget underflows the Noise record bound".into())
}

fn encode_sync_request(
    start_height: u64,
    max_blocks: usize,
    max_bytes: usize,
    expected_snapshot: Option<(u64, [u8; 32])>,
) -> Result<Vec<u8>, String> {
    let max_record_bytes = max_sync_response_block_bytes(max_blocks)?;
    if start_height == 0
        || max_bytes == 0
        || max_bytes > max_record_bytes
        || max_bytes > u32::MAX as usize
    {
        return Err("canonical sync request is outside the allowed height/size bounds".into());
    }
    let mut request = Vec::with_capacity(SYNC_REQUEST_BYTES);
    request.extend_from_slice(SYNC_REQUEST_MAGIC);
    request.extend_from_slice(&SYNC_PROTOCOL_VERSION.to_be_bytes());
    request.extend_from_slice(&start_height.to_be_bytes());
    request.extend_from_slice(&(max_blocks as u16).to_be_bytes());
    request.extend_from_slice(&(max_bytes as u32).to_be_bytes());
    match expected_snapshot {
        Some((height, tip)) => {
            request.push(1);
            request.extend_from_slice(&height.to_be_bytes());
            request.extend_from_slice(&tip);
        }
        None => {
            request.push(0);
            request.extend_from_slice(&0u64.to_be_bytes());
            request.extend_from_slice(&[0u8; 32]);
        }
    }
    Ok(request)
}

fn decode_sync_request(
    request: &[u8],
) -> Result<(u64, usize, usize, Option<(u64, [u8; 32])>), String> {
    if request.len() != SYNC_REQUEST_BYTES
        || &request[..4] != SYNC_REQUEST_MAGIC
        || u16::from_be_bytes([request[4], request[5]]) != SYNC_PROTOCOL_VERSION
    {
        return Err("invalid canonical sync request magic/version/length".into());
    }
    let start_height = u64::from_be_bytes(request[6..14].try_into().unwrap());
    let max_blocks = u16::from_be_bytes([request[14], request[15]]) as usize;
    let max_bytes = u32::from_be_bytes(request[16..20].try_into().unwrap()) as usize;
    let snapshot_height = u64::from_be_bytes(request[21..29].try_into().unwrap());
    let snapshot_tip: [u8; 32] = request[29..61].try_into().unwrap();
    let expected_snapshot = match request[20] {
        0 if snapshot_height == 0 && snapshot_tip == [0u8; 32] => None,
        1 => Some((snapshot_height, snapshot_tip)),
        _ => return Err("canonical sync request has an invalid snapshot pin".into()),
    };
    encode_sync_request(start_height, max_blocks, max_bytes, expected_snapshot)?;
    Ok((start_height, max_blocks, max_bytes, expected_snapshot))
}

fn validate_sync_snapshot_pin(
    expected: Option<(u64, [u8; 32])>,
    actual_height: u64,
    actual_tip: [u8; 32],
) -> Result<(), String> {
    if let Some((expected_height, expected_tip)) = expected {
        if actual_height != expected_height || actual_tip != expected_tip {
            return Err(format!(
                "authenticated sync peer changed canonical snapshot during pagination (expected height {expected_height}, received {actual_height})"
            ));
        }
    }
    Ok(())
}
fn encode_sync_response(
    base_height: u64,
    height: u64,
    base_tip: [u8; 32],
    canonical_tip: [u8; 32],
    state_root: [u8; 32],
    envelopes: &[Vec<u8>],
) -> Result<Vec<u8>, String> {
    if envelopes.len() > MAX_SYNC_PAGE_BLOCKS {
        return Err("canonical sync response has too many blocks".into());
    }
    let mut response = Vec::with_capacity(SYNC_RESPONSE_HEADER_BYTES);
    response.extend_from_slice(SYNC_RESPONSE_MAGIC);
    response.extend_from_slice(&SYNC_PROTOCOL_VERSION.to_be_bytes());
    response.extend_from_slice(&base_height.to_be_bytes());
    response.extend_from_slice(&height.to_be_bytes());
    response.extend_from_slice(&base_tip);
    response.extend_from_slice(&canonical_tip);
    response.extend_from_slice(&state_root);
    response.extend_from_slice(&(envelopes.len() as u16).to_be_bytes());
    for envelope in envelopes {
        if envelope.is_empty() || envelope.len() > u32::MAX as usize {
            return Err("canonical sync response has an invalid envelope length".into());
        }
        response.extend_from_slice(&(envelope.len() as u32).to_be_bytes());
        response.extend_from_slice(envelope);
        if response.len() > MAX_NOISE_APPLICATION_RECORD_BYTES {
            return Err("canonical sync response exceeds the bounded Noise record size".into());
        }
    }
    Ok(response)
}

fn decode_sync_response(
    response: &[u8],
    max_blocks: usize,
    max_bytes: usize,
) -> Result<CanonicalSyncResponse, String> {
    let allowed_bytes = max_sync_response_block_bytes(max_blocks)?.min(max_bytes);
    if response.len() < SYNC_RESPONSE_HEADER_BYTES
        || response.len() > MAX_NOISE_APPLICATION_RECORD_BYTES
        || &response[..4] != SYNC_RESPONSE_MAGIC
        || u16::from_be_bytes([response[4], response[5]]) != SYNC_PROTOCOL_VERSION
    {
        return Err("invalid canonical sync response magic/version/length".into());
    }
    let base_height = u64::from_be_bytes(response[6..14].try_into().unwrap());
    let height = u64::from_be_bytes(response[14..22].try_into().unwrap());
    let base_tip: [u8; 32] = response[22..54].try_into().unwrap();
    let canonical_tip: [u8; 32] = response[54..86].try_into().unwrap();
    let state_root: [u8; 32] = response[86..118].try_into().unwrap();
    let count = u16::from_be_bytes([response[118], response[119]]) as usize;
    if count > max_blocks || count > MAX_SYNC_PAGE_BLOCKS || base_height > height {
        return Err("canonical sync response violates the requested bounds".into());
    }
    let mut offset = SYNC_RESPONSE_HEADER_BYTES;
    let mut total_bytes = 0usize;
    let mut envelopes = Vec::with_capacity(count);
    for _ in 0..count {
        let length_end = offset
            .checked_add(4)
            .ok_or("sync response length overflow")?;
        if length_end > response.len() {
            return Err("truncated canonical sync envelope length".into());
        }
        let length = u32::from_be_bytes(response[offset..length_end].try_into().unwrap()) as usize;
        offset = length_end;
        if length == 0 {
            return Err("canonical sync response contains an empty block envelope".into());
        }
        let envelope_end = offset
            .checked_add(length)
            .ok_or("sync response length overflow")?;
        if envelope_end > response.len() {
            return Err("truncated canonical sync block envelope".into());
        }
        total_bytes = total_bytes
            .checked_add(length)
            .ok_or("sync response byte budget overflow")?;
        if total_bytes > allowed_bytes {
            return Err("canonical sync response exceeds its requested byte budget".into());
        }
        envelopes.push(response[offset..envelope_end].to_vec());
        offset = envelope_end;
    }
    if offset != response.len() {
        return Err("canonical sync response contains trailing bytes".into());
    }
    if count > 0 && height < base_height.saturating_add(count as u64) {
        return Err("canonical sync response range extends beyond its advertised tip".into());
    }
    Ok(CanonicalSyncResponse {
        base_height,
        height,
        base_tip,
        canonical_tip,
        state_root,
        envelopes,
    })
}

fn serve_sync_request(
    request: &[u8],
    session: &mut QRunV05NoiseSession,
    stream: &mut TcpStream,
    state: &Arc<Mutex<NodeState>>,
) -> Result<(), String> {
    let (start_height, max_blocks, max_bytes, expected_snapshot) = decode_sync_request(request)?;
    let (base_height, height, base_tip, canonical_tip, state_root, envelopes) = {
        let locked = state
            .lock()
            .map_err(|_| "node state lock poisoned".to_string())?;
        let (height, canonical_tip, state_root) = match expected_snapshot {
            Some((expected_height, expected_tip)) => {
                let (retained_height, retained_state_root, _) = locked
                    .runtime
                    .archived_branch_summary(&expected_tip)
                    .ok_or("requested authenticated sync snapshot is no longer retained")?;
                if retained_height != expected_height {
                    return Err(
                        "requested authenticated sync snapshot height differs from retained branch"
                            .into(),
                    );
                }
                (retained_height, expected_tip, retained_state_root)
            }
            None => (
                locked.runtime.canonical_height(),
                locked.runtime.canonical_tip(),
                locked.runtime.canonical_state_root(),
            ),
        };
        let envelopes = locked
            .runtime
            .archived_branch_envelopes_range(&canonical_tip, start_height, max_blocks, max_bytes)
            .map_err(|error| format!("export retained sync snapshot range: {error:?}"))?;
        (
            locked.runtime.archive_base_height(),
            height,
            locked.runtime.archive_base_tip(),
            canonical_tip,
            state_root,
            envelopes,
        )
    };
    let response = encode_sync_response(
        base_height,
        height,
        base_tip,
        canonical_tip,
        state_root,
        &envelopes,
    )?;
    session
        .write_record(stream, &response)
        .map_err(|error| format!("write encrypted canonical sync response: {error}"))?;
    println!(
        "qrun_pow_local_canonical_sync_served start_height={start_height} count={} tip_height={height} base_height={base_height}",
        envelopes.len()
    );
    Ok(())
}
fn block_ack(status: u8, height: u64, hash: [u8; 32]) -> [u8; BLOCK_ACK_BYTES] {
    let mut ack = [0u8; BLOCK_ACK_BYTES];
    ack[..4].copy_from_slice(BLOCK_ACK_MAGIC);
    ack[4..6].copy_from_slice(&BLOCK_PROTOCOL_VERSION.to_be_bytes());
    ack[6] = status;
    ack[7..15].copy_from_slice(&height.to_be_bytes());
    ack[15..47].copy_from_slice(&hash);
    ack
}

const D1_ACK_MAGIC: &[u8; 4] = b"QDE5";
const D1_ACK_VERSION: u16 = 1;
const D1_ACK_FIXED_BYTES: usize = 4 + 2 + 32 + 32 + 8 + 32 + 32 + 32 + 2;
const D1_ACK_RECEIPT_BYTES: usize = 32 + 8;
const D1_ACK_MAX_BYTES: usize =
    D1_ACK_FIXED_BYTES + MAX_TRANSACTIONS_PER_BLOCK * D1_ACK_RECEIPT_BYTES;

#[derive(Clone, Debug, PartialEq, Eq)]
struct D1BlockAckEvidence {
    network_id: NetworkId,
    profile_id: [u8; 32],
    canonical_height: u64,
    canonical_tip: [u8; 32],
    state_root: [u8; 32],
    accepted_block_id: [u8; 32],
    confirmed_receipts: Vec<([u8; 32], u64)>,
}

fn encode_d1_block_ack_evidence(evidence: &D1BlockAckEvidence) -> Result<Vec<u8>, String> {
    if evidence.network_id.iter().all(|byte| *byte == 0)
        || evidence.profile_id.iter().all(|byte| *byte == 0)
        || evidence.canonical_tip.iter().all(|byte| *byte == 0)
        || evidence.state_root.iter().all(|byte| *byte == 0)
        || evidence.accepted_block_id.iter().all(|byte| *byte == 0)
        || evidence.canonical_height == 0
        || evidence.confirmed_receipts.len() > MAX_TRANSACTIONS_PER_BLOCK
    {
        return Err(
            "D1 evidence contains an invalid identity, canonical tuple, or receipt count".into(),
        );
    }
    if evidence.canonical_tip != evidence.accepted_block_id {
        return Err(format!(
            "D1 receiver tip {} differs from accepted QFP5 block ID {}",
            hex(&evidence.canonical_tip),
            hex(&evidence.accepted_block_id)
        ));
    }
    let mut seen = BTreeSet::new();
    for (txid, height) in &evidence.confirmed_receipts {
        if txid.iter().all(|byte| *byte == 0)
            || *height == 0
            || *height > evidence.canonical_height
            || !seen.insert(*txid)
        {
            return Err(
                "D1 evidence contains an invalid, future, or duplicate canonical receipt".into(),
            );
        }
    }
    let count = u16::try_from(evidence.confirmed_receipts.len())
        .map_err(|_| "D1 evidence receipt count overflow")?;
    let mut bytes = Vec::with_capacity(
        D1_ACK_FIXED_BYTES + evidence.confirmed_receipts.len() * D1_ACK_RECEIPT_BYTES,
    );
    bytes.extend_from_slice(D1_ACK_MAGIC);
    bytes.extend_from_slice(&D1_ACK_VERSION.to_be_bytes());
    bytes.extend_from_slice(&evidence.network_id);
    bytes.extend_from_slice(&evidence.profile_id);
    bytes.extend_from_slice(&evidence.canonical_height.to_be_bytes());
    bytes.extend_from_slice(&evidence.canonical_tip);
    bytes.extend_from_slice(&evidence.state_root);
    bytes.extend_from_slice(&evidence.accepted_block_id);
    bytes.extend_from_slice(&count.to_be_bytes());
    for (txid, height) in &evidence.confirmed_receipts {
        bytes.extend_from_slice(txid);
        bytes.extend_from_slice(&height.to_be_bytes());
    }
    if bytes.len() > D1_ACK_MAX_BYTES {
        return Err("D1 evidence exceeds its fixed bounded record size".into());
    }
    Ok(bytes)
}

fn decode_d1_block_ack_evidence(bytes: &[u8]) -> Result<D1BlockAckEvidence, String> {
    if bytes.len() < D1_ACK_FIXED_BYTES || bytes.len() > D1_ACK_MAX_BYTES {
        return Err("D1 evidence length is outside its bounded range".into());
    }
    if &bytes[..4] != D1_ACK_MAGIC || u16::from_be_bytes([bytes[4], bytes[5]]) != D1_ACK_VERSION {
        return Err("D1 evidence magic or version is invalid".into());
    }
    let mut offset = 6usize;
    let mut take = |length: usize| -> Result<&[u8], String> {
        let end = offset
            .checked_add(length)
            .ok_or("D1 evidence offset overflow")?;
        let value = bytes.get(offset..end).ok_or("D1 evidence is truncated")?;
        offset = end;
        Ok(value)
    };
    let network_id: NetworkId = take(32)?.try_into().map_err(|_| "invalid D1 network ID")?;
    let profile_id: [u8; 32] = take(32)?.try_into().map_err(|_| "invalid D1 profile ID")?;
    let canonical_height = u64::from_be_bytes(
        take(8)?
            .try_into()
            .map_err(|_| "invalid D1 canonical height")?,
    );
    let canonical_tip: [u8; 32] = take(32)?
        .try_into()
        .map_err(|_| "invalid D1 canonical tip")?;
    let state_root: [u8; 32] = take(32)?.try_into().map_err(|_| "invalid D1 state root")?;
    let accepted_block_id: [u8; 32] = take(32)?
        .try_into()
        .map_err(|_| "invalid D1 accepted block ID")?;
    let count = u16::from_be_bytes(
        take(2)?
            .try_into()
            .map_err(|_| "invalid D1 receipt count")?,
    ) as usize;
    if count > MAX_TRANSACTIONS_PER_BLOCK
        || bytes.len() != D1_ACK_FIXED_BYTES + count * D1_ACK_RECEIPT_BYTES
    {
        return Err("D1 evidence receipt count does not match its bounded record length".into());
    }
    let mut confirmed_receipts = Vec::with_capacity(count);
    let mut seen = BTreeSet::new();
    for _ in 0..count {
        let txid: [u8; 32] = take(32)?
            .try_into()
            .map_err(|_| "invalid D1 receipt TXID")?;
        let height = u64::from_be_bytes(
            take(8)?
                .try_into()
                .map_err(|_| "invalid D1 receipt height")?,
        );
        if txid.iter().all(|byte| *byte == 0)
            || height == 0
            || height > canonical_height
            || !seen.insert(txid)
        {
            return Err(
                "D1 evidence contains an invalid, future, or duplicate canonical receipt".into(),
            );
        }
        confirmed_receipts.push((txid, height));
    }
    if offset != bytes.len()
        || network_id.iter().all(|byte| *byte == 0)
        || profile_id.iter().all(|byte| *byte == 0)
        || canonical_height == 0
        || canonical_tip.iter().all(|byte| *byte == 0)
        || state_root.iter().all(|byte| *byte == 0)
        || accepted_block_id.iter().all(|byte| *byte == 0)
        || canonical_tip != accepted_block_id
    {
        return Err("D1 evidence contains an incomplete or zero canonical identity tuple".into());
    }
    Ok(D1BlockAckEvidence {
        network_id,
        profile_id,
        canonical_height,
        canonical_tip,
        state_root,
        accepted_block_id,
        confirmed_receipts,
    })
}

fn validate_d1_block_ack_evidence(
    peer: SocketAddr,
    evidence: &D1BlockAckEvidence,
    expected_network_id: &[u8; 32],
    expected_profile_id: &[u8; 32],
    expected_block_height: u64,
    expected_block_id: &[u8; 32],
    expected_txids: &[[u8; 32]],
) -> Result<(), String> {
    if &evidence.network_id != expected_network_id
        || &evidence.profile_id != expected_profile_id
        || evidence.canonical_height != expected_block_height
        || &evidence.canonical_tip != expected_block_id
        || &evidence.accepted_block_id != expected_block_id
    {
        return Err(format!(
            "peer {peer} returned D1 evidence for a different network/profile or an older canonical height"
        ));
    }
    let expected = expected_txids.iter().copied().collect::<BTreeSet<_>>();
    let reported = evidence
        .confirmed_receipts
        .iter()
        .map(|(txid, _)| *txid)
        .collect::<BTreeSet<_>>();
    if expected.len() != expected_txids.len()
        || expected != reported
        || evidence
            .confirmed_receipts
            .iter()
            .any(|(_, receipt_height)| *receipt_height != expected_block_height)
    {
        return Err(format!(
            "peer {peer} did not independently report every exact block TXID as canonical at the received block height"
        ));
    }
    Ok(())
}

fn d1_ack_evidence_for_block(
    state: &NodeState,
    candidate_txids: &[[u8; 32]],
    accepted_block_id: [u8; 32],
) -> D1BlockAckEvidence {
    let confirmed_receipts = candidate_txids
        .iter()
        .filter_map(|txid| {
            state
                .receipts
                .get(txid)
                .map(|receipt| (*txid, receipt.height))
        })
        .collect();
    D1BlockAckEvidence {
        network_id: state.runtime.network_id(),
        profile_id: state.profile_id,
        canonical_height: state.runtime.canonical_height(),
        canonical_tip: state.runtime.canonical_tip(),
        state_root: state.runtime.canonical_state_root(),
        accepted_block_id,
        confirmed_receipts,
    }
}

fn d1_receipt_list(evidence: &D1BlockAckEvidence) -> String {
    evidence
        .confirmed_receipts
        .iter()
        .map(|(txid, height)| format!("{}:{height}", hex(txid)))
        .collect::<Vec<_>>()
        .join(",")
}

#[cfg(test)]
mod d1_ack_evidence_tests {
    use super::*;

    fn sample() -> D1BlockAckEvidence {
        D1BlockAckEvidence {
            network_id: [0x11; 32],
            profile_id: [0x22; 32],
            canonical_height: 2,
            canonical_tip: [0x33; 32],
            state_root: [0x44; 32],
            accepted_block_id: [0x33; 32],
            confirmed_receipts: vec![([0x55; 32], 2)],
        }
    }

    #[test]
    fn d1_evidence_roundtrips_exact_identity_tuple_and_canonical_receipt() {
        let evidence = sample();
        let encoded = encode_d1_block_ack_evidence(&evidence).unwrap();
        assert_eq!(encoded.len(), D1_ACK_FIXED_BYTES + D1_ACK_RECEIPT_BYTES);
        assert_eq!(decode_d1_block_ack_evidence(&encoded).unwrap(), evidence);
    }

    #[test]
    fn d1_evidence_rejects_truncation_trailing_bytes_and_duplicate_receipts() {
        let encoded = encode_d1_block_ack_evidence(&sample()).unwrap();
        assert!(decode_d1_block_ack_evidence(&encoded[..encoded.len() - 1]).is_err());
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(decode_d1_block_ack_evidence(&trailing).is_err());

        let mut duplicate = sample();
        duplicate.confirmed_receipts.push(([0x55; 32], 2));
        assert!(encode_d1_block_ack_evidence(&duplicate).is_err());
    }

    #[test]
    fn d1_evidence_rejects_future_receipt_heights_and_wrong_transaction_sets() {
        let mut future = sample();
        future.confirmed_receipts[0].1 = 3;
        assert!(encode_d1_block_ack_evidence(&future).is_err());

        let evidence = sample();
        assert!(validate_d1_block_ack_evidence(
            "127.0.0.1:49341".parse().unwrap(),
            &evidence,
            &[0x11; 32],
            &[0x22; 32],
            2,
            &[0x33; 32],
            &[[0x55; 32]],
        )
        .is_ok());
        assert!(validate_d1_block_ack_evidence(
            "127.0.0.1:49341".parse().unwrap(),
            &evidence,
            &[0x11; 32],
            &[0x22; 32],
            2,
            &[0x33; 32],
            &[[0x66; 32]],
        )
        .is_err());
        assert!(validate_d1_block_ack_evidence(
            "127.0.0.1:49341".parse().unwrap(),
            &evidence,
            &[0x11; 32],
            &[0x22; 32],
            2,
            &[0x99; 32],
            &[[0x55; 32]],
        )
        .is_err());
    }

    #[test]
    fn d2_partition_exception_only_accepts_the_pinned_peer_tcp_connect_failure() {
        let peer: SocketAddr = "100.100.1.10:49341".parse().unwrap();
        assert!(is_d2_partition_connect_failure(
            peer,
            "connect authenticated block peer 100.100.1.10:49341: connection timed out"
        ));
        assert!(!is_d2_partition_connect_failure(
            peer,
            "Noise XX peer authentication failed: invalid static key"
        ));
        assert!(!is_d2_partition_connect_failure(
            peer,
            "read authenticated D1 receipt/state evidence from 100.100.1.10:49341: truncated record"
        ));
        assert!(!is_d2_partition_connect_failure(
            peer,
            "connect authenticated block peer 100.100.1.11:49341: connection refused"
        ));
    }
}

fn send_block_to_peer_plain(peer: SocketAddr, envelope: &[u8]) -> Result<(), String> {
    if !peer.ip().is_loopback() {
        return Err("peer must be loopback in the local PoW integration profile".into());
    }
    let candidate = decode_candidate_network_block(envelope)
        .map_err(|error| format!("decode PTB2 envelope: {error:?}"))?;
    if candidate.fee_block.is_some() {
        return Err(
            "local loopback PTB2 node refuses QFP5; use the profile-locked QRun path".into(),
        );
    }
    let height = candidate.block.height;
    let expected_hash = block_id(envelope);
    let frame = encode_block_frame(envelope)?;
    let mut stream = TcpStream::connect_timeout(&peer, Duration::from_secs(2))
        .map_err(|error| format!("connect block peer {peer}: {error}"))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .map_err(|error| error.to_string())?;
    stream
        .set_write_timeout(Some(Duration::from_secs(2)))
        .map_err(|error| error.to_string())?;
    stream
        .write_all(&frame)
        .map_err(|error| format!("send block to {peer}: {error}"))?;
    let mut ack = [0u8; BLOCK_ACK_BYTES];
    stream
        .read_exact(&mut ack)
        .map_err(|error| format!("read block ACK from {peer}: {error}"))?;
    validate_block_ack(peer, &ack, height, expected_hash)
}

fn validate_block_ack(
    peer: SocketAddr,
    ack: &[u8],
    height: u64,
    expected_hash: [u8; 32],
) -> Result<(), String> {
    if ack.len() != BLOCK_ACK_BYTES {
        return Err(format!("peer {peer} returned an invalid ACK length"));
    }
    let ack_height = u64::from_be_bytes(ack[7..15].try_into().unwrap());
    if &ack[..4] != BLOCK_ACK_MAGIC
        || u16::from_be_bytes([ack[4], ack[5]]) != BLOCK_PROTOCOL_VERSION
        || ack[6] > 1
        || ack_height != height
        || ack[15..47] != expected_hash
    {
        return Err(format!(
            "peer {peer} rejected envelope or returned a mismatched ACK"
        ));
    }
    Ok(())
}

struct EphemeralNoisePrivateKey([u8; 32]);

impl Drop for EphemeralNoisePrivateKey {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

fn send_block_to_peer_authenticated(
    peer: SocketAddr,
    envelope: &[u8],
    network_id: &[u8; 32],
    profile_id: &[u8; 32],
    local_private_key: [u8; 32],
    remote_static_public_key: Option<&[u8; 32]>,
    expected_canonical_tip: Option<[u8; 32]>,
    allow_public_peer: bool,
    expect_d1_evidence: bool,
) -> Result<Option<D1BlockAckEvidence>, String> {
    let local_private_key = EphemeralNoisePrivateKey(local_private_key);
    if !allow_public_peer && !peer.ip().is_loopback() {
        return Err("non-loopback peers require explicit public-alpha mode".into());
    }
    let candidate = decode_candidate_network_block(envelope)
        .map_err(|error| format!("decode PTB2 envelope: {error:?}"))?;
    // QFP5 relay is permitted only through this authenticated, profile-bound session.
    let height = candidate.block.height;
    let candidate_txids = candidate
        .block
        .transactions
        .iter()
        .map(transaction_id)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("derive QFP5 candidate transaction IDs: {error:?}"))?;
    let expected_hash = block_id(envelope);
    let frame = encode_block_frame(envelope)?;
    let mut stream = TcpStream::connect_timeout(&peer, Duration::from_secs(2))
        .map_err(|error| format!("connect authenticated block peer {peer}: {error}"))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(6)))
        .map_err(|error| error.to_string())?;
    stream
        .set_write_timeout(Some(Duration::from_secs(6)))
        .map_err(|error| error.to_string())?;
    let established = match remote_static_public_key {
        Some(expected_key) => QRunV05NoiseSession::connect(
            &mut stream,
            &local_private_key.0,
            expected_key,
            network_id,
            profile_id,
        ),
        None if allow_public_peer => QRunV05NoiseSession::connect_public(
            &mut stream,
            &local_private_key.0,
            network_id,
            profile_id,
        ),
        None => {
            return Err("outbound peer requires a static-key pin outside public-alpha mode".into())
        }
    };
    let mut session =
        established.map_err(|error| format!("Noise XX peer authentication failed: {error}"))?;
    if let Some(expected_key) = remote_static_public_key {
        if session.remote_static_public_key() != expected_key {
            return Err(format!(
                "peer {peer} Noise static key differs from the configured pin"
            ));
        }
    }
    session
        .write_record(&mut stream, &frame)
        .map_err(|error| format!("send encrypted block to {peer}: {error}"))?;
    let ack = session
        .read_block_ack_record(&mut stream)
        .map_err(|error| format!("read authenticated block ACK from {peer}: {error}"))?;
    validate_block_ack(peer, &ack, height, expected_hash)?;
    if !expect_d1_evidence {
        return Ok(None);
    }
    let expected_canonical_block_id = expected_canonical_tip.ok_or_else(|| {
        "D1 receipt/state evidence requires the runtime's canonical PoW digest".to_string()
    })?;
    let evidence_bytes = session
        .read_block_ack_record(&mut stream)
        .map_err(|error| {
            format!("read authenticated D1 receipt/state evidence from {peer}: {error}")
        })?;
    let evidence = decode_d1_block_ack_evidence(&evidence_bytes)?;
    validate_d1_block_ack_evidence(
        peer,
        &evidence,
        network_id,
        profile_id,
        height,
        &expected_canonical_block_id,
        &candidate_txids,
    )?;
    Ok(Some(evidence))
}

fn is_d2_partition_connect_failure(peer: SocketAddr, error: &str) -> bool {
    error.starts_with(&format!("connect authenticated block peer {peer}:"))
}

fn send_block_to_peer(
    peer: SocketAddr,
    envelope: &[u8],
    state: &Arc<Mutex<NodeState>>,
) -> Result<Option<D1BlockAckEvidence>, String> {
    let (
        network_id,
        profile_id,
        local_private_key,
        remote_static_public_key,
        public_alpha,
        d1_evidence,
        expected_d1_canonical_tip,
    ) = {
        let locked = state
            .lock()
            .map_err(|_| "node state lock poisoned".to_string())?;
        let expected_d1_canonical_tip = if locked.d1_evidence {
            Some(
                locked
                    .runtime
                    .candidate_pow_digest(envelope)
                    .map_err(|error| format!("derive local D1 canonical PoW digest: {error:?}"))?,
            )
        } else {
            None
        };
        (
            locked.runtime.network_id(),
            locked.profile_id,
            locked.noise_private_key,
            locked.peer_static_keys_by_addr.get(&peer).copied(),
            locked.public_alpha,
            locked.d1_evidence,
            expected_d1_canonical_tip,
        )
    };
    match (local_private_key, remote_static_public_key) {
        (None, None) => send_block_to_peer_plain(peer, envelope).map(|_| None),
        (Some(mut private_key), remote_key) if public_alpha || remote_key.is_some() => {
            let result = send_block_to_peer_authenticated(
                peer,
                envelope,
                &network_id,
                &profile_id,
                private_key,
                remote_key.as_ref(),
                expected_d1_canonical_tip,
                public_alpha,
                d1_evidence,
            );
            private_key.fill(0);
            result
        }
        _ => {
            Err("authenticated block peer config is incomplete; refusing plaintext fallback".into())
        }
    }
}

/// Request one bounded canonical page from an authenticated peer. Pages are imported into
/// the durable fork graph (not forced to extend the current canonical tip), allowing a node that
/// was partitioned onto a competing branch to recover the peer's complete canonical path.
fn request_sync_page_authenticated(
    peer: SocketAddr,
    state: &Arc<Mutex<NodeState>>,
    max_blocks: usize,
    max_bytes: usize,
    start_height: u64,
    expected_snapshot: Option<(u64, [u8; 32])>,
) -> Result<(u64, u64, usize, [u8; 32], [u8; 32], u64, [u8; 32]), String> {
    let public_alpha = state
        .lock()
        .map_err(|_| "node state lock poisoned".to_string())?
        .public_alpha;
    if !public_alpha && !peer.ip().is_loopback() {
        return Err("non-loopback peers require explicit public-alpha mode".into());
    }
    let (
        network_id,
        profile_id,
        local_private_key,
        remote_static_public_key,
        local_base_height,
        local_base_tip,
    ) = {
        let locked = state
            .lock()
            .map_err(|_| "node state lock poisoned".to_string())?;
        let remote_static_key = locked.peer_static_keys_by_addr.get(&peer).copied();
        if remote_static_key.is_none() && !locked.public_alpha {
            return Err(
                "authenticated sync requires a pinned peer key outside public-alpha mode".into(),
            );
        }
        (
            locked.runtime.network_id(),
            locked.profile_id,
            locked
                .noise_private_key
                .ok_or("authenticated sync requires a local Noise key")?,
            remote_static_key,
            locked.runtime.archive_base_height(),
            locked.runtime.archive_base_tip(),
        )
    };
    if start_height <= local_base_height {
        return Err(
            "canonical sync cursor must be above the locally trusted checkpoint base".into(),
        );
    }
    let request = encode_sync_request(start_height, max_blocks, max_bytes, expected_snapshot)?;
    let local_private_key = EphemeralNoisePrivateKey(local_private_key);
    let mut stream = TcpStream::connect_timeout(&peer, Duration::from_secs(2))
        .map_err(|error| format!("connect authenticated sync peer {peer}: {error}"))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(6)))
        .map_err(|error| error.to_string())?;
    stream
        .set_write_timeout(Some(Duration::from_secs(6)))
        .map_err(|error| error.to_string())?;
    let established = match remote_static_public_key.as_ref() {
        Some(expected_key) => QRunV05NoiseSession::connect(
            &mut stream,
            &local_private_key.0,
            expected_key,
            &network_id,
            &profile_id,
        ),
        None if public_alpha => QRunV05NoiseSession::connect_public(
            &mut stream,
            &local_private_key.0,
            &network_id,
            &profile_id,
        ),
        None => return Err("sync peer needs a static-key pin outside public-alpha mode".into()),
    };
    let mut session =
        established.map_err(|error| format!("Noise XX sync authentication failed: {error}"))?;
    if let Some(expected_key) = remote_static_public_key.as_ref() {
        if session.remote_static_public_key() != expected_key {
            return Err("sync peer static key differs from the configured pin".into());
        }
    }
    session
        .write_record(&mut stream, &request)
        .map_err(|error| format!("send encrypted canonical sync request: {error}"))?;
    let response_bytes = session
        .read_record(&mut stream)
        .map_err(|error| format!("read encrypted canonical sync response: {error}"))?;
    let response = decode_sync_response(&response_bytes, max_blocks, max_bytes)?;

    // A peer may share the same trusted Genesis/checkpoint base while having a different
    // canonical tip. Different or newer bases remain a hard failure: sync never adopts a
    // peer-supplied checkpoint or silently skips history.
    if response.base_height != local_base_height || response.base_tip != local_base_tip {
        return Err(format!(
            "peer trusted base differs from local base (peer_height={}, local_height={}); obtain and verify the checkpoint out of band",
            response.base_height, local_base_height
        ));
    }
    validate_sync_snapshot_pin(expected_snapshot, response.height, response.canonical_tip)?;
    if response.height < start_height.saturating_sub(1) && !response.envelopes.is_empty() {
        return Err("peer returned canonical blocks below the requested sync cursor".into());
    }
    let maximum_count = response
        .height
        .saturating_sub(start_height.saturating_sub(1));
    if response.envelopes.len() as u64 > maximum_count {
        return Err(
            "peer returned more canonical blocks than its advertised height permits".into(),
        );
    }
    for (index, envelope) in response.envelopes.iter().enumerate() {
        let candidate = decode_candidate_network_block(envelope)
            .map_err(|error| format!("decode synced PTB2 block: {error:?}"))?;
        let expected_height = start_height
            .checked_add(index as u64)
            .ok_or("sync block height overflow")?;
        if candidate.block.height != expected_height {
            return Err(format!(
                "peer canonical page is not contiguous: received height {}, expected {expected_height}",
                candidate.block.height
            ));
        }
        let mut locked = state
            .lock()
            .map_err(|_| "node state lock poisoned".to_string())?;
        if candidate.fee_block.is_some() != locked.runtime.is_qrun_v05_fee_only() {
            return Err("sync envelope execution mode differs from the local QRun profile".into());
        }
        let previous_count = locked.runtime.retained_branch_count();
        let submit_result = {
            let NodeState {
                runtime,
                authenticator,
                clock,
                ..
            } = &mut *locked;
            runtime.submit_authenticated_sync_block(envelope, authenticator, clock)
        };
        submit_result
            .map_err(|error| format!("local consensus rejected synced branch block: {error:?}"))?;
        if locked.runtime.retained_branch_count() > previous_count {
            locked.refresh_receipts()?;
        }
    }

    let locked = state
        .lock()
        .map_err(|_| "node state lock poisoned".to_string())?;
    println!(
        "qrun_pow_authenticated_sync_page peer={peer} start_height={start_height} received={} local_height={} peer_height={}",
        response.envelopes.len(),
        locked.runtime.canonical_height(),
        response.height
    );
    Ok((
        locked.runtime.canonical_height(),
        response.height,
        response.envelopes.len(),
        response.canonical_tip,
        response.state_root,
        response.base_height,
        response.base_tip,
    ))
}

/// Catch up from the latest trusted base over bounded authenticated pages. The complete peer
/// canonical path is merged into local fork choice; local branches are retained and the node
/// selects the greatest cumulative work with the protocol's deterministic tie-break. No
/// peer-supplied checkpoint is adopted automatically.
fn sync_from_peer_authenticated(
    peer: SocketAddr,
    state: &Arc<Mutex<NodeState>>,
    max_blocks: usize,
    max_bytes: usize,
) -> Result<u64, String> {
    if max_blocks == 0 || max_blocks > MAX_SYNC_PAGE_BLOCKS {
        return Err("canonical sync page block count is outside the allowed range".into());
    }
    let max_pages = (1_024usize + max_blocks - 1) / max_blocks + 1;
    let (base_height, base_tip) = {
        let locked = state
            .lock()
            .map_err(|_| "node state lock poisoned".to_string())?;
        (
            locked.runtime.archive_base_height(),
            locked.runtime.archive_base_tip(),
        )
    };
    let mut next_start_height = base_height
        .checked_add(1)
        .ok_or("trusted checkpoint base height overflow")?;
    let mut remote_height = base_height;
    let mut remote_tip = base_tip;
    let mut remote_state_root = [0u8; 32];
    let mut expected_peer_snapshot: Option<(u64, [u8; 32])> = None;
    let mut complete = false;

    for _ in 0..max_pages {
        let (
            _local_height,
            page_peer_height,
            received,
            page_peer_tip,
            page_state_root,
            page_base_height,
            page_base_tip,
        ) = request_sync_page_authenticated(
            peer,
            state,
            max_blocks,
            max_bytes,
            next_start_height,
            expected_peer_snapshot,
        )?;
        if page_base_height != base_height || page_base_tip != base_tip {
            return Err(
                "authenticated sync peer changed its trusted base during pagination".into(),
            );
        }
        let page_snapshot = (page_peer_height, page_peer_tip);
        validate_sync_snapshot_pin(expected_peer_snapshot, page_peer_height, page_peer_tip)?;
        expected_peer_snapshot = Some(page_snapshot);
        remote_height = page_peer_height;
        remote_tip = page_peer_tip;
        remote_state_root = page_state_root;
        if received == 0 {
            if next_start_height <= remote_height {
                return Err(
                    "sync peer advertised a higher tip but returned an empty canonical page".into(),
                );
            }
            complete = true;
            break;
        }
        next_start_height = next_start_height
            .checked_add(received as u64)
            .ok_or("canonical sync cursor overflow")?;
        if next_start_height > remote_height {
            complete = true;
            break;
        }
    }
    if !complete {
        return Err("authenticated sync exceeded the bounded catch-up page budget".into());
    }

    let locked = state
        .lock()
        .map_err(|_| "node state lock poisoned".to_string())?;
    if remote_height == base_height {
        if remote_tip != base_tip {
            return Err("empty peer chain tip differs from the trusted checkpoint base".into());
        }
        return Ok(locked.runtime.canonical_height());
    }
    let (retained_height, retained_state_root, remote_work) = locked
        .runtime
        .archived_branch_summary(&remote_tip)
        .ok_or("authenticated sync did not retain the peer's advertised canonical tip")?;
    if retained_height != remote_height || retained_state_root != remote_state_root {
        return Err("retained peer branch height/state root differs from its authenticated sync advertisement".into());
    }
    let local_work = locked.runtime.canonical_cumulative_work();
    let local_tip = locked.runtime.canonical_tip();
    let remote_should_win =
        remote_work > local_work || (remote_work == local_work && remote_tip < local_tip);
    let expected_tip = if remote_should_win {
        remote_tip
    } else {
        local_tip
    };
    if locked.runtime.canonical_tip() != expected_tip {
        return Err("local fork choice did not select the greatest cumulative-work branch/tie-break after sync".into());
    }
    println!(
        "qrun_pow_authenticated_sync_complete peer={peer} peer_height={remote_height} local_height={} selected_peer_branch={}",
        locked.runtime.canonical_height(),
        expected_tip == remote_tip
    );
    Ok(locked.runtime.canonical_height())
}

fn handle_block(stream: &mut TcpStream, state: &Arc<Mutex<NodeState>>) -> Result<(), String> {
    stream
        .set_nonblocking(false)
        .map_err(|error| error.to_string())?;
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|error| error.to_string())?;
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .map_err(|error| error.to_string())?;
    let (
        network_id,
        profile_id,
        local_private_key,
        trusted_peer_static_keys,
        public_alpha,
        d1_evidence_enabled,
    ) = {
        let locked = state
            .lock()
            .map_err(|_| "node state lock poisoned".to_string())?;
        (
            locked.runtime.network_id(),
            locked.profile_id,
            locked.noise_private_key,
            locked.trusted_peer_static_keys.clone(),
            locked.public_alpha,
            locked.d1_evidence,
        )
    };
    let mut noise_session = if let Some(mut private_key) = local_private_key {
        // Public Alpha may accept unpinned Noise XX peers only when the operator has
        // deliberately configured no static-key trust pins. Once one or more pins are
        // configured, inbound sessions must prove one of those identities too.
        let result = if public_alpha && trusted_peer_static_keys.is_empty() {
            QRunV05NoiseSession::accept_public(stream, &private_key, &network_id, &profile_id)
        } else {
            QRunV05NoiseSession::accept(
                stream,
                &private_key,
                &trusted_peer_static_keys,
                &network_id,
                &profile_id,
            )
        };
        private_key.fill(0);
        Some(
            result
                .map_err(|error| format!("Noise XX inbound peer authentication failed: {error}"))?,
        )
    } else {
        None
    };
    let payload = if let Some(session) = noise_session.as_mut() {
        let frame = session.read_record(stream).map_err(|error| {
            format!("read authenticated encrypted QRun application record: {error}")
        })?;
        if frame.starts_with(SYNC_REQUEST_MAGIC) {
            serve_sync_request(&frame, session, stream, state)?;
            return Ok(());
        }
        decode_block_frame(&frame)?
    } else {
        let mut header = [0u8; BLOCK_FRAME_HEADER_BYTES];
        stream
            .read_exact(&mut header)
            .map_err(|error| format!("read QRun PoW frame header: {error}"))?;
        if &header[..4] != BLOCK_MAGIC
            || u16::from_be_bytes([header[4], header[5]]) != BLOCK_PROTOCOL_VERSION
        {
            return Err("invalid QRun PoW frame magic/version".into());
        }
        let payload_len = u32::from_be_bytes(header[6..10].try_into().unwrap()) as usize;
        if payload_len == 0 || payload_len > MAX_BLOCK_FRAME_BYTES {
            return Err("invalid or oversized QRun PTB2 frame".into());
        }
        let mut full_frame = Vec::with_capacity(BLOCK_FRAME_HEADER_BYTES + payload_len);
        full_frame.extend_from_slice(&header);
        full_frame.resize(BLOCK_FRAME_HEADER_BYTES + payload_len, 0);
        stream
            .read_exact(&mut full_frame[BLOCK_FRAME_HEADER_BYTES..])
            .map_err(|error| format!("read PTB2 envelope: {error}"))?;
        decode_block_frame(&full_frame)?
    };
    let candidate = decode_candidate_network_block(&payload)
        .map_err(|error| format!("decode PTB2 envelope: {error:?}"))?;
    let height = candidate.block.height;
    let id = block_id(&payload);
    let canonical_candidate_id = if d1_evidence_enabled {
        let locked = state
            .lock()
            .map_err(|_| "node state lock poisoned".to_string())?;
        Some(
            locked
                .runtime
                .candidate_pow_digest(&payload)
                .map_err(|error| format!("derive incoming D1 canonical PoW digest: {error:?}"))?,
        )
    } else {
        None
    };
    let candidate_txids = candidate
        .block
        .transactions
        .iter()
        .map(transaction_id)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("derive incoming QFP5 transaction IDs: {error:?}"))?;
    let (status, forward_peers, log, ack_evidence) = {
        let mut locked = state
            .lock()
            .map_err(|_| "node state lock poisoned".to_string())?;
        if candidate.fee_block.is_some() != locked.runtime.is_qrun_v05_fee_only() {
            return Err("incoming block execution mode differs from the local QRun profile".into());
        }
        let previous_count = locked.runtime.retained_branch_count();
        let submit_result = {
            let NodeState {
                runtime,
                authenticator,
                clock,
                ..
            } = &mut *locked;
            runtime.submit_block(&payload, authenticator, clock)
        };
        match submit_result {
            Ok(canonical_tip) => {
                let inserted = locked.runtime.retained_branch_count() > previous_count;
                if inserted {
                    locked.refresh_receipts()?;
                }
                let evidence = if locked.d1_evidence {
                    Some(d1_ack_evidence_for_block(
                        &locked,
                        &candidate_txids,
                        canonical_candidate_id.ok_or_else(|| {
                            "D1 receipt/state evidence requires an incoming canonical PoW digest".to_string()
                        })?,
                    ))
                } else {
                    None
                };
                (
                    if inserted { 0u8 } else { 1u8 },
                    if inserted {
                        locked.block_peers.clone()
                    } else {
                        Vec::new()
                    },
                    format!(
                        "{} height={} canonical_height={} canonical_tip={}",
                        if inserted { "accepted" } else { "duplicate" },
                        height,
                        locked.runtime.canonical_height(),
                        hex(&canonical_tip)
                    ),
                    evidence,
                )
            }
            Err(error) => (
                2u8,
                Vec::new(),
                format!("rejected height={height} reason={error:?}"),
                None,
            ),
        }
    };
    let ack = block_ack(status, height, id);
    if let Some(session) = noise_session.as_mut() {
        session
            .write_record(stream, &ack)
            .map_err(|error| format!("write encrypted QRun block ACK: {error}"))?;
        if let Some(evidence) = ack_evidence.as_ref() {
            let evidence_bytes = encode_d1_block_ack_evidence(evidence)?;
            session
                .write_record(stream, &evidence_bytes)
                .map_err(|error| format!("write encrypted D1 receipt/state evidence: {error}"))?;
        }
    } else {
        if d1_evidence_enabled {
            return Err(
                "D1 evidence requires an authenticated Noise session; refusing plaintext evidence"
                    .into(),
            );
        }
        stream.write_all(&ack).map_err(|error| error.to_string())?;
    }
    println!("qrun_pow_local_block_gossip {log}");
    if let Some(evidence) = ack_evidence.as_ref() {
        let peer = stream
            .peer_addr()
            .map(|address| address.to_string())
            .unwrap_or_else(|_| "unknown".into());
        println!(
            "qrun_d1_block_evidence_sent peer={} network_id={} profile_id={} canonical_height={} canonical_tip={} state_root={} confirmed_receipts={}",
            peer,
            hex(&evidence.network_id),
            hex(&evidence.profile_id),
            evidence.canonical_height,
            hex(&evidence.canonical_tip),
            hex(&evidence.state_root),
            d1_receipt_list(evidence)
        );
    }
    if status == 0 {
        for peer in forward_peers {
            if peer == stream.peer_addr().unwrap_or(peer) {
                continue;
            }
            match send_block_to_peer(peer, &payload, state) {
                Ok(Some(evidence)) => println!(
                    "qrun_pow_local_block_forwarded peer={peer} height={height} d1_remote_height={}",
                    evidence.canonical_height
                ),
                Ok(None) => println!("qrun_pow_local_block_forwarded peer={peer} height={height}"),
                Err(error) => eprintln!(
                    "qrun_pow_local_block_forward_failed peer={peer} reason={}",
                    error.replace(['\r', '\n'], "_")
                ),
            }
        }
    }
    Ok(())
}

fn poll_block_listener(
    listener: &TcpListener,
    state: &Arc<Mutex<NodeState>>,
) -> Result<bool, String> {
    match listener.accept() {
        Ok((mut stream, _)) => {
            if let Err(error) = handle_block(&mut stream, state) {
                eprintln!(
                    "qrun_pow_local_block_request_rejected reason={}",
                    error.replace(['\r', '\n'], "_")
                );
            }
            Ok(true)
        }
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => Ok(false),
        Err(error) => Err(format!("block listener accept failed: {error}")),
    }
}

fn reject_ack(transaction_id: [u8; 32], status: TxIngressStatus, count: usize) -> [u8; ACK_BYTES] {
    encode_ack(TxIngressAck {
        status,
        mempool_count: u32::try_from(count).unwrap_or(u32::MAX),
        transaction_id,
    })
}

fn handle_transaction(stream: &mut TcpStream, state: &Arc<Mutex<NodeState>>) -> Result<(), String> {
    stream
        .set_nonblocking(false)
        .map_err(|error| error.to_string())?;
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .map_err(|error| error.to_string())?;
    stream
        .set_write_timeout(Some(Duration::from_secs(10)))
        .map_err(|error| error.to_string())?;
    let mut header = [0u8; REQUEST_HEADER_BYTES];
    if stream.read_exact(&mut header).is_err() {
        return Err("could not read complete QZTS/1 header".into());
    }
    let payload_len = decode_request_header(&header)
        .map_err(|error| format!("invalid QZTS/1 header: {error:?}"))?;
    if payload_len > MAX_TRANSACTION_BYTES {
        return Err("transaction exceeds QZXB wire cap".into());
    }
    let mut wire = vec![0u8; payload_len];
    stream
        .read_exact(&mut wire)
        .map_err(|error| format!("short QZTS/1 body: {error}"))?;
    let tx = decode_transaction(&wire)
        .map_err(|error| format!("invalid TXN2 transaction: {error:?}"))?;
    let txid = transaction_id(&tx).map_err(|error| format!("transaction ID error: {error:?}"))?;
    let (d1_evidence_enabled, d2_partition_qualification) = {
        let locked = state
            .lock()
            .map_err(|_| "node state lock poisoned".to_string())?;
        (locked.d1_evidence, locked.d2_partition_qualification)
    };

    let mut block_to_broadcast: Option<Vec<u8>> = None;
    let mut peers_to_broadcast = Vec::new();
    let (mut ack, mut log_line) = {
        let mut locked = state
            .lock()
            .map_err(|_| "node state lock poisoned".to_string())?;
        if locked.receipts.contains_key(&txid) {
            (
                reject_ack(txid, TxIngressStatus::Duplicate, 0),
                format!("duplicate canonical txid={}", hex(&txid)),
            )
        } else {
            let reference_time_sample = locked.clock.sample().map_err(|error| {
                format!("sample configured block-production reference time: {error:?}")
            })?;
            let timestamp = next_live_block_timestamp(
                reference_time_sample.unix_seconds,
                locked.runtime.canonical_state().last_timestamp(),
            )?;
            // Public-alpha uses the calibrated target, so it must allow enough nonce attempts
            // for expected block production. Local-loopback tests keep the single-attempt smoke path.
            let max_nonce_attempts = if locked.public_alpha { 10_000 } else { 1 };
            let snapshot = locked
                .runtime
                .mining_snapshot()
                .map_err(|error| format!("capture branch-bound QFP5 mining snapshot: {error:?}"))?;
            let parent_tip = snapshot.parent_tip();
            let parent_height = snapshot.parent_height();
            let authenticator = locked.authenticator.clone();
            // Hash an immutable branch snapshot with the node mutex released. This does not
            // move StoreWriterLock: the live runtime remains owned by the event-loop thread.
            drop(locked);
            // Keep each candidate timestamp fresh even when the complete PoW budget is slow
            // on a modest host. Every slice hashes a new timestamp-bound header; the total nonce
            // budget is unchanged, and the parent is rechecked before spending the next slice.
            let mut candidate_timestamp = timestamp;
            let mut attempts_used = 0u64;
            let envelope_result = loop {
                let attempts_this_slice =
                    (max_nonce_attempts - attempts_used).min(PUBLIC_ALPHA_POW_NONCE_SLICE_ATTEMPTS);
                match snapshot.mine_candidate(
                    candidate_timestamp,
                    vec![tx.clone()],
                    &authenticator,
                    attempts_this_slice,
                ) {
                    Ok(envelope) => break Ok(envelope),
                    Err(QRunV05PowRuntimeError::MiningExhausted { .. }) => {
                        attempts_used = attempts_used.saturating_add(attempts_this_slice);
                        if attempts_used >= max_nonce_attempts {
                            break Err(QRunV05PowRuntimeError::MiningExhausted {
                                attempts: attempts_used,
                            });
                        }
                        let locked = state.lock().map_err(|_| {
                            "node state lock poisoned between PoW slices".to_string()
                        })?;
                        if locked.runtime.canonical_tip() != parent_tip
                            || locked.runtime.canonical_height() != parent_height
                        {
                            break Err(QRunV05PowRuntimeError::InvalidCandidate(
                                "mining snapshot parent changed before the next PoW time slice"
                                    .into(),
                            ));
                        }
                        let refreshed_sample = locked.clock.sample().map_err(|error| {
                            format!(
                                "refresh configured reference time between PoW slices: {error:?}"
                            )
                        })?;
                        candidate_timestamp = next_live_block_timestamp(
                            refreshed_sample.unix_seconds,
                            candidate_timestamp,
                        )?;
                    }
                    Err(error) => break Err(error),
                }
            };
            let mut locked = state
                .lock()
                .map_err(|_| "node state lock poisoned after PoW".to_string())?;
            if locked.runtime.canonical_tip() != parent_tip
                || locked.runtime.canonical_height() != parent_height
            {
                (
                    reject_ack(txid, TxIngressStatus::Rejected, 0),
                    format!(
                        "stale_mining_parent txid={} snapshot_height={} current_height={} snapshot_tip={} current_tip={}",
                        hex(&txid),
                        parent_height,
                        locked.runtime.canonical_height(),
                        hex(&parent_tip),
                        hex(&locked.runtime.canonical_tip())
                    ),
                )
            } else {
                match envelope_result {
                    Ok(envelope) => {
                        let candidate =
                            decode_candidate_network_block(&envelope).map_err(|error| {
                                format!("decode newly mined QFP5 envelope: {error:?}")
                            })?;
                        if candidate.fee_block.is_some() != locked.runtime.is_qrun_v05_fee_only() {
                            return Err(
                                "mined envelope execution mode differs from the local QRun profile"
                                    .into(),
                            );
                        }
                        let candidate_height = candidate.block.height;
                        block_to_broadcast = Some(envelope.clone());
                        peers_to_broadcast = locked.block_peers.clone();
                        if locked.d1_evidence {
                            // In D1, the pinned peer must first accept this exact candidate and
                            // return QDE5 canonical receipt/state evidence. Do not commit locally
                            // while remote confirmation is still unknown.
                            (
                                reject_ack(txid, TxIngressStatus::Rejected, 0),
                                format!(
                                    "awaiting_d1_remote_confirmation txid={} height={} parent_tip={}",
                                    hex(&txid),
                                    candidate_height,
                                    hex(&parent_tip)
                                ),
                            )
                        } else {
                            let submit_result = {
                                let NodeState {
                                    runtime,
                                    authenticator,
                                    clock,
                                    ..
                                } = &mut *locked;
                                runtime.submit_block(&envelope, authenticator, clock)
                            };
                            match submit_result {
                                Ok(canonical_tip) => {
                                    locked.refresh_receipts()?;
                                    (
                                        reject_ack(txid, TxIngressStatus::Accepted, 0),
                                        format!(
                                            "accepted_pow_candidate txid={} height={} canonical_height={} canonical_tip={} canonically_included={}",
                                            hex(&txid),
                                            candidate_height,
                                            locked.runtime.canonical_height(),
                                            hex(&canonical_tip),
                                            locked.receipts.contains_key(&txid)
                                        ),
                                    )
                                }
                                Err(error) => (
                                    reject_ack(txid, TxIngressStatus::Rejected, 0),
                                    format!(
                                        "pow_consensus_rejected txid={} error={error:?}",
                                        hex(&txid)
                                    ),
                                ),
                            }
                        }
                    }
                    Err(error) => (
                        reject_ack(txid, TxIngressStatus::Rejected, 0),
                        format!("pow_mining_rejected txid={} error={error:?}", hex(&txid)),
                    ),
                }
            }
        }
    };
    if d1_evidence_enabled && block_to_broadcast.is_none() {
        return Err("D1 evidence mode requires a newly mined canonical block; duplicate/rejected ingress is not accepted as remote qualification".into());
    }
    let mut d1_remote_evidence: Option<D1BlockAckEvidence> = None;
    let mut d2_partition_peer_unreachable = false;
    for peer in peers_to_broadcast {
        if let Some(envelope) = block_to_broadcast.as_ref() {
            match send_block_to_peer(peer, envelope, state) {
                Ok(Some(evidence)) => {
                    if !evidence
                        .confirmed_receipts
                        .iter()
                        .any(|(confirmed_txid, _)| confirmed_txid == &txid)
                    {
                        return Err(format!(
                            "D1 peer {peer} did not return the exact submitted transaction ID as a canonical receipt"
                        ));
                    }
                    println!(
                        "qrun_d1_remote_receipt_confirmed txid={} peer={} network_id={} profile_id={} canonical_height={} canonical_tip={} state_root={}",
                        hex(&txid),
                        peer,
                        hex(&evidence.network_id),
                        hex(&evidence.profile_id),
                        evidence.canonical_height,
                        hex(&evidence.canonical_tip),
                        hex(&evidence.state_root)
                    );
                    d1_remote_evidence = Some(evidence);
                }
                Ok(None) if d1_evidence_enabled => {
                    return Err(format!(
                        "D1 peer {peer} did not return authenticated canonical receipt/state evidence"
                    ));
                }
                Ok(None) => println!("qrun_pow_local_block_broadcast peer={peer}"),
                Err(error)
                    if d1_evidence_enabled
                        && d2_partition_qualification
                        && is_d2_partition_connect_failure(peer, &error) =>
                {
                    eprintln!(
                        "qrun_pow_local_block_broadcast_failed peer={peer} reason={}",
                        error.replace(['\r', '\n'], "_")
                    );
                    d2_partition_peer_unreachable = true;
                }
                Err(error) if d1_evidence_enabled => return Err(error),
                Err(error) => eprintln!(
                    "qrun_pow_local_block_broadcast_failed peer={peer} reason={}",
                    error.replace(['\r', '\n'], "_")
                ),
            }
        }
    }
    if d1_evidence_enabled {
        if d1_remote_evidence.is_none()
            && !(d2_partition_qualification && d2_partition_peer_unreachable)
        {
            return Err(
                "D1 mode requires authenticated exact-TXID evidence; D2 only permits a TCP connect failure to its configured pinned peer"
                    .into(),
            );
        }

        let envelope = block_to_broadcast
            .as_ref()
            .ok_or_else(|| "D1 mode lost its newly mined candidate envelope".to_string())?;
        let candidate = decode_candidate_network_block(envelope)
            .map_err(|error| format!("decode D1 candidate before local commit: {error:?}"))?;
        let candidate_height = candidate.block.height;
        let candidate_parent = candidate.block.parent_hash;

        // In D1, remote canonical evidence is collected before local commit. D2 reaches this
        // point without remote evidence only after the exact pinned TCP peer failed to connect.
        let mut locked = state
            .lock()
            .map_err(|_| "node state lock poisoned before D1 local commit".to_string())?;
        let expected_tip = locked
            .runtime
            .candidate_pow_digest(envelope)
            .map_err(|error| format!("compute D1 candidate fork-choice digest: {error:?}"))?;
        let current_tip = locked.runtime.canonical_tip();
        let current_height = locked.runtime.canonical_height();

        if current_tip == expected_tip && current_height == candidate_height {
            // The exact block may already have been imported by the authenticated peer path.
        } else if current_tip == candidate_parent
            && current_height.checked_add(1) == Some(candidate_height)
        {
            let submit_result = {
                let NodeState {
                    runtime,
                    authenticator,
                    clock,
                    ..
                } = &mut *locked;
                runtime.submit_block(envelope, authenticator, clock)
            };
            submit_result.map_err(|error| {
                format!("local QFP5 commit after D1 peer evidence failed: {error:?}")
            })?;
        } else {
            return Err(format!(
                "D1 candidate parent became stale before local commit: candidate_height={} local_height={} candidate_parent={} local_tip={}",
                candidate_height,
                current_height,
                hex(&candidate_parent),
                hex(&current_tip)
            ));
        }

        locked.refresh_receipts()?;
        if !locked.receipts.contains_key(&txid) {
            return Err(format!(
                "D1 local canonical chain does not contain the exact submitted TXID {}",
                hex(&txid)
            ));
        }

        let local_height = locked.runtime.canonical_height();
        let local_tip = locked.runtime.canonical_tip();
        let local_state_root = locked.runtime.canonical_state_root();
        if local_height != candidate_height || local_tip != expected_tip {
            return Err(format!(
                "D1 local canonical tuple differs from the submitted candidate: candidate_height={} local_height={} candidate_tip={} local_tip={}",
                candidate_height,
                local_height,
                hex(&expected_tip),
                hex(&local_tip)
            ));
        }
        if let Some(remote) = d1_remote_evidence.as_ref() {
            if remote.canonical_height != local_height
                || remote.canonical_tip != local_tip
                || remote.state_root != local_state_root
            {
                return Err(format!(
                    "D1 remote/local canonical state tuple mismatch: remote_height={} local_height={} remote_tip={} local_tip={} remote_state_root={} local_state_root={}",
                    remote.canonical_height,
                    local_height,
                    hex(&remote.canonical_tip),
                    hex(&local_tip),
                    hex(&remote.state_root),
                    hex(&local_state_root)
                ));
            }
        }

        ack = reject_ack(txid, TxIngressStatus::Accepted, 0);
        log_line = format!(
            "accepted_pow_candidate txid={} height={} canonical_height={} canonical_tip={} canonically_included=true remote_evidence={}",
            hex(&txid),
            candidate_height,
            local_height,
            hex(&local_tip),
            d1_remote_evidence.is_some()
        );
    }

    stream.write_all(&ack).map_err(|error| error.to_string())?;
    println!("qrun_pow_local_tx_ingress {log_line}");
    Ok(())
}

fn poll_transaction_listener(
    listener: &TcpListener,
    state: &Arc<Mutex<NodeState>>,
) -> Result<bool, String> {
    match listener.accept() {
        Ok((mut stream, _)) => {
            if let Err(error) = handle_transaction(&mut stream, state) {
                eprintln!(
                    "qrun_pow_local_tx_request_rejected reason={}",
                    error.replace(['\r', '\n'], "_")
                );
            }
            Ok(true)
        }
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => Ok(false),
        Err(error) => Err(format!("transaction listener accept failed: {error}")),
    }
}

fn run(config: Config) -> Result<(), String> {
    validate_listener_bind_policy(
        config.public_alpha,
        config.mainnet,
        config.rpc_listen,
        config.tx_listen,
        config.block_listen,
        &config.peers,
    )?;
    let clock = build_node_reference_time(&config)?;
    let startup_time = clock.sample().map_err(|error| {
        format!("authenticated reference-time startup sample failed: {error:?}")
    })?;
    if (config.public_alpha || config.mainnet)
        && startup_time.provenance != ReferenceTimeProvenance::ConfiguredProvider
    {
        return Err(
            "public QRun mode requires an authenticated configured reference-time sample".into(),
        );
    }
    println!(
        "qrun_reference_time_ready source={} provenance={:?} unix_seconds={} policy_digest={}",
        clock.source_label(),
        startup_time.provenance,
        startup_time.unix_seconds,
        clock
            .policy_digest()
            .map(|digest| hex(&digest))
            .unwrap_or_else(|| "none".into())
    );
    fs::create_dir_all(&config.data_dir)
        .map_err(|error| format!("create data directory: {error}"))?;
    let authenticator = Ed25519TransactionAuthenticator::select(
        TransactionAuthenticatorKind::Ed25519V1,
        [AccountPublicKey {
            account_id: config.owner_account,
            public_key: config.owner_public_key,
        }],
    )
    .map_err(|error| format!("configure Ed25519 authenticator: {error:?}"))?;

    // Local-testnet keeps its trivial target and reduced memory for fast smoke tests. Public-alpha
    // and Mainnet use the calibrated QRun v0.5 consensus profile. A wallet-bound Genesis may use a
    // custom network ID and owner account; those inputs deterministically change the Genesis and
    // profile IDs, so every peer must be configured with the same values to join the same chain.
    let qrun_v05_identity = is_qrun_v05_identity(&config.network_id, &config.owner_account);
    if config.public_alpha && config.noise_private_key_file.is_none() {
        return Err("--public-alpha requires the network-bound Noise static key".into());
    }
    let params =
        consensus_parameters_for_mode(config.public_alpha, config.mainnet, qrun_v05_identity)?;
    let profile_params = params.clone();
    if !config.peers.is_empty() && config.noise_private_key_file.is_none() {
        return Err(
            "QFP5 peer operation requires the authenticated, pinned Noise transport".into(),
        );
    }
    let store_dir = if qrun_v05_identity {
        config.data_dir.join("qrun-v05-qfp5-store")
    } else {
        // Preserve isolated PTB2 fixtures for startup-sync compatibility tests; QRun v0.5 uses
        // its profile-specific directory so the two modes cannot share a manifest accidentally.
        config.data_dir.join("qrun-v05-pow-fork-store")
    };
    let mut runtime = open_node_runtime_with_genesis_timestamp(
        &store_dir,
        config.network_id,
        config.owner_account,
        params,
        &authenticator,
        &clock,
        config.genesis_timestamp,
        config.external_cas.as_ref(),
    )?;
    runtime
        .set_producer_account(config.producer_account)
        .map_err(|error| format!("configure fee-only producer: {error:?}"))?;
    let network_id = runtime.network_id();
    let genesis_id = runtime.genesis_commitment();
    let profile_id = profile_id_with_reference_time_policy(
        &network_id,
        &profile_params,
        &genesis_id,
        clock.policy_digest(),
    );
    let root = runtime.canonical_state_root();
    let owner_balance = runtime
        .canonical_state()
        .account(&config.owner_account)
        .map_or(0, |account| account.balance);
    let total_supply = runtime
        .canonical_state()
        .total_value()
        .map_err(|error| format!("{error:?}"))?;
    validate_frozen_mainnet_genesis(
        config.mainnet,
        &genesis_id,
        &profile_id,
        &root,
        owner_balance as u128,
        total_supply,
        runtime.canonical_state().account_count(),
        runtime.canonical_height(),
    )?;

    println!(
        "{}",
        if config.mainnet && config.sync_on_start {
            "QRUN_V05_MAINNET_STARTUP_SYNC_PENDING"
        } else if config.mainnet {
            "QRUN_V05_MAINNET_GENESIS_BOOTSTRAP"
        } else if config.public_alpha {
            "QRUN_V05_PUBLIC_ALPHA_CANDIDATE_READY"
        } else {
            "QRUN_V05_LOCAL_POW_LOOPBACK_TESTNET_READY"
        }
    );
    // Until the pinned peer has answered sync and all listeners bind, Mainnet is not active.
    println!("mainnet=false");
    println!(
        "network_class={}",
        if config.mainnet && config.sync_on_start {
            "qzxb_mainnet_startup_sync_pending"
        } else if config.mainnet {
            "qzxb_mainnet_genesis_bootstrap"
        } else if config.public_alpha {
            "public_alpha_experimental_not_mainnet"
        } else {
            "local_loopback_pow_testnet_not_public"
        }
    );
    println!("network_id_hex={}", hex(&network_id));
    println!("genesis_id_hex={}", hex(&genesis_id));
    println!("profile_id_hex={}", hex(&profile_id));
    println!("owner_account_id_hex={}", hex(&config.owner_account));
    println!("producer_account_id_hex={}", hex(&config.producer_account));
    println!("owner_balance_atoms={owner_balance}");
    println!(
        "owner_balance_qzxb={:.8}",
        owner_balance as f64 / 100_000_000.0
    );
    println!("total_supply_atoms={total_supply}");
    println!("state_root_hex={}", hex(&root));
    println!("height={}", runtime.canonical_height());
    println!("rpc_listen={}", config.rpc_listen);
    println!("tx_listen={}", config.tx_listen);
    println!("block_listen={}", config.block_listen);
    println!("configured_peer_count={}", config.peers.len());
    println!(
        "d1_evidence_ack={}",
        if config.d1_evidence {
            "enabled"
        } else {
            "disabled"
        }
    );
    println!(
        "d2_partition_qualification={}",
        if config.d2_partition_qualification {
            "enabled"
        } else {
            "disabled"
        }
    );
    println!(
        "peer_transport={}",
        if config.mainnet {
            "qrun_v05_mainnet_noise_xx_optional_pinned_startup_sync"
        } else if config.public_alpha {
            "qrun_v05_noise_xx_open_public_peers_optional_seed_pins"
        } else if config.noise_private_key_file.is_some() {
            "qrun_v05_noise_xx_pinned_candidate"
        } else {
            "plaintext_loopback_smoke_only"
        }
    );
    println!("consensus=PoW_fork_choice_persistent_PFS2");
    println!(
        "security_note={}",
        if config.mainnet {
            "qzxb_mainnet; frozen_genesis_and_profile; calibrated_argon2id_pow; fixed_10b_supply; zero_block_subsidy; CAS_optional"
        } else if config.public_alpha {
            "experimental_public_alpha; calibrated_argon2id_pow; fixed_genesis_supply; zero_block_subsidy; CAS_optional; mainnet_disabled"
        } else {
            "loopback_only_max_target_smoke_profile_not_public_consensus"
        }
    );

    let state = Arc::new(Mutex::new(NodeState {
        runtime,
        public_alpha: config.public_alpha,
        mainnet: false,
        authenticator,
        clock,
        receipts: BTreeMap::new(),
        profile_id,
        block_peers: config.peers.clone(),
        noise_private_key: config
            .noise_private_key_file
            .as_ref()
            .map(|path| {
                load_protected_noise_private_key(path, &network_id)
                    .map_err(|error| format!("load network-bound QRun Noise private key: {error}"))
            })
            .transpose()?,
        trusted_peer_static_keys: config.peer_static_public_keys.clone(),
        peer_static_keys_by_addr: config
            .peers
            .iter()
            .copied()
            .zip(config.peer_static_public_keys.iter().copied())
            .collect(),
        d1_evidence: config.d1_evidence,
        d2_partition_qualification: config.d2_partition_qualification,
        offhost_anchor_service: OffhostAnchorNodeServiceOwner::disabled(),
    }));
    state
        .lock()
        .map_err(|_| "node state lock poisoned".to_string())?
        .refresh_receipts()?;

    if config.sync_on_start {
        let page_bytes = max_sync_response_block_bytes(MAX_SYNC_PAGE_BLOCKS)?;
        let mut synced = false;
        let mut last_error = "no pinned peers configured".to_string();
        for peer in &config.peers {
            match sync_from_peer_authenticated(*peer, &state, MAX_SYNC_PAGE_BLOCKS, page_bytes) {
                Ok(height) => {
                    println!(
                        "qrun_pow_authenticated_startup_sync_complete peer={peer} height={height}"
                    );
                    synced = true;
                    break;
                }
                Err(error) => {
                    eprintln!(
                        "qrun_pow_authenticated_startup_sync_failed peer={peer} reason={}",
                        error.replace(['\r', '\n'], "_")
                    );
                    last_error = error;
                }
            }
        }
        if !synced {
            return Err(format!(
                "authenticated startup sync requested but every pinned peer failed: {last_error}"
            ));
        }
    }

    // StoreWriterLock remains single-writer: NodeState's mutex serializes every operation that
    // can mutate the canonical runtime. Mining releases that mutex while hashing its immutable
    // snapshot, so the authenticated block listener can continue accepting peer blocks meanwhile.
    let rpc_listener =
        TcpListener::bind(config.rpc_listen).map_err(|error| format!("bind RPC: {error}"))?;
    let tx_listener = TcpListener::bind(config.tx_listen)
        .map_err(|error| format!("bind transaction ingress: {error}"))?;
    let block_listener = TcpListener::bind(config.block_listen)
        .map_err(|error| format!("bind block listener: {error}"))?;
    rpc_listener
        .set_nonblocking(true)
        .map_err(|error| error.to_string())?;
    tx_listener
        .set_nonblocking(true)
        .map_err(|error| error.to_string())?;
    block_listener
        .set_nonblocking(true)
        .map_err(|error| error.to_string())?;

    // Install only once startup sync and all listener binds have completed. The OS callback sets
    // an atomic flag; the node thread below owns all service shutdown and joins.
    let shutdown_signal = QRunNodeShutdownSignalCandidate::install()
        .map_err(|error| format!("install QRun process shutdown handlers: {error}"))?;

    // RPC is read-only and owns no store writer lock. Run its listener independently so a
    // synchronous 64 MiB Argon2id mining attempt cannot starve status/balance/receipt queries.
    let rpc_shutdown = Arc::new(AtomicBool::new(false));
    let rpc_worker_shutdown = Arc::clone(&rpc_shutdown);
    let rpc_worker_state = Arc::clone(&state);
    let rpc_worker = thread::Builder::new()
        .name("qrun-read-only-rpc".into())
        .spawn(move || -> Result<(), String> {
            loop {
                if rpc_worker_shutdown.load(Ordering::Acquire) {
                    return Ok(());
                }
                match poll_rpc_listener(&rpc_listener, &rpc_worker_state) {
                    Ok(true) => {}
                    Ok(false) => thread::sleep(Duration::from_millis(5)),
                    Err(error) => return Err(error),
                }
            }
        })
        .map_err(|error| format!("start read-only RPC worker: {error}"))?;

    // Keep authenticated P2P block ingress responsive during local PoW. The worker handles one
    // inbound connection at a time (bounded back-pressure); canonical writes remain serialized
    // by NodeState's mutex and therefore cannot race the transaction-mining submit path.
    let block_shutdown = Arc::new(AtomicBool::new(false));
    let block_worker_shutdown = Arc::clone(&block_shutdown);
    let block_worker_state = Arc::clone(&state);
    let (block_worker_error_tx, block_worker_error_rx) = mpsc::channel::<String>();
    let block_worker = thread::Builder::new()
        .name("qrun-authenticated-block-listener".into())
        .spawn(move || -> Result<(), String> {
            loop {
                if block_worker_shutdown.load(Ordering::Acquire) {
                    return Ok(());
                }
                match poll_block_listener(&block_listener, &block_worker_state) {
                    Ok(true) => {}
                    Ok(false) => thread::sleep(Duration::from_millis(5)),
                    Err(error) => {
                        let _ = block_worker_error_tx.send(error.clone());
                        return Err(error);
                    }
                }
            }
        })
        .map_err(|error| format!("start authenticated block listener worker: {error}"))?;

    if config.mainnet {
        state
            .lock()
            .map_err(|_| "node state lock poisoned".to_string())?
            .mainnet = true;
        println!("QRUN_V05_MAINNET_NODE_READY");
        println!("mainnet=true");
        println!("network_class=qzxb_mainnet");
        println!("frozen_genesis_verified=true");
        if config.sync_on_start {
            println!("pinned_peer_sync_verified=true");
        } else {
            println!("startup_mode=genesis_bootstrap_or_validated_local_store");
        }
    }
    println!(
        "qrun_pow_local_rpc_ready address={} read_only=true mainnet={}",
        config.rpc_listen, config.mainnet
    );
    println!(
        "qrun_pow_local_tx_ready address={} protocol=QZTS/1 mainnet={}",
        config.tx_listen, config.mainnet
    );
    println!(
        "qrun_pow_local_block_ready address={} protocol=QRB5/2 loopback_only={}",
        config.block_listen, !config.public_alpha
    );

    let loop_result: Result<(), String> = loop {
        if shutdown_signal.is_shutdown_requested() {
            println!("qrun_node_shutdown_requested source=process_signal_or_console_control");
            break Ok(());
        }
        match block_worker_error_rx.try_recv() {
            Ok(error) => {
                break Err(format!(
                    "authenticated block listener worker failed: {error}"
                ))
            }
            Err(mpsc::TryRecvError::Empty) => {}
            Err(mpsc::TryRecvError::Disconnected) => {
                break Err("authenticated block listener worker exited unexpectedly".into());
            }
        }

        let iteration_result =
            (|| -> Result<bool, String> { poll_transaction_listener(&tx_listener, &state) })();

        match iteration_result {
            Ok(handled) => {
                if !handled {
                    std::thread::sleep(Duration::from_millis(5));
                }
            }
            Err(error) => break Err(error),
        }
    };

    // Stop both listener workers before dropping NodeState. A block worker may be finishing
    // one bounded Noise exchange / block validation / peer forward; no new request is accepted.
    block_shutdown.store(true, Ordering::Release);
    rpc_shutdown.store(true, Ordering::Release);
    let block_worker_result = block_worker
        .join()
        .map_err(|_| "authenticated block listener worker panicked".to_string())
        .and_then(|result| result);
    let rpc_worker_result = rpc_worker
        .join()
        .map_err(|_| "read-only RPC worker panicked".to_string())
        .and_then(|result| result);

    // Join the optional service explicitly while the signal callback is still installed. Dropping
    // NodeState afterwards is idempotent and zeroizes its node-local Noise private key.
    let shutdown_result = state
        .lock()
        .map_err(|_| "node state lock poisoned during shutdown".to_string())
        .and_then(|mut node_state| node_state.shutdown_offhost_anchor_service());
    drop(state);

    let signal_restore_result = shutdown_signal
        .uninstall()
        .map_err(|error| format!("restore QRun process shutdown handlers: {error}"));

    loop_result?;
    block_worker_result?;
    rpc_worker_result?;
    shutdown_result?;
    signal_restore_result?;
    println!("qrun_node_lifecycle_cleanup_complete");
    Ok(())
}

fn main() {
    match parse_config() {
        Ok(config) => {
            if let Err(error) = run(config) {
                eprintln!(
                    "QRUN_V05_LOCAL_NODE_ERROR: {}",
                    error.replace(['\r', '\n'], "_")
                );
                std::process::exit(2);
            }
        }
        Err(error) if error == "__help__" => {}
        Err(error) => {
            eprintln!(
                "QRUN_V05_LOCAL_NODE_ERROR: {}",
                error.replace(['\r', '\n'], "_")
            );
            std::process::exit(2);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ai_native_l1_pow_bench::external_cas_disk_provider_candidate::DurableExternalCasProvider;
    use ai_native_l1_pow_bench::state_machine::Transaction;
    use ai_native_l1_pow_bench::transaction_auth::Ed25519TransactionSigner;
    use libcrux_ml_dsa::ml_dsa_65::portable;
    use snow::{params::NoiseParams, Builder};
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::Arc;
    use std::thread;

    static NEXT_TEST_DIR: AtomicU64 = AtomicU64::new(1);
    #[test]
    fn public_alpha_pow_nonce_slice_size_is_bounded_for_live_timestamp_freshness() {
        assert!(PUBLIC_ALPHA_POW_NONCE_SLICE_ATTEMPTS > 0);
        assert!(
            PUBLIC_ALPHA_POW_NONCE_SLICE_ATTEMPTS <= 16,
            "PoW slices must stay short enough to refresh the live timestamp during slow mining"
        );
    }

    #[test]
    fn genesis_timestamp_cli_requires_nonzero_shared_epoch_for_public_modes() {
        let empty = BTreeMap::new();
        assert_eq!(
            parse_genesis_timestamp_option(&empty, false, false),
            Ok(None)
        );
        assert!(parse_genesis_timestamp_option(&empty, true, false)
            .unwrap_err()
            .contains("--public-alpha requires"));
        assert!(parse_genesis_timestamp_option(&empty, false, true)
            .unwrap_err()
            .contains("--mainnet requires"));

        let valid = BTreeMap::from([(
            "--genesis-time-unix-secs".to_string(),
            "1800000000".to_string(),
        )]);
        assert_eq!(
            parse_genesis_timestamp_option(&valid, true, false),
            Ok(Some(1_800_000_000))
        );
        assert_eq!(
            parse_genesis_timestamp_option(&valid, false, true),
            Ok(Some(1_800_000_000))
        );
        // Isolated loopback compatibility mode may still omit the optional time anchor.
        assert_eq!(
            parse_genesis_timestamp_option(&valid, false, false),
            Ok(Some(1_800_000_000))
        );

        let zero = BTreeMap::from([("--genesis-time-unix-secs".to_string(), "0".to_string())]);
        assert!(parse_genesis_timestamp_option(&zero, false, false)
            .unwrap_err()
            .contains("must be nonzero"));

        let malformed = BTreeMap::from([(
            "--genesis-time-unix-secs".to_string(),
            "not-a-timestamp".to_string(),
        )]);
        assert!(parse_genesis_timestamp_option(&malformed, false, false)
            .unwrap_err()
            .contains("unsigned Unix timestamp"));
    }

    #[test]
    fn qrun_nodes_with_different_signed_time_policies_cannot_complete_noise_handshake() {
        let network = [0xB8; 32];
        let params = smoke_params();
        let genesis = [0xB9; 32];
        let profile_a =
            profile_id_with_reference_time_policy(&network, &params, &genesis, Some([0xC1; 32]));
        let profile_b =
            profile_id_with_reference_time_policy(&network, &params, &genesis, Some([0xC2; 32]));
        assert_ne!(profile_a, profile_b);

        let (server_private, _) = test_noise_keypair();
        let (client_private, _) = test_noise_keypair();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(6)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(6)))
                .unwrap();
            QRunV05NoiseSession::accept_public(&mut stream, &server_private, &network, &profile_a)
                .map(|_| ())
        });

        let mut stream = TcpStream::connect(address).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(6)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(6)))
            .unwrap();
        let client =
            QRunV05NoiseSession::connect_public(&mut stream, &client_private, &network, &profile_b);
        assert!(
            client.is_err(),
            "different signed time-policy digests must fail the Noise prologue authentication"
        );
        assert!(
            server.join().unwrap().is_err(),
            "the peer must independently reject the mismatched QRun profile"
        );
    }

    #[test]
    fn live_mining_timestamp_uses_reference_sample_and_fails_when_chain_is_too_far_ahead() {
        assert_eq!(
            next_live_block_timestamp(1_000, 999),
            Ok(1_000),
            "a node must not substitute its raw OS clock after receiving the shared sample"
        );
        assert_eq!(
            next_live_block_timestamp(1_001, 1_000),
            Ok(1_001),
            "the first block must advance strictly beyond Genesis"
        );
        assert_eq!(
            next_live_block_timestamp(1_000, 1_119),
            Ok(1_120),
            "monotonic advancement at the inclusive +120-second edge is allowed"
        );
        assert!(next_live_block_timestamp(1_000, 1_120)
            .unwrap_err()
            .contains("more than 120 seconds ahead"));
        assert!(next_live_block_timestamp(1_000, u64::MAX)
            .unwrap_err()
            .contains("timestamp is exhausted"));
    }

    #[test]
    fn authenticated_reference_time_cli_is_required_for_public_networks_and_all_or_none() {
        let empty = BTreeMap::new();
        assert!(parse_reference_time_node_config(&empty, true)
            .unwrap_err()
            .contains("complete authenticated reference-time configuration"));
        assert!(parse_reference_time_node_config(&empty, false)
            .unwrap()
            .is_none());

        let signer = Ed25519TransactionSigner::from_seed([0x72; 32]);
        let policy_file = std::env::temp_dir().join("qrun-reference-time-policy.rtp1");
        let state_file = std::env::temp_dir().join("qrun-reference-time-high-water.rts1");
        let valid = BTreeMap::from([
            (
                "--reference-time-policy-file".into(),
                policy_file.to_string_lossy().into_owned(),
            ),
            (
                "--reference-time-admin-public-key-hex".into(),
                hex(&signer.public_key()),
            ),
            ("--reference-time-address".into(), "192.0.2.81:49550".into()),
            (
                "--reference-time-state-file".into(),
                state_file.to_string_lossy().into_owned(),
            ),
        ]);
        let parsed = parse_reference_time_node_config(&valid, true)
            .unwrap()
            .unwrap();
        assert_eq!(parsed.policy_file, policy_file);
        assert_eq!(parsed.state_file, state_file);
        assert_eq!(parsed.address, "192.0.2.81:49550".parse().unwrap());
        assert_eq!(parsed.admin_public_key, signer.public_key());

        let mut partial = valid.clone();
        partial.remove("--reference-time-state-file");
        assert!(parse_reference_time_node_config(&partial, false)
            .unwrap_err()
            .contains("all-or-none"));

        let mut weak_key = valid.clone();
        weak_key.insert(
            "--reference-time-admin-public-key-hex".into(),
            "00".repeat(32),
        );
        assert!(parse_reference_time_node_config(&weak_key, false)
            .unwrap_err()
            .contains("must be nonzero"));

        let mut invalid_address = valid.clone();
        invalid_address.insert("--reference-time-address".into(), "0.0.0.0:0".into());
        assert!(parse_reference_time_node_config(&invalid_address, false)
            .unwrap_err()
            .contains("nonzero port"));

        let mut overlapping = valid;
        overlapping.insert(
            "--reference-time-state-file".into(),
            policy_file.to_string_lossy().into_owned(),
        );
        assert!(parse_reference_time_node_config(&overlapping, false)
            .unwrap_err()
            .contains("separate from the signed policy file"));
    }

    #[test]
    fn qrun_node_reference_time_wiring_verifies_network_bound_policy_and_persists_attestation() {
        use ai_native_l1_pow_bench::reference_time::{
            ATTESTATION_BODY_LEN, ATTESTATION_DOMAIN, ATTESTATION_MAGIC, POLICY_BODY_LEN,
            POLICY_DOMAIN, POLICY_MAGIC, WIRE_VERSION,
        };
        use ed25519_dalek::{Signer, SigningKey};

        const NETWORK: [u8; 32] = [0xB3; 32];
        const ADMIN_SEED: [u8; 32] = [0xB4; 32];
        const AUTHORITY_SEED: [u8; 32] = [0xB5; 32];
        let dir = TestDir::new();
        let policy_file = dir.0.join("node-time-policy.rtp1");
        let state_file = dir.0.join("node-time-state.rts1");
        let admin = SigningKey::from_bytes(&ADMIN_SEED);
        let authority = SigningKey::from_bytes(&AUTHORITY_SEED);

        let mut policy_wire = Vec::with_capacity(POLICY_WIRE_LEN);
        policy_wire.extend_from_slice(POLICY_MAGIC);
        policy_wire.extend_from_slice(&WIRE_VERSION.to_be_bytes());
        policy_wire.extend_from_slice(&NETWORK);
        policy_wire.extend_from_slice(&1u64.to_be_bytes());
        policy_wire.extend_from_slice(&authority.verifying_key().to_bytes());
        policy_wire.extend_from_slice(&500u32.to_be_bytes());
        policy_wire.extend_from_slice(&u64::MAX.to_be_bytes());
        assert_eq!(policy_wire.len(), POLICY_BODY_LEN);
        let policy_signature = admin.sign(&[POLICY_DOMAIN, policy_wire.as_slice()].concat());
        policy_wire.extend_from_slice(&policy_signature.to_bytes());
        fs::write(&policy_file, &policy_wire).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut frame_length = [0u8; 4];
            stream.read_exact(&mut frame_length).unwrap();
            assert_eq!(
                u32::from_be_bytes(frame_length) as usize,
                ai_native_l1_pow_bench::reference_time_tcp::REQUEST_BODY_LEN
            );
            let mut request =
                vec![0u8; ai_native_l1_pow_bench::reference_time_tcp::REQUEST_BODY_LEN];
            stream.read_exact(&mut request).unwrap();
            assert_eq!(
                &request[..4],
                ai_native_l1_pow_bench::reference_time_tcp::REQUEST_MAGIC
            );
            assert_eq!(&request[6..38], &NETWORK);
            let challenge: [u8; 32] = request[38..70].try_into().unwrap();
            let unix_seconds = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            let mut response =
                Vec::with_capacity(ai_native_l1_pow_bench::reference_time::ATTESTATION_WIRE_LEN);
            response.extend_from_slice(ATTESTATION_MAGIC);
            response.extend_from_slice(&WIRE_VERSION.to_be_bytes());
            response.extend_from_slice(&NETWORK);
            response.extend_from_slice(&challenge);
            response.extend_from_slice(&unix_seconds.to_be_bytes());
            response.extend_from_slice(&1u64.to_be_bytes());
            assert_eq!(response.len(), ATTESTATION_BODY_LEN);
            let signature = authority.sign(&[ATTESTATION_DOMAIN, response.as_slice()].concat());
            response.extend_from_slice(&signature.to_bytes());
            stream
                .write_all(&(response.len() as u32).to_be_bytes())
                .unwrap();
            stream.write_all(&response).unwrap();
            stream.flush().unwrap();
        });

        let reference_time_config = ReferenceTimeNodeConfig {
            policy_file: policy_file.clone(),
            admin_public_key: admin.verifying_key().to_bytes(),
            address,
            state_file: state_file.clone(),
        };
        let provider =
            build_authenticated_node_reference_time(&reference_time_config, &NETWORK).unwrap();
        let expected_policy_digest: [u8; 32] = Sha256::digest(&policy_wire).into();
        assert_eq!(provider.policy_digest(), Some(expected_policy_digest));
        let sample = provider.sample().unwrap();
        assert_eq!(
            sample.provenance,
            ReferenceTimeProvenance::ConfiguredProvider
        );
        assert_eq!(sample.source_id, "ed25519-attested-time-v1");
        assert!(sample.unix_seconds > 0);
        server.join().unwrap();
        drop(provider);

        let stored = ReferenceTimeStateStore::open(&state_file, &NETWORK).unwrap();
        assert_eq!(stored.last_accepted_sequence().unwrap(), 1);
        assert_eq!(stored.policy_trust_state().unwrap().highest_sequence(), 1);
        drop(stored);

        let wrong_network_state = dir.0.join("wrong-network-time-state.rts1");
        let error = match build_authenticated_node_reference_time(
            &ReferenceTimeNodeConfig {
                state_file: wrong_network_state,
                ..reference_time_config
            },
            &[0xB6; 32],
        ) {
            Ok(_) => panic!("wrong-network reference-time policy unexpectedly verified"),
            Err(error) => error,
        };
        assert!(error.contains("PolicyNetworkMismatch"));
    }

    fn external_cas_cli_values() -> BTreeMap<String, String> {
        // These are parser fixtures, not fixed Windows paths: the parser must accept
        // native absolute paths on every CI operating system.
        let temp = std::env::temp_dir();
        let path = |name: &str| temp.join(name).to_string_lossy().into_owned();
        BTreeMap::from([
            ("--external-cas-endpoint".into(), "127.0.0.1:49410".into()),
            ("--external-cas-provider-id-hex".into(), "11".repeat(32)),
            ("--external-cas-genesis-id-hex".into(), "22".repeat(32)),
            (
                "--external-cas-noise-server-static-public-key-hex".into(),
                "33".repeat(32),
            ),
            (
                "--external-cas-noise-private-key-file".into(),
                path("qrun-cas-client.npk1"),
            ),
            ("--external-cas-receipt-key-id-hex".into(), "44".repeat(32)),
            (
                "--external-cas-receipt-public-key-file".into(),
                path("qrun-cas-receipt.pub"),
            ),
            (
                "--external-cas-bootstrap-record-file".into(),
                path("qrun-cas-bootstrap.ecr1"),
            ),
            (
                "--external-cas-floor-dir".into(),
                path("qrun-independent-floor"),
            ),
        ])
    }

    #[test]
    fn qrm1_recovery_cli_is_explicit_and_requires_separate_archive_and_existing_floor() {
        let mut missing_archive_root = external_cas_cli_values();
        missing_archive_root.insert("--external-cas-recover-qrm1".into(), "true".into());
        assert!(parse_external_cas_config(&missing_archive_root, false)
            .unwrap_err()
            .contains("--external-cas-history-archive-root"));

        let mut recovery = external_cas_cli_values();
        let archive_root = std::env::temp_dir().join("qrun-qra1-operator-archives");
        recovery.insert("--external-cas-recover-qrm1".into(), "true".into());
        recovery.insert(
            "--external-cas-history-archive-root".into(),
            archive_root.to_string_lossy().into_owned(),
        );
        let config = parse_external_cas_config(&recovery, false)
            .unwrap()
            .unwrap();
        assert!(config.recover_qrm1);
        assert_eq!(config.history_archive_root, Some(archive_root.clone()));
        assert!(!config.initialize_floor);

        let mut reset_floor = recovery.clone();
        reset_floor.insert("--external-cas-initialize-floor".into(), "true".into());
        assert!(parse_external_cas_config(&reset_floor, false)
            .unwrap_err()
            .contains("existing QCF1 floor"));

        let mut stale_checkpoint = recovery.clone();
        stale_checkpoint.insert(
            "--external-cas-checkpoint-file".into(),
            std::env::temp_dir()
                .join("qrun-old-checkpoint.qrcp")
                .to_string_lossy()
                .into_owned(),
        );
        stale_checkpoint.insert(
            "--external-cas-checkpoint-commitment-hex".into(),
            "55".repeat(32),
        );
        stale_checkpoint.insert("--external-cas-checkpoint-min-height".into(), "10".into());
        stale_checkpoint.insert(
            "--external-cas-migration-parent-commitment-hex".into(),
            "66".repeat(32),
        );
        assert!(parse_external_cas_config(&stale_checkpoint, false)
            .unwrap_err()
            .contains("derive the checkpoint internally"));

        let mut orphan_root = external_cas_cli_values();
        orphan_root.insert(
            "--external-cas-history-archive-root".into(),
            archive_root.to_string_lossy().into_owned(),
        );
        assert!(parse_external_cas_config(&orphan_root, false)
            .unwrap_err()
            .contains("only with explicit QRM1 recovery or Genesis checkpoint migration"));
    }

    #[test]
    fn genesis_checkpoint_migration_cli_requires_explicit_archive_output_and_parent() {
        let mut values = external_cas_cli_values();
        let archive_root = std::env::temp_dir().join("qrun-genesis-migration-archives");
        let checkpoint_output = std::env::temp_dir().join("qrun-genesis-migrated.qrcp");
        values.insert(
            "--external-cas-migrate-genesis-checkpoint".into(),
            "true".into(),
        );
        values.insert(
            "--external-cas-history-archive-root".into(),
            archive_root.to_string_lossy().into_owned(),
        );
        values.insert(
            "--external-cas-checkpoint-output-file".into(),
            checkpoint_output.to_string_lossy().into_owned(),
        );
        values.insert(
            "--external-cas-migration-parent-commitment-hex".into(),
            "66".repeat(32),
        );
        let config = parse_external_cas_config(&values, false).unwrap().unwrap();
        assert!(config.migrate_genesis_checkpoint);
        assert_eq!(config.history_archive_root, Some(archive_root));
        assert_eq!(config.checkpoint_output_file, Some(checkpoint_output));
        assert_eq!(config.checkpoint_parent_commitment, Some([0x66; 32]));
        assert!(config.checkpoint.is_none());

        let mut missing_output = values.clone();
        missing_output.remove("--external-cas-checkpoint-output-file");
        assert!(parse_external_cas_config(&missing_output, false)
            .unwrap_err()
            .contains("requires both --external-cas-checkpoint-output-file"));

        let mut zero_parent = values.clone();
        zero_parent.insert(
            "--external-cas-migration-parent-commitment-hex".into(),
            "00".repeat(32),
        );
        assert!(parse_external_cas_config(&zero_parent, false)
            .unwrap_err()
            .contains("parent checkpoint commitment must be nonzero"));

        let mut without_archive = values.clone();
        without_archive.remove("--external-cas-history-archive-root");
        assert!(parse_external_cas_config(&without_archive, false)
            .unwrap_err()
            .contains("requires --external-cas-history-archive-root"));

        let mut with_recovery = values.clone();
        with_recovery.insert("--external-cas-recover-qrm1".into(), "true".into());
        assert!(parse_external_cas_config(&with_recovery, false)
            .unwrap_err()
            .contains("separate maintenance operations"));

        let mut with_checkpoint_bootstrap = values.clone();
        with_checkpoint_bootstrap.insert(
            "--external-cas-checkpoint-file".into(),
            std::env::temp_dir()
                .join("stale.qrcp")
                .to_string_lossy()
                .into_owned(),
        );
        with_checkpoint_bootstrap.insert(
            "--external-cas-checkpoint-commitment-hex".into(),
            "55".repeat(32),
        );
        with_checkpoint_bootstrap.insert("--external-cas-checkpoint-min-height".into(), "1".into());
        with_checkpoint_bootstrap.insert(
            "--external-cas-checkpoint-parent-commitment-hex".into(),
            "77".repeat(32),
        );
        assert!(parse_external_cas_config(&with_checkpoint_bootstrap, false)
            .unwrap_err()
            .contains("derive the checkpoint internally"));

        let mut output_without_flag = values.clone();
        output_without_flag.remove("--external-cas-migrate-genesis-checkpoint");
        output_without_flag.remove("--external-cas-history-archive-root");
        assert!(parse_external_cas_config(&output_without_flag, false)
            .unwrap_err()
            .contains("options require --external-cas-migrate-genesis-checkpoint true"));
    }

    #[test]
    fn external_cas_cli_config_is_all_or_none_and_requires_numeric_endpoint() {
        assert!(parse_external_cas_config(&BTreeMap::new(), false)
            .unwrap()
            .is_none());

        let mut partial = external_cas_cli_values();
        partial.remove("--external-cas-bootstrap-record-file");
        assert!(parse_external_cas_config(&partial, true)
            .unwrap_err()
            .contains("all-or-none"));

        let mut init_alone = BTreeMap::new();
        init_alone.insert("--external-cas-initialize-floor".into(), "true".into());
        assert!(parse_external_cas_config(&init_alone, true)
            .unwrap_err()
            .contains("requires the complete"));

        let mut bad_endpoint = external_cas_cli_values();
        bad_endpoint.insert(
            "--external-cas-endpoint".into(),
            "provider.example:49410".into(),
        );
        assert!(parse_external_cas_config(&bad_endpoint, true)
            .unwrap_err()
            .contains("numeric IP:PORT"));
    }

    #[test]
    fn external_cas_cli_config_parses_pins_paths_and_explicit_floor_initialization() {
        let mut values = external_cas_cli_values();
        values.insert("--external-cas-initialize-floor".into(), "true".into());
        let config = parse_external_cas_config(&values, false).unwrap().unwrap();
        assert_eq!(config.endpoint, "127.0.0.1:49410".parse().unwrap());
        assert_eq!(config.provider_id, [0x11; 32]);
        assert_eq!(config.genesis_commitment, [0x22; 32]);
        assert_eq!(config.noise_server_static_public_key, [0x33; 32]);
        assert_eq!(config.receipt_key_id, [0x44; 32]);
        assert!(config.initialize_floor);
        assert!(!config.recover_qrm1);
        assert!(config.history_archive_root.is_none());
        assert_eq!(
            config.floor_directory,
            std::env::temp_dir().join("qrun-independent-floor")
        );
    }

    #[test]
    fn external_cas_checkpoint_cli_requires_the_complete_independent_trust_tuple() {
        let mut values = external_cas_cli_values();
        let temp = std::env::temp_dir();
        values.insert(
            "--external-cas-checkpoint-file".into(),
            temp.join("qrun-checkpoint.qrcp")
                .to_string_lossy()
                .into_owned(),
        );
        values.insert(
            "--external-cas-checkpoint-commitment-hex".into(),
            "55".repeat(32),
        );
        values.insert("--external-cas-checkpoint-min-height".into(), "2048".into());
        values.insert(
            "--external-cas-checkpoint-parent-commitment-hex".into(),
            "66".repeat(32),
        );

        let config = parse_external_cas_config(&values, false).unwrap().unwrap();
        let checkpoint = config.checkpoint.unwrap();
        assert_eq!(checkpoint.expected_commitment, [0x55; 32]);
        assert_eq!(checkpoint.minimum_height, 2048);
        assert_eq!(checkpoint.expected_parent_commitment, [0x66; 32]);
        assert_eq!(checkpoint.record_file, temp.join("qrun-checkpoint.qrcp"));

        let mut partial = values.clone();
        partial.remove("--external-cas-checkpoint-parent-commitment-hex");
        assert!(parse_external_cas_config(&partial, false)
            .unwrap_err()
            .contains("checkpoint bootstrap configuration is all-or-none"));

        let mut zero_height = values.clone();
        zero_height.insert("--external-cas-checkpoint-min-height".into(), "0".into());
        assert!(parse_external_cas_config(&zero_height, false)
            .unwrap_err()
            .contains("must be nonzero"));

        let mut checkpoint_without_cas = BTreeMap::new();
        checkpoint_without_cas.extend(
            values
                .into_iter()
                .filter(|(key, _)| key.starts_with("--external-cas-checkpoint-")),
        );
        assert!(parse_external_cas_config(&checkpoint_without_cas, false)
            .unwrap_err()
            .contains("complete external-CAS pin and floor configuration"));
    }

    #[test]
    fn external_cas_cli_config_rejects_zero_pins_public_endpoint_in_local_mode_and_bad_boolean() {
        let mut zero_pin = external_cas_cli_values();
        zero_pin.insert("--external-cas-provider-id-hex".into(), "00".repeat(32));
        assert!(parse_external_cas_config(&zero_pin, true)
            .unwrap_err()
            .contains("must be nonzero"));

        let mut public_endpoint = external_cas_cli_values();
        public_endpoint.insert(
            "--external-cas-endpoint".into(),
            "203.0.113.10:49410".into(),
        );
        assert!(parse_external_cas_config(&public_endpoint, false)
            .unwrap_err()
            .contains("loopback-only"));

        let mut bad_boolean = external_cas_cli_values();
        bad_boolean.insert("--external-cas-initialize-floor".into(), "yes".into());
        assert!(parse_external_cas_config(&bad_boolean, true)
            .unwrap_err()
            .contains("exactly true or false"));
    }

    #[test]
    fn external_cas_floor_directory_must_not_overlap_node_data() {
        assert!(paths_overlap(
            std::path::Path::new(r"C:\qrun\data"),
            std::path::Path::new(r"C:\qrun\data\floor")
        ));
        assert!(paths_overlap(
            std::path::Path::new(r"C:\qrun\data"),
            std::path::Path::new(r"c:\QRUN\data")
        ));
        assert!(!paths_overlap(
            std::path::Path::new(r"C:\qrun\data"),
            std::path::Path::new(r"D:\qrun\floor")
        ));
        assert!(!paths_overlap(
            std::path::Path::new(r"C:\qrun\data"),
            std::path::Path::new(r"C:\qrun\data-floor")
        ));
        assert!(paths_overlap(
            std::path::Path::new(r"C:\qrun\floor"),
            std::path::Path::new(r"C:\qrun\floor\..\floor\checkpoint.qrcp")
        ));
        assert!(paths_overlap(
            std::path::Path::new("/qrun/floor"),
            std::path::Path::new("/qrun/floor/../floor/checkpoint.qrcp")
        ));
        assert!(!paths_overlap(
            std::path::Path::new(r"C:\qrun\floor"),
            std::path::Path::new(r"C:\qrun\checkpoint.qrcp")
        ));
    }

    // DPAPI protects the client Noise private key on Windows; this integration
    // path is intentionally exercised only on Windows rather than weakening key
    // protection or adding a plaintext fallback on Unix CI.
    #[cfg(windows)]
    #[test]
    fn external_cas_node_startup_uses_pinned_noise_provider_and_advances_floor_before_return() {
        let dir = TestDir::new();
        let node_data_dir = dir.0.join("node-data");
        let floor_dir = dir.0.join("independent-floor");
        let provider_dir = dir.0.join("provider");
        let store_dir = node_data_dir.join("qrun-v05-qfp5-store");
        let archive_root = dir.0.join("history-archives");
        let checkpoint_record_file = dir.0.join("qrun-genesis-migrated.qrcp");
        fs::create_dir_all(&node_data_dir).unwrap();
        fs::create_dir_all(&archive_root).unwrap();

        let network = [0x71; 32];
        let signer = Ed25519TransactionSigner::from_seed([0x72; 32]);
        let owner = signer.account_id();
        let authenticator = Ed25519TransactionAuthenticator::select(
            TransactionAuthenticatorKind::Ed25519V1,
            [AccountPublicKey {
                account_id: owner,
                public_key: signer.public_key(),
            }],
        )
        .unwrap();
        let clock = SystemClockReferenceTime;
        let mut params = smoke_params();
        params.protocol_version = 5;
        let genesis_timestamp = now_unix().unwrap().saturating_sub(10);
        let genesis =
            QRunGenesisV05::new_with_genesis_timestamp(network, owner, genesis_timestamp).unwrap();

        // Build a parent-linked height-one checkpoint, then derive the exact empty PFS2 suffix
        // manifest that the independently initialized provider is expected to anchor.
        let genesis_archive =
            ai_native_l1_pow_bench::private_testnet_fork_choice::PrivateTestnetForkChoice::new_qrun_v05_fee_only(
                genesis.ledger().clone(),
                params.clone(),
            )
            .unwrap();
        let genesis_checkpoint =
            ai_native_l1_pow_bench::qrun_v05_checkpoint_candidate::QRunV05PowCheckpoint::capture(
                network,
                genesis.commitment(),
                &params,
                genesis_archive.canonical_chain(),
                [0; 32],
            )
            .unwrap();
        let genesis_checkpoint_commitment = genesis_checkpoint.commitment(&params).unwrap();

        // Create a real Genesis-rooted PFS2 source store at the exact node data path, with one
        // accepted QFP5 block. The ECR1/QCF1 bootstrap is provisioned out-of-band against this
        // exact active manifest; the migration command itself must not rewrite the bootstrap.
        let mut source_runtime = QRunV05PowForkRuntime::open_with_genesis_timestamp(
            &store_dir,
            network,
            owner,
            params.clone(),
            &authenticator,
            &clock,
            genesis_timestamp,
        )
        .unwrap();
        source_runtime.set_producer_account(owner).unwrap();
        let source_envelope = source_runtime
            .mine_candidate(now_unix().unwrap() + 5, Vec::new(), &authenticator, 1)
            .unwrap();
        source_runtime
            .submit_block(&source_envelope, &authenticator, &clock)
            .unwrap();
        assert_eq!(source_runtime.canonical_height(), 1);
        let source_tip = source_runtime.canonical_tip();
        let source_state_root = source_runtime.canonical_state_root();
        let source_store = source_runtime.into_store();
        let initial_anchor = source_store.manifest_anchor().unwrap();
        drop(source_store);

        let receipt_keys = portable::generate_key_pair([0x73; 32]);
        let receipt_signing_key = Arc::new(receipt_keys.signing_key);
        let receipt_public_key: [u8;
            ai_native_l1_pow_bench::v4_fat1_trust_candidate::ML_DSA_65_PUBLIC_KEY_BYTES] =
            *receipt_keys.verification_key.as_ref();
        let pin = ExternalCasPin {
            provider_id: [0x74; 32],
            network_id: network,
            genesis_digest: genesis.commitment(),
            receipt_key_id: [0x75; 32],
            receipt_public_key,
        };
        let bootstrap = ExternalCasRecord {
            generation: 0,
            provider_id: pin.provider_id,
            network_id: pin.network_id,
            genesis_digest: pin.genesis_digest,
            previous_record_digest: [0; 32],
            previous_state_digest: [0; 32],
            next_state_digest: initial_anchor,
            operation_id: [0x76; 32],
            request_digest: [0x77; 32],
        };
        DurableExternalCasProvider::initialize(&provider_dir, pin.clone(), bootstrap.clone(), {
            let key = receipt_signing_key.clone();
            move |digest| {
                let signature = portable::sign(&key, digest, &[], [0x78; 32])
                    .map_err(|error| format!("{error:?}"))?;
                Ok(*signature.as_ref())
            }
        })
        .unwrap();

        let noise_params: NoiseParams = "Noise_XX_25519_ChaChaPoly_SHA256".parse().unwrap();
        let server_noise = Builder::new(noise_params.clone())
            .generate_keypair()
            .unwrap();
        let client_noise = Builder::new(noise_params).generate_keypair().unwrap();
        let server_private: [u8; 32] = server_noise.private.as_slice().try_into().unwrap();
        let server_public: [u8; 32] = server_noise.public.as_slice().try_into().unwrap();
        let client_private: [u8; 32] = client_noise.private.as_slice().try_into().unwrap();
        let client_public: [u8; 32] = client_noise.public.as_slice().try_into().unwrap();

        let noise_private_key_file = dir.0.join("cas-client.npk1");
        ai_native_l1_pow_bench::noise_key_provisioning::store_protected_noise_private_key(
            &noise_private_key_file,
            &network,
            &client_private,
        )
        .unwrap();
        let receipt_public_key_file = dir.0.join("receipt-key.pub");
        fs::write(&receipt_public_key_file, receipt_public_key).unwrap();
        let bootstrap_record_file = dir.0.join("provider-bootstrap.ecr1");
        fs::write(&bootstrap_record_file, bootstrap.encode().unwrap()).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let endpoint = listener.local_addr().unwrap();
        let server_pin = pin.clone();
        let server_receipt_key = receipt_signing_key.clone();
        let server_stop = Arc::new(AtomicBool::new(false));
        let server_stop_thread = server_stop.clone();
        let server_dir = provider_dir.clone();
        let server = thread::spawn(move || -> Result<(), String> {
            while !server_stop_thread.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        stream
                            .set_read_timeout(Some(Duration::from_secs(5)))
                            .map_err(|error| error.to_string())?;
                        stream
                            .set_write_timeout(Some(Duration::from_secs(5)))
                            .map_err(|error| error.to_string())?;
                        let key = server_receipt_key.clone();
                        let mut provider = DurableExternalCasProvider::open(
                            &server_dir,
                            server_pin.clone(),
                            move |digest| {
                                let signature = portable::sign(&key, digest, &[], [0x78; 32])
                                    .map_err(|error| format!("{error:?}"))?;
                                Ok(*signature.as_ref())
                            },
                        )
                        .map_err(|error| error.to_string())?;
                        ai_native_l1_pow_bench::external_cas_noise_transport_candidate::serve_external_cas_noise_connection(
                            &mut stream,
                            &server_private,
                            &[client_public],
                            &server_pin,
                            &mut provider,
                        )
                        .map_err(|error| error.to_string())?;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) => return Err(error.to_string()),
                }
            }
            Ok(())
        });

        let external = ExternalCasNodeConfig {
            endpoint,
            provider_id: pin.provider_id,
            genesis_commitment: pin.genesis_digest,
            receipt_key_id: pin.receipt_key_id,
            noise_server_static_public_key: server_public,
            noise_private_key_file,
            receipt_public_key_file,
            bootstrap_record_file,
            floor_directory: floor_dir.clone(),
            initialize_floor: true,
            recover_qrm1: false,
            history_archive_root: Some(archive_root.clone()),
            migrate_genesis_checkpoint: true,
            checkpoint_output_file: Some(checkpoint_record_file.clone()),
            checkpoint_parent_commitment: Some(genesis_checkpoint_commitment),
            checkpoint: None,
        };

        // A wrong parent checkpoint must fail before QRM1/CAS mutation. QCF1 is already
        // initialized from the independent generation-zero bootstrap, but its record/floor must
        // remain byte-exactly at generation zero after this rejected maintenance request.
        let mut wrong_parent = external.clone();
        wrong_parent.checkpoint_parent_commitment = Some([0xFE; 32]);
        let rejection = match open_node_runtime_with_genesis_timestamp(
            &store_dir,
            network,
            owner,
            params.clone(),
            &authenticator,
            &clock,
            Some(genesis_timestamp),
            Some(&wrong_parent),
        ) {
            Ok(_) => panic!("Genesis checkpoint migration accepted an unrelated QRCP parent"),
            Err(error) => error,
        };
        assert!(
            rejection.contains("Genesis checkpoint parent commitment mismatch"),
            "unexpected wrong-parent migration failure: {rejection}"
        );
        assert!(!checkpoint_record_file.exists());
        assert!(!store_dir.join("qrun-v05-migration.qrm1").exists());
        assert!(
            !floor_dir.exists(),
            "wrong Genesis parent must be rejected before QCF1 initialization"
        );
        let source_reopened = QRunV05PowForkRuntime::open_with_genesis_timestamp(
            &store_dir,
            network,
            owner,
            params.clone(),
            &authenticator,
            &clock,
            genesis_timestamp,
        )
        .unwrap();
        assert_eq!(source_reopened.canonical_height(), 1);
        assert_eq!(source_reopened.canonical_tip(), source_tip);
        assert_eq!(source_reopened.canonical_state_root(), source_state_root);
        drop(source_reopened);

        // The explicit migration flag now drives the complete signed Noise/TCP -> QRA1 replay
        // -> QRM1/CAS/QCF1 -> QRCP/PFS2 transition, and returns an ordinary checkpoint-rooted
        // runtime. A second Noise client session and QCF1 reopen are performed inside startup.
        let opened = open_node_runtime_with_genesis_timestamp(
            &store_dir,
            network,
            owner,
            params.clone(),
            &authenticator,
            &clock,
            Some(genesis_timestamp),
            Some(&external),
        );
        let mut runtime = match opened {
            Ok(runtime) => runtime,
            Err(error) => {
                server_stop.store(true, Ordering::Release);
                let _ = server.join();
                panic!("external-CAS node startup failed: {error}");
            }
        };
        runtime.set_producer_account(owner).unwrap();
        assert_eq!(runtime.canonical_height(), 1);
        assert_eq!(runtime.canonical_tip(), source_tip);
        assert_eq!(runtime.canonical_state_root(), source_state_root);
        let envelope = runtime
            .mine_candidate(now_unix().unwrap() + 15, Vec::new(), &authenticator, 1)
            .unwrap();
        runtime
            .submit_block(&envelope, &authenticator, &clock)
            .unwrap();
        assert_eq!(runtime.canonical_height(), 2);
        let local_manifest_tip = runtime.canonical_tip();
        let local_state_root = runtime.canonical_state_root();

        let store = runtime.into_store();
        let local_manifest_anchor = store.manifest_anchor().unwrap();
        assert!(matches!(store, NodeForkStore::ExternalCas(_)));

        let floor = ExternalCasFloorStore::open(&floor_dir, pin.clone()).unwrap();
        let floor_snapshot = floor.snapshot().unwrap();
        assert_eq!(floor_snapshot.trusted_record.generation, 2);
        assert_eq!(floor_snapshot.minimum_object_generation, 3);
        assert_eq!(
            floor_snapshot.trusted_record.next_state_digest,
            local_manifest_anchor
        );
        assert!(node_data_dir.exists());
        drop(store);

        // Restart must reopen the same checkpoint-rooted suffix with the already advanced CAS
        // record and QCF1 floor; the initialization switch must not reset either anchor.
        let checkpoint_bytes = fs::read(&checkpoint_record_file).unwrap();
        let checkpoint_commitment =
            ai_native_l1_pow_bench::qrun_v05_checkpoint_candidate::QRunV05PowCheckpoint::commitment_for_bytes(
                &checkpoint_bytes,
            );
        let mut restart_config = external.clone();
        restart_config.initialize_floor = true; // AlreadyInitialized must reopen, never reset.
        restart_config.migrate_genesis_checkpoint = false;
        restart_config.history_archive_root = None;
        restart_config.checkpoint_output_file = None;
        restart_config.checkpoint_parent_commitment = None;
        restart_config.checkpoint = Some(ExternalCasNodeCheckpointConfig {
            record_file: checkpoint_record_file.clone(),
            expected_commitment: checkpoint_commitment,
            minimum_height: 1,
            expected_parent_commitment: genesis_checkpoint_commitment,
        });
        let reopened = open_node_runtime_with_genesis_timestamp(
            &store_dir,
            network,
            owner,
            params,
            &authenticator,
            &clock,
            Some(genesis_timestamp),
            Some(&restart_config),
        )
        .unwrap();
        assert_eq!(reopened.canonical_height(), 2);
        assert_eq!(reopened.canonical_tip(), local_manifest_tip);
        assert_eq!(reopened.canonical_state_root(), local_state_root);
        drop(reopened);
        assert!(checkpoint_record_file.is_file());
        let archive_entries = fs::read_dir(&archive_root)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| path.is_dir())
            .collect::<Vec<_>>();
        assert_eq!(
            archive_entries.len(),
            1,
            "unexpected QRA1 archive directories: {archive_entries:?}"
        );
        assert!(archive_entries[0].join("archive.qra1").is_file());
        assert!(archive_root.join("qrun-history-archive.lock").is_file());
        assert!(!store_dir.join("qrun-v05-migration.qrm1").exists());
        assert_eq!(
            ai_native_l1_pow_bench::qrun_v05_checkpoint_candidate::QRunV05PowCheckpoint::commitment_for_bytes(
                &checkpoint_bytes,
            ),
            checkpoint_commitment,
        );

        server_stop.store(true, Ordering::Release);
        server.join().unwrap().unwrap();
    }

    #[test]
    fn qrun_v05_identity_recognizes_current_wallet_bound_and_historical_candidate() {
        assert!(is_qrun_v05_identity(
            &QZXB_MAINNET_NETWORK_ID,
            &QZXB_MAINNET_OWNER_ACCOUNT_ID
        ));
        assert!(is_qrun_v05_identity(
            &ai_native_l1_pow_bench::qrun_v05_profile_identity_candidate::PROPOSED_QRUN_V05_NETWORK_ID,
            &ai_native_l1_pow_bench::qrun_v05_profile_identity_candidate::PROPOSED_OWNER_ACCOUNT_ID
        ));
        assert!(!is_qrun_v05_identity(
            &[0x99; 32],
            &QZXB_MAINNET_OWNER_ACCOUNT_ID
        ));
        assert!(!is_qrun_v05_identity(&QZXB_MAINNET_NETWORK_ID, &[0x99; 32]));
    }

    #[test]
    fn mainnet_release_gate_fails_closed_on_concrete_protocol_blockers() {
        assert!(!QRUN_MAINNET_RELEASE_APPROVED);
        assert!(validate_mainnet_release_gate(false).is_ok());
        let error = validate_mainnet_release_gate(true).unwrap_err();
        assert!(error.contains("--mainnet is disabled by the QRun production release gate"));
        assert!(error.contains("full-history validation/recovery"));
        assert!(error.contains("multi-host restart/reorg/partition/transaction-relay"));
        assert!(error.contains("authenticated bootstrap"));
    }

    #[test]
    fn permissionless_release_gate_does_not_require_a_fixed_operator_count_or_auditor() {
        let blockers = QRUN_MAINNET_RELEASE_BLOCKERS.join(" ");
        assert!(!blockers.contains("three independent operators"));
        assert!(!blockers.contains("independent security review"));
        // Removing those non-protocol dependencies never opens the actual release gate.
        assert!(!QRUN_MAINNET_RELEASE_APPROVED);
    }

    #[test]
    fn mainnet_requires_pinned_external_seed_before_activation() {
        let peer: SocketAddr = "198.51.100.10:49341".parse().unwrap();
        let loopback_peer: SocketAddr = "127.0.0.1:49341".parse().unwrap();
        let public_listener: SocketAddr = "0.0.0.0:49341".parse().unwrap();
        let loopback_listener: SocketAddr = "127.0.0.1:49341".parse().unwrap();

        assert!(validate_mainnet_p2p_requirements(false, false, &[], 0, loopback_listener).is_ok());
        assert!(validate_mainnet_p2p_requirements(true, false, &[], 0, public_listener).is_err());
        assert!(validate_mainnet_p2p_requirements(true, true, &[], 0, public_listener).is_err());
        assert!(validate_mainnet_p2p_requirements(
            true,
            true,
            &[loopback_peer],
            1,
            public_listener
        )
        .is_err());
        assert!(
            validate_mainnet_p2p_requirements(true, true, &[peer], 0, public_listener).is_err()
        );
        assert!(
            validate_mainnet_p2p_requirements(true, true, &[peer], 1, loopback_listener).is_err()
        );
        assert!(validate_mainnet_p2p_requirements(true, true, &[peer], 1, public_listener).is_ok());
    }

    #[test]
    fn listener_policy_allows_public_p2p_for_mainnet_but_keeps_rpc_and_tx_loopback() {
        let rpc: SocketAddr = "127.0.0.1:49339".parse().unwrap();
        let tx: SocketAddr = "127.0.0.1:49340".parse().unwrap();
        let public_listener: SocketAddr = "0.0.0.0:49341".parse().unwrap();
        let peer: SocketAddr = "198.51.100.10:49341".parse().unwrap();
        let loopback_listener: SocketAddr = "127.0.0.1:49341".parse().unwrap();
        let public_rpc: SocketAddr = "0.0.0.0:49339".parse().unwrap();

        assert!(
            validate_listener_bind_policy(false, true, rpc, tx, public_listener, &[peer]).is_ok()
        );
        assert!(validate_listener_bind_policy(true, false, rpc, tx, public_listener, &[]).is_ok());
        assert!(
            validate_listener_bind_policy(false, false, rpc, tx, loopback_listener, &[]).is_ok()
        );
        assert!(
            validate_listener_bind_policy(false, false, rpc, tx, public_listener, &[]).is_err()
        );
        assert!(
            validate_listener_bind_policy(false, false, rpc, tx, loopback_listener, &[peer])
                .is_err()
        );
        assert!(validate_listener_bind_policy(
            false,
            true,
            public_rpc,
            tx,
            public_listener,
            &[peer]
        )
        .is_err());
        assert!(validate_listener_bind_policy(
            false,
            true,
            rpc,
            public_rpc,
            public_listener,
            &[peer]
        )
        .is_err());
    }

    #[test]
    fn mainnet_uses_same_calibrated_candidate_profile_as_public_alpha() {
        let genesis = parse_hex32(QZXB_MAINNET_GENESIS_ID_HEX, "genesis").unwrap();
        let public_alpha = consensus_parameters_for_mode(true, false, false).unwrap();
        let mainnet = consensus_parameters_for_mode(false, true, false).unwrap();
        let local_smoke = consensus_parameters_for_mode(false, false, false).unwrap();

        let public_profile = profile_id(&QZXB_MAINNET_NETWORK_ID, &public_alpha, &genesis);
        let mainnet_profile = profile_id(&QZXB_MAINNET_NETWORK_ID, &mainnet, &genesis);
        let local_profile = profile_id(&QZXB_MAINNET_NETWORK_ID, &local_smoke, &genesis);

        assert_eq!(hex(&public_profile), QZXB_MAINNET_PROFILE_ID_HEX);
        assert_eq!(public_profile, mainnet_profile);
        assert_ne!(public_profile, local_profile);
    }

    #[test]
    fn frozen_mainnet_genesis_gate_checks_frozen_identity_and_genesis_allocation() {
        let genesis = parse_hex32(QZXB_MAINNET_GENESIS_ID_HEX, "genesis").unwrap();
        let profile = parse_hex32(QZXB_MAINNET_PROFILE_ID_HEX, "profile").unwrap();
        let root = parse_hex32(QZXB_MAINNET_STATE_ROOT_HEX, "state root").unwrap();
        let supply = ai_native_l1_pow_bench::state_machine::MAX_TOTAL_SUPPLY_ATOMS;
        assert!(validate_frozen_mainnet_genesis(
            true, &genesis, &profile, &root, supply, supply, 1, 0
        )
        .is_ok());
        assert!(validate_frozen_mainnet_genesis(
            true,
            &genesis,
            &profile,
            &[0xff; 32],
            supply,
            supply,
            1,
            0
        )
        .is_err());
        assert!(validate_frozen_mainnet_genesis(
            true,
            &genesis,
            &profile,
            &root,
            supply - 1,
            supply,
            1,
            0
        )
        .is_err());
        assert!(validate_frozen_mainnet_genesis(
            true, &genesis, &profile, &root, supply, supply, 2, 0
        )
        .is_err());
        // The live tip root/balance/account count can change after valid transfers; the frozen
        // Genesis ID and profile stay constant and the global supply must still match the cap.
        assert!(validate_frozen_mainnet_genesis(
            true,
            &genesis,
            &profile,
            &[0xff; 32],
            supply - 1,
            supply,
            2,
            1
        )
        .is_ok());
        assert!(validate_frozen_mainnet_genesis(
            true,
            &genesis,
            &profile,
            &[0xff; 32],
            supply - 1,
            supply - 1,
            2,
            1
        )
        .is_err());
    }

    #[test]
    fn startup_sync_requires_noise_key_and_a_pinned_seed_for_every_peer() {
        assert!(validate_sync_start_config(false, false, 0, 0).is_ok());
        assert!(validate_sync_start_config(true, false, 1, 1)
            .unwrap_err()
            .contains("--noise-private-key-file"));
        assert!(validate_sync_start_config(true, true, 0, 0)
            .unwrap_err()
            .contains("at least one --peer"));
        assert!(validate_sync_start_config(true, true, 1, 0)
            .unwrap_err()
            .contains("one --peer-static-public-key-hex pin"));
        assert!(validate_sync_start_config(true, true, 2, 1).is_err());
        assert!(validate_sync_start_config(true, true, 2, 2).is_ok());
    }

    struct TestDir(PathBuf);
    impl TestDir {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "qrun_v05_pow_local_node_{}_{}",
                std::process::id(),
                NEXT_TEST_DIR.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn smoke_params() -> ConsensusParameters {
        let mut params = ConsensusParameters::candidate_testnet().unwrap();
        params.initial_target = Uint256::MAX;
        params.pow_limit = Uint256::MAX;
        params.pow.memory_kib = 8 * 1024;
        params.pow.iterations = 1;
        params.pow.lanes = 1;
        params
    }

    fn node_state(
        directory: &Path,
        network: NetworkId,
        signer: &Ed25519TransactionSigner,
    ) -> NodeState {
        node_state_with_params(directory, network, signer, smoke_params())
    }

    fn node_state_with_params(
        directory: &Path,
        network: NetworkId,
        signer: &Ed25519TransactionSigner,
        params: ConsensusParameters,
    ) -> NodeState {
        let owner = signer.account_id();
        let authenticator = Ed25519TransactionAuthenticator::select(
            TransactionAuthenticatorKind::Ed25519V1,
            [AccountPublicKey {
                account_id: owner,
                public_key: signer.public_key(),
            }],
        )
        .unwrap();
        let clock = SystemClockReferenceTime;
        let profile_params = params.clone();
        let runtime =
            open_local_node_runtime(directory, network, owner, params, &authenticator, &clock)
                .unwrap();
        let profile_id = profile_id(&network, &profile_params, &runtime.genesis_commitment());
        let mut state = NodeState {
            runtime,
            public_alpha: false,
            mainnet: false,
            authenticator,
            clock: NodeReferenceTime::SystemClock,
            receipts: BTreeMap::new(),
            profile_id,
            block_peers: Vec::new(),
            noise_private_key: None,
            trusted_peer_static_keys: Vec::new(),
            peer_static_keys_by_addr: BTreeMap::new(),
            d1_evidence: false,
            d2_partition_qualification: false,
            offhost_anchor_service: OffhostAnchorNodeServiceOwner::disabled(),
        };
        state.refresh_receipts().unwrap();
        state
    }

    fn qrun_v05_node_state(directory: &Path, signer: &Ed25519TransactionSigner) -> NodeState {
        use ai_native_l1_pow_bench::qrun_v05_profile_identity_candidate::{
            PROPOSED_OWNER_ACCOUNT_ID, PROPOSED_QRUN_V05_NETWORK_ID,
        };

        let network = PROPOSED_QRUN_V05_NETWORK_ID;
        let owner = PROPOSED_OWNER_ACCOUNT_ID;
        let authenticator = Ed25519TransactionAuthenticator::select(
            TransactionAuthenticatorKind::Ed25519V1,
            [AccountPublicKey {
                account_id: signer.account_id(),
                public_key: signer.public_key(),
            }],
        )
        .unwrap();
        let clock = SystemClockReferenceTime;
        let mut params = smoke_params();
        params.protocol_version = 5;
        let profile_params = params.clone();
        let mut runtime =
            open_local_node_runtime(directory, network, owner, params, &authenticator, &clock)
                .unwrap();
        runtime.set_producer_account(owner).unwrap();
        assert!(runtime.is_qrun_v05_fee_only());
        let profile_id = profile_id(&network, &profile_params, &runtime.genesis_commitment());
        let mut state = NodeState {
            runtime,
            public_alpha: false,
            mainnet: false,
            authenticator,
            clock: NodeReferenceTime::SystemClock,
            receipts: BTreeMap::new(),
            profile_id,
            block_peers: Vec::new(),
            noise_private_key: None,
            trusted_peer_static_keys: Vec::new(),
            peer_static_keys_by_addr: BTreeMap::new(),
            d1_evidence: false,
            d2_partition_qualification: false,
            offhost_anchor_service: OffhostAnchorNodeServiceOwner::disabled(),
        };
        state.refresh_receipts().unwrap();
        state
    }

    fn d1_qrun_node_state(
        directory: &Path,
        network: NetworkId,
        signer: &Ed25519TransactionSigner,
    ) -> NodeState {
        let owner = signer.account_id();
        let authenticator = Ed25519TransactionAuthenticator::select(
            TransactionAuthenticatorKind::Ed25519V1,
            [AccountPublicKey {
                account_id: owner,
                public_key: signer.public_key(),
            }],
        )
        .unwrap();
        let clock = SystemClockReferenceTime;
        let mut params = smoke_params();
        params.protocol_version = 5;
        let profile_params = params.clone();
        let mut runtime =
            open_local_node_runtime(directory, network, owner, params, &authenticator, &clock)
                .unwrap();
        runtime.set_producer_account(owner).unwrap();
        assert!(runtime.is_qrun_v05_fee_only());
        let profile_id = profile_id(&network, &profile_params, &runtime.genesis_commitment());
        let mut state = NodeState {
            runtime,
            public_alpha: false,
            mainnet: false,
            authenticator,
            clock: NodeReferenceTime::SystemClock,
            receipts: BTreeMap::new(),
            profile_id,
            block_peers: Vec::new(),
            noise_private_key: None,
            trusted_peer_static_keys: Vec::new(),
            peer_static_keys_by_addr: BTreeMap::new(),
            d1_evidence: true,
            d2_partition_qualification: false,
            offhost_anchor_service: OffhostAnchorNodeServiceOwner::disabled(),
        };
        state.refresh_receipts().unwrap();
        state
    }

    fn deliver_ptb2_over_tcp(
        listener: &TcpListener,
        state: &Arc<Mutex<NodeState>>,
        envelope: &[u8],
    ) {
        let candidate = decode_candidate_network_block(envelope).unwrap();
        let expected_hash = block_id(envelope);
        let mut sender = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        sender
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        sender
            .set_write_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        sender
            .write_all(&encode_block_frame(envelope).unwrap())
            .unwrap();

        let (mut receiver, _) = listener.accept().unwrap();
        handle_block(&mut receiver, state).unwrap();

        let mut ack = [0u8; BLOCK_ACK_BYTES];
        sender.read_exact(&mut ack).unwrap();
        assert_eq!(&ack[..4], BLOCK_ACK_MAGIC);
        assert_eq!(u16::from_be_bytes([ack[4], ack[5]]), BLOCK_PROTOCOL_VERSION);
        assert_eq!(ack[6], 0);
        assert_eq!(
            u64::from_be_bytes(ack[7..15].try_into().unwrap()),
            candidate.block.height
        );
        assert_eq!(&ack[15..47], expected_hash.as_slice());
    }

    fn test_noise_keypair() -> ([u8; 32], [u8; 32]) {
        let params: NoiseParams = "Noise_XX_25519_ChaChaPoly_SHA256".parse().unwrap();
        let mut pair = Builder::new(params).generate_keypair().unwrap();
        let mut private = [0u8; 32];
        private.copy_from_slice(&pair.private);
        let mut public = [0u8; 32];
        public.copy_from_slice(&pair.public);
        pair.private.fill(0);
        pair.public.fill(0);
        (private, public)
    }

    fn deliver_authenticated_block(
        listener: &TcpListener,
        receiver: &Arc<Mutex<NodeState>>,
        sender: &Arc<Mutex<NodeState>>,
        envelope: &[u8],
    ) {
        let peer = listener.local_addr().unwrap();
        let (network_id, profile_id, mut local_private_key, remote_static_public_key) = {
            let locked = sender.lock().unwrap();
            (
                locked.runtime.network_id(),
                locked.profile_id,
                locked.noise_private_key.unwrap(),
                *locked.peer_static_keys_by_addr.get(&peer).unwrap(),
            )
        };
        let envelope = envelope.to_vec();
        let client = std::thread::spawn(move || {
            let result = send_block_to_peer_authenticated(
                peer,
                &envelope,
                &network_id,
                &profile_id,
                local_private_key,
                Some(&remote_static_public_key),
                None,
                false,
                false,
            );
            local_private_key.fill(0);
            result.unwrap();
        });
        let (mut stream, _) = listener.accept().unwrap();
        handle_block(&mut stream, receiver).unwrap();
        client.join().unwrap();
    }

    #[test]
    fn bounded_sync_wire_rejects_bad_versions_trailing_bytes_and_budget_overruns() {
        let request = encode_sync_request(7, 2, 1_024, None).unwrap();
        assert_eq!(decode_sync_request(&request).unwrap(), (7, 2, 1_024, None));
        let pinned_snapshot = (18, [0xA5; 32]);
        let pinned_request = encode_sync_request(9, 2, 1_024, Some(pinned_snapshot)).unwrap();
        assert_eq!(
            decode_sync_request(&pinned_request).unwrap(),
            (9, 2, 1_024, Some(pinned_snapshot))
        );
        assert!(validate_sync_snapshot_pin(Some(pinned_snapshot), 18, [0xA5; 32]).is_ok());
        assert!(validate_sync_snapshot_pin(Some(pinned_snapshot), 19, [0xA5; 32]).is_err());
        assert!(validate_sync_snapshot_pin(Some(pinned_snapshot), 18, [0xA6; 32]).is_err());
        let mut malformed_pin = request.clone();
        malformed_pin[20] = 2;
        assert!(decode_sync_request(&malformed_pin).is_err());
        let mut bad_request = request.clone();
        bad_request[0] ^= 0x40;
        assert!(decode_sync_request(&bad_request).is_err());
        assert!(encode_sync_request(0, 2, 1_024, None).is_err());
        assert!(encode_sync_request(7, 0, 1_024, None).is_err());

        let envelope = vec![0xAB; 8];
        let response =
            encode_sync_response(0, 9, [1; 32], [2; 32], [3; 32], &[envelope.clone()]).unwrap();
        let decoded = decode_sync_response(&response, 1, 8).unwrap();
        assert_eq!(decoded.envelopes, vec![envelope.clone()]);
        assert_eq!(decoded.height, 9);
        assert!(decode_sync_response(&response, 1, 7).is_err());
        assert!(decode_sync_response(&response, 0, 8).is_err());

        let mut trailing = response.clone();
        trailing.push(0);
        assert!(decode_sync_response(&trailing, 1, 8).is_err());
        let two_envelopes = encode_sync_response(
            0,
            9,
            [1; 32],
            [2; 32],
            [3; 32],
            &[envelope.clone(), envelope],
        )
        .unwrap();
        assert!(decode_sync_response(&two_envelopes, 1, 64).is_err());
    }

    #[test]
    fn consensus_profile_fingerprint_changes_when_pow_parameters_change() {
        let network = [0x54; 32];
        let baseline = smoke_params();
        let mut modified = baseline.clone();
        modified.pow.memory_kib += 1;
        let genesis = [0x64; 32];
        let genesis_other = [0x65; 32];
        let baseline_fingerprint = profile_id(&network, &baseline, &genesis);
        assert_eq!(
            baseline_fingerprint,
            profile_id(&network, &smoke_params(), &genesis)
        );
        assert_eq!(
            profile_id_with_reference_time_policy(&network, &baseline, &genesis, None),
            baseline_fingerprint,
            "local compatibility profiles retain their historical fingerprint"
        );
        let time_policy_a =
            profile_id_with_reference_time_policy(&network, &baseline, &genesis, Some([0x71; 32]));
        let time_policy_b =
            profile_id_with_reference_time_policy(&network, &baseline, &genesis, Some([0x72; 32]));
        assert_ne!(
            time_policy_a, baseline_fingerprint,
            "an authenticated public-network time policy must be part of the session profile"
        );
        assert_ne!(
            time_policy_a, time_policy_b,
            "nodes with different signed time policies must not share a QRun profile identity"
        );
        assert_ne!(
            baseline_fingerprint,
            profile_id(&network, &modified, &genesis)
        );
        assert_ne!(
            baseline_fingerprint,
            profile_id(&network, &baseline, &genesis_other)
        );
    }

    #[test]
    fn authenticated_mode_refuses_unpinned_peer_instead_of_plaintext_fallback() {
        let dir = TestDir::new();
        let network = [0x53; 32];
        let signer = Ed25519TransactionSigner::from_seed([0x37; 32]);
        let state = Arc::new(Mutex::new(node_state(&dir.0, network, &signer)));
        state.lock().unwrap().noise_private_key = Some([0xA3; 32]);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let peer = listener.local_addr().unwrap();

        let error = send_block_to_peer(peer, b"not-a-block", &state).unwrap_err();
        assert!(error.contains("authenticated block peer config is incomplete"));

        listener.set_nonblocking(true).unwrap();
        assert!(matches!(
            listener.accept(),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock
        ));
    }

    #[test]
    fn listener_bind_policy_separates_loopback_and_public_alpha_modes() {
        assert!(parse_socket("0.0.0.0:49341", "--block-listen", false).is_err());
        assert!(parse_socket("192.0.2.10:49341", "--peer", false).is_err());
        assert!(parse_socket("127.0.0.1:49341", "--block-listen", false).is_ok());
        assert!(parse_socket("0.0.0.0:49341", "--block-listen", true).is_ok());
        assert!(parse_socket("192.0.2.10:49341", "--peer", true).is_ok());
        // Public-alpha still cannot expose the unauthenticated RPC or transaction ingress.
        assert!(parse_socket("0.0.0.0:49339", "--rpc-listen", false).is_err());
        assert!(parse_socket("0.0.0.0:49340", "--tx-listen", false).is_err());
    }

    #[test]
    fn two_pow_nodes_sync_signed_transfer_over_real_loopback_socket() {
        let first_dir = TestDir::new();
        let second_dir = TestDir::new();
        let network = [0x51; 32];
        let signer = Ed25519TransactionSigner::from_seed([0x35; 32]);
        let owner = signer.account_id();
        let recipient = [0x77; 32];
        let first = Arc::new(Mutex::new(node_state(&first_dir.0, network, &signer)));
        let second = Arc::new(Mutex::new(node_state(&second_dir.0, network, &signer)));
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();

        let timestamp = now_unix().unwrap();
        let empty_envelope = {
            let mut node = first.lock().unwrap();
            let auth = &node.authenticator;
            node.runtime
                .mine_candidate(timestamp, Vec::new(), auth, 1)
                .unwrap()
        };
        {
            let mut node = first.lock().unwrap();
            let NodeState {
                runtime,
                authenticator,
                clock,
                ..
            } = &mut *node;
            runtime
                .submit_block(&empty_envelope, authenticator, clock)
                .unwrap();
        }
        deliver_ptb2_over_tcp(&listener, &second, &empty_envelope);

        let mut tx = Transaction {
            network_id: network,
            sender: owner,
            recipient,
            nonce: 1,
            amount: 1_000,
            fee: 1,
            expires_at: timestamp + 3_600,
            signature: Vec::new(),
        };
        signer.sign_transaction(&mut tx).unwrap();
        let transfer_envelope = {
            let mut node = first.lock().unwrap();
            let auth = &node.authenticator;
            node.runtime
                .mine_candidate(timestamp + 1, vec![tx.clone()], auth, 1)
                .unwrap()
        };
        {
            let mut node = first.lock().unwrap();
            let NodeState {
                runtime,
                authenticator,
                clock,
                ..
            } = &mut *node;
            runtime
                .submit_block(&transfer_envelope, authenticator, clock)
                .unwrap();
        }
        deliver_ptb2_over_tcp(&listener, &second, &transfer_envelope);

        let first = first.lock().unwrap();
        let second = second.lock().unwrap();
        assert_eq!(first.runtime.canonical_height(), 2);
        assert_eq!(second.runtime.canonical_height(), 2);
        assert_eq!(
            first.runtime.canonical_tip(),
            second.runtime.canonical_tip()
        );
        assert_eq!(
            first.runtime.canonical_state_root(),
            second.runtime.canonical_state_root()
        );
        assert_eq!(
            second
                .runtime
                .canonical_state()
                .account(&recipient)
                .unwrap()
                .balance,
            1_000
        );
        assert_eq!(
            second.runtime.canonical_state().total_value().unwrap(),
            ai_native_l1_pow_bench::state_machine::MAX_TOTAL_SUPPLY_ATOMS
        );
        let txid = transaction_id(&tx).unwrap();
        assert_eq!(
            second.receipts.get(&txid).map(|receipt| receipt.height),
            Some(2)
        );
    }

    #[test]
    fn fresh_node_catches_up_canonical_signed_transfer_over_authenticated_sync_page() {
        let source_dir = TestDir::new();
        let receiver_dir = TestDir::new();
        let network = [0x55; 32];
        let signer = Ed25519TransactionSigner::from_seed([0x38; 32]);
        let owner = signer.account_id();
        let recipient = [0x7a; 32];
        let source = Arc::new(Mutex::new(node_state(&source_dir.0, network, &signer)));
        let receiver = Arc::new(Mutex::new(node_state(&receiver_dir.0, network, &signer)));
        let timestamp = now_unix().unwrap();

        let first_envelope = {
            let mut node = source.lock().unwrap();
            let auth = &node.authenticator;
            node.runtime
                .mine_candidate(timestamp, Vec::new(), auth, 1)
                .unwrap()
        };
        {
            let mut node = source.lock().unwrap();
            let NodeState {
                runtime,
                authenticator,
                clock,
                ..
            } = &mut *node;
            runtime
                .submit_block(&first_envelope, authenticator, clock)
                .unwrap();
        }

        let mut tx = Transaction {
            network_id: network,
            sender: owner,
            recipient,
            nonce: 1,
            amount: 2_500,
            fee: 1,
            expires_at: timestamp + 3_600,
            signature: Vec::new(),
        };
        signer.sign_transaction(&mut tx).unwrap();
        let second_envelope = {
            let mut node = source.lock().unwrap();
            let auth = &node.authenticator;
            node.runtime
                .mine_candidate(timestamp + 1, vec![tx.clone()], auth, 1)
                .unwrap()
        };
        {
            let mut node = source.lock().unwrap();
            let NodeState {
                runtime,
                authenticator,
                clock,
                ..
            } = &mut *node;
            runtime
                .submit_block(&second_envelope, authenticator, clock)
                .unwrap();
        }

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let peer = listener.local_addr().unwrap();
        let (mut source_private, source_public) = test_noise_keypair();
        let (mut receiver_private, receiver_public) = test_noise_keypair();
        {
            let mut node = source.lock().unwrap();
            node.noise_private_key = Some(source_private);
            node.trusted_peer_static_keys = vec![receiver_public];
        }
        {
            let mut node = receiver.lock().unwrap();
            node.noise_private_key = Some(receiver_private);
            node.trusted_peer_static_keys = vec![source_public];
            node.peer_static_keys_by_addr.insert(peer, source_public);
            receiver_private.fill(0);
        }

        let page_budget = max_sync_response_block_bytes(8).unwrap();
        let (base_height, peer_height, base_tip, peer_tip, peer_root, peer_envelopes, peer_profile) = {
            let node = source.lock().unwrap();
            let envelopes = node
                .runtime
                .canonical_envelopes_range(1, 8, page_budget)
                .unwrap();
            (
                node.runtime.archive_base_height(),
                node.runtime.canonical_height(),
                node.runtime.archive_base_tip(),
                node.runtime.canonical_tip(),
                node.runtime.canonical_state_root(),
                envelopes,
                node.profile_id,
            )
        };
        let accepted = listener.try_clone().unwrap();
        let mut server_private = source_private;
        source_private.fill(0);
        let network_for_server = network;
        let server = std::thread::spawn(move || {
            let (mut stream, _) = accepted.accept().unwrap();
            let trusted_client = [receiver_public];
            let mut session = QRunV05NoiseSession::accept(
                &mut stream,
                &server_private,
                &trusted_client,
                &network_for_server,
                &peer_profile,
            )
            .unwrap();
            let request = session.read_record(&mut stream).unwrap();
            let (start_height, max_blocks, max_bytes, expected_snapshot) =
                decode_sync_request(&request).unwrap();
            assert_eq!(start_height, 1);
            assert_eq!(max_blocks, 8);
            assert_eq!(max_bytes, page_budget);
            assert_eq!(expected_snapshot, None);
            let response = encode_sync_response(
                base_height,
                peer_height,
                base_tip,
                peer_tip,
                peer_root,
                &peer_envelopes,
            )
            .unwrap();
            session.write_record(&mut stream, &response).unwrap();
            server_private.fill(0);
        });
        let synced_height = sync_from_peer_authenticated(peer, &receiver, 8, page_budget).unwrap();
        server.join().unwrap();

        let source = source.lock().unwrap();
        let receiver = receiver.lock().unwrap();
        assert_eq!(synced_height, 2);
        assert_eq!(
            receiver.runtime.canonical_height(),
            source.runtime.canonical_height()
        );
        assert_eq!(
            receiver.runtime.canonical_tip(),
            source.runtime.canonical_tip()
        );
        assert_eq!(
            receiver.runtime.canonical_state_root(),
            source.runtime.canonical_state_root()
        );
        assert_eq!(
            receiver
                .runtime
                .canonical_state()
                .account(&recipient)
                .unwrap()
                .balance,
            2_500
        );
        assert_eq!(
            receiver.runtime.canonical_state().total_value().unwrap(),
            ai_native_l1_pow_bench::state_machine::MAX_TOTAL_SUPPLY_ATOMS
        );
        assert_eq!(
            receiver
                .receipts
                .get(&transaction_id(&tx).unwrap())
                .map(|receipt| receipt.height),
            Some(2)
        );
    }

    #[test]
    fn qrun_v05_partitioned_sync_reorgs_to_peer_cumulative_work_and_recovers_receipts_after_restart(
    ) {
        let source_dir = TestDir::new();
        let receiver_dir = TestDir::new();
        let network = [0x59; 32];
        let signer = Ed25519TransactionSigner::from_seed([0x5A; 32]);
        let owner = signer.account_id();
        let recipient_a = [0xA1; 32];
        let recipient_b = [0xB2; 32];
        let mut params = smoke_params();
        params.protocol_version = 5;

        // Create two isolated QFP5 runtimes with identical Genesis/profile but no block exchange.
        let mut source_state =
            node_state_with_params(&source_dir.0, network, &signer, params.clone());
        let mut receiver_state =
            node_state_with_params(&receiver_dir.0, network, &signer, params.clone());
        source_state.runtime.set_producer_account(owner).unwrap();
        receiver_state.runtime.set_producer_account(owner).unwrap();
        let source = Arc::new(Mutex::new(source_state));
        let receiver = Arc::new(Mutex::new(receiver_state));

        let timestamp = now_unix().unwrap();
        let mut tx_a = Transaction {
            network_id: network,
            sender: owner,
            recipient: recipient_a,
            nonce: 1,
            amount: 111,
            fee: 1,
            expires_at: timestamp + 3_600,
            signature: Vec::new(),
        };
        signer.sign_transaction(&mut tx_a).unwrap();
        let mut tx_b = Transaction {
            network_id: network,
            sender: owner,
            recipient: recipient_b,
            nonce: 1,
            amount: 222,
            fee: 1,
            expires_at: timestamp + 3_600,
            signature: Vec::new(),
        };
        signer.sign_transaction(&mut tx_b).unwrap();
        let txid_a = transaction_id(&tx_a).unwrap();
        let txid_b = transaction_id(&tx_b).unwrap();

        // Partition side A mines a valid height-1 transaction that must become orphaned.
        let envelope_a = {
            let node = receiver.lock().unwrap();
            node.runtime
                .mine_candidate(timestamp, vec![tx_a], &node.authenticator, 1)
                .unwrap()
        };
        {
            let mut node = receiver.lock().unwrap();
            let NodeState {
                runtime,
                authenticator,
                clock,
                ..
            } = &mut *node;
            runtime
                .submit_block(&envelope_a, authenticator, clock)
                .unwrap();
            node.refresh_receipts().unwrap();
        }

        // Partition side B independently mines a conflicting nonce-1 transaction and extends
        // that competing branch to height 2. No block from either side has crossed the partition.
        let envelope_b1 = {
            let node = source.lock().unwrap();
            node.runtime
                .mine_candidate(timestamp + 1, vec![tx_b], &node.authenticator, 1)
                .unwrap()
        };
        {
            let mut node = source.lock().unwrap();
            let NodeState {
                runtime,
                authenticator,
                clock,
                ..
            } = &mut *node;
            runtime
                .submit_block(&envelope_b1, authenticator, clock)
                .unwrap();
        }
        let envelope_b2 = {
            let node = source.lock().unwrap();
            node.runtime
                .mine_candidate(timestamp + 2, Vec::new(), &node.authenticator, 1)
                .unwrap()
        };
        {
            let mut node = source.lock().unwrap();
            let NodeState {
                runtime,
                authenticator,
                clock,
                ..
            } = &mut *node;
            runtime
                .submit_block(&envelope_b2, authenticator, clock)
                .unwrap();
            node.refresh_receipts().unwrap();
        }

        {
            let node_a = receiver.lock().unwrap();
            let node_b = source.lock().unwrap();
            assert_eq!(node_a.runtime.canonical_height(), 1);
            assert_eq!(node_b.runtime.canonical_height(), 2);
            assert_ne!(
                node_a.runtime.canonical_tip(),
                node_b.runtime.canonical_tip()
            );
            assert_eq!(
                node_a.receipts.get(&txid_a).map(|receipt| receipt.height),
                Some(1)
            );
            assert!(!node_a.receipts.contains_key(&txid_b));
            assert_eq!(
                node_b.receipts.get(&txid_b).map(|receipt| receipt.height),
                Some(1)
            );
            assert!(!node_b.receipts.contains_key(&txid_a));
        }

        // Reconnect through a real Noise XX canonical-sync request. The authenticated peer
        // serves its complete canonical path from the shared trusted base, not just height+1.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let peer = listener.local_addr().unwrap();
        let (mut source_private, source_public) = test_noise_keypair();
        let (mut receiver_private, receiver_public) = test_noise_keypair();
        {
            let mut node = source.lock().unwrap();
            node.noise_private_key = Some(source_private);
            node.trusted_peer_static_keys = vec![receiver_public];
        }
        {
            let mut node = receiver.lock().unwrap();
            node.noise_private_key = Some(receiver_private);
            node.trusted_peer_static_keys = vec![source_public];
            node.peer_static_keys_by_addr.insert(peer, source_public);
        }
        source_private.fill(0);
        receiver_private.fill(0);

        let accepted = listener.try_clone().unwrap();
        let sync_source = Arc::clone(&source);
        let sync_server = std::thread::spawn(move || {
            let (mut stream, _) = accepted.accept().unwrap();
            handle_block(&mut stream, &sync_source).unwrap();
        });
        let page_budget = max_sync_response_block_bytes(8).unwrap();
        let synced_height = sync_from_peer_authenticated(peer, &receiver, 8, page_budget).unwrap();
        sync_server.join().unwrap();

        let (source_tip, source_root, source_balance, source_supply) = {
            let node = source.lock().unwrap();
            (
                node.runtime.canonical_tip(),
                node.runtime.canonical_state_root(),
                node.runtime
                    .canonical_state()
                    .account(&owner)
                    .unwrap()
                    .balance,
                node.runtime.canonical_state().total_value().unwrap(),
            )
        };
        {
            let node = receiver.lock().unwrap();
            assert_eq!(synced_height, 2);
            assert_eq!(node.runtime.canonical_height(), 2);
            assert_eq!(node.runtime.canonical_tip(), source_tip);
            assert_eq!(node.runtime.canonical_state_root(), source_root);
            assert_eq!(
                node.runtime
                    .canonical_state()
                    .account(&owner)
                    .unwrap()
                    .balance,
                source_balance
            );
            assert_eq!(
                node.runtime
                    .canonical_state()
                    .account(&recipient_b)
                    .unwrap()
                    .balance,
                222
            );
            assert_eq!(
                node.runtime.canonical_state().total_value().unwrap(),
                source_supply
            );
            assert_eq!(
                source_supply,
                ai_native_l1_pow_bench::state_machine::MAX_TOTAL_SUPPLY_ATOMS
            );
            assert!(
                !node.receipts.contains_key(&txid_a),
                "orphaned partition-side receipt must be removed"
            );
            assert_eq!(
                node.receipts.get(&txid_b).map(|receipt| receipt.height),
                Some(1)
            );
        }

        // The recovered branch selection and receipt index must survive a durable reopen.
        drop(receiver);
        let mut reopened_state = node_state_with_params(&receiver_dir.0, network, &signer, params);
        reopened_state.runtime.set_producer_account(owner).unwrap();
        assert_eq!(reopened_state.runtime.canonical_height(), 2);
        assert_eq!(reopened_state.runtime.canonical_tip(), source_tip);
        assert_eq!(reopened_state.runtime.canonical_state_root(), source_root);
        assert!(!reopened_state.receipts.contains_key(&txid_a));
        assert_eq!(
            reopened_state
                .receipts
                .get(&txid_b)
                .map(|receipt| receipt.height),
            Some(1)
        );
        assert_eq!(
            reopened_state
                .runtime
                .canonical_state()
                .account(&recipient_b)
                .unwrap()
                .balance,
            222
        );
        assert_eq!(
            reopened_state
                .runtime
                .canonical_state()
                .total_value()
                .unwrap(),
            ai_native_l1_pow_bench::state_machine::MAX_TOTAL_SUPPLY_ATOMS
        );

        let _ = envelope_a;
        let _ = envelope_b1;
        let _ = envelope_b2;
    }

    #[test]
    fn authenticated_sync_serves_retained_snapshot_across_competing_reorg_then_catches_up() {
        let source_dir = TestDir::new();
        let receiver_dir = TestDir::new();
        let source_path = source_dir.0.clone();
        let network = [0x56; 32];
        let seed = [0x39; 32];
        let signer = Ed25519TransactionSigner::from_seed(seed);
        let mut sync_params = smoke_params();
        sync_params.pow.memory_kib = 8;
        let owner = signer.account_id();
        let recipient = [0x7b; 32];
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let peer = listener.local_addr().unwrap();

        let (mut server_private, server_public) = test_noise_keypair();
        let (mut receiver_private, receiver_public) = test_noise_keypair();
        let receiver = Arc::new(Mutex::new(node_state_with_params(
            &receiver_dir.0,
            network,
            &signer,
            sync_params.clone(),
        )));
        {
            let mut node = receiver.lock().unwrap();
            node.noise_private_key = Some(receiver_private);
            node.trusted_peer_static_keys = vec![server_public];
            node.peer_static_keys_by_addr.insert(peer, server_public);
            receiver_private.fill(0);
        }

        let (ready_sender, ready_receiver) = std::sync::mpsc::channel();
        let server_params = sync_params.clone();
        let server = std::thread::spawn(move || {
            let signer = Ed25519TransactionSigner::from_seed(seed);
            let mut source =
                node_state_with_params(&source_path, network, &signer, server_params.clone());
            source.noise_private_key = Some(server_private);
            source.trusted_peer_static_keys = vec![receiver_public];
            server_private.fill(0);
            let source = Arc::new(Mutex::new(source));
            let timestamp = now_unix().unwrap();

            let first_envelope = {
                let mut node = source.lock().unwrap();
                let auth = &node.authenticator;
                node.runtime
                    .mine_candidate(timestamp, Vec::new(), auth, 1)
                    .unwrap()
            };
            {
                let mut node = source.lock().unwrap();
                let NodeState {
                    runtime,
                    authenticator,
                    clock,
                    ..
                } = &mut *node;
                runtime
                    .submit_block(&first_envelope, authenticator, clock)
                    .unwrap();
            }

            let mut tx = Transaction {
                network_id: network,
                sender: owner,
                recipient,
                nonce: 1,
                amount: 2_500,
                fee: 1,
                expires_at: timestamp + 3_600,
                signature: Vec::new(),
            };
            signer.sign_transaction(&mut tx).unwrap();
            let txid = transaction_id(&tx).unwrap();
            let second_envelope = {
                let mut node = source.lock().unwrap();
                let auth = &node.authenticator;
                node.runtime
                    .mine_candidate(timestamp + 1, vec![tx], auth, 1)
                    .unwrap()
            };
            {
                let mut node = source.lock().unwrap();
                let NodeState {
                    runtime,
                    authenticator,
                    clock,
                    ..
                } = &mut *node;
                runtime
                    .submit_block(&second_envelope, authenticator, clock)
                    .unwrap();
            }

            for height in 3..=18 {
                let envelope = {
                    let mut node = source.lock().unwrap();
                    let auth = &node.authenticator;
                    node.runtime
                        .mine_candidate(timestamp + height, Vec::new(), auth, 1)
                        .unwrap()
                };
                let mut node = source.lock().unwrap();
                let NodeState {
                    runtime,
                    authenticator,
                    clock,
                    ..
                } = &mut *node;
                runtime
                    .submit_block(&envelope, authenticator, clock)
                    .unwrap();
            }

            source.lock().unwrap().refresh_receipts().unwrap();

            // Pre-build the rival branch before starting the Noise handshake deadline. Its
            // envelopes are imported only after the first snapshot page has been served.
            let rival_dir = TestDir::new();
            let rival_signer = Ed25519TransactionSigner::from_seed(seed);
            let mut rival =
                node_state_with_params(&rival_dir.0, network, &rival_signer, server_params.clone());
            let mut competing_envelopes = Vec::new();
            for height in 1..=19u64 {
                let envelope = {
                    let auth = &rival.authenticator;
                    rival
                        .runtime
                        .mine_candidate(timestamp + height, Vec::new(), auth, 1)
                        .unwrap()
                };
                {
                    let NodeState {
                        runtime,
                        authenticator,
                        clock,
                        ..
                    } = &mut rival;
                    runtime
                        .submit_block(&envelope, authenticator, clock)
                        .unwrap();
                }
                competing_envelopes.push(envelope);
            }

            // The handshake deadline starts only after all PoW fixtures are constructed.
            ready_sender.send(()).unwrap();
            // The first request pins canonical height 18. A separate node then builds a
            // genuinely competing 19-block branch from Genesis and wins fork choice.
            let (mut first_stream, _) = listener.accept().unwrap();
            handle_block(&mut first_stream, &source).unwrap();
            let snapshot = {
                let node = source.lock().unwrap();
                assert_eq!(node.runtime.canonical_height(), 18);
                (
                    node.runtime.canonical_height(),
                    node.runtime.canonical_tip(),
                )
            };

            for envelope in competing_envelopes {
                let mut node = source.lock().unwrap();
                let NodeState {
                    runtime,
                    authenticator,
                    clock,
                    ..
                } = &mut *node;
                runtime
                    .submit_block(&envelope, authenticator, clock)
                    .unwrap();
            }
            source.lock().unwrap().refresh_receipts().unwrap();
            let retained_old_snapshot = {
                let node = source.lock().unwrap();
                assert_eq!(node.runtime.canonical_height(), 19);
                node.runtime
                    .archived_branch_summary(&snapshot.1)
                    .map(|(height, _, _)| height)
                    == Some(snapshot.0)
            };
            assert!(
                retained_old_snapshot,
                "the previous canonical branch must remain available"
            );

            // Finish the original height-18 snapshot after the actual competing reorganization.
            for _ in 0..2 {
                let (mut stream, _) = listener.accept().unwrap();
                handle_block(&mut stream, &source).unwrap();
            }

            // A second sync attempt observes and imports the new canonical 19-block branch.
            for _ in 0..3 {
                let (mut stream, _) = listener.accept().unwrap();
                handle_block(&mut stream, &source).unwrap();
            }
            let node = source.lock().unwrap();
            (
                txid,
                snapshot,
                retained_old_snapshot,
                node.runtime.canonical_height(),
                node.runtime.canonical_tip(),
                node.runtime.canonical_state_root(),
                node.runtime
                    .canonical_state()
                    .account(&recipient)
                    .map(|account| account.balance)
                    .unwrap_or(0),
                node.runtime.canonical_state().total_value().unwrap(),
                node.receipts.get(&txid).map(|receipt| receipt.height),
            )
        });

        ready_receiver
            .recv_timeout(Duration::from_secs(30))
            .expect("PoW fixture and authenticated sync listener should become ready");
        let page_budget = max_sync_response_block_bytes(8).unwrap();
        let first_synced_height =
            sync_from_peer_authenticated(peer, &receiver, 8, page_budget).unwrap();
        assert_eq!(first_synced_height, 18);
        {
            let node = receiver.lock().unwrap();
            assert_eq!(node.runtime.canonical_height(), 18);
            assert_eq!(
                node.runtime
                    .canonical_state()
                    .account(&recipient)
                    .unwrap()
                    .balance,
                2_500
            );
        }

        let synced_height = sync_from_peer_authenticated(peer, &receiver, 8, page_budget).unwrap();
        let (
            txid,
            initial_snapshot,
            retained_old_snapshot,
            source_height,
            source_tip,
            source_root,
            source_balance,
            source_supply,
            source_receipt,
        ) = server.join().unwrap();
        let receiver = receiver.lock().unwrap();

        assert_eq!(synced_height, 19);
        assert_eq!(source_height, 19);
        assert_eq!(receiver.runtime.canonical_height(), source_height);
        assert_eq!(receiver.runtime.canonical_tip(), source_tip);
        assert_eq!(receiver.runtime.canonical_state_root(), source_root);
        assert_eq!(
            receiver
                .runtime
                .canonical_state()
                .account(&recipient)
                .map(|account| account.balance)
                .unwrap_or(0),
            0
        );
        assert_eq!(
            receiver
                .runtime
                .canonical_state()
                .account(&recipient)
                .map(|account| account.balance)
                .unwrap_or(0),
            source_balance
        );
        assert_eq!(
            receiver.runtime.canonical_state().total_value().unwrap(),
            source_supply
        );
        assert_eq!(
            source_supply,
            ai_native_l1_pow_bench::state_machine::MAX_TOTAL_SUPPLY_ATOMS
        );
        assert_eq!(
            receiver.receipts.get(&txid).map(|receipt| receipt.height),
            None
        );
        assert_eq!(source_receipt, None);
        assert!(retained_old_snapshot);
        assert_eq!(initial_snapshot.0, 18);
        assert_ne!(initial_snapshot.1, source_tip);
    }

    #[test]
    fn d1_mutually_pinned_noise_ack_confirms_exact_qfp5_txid_and_canonical_state() {
        let source_dir = TestDir::new();
        let receiver_dir = TestDir::new();
        let network = [0x92; 32];
        let signer = Ed25519TransactionSigner::from_seed([0x93; 32]);
        let owner = signer.account_id();
        let recipient = [0xA7; 32];
        let source = Arc::new(Mutex::new(d1_qrun_node_state(
            &source_dir.0,
            network,
            &signer,
        )));
        let receiver = Arc::new(Mutex::new(d1_qrun_node_state(
            &receiver_dir.0,
            network,
            &signer,
        )));
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let peer = listener.local_addr().unwrap();
        let (mut source_private, source_public) = test_noise_keypair();
        let (mut receiver_private, receiver_public) = test_noise_keypair();
        {
            let mut node = source.lock().unwrap();
            node.noise_private_key = Some(source_private);
            node.trusted_peer_static_keys = vec![receiver_public];
            node.peer_static_keys_by_addr.insert(peer, receiver_public);
            node.block_peers = vec![peer];
            source_private.fill(0);
        }
        {
            let mut node = receiver.lock().unwrap();
            node.noise_private_key = Some(receiver_private);
            node.trusted_peer_static_keys = vec![source_public];
            receiver_private.fill(0);
        }

        let timestamp = now_unix().unwrap();
        let mut transaction = Transaction {
            network_id: network,
            sender: owner,
            recipient,
            nonce: 1,
            amount: 2_000,
            fee: 1,
            expires_at: timestamp + 3_600,
            signature: Vec::new(),
        };
        signer.sign_transaction(&mut transaction).unwrap();
        let txid = transaction_id(&transaction).unwrap();
        let envelope = {
            let mut node = source.lock().unwrap();
            let auth = &node.authenticator;
            node.runtime
                .mine_candidate(timestamp, vec![transaction], auth, 1)
                .unwrap()
        };
        assert!(envelope.starts_with(b"QFP5"));
        {
            let mut node = source.lock().unwrap();
            let NodeState {
                runtime,
                authenticator,
                clock,
                ..
            } = &mut *node;
            runtime
                .submit_block(&envelope, authenticator, clock)
                .unwrap();
            node.refresh_receipts().unwrap();
            assert_eq!(
                node.receipts.get(&txid).map(|receipt| receipt.height),
                Some(1)
            );
        }

        let (network_id, profile_id, mut local_private_key) = {
            let node = source.lock().unwrap();
            (
                node.runtime.network_id(),
                node.profile_id,
                node.noise_private_key.unwrap(),
            )
        };
        let outbound = envelope.clone();
        let expected_pow_digest = source
            .lock()
            .unwrap()
            .runtime
            .candidate_pow_digest(&outbound)
            .unwrap();
        assert_eq!(
            expected_pow_digest,
            source.lock().unwrap().runtime.canonical_tip()
        );
        let client = std::thread::spawn(move || {
            let result = send_block_to_peer_authenticated(
                peer,
                &outbound,
                &network_id,
                &profile_id,
                local_private_key,
                Some(&receiver_public),
                Some(expected_pow_digest),
                false,
                true,
            );
            local_private_key.fill(0);
            result.unwrap().unwrap()
        });
        let (mut stream, _) = listener.accept().unwrap();
        handle_block(&mut stream, &receiver).unwrap();
        let evidence = client.join().unwrap();
        let source = source.lock().unwrap();
        let receiver = receiver.lock().unwrap();
        assert_eq!(evidence.network_id, network);
        assert_eq!(evidence.profile_id, source.profile_id);
        assert_eq!(evidence.canonical_height, 1);
        assert_eq!(evidence.canonical_tip, source.runtime.canonical_tip());
        assert_eq!(evidence.state_root, source.runtime.canonical_state_root());
        assert_eq!(evidence.accepted_block_id, source.runtime.canonical_tip());
        assert_eq!(
            evidence.confirmed_receipts,
            vec![(txid, 1)],
            "the remote QDE5 evidence must contain the exact canonical transaction ID"
        );
        assert_eq!(
            receiver.runtime.canonical_tip(),
            source.runtime.canonical_tip()
        );
        assert_eq!(
            receiver.runtime.canonical_state_root(),
            source.runtime.canonical_state_root()
        );
        assert_eq!(
            receiver.receipts.get(&txid).map(|receipt| receipt.height),
            Some(1)
        );
        assert!(validate_d1_block_ack_evidence(
            peer,
            &evidence,
            &network,
            &source.profile_id,
            1,
            &source.runtime.canonical_tip(),
            &[txid],
        )
        .is_ok());
    }

    #[test]
    fn qrun_fee_only_qfp5_authenticated_gossip_and_sync_converge() {
        use ai_native_l1_pow_bench::{
            qrun_v05_profile_identity_candidate::PROPOSED_OWNER_ACCOUNT_ID,
            state_machine::MAX_TOTAL_SUPPLY_ATOMS,
        };

        let source_dir = TestDir::new();
        let receiver_dir = TestDir::new();
        let fresh_dir = TestDir::new();
        let source_signer = Ed25519TransactionSigner::from_seed([0x31; 32]);
        let receiver_signer = Ed25519TransactionSigner::from_seed([0x32; 32]);
        let fresh_signer = Ed25519TransactionSigner::from_seed([0x33; 32]);
        let source = Arc::new(Mutex::new(qrun_v05_node_state(
            &source_dir.0,
            &source_signer,
        )));
        let receiver = Arc::new(Mutex::new(qrun_v05_node_state(
            &receiver_dir.0,
            &receiver_signer,
        )));
        let gossip_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let gossip_peer = gossip_listener.local_addr().unwrap();
        let (mut source_private, source_public) = test_noise_keypair();
        let (mut receiver_private, receiver_public) = test_noise_keypair();
        {
            let mut node = source.lock().unwrap();
            node.noise_private_key = Some(source_private);
            node.trusted_peer_static_keys = vec![receiver_public];
            node.peer_static_keys_by_addr
                .insert(gossip_peer, receiver_public);
            node.block_peers = vec![gossip_peer];
            source_private.fill(0);
        }
        {
            let mut node = receiver.lock().unwrap();
            node.noise_private_key = Some(receiver_private);
            node.trusted_peer_static_keys = vec![source_public];
            receiver_private.fill(0);
        }

        let timestamp = now_unix().unwrap();
        let envelope = {
            let mut node = source.lock().unwrap();
            let auth = &node.authenticator;
            node.runtime
                .mine_candidate(timestamp, Vec::new(), auth, 1)
                .unwrap()
        };
        assert!(envelope.starts_with(b"QFP5"));
        {
            let mut node = source.lock().unwrap();
            let NodeState {
                runtime,
                authenticator,
                clock,
                ..
            } = &mut *node;
            runtime
                .submit_block(&envelope, authenticator, clock)
                .unwrap();
        }
        deliver_authenticated_block(&gossip_listener, &receiver, &source, &envelope);

        let sync_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let sync_peer = sync_listener.local_addr().unwrap();
        let (mut fresh_private, fresh_public) = test_noise_keypair();
        {
            let mut node = source.lock().unwrap();
            node.trusted_peer_static_keys.push(fresh_public);
        }
        let fresh = Arc::new(Mutex::new(qrun_v05_node_state(&fresh_dir.0, &fresh_signer)));
        {
            let mut node = fresh.lock().unwrap();
            node.noise_private_key = Some(fresh_private);
            node.trusted_peer_static_keys = vec![source_public];
            node.peer_static_keys_by_addr
                .insert(sync_peer, source_public);
            fresh_private.fill(0);
        }

        // The store lock is deliberately not Send on Windows, so the source node remains on the
        // test thread. The client worker carries only the network identity, Noise key and wire bytes.
        let (network, profile, client_private) = {
            let node = fresh.lock().unwrap();
            (
                node.runtime.network_id(),
                node.profile_id,
                node.noise_private_key.unwrap(),
            )
        };
        let page_bytes = max_sync_response_block_bytes(MAX_SYNC_PAGE_BLOCKS).unwrap();
        let request = encode_sync_request(1, MAX_SYNC_PAGE_BLOCKS, page_bytes, None).unwrap();
        let client = std::thread::spawn(move || {
            let private_key = EphemeralNoisePrivateKey(client_private);
            let mut stream =
                TcpStream::connect_timeout(&sync_peer, Duration::from_secs(2)).unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(6)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(6)))
                .unwrap();
            let mut session = QRunV05NoiseSession::connect(
                &mut stream,
                &private_key.0,
                &source_public,
                &network,
                &profile,
            )
            .unwrap();
            session.write_record(&mut stream, &request).unwrap();
            session.read_record(&mut stream).unwrap()
        });
        let (mut stream, _) = sync_listener.accept().unwrap();
        handle_block(&mut stream, &source).unwrap();
        let response_bytes = client.join().unwrap();
        let response =
            decode_sync_response(&response_bytes, MAX_SYNC_PAGE_BLOCKS, page_bytes).unwrap();
        assert_eq!(response.height, 1);
        assert_eq!(response.envelopes.len(), 1);
        assert!(response.envelopes[0].starts_with(b"QFP5"));
        for envelope in &response.envelopes {
            let candidate = decode_candidate_network_block(envelope).unwrap();
            assert!(candidate.fee_block.is_some());
            let mut node = fresh.lock().unwrap();
            let NodeState {
                runtime,
                authenticator,
                clock,
                ..
            } = &mut *node;
            runtime
                .submit_block(envelope, authenticator, clock)
                .unwrap();
            node.refresh_receipts().unwrap();
        }

        let source = source.lock().unwrap();
        let receiver = receiver.lock().unwrap();
        let fresh = fresh.lock().unwrap();
        assert_eq!(receiver.runtime.canonical_height(), 1);
        assert_eq!(fresh.runtime.canonical_height(), 1);
        assert_eq!(
            source.runtime.canonical_tip(),
            receiver.runtime.canonical_tip()
        );
        assert_eq!(
            source.runtime.canonical_tip(),
            fresh.runtime.canonical_tip()
        );
        assert_eq!(
            source.runtime.canonical_state_root(),
            receiver.runtime.canonical_state_root()
        );
        assert_eq!(
            source.runtime.canonical_state_root(),
            fresh.runtime.canonical_state_root()
        );
        for node in [&*source, &*receiver, &*fresh] {
            assert_eq!(
                node.runtime.canonical_state().total_value().unwrap(),
                MAX_TOTAL_SUPPLY_ATOMS
            );
            assert_eq!(
                node.runtime
                    .canonical_state()
                    .account(&PROPOSED_OWNER_ACCOUNT_ID)
                    .unwrap()
                    .balance as u128,
                MAX_TOTAL_SUPPLY_ATOMS
            );
        }
    }

    #[test]
    fn public_alpha_nodes_gossip_unpinned_qfp5_blocks_and_converge() {
        use ai_native_l1_pow_bench::state_machine::MAX_TOTAL_SUPPLY_ATOMS;

        let source_dir = TestDir::new();
        let receiver_dir = TestDir::new();
        let source_signer = Ed25519TransactionSigner::from_seed([0x41; 32]);
        let receiver_signer = Ed25519TransactionSigner::from_seed([0x42; 32]);
        let source = Arc::new(Mutex::new(qrun_v05_node_state(
            &source_dir.0,
            &source_signer,
        )));
        let receiver = Arc::new(Mutex::new(qrun_v05_node_state(
            &receiver_dir.0,
            &receiver_signer,
        )));
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let peer = listener.local_addr().unwrap();
        let (mut source_private, _) = test_noise_keypair();
        let (mut receiver_private, _) = test_noise_keypair();
        {
            let mut node = source.lock().unwrap();
            node.public_alpha = true;
            node.noise_private_key = Some(source_private);
            node.block_peers = vec![peer];
            // Public-alpha does not require the remote static key to be pre-pinned.
            node.peer_static_keys_by_addr.clear();
            node.trusted_peer_static_keys.clear();
            source_private.fill(0);
        }
        {
            let mut node = receiver.lock().unwrap();
            node.public_alpha = true;
            node.noise_private_key = Some(receiver_private);
            node.peer_static_keys_by_addr.clear();
            node.trusted_peer_static_keys.clear();
            receiver_private.fill(0);
        }

        let envelope = {
            let mut node = source.lock().unwrap();
            let auth = &node.authenticator;
            let timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            let envelope = node
                .runtime
                .mine_candidate(timestamp, Vec::new(), auth, 1)
                .unwrap();
            let NodeState {
                runtime,
                authenticator,
                clock,
                ..
            } = &mut *node;
            runtime
                .submit_block(&envelope, authenticator, clock)
                .unwrap();
            envelope
        };
        assert!(envelope.starts_with(b"QFP5"));

        let (network_id, profile_id, mut local_private_key) = {
            let node = source.lock().unwrap();
            (
                node.runtime.network_id(),
                node.profile_id,
                node.noise_private_key.unwrap(),
            )
        };
        let outbound = envelope.clone();
        let client = std::thread::spawn(move || {
            let result = send_block_to_peer_authenticated(
                peer,
                &outbound,
                &network_id,
                &profile_id,
                local_private_key,
                None,
                None,
                true,
                false,
            );
            local_private_key.fill(0);
            result.unwrap();
        });
        let (mut stream, _) = listener.accept().unwrap();
        handle_block(&mut stream, &receiver).unwrap();
        client.join().unwrap();

        let source = source.lock().unwrap();
        let receiver = receiver.lock().unwrap();
        assert_eq!(source.runtime.canonical_height(), 1);
        assert_eq!(receiver.runtime.canonical_height(), 1);
        assert_eq!(
            source.runtime.canonical_tip(),
            receiver.runtime.canonical_tip()
        );
        assert_eq!(
            source.runtime.canonical_state_root(),
            receiver.runtime.canonical_state_root()
        );
        assert_eq!(
            receiver.runtime.canonical_state().total_value().unwrap(),
            MAX_TOTAL_SUPPLY_ATOMS
        );
    }

    #[test]
    fn public_alpha_nodes_enforce_configured_noise_static_key_pins() {
        let source_dir = TestDir::new();
        let receiver_dir = TestDir::new();
        let signer = Ed25519TransactionSigner::from_seed([0x51; 32]);
        let source = Arc::new(Mutex::new(qrun_v05_node_state(&source_dir.0, &signer)));
        let receiver = Arc::new(Mutex::new(qrun_v05_node_state(&receiver_dir.0, &signer)));
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let peer = listener.local_addr().unwrap();
        let (mut source_private, source_public) = test_noise_keypair();
        let (mut receiver_private, receiver_public) = test_noise_keypair();
        let (mut wrong_private, wrong_public) = test_noise_keypair();
        assert_ne!(wrong_public, source_public);

        {
            let mut node = source.lock().unwrap();
            node.public_alpha = true;
            node.noise_private_key = Some(source_private);
            node.peer_static_keys_by_addr.insert(peer, receiver_public);
            node.block_peers = vec![peer];
            source_private.fill(0);
        }
        {
            let mut node = receiver.lock().unwrap();
            node.public_alpha = true;
            node.noise_private_key = Some(receiver_private);
            node.trusted_peer_static_keys = vec![source_public];
            receiver_private.fill(0);
        }

        let envelope = {
            let mut node = source.lock().unwrap();
            let auth = &node.authenticator;
            let timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            let envelope = node
                .runtime
                .mine_candidate(timestamp, Vec::new(), auth, 1)
                .unwrap();
            let NodeState {
                runtime,
                authenticator,
                clock,
                ..
            } = &mut *node;
            runtime
                .submit_block(&envelope, authenticator, clock)
                .unwrap();
            envelope
        };

        let (network_id, profile_id, mut sender_key) = {
            let node = source.lock().unwrap();
            (
                node.runtime.network_id(),
                node.profile_id,
                node.noise_private_key.unwrap(),
            )
        };
        let outbound = envelope.clone();
        let expected_receiver = receiver_public;
        let good_sender = std::thread::spawn(move || {
            let result = send_block_to_peer_authenticated(
                peer,
                &outbound,
                &network_id,
                &profile_id,
                sender_key,
                Some(&expected_receiver),
                None,
                true,
                false,
            );
            sender_key.fill(0);
            result
        });
        let (mut stream, _) = listener.accept().unwrap();
        handle_block(&mut stream, &receiver).unwrap();
        good_sender.join().unwrap().unwrap();
        {
            let node = receiver.lock().unwrap();
            assert_eq!(node.runtime.canonical_height(), 1);
        }

        // A Public Alpha inbound connection with an unconfigured static key must not
        // bypass an explicit pin merely because the node runs in Public Alpha mode.
        let bad_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let bad_peer = bad_listener.local_addr().unwrap();
        let bad_payload = {
            let mut node = source.lock().unwrap();
            let auth = &node.authenticator;
            node.runtime
                .mine_candidate(
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs()
                        + 1,
                    Vec::new(),
                    auth,
                    1,
                )
                .unwrap()
        };
        let bad_network = network_id;
        let bad_profile = profile_id;
        let bad_sender = std::thread::spawn(move || {
            let result = (|| {
                let mut stream = TcpStream::connect(bad_peer).ok()?;
                stream.set_read_timeout(Some(Duration::from_secs(3))).ok()?;
                stream
                    .set_write_timeout(Some(Duration::from_secs(3)))
                    .ok()?;
                let mut session = QRunV05NoiseSession::connect_public(
                    &mut stream,
                    &wrong_private,
                    &bad_network,
                    &bad_profile,
                )
                .ok()?;
                session
                    .write_qfp5_block_record(&mut stream, &bad_payload)
                    .ok()?;
                session.read_block_ack_record(&mut stream).ok()
            })();
            wrong_private.fill(0);
            result.is_none()
        });
        let (mut bad_stream, _) = bad_listener.accept().unwrap();
        assert!(handle_block(&mut bad_stream, &receiver).is_err());
        assert!(bad_sender.join().unwrap());
        let node = receiver.lock().unwrap();
        assert_eq!(node.runtime.canonical_height(), 1);
    }
    #[test]
    fn two_qrun_nodes_sync_signed_transfer_over_authenticated_noise_xx() {
        let first_dir = TestDir::new();
        let second_dir = TestDir::new();
        let network = [0x52; 32];
        let signer = Ed25519TransactionSigner::from_seed([0x36; 32]);
        let owner = signer.account_id();
        let recipient = [0x79; 32];
        let first = Arc::new(Mutex::new(node_state(&first_dir.0, network, &signer)));
        let second = Arc::new(Mutex::new(node_state(&second_dir.0, network, &signer)));
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let peer = listener.local_addr().unwrap();
        let (mut first_private, first_public) = test_noise_keypair();
        let (mut second_private, second_public) = test_noise_keypair();
        {
            let mut node = first.lock().unwrap();
            node.noise_private_key = Some(first_private);
            node.trusted_peer_static_keys = vec![second_public];
            node.peer_static_keys_by_addr.insert(peer, second_public);
            node.block_peers = vec![peer];
            first_private.fill(0);
        }
        {
            let mut node = second.lock().unwrap();
            node.noise_private_key = Some(second_private);
            node.trusted_peer_static_keys = vec![first_public];
            second_private.fill(0);
        }

        let timestamp = now_unix().unwrap();
        let empty_envelope = {
            let mut node = first.lock().unwrap();
            let auth = &node.authenticator;
            node.runtime
                .mine_candidate(timestamp, Vec::new(), auth, 1)
                .unwrap()
        };
        {
            let mut node = first.lock().unwrap();
            let NodeState {
                runtime,
                authenticator,
                clock,
                ..
            } = &mut *node;
            runtime
                .submit_block(&empty_envelope, authenticator, clock)
                .unwrap();
        }
        deliver_authenticated_block(&listener, &second, &first, &empty_envelope);

        let mut tx = Transaction {
            network_id: network,
            sender: owner,
            recipient,
            nonce: 1,
            amount: 2_500,
            fee: 1,
            expires_at: timestamp + 3_600,
            signature: Vec::new(),
        };
        signer.sign_transaction(&mut tx).unwrap();
        let transfer_envelope = {
            let mut node = first.lock().unwrap();
            let auth = &node.authenticator;
            node.runtime
                .mine_candidate(timestamp + 1, vec![tx.clone()], auth, 1)
                .unwrap()
        };
        {
            let mut node = first.lock().unwrap();
            let NodeState {
                runtime,
                authenticator,
                clock,
                ..
            } = &mut *node;
            runtime
                .submit_block(&transfer_envelope, authenticator, clock)
                .unwrap();
        }
        deliver_authenticated_block(&listener, &second, &first, &transfer_envelope);

        let txid = transaction_id(&tx).unwrap();
        let first = first.lock().unwrap();
        let second = second.lock().unwrap();
        assert_eq!(first.runtime.canonical_height(), 2);
        assert_eq!(second.runtime.canonical_height(), 2);
        assert_eq!(
            first.runtime.canonical_tip(),
            second.runtime.canonical_tip()
        );
        assert_eq!(
            first.runtime.canonical_state_root(),
            second.runtime.canonical_state_root()
        );
        assert_eq!(
            second
                .runtime
                .canonical_state()
                .account(&recipient)
                .unwrap()
                .balance,
            2_500
        );
        assert_eq!(
            second.runtime.canonical_state().total_value().unwrap(),
            ai_native_l1_pow_bench::state_machine::MAX_TOTAL_SUPPLY_ATOMS
        );
        assert_eq!(
            second.receipts.get(&txid).map(|receipt| receipt.height),
            Some(2)
        );
    }
}

#[cfg(test)]
mod tx_ingress_tests {
    use super::*;
    use ai_native_l1_pow_bench::qzbe_tx_ingress_candidate::{decode_ack, encode_request};
    use ai_native_l1_pow_bench::state_machine::{encode_transaction, Transaction};
    use ai_native_l1_pow_bench::transaction_auth::Ed25519TransactionSigner;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_TX_TEST: AtomicU64 = AtomicU64::new(1);
    struct TestDir(PathBuf);
    impl TestDir {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "qrun_v05_qzts_ingress_{}_{}",
                std::process::id(),
                NEXT_TX_TEST.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn test_params() -> ConsensusParameters {
        let mut params = ConsensusParameters::candidate_testnet().unwrap();
        // This binary's signed transaction ingress mines QRun v0.5 QFP5 fee-only blocks.
        params.protocol_version = 5;
        params.initial_target = Uint256::MAX;
        params.pow_limit = Uint256::MAX;
        params.pow.memory_kib = 8 * 1024;
        params.pow.iterations = 1;
        params.pow.lanes = 1;
        params
    }

    fn test_node_state(
        directory: &Path,
        network: NetworkId,
        signer: &Ed25519TransactionSigner,
    ) -> NodeState {
        let account = signer.account_id();
        let authenticator = Ed25519TransactionAuthenticator::select(
            TransactionAuthenticatorKind::Ed25519V1,
            [AccountPublicKey {
                account_id: account,
                public_key: signer.public_key(),
            }],
        )
        .unwrap();
        let clock = SystemClockReferenceTime;
        let params = test_params();
        let profile_params = params.clone();
        let runtime =
            open_local_node_runtime(directory, network, account, params, &authenticator, &clock)
                .unwrap();
        let profile_id = profile_id(&network, &profile_params, &runtime.genesis_commitment());
        let mut state = NodeState {
            runtime,
            public_alpha: false,
            mainnet: false,
            authenticator,
            clock: NodeReferenceTime::SystemClock,
            receipts: BTreeMap::new(),
            profile_id,
            block_peers: Vec::new(),
            noise_private_key: None,
            trusted_peer_static_keys: Vec::new(),
            peer_static_keys_by_addr: BTreeMap::new(),
            d1_evidence: false,
            d2_partition_qualification: false,
            offhost_anchor_service: OffhostAnchorNodeServiceOwner::disabled(),
        };
        state.refresh_receipts().unwrap();
        state
    }

    #[test]
    fn qrun_node_state_keeps_offhost_anchor_daemon_disabled_by_default() {
        let dir = TestDir::new();
        let network = [0xA4; 32];
        let signer = Ed25519TransactionSigner::from_seed([0xA5; 32]);
        let mut state = test_node_state(&dir.0, network, &signer);

        assert!(!state.offhost_anchor_service.is_attached());
        assert_eq!(state.offhost_anchor_service.stats(), None);
        state.shutdown_offhost_anchor_service().unwrap();
        assert!(!state.offhost_anchor_service.is_attached());
    }

    #[test]
    fn qzts_signed_wallet_request_executes_and_persists_canonical_receipt() {
        let dir = TestDir::new();
        let network = [0x51; 32];
        let signer = Ed25519TransactionSigner::from_seed([0x46; 32]);
        let owner = signer.account_id();
        let recipient = [0x78; 32];
        let state = Arc::new(Mutex::new(test_node_state(&dir.0, network, &signer)));
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();

        let timestamp = now_unix().unwrap();
        let mut tx = Transaction {
            network_id: network,
            sender: owner,
            recipient,
            nonce: 1,
            amount: 7_500,
            fee: 7,
            expires_at: timestamp + 3_600,
            signature: Vec::new(),
        };
        signer.sign_transaction(&mut tx).unwrap();
        let wire = encode_transaction(&tx).unwrap();
        client.write_all(&encode_request(&wire).unwrap()).unwrap();
        let (mut server, _) = listener.accept().unwrap();
        handle_transaction(&mut server, &state).unwrap();

        let mut ack_wire = [0u8; ACK_BYTES];
        client.read_exact(&mut ack_wire).unwrap();
        let ack = decode_ack(&ack_wire).unwrap();
        let txid = transaction_id(&tx).unwrap();
        assert_eq!(ack.status, TxIngressStatus::Accepted);
        assert_eq!(ack.transaction_id, txid);

        let node = state.lock().unwrap();
        assert_eq!(node.runtime.canonical_height(), 1);
        assert_eq!(
            node.runtime
                .canonical_state()
                .account(&recipient)
                .unwrap()
                .balance,
            7_500
        );
        assert_eq!(
            node.runtime.canonical_state().total_value().unwrap(),
            ai_native_l1_pow_bench::state_machine::MAX_TOTAL_SUPPLY_ATOMS
        );
        assert_eq!(
            node.receipts.get(&txid).map(|receipt| receipt.height),
            Some(1)
        );
    }

    #[test]
    fn d1_remote_confirmation_failure_does_not_commit_the_candidate_locally() {
        let dir = TestDir::new();
        let network = [0xE1; 32];
        let signer = Ed25519TransactionSigner::from_seed([0xE2; 32]);
        let owner = signer.account_id();
        let recipient = [0xE3; 32];
        let mut node = test_node_state(&dir.0, network, &signer);

        // Reserve then release a loopback port so the mutually pinned peer is unavailable.
        let abandoned_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let peer = abandoned_listener.local_addr().unwrap();
        drop(abandoned_listener);
        let remote_static_public = [0xE4; 32];
        node.public_alpha = true;
        node.noise_private_key = Some([0xE5; 32]);
        node.trusted_peer_static_keys = vec![remote_static_public];
        node.peer_static_keys_by_addr
            .insert(peer, remote_static_public);
        node.block_peers = vec![peer];
        node.d1_evidence = true;
        node.d2_partition_qualification = false;

        let state = Arc::new(Mutex::new(node));
        let ingress = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut client = TcpStream::connect(ingress.local_addr().unwrap()).unwrap();
        let timestamp = now_unix().unwrap();
        let mut tx = Transaction {
            network_id: network,
            sender: owner,
            recipient,
            nonce: 1,
            amount: 4_321,
            fee: 7,
            expires_at: timestamp + 3_600,
            signature: Vec::new(),
        };
        signer.sign_transaction(&mut tx).unwrap();
        let txid = transaction_id(&tx).unwrap();
        let wire = encode_transaction(&tx).unwrap();
        client.write_all(&encode_request(&wire).unwrap()).unwrap();
        let (mut server, _) = ingress.accept().unwrap();

        let error = handle_transaction(&mut server, &state).unwrap_err();
        assert!(error.contains("connect authenticated block peer"));
        drop(server);

        // A failed remote confirmation must not leave the client guessing about a locally
        // committed transfer: no ACK, no canonical block, no receipt and no balance movement.
        let mut ack_wire = [0u8; ACK_BYTES];
        assert!(client.read_exact(&mut ack_wire).is_err());

        let node = state.lock().unwrap();
        assert!(node.d1_evidence);
        assert!(!node.d2_partition_qualification);
        assert_eq!(node.runtime.canonical_height(), 0);
        assert!(!node.receipts.contains_key(&txid));
        assert_eq!(
            node.runtime
                .canonical_state()
                .account(&recipient)
                .map(|account| account.balance)
                .unwrap_or(0),
            0
        );
        assert_eq!(
            node.runtime
                .canonical_state()
                .account(&owner)
                .unwrap()
                .nonce,
            0
        );
        assert_eq!(
            node.runtime.canonical_state().total_value().unwrap(),
            ai_native_l1_pow_bench::state_machine::MAX_TOTAL_SUPPLY_ATOMS
        );
    }

    #[test]
    fn d2_partition_mode_accepts_canonical_local_tx_when_pinned_peer_is_unreachable() {
        let dir = TestDir::new();
        let network = [0xD2; 32];
        let signer = Ed25519TransactionSigner::from_seed([0xD3; 32]);
        let owner = signer.account_id();
        let recipient = [0xD4; 32];
        let mut node = test_node_state(&dir.0, network, &signer);

        // Reserve then release a loopback port so the configured, pinned peer is
        // deliberately unreachable during this isolated D2 partition-side transaction.
        let abandoned_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let peer = abandoned_listener.local_addr().unwrap();
        drop(abandoned_listener);
        let remote_static_public = [0xD5; 32];
        node.public_alpha = true;
        node.noise_private_key = Some([0xD6; 32]);
        node.trusted_peer_static_keys = vec![remote_static_public];
        node.peer_static_keys_by_addr
            .insert(peer, remote_static_public);
        node.block_peers = vec![peer];
        node.d1_evidence = true;
        node.d2_partition_qualification = true;

        let state = Arc::new(Mutex::new(node));
        let ingress = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut client = TcpStream::connect(ingress.local_addr().unwrap()).unwrap();
        let timestamp = now_unix().unwrap();
        let mut tx = Transaction {
            network_id: network,
            sender: owner,
            recipient,
            nonce: 1,
            amount: 4_321,
            fee: 7,
            expires_at: timestamp + 3_600,
            signature: Vec::new(),
        };
        signer.sign_transaction(&mut tx).unwrap();
        let txid = transaction_id(&tx).unwrap();
        let wire = encode_transaction(&tx).unwrap();
        client.write_all(&encode_request(&wire).unwrap()).unwrap();
        let (mut server, _) = ingress.accept().unwrap();

        // D2 is the sole opt-in exception to D1's remote-receipt requirement.
        handle_transaction(&mut server, &state).unwrap();
        let mut ack_wire = [0u8; ACK_BYTES];
        client.read_exact(&mut ack_wire).unwrap();
        let ack = decode_ack(&ack_wire).unwrap();
        assert_eq!(ack.status, TxIngressStatus::Accepted);
        assert_eq!(ack.transaction_id, txid);

        let node = state.lock().unwrap();
        assert!(node.d1_evidence);
        assert!(node.d2_partition_qualification);
        assert_eq!(node.runtime.canonical_height(), 1);
        assert_eq!(
            node.receipts.get(&txid).map(|receipt| receipt.height),
            Some(1)
        );
        assert_eq!(
            node.runtime
                .canonical_state()
                .account(&recipient)
                .unwrap()
                .balance,
            4_321
        );
        assert_eq!(
            node.runtime.canonical_state().total_value().unwrap(),
            ai_native_l1_pow_bench::state_machine::MAX_TOTAL_SUPPLY_ATOMS
        );
    }
}
