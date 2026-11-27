//! Candidate-only public-devnet profile and strict zero-balance Genesis manifest.
//!
//! This module deliberately does not open sockets or start a node. It gives the next runtime a
//! typed, deterministic configuration contract that cannot silently inherit private-smoke
//! parameters or premine Genesis accounts. The selected consensus values are still provisional;
//! this is not public-devnet launch approval or Mainnet configuration.

use crate::{
    consensus::{ConsensusParameters, PowAlgorithm, Uint256},
    state_machine::{LedgerState, NetworkId},
};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::Path,
};

const MANIFEST_MAGIC: &[u8; 4] = b"QVDN";
const MANIFEST_VERSION: u16 = 1;
const MANIFEST_CORE_LEN: usize = 4 + 2 + 32 + 32 + 32 + 32 + 4 + 1;
const MANIFEST_LEN: usize = MANIFEST_CORE_LEN + 32;
const PROFILE_DOMAIN: &[u8] = b"QANVORYX-ZERO-VALUE-DEVNET-PROFILE-V1\0";
const TEST_PROFILE_DOMAIN: &[u8] = b"QANVORYX-ZERO-VALUE-DEVNET-TEST-POW-PROFILE-V1\0";
const CONSENSUS_DOMAIN: &[u8] = b"QANVORYX-DEVNET-CONSENSUS-DIGEST-V1\0";
const MANIFEST_DOMAIN: &[u8] = b"QANVORYX-DEVNET-MANIFEST-DIGEST-V1\0";
const EXPECTED_MINIMUM_MEMORY_KIB: u32 = 64 * 1024;
const MAX_MANIFEST_READ: u64 = (MANIFEST_LEN + 1) as u64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DevnetProfileError {
    InvalidNetworkId,
    ConsensusParameters(String),
    SmokePowProfile,
    UnsupportedAlgorithm,
    Genesis(String),
    MalformedManifest,
    UnsupportedManifestVersion,
    NetworkMismatch,
    ProfileMismatch,
    ConsensusMismatch,
    GenesisMismatch,
    PremineNotAllowed,
    ValueBearingProfileNotAllowed,
    ManifestConflict,
    InvalidManifestPath,
    Io(String),
}

impl std::fmt::Display for DevnetProfileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidNetworkId => write!(f, "devnet Network ID must be nonzero"),
            Self::ConsensusParameters(error) => {
                write!(f, "candidate consensus parameters rejected: {error}")
            }
            Self::SmokePowProfile => write!(
                f,
                "private smoke-test PoW overrides are forbidden in the devnet profile"
            ),
            Self::UnsupportedAlgorithm => write!(f, "devnet candidate requires Argon2id"),
            Self::Genesis(error) => write!(f, "zero-balance Genesis construction failed: {error}"),
            Self::MalformedManifest => write!(f, "devnet Genesis manifest is malformed"),
            Self::UnsupportedManifestVersion => {
                write!(f, "devnet Genesis manifest version is unsupported")
            }
            Self::NetworkMismatch => {
                write!(f, "devnet Genesis manifest belongs to another Network ID")
            }
            Self::ProfileMismatch => write!(f, "devnet profile identifier does not match"),
            Self::ConsensusMismatch => {
                write!(f, "devnet consensus parameter digest does not match")
            }
            Self::GenesisMismatch => {
                write!(f, "devnet zero-balance Genesis state root does not match")
            }
            Self::PremineNotAllowed => write!(
                f,
                "candidate public devnet Genesis must contain zero accounts"
            ),
            Self::ValueBearingProfileNotAllowed => {
                write!(f, "manifest cannot enable value-bearing mode")
            }
            Self::ManifestConflict => write!(
                f,
                "existing devnet Genesis manifest conflicts with requested profile"
            ),
            Self::InvalidManifestPath => write!(
                f,
                "devnet Genesis manifest path must be a regular non-symlink file path"
            ),
            Self::Io(error) => write!(f, "devnet Genesis manifest I/O failed: {error}"),
        }
    }
}
impl std::error::Error for DevnetProfileError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedDevnetManifest {
    network_id: NetworkId,
    profile_id: [u8; 32],
    consensus_digest: [u8; 32],
    genesis_state_root: [u8; 32],
    manifest_digest: [u8; 32],
}
impl VerifiedDevnetManifest {
    pub fn network_id(&self) -> &NetworkId {
        &self.network_id
    }
    pub fn profile_id(&self) -> &[u8; 32] {
        &self.profile_id
    }
    pub fn consensus_digest(&self) -> &[u8; 32] {
        &self.consensus_digest
    }
    pub fn genesis_state_root(&self) -> &[u8; 32] {
        &self.genesis_state_root
    }
    pub fn manifest_digest(&self) -> &[u8; 32] {
        &self.manifest_digest
    }
    pub fn value_bearing(&self) -> bool {
        false
    }
    pub fn genesis_account_count(&self) -> usize {
        0
    }
}

/// A stable, explicitly separate *candidate* devnet profile. Runtime/network integration is a
/// later step and must preserve this fail-closed manifest check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DevnetProfileCandidate {
    network_id: NetworkId,
    consensus: ConsensusParameters,
    profile_id: [u8; 32],
    consensus_digest: [u8; 32],
    genesis_state_root: [u8; 32],
}

impl DevnetProfileCandidate {
    pub fn new(network_id: NetworkId) -> Result<Self, DevnetProfileError> {
        Self::new_with_test_pow(network_id, false)
    }

    /// Explicit local-test-only zero-value profile. Its manifest receives a different profile ID,
    /// maximum target and 8 MiB memory ceiling, so it cannot reuse the normal Devnet data directory.
    pub fn new_test_pow(network_id: NetworkId) -> Result<Self, DevnetProfileError> {
        Self::new_with_test_pow(network_id, true)
    }

    fn new_with_test_pow(
        network_id: NetworkId,
        test_only: bool,
    ) -> Result<Self, DevnetProfileError> {
        if network_id.iter().all(|byte| *byte == 0) {
            return Err(DevnetProfileError::InvalidNetworkId);
        }
        let mut consensus = ConsensusParameters::candidate_testnet()
            .map_err(|error| DevnetProfileError::ConsensusParameters(error.to_string()))?;
        if test_only {
            consensus.initial_target = Uint256::MAX;
            consensus.pow_limit = Uint256::MAX;
            consensus.pow.memory_kib = 8 * 1024;
        }
        consensus
            .validate()
            .map_err(|error| DevnetProfileError::ConsensusParameters(error.to_string()))?;
        if consensus.pow.algorithm != PowAlgorithm::Argon2id {
            return Err(DevnetProfileError::UnsupportedAlgorithm);
        }
        // Do not inherit the private node's maximum initial target / 8 MiB smoke overrides.
        if (!test_only
            && (consensus.initial_target == Uint256::MAX
                || consensus.pow.memory_kib < EXPECTED_MINIMUM_MEMORY_KIB))
            || (test_only
                && (consensus.initial_target != Uint256::MAX
                    || consensus.pow_limit != Uint256::MAX
                    || consensus.pow.memory_kib != 8 * 1024))
            || consensus.pow.iterations == 0
            || consensus.pow.lanes == 0
        {
            return Err(DevnetProfileError::SmokePowProfile);
        }
        let genesis = LedgerState::genesis(network_id, Vec::new())
            .map_err(|error| DevnetProfileError::Genesis(format!("{error:?}")))?;
        if genesis.height() != 0 || genesis.network_id() != network_id {
            return Err(DevnetProfileError::Genesis(
                "unexpected initial state identity or height".into(),
            ));
        }
        let genesis_state_root = genesis.state_root();
        let profile_id = hash(if test_only {
            TEST_PROFILE_DOMAIN
        } else {
            PROFILE_DOMAIN
        });
        let consensus_digest = consensus_digest(&consensus);
        Ok(Self {
            network_id,
            consensus,
            profile_id,
            consensus_digest,
            genesis_state_root,
        })
    }

    pub fn network_id(&self) -> &NetworkId {
        &self.network_id
    }
    pub fn consensus(&self) -> &ConsensusParameters {
        &self.consensus
    }
    pub fn profile_id(&self) -> &[u8; 32] {
        &self.profile_id
    }
    pub fn consensus_digest(&self) -> &[u8; 32] {
        &self.consensus_digest
    }
    pub fn genesis_state_root(&self) -> &[u8; 32] {
        &self.genesis_state_root
    }
    pub fn value_bearing(&self) -> bool {
        false
    }
    pub fn genesis_account_count(&self) -> usize {
        0
    }

    /// Build the canonical fixed-length QVDN manifest. The all-zero account count and the explicit
    /// zero-value byte are encoded into the manifest and covered by the final digest.
    pub fn encode_manifest(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(MANIFEST_LEN);
        bytes.extend_from_slice(MANIFEST_MAGIC);
        bytes.extend_from_slice(&MANIFEST_VERSION.to_be_bytes());
        bytes.extend_from_slice(&self.network_id);
        bytes.extend_from_slice(&self.profile_id);
        bytes.extend_from_slice(&self.consensus_digest);
        bytes.extend_from_slice(&self.genesis_state_root);
        bytes.extend_from_slice(&0u32.to_be_bytes()); // no Genesis accounts / no premine
        bytes.push(0); // explicit zero-value devnet; never mainnet/value-bearing mode
        debug_assert_eq!(bytes.len(), MANIFEST_CORE_LEN);
        let digest = hash_parts(MANIFEST_DOMAIN, &[&bytes]);
        bytes.extend_from_slice(&digest);
        bytes
    }

    /// Verify exact canonical bytes against a locally constructed expected profile. Any mismatch
    /// is fatal; there is no fallback to the private smoke manifest or to a different profile.
    pub fn verify_manifest(
        &self,
        wire: &[u8],
    ) -> Result<VerifiedDevnetManifest, DevnetProfileError> {
        let expected = self.encode_manifest();
        if wire.len() != expected.len() || wire.len() < MANIFEST_LEN {
            return Err(DevnetProfileError::MalformedManifest);
        }
        if &wire[..4] != MANIFEST_MAGIC {
            return Err(DevnetProfileError::MalformedManifest);
        }
        let version = u16::from_be_bytes([wire[4], wire[5]]);
        if version != MANIFEST_VERSION {
            return Err(DevnetProfileError::UnsupportedManifestVersion);
        }
        if wire[6..38] != self.network_id {
            return Err(DevnetProfileError::NetworkMismatch);
        }
        if wire[38..70] != self.profile_id {
            return Err(DevnetProfileError::ProfileMismatch);
        }
        if wire[70..102] != self.consensus_digest {
            return Err(DevnetProfileError::ConsensusMismatch);
        }
        if wire[102..134] != self.genesis_state_root {
            return Err(DevnetProfileError::GenesisMismatch);
        }
        if wire[134..138] != [0, 0, 0, 0] {
            return Err(DevnetProfileError::PremineNotAllowed);
        }
        if wire[138] != 0 {
            return Err(DevnetProfileError::ValueBearingProfileNotAllowed);
        }
        let expected_digest = hash_parts(MANIFEST_DOMAIN, &[&wire[..139]]);
        if wire[139..171] != expected_digest {
            return Err(DevnetProfileError::MalformedManifest);
        }
        if wire != expected.as_slice() {
            return Err(DevnetProfileError::ManifestConflict);
        }
        Ok(VerifiedDevnetManifest {
            network_id: self.network_id,
            profile_id: self.profile_id,
            consensus_digest: self.consensus_digest,
            genesis_state_root: self.genesis_state_root,
            manifest_digest: expected_digest,
        })
    }

    /// Create a new manifest exclusively, or verify existing bytes before allowing reuse of a data
    /// directory. A mismatching/corrupt file is never overwritten automatically.
    pub fn persist_or_verify_manifest(
        &self,
        path: impl AsRef<Path>,
    ) -> Result<VerifiedDevnetManifest, DevnetProfileError> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent).map_err(io_error)?;
            }
        }
        match fs::symlink_metadata(path) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() || !metadata.is_file() {
                    return Err(DevnetProfileError::InvalidManifestPath);
                }
                if metadata.len() > MAX_MANIFEST_READ {
                    return Err(DevnetProfileError::MalformedManifest);
                }
                let file = File::open(path).map_err(io_error)?;
                let mut bytes = Vec::with_capacity(MANIFEST_LEN);
                file.take(MAX_MANIFEST_READ)
                    .read_to_end(&mut bytes)
                    .map_err(io_error)?;
                self.verify_manifest(&bytes)
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let wire = self.encode_manifest();
                let mut file = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(path)
                    .map_err(io_error)?;
                file.write_all(&wire)
                    .and_then(|_| file.sync_all())
                    .map_err(io_error)?;
                self.verify_manifest(&wire)
            }
            Err(error) => Err(io_error(error)),
        }
    }
}

fn consensus_digest(consensus: &ConsensusParameters) -> [u8; 32] {
    let mut bytes = Vec::with_capacity(180);
    bytes.extend_from_slice(&consensus.protocol_version.to_be_bytes());
    bytes.extend_from_slice(&consensus.target_block_time_secs.to_be_bytes());
    bytes.extend_from_slice(&consensus.difficulty_window_blocks.to_be_bytes());
    bytes.extend_from_slice(&consensus.difficulty_min_ratio_divisor.to_be_bytes());
    bytes.extend_from_slice(&consensus.difficulty_max_ratio.to_be_bytes());
    bytes.extend_from_slice(&consensus.pow_limit.to_be_bytes());
    bytes.extend_from_slice(&consensus.initial_target.to_be_bytes());
    bytes.push(match consensus.pow.algorithm {
        PowAlgorithm::Argon2id => 1,
    });
    bytes.extend_from_slice(&consensus.pow.memory_kib.to_be_bytes());
    bytes.extend_from_slice(&consensus.pow.iterations.to_be_bytes());
    bytes.extend_from_slice(&consensus.pow.lanes.to_be_bytes());
    bytes.push(consensus.pow.output_bytes);
    bytes.extend_from_slice(&consensus.issuance.maximum_supply().to_be_bytes());
    bytes.extend_from_slice(&consensus.issuance.initial_subsidy().to_be_bytes());
    bytes.extend_from_slice(&consensus.issuance.blocks_per_halving().to_be_bytes());
    hash_parts(CONSENSUS_DOMAIN, &[&bytes])
}
fn hash(domain: &[u8]) -> [u8; 32] {
    hash_parts(domain, &[])
}
fn hash_parts(domain: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}
fn io_error(error: io::Error) -> DevnetProfileError {
    DevnetProfileError::Io(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

    fn network(byte: u8) -> NetworkId {
        [byte; 32]
    }
    fn scratch() -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("ain1_cp0247_devnet_{unique}"))
    }

    #[test]
    fn candidate_profile_is_not_the_private_smoke_profile() {
        let profile = DevnetProfileCandidate::new(network(0x47)).unwrap();
        assert_ne!(profile.consensus.initial_target, Uint256::MAX);
        assert_eq!(
            profile.consensus.pow.memory_kib,
            EXPECTED_MINIMUM_MEMORY_KIB
        );
        assert_eq!(profile.consensus.pow.algorithm, PowAlgorithm::Argon2id);
        assert!(!profile.value_bearing());
        assert_eq!(profile.genesis_account_count(), 0);
    }

    #[test]
    fn test_easy_pow_profile_is_zero_value_and_cannot_reuse_production_candidate_manifest() {
        let network = network(0x46);
        let normal = DevnetProfileCandidate::new(network).unwrap();
        let test = DevnetProfileCandidate::new_test_pow(network).unwrap();
        assert_ne!(normal.profile_id(), test.profile_id());
        assert_ne!(normal.consensus_digest(), test.consensus_digest());
        assert_eq!(test.consensus.initial_target, Uint256::MAX);
        assert_eq!(test.consensus.pow_limit, Uint256::MAX);
        assert_eq!(test.consensus.pow.memory_kib, 8 * 1024);
        assert_eq!(test.genesis_account_count(), 0);
        assert!(!test.value_bearing());
        assert_ne!(normal.encode_manifest(), test.encode_manifest());
        assert_eq!(
            test.verify_manifest(&test.encode_manifest())
                .unwrap()
                .genesis_account_count(),
            0
        );
        assert_eq!(
            normal.verify_manifest(&test.encode_manifest()),
            Err(DevnetProfileError::ProfileMismatch)
        );
    }

    #[test]
    fn all_zero_network_id_is_rejected() {
        assert_eq!(
            DevnetProfileCandidate::new([0; 32]),
            Err(DevnetProfileError::InvalidNetworkId)
        );
    }

    #[test]
    fn empty_genesis_state_is_constructed_for_the_requested_network() {
        let profile = DevnetProfileCandidate::new(network(0x48)).unwrap();
        let state = LedgerState::genesis(*profile.network_id(), Vec::new()).unwrap();
        assert_eq!(state.network_id(), *profile.network_id());
        assert_eq!(state.height(), 0);
        assert_eq!(state.state_root(), *profile.genesis_state_root());
    }

    #[test]
    fn manifest_round_trips_and_discloses_no_value_bearing_or_premine_flag() {
        let profile = DevnetProfileCandidate::new(network(0x49)).unwrap();
        let bytes = profile.encode_manifest();
        assert_eq!(bytes.len(), MANIFEST_LEN);
        let verified = profile.verify_manifest(&bytes).unwrap();
        assert_eq!(verified.network_id(), profile.network_id());
        assert_eq!(verified.genesis_state_root(), profile.genesis_state_root());
        assert_eq!(verified.genesis_account_count(), 0);
        assert!(!verified.value_bearing());
    }

    #[test]
    fn manifest_rejects_wrong_network_and_profile() {
        let left = DevnetProfileCandidate::new(network(0x4a)).unwrap();
        let right = DevnetProfileCandidate::new(network(0x4b)).unwrap();
        assert_eq!(
            right.verify_manifest(&left.encode_manifest()),
            Err(DevnetProfileError::NetworkMismatch)
        );
        let mut bytes = left.encode_manifest();
        bytes[38] ^= 1;
        repair_digest(&mut bytes);
        assert_eq!(
            left.verify_manifest(&bytes),
            Err(DevnetProfileError::ProfileMismatch)
        );
    }

    #[test]
    fn manifest_rejects_consensus_genesis_premine_value_and_digest_mutations() {
        let profile = DevnetProfileCandidate::new(network(0x4c)).unwrap();
        let canonical = profile.encode_manifest();
        let cases = [
            (70usize, DevnetProfileError::ConsensusMismatch),
            (102usize, DevnetProfileError::GenesisMismatch),
            (137usize, DevnetProfileError::PremineNotAllowed),
            (138usize, DevnetProfileError::ValueBearingProfileNotAllowed),
            (170usize, DevnetProfileError::MalformedManifest),
        ];
        for (offset, expected) in cases {
            let mut mutated = canonical.clone();
            mutated[offset] ^= 1;
            if offset < 139 {
                repair_digest(&mut mutated);
            }
            assert_eq!(
                profile.verify_manifest(&mutated),
                Err(expected),
                "offset {offset}"
            );
        }
    }

    #[test]
    fn manifest_rejects_bad_magic_version_truncation_and_trailing_bytes() {
        let profile = DevnetProfileCandidate::new(network(0x4d)).unwrap();
        let canonical = profile.encode_manifest();
        let mut bad_magic = canonical.clone();
        bad_magic[0] ^= 1;
        assert_eq!(
            profile.verify_manifest(&bad_magic),
            Err(DevnetProfileError::MalformedManifest)
        );
        let mut bad_version = canonical.clone();
        bad_version[5] = 2;
        repair_digest(&mut bad_version);
        assert_eq!(
            profile.verify_manifest(&bad_version),
            Err(DevnetProfileError::UnsupportedManifestVersion)
        );
        assert_eq!(
            profile.verify_manifest(&canonical[..canonical.len() - 1]),
            Err(DevnetProfileError::MalformedManifest)
        );
        let mut trailing = canonical;
        trailing.push(0);
        assert_eq!(
            profile.verify_manifest(&trailing),
            Err(DevnetProfileError::MalformedManifest)
        );
    }

    #[test]
    fn different_networks_have_distinct_genesis_root_and_manifest() {
        let left = DevnetProfileCandidate::new(network(0x4e)).unwrap();
        let right = DevnetProfileCandidate::new(network(0x4f)).unwrap();
        assert_eq!(left.consensus_digest(), right.consensus_digest());
        assert_ne!(left.genesis_state_root(), right.genesis_state_root());
        assert_ne!(left.encode_manifest(), right.encode_manifest());
    }

    #[test]
    fn persisted_manifest_is_create_once_and_conflicts_fail_closed() {
        let dir = scratch();
        let path = dir.join("genesis.qvdn");
        let first = DevnetProfileCandidate::new(network(0x50)).unwrap();
        let second = DevnetProfileCandidate::new(network(0x51)).unwrap();
        let created = first.persist_or_verify_manifest(&path).unwrap();
        assert_eq!(
            created,
            first.verify_manifest(&first.encode_manifest()).unwrap()
        );
        let original = fs::read(&path).unwrap();
        assert_eq!(
            second.persist_or_verify_manifest(&path),
            Err(DevnetProfileError::NetworkMismatch)
        );
        assert_eq!(fs::read(&path).unwrap(), original);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn corrupted_existing_manifest_is_never_overwritten() {
        let dir = scratch();
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("genesis.qvdn");
        fs::write(&path, b"corrupt").unwrap();
        let profile = DevnetProfileCandidate::new(network(0x52)).unwrap();
        assert!(profile.persist_or_verify_manifest(&path).is_err());
        assert_eq!(fs::read(&path).unwrap(), b"corrupt");
        fs::remove_dir_all(dir).unwrap();
    }

    fn repair_digest(bytes: &mut [u8]) {
        let digest = hash_parts(MANIFEST_DOMAIN, &[&bytes[..139]]);
        bytes[139..171].copy_from_slice(&digest);
    }
}
