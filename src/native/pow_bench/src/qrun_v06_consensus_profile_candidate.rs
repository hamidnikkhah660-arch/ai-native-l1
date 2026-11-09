//! Canonical Q6CP consensus-parameter artifact for QFP6 bootstrap.
//!
//! Q6CP is deliberately a parameter container, not a Mainnet approval token. Its SHA-256 must
//! be pinned independently in the bootstrap config, and the embedded network/profile/Genesis
//! descriptor/fingerprint must match the separately trusted Q6PN/Q6GD identity. This decoder
//! rejects non-v0.6 protocol versions and issuance schedules that differ from the monetary
//! execution constants compiled into this candidate.

use crate::{
    consensus::{ConsensusParameters, PowAlgorithm, PowParameters, Uint256},
    issuance_schedule::IssuanceParameters,
    qrun_v06_checkpoint_candidate::qrun_v06_consensus_fingerprint,
    qrun_v06_genesis_descriptor_candidate::QRunV06GenesisDescriptor,
    qrun_v06_pow_wire_candidate::QRUN_V06_PROTOCOL_VERSION,
};
pub const QRUN_V06_CONSENSUS_PROFILE_MAGIC: &[u8; 4] = b"Q6CP";
pub const QRUN_V06_CONSENSUS_PROFILE_VERSION: u16 = 1;
pub const QRUN_V06_CONSENSUS_PROFILE_BYTES: usize = 294;
pub const QRUN_V06_CONSENSUS_PROFILE_MAX_BYTES: usize = QRUN_V06_CONSENSUS_PROFILE_BYTES;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QRunV06ConsensusProfileError {
    InvalidLength,
    InvalidMagic,
    UnsupportedVersion,
    NonCanonicalReservedBytes,
    UnsupportedPowAlgorithm,
    InvalidIdentity,
    WrongNetwork,
    WrongProfile,
    WrongGenesisDescriptor,
    WrongConsensusFingerprint,
    WrongProtocolVersion,
    MonetaryIssuanceProfileMismatch,
    InvalidParameters(String),
}

impl std::fmt::Display for QRunV06ConsensusProfileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "QFP6 Q6CP consensus profile error: {self:?}")
    }
}
impl std::error::Error for QRunV06ConsensusProfileError {}

/// An immutable, canonical encoding of the full QFP6 consensus parameter set.
///
/// The type does not contain private keys, trust roots, or a production-approval assertion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QRunV06ConsensusProfile {
    network_id: [u8; 32],
    profile_id: [u8; 32],
    genesis_descriptor_commitment: [u8; 32],
    parameters: ConsensusParameters,
    consensus_fingerprint: [u8; 32],
}

impl QRunV06ConsensusProfile {
    /// Validate the v0.6 protocol/monetary execution requirements and derive the canonical
    /// fingerprint. This public helper exposes no alternate algorithm or parameter defaults.
    pub fn fingerprint_parameters(
        parameters: &ConsensusParameters,
    ) -> Result<[u8; 32], QRunV06ConsensusProfileError> {
        validate_parameters(parameters)?;
        qrun_v06_consensus_fingerprint(parameters)
            .map_err(|error| QRunV06ConsensusProfileError::InvalidParameters(error.to_string()))
    }

    pub fn new(
        network_id: [u8; 32],
        profile_id: [u8; 32],
        genesis_descriptor_commitment: [u8; 32],
        parameters: ConsensusParameters,
    ) -> Result<Self, QRunV06ConsensusProfileError> {
        if network_id == [0; 32]
            || profile_id == [0; 32]
            || genesis_descriptor_commitment == [0; 32]
        {
            return Err(QRunV06ConsensusProfileError::InvalidIdentity);
        }
        let consensus_fingerprint = Self::fingerprint_parameters(&parameters)?;
        Ok(Self {
            network_id,
            profile_id,
            genesis_descriptor_commitment,
            parameters,
            consensus_fingerprint,
        })
    }

    pub fn network_id(&self) -> [u8; 32] {
        self.network_id
    }

    pub fn profile_id(&self) -> [u8; 32] {
        self.profile_id
    }

    pub fn genesis_descriptor_commitment(&self) -> [u8; 32] {
        self.genesis_descriptor_commitment
    }

    pub fn parameters(&self) -> &ConsensusParameters {
        &self.parameters
    }

    pub fn consensus_fingerprint(&self) -> [u8; 32] {
        self.consensus_fingerprint
    }

    /// Validate every Q6CP identity binding against the separately pinned Genesis descriptor.
    pub fn validate_against(
        &self,
        descriptor: &QRunV06GenesisDescriptor,
    ) -> Result<(), QRunV06ConsensusProfileError> {
        if self.network_id != descriptor.network_id() {
            return Err(QRunV06ConsensusProfileError::WrongNetwork);
        }
        if self.profile_id != descriptor.profile_id() {
            return Err(QRunV06ConsensusProfileError::WrongProfile);
        }
        if self.genesis_descriptor_commitment != descriptor.commitment() {
            return Err(QRunV06ConsensusProfileError::WrongGenesisDescriptor);
        }
        if self.consensus_fingerprint != descriptor.consensus_fingerprint() {
            return Err(QRunV06ConsensusProfileError::WrongConsensusFingerprint);
        }
        let recomputed = Self::fingerprint_parameters(&self.parameters)?;
        if recomputed != self.consensus_fingerprint {
            return Err(QRunV06ConsensusProfileError::WrongConsensusFingerprint);
        }
        Ok(())
    }

    /// Canonical fixed-width Q6CP v1 encoding. The trailing consensus fingerprint is recomputed
    /// from every preceding parameter and is not trusted during decode.
    pub fn encode(
        &self,
    ) -> Result<[u8; QRUN_V06_CONSENSUS_PROFILE_BYTES], QRunV06ConsensusProfileError> {
        let fingerprint = Self::fingerprint_parameters(&self.parameters)?;
        if fingerprint != self.consensus_fingerprint {
            return Err(QRunV06ConsensusProfileError::WrongConsensusFingerprint);
        }

        let mut bytes = Vec::with_capacity(QRUN_V06_CONSENSUS_PROFILE_BYTES);
        bytes.extend_from_slice(QRUN_V06_CONSENSUS_PROFILE_MAGIC);
        bytes.extend_from_slice(&QRUN_V06_CONSENSUS_PROFILE_VERSION.to_be_bytes());
        bytes.extend_from_slice(&[0, 0]);
        bytes.extend_from_slice(&self.network_id);
        bytes.extend_from_slice(&self.profile_id);
        bytes.extend_from_slice(&self.genesis_descriptor_commitment);

        let params = &self.parameters;
        bytes.extend_from_slice(&params.protocol_version.to_be_bytes());
        bytes.extend_from_slice(&params.target_block_time_secs.to_be_bytes());
        bytes.extend_from_slice(&params.difficulty_window_blocks.to_be_bytes());
        bytes.extend_from_slice(&params.difficulty_min_ratio_divisor.to_be_bytes());
        bytes.extend_from_slice(&params.difficulty_max_ratio.to_be_bytes());
        bytes.extend_from_slice(&params.pow_limit.to_be_bytes());
        bytes.extend_from_slice(&params.initial_target.to_be_bytes());
        match params.pow.algorithm {
            PowAlgorithm::Argon2id => bytes.push(1),
        }
        bytes.extend_from_slice(&[0, 0, 0]);
        bytes.extend_from_slice(&params.pow.memory_kib.to_be_bytes());
        bytes.extend_from_slice(&params.pow.iterations.to_be_bytes());
        bytes.extend_from_slice(&params.pow.lanes.to_be_bytes());
        bytes.push(params.pow.output_bytes);
        bytes.extend_from_slice(&[0, 0, 0]);
        bytes.extend_from_slice(&params.issuance.maximum_supply().to_be_bytes());
        bytes.extend_from_slice(&params.issuance.initial_subsidy().to_be_bytes());
        bytes.extend_from_slice(&params.issuance.blocks_per_halving().to_be_bytes());
        bytes.extend_from_slice(&fingerprint);

        if bytes.len() != QRUN_V06_CONSENSUS_PROFILE_BYTES {
            return Err(QRunV06ConsensusProfileError::InvalidLength);
        }
        bytes
            .try_into()
            .map_err(|_| QRunV06ConsensusProfileError::InvalidLength)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, QRunV06ConsensusProfileError> {
        if bytes.len() != QRUN_V06_CONSENSUS_PROFILE_BYTES {
            return Err(QRunV06ConsensusProfileError::InvalidLength);
        }
        if &bytes[..4] != QRUN_V06_CONSENSUS_PROFILE_MAGIC {
            return Err(QRunV06ConsensusProfileError::InvalidMagic);
        }
        if u16::from_be_bytes([bytes[4], bytes[5]]) != QRUN_V06_CONSENSUS_PROFILE_VERSION {
            return Err(QRunV06ConsensusProfileError::UnsupportedVersion);
        }
        if bytes[6..8] != [0, 0] {
            return Err(QRunV06ConsensusProfileError::NonCanonicalReservedBytes);
        }

        let mut cursor = 8usize;
        let network_id = take::<32>(bytes, &mut cursor)?;
        let profile_id = take::<32>(bytes, &mut cursor)?;
        let genesis_descriptor_commitment = take::<32>(bytes, &mut cursor)?;

        let protocol_version = u16::from_be_bytes(take::<2>(bytes, &mut cursor)?);
        let target_block_time_secs = u64::from_be_bytes(take::<8>(bytes, &mut cursor)?);
        let difficulty_window_blocks = u64::from_be_bytes(take::<8>(bytes, &mut cursor)?);
        let difficulty_min_ratio_divisor = u64::from_be_bytes(take::<8>(bytes, &mut cursor)?);
        let difficulty_max_ratio = u64::from_be_bytes(take::<8>(bytes, &mut cursor)?);
        let pow_limit = Uint256::from_be_bytes(take::<32>(bytes, &mut cursor)?);
        let initial_target = Uint256::from_be_bytes(take::<32>(bytes, &mut cursor)?);
        let algorithm = match take::<1>(bytes, &mut cursor)?[0] {
            1 => PowAlgorithm::Argon2id,
            _ => return Err(QRunV06ConsensusProfileError::UnsupportedPowAlgorithm),
        };
        if take::<3>(bytes, &mut cursor)? != [0, 0, 0] {
            return Err(QRunV06ConsensusProfileError::NonCanonicalReservedBytes);
        }
        let memory_kib = u32::from_be_bytes(take::<4>(bytes, &mut cursor)?);
        let iterations = u32::from_be_bytes(take::<4>(bytes, &mut cursor)?);
        let lanes = u32::from_be_bytes(take::<4>(bytes, &mut cursor)?);
        let output_bytes = take::<1>(bytes, &mut cursor)?[0];
        if take::<3>(bytes, &mut cursor)? != [0, 0, 0] {
            return Err(QRunV06ConsensusProfileError::NonCanonicalReservedBytes);
        }
        let maximum_supply = u128::from_be_bytes(take::<16>(bytes, &mut cursor)?);
        let initial_subsidy = u128::from_be_bytes(take::<16>(bytes, &mut cursor)?);
        let blocks_per_halving = u64::from_be_bytes(take::<8>(bytes, &mut cursor)?);
        let encoded_fingerprint = take::<32>(bytes, &mut cursor)?;
        if cursor != bytes.len() {
            return Err(QRunV06ConsensusProfileError::InvalidLength);
        }

        let issuance = if initial_subsidy == 0 {
            if blocks_per_halving != 1 {
                return Err(QRunV06ConsensusProfileError::MonetaryIssuanceProfileMismatch);
            }
            IssuanceParameters::fee_only(maximum_supply)
        } else {
            IssuanceParameters::new(maximum_supply, initial_subsidy, blocks_per_halving)
        }
        .map_err(|error| QRunV06ConsensusProfileError::InvalidParameters(error.to_string()))?;

        let parameters = ConsensusParameters {
            protocol_version,
            target_block_time_secs,
            difficulty_window_blocks,
            difficulty_min_ratio_divisor,
            difficulty_max_ratio,
            pow_limit,
            initial_target,
            pow: PowParameters {
                algorithm,
                memory_kib,
                iterations,
                lanes,
                output_bytes,
            },
            issuance,
        };
        let profile = Self::new(
            network_id,
            profile_id,
            genesis_descriptor_commitment,
            parameters,
        )?;
        if profile.consensus_fingerprint != encoded_fingerprint {
            return Err(QRunV06ConsensusProfileError::WrongConsensusFingerprint);
        }
        Ok(profile)
    }
}

fn validate_parameters(
    parameters: &ConsensusParameters,
) -> Result<(), QRunV06ConsensusProfileError> {
    parameters
        .validate()
        .map_err(|error| QRunV06ConsensusProfileError::InvalidParameters(error.to_string()))?;
    if parameters.protocol_version != QRUN_V06_PROTOCOL_VERSION {
        return Err(QRunV06ConsensusProfileError::WrongProtocolVersion);
    }
    parameters
        .validate_monetary_execution_compatibility()
        .map_err(|_| QRunV06ConsensusProfileError::MonetaryIssuanceProfileMismatch)
}

fn take<const N: usize>(
    bytes: &[u8],
    cursor: &mut usize,
) -> Result<[u8; N], QRunV06ConsensusProfileError> {
    let end = cursor
        .checked_add(N)
        .ok_or(QRunV06ConsensusProfileError::InvalidLength)?;
    let slice = bytes
        .get(*cursor..end)
        .ok_or(QRunV06ConsensusProfileError::InvalidLength)?;
    *cursor = end;
    slice
        .try_into()
        .map_err(|_| QRunV06ConsensusProfileError::InvalidLength)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::ConsensusParameters;
    use crate::qrun_v06_genesis_descriptor_candidate::QRunV06GenesisDescriptor;

    const NETWORK: [u8; 32] = [0xA1; 32];
    const PROFILE: [u8; 32] = [0xA2; 32];
    const FOUNDER: [u8; 32] = [0xA3; 32];
    const POLICY: [u8; 32] = [0xA4; 32];

    fn params() -> ConsensusParameters {
        let mut params = ConsensusParameters::candidate_testnet().unwrap();
        params.protocol_version = QRUN_V06_PROTOCOL_VERSION;
        params
    }

    fn descriptor(params: &ConsensusParameters) -> QRunV06GenesisDescriptor {
        QRunV06GenesisDescriptor::new(
            NETWORK,
            PROFILE,
            FOUNDER,
            1_800_000_000,
            qrun_v06_consensus_fingerprint(params).unwrap(),
            POLICY,
        )
        .unwrap()
    }

    #[test]
    fn q6cp_fixed_width_round_trip_recomputes_full_consensus_fingerprint() {
        let params = params();
        let descriptor = descriptor(&params);
        let profile =
            QRunV06ConsensusProfile::new(NETWORK, PROFILE, descriptor.commitment(), params.clone())
                .unwrap();
        let encoded = profile.encode().unwrap();
        assert_eq!(encoded.len(), QRUN_V06_CONSENSUS_PROFILE_BYTES);
        let decoded = QRunV06ConsensusProfile::decode(&encoded).unwrap();
        assert_eq!(decoded, profile);
        decoded.validate_against(&descriptor).unwrap();
        assert_eq!(
            decoded.parameters().issuance.maximum_supply(),
            crate::state_machine::MAX_TOTAL_SUPPLY_ATOMS
        );
        assert_eq!(
            decoded.parameters().issuance.initial_subsidy(),
            crate::state_machine::MONETARY_INITIAL_SUBSIDY_ATOMS
        );
        assert_eq!(
            decoded.parameters().issuance.blocks_per_halving(),
            crate::state_machine::MONETARY_BLOCKS_PER_HALVING
        );
    }

    #[test]
    fn q6cp_rejects_trailing_bytes_bad_reserved_fields_and_mutated_pow_fields() {
        let params = params();
        let descriptor = descriptor(&params);
        let profile =
            QRunV06ConsensusProfile::new(NETWORK, PROFILE, descriptor.commitment(), params)
                .unwrap();
        let encoded = profile.encode().unwrap();

        let mut trailing = encoded.to_vec();
        trailing.push(0);
        assert_eq!(
            QRunV06ConsensusProfile::decode(&trailing),
            Err(QRunV06ConsensusProfileError::InvalidLength)
        );

        let mut reserved = encoded;
        reserved[6] = 1;
        assert_eq!(
            QRunV06ConsensusProfile::decode(&reserved),
            Err(QRunV06ConsensusProfileError::NonCanonicalReservedBytes)
        );

        let mut changed_memory = encoded;
        // memory_kib begins at the fixed Q6CP byte offset 206.
        changed_memory[206] ^= 1;
        assert_eq!(
            QRunV06ConsensusProfile::decode(&changed_memory),
            Err(QRunV06ConsensusProfileError::WrongConsensusFingerprint)
        );
    }

    #[test]
    fn q6cp_decoder_rejects_zero_network_profile_or_genesis_identity() {
        let params = params();
        let descriptor = descriptor(&params);
        let profile =
            QRunV06ConsensusProfile::new(NETWORK, PROFILE, descriptor.commitment(), params)
                .unwrap();
        let encoded = profile.encode().unwrap();

        for range in [8..40, 40..72, 72..104] {
            let mut corrupted = encoded;
            corrupted[range].fill(0);
            assert_eq!(
                QRunV06ConsensusProfile::decode(&corrupted),
                Err(QRunV06ConsensusProfileError::InvalidIdentity)
            );
        }
    }

    #[test]
    fn q6cp_identity_must_match_the_exact_q6gd_descriptor() {
        let params = params();
        let descriptor = descriptor(&params);
        let correct =
            QRunV06ConsensusProfile::new(NETWORK, PROFILE, descriptor.commitment(), params.clone())
                .unwrap();
        correct.validate_against(&descriptor).unwrap();

        let wrong_network = QRunV06ConsensusProfile::new(
            [0xB1; 32],
            PROFILE,
            descriptor.commitment(),
            params.clone(),
        )
        .unwrap();
        assert_eq!(
            wrong_network.validate_against(&descriptor),
            Err(QRunV06ConsensusProfileError::WrongNetwork)
        );

        let wrong_profile = QRunV06ConsensusProfile::new(
            NETWORK,
            [0xB2; 32],
            descriptor.commitment(),
            params.clone(),
        )
        .unwrap();
        assert_eq!(
            wrong_profile.validate_against(&descriptor),
            Err(QRunV06ConsensusProfileError::WrongProfile)
        );

        let wrong_genesis =
            QRunV06ConsensusProfile::new(NETWORK, PROFILE, [0xB3; 32], params).unwrap();
        assert_eq!(
            wrong_genesis.validate_against(&descriptor),
            Err(QRunV06ConsensusProfileError::WrongGenesisDescriptor)
        );
    }

    #[test]
    fn q6cp_refuses_fee_only_or_altered_monetary_execution_policy() {
        let mut fee_only = ConsensusParameters::qrun_v05_calibrated_candidate().unwrap();
        fee_only.protocol_version = QRUN_V06_PROTOCOL_VERSION;
        assert_eq!(
            QRunV06ConsensusProfile::new(NETWORK, PROFILE, [0xB3; 32], fee_only),
            Err(QRunV06ConsensusProfileError::MonetaryIssuanceProfileMismatch)
        );

        let mut altered = params();
        altered.issuance = IssuanceParameters::new(
            altered.issuance.maximum_supply(),
            altered.issuance.initial_subsidy() + 1,
            altered.issuance.blocks_per_halving(),
        )
        .unwrap();
        assert_eq!(
            QRunV06ConsensusProfile::new(NETWORK, PROFILE, [0xB3; 32], altered),
            Err(QRunV06ConsensusProfileError::MonetaryIssuanceProfileMismatch)
        );
    }
}
