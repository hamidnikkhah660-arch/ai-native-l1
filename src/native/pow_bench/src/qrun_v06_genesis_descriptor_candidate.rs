//! Immutable QFP6 Genesis descriptor candidate.
//!
//! It binds Genesis time, Network/Profile, Founder, consensus parameters and the
//! CP-0528 tokenomics policy. A selected network profile must pin this commitment
//! out-of-band; the encoding itself is not anti-rollback authority.

use sha2::{Digest, Sha256};

const MAGIC: [u8; 4] = *b"Q6GD";
const VERSION: u16 = 1;
const COMMITMENT_DOMAIN: &[u8] = b"QRUN-V06-GENESIS-DESCRIPTOR-COMMITMENT-V1\0";
const CORE_BYTES: usize = 4 + 2 + 32 + 32 + 32 + 8 + 32 + 32;
pub const QRUN_V06_GENESIS_DESCRIPTOR_BYTES: usize = CORE_BYTES + 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QRunV06GenesisDescriptorError {
    Malformed,
    ZeroNetwork,
    ZeroProfile,
    ZeroFounder,
    ZeroGenesisTimestamp,
    ZeroConsensusFingerprint,
    ZeroTokenomicsPolicyFingerprint,
    CommitmentMismatch,
}

impl std::fmt::Display for QRunV06GenesisDescriptorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed => f.write_str("QFP6 Genesis descriptor is malformed"),
            Self::ZeroNetwork => f.write_str("QFP6 Genesis descriptor network ID cannot be zero"),
            Self::ZeroProfile => f.write_str("QFP6 Genesis descriptor profile ID cannot be zero"),
            Self::ZeroFounder => f.write_str("QFP6 Genesis descriptor Founder cannot be zero"),
            Self::ZeroGenesisTimestamp => f.write_str("QFP6 Genesis timestamp must be nonzero"),
            Self::ZeroConsensusFingerprint => {
                f.write_str("QFP6 Genesis consensus fingerprint cannot be zero")
            }
            Self::ZeroTokenomicsPolicyFingerprint => {
                f.write_str("QFP6 Genesis tokenomics fingerprint cannot be zero")
            }
            Self::CommitmentMismatch => f.write_str("QFP6 Genesis descriptor commitment mismatch"),
        }
    }
}
impl std::error::Error for QRunV06GenesisDescriptorError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QRunV06GenesisDescriptor {
    network_id: [u8; 32],
    profile_id: [u8; 32],
    founder_account: [u8; 32],
    genesis_timestamp: u64,
    consensus_fingerprint: [u8; 32],
    tokenomics_policy_fingerprint: [u8; 32],
    commitment: [u8; 32],
}

impl QRunV06GenesisDescriptor {
    pub fn new(
        network_id: [u8; 32],
        profile_id: [u8; 32],
        founder_account: [u8; 32],
        genesis_timestamp: u64,
        consensus_fingerprint: [u8; 32],
        tokenomics_policy_fingerprint: [u8; 32],
    ) -> Result<Self, QRunV06GenesisDescriptorError> {
        if network_id == [0; 32] {
            return Err(QRunV06GenesisDescriptorError::ZeroNetwork);
        }
        if profile_id == [0; 32] {
            return Err(QRunV06GenesisDescriptorError::ZeroProfile);
        }
        if founder_account == [0; 32] {
            return Err(QRunV06GenesisDescriptorError::ZeroFounder);
        }
        if genesis_timestamp == 0 {
            return Err(QRunV06GenesisDescriptorError::ZeroGenesisTimestamp);
        }
        if consensus_fingerprint == [0; 32] {
            return Err(QRunV06GenesisDescriptorError::ZeroConsensusFingerprint);
        }
        if tokenomics_policy_fingerprint == [0; 32] {
            return Err(QRunV06GenesisDescriptorError::ZeroTokenomicsPolicyFingerprint);
        }
        let mut descriptor = Self {
            network_id,
            profile_id,
            founder_account,
            genesis_timestamp,
            consensus_fingerprint,
            tokenomics_policy_fingerprint,
            commitment: [0; 32],
        };
        descriptor.commitment = descriptor.calculate_commitment();
        Ok(descriptor)
    }

    fn encode_core(&self) -> [u8; CORE_BYTES] {
        let mut out = [0u8; CORE_BYTES];
        let mut cursor = 0usize;
        out[cursor..cursor + 4].copy_from_slice(&MAGIC);
        cursor += 4;
        out[cursor..cursor + 2].copy_from_slice(&VERSION.to_be_bytes());
        cursor += 2;
        out[cursor..cursor + 32].copy_from_slice(&self.network_id);
        cursor += 32;
        out[cursor..cursor + 32].copy_from_slice(&self.profile_id);
        cursor += 32;
        out[cursor..cursor + 32].copy_from_slice(&self.founder_account);
        cursor += 32;
        out[cursor..cursor + 8].copy_from_slice(&self.genesis_timestamp.to_be_bytes());
        cursor += 8;
        out[cursor..cursor + 32].copy_from_slice(&self.consensus_fingerprint);
        cursor += 32;
        out[cursor..cursor + 32].copy_from_slice(&self.tokenomics_policy_fingerprint);
        out
    }

    fn calculate_commitment(&self) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(COMMITMENT_DOMAIN);
        hash.update(self.encode_core());
        hash.finalize().into()
    }

    pub fn encode(&self) -> [u8; QRUN_V06_GENESIS_DESCRIPTOR_BYTES] {
        let mut out = [0u8; QRUN_V06_GENESIS_DESCRIPTOR_BYTES];
        out[..CORE_BYTES].copy_from_slice(&self.encode_core());
        out[CORE_BYTES..].copy_from_slice(&self.commitment);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, QRunV06GenesisDescriptorError> {
        if bytes.len() != QRUN_V06_GENESIS_DESCRIPTOR_BYTES
            || bytes[..4] != MAGIC
            || u16::from_be_bytes([bytes[4], bytes[5]]) != VERSION
        {
            return Err(QRunV06GenesisDescriptorError::Malformed);
        }
        let mut cursor = 6usize;
        let network_id = take_array::<32>(bytes, &mut cursor)?;
        let profile_id = take_array::<32>(bytes, &mut cursor)?;
        let founder_account = take_array::<32>(bytes, &mut cursor)?;
        let genesis_timestamp = u64::from_be_bytes(take_array::<8>(bytes, &mut cursor)?);
        let consensus_fingerprint = take_array::<32>(bytes, &mut cursor)?;
        let tokenomics_policy_fingerprint = take_array::<32>(bytes, &mut cursor)?;
        let commitment = take_array::<32>(bytes, &mut cursor)?;
        let descriptor = Self::new(
            network_id,
            profile_id,
            founder_account,
            genesis_timestamp,
            consensus_fingerprint,
            tokenomics_policy_fingerprint,
        )?;
        if descriptor.commitment != commitment {
            return Err(QRunV06GenesisDescriptorError::CommitmentMismatch);
        }
        if descriptor.encode().as_slice() != bytes {
            return Err(QRunV06GenesisDescriptorError::Malformed);
        }
        Ok(descriptor)
    }

    pub fn validate_binding(
        &self,
        network_id: &[u8; 32],
        profile_id: &[u8; 32],
        founder_account: &[u8; 32],
        consensus_fingerprint: &[u8; 32],
        tokenomics_policy_fingerprint: &[u8; 32],
    ) -> Result<(), QRunV06GenesisDescriptorError> {
        if &self.network_id != network_id {
            return Err(QRunV06GenesisDescriptorError::ZeroNetwork);
        }
        if &self.profile_id != profile_id {
            return Err(QRunV06GenesisDescriptorError::ZeroProfile);
        }
        if &self.founder_account != founder_account {
            return Err(QRunV06GenesisDescriptorError::ZeroFounder);
        }
        if &self.consensus_fingerprint != consensus_fingerprint {
            return Err(QRunV06GenesisDescriptorError::ZeroConsensusFingerprint);
        }
        if &self.tokenomics_policy_fingerprint != tokenomics_policy_fingerprint {
            return Err(QRunV06GenesisDescriptorError::ZeroTokenomicsPolicyFingerprint);
        }
        if self.commitment != self.calculate_commitment() {
            return Err(QRunV06GenesisDescriptorError::CommitmentMismatch);
        }
        Ok(())
    }

    pub fn network_id(&self) -> [u8; 32] {
        self.network_id
    }
    pub fn profile_id(&self) -> [u8; 32] {
        self.profile_id
    }
    pub fn founder_account(&self) -> [u8; 32] {
        self.founder_account
    }
    pub fn genesis_timestamp(&self) -> u64 {
        self.genesis_timestamp
    }
    pub fn consensus_fingerprint(&self) -> [u8; 32] {
        self.consensus_fingerprint
    }
    pub fn tokenomics_policy_fingerprint(&self) -> [u8; 32] {
        self.tokenomics_policy_fingerprint
    }
    pub fn commitment(&self) -> [u8; 32] {
        self.commitment
    }
}

fn take_array<const N: usize>(
    bytes: &[u8],
    cursor: &mut usize,
) -> Result<[u8; N], QRunV06GenesisDescriptorError> {
    let end = (*cursor)
        .checked_add(N)
        .ok_or(QRunV06GenesisDescriptorError::Malformed)?;
    let output = bytes
        .get(*cursor..end)
        .ok_or(QRunV06GenesisDescriptorError::Malformed)?
        .try_into()
        .map_err(|_| QRunV06GenesisDescriptorError::Malformed)?;
    *cursor = end;
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    const NETWORK: [u8; 32] = [0x11; 32];
    const PROFILE: [u8; 32] = [0x22; 32];
    const FOUNDER: [u8; 32] = [0x23; 32];
    const CONSENSUS: [u8; 32] = [0x33; 32];
    const TOKENOMICS: [u8; 32] = [0x44; 32];

    fn descriptor(timestamp: u64) -> QRunV06GenesisDescriptor {
        QRunV06GenesisDescriptor::new(NETWORK, PROFILE, FOUNDER, timestamp, CONSENSUS, TOKENOMICS)
            .unwrap()
    }

    #[test]
    fn descriptor_roundtrip_is_canonical_and_binds_every_protocol_input() {
        let original = descriptor(1_800_000_000);
        let encoded = original.encode();
        assert_eq!(encoded.len(), QRUN_V06_GENESIS_DESCRIPTOR_BYTES);
        assert_eq!(
            QRunV06GenesisDescriptor::decode(&encoded).unwrap(),
            original
        );
        let commitment_hex = original
            .commitment()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        assert_eq!(
            commitment_hex, "c55171f164a12fb8ee4e70bc0b51a08fe0764440fce95af7a694dad4c052e070",
            "Q6GD v1 cross-language commitment vector must remain stable"
        );
        assert_ne!(
            descriptor(1_800_000_001).commitment(),
            original.commitment()
        );
        assert_ne!(
            QRunV06GenesisDescriptor::new(
                [0x12; 32],
                PROFILE,
                FOUNDER,
                1_800_000_000,
                CONSENSUS,
                TOKENOMICS
            )
            .unwrap()
            .commitment(),
            original.commitment()
        );
        assert_ne!(
            QRunV06GenesisDescriptor::new(
                NETWORK,
                PROFILE,
                [0x24; 32],
                1_800_000_000,
                CONSENSUS,
                TOKENOMICS
            )
            .unwrap()
            .commitment(),
            original.commitment()
        );
        assert_ne!(
            QRunV06GenesisDescriptor::new(
                NETWORK,
                PROFILE,
                FOUNDER,
                1_800_000_000,
                [0x34; 32],
                TOKENOMICS
            )
            .unwrap()
            .commitment(),
            original.commitment()
        );
        assert_ne!(
            QRunV06GenesisDescriptor::new(
                NETWORK,
                PROFILE,
                FOUNDER,
                1_800_000_000,
                CONSENSUS,
                [0x45; 32]
            )
            .unwrap()
            .commitment(),
            original.commitment()
        );
    }

    #[test]
    fn descriptor_rejects_zero_inputs_and_modified_commitments() {
        assert_eq!(
            QRunV06GenesisDescriptor::new(NETWORK, PROFILE, FOUNDER, 0, CONSENSUS, TOKENOMICS),
            Err(QRunV06GenesisDescriptorError::ZeroGenesisTimestamp)
        );
        assert_eq!(
            QRunV06GenesisDescriptor::new([0; 32], PROFILE, FOUNDER, 1, CONSENSUS, TOKENOMICS),
            Err(QRunV06GenesisDescriptorError::ZeroNetwork)
        );
        let mut tampered = descriptor(1_800_000_000).encode();
        tampered[110] ^= 1;
        assert_eq!(
            QRunV06GenesisDescriptor::decode(&tampered),
            Err(QRunV06GenesisDescriptorError::CommitmentMismatch)
        );
        assert_eq!(
            QRunV06GenesisDescriptor::decode(&tampered[..tampered.len() - 1]),
            Err(QRunV06GenesisDescriptorError::Malformed)
        );
    }
}
