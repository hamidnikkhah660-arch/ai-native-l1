//! CP-0675 candidate-only dual-signature approval for an exact QFP6 Genesis package.
//!
//! Q6GA is a detached, versioned owner-approval envelope that the local permissionless launcher
//! can require and verify. It binds the exact Genesis descriptor, consensus profile, network
//! profile pin and canonical Genesis snapshot hashes plus CP-0651 economics. It is not a Mainnet
//! authorization or an independent security review.
use crate::{
    qrun_v06_cp0651_supply_candidate::{CP0651_MAX_GROSS_ATOMS, CP0651_OWNER_GENESIS_ATOMS},
    qrun_v06_genesis_descriptor_candidate::QRunV06GenesisDescriptor,
    qrun_v06_hybrid_auth_candidate::{
        qrun_v06_hybrid_account_id, QRunV06HybridTransactionSigner,
        QRUN_V06_ED25519_PUBLIC_KEY_BYTES,
    },
    v4_fat1_trust_candidate::{ML_DSA_65_PUBLIC_KEY_BYTES, ML_DSA_65_SIGNATURE_BYTES},
};
use ed25519_dalek::{Signature as Ed25519Signature, VerifyingKey};
use libcrux_ml_dsa::ml_dsa_65::{portable, MLDSA65Signature, MLDSA65VerificationKey};
use sha2::{Digest, Sha256};

pub const Q6GA_MAGIC: [u8; 4] = *b"Q6GA";
pub const Q6GA_VERSION: u16 = 1;
pub const Q6GA_SUITE_ED25519_MLDSA65: u16 = 1;
pub const Q6GA_PRODUCER_COMPENSATION_FEES_ONLY: u8 = 1;
pub const Q6GA_SIGNATURE_BYTES: usize =
    QRUN_V06_ED25519_PUBLIC_KEY_BYTES + ML_DSA_65_PUBLIC_KEY_BYTES + 64 + ML_DSA_65_SIGNATURE_BYTES;
const CORE_BYTES: usize = 8 + 9 * 32 + 8 * 3 + 1 + 7;
pub const Q6GA_ENCODED_BYTES: usize = CORE_BYTES + Q6GA_SIGNATURE_BYTES;
const SIGNING_DOMAIN_LOCAL: &[u8] = b"AIN1-QFP6-OWNER-GENESIS-APPROVAL-V1\0";
const SIGNING_DOMAIN_PUBLIC_TESTNET: &[u8] = b"AIN1-QFP6-OWNER-PUBLIC-TESTNET-AUTHORIZATION-V1\0";
pub const Q6GA_PUBLIC_TESTNET_VERSION: u16 = 2;
pub const Q6GA_SCOPE_LOCAL_ONLY: u8 = 1;
pub const Q6GA_SCOPE_ZERO_VALUE_PUBLIC_TESTNET: u8 = 2;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Q6gaError {
    Malformed,
    UnsupportedVersion,
    InvalidField(&'static str),
    WrongOwner,
    WrongNetwork,
    WrongProfile,
    WrongDescriptorCommitment,
    WrongArtifactHash(&'static str),
    WrongEconomics,
    WrongScope,
    InvalidEd25519Key,
    InvalidEd25519Signature,
    InvalidMlDsa65Signature,
    SigningFailed,
}
impl std::fmt::Display for Q6gaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for Q6gaError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QRunV06GenesisApproval {
    version: u16,
    scope: u8,
    network_id: [u8; 32],
    profile_id: [u8; 32],
    owner_account: [u8; 32],
    descriptor_commitment: [u8; 32],
    q6gd_sha256: [u8; 32],
    q6cp_sha256: [u8; 32],
    q6pn_sha256: [u8; 32],
    genesis_snapshot_sha256: [u8; 32],
    bootstrap_peers_sha256: [u8; 32],
    gross_supply_ceiling: u64,
    owner_genesis_allocation: u64,
    block_subsidy: u64,
    producer_compensation: u8,
    ed25519_public_key: [u8; QRUN_V06_ED25519_PUBLIC_KEY_BYTES],
    mldsa65_public_key: [u8; ML_DSA_65_PUBLIC_KEY_BYTES],
    ed25519_signature: [u8; 64],
    mldsa65_signature: [u8; ML_DSA_65_SIGNATURE_BYTES],
}

impl QRunV06GenesisApproval {
    #[allow(clippy::too_many_arguments)]
    pub fn sign(
        descriptor: &QRunV06GenesisDescriptor,
        q6gd_sha256: [u8; 32],
        q6cp_sha256: [u8; 32],
        q6pn_sha256: [u8; 32],
        genesis_snapshot_sha256: [u8; 32],
        bootstrap_peers_sha256: [u8; 32],
        signer: &QRunV06HybridTransactionSigner,
    ) -> Result<Self, Q6gaError> {
        Self::sign_scoped(
            Q6GA_VERSION,
            Q6GA_SCOPE_LOCAL_ONLY,
            descriptor,
            q6gd_sha256,
            q6cp_sha256,
            q6pn_sha256,
            genesis_snapshot_sha256,
            bootstrap_peers_sha256,
            signer,
        )
    }

    pub fn sign_public_testnet(
        descriptor: &QRunV06GenesisDescriptor,
        q6gd_sha256: [u8; 32],
        q6cp_sha256: [u8; 32],
        q6pn_sha256: [u8; 32],
        genesis_snapshot_sha256: [u8; 32],
        signer: &QRunV06HybridTransactionSigner,
    ) -> Result<Self, Q6gaError> {
        Self::sign_scoped(
            Q6GA_PUBLIC_TESTNET_VERSION,
            Q6GA_SCOPE_ZERO_VALUE_PUBLIC_TESTNET,
            descriptor,
            q6gd_sha256,
            q6cp_sha256,
            q6pn_sha256,
            genesis_snapshot_sha256,
            [0; 32],
            signer,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn sign_scoped(
        version: u16,
        scope: u8,
        descriptor: &QRunV06GenesisDescriptor,
        q6gd_sha256: [u8; 32],
        q6cp_sha256: [u8; 32],
        q6pn_sha256: [u8; 32],
        genesis_snapshot_sha256: [u8; 32],
        bootstrap_peers_sha256: [u8; 32],
        signer: &QRunV06HybridTransactionSigner,
    ) -> Result<Self, Q6gaError> {
        if signer.account_id() != descriptor.founder_account() {
            return Err(Q6gaError::WrongOwner);
        }
        let mut approval = Self {
            version,
            scope,
            network_id: descriptor.network_id(),
            profile_id: descriptor.profile_id(),
            owner_account: descriptor.founder_account(),
            descriptor_commitment: descriptor.commitment(),
            q6gd_sha256,
            q6cp_sha256,
            q6pn_sha256,
            genesis_snapshot_sha256,
            bootstrap_peers_sha256,
            gross_supply_ceiling: CP0651_MAX_GROSS_ATOMS as u64,
            owner_genesis_allocation: CP0651_OWNER_GENESIS_ATOMS as u64,
            block_subsidy: 0,
            producer_compensation: Q6GA_PRODUCER_COMPENSATION_FEES_ONLY,
            ed25519_public_key: signer.ed25519_public_key(),
            mldsa65_public_key: signer.mldsa65_public_key(),
            ed25519_signature: [0; 64],
            mldsa65_signature: [0; ML_DSA_65_SIGNATURE_BYTES],
        };
        approval.validate_fields()?;
        let digest = approval.signing_digest();
        let q6ha = signer
            .sign_digest(&digest)
            .map_err(|_| Q6gaError::SigningFailed)?;
        if q6ha.len() != 8 + 32 + ML_DSA_65_PUBLIC_KEY_BYTES + 64 + ML_DSA_65_SIGNATURE_BYTES
            || &q6ha[..4] != b"Q6HA"
        {
            return Err(Q6gaError::SigningFailed);
        }
        let mut offset = 8 + 32 + ML_DSA_65_PUBLIC_KEY_BYTES;
        approval
            .ed25519_signature
            .copy_from_slice(&q6ha[offset..offset + 64]);
        offset += 64;
        approval
            .mldsa65_signature
            .copy_from_slice(&q6ha[offset..offset + ML_DSA_65_SIGNATURE_BYTES]);
        approval.verify()?;
        Ok(approval)
    }

    fn encode_core(&self) -> [u8; CORE_BYTES] {
        let mut bytes = [0u8; CORE_BYTES];
        let mut cursor = 0usize;
        bytes[cursor..cursor + 4].copy_from_slice(&Q6GA_MAGIC);
        cursor += 4;
        bytes[cursor..cursor + 2].copy_from_slice(&self.version.to_be_bytes());
        cursor += 2;
        bytes[cursor..cursor + 2].copy_from_slice(&Q6GA_SUITE_ED25519_MLDSA65.to_be_bytes());
        cursor += 2;
        for field in [
            &self.network_id,
            &self.profile_id,
            &self.owner_account,
            &self.descriptor_commitment,
            &self.q6gd_sha256,
            &self.q6cp_sha256,
            &self.q6pn_sha256,
            &self.genesis_snapshot_sha256,
            &self.bootstrap_peers_sha256,
        ] {
            bytes[cursor..cursor + 32].copy_from_slice(field);
            cursor += 32;
        }
        bytes[cursor..cursor + 8].copy_from_slice(&self.gross_supply_ceiling.to_be_bytes());
        cursor += 8;
        bytes[cursor..cursor + 8].copy_from_slice(&self.owner_genesis_allocation.to_be_bytes());
        cursor += 8;
        bytes[cursor..cursor + 8].copy_from_slice(&self.block_subsidy.to_be_bytes());
        cursor += 8;
        bytes[cursor] = self.producer_compensation;
        cursor += 1;
        // V1 reserves all seven bytes; V2 uses the first byte as its explicit scope.
        if self.version == Q6GA_PUBLIC_TESTNET_VERSION {
            bytes[cursor] = self.scope;
        }
        debug_assert_eq!(cursor + 7, CORE_BYTES);
        bytes
    }

    fn signing_digest(&self) -> [u8; 32] {
        let mut hash = Sha256::new();
        let domain = match self.version {
            Q6GA_VERSION => SIGNING_DOMAIN_LOCAL,
            Q6GA_PUBLIC_TESTNET_VERSION => SIGNING_DOMAIN_PUBLIC_TESTNET,
            _ => SIGNING_DOMAIN_LOCAL,
        };
        hash.update(domain);
        hash.update(self.encode_core());
        hash.finalize().into()
    }

    fn validate_fields(&self) -> Result<(), Q6gaError> {
        match (self.version, self.scope) {
            (Q6GA_VERSION, Q6GA_SCOPE_LOCAL_ONLY)
            | (Q6GA_PUBLIC_TESTNET_VERSION, Q6GA_SCOPE_ZERO_VALUE_PUBLIC_TESTNET) => {}
            _ => return Err(Q6gaError::WrongScope),
        }
        if self.version == Q6GA_PUBLIC_TESTNET_VERSION && self.bootstrap_peers_sha256 != [0; 32] {
            return Err(Q6gaError::WrongScope);
        }
        for (label, bytes) in [
            ("network ID", self.network_id.as_slice()),
            ("profile ID", self.profile_id.as_slice()),
            ("owner account", self.owner_account.as_slice()),
            (
                "descriptor commitment",
                self.descriptor_commitment.as_slice(),
            ),
            ("Q6GD SHA-256", self.q6gd_sha256.as_slice()),
            ("Q6CP SHA-256", self.q6cp_sha256.as_slice()),
            ("Q6PN SHA-256", self.q6pn_sha256.as_slice()),
            (
                "Genesis snapshot SHA-256",
                self.genesis_snapshot_sha256.as_slice(),
            ),
            ("Ed25519 public key", self.ed25519_public_key.as_slice()),
            ("ML-DSA-65 public key", self.mldsa65_public_key.as_slice()),
        ] {
            if bytes.iter().all(|byte| *byte == 0) {
                return Err(Q6gaError::InvalidField(label));
            }
        }
        if self.gross_supply_ceiling != CP0651_MAX_GROSS_ATOMS as u64
            || self.owner_genesis_allocation != CP0651_OWNER_GENESIS_ATOMS as u64
            || self.block_subsidy != 0
            || self.producer_compensation != Q6GA_PRODUCER_COMPENSATION_FEES_ONLY
        {
            return Err(Q6gaError::WrongEconomics);
        }
        if qrun_v06_hybrid_account_id(&self.ed25519_public_key, &self.mldsa65_public_key)
            != self.owner_account
        {
            return Err(Q6gaError::WrongOwner);
        }
        Ok(())
    }

    pub fn verify(&self) -> Result<(), Q6gaError> {
        self.validate_fields()?;
        let digest = self.signing_digest();
        let verifying_key = VerifyingKey::from_bytes(&self.ed25519_public_key)
            .map_err(|_| Q6gaError::InvalidEd25519Key)?;
        verifying_key
            .verify_strict(
                &digest,
                &Ed25519Signature::from_bytes(&self.ed25519_signature),
            )
            .map_err(|_| Q6gaError::InvalidEd25519Signature)?;
        let ml_key = MLDSA65VerificationKey::new(self.mldsa65_public_key);
        let ml_signature = MLDSA65Signature::new(self.mldsa65_signature);
        portable::verify(&ml_key, &digest, &[], &ml_signature)
            .map_err(|_| Q6gaError::InvalidMlDsa65Signature)?;
        Ok(())
    }

    pub fn verify_bindings(
        &self,
        descriptor: &QRunV06GenesisDescriptor,
        q6gd_sha256: &[u8; 32],
        q6cp_sha256: &[u8; 32],
        q6pn_sha256: &[u8; 32],
        genesis_snapshot_sha256: &[u8; 32],
        bootstrap_peers_sha256: &[u8; 32],
    ) -> Result<(), Q6gaError> {
        if self.version != Q6GA_VERSION || self.scope != Q6GA_SCOPE_LOCAL_ONLY {
            return Err(Q6gaError::WrongScope);
        }
        self.verify()?;
        if self.network_id != descriptor.network_id() {
            return Err(Q6gaError::WrongNetwork);
        }
        if self.profile_id != descriptor.profile_id() {
            return Err(Q6gaError::WrongProfile);
        }
        if self.owner_account != descriptor.founder_account() {
            return Err(Q6gaError::WrongOwner);
        }
        if self.descriptor_commitment != descriptor.commitment() {
            return Err(Q6gaError::WrongDescriptorCommitment);
        }
        if &self.q6gd_sha256 != q6gd_sha256 {
            return Err(Q6gaError::WrongArtifactHash("Q6GD"));
        }
        if &self.q6cp_sha256 != q6cp_sha256 {
            return Err(Q6gaError::WrongArtifactHash("Q6CP"));
        }
        if &self.q6pn_sha256 != q6pn_sha256 {
            return Err(Q6gaError::WrongArtifactHash("Q6PN"));
        }
        if &self.genesis_snapshot_sha256 != genesis_snapshot_sha256 {
            return Err(Q6gaError::WrongArtifactHash("Genesis snapshot"));
        }
        if &self.bootstrap_peers_sha256 != bootstrap_peers_sha256 {
            return Err(Q6gaError::WrongArtifactHash("bootstrap peers"));
        }
        Ok(())
    }

    pub fn verify_public_testnet_bindings(
        &self,
        descriptor: &QRunV06GenesisDescriptor,
        q6gd_sha256: &[u8; 32],
        q6cp_sha256: &[u8; 32],
        q6pn_sha256: &[u8; 32],
        genesis_snapshot_sha256: &[u8; 32],
    ) -> Result<(), Q6gaError> {
        if self.version != Q6GA_PUBLIC_TESTNET_VERSION
            || self.scope != Q6GA_SCOPE_ZERO_VALUE_PUBLIC_TESTNET
            || self.bootstrap_peers_sha256 != [0; 32]
        {
            return Err(Q6gaError::WrongScope);
        }
        self.verify()?;
        if self.network_id != descriptor.network_id() {
            return Err(Q6gaError::WrongNetwork);
        }
        if self.profile_id != descriptor.profile_id() {
            return Err(Q6gaError::WrongProfile);
        }
        if self.owner_account != descriptor.founder_account() {
            return Err(Q6gaError::WrongOwner);
        }
        if self.descriptor_commitment != descriptor.commitment() {
            return Err(Q6gaError::WrongDescriptorCommitment);
        }
        for (actual, expected, label) in [
            (&self.q6gd_sha256, q6gd_sha256, "Q6GD"),
            (&self.q6cp_sha256, q6cp_sha256, "Q6CP"),
            (&self.q6pn_sha256, q6pn_sha256, "Q6PN"),
            (
                &self.genesis_snapshot_sha256,
                genesis_snapshot_sha256,
                "Genesis snapshot",
            ),
        ] {
            if actual != expected {
                return Err(Q6gaError::WrongArtifactHash(label));
            }
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>, Q6gaError> {
        self.verify()?;
        let mut bytes = Vec::with_capacity(Q6GA_ENCODED_BYTES);
        bytes.extend_from_slice(&self.encode_core());
        bytes.extend_from_slice(&self.ed25519_public_key);
        bytes.extend_from_slice(&self.mldsa65_public_key);
        bytes.extend_from_slice(&self.ed25519_signature);
        bytes.extend_from_slice(&self.mldsa65_signature);
        if bytes.len() != Q6GA_ENCODED_BYTES {
            return Err(Q6gaError::Malformed);
        }
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, Q6gaError> {
        if bytes.len() != Q6GA_ENCODED_BYTES
            || bytes[..4] != Q6GA_MAGIC
            || !matches!(
                u16::from_be_bytes([bytes[4], bytes[5]]),
                Q6GA_VERSION | Q6GA_PUBLIC_TESTNET_VERSION
            )
            || u16::from_be_bytes([bytes[6], bytes[7]]) != Q6GA_SUITE_ED25519_MLDSA65
        {
            return Err(Q6gaError::Malformed);
        }
        let version = u16::from_be_bytes([bytes[4], bytes[5]]);
        let mut cursor = 8usize;
        let network_id = take::<32>(bytes, &mut cursor)?;
        let profile_id = take::<32>(bytes, &mut cursor)?;
        let owner_account = take::<32>(bytes, &mut cursor)?;
        let descriptor_commitment = take::<32>(bytes, &mut cursor)?;
        let q6gd_sha256 = take::<32>(bytes, &mut cursor)?;
        let q6cp_sha256 = take::<32>(bytes, &mut cursor)?;
        let q6pn_sha256 = take::<32>(bytes, &mut cursor)?;
        let genesis_snapshot_sha256 = take::<32>(bytes, &mut cursor)?;
        let bootstrap_peers_sha256 = take::<32>(bytes, &mut cursor)?;
        let gross_supply_ceiling = take::<8>(bytes, &mut cursor)?;
        let owner_genesis_allocation = take::<8>(bytes, &mut cursor)?;
        let block_subsidy = take::<8>(bytes, &mut cursor)?;
        let producer_compensation = *bytes.get(cursor).ok_or(Q6gaError::Malformed)?;
        cursor += 1;
        let reserved = bytes.get(cursor..cursor + 7).ok_or(Q6gaError::Malformed)?;
        let scope = match version {
            Q6GA_VERSION if reserved == [0u8; 7] => Q6GA_SCOPE_LOCAL_ONLY,
            Q6GA_PUBLIC_TESTNET_VERSION
                if reserved[0] == Q6GA_SCOPE_ZERO_VALUE_PUBLIC_TESTNET
                    && reserved[1..] == [0u8; 6] =>
            {
                Q6GA_SCOPE_ZERO_VALUE_PUBLIC_TESTNET
            }
            _ => return Err(Q6gaError::Malformed),
        };
        cursor += 7;
        let ed25519_public_key = take::<QRUN_V06_ED25519_PUBLIC_KEY_BYTES>(bytes, &mut cursor)?;
        let mldsa65_public_key = take::<ML_DSA_65_PUBLIC_KEY_BYTES>(bytes, &mut cursor)?;
        let ed25519_signature = take::<64>(bytes, &mut cursor)?;
        let mldsa65_signature = take::<ML_DSA_65_SIGNATURE_BYTES>(bytes, &mut cursor)?;
        if cursor != bytes.len() {
            return Err(Q6gaError::Malformed);
        }
        let approval = Self {
            version,
            scope,
            network_id,
            profile_id,
            owner_account,
            descriptor_commitment,
            q6gd_sha256,
            q6cp_sha256,
            q6pn_sha256,
            genesis_snapshot_sha256,
            bootstrap_peers_sha256,
            gross_supply_ceiling: u64::from_be_bytes(gross_supply_ceiling),
            owner_genesis_allocation: u64::from_be_bytes(owner_genesis_allocation),
            block_subsidy: u64::from_be_bytes(block_subsidy),
            producer_compensation,
            ed25519_public_key,
            mldsa65_public_key,
            ed25519_signature,
            mldsa65_signature,
        };
        approval.verify()?;
        Ok(approval)
    }

    pub fn network_id(&self) -> [u8; 32] {
        self.network_id
    }
    pub fn profile_id(&self) -> [u8; 32] {
        self.profile_id
    }
    pub fn owner_account(&self) -> [u8; 32] {
        self.owner_account
    }
    pub fn descriptor_commitment(&self) -> [u8; 32] {
        self.descriptor_commitment
    }
    pub fn gross_supply_ceiling(&self) -> u64 {
        self.gross_supply_ceiling
    }
    pub fn owner_genesis_allocation(&self) -> u64 {
        self.owner_genesis_allocation
    }
    pub fn block_subsidy(&self) -> u64 {
        self.block_subsidy
    }
}

fn take<const N: usize>(bytes: &[u8], cursor: &mut usize) -> Result<[u8; N], Q6gaError> {
    let end = cursor.checked_add(N).ok_or(Q6gaError::Malformed)?;
    let value = bytes
        .get(*cursor..end)
        .ok_or(Q6gaError::Malformed)?
        .try_into()
        .map_err(|_| Q6gaError::Malformed)?;
    *cursor = end;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::qrun_v06_genesis_descriptor_candidate::QRunV06GenesisDescriptor;

    fn fixture() -> (QRunV06GenesisApproval, QRunV06GenesisDescriptor) {
        let signer = QRunV06HybridTransactionSigner::from_seeds([0x31; 32], [0x42; 32]).unwrap();
        let descriptor = QRunV06GenesisDescriptor::new(
            [0x11; 32],
            [0x22; 32],
            signer.account_id(),
            1_800_000_000,
            [0x33; 32],
            [0x44; 32],
        )
        .unwrap();
        let approval = QRunV06GenesisApproval::sign(
            &descriptor,
            [0x51; 32],
            [0x52; 32],
            [0x53; 32],
            [0x54; 32],
            [0x55; 32],
            &signer,
        )
        .unwrap();
        (approval, descriptor)
    }

    #[test]
    fn q6ga_roundtrip_verifies_dual_signatures_and_exact_artifact_bindings() {
        let (approval, descriptor) = fixture();
        let bytes = approval.encode().unwrap();
        assert_eq!(bytes.len(), Q6GA_ENCODED_BYTES);
        let decoded = QRunV06GenesisApproval::decode(&bytes).unwrap();
        decoded
            .verify_bindings(
                &descriptor,
                &[0x51; 32],
                &[0x52; 32],
                &[0x53; 32],
                &[0x54; 32],
                &[0x55; 32],
            )
            .unwrap();
        assert!(decoded
            .verify_bindings(
                &descriptor,
                &[0x51; 32],
                &[0x52; 32],
                &[0x53; 32],
                &[0x54; 32],
                &[0x56; 32],
            )
            .is_err());
    }

    #[test]
    fn q6ga_v2_is_separately_scoped_to_zero_value_public_testnet() {
        let signer = QRunV06HybridTransactionSigner::from_seeds([0x31; 32], [0x42; 32]).unwrap();
        let descriptor = QRunV06GenesisDescriptor::new(
            [0x11; 32],
            [0x22; 32],
            signer.account_id(),
            1_800_000_000,
            [0x33; 32],
            [0x44; 32],
        )
        .unwrap();
        let approval = QRunV06GenesisApproval::sign_public_testnet(
            &descriptor,
            [0x51; 32],
            [0x52; 32],
            [0x53; 32],
            [0x54; 32],
            &signer,
        )
        .unwrap();
        let bytes = approval.encode().unwrap();
        assert_eq!(
            u16::from_be_bytes([bytes[4], bytes[5]]),
            Q6GA_PUBLIC_TESTNET_VERSION
        );
        let decoded = QRunV06GenesisApproval::decode(&bytes).unwrap();
        decoded
            .verify_public_testnet_bindings(
                &descriptor,
                &[0x51; 32],
                &[0x52; 32],
                &[0x53; 32],
                &[0x54; 32],
            )
            .unwrap();
        assert_eq!(
            decoded.verify_bindings(
                &descriptor,
                &[0x51; 32],
                &[0x52; 32],
                &[0x53; 32],
                &[0x54; 32],
                &[0x55; 32],
            ),
            Err(Q6gaError::WrongScope)
        );
        assert!(decoded
            .verify_public_testnet_bindings(
                &descriptor,
                &[0x51; 32],
                &[0x99; 32],
                &[0x53; 32],
                &[0x54; 32],
            )
            .is_err());
        let mut changed_scope = bytes;
        let scope_offset = 8 + 9 * 32 + 8 * 3 + 1;
        changed_scope[scope_offset] = Q6GA_SCOPE_LOCAL_ONLY;
        assert!(QRunV06GenesisApproval::decode(&changed_scope).is_err());
    }

    #[test]
    fn q6ga_rejects_signature_tampering_and_economic_substitution() {
        let (approval, _) = fixture();
        let mut bytes = approval.encode().unwrap();
        let signature_offset =
            CORE_BYTES + QRUN_V06_ED25519_PUBLIC_KEY_BYTES + ML_DSA_65_PUBLIC_KEY_BYTES;
        bytes[signature_offset] ^= 1;
        assert!(QRunV06GenesisApproval::decode(&bytes).is_err());

        let mut changed = approval.clone();
        changed.block_subsidy = 1;
        assert_eq!(changed.verify(), Err(Q6gaError::WrongEconomics));
    }

    #[test]
    fn q6ga_rejects_wrong_signing_owner() {
        let signer = QRunV06HybridTransactionSigner::from_seeds([0x61; 32], [0x72; 32]).unwrap();
        let other = QRunV06HybridTransactionSigner::from_seeds([0x63; 32], [0x74; 32]).unwrap();
        let descriptor = QRunV06GenesisDescriptor::new(
            [0x11; 32],
            [0x22; 32],
            other.account_id(),
            1_800_000_000,
            [0x33; 32],
            [0x44; 32],
        )
        .unwrap();
        assert_eq!(
            QRunV06GenesisApproval::sign(
                &descriptor,
                [0x51; 32],
                [0x52; 32],
                [0x53; 32],
                [0x54; 32],
                [0x55; 32],
                &signer,
            )
            .unwrap_err(),
            Q6gaError::WrongOwner
        );
    }
}
