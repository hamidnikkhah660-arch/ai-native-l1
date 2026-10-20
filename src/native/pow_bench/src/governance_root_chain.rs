//! Dual-authorized, monotonically versioned governance-root rotation chains.
//!
//! The first root is pinned out of band. Every subsequent root transition is authorized by both
//! the old and the new root. The operator supplies a minimum root epoch independently of writable
//! registry state; this is an operational rollback floor, not a hardware monotonic counter.
use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};

const MAGIC: &[u8; 4] = b"GRC1";
const VERSION_V1: u16 = 1;
const VERSION_V2: u16 = 2;
const PREFIX_LEN: usize = 40;
const TRANSITION_CORE_LEN_V1: usize = 72;
const TRANSITION_CORE_LEN_V2: usize = 73;
const SIGNATURE_LEN: usize = 64;
const TRANSITION_LEN_V1: usize = TRANSITION_CORE_LEN_V1 + SIGNATURE_LEN * 2;
const TRANSITION_LEN_V2: usize = TRANSITION_CORE_LEN_V2 + SIGNATURE_LEN * 2;
pub const MAX_GOVERNANCE_ROOT_TRANSITIONS: usize = 32;
pub const MAX_ROOT_CHAIN_WIRE_LEN: usize =
    PREFIX_LEN + TRANSITION_LEN_V2 * MAX_GOVERNANCE_ROOT_TRANSITIONS;
const SIGNING_DOMAIN: &[u8] = b"AIN1-NOISE-GOVERNANCE-ROOT-ROTATION-V1\0";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GovernanceRootChainError {
    Malformed,
    UnsupportedVersion,
    NetworkMismatch,
    InvalidRootKey,
    InvalidOldRootSignature,
    InvalidRecoverySignature,
    RecoveryKeyUnavailable,
    RecoveryKeyNotIndependent,
    InvalidNewRootSignature,
    InvalidAnchor,
    CurrentRootMismatch,
    RootEpochRollback,
    RootEpochDiscontinuity,
    RootChainDiscontinuity,
    SameRootTransition,
}

impl std::fmt::Display for GovernanceRootChainError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed => write!(f, "governance root chain is malformed"),
            Self::UnsupportedVersion => write!(f, "governance root chain version is unsupported"),
            Self::NetworkMismatch => write!(f, "governance root chain belongs to another network"),
            Self::InvalidRootKey => write!(f, "governance root contains an invalid Ed25519 key"),
            Self::InvalidOldRootSignature => {
                write!(f, "old governance root did not authorize rotation")
            }
            Self::InvalidRecoverySignature => {
                write!(f, "pinned offline recovery root did not authorize recovery")
            }
            Self::RecoveryKeyUnavailable => {
                write!(
                    f,
                    "recovery transition requires a separately pinned recovery public key"
                )
            }
            Self::RecoveryKeyNotIndependent => {
                write!(f, "offline recovery public key must be distinct from every online governance root")
            }
            Self::InvalidNewRootSignature => {
                write!(f, "new governance root did not countersign rotation")
            }
            Self::InvalidAnchor => write!(
                f,
                "governance root chain does not start at the configured trust anchor"
            ),
            Self::CurrentRootMismatch => {
                write!(f, "configured governance root does not match the chain tip")
            }
            Self::RootEpochRollback => write!(
                f,
                "governance root chain is below the independently configured minimum epoch"
            ),
            Self::RootEpochDiscontinuity => {
                write!(f, "governance root epochs must increase by exactly one")
            }
            Self::RootChainDiscontinuity => write!(
                f,
                "governance root transition old key does not match the prior chain tip"
            ),
            Self::SameRootTransition => {
                write!(f, "governance root rotation must change the public key")
            }
        }
    }
}

impl std::error::Error for GovernanceRootChainError {}

/// Fully checked chain from the out-of-band anchor (epoch 1) to the configured current root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedGovernanceRootChain {
    network_id: [u8; 32],
    roots: Vec<([u8; 32], u64)>,
    digest: [u8; 32],
}

impl VerifiedGovernanceRootChain {
    pub fn current_key(&self) -> &[u8; 32] {
        &self
            .roots
            .last()
            .expect("verified chain always has its anchor")
            .0
    }

    pub fn current_epoch(&self) -> u64 {
        self.roots
            .last()
            .expect("verified chain always has its anchor")
            .1
    }

    pub fn digest(&self) -> &[u8; 32] {
        &self.digest
    }

    pub fn network_id(&self) -> &[u8; 32] {
        &self.network_id
    }

    /// Resolve the historical root whose public-key fingerprint is recorded in durable registry
    /// state. Returning a key only means it appears in a fully verified chain from the pinned
    /// anchor; caller still verifies the historical registry signature with this key.
    pub fn key_for_fingerprint(&self, fingerprint: &[u8; 32]) -> Option<[u8; 32]> {
        self.roots.iter().find_map(|(key, _)| {
            let candidate: [u8; 32] = Sha256::digest(key).into();
            (&candidate == fingerprint).then_some(*key)
        })
    }

    pub fn contains_root(&self, public_key: &[u8; 32]) -> bool {
        self.roots.iter().any(|(key, _)| key == public_key)
    }

    /// A one-root chain is useful for first bootstrap and for deployments that have not rotated
    /// their original pinned trust anchor. Its epoch is exactly one.
    pub fn pinned_anchor(
        network_id: [u8; 32],
        anchor_public_key: [u8; 32],
    ) -> Result<Self, GovernanceRootChainError> {
        VerifyingKey::from_bytes(&anchor_public_key)
            .map_err(|_| GovernanceRootChainError::InvalidRootKey)?;
        let mut canonical = Vec::with_capacity(PREFIX_LEN);
        canonical.extend_from_slice(MAGIC);
        canonical.extend_from_slice(&VERSION_V1.to_be_bytes());
        canonical.extend_from_slice(&network_id);
        canonical.extend_from_slice(&0u16.to_be_bytes());
        Ok(Self {
            network_id,
            roots: vec![(anchor_public_key, 1)],
            digest: Sha256::digest(canonical).into(),
        })
    }
}

/// Verify a GRC1 file. The anchor public key and minimum epoch must come from trusted deployment
/// configuration that is not rolled back with the writable registry/state directory.
pub fn verify_governance_root_chain(
    wire: &[u8],
    expected_network_id: &[u8; 32],
    anchor_public_key: &[u8; 32],
    configured_current_public_key: &[u8; 32],
    minimum_epoch: u64,
) -> Result<VerifiedGovernanceRootChain, GovernanceRootChainError> {
    verify_governance_root_chain_inner(
        wire,
        expected_network_id,
        anchor_public_key,
        None,
        configured_current_public_key,
        minimum_epoch,
    )
}

/// Verify a GRC1 root chain which may contain recovery-authorized transitions. The recovery key
/// is pinned independently of the writable registry/state directory and should normally be held
/// offline. In format v2, a mode-2 transition replaces the compromised/unavailable current root's
/// signature with this recovery root's signature; the proposed new root must still countersign.
pub fn verify_governance_root_chain_with_recovery(
    wire: &[u8],
    expected_network_id: &[u8; 32],
    anchor_public_key: &[u8; 32],
    recovery_public_key: &[u8; 32],
    configured_current_public_key: &[u8; 32],
    minimum_epoch: u64,
) -> Result<VerifiedGovernanceRootChain, GovernanceRootChainError> {
    VerifyingKey::from_bytes(recovery_public_key)
        .map_err(|_| GovernanceRootChainError::InvalidRootKey)?;
    if recovery_public_key == anchor_public_key
        || recovery_public_key == configured_current_public_key
    {
        return Err(GovernanceRootChainError::RecoveryKeyNotIndependent);
    }
    verify_governance_root_chain_inner(
        wire,
        expected_network_id,
        anchor_public_key,
        Some(recovery_public_key),
        configured_current_public_key,
        minimum_epoch,
    )
}

fn verify_governance_root_chain_inner(
    wire: &[u8],
    expected_network_id: &[u8; 32],
    anchor_public_key: &[u8; 32],
    recovery_public_key: Option<&[u8; 32]>,
    configured_current_public_key: &[u8; 32],
    minimum_epoch: u64,
) -> Result<VerifiedGovernanceRootChain, GovernanceRootChainError> {
    if minimum_epoch == 0 || wire.len() < PREFIX_LEN || wire.len() > MAX_ROOT_CHAIN_WIRE_LEN {
        return Err(if minimum_epoch == 0 {
            GovernanceRootChainError::RootEpochRollback
        } else {
            GovernanceRootChainError::Malformed
        });
    }
    if &wire[..4] != MAGIC {
        return Err(GovernanceRootChainError::Malformed);
    }
    let version = u16::from_be_bytes(
        wire[4..6]
            .try_into()
            .map_err(|_| GovernanceRootChainError::Malformed)?,
    );
    let (core_len, transition_len) = match version {
        VERSION_V1 => (TRANSITION_CORE_LEN_V1, TRANSITION_LEN_V1),
        VERSION_V2 => (TRANSITION_CORE_LEN_V2, TRANSITION_LEN_V2),
        _ => return Err(GovernanceRootChainError::UnsupportedVersion),
    };
    let network_id: [u8; 32] = wire[6..38]
        .try_into()
        .map_err(|_| GovernanceRootChainError::Malformed)?;
    if &network_id != expected_network_id {
        return Err(GovernanceRootChainError::NetworkMismatch);
    }
    let count = u16::from_be_bytes(
        wire[38..40]
            .try_into()
            .map_err(|_| GovernanceRootChainError::Malformed)?,
    ) as usize;
    if count > MAX_GOVERNANCE_ROOT_TRANSITIONS || wire.len() != PREFIX_LEN + count * transition_len
    {
        return Err(GovernanceRootChainError::Malformed);
    }
    VerifyingKey::from_bytes(anchor_public_key)
        .map_err(|_| GovernanceRootChainError::InvalidRootKey)?;

    let mut roots = vec![(*anchor_public_key, 1u64)];
    let mut expected_epoch = 2u64;
    let mut offset = PREFIX_LEN;
    for _ in 0..count {
        let epoch = u64::from_be_bytes(
            wire[offset..offset + 8]
                .try_into()
                .map_err(|_| GovernanceRootChainError::Malformed)?,
        );
        if epoch != expected_epoch {
            return Err(GovernanceRootChainError::RootEpochDiscontinuity);
        }
        let old_root: [u8; 32] = wire[offset + 8..offset + 40]
            .try_into()
            .map_err(|_| GovernanceRootChainError::Malformed)?;
        let new_root: [u8; 32] = wire[offset + 40..offset + 72]
            .try_into()
            .map_err(|_| GovernanceRootChainError::Malformed)?;
        if old_root != roots.last().expect("anchor exists").0 {
            return Err(GovernanceRootChainError::RootChainDiscontinuity);
        }
        if old_root == new_root {
            return Err(GovernanceRootChainError::SameRootTransition);
        }
        if recovery_public_key
            .is_some_and(|recovery| recovery == &old_root || recovery == &new_root)
        {
            return Err(GovernanceRootChainError::RecoveryKeyNotIndependent);
        }
        let new_verifying = VerifyingKey::from_bytes(&new_root)
            .map_err(|_| GovernanceRootChainError::InvalidRootKey)?;
        let mode = if version == VERSION_V1 {
            1
        } else {
            match wire[offset + TRANSITION_CORE_LEN_V1] {
                1 => 1, // normal: previous root + new root both authorize
                2 => 2, // recovery: offline recovery root + new root authorize
                _ => return Err(GovernanceRootChainError::Malformed),
            }
        };
        // GRC1 v2 normal transitions keep the v1 signature preimage so an existing verified
        // v1 history can be carried forward without asking an old root to sign again. Switching
        // mode 1 <-> 2 still changes which first public key verifies the first signature; old and
        // recovery keys are required to be independent. Recovery transitions bind their mode byte.
        let signed_core_len = if version == VERSION_V2 && mode == 1 {
            TRANSITION_CORE_LEN_V1
        } else {
            core_len
        };
        let mut preimage = Vec::with_capacity(SIGNING_DOMAIN.len() + 32 + signed_core_len);
        preimage.extend_from_slice(SIGNING_DOMAIN);
        preimage.extend_from_slice(&network_id);
        preimage.extend_from_slice(&wire[offset..offset + signed_core_len]);
        let first_signature =
            Signature::from_slice(&wire[offset + core_len..offset + core_len + SIGNATURE_LEN])
                .map_err(|_| {
                    if mode == 2 {
                        GovernanceRootChainError::InvalidRecoverySignature
                    } else {
                        GovernanceRootChainError::InvalidOldRootSignature
                    }
                })?;
        let new_signature = Signature::from_slice(
            &wire[offset + core_len + SIGNATURE_LEN..offset + transition_len],
        )
        .map_err(|_| GovernanceRootChainError::InvalidNewRootSignature)?;

        if mode == 1 {
            let old_verifying = VerifyingKey::from_bytes(&old_root)
                .map_err(|_| GovernanceRootChainError::InvalidRootKey)?;
            old_verifying
                .verify_strict(&preimage, &first_signature)
                .map_err(|_| GovernanceRootChainError::InvalidOldRootSignature)?;
        } else {
            let recovery_public_key =
                recovery_public_key.ok_or(GovernanceRootChainError::RecoveryKeyUnavailable)?;
            let recovery_verifying = VerifyingKey::from_bytes(recovery_public_key)
                .map_err(|_| GovernanceRootChainError::InvalidRootKey)?;
            recovery_verifying
                .verify_strict(&preimage, &first_signature)
                .map_err(|_| GovernanceRootChainError::InvalidRecoverySignature)?;
        }
        new_verifying
            .verify_strict(&preimage, &new_signature)
            .map_err(|_| GovernanceRootChainError::InvalidNewRootSignature)?;
        roots.push((new_root, epoch));
        expected_epoch = expected_epoch
            .checked_add(1)
            .ok_or(GovernanceRootChainError::RootEpochDiscontinuity)?;
        offset += transition_len;
    }
    let current_epoch = roots.last().expect("anchor exists").1;
    if current_epoch < minimum_epoch {
        return Err(GovernanceRootChainError::RootEpochRollback);
    }
    if roots.last().expect("anchor exists").0 != *configured_current_public_key {
        return Err(GovernanceRootChainError::CurrentRootMismatch);
    }
    Ok(VerifiedGovernanceRootChain {
        network_id,
        roots,
        digest: Sha256::digest(wire).into(),
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn signed_chain(network: [u8; 32], roots: &[SigningKey]) -> Vec<u8> {
        let count = roots.len().saturating_sub(1);
        assert!(count <= MAX_GOVERNANCE_ROOT_TRANSITIONS);
        let mut wire = Vec::with_capacity(PREFIX_LEN + count * TRANSITION_LEN_V1);
        wire.extend_from_slice(MAGIC);
        wire.extend_from_slice(&VERSION_V1.to_be_bytes());
        wire.extend_from_slice(&network);
        wire.extend_from_slice(&(count as u16).to_be_bytes());
        for (index, pair) in roots.windows(2).enumerate() {
            let epoch = (index as u64) + 2;
            let old_root = pair[0].verifying_key().to_bytes();
            let new_root = pair[1].verifying_key().to_bytes();
            let mut core = Vec::with_capacity(TRANSITION_CORE_LEN_V1);
            core.extend_from_slice(&epoch.to_be_bytes());
            core.extend_from_slice(&old_root);
            core.extend_from_slice(&new_root);
            let mut preimage = Vec::with_capacity(SIGNING_DOMAIN.len() + 32 + core.len());
            preimage.extend_from_slice(SIGNING_DOMAIN);
            preimage.extend_from_slice(&network);
            preimage.extend_from_slice(&core);
            wire.extend_from_slice(&core);
            wire.extend_from_slice(&pair[0].sign(&preimage).to_bytes());
            wire.extend_from_slice(&pair[1].sign(&preimage).to_bytes());
        }
        wire
    }

    /// Carry forward an already-signed v1 history, then append one v2 recovery transition.
    /// The append operation needs only the historical wire bytes plus the new root and offline
    /// recovery key; it deliberately does not receive the displaced root's private key.
    fn signed_recovery_chain(
        network: [u8; 32],
        roots: &[SigningKey],
        recovery: &SigningKey,
    ) -> Vec<u8> {
        assert!(roots.len() >= 2);
        let historical_v1 = signed_chain(network, &roots[..roots.len() - 1]);
        let new_root = roots.last().expect("at least two roots");
        append_recovery_to_v1_history(&historical_v1, new_root, recovery)
    }

    fn append_recovery_to_v1_history(
        historical: &[u8],
        new_root: &SigningKey,
        recovery: &SigningKey,
    ) -> Vec<u8> {
        assert_eq!(&historical[..4], MAGIC);
        assert_eq!(
            u16::from_be_bytes([historical[4], historical[5]]),
            VERSION_V1
        );
        let network: [u8; 32] = historical[6..38].try_into().unwrap();
        let old_count = u16::from_be_bytes([historical[38], historical[39]]) as usize;
        assert!(old_count > 0 && old_count < MAX_GOVERNANCE_ROOT_TRANSITIONS);
        assert_eq!(historical.len(), PREFIX_LEN + old_count * TRANSITION_LEN_V1);

        let new_count = old_count + 1;
        let mut wire = Vec::with_capacity(PREFIX_LEN + new_count * TRANSITION_LEN_V2);
        wire.extend_from_slice(MAGIC);
        wire.extend_from_slice(&VERSION_V2.to_be_bytes());
        wire.extend_from_slice(&network);
        wire.extend_from_slice(&(new_count as u16).to_be_bytes());
        for index in 0..old_count {
            let offset = PREFIX_LEN + index * TRANSITION_LEN_V1;
            let core = &historical[offset..offset + TRANSITION_CORE_LEN_V1];
            let old_signature = &historical
                [offset + TRANSITION_CORE_LEN_V1..offset + TRANSITION_CORE_LEN_V1 + SIGNATURE_LEN];
            let new_signature = &historical
                [offset + TRANSITION_CORE_LEN_V1 + SIGNATURE_LEN..offset + TRANSITION_LEN_V1];
            wire.extend_from_slice(core);
            wire.push(1); // v2 normal transition; its v1 preimage/signatures remain unchanged.
            wire.extend_from_slice(old_signature);
            wire.extend_from_slice(new_signature);
        }

        let last_offset = PREFIX_LEN + (old_count - 1) * TRANSITION_LEN_V1;
        let prior_tip: [u8; 32] = historical[last_offset + 40..last_offset + 72]
            .try_into()
            .unwrap();
        let next_public = new_root.verifying_key().to_bytes();
        let mut core = Vec::with_capacity(TRANSITION_CORE_LEN_V2);
        core.extend_from_slice(&((old_count as u64) + 2).to_be_bytes());
        core.extend_from_slice(&prior_tip);
        core.extend_from_slice(&next_public);
        core.push(2); // Recovery authorization plus new-root countersign.
        let mut preimage = Vec::with_capacity(SIGNING_DOMAIN.len() + 32 + core.len());
        preimage.extend_from_slice(SIGNING_DOMAIN);
        preimage.extend_from_slice(&network);
        preimage.extend_from_slice(&core);
        wire.extend_from_slice(&core);
        wire.extend_from_slice(&recovery.sign(&preimage).to_bytes());
        wire.extend_from_slice(&new_root.sign(&preimage).to_bytes());
        wire
    }

    #[test]
    fn offline_recovery_root_can_replace_unavailable_previous_root() {
        let root1 = SigningKey::from_bytes(&[0x98; 32]);
        let root2 = SigningKey::from_bytes(&[0x99; 32]);
        let root3 = SigningKey::from_bytes(&[0x9a; 32]);
        let recovery = SigningKey::from_bytes(&[0x9b; 32]);
        let wrong_recovery = SigningKey::from_bytes(&[0x9c; 32]);
        let network = [0xc6; 32];
        let roots = [root1.clone(), root2.clone(), root3.clone()];
        let wire = signed_recovery_chain(network, &roots, &recovery);
        let verified = verify_governance_root_chain_with_recovery(
            &wire,
            &network,
            &root1.verifying_key().to_bytes(),
            &recovery.verifying_key().to_bytes(),
            &root3.verifying_key().to_bytes(),
            3,
        )
        .unwrap();
        assert_eq!(verified.current_epoch(), 3);
        assert_eq!(verified.current_key(), &root3.verifying_key().to_bytes());

        assert_eq!(
            verify_governance_root_chain(
                &wire,
                &network,
                &root1.verifying_key().to_bytes(),
                &root3.verifying_key().to_bytes(),
                3,
            )
            .unwrap_err(),
            GovernanceRootChainError::RecoveryKeyUnavailable
        );
        assert_eq!(
            verify_governance_root_chain_with_recovery(
                &wire,
                &network,
                &root1.verifying_key().to_bytes(),
                &wrong_recovery.verifying_key().to_bytes(),
                &root3.verifying_key().to_bytes(),
                3,
            )
            .unwrap_err(),
            GovernanceRootChainError::InvalidRecoverySignature
        );
        assert_eq!(
            verify_governance_root_chain_with_recovery(
                &wire,
                &network,
                &root1.verifying_key().to_bytes(),
                &root1.verifying_key().to_bytes(),
                &root3.verifying_key().to_bytes(),
                3,
            )
            .unwrap_err(),
            GovernanceRootChainError::RecoveryKeyNotIndependent
        );
        assert_eq!(
            verify_governance_root_chain_with_recovery(
                &wire,
                &network,
                &root1.verifying_key().to_bytes(),
                &recovery.verifying_key().to_bytes(),
                &recovery.verifying_key().to_bytes(),
                3,
            )
            .unwrap_err(),
            GovernanceRootChainError::RecoveryKeyNotIndependent
        );
        let mut invalid_recovery_signature = wire.clone();
        invalid_recovery_signature[PREFIX_LEN + TRANSITION_LEN_V2 + TRANSITION_CORE_LEN_V2] ^= 1;
        assert_eq!(
            verify_governance_root_chain_with_recovery(
                &invalid_recovery_signature,
                &network,
                &root1.verifying_key().to_bytes(),
                &recovery.verifying_key().to_bytes(),
                &root3.verifying_key().to_bytes(),
                3,
            )
            .unwrap_err(),
            GovernanceRootChainError::InvalidRecoverySignature
        );
    }

    #[test]
    fn root_chain_requires_both_roots_and_monotonic_epochs() {
        let root1 = SigningKey::from_bytes(&[0x81; 32]);
        let root2 = SigningKey::from_bytes(&[0x82; 32]);
        let root3 = SigningKey::from_bytes(&[0x83; 32]);
        let network = [0xc1; 32];
        let wire = signed_chain(network, &[root1.clone(), root2.clone(), root3.clone()]);
        let verified = verify_governance_root_chain(
            &wire,
            &network,
            &root1.verifying_key().to_bytes(),
            &root3.verifying_key().to_bytes(),
            3,
        )
        .unwrap();
        assert_eq!(verified.current_epoch(), 3);
        assert!(verified.contains_root(&root2.verifying_key().to_bytes()));
        let fp2: [u8; 32] = Sha256::digest(root2.verifying_key().to_bytes()).into();
        assert_eq!(
            verified.key_for_fingerprint(&fp2),
            Some(root2.verifying_key().to_bytes())
        );
        assert_eq!(
            verify_governance_root_chain(
                &wire,
                &network,
                &root1.verifying_key().to_bytes(),
                &root3.verifying_key().to_bytes(),
                4,
            )
            .unwrap_err(),
            GovernanceRootChainError::RootEpochRollback
        );
    }

    #[test]
    fn root_chain_rejects_wrong_anchor_tip_tamper_and_network() {
        let root1 = SigningKey::from_bytes(&[0x84; 32]);
        let root2 = SigningKey::from_bytes(&[0x85; 32]);
        let other = SigningKey::from_bytes(&[0x86; 32]);
        let network = [0xc2; 32];
        let wire = signed_chain(network, &[root1.clone(), root2.clone()]);
        assert_eq!(
            verify_governance_root_chain(
                &wire,
                &network,
                &other.verifying_key().to_bytes(),
                &root2.verifying_key().to_bytes(),
                2,
            )
            .unwrap_err(),
            GovernanceRootChainError::RootChainDiscontinuity
        );
        assert_eq!(
            verify_governance_root_chain(
                &wire,
                &network,
                &root1.verifying_key().to_bytes(),
                &other.verifying_key().to_bytes(),
                2,
            )
            .unwrap_err(),
            GovernanceRootChainError::CurrentRootMismatch
        );
        assert_eq!(
            verify_governance_root_chain(
                &wire,
                &[0xff; 32],
                &root1.verifying_key().to_bytes(),
                &root2.verifying_key().to_bytes(),
                2,
            )
            .unwrap_err(),
            GovernanceRootChainError::NetworkMismatch
        );
        let mut tampered = wire.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        assert_eq!(
            verify_governance_root_chain(
                &tampered,
                &network,
                &root1.verifying_key().to_bytes(),
                &root2.verifying_key().to_bytes(),
                2,
            )
            .unwrap_err(),
            GovernanceRootChainError::InvalidNewRootSignature
        );
    }

    #[test]
    fn root_chain_rejects_missing_old_root_authorization_and_epoch_gaps() {
        let root1 = SigningKey::from_bytes(&[0x88; 32]);
        let root2 = SigningKey::from_bytes(&[0x89; 32]);
        let network = [0xc5; 32];
        let valid = signed_chain(network, &[root1.clone(), root2.clone()]);

        let mut bad_old_signature = valid.clone();
        // Header is 40 bytes, core is 72 bytes, then the old-root signature starts.
        bad_old_signature[40 + TRANSITION_CORE_LEN_V1] ^= 1;
        assert_eq!(
            verify_governance_root_chain(
                &bad_old_signature,
                &network,
                &root1.verifying_key().to_bytes(),
                &root2.verifying_key().to_bytes(),
                2,
            )
            .unwrap_err(),
            GovernanceRootChainError::InvalidOldRootSignature
        );

        let mut skipped_epoch = valid;
        skipped_epoch[47] = 3; // Epoch field is big-endian u64 at bytes 40..48.
        assert_eq!(
            verify_governance_root_chain(
                &skipped_epoch,
                &network,
                &root1.verifying_key().to_bytes(),
                &root2.verifying_key().to_bytes(),
                2,
            )
            .unwrap_err(),
            GovernanceRootChainError::RootEpochDiscontinuity
        );
    }

    #[test]
    fn one_root_anchor_requires_independent_epoch_floor_one() {
        let root = SigningKey::from_bytes(&[0x87; 32]);
        let network = [0xc3; 32];
        let wire = signed_chain(network, std::slice::from_ref(&root));
        assert_eq!(wire.len(), PREFIX_LEN);
        let verified = verify_governance_root_chain(
            &wire,
            &network,
            &root.verifying_key().to_bytes(),
            &root.verifying_key().to_bytes(),
            1,
        )
        .unwrap();
        assert_eq!(verified.current_epoch(), 1);
        assert_eq!(
            verify_governance_root_chain(
                &wire,
                &network,
                &root.verifying_key().to_bytes(),
                &root.verifying_key().to_bytes(),
                2,
            )
            .unwrap_err(),
            GovernanceRootChainError::RootEpochRollback
        );
    }
}
