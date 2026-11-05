//! QRun v0.6 canonical asset metadata and issuer-policy registry candidate.
//!
//! This module is isolated from QFP5/QFB5. It provides deterministic, network-bound
//! registration and issuer-admin transitions. A registry entry is metadata, not proof
//! of legal ownership, reserve backing, redemption, or external-custodian solvency.
use crate::state_machine::{AccountId, NetworkId, TransactionAuthenticator};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

const ASSET_ID_DOMAIN: &[u8] = b"QRUN-V06-ASSET-ID-V1\0";
const REGISTRATION_SIGN_DOMAIN: &[u8] = b"QRUN-V06-ASSET-REGISTRATION-SIGN-V1\0";
const ADMIN_SIGN_DOMAIN: &[u8] = b"QRUN-V06-ASSET-ADMIN-SIGN-V1\0";
const REGISTRY_ROOT_DOMAIN: &[u8] = b"QRUN-V06-ASSET-REGISTRY-ROOT-V1\0";
const REGISTRY_SNAPSHOT_MAGIC: [u8; 4] = *b"Q6RG";
const REGISTRY_SNAPSHOT_VERSION: u16 = 1;
const REGISTRY_SNAPSHOT_CHECKSUM_DOMAIN: &[u8] = b"QRUN-V06-ASSET-REGISTRY-SNAPSHOT-CHECKSUM-V1\0";
pub const MAX_QRUN_V06_REGISTRY_SNAPSHOT_BYTES: usize = 8 * 1024 * 1024;
const MAX_REGISTRY_SNAPSHOT_ENTRIES: usize = 100_000;
pub const MAX_ASSET_NAME_BYTES: usize = 64;
pub const MAX_ASSET_SYMBOL_BYTES: usize = 16;
pub const MAX_ASSET_SIGNATURE_BYTES: usize = 4 * 1024;
pub const MAX_ASSET_DECIMALS: u8 = 18;
pub const DEFAULT_MAX_REGISTERED_ASSETS: usize = 4_096;

pub type AssetId = [u8; 32];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AssetSupplyPolicy {
    /// Exact initial supply is issued at registration. No later mint operation is allowed.
    Fixed { total_supply: u128 },
    /// The issuer may mint more units, but total outstanding units may never exceed this cap.
    IssuerCapped { max_supply: u128 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AssetTrustPolicy {
    /// No external backing, reserve, custodian, or redemption claim is recorded.
    Unverified,
    /// Issuer supplied an evidence digest; the digest is not independently verified here.
    IssuerAttested { evidence_hash: [u8; 32] },
    /// A named custodian is asserted by the issuer; no custody proof is verified here.
    CustodianAttested {
        custodian: AccountId,
        evidence_hash: [u8; 32],
    },
    /// A bridge identity and evidence digest are asserted; bridge security is not verified here.
    BridgeAttested {
        bridge_id: [u8; 32],
        evidence_hash: [u8; 32],
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssetRegistration {
    pub network_id: NetworkId,
    pub issuer: AccountId,
    /// Shared issuer-admin nonce; registration and later admin actions use one sequence.
    pub issuer_nonce: u64,
    /// User-chosen uniqueness salt; asset ID is derived, never supplied independently.
    pub salt: [u8; 32],
    pub name: String,
    pub symbol: String,
    pub decimals: u8,
    pub supply_policy: AssetSupplyPolicy,
    pub initial_supply: u128,
    /// Account credited with the complete initial issuance during the unified transition.
    pub initial_recipient: AccountId,
    pub trust_policy: AssetTrustPolicy,
    /// Exclusive expiry: invalid when inclusion_timestamp >= expires_at.
    pub expires_at: u64,
    pub signature: Vec<u8>,
}

impl AssetRegistration {
    pub fn asset_id(&self) -> AssetId {
        let mut hash = Sha256::new();
        hash.update(ASSET_ID_DOMAIN);
        hash.update(self.network_id);
        hash.update(self.issuer);
        hash.update(self.issuer_nonce.to_be_bytes());
        hash.update(self.salt);
        hash.finalize().into()
    }

    pub fn signing_digest(&self) -> Result<[u8; 32], AssetRegistryError> {
        validate_registration_fields(self)?;
        let mut hash = Sha256::new();
        hash.update(REGISTRATION_SIGN_DOMAIN);
        hash.update(self.network_id);
        hash.update(self.issuer);
        hash.update(self.issuer_nonce.to_be_bytes());
        hash.update(self.salt);
        put_bytes(&mut hash, self.name.as_bytes());
        put_bytes(&mut hash, self.symbol.as_bytes());
        hash.update([self.decimals]);
        match &self.supply_policy {
            AssetSupplyPolicy::Fixed { total_supply } => {
                hash.update([1]);
                hash.update(total_supply.to_be_bytes());
            }
            AssetSupplyPolicy::IssuerCapped { max_supply } => {
                hash.update([2]);
                hash.update(max_supply.to_be_bytes());
            }
        }
        hash.update(self.initial_supply.to_be_bytes());
        hash.update(self.initial_recipient);
        hash_trust_policy(&mut hash, &self.trust_policy);
        hash.update(self.expires_at.to_be_bytes());
        Ok(hash.finalize().into())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AssetAdminAction {
    Mint {
        asset_id: AssetId,
        recipient: AccountId,
        amount: u128,
    },
    SetTransfersEnabled {
        asset_id: AssetId,
        enabled: bool,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedAssetAdminOperation {
    pub network_id: NetworkId,
    pub issuer: AccountId,
    pub issuer_nonce: u64,
    pub expires_at: u64,
    pub action: AssetAdminAction,
    pub signature: Vec<u8>,
}

impl SignedAssetAdminOperation {
    pub fn signing_digest(&self) -> Result<[u8; 32], AssetRegistryError> {
        if self.network_id.iter().all(|b| *b == 0)
            || self.issuer.iter().all(|b| *b == 0)
            || self.issuer_nonce == 0
            || self.expires_at == 0
            || self.signature.len() > MAX_ASSET_SIGNATURE_BYTES
        {
            return Err(AssetRegistryError::MalformedAdminOperation);
        }
        let mut hash = Sha256::new();
        hash.update(ADMIN_SIGN_DOMAIN);
        hash.update(self.network_id);
        hash.update(self.issuer);
        hash.update(self.issuer_nonce.to_be_bytes());
        hash.update(self.expires_at.to_be_bytes());
        match &self.action {
            AssetAdminAction::Mint {
                asset_id,
                recipient,
                amount,
            } => {
                if is_zero(asset_id) || is_zero(recipient) || *amount == 0 {
                    return Err(AssetRegistryError::MalformedAdminOperation);
                }
                hash.update([1]);
                hash.update(asset_id);
                hash.update(recipient);
                hash.update(amount.to_be_bytes());
            }
            AssetAdminAction::SetTransfersEnabled { asset_id, enabled } => {
                if is_zero(asset_id) {
                    return Err(AssetRegistryError::MalformedAdminOperation);
                }
                hash.update([2]);
                hash.update(asset_id);
                hash.update([u8::from(*enabled)]);
            }
        }
        Ok(hash.finalize().into())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssetMetadata {
    pub asset_id: AssetId,
    pub issuer: AccountId,
    pub registration_nonce: u64,
    pub name: String,
    pub symbol: String,
    pub decimals: u8,
    pub supply_policy: AssetSupplyPolicy,
    pub initial_supply: u128,
    pub current_supply: u128,
    pub trust_policy: AssetTrustPolicy,
    pub transfers_enabled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AssetRegistryError {
    InvalidNetworkId,
    WrongNetwork,
    InvalidIssuer,
    InvalidIssuerNonce { expected: u64, actual: u64 },
    Expired,
    InvalidSignature,
    SignatureOversize,
    InvalidName,
    InvalidSymbol,
    InvalidDecimals,
    InvalidSupplyPolicy,
    InvalidInitialSupply,
    InvalidSalt,
    InvalidTrustEvidence,
    AssetIdCollision,
    TooManyAssets,
    AssetNotFound,
    NotIssuer,
    MintNotAllowed,
    SupplyCapExceeded,
    ZeroAmount,
    InvalidRecipient,
    ArithmeticOverflow,
    MalformedAdminOperation,
    SnapshotMalformed,
    SnapshotChecksumMismatch,
    SnapshotNonCanonical,
    SnapshotOversize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssetAdminEffect {
    pub minted: Option<(AssetId, AccountId, u128)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QRunV06AssetRegistryCandidate {
    network_id: NetworkId,
    assets: BTreeMap<AssetId, AssetMetadata>,
    issuer_nonces: BTreeMap<AccountId, u64>,
    max_assets: usize,
}

impl QRunV06AssetRegistryCandidate {
    pub fn new(network_id: NetworkId, max_assets: usize) -> Result<Self, AssetRegistryError> {
        if is_zero(&network_id) {
            return Err(AssetRegistryError::InvalidNetworkId);
        }
        if max_assets == 0 || max_assets > 100_000 {
            return Err(AssetRegistryError::TooManyAssets);
        }
        Ok(Self {
            network_id,
            assets: BTreeMap::new(),
            issuer_nonces: BTreeMap::new(),
            max_assets,
        })
    }

    pub fn network_id(&self) -> NetworkId {
        self.network_id
    }

    pub fn asset_count(&self) -> usize {
        self.assets.len()
    }

    pub fn asset(&self, asset_id: &AssetId) -> Option<&AssetMetadata> {
        self.assets.get(asset_id)
    }

    pub fn registered_asset_ids(&self) -> Vec<AssetId> {
        self.assets.keys().copied().collect()
    }

    pub fn issuer_nonce(&self, issuer: &AccountId) -> u64 {
        self.issuer_nonces.get(issuer).copied().unwrap_or(0)
    }

    pub fn register<A: TransactionAuthenticator>(
        &mut self,
        registration: &AssetRegistration,
        inclusion_timestamp: u64,
        authenticator: &A,
    ) -> Result<AssetMetadata, AssetRegistryError> {
        self.verify_invariants()?;
        let mut next = self.clone();
        let metadata = next.register_inner(registration, inclusion_timestamp, authenticator)?;
        *self = next;
        Ok(metadata)
    }

    fn register_inner<A: TransactionAuthenticator>(
        &mut self,
        registration: &AssetRegistration,
        inclusion_timestamp: u64,
        authenticator: &A,
    ) -> Result<AssetMetadata, AssetRegistryError> {
        if registration.network_id != self.network_id {
            return Err(AssetRegistryError::WrongNetwork);
        }
        validate_registration_fields(registration)?;
        if inclusion_timestamp == 0 || registration.expires_at <= inclusion_timestamp {
            return Err(AssetRegistryError::Expired);
        }
        let expected = self
            .issuer_nonce(&registration.issuer)
            .checked_add(1)
            .ok_or(AssetRegistryError::ArithmeticOverflow)?;
        if registration.issuer_nonce != expected {
            return Err(AssetRegistryError::InvalidIssuerNonce {
                expected,
                actual: registration.issuer_nonce,
            });
        }
        if self.assets.len() >= self.max_assets {
            return Err(AssetRegistryError::TooManyAssets);
        }
        let asset_id = registration.asset_id();
        if self.assets.contains_key(&asset_id) {
            return Err(AssetRegistryError::AssetIdCollision);
        }
        let digest = registration.signing_digest()?;
        authenticator
            .verify(&registration.issuer, &digest, &registration.signature)
            .map_err(|_| AssetRegistryError::InvalidSignature)?;

        let metadata = AssetMetadata {
            asset_id,
            issuer: registration.issuer,
            registration_nonce: registration.issuer_nonce,
            name: registration.name.clone(),
            symbol: registration.symbol.clone(),
            decimals: registration.decimals,
            supply_policy: registration.supply_policy.clone(),
            initial_supply: registration.initial_supply,
            current_supply: registration.initial_supply,
            trust_policy: registration.trust_policy.clone(),
            transfers_enabled: true,
        };
        self.assets.insert(asset_id, metadata.clone());
        self.issuer_nonces
            .insert(registration.issuer, registration.issuer_nonce);
        self.verify_invariants()?;
        Ok(metadata)
    }

    pub fn apply_admin_operation<A: TransactionAuthenticator>(
        &mut self,
        operation: &SignedAssetAdminOperation,
        inclusion_timestamp: u64,
        authenticator: &A,
    ) -> Result<AssetAdminEffect, AssetRegistryError> {
        self.verify_invariants()?;
        let mut next = self.clone();
        let effect =
            next.apply_admin_operation_inner(operation, inclusion_timestamp, authenticator)?;
        *self = next;
        Ok(effect)
    }

    fn apply_admin_operation_inner<A: TransactionAuthenticator>(
        &mut self,
        operation: &SignedAssetAdminOperation,
        inclusion_timestamp: u64,
        authenticator: &A,
    ) -> Result<AssetAdminEffect, AssetRegistryError> {
        if operation.network_id != self.network_id {
            return Err(AssetRegistryError::WrongNetwork);
        }
        if inclusion_timestamp == 0 || operation.expires_at <= inclusion_timestamp {
            return Err(AssetRegistryError::Expired);
        }
        let expected = self
            .issuer_nonce(&operation.issuer)
            .checked_add(1)
            .ok_or(AssetRegistryError::ArithmeticOverflow)?;
        if operation.issuer_nonce != expected {
            return Err(AssetRegistryError::InvalidIssuerNonce {
                expected,
                actual: operation.issuer_nonce,
            });
        }
        let digest = operation.signing_digest()?;
        authenticator
            .verify(&operation.issuer, &digest, &operation.signature)
            .map_err(|_| AssetRegistryError::InvalidSignature)?;

        let minted = match &operation.action {
            AssetAdminAction::Mint {
                asset_id,
                recipient,
                amount,
            } => {
                let metadata = self
                    .assets
                    .get_mut(asset_id)
                    .ok_or(AssetRegistryError::AssetNotFound)?;
                if metadata.issuer != operation.issuer {
                    return Err(AssetRegistryError::NotIssuer);
                }
                let max_supply = match &metadata.supply_policy {
                    AssetSupplyPolicy::Fixed { .. } => {
                        return Err(AssetRegistryError::MintNotAllowed)
                    }
                    AssetSupplyPolicy::IssuerCapped { max_supply } => *max_supply,
                };
                let next_supply = metadata
                    .current_supply
                    .checked_add(*amount)
                    .ok_or(AssetRegistryError::ArithmeticOverflow)?;
                if next_supply > max_supply {
                    return Err(AssetRegistryError::SupplyCapExceeded);
                }
                metadata.current_supply = next_supply;
                Some((*asset_id, *recipient, *amount))
            }
            AssetAdminAction::SetTransfersEnabled { asset_id, enabled } => {
                let metadata = self
                    .assets
                    .get_mut(asset_id)
                    .ok_or(AssetRegistryError::AssetNotFound)?;
                if metadata.issuer != operation.issuer {
                    return Err(AssetRegistryError::NotIssuer);
                }
                metadata.transfers_enabled = *enabled;
                None
            }
        };
        self.issuer_nonces
            .insert(operation.issuer, operation.issuer_nonce);
        self.verify_invariants()?;
        Ok(AssetAdminEffect { minted })
    }

    pub fn verify_invariants(&self) -> Result<(), AssetRegistryError> {
        if is_zero(&self.network_id) || self.assets.len() > self.max_assets {
            return Err(AssetRegistryError::InvalidNetworkId);
        }
        for (asset_id, metadata) in &self.assets {
            if is_zero(asset_id)
                || *asset_id != metadata.asset_id
                || is_zero(&metadata.issuer)
                || metadata.registration_nonce == 0
                || self.issuer_nonce(&metadata.issuer) < metadata.registration_nonce
                || metadata.decimals > MAX_ASSET_DECIMALS
                || validate_name(&metadata.name).is_err()
                || validate_symbol(&metadata.symbol).is_err()
                || validate_supply_policy(&metadata.supply_policy, metadata.initial_supply).is_err()
                || metadata.current_supply < metadata.initial_supply
            {
                return Err(AssetRegistryError::InvalidSupplyPolicy);
            }
            match &metadata.supply_policy {
                AssetSupplyPolicy::Fixed { total_supply } => {
                    if metadata.current_supply != *total_supply {
                        return Err(AssetRegistryError::InvalidSupplyPolicy);
                    }
                }
                AssetSupplyPolicy::IssuerCapped { max_supply } => {
                    if metadata.current_supply > *max_supply {
                        return Err(AssetRegistryError::SupplyCapExceeded);
                    }
                }
            }
            validate_trust_policy(&metadata.trust_policy)?;
        }
        for (issuer, nonce) in &self.issuer_nonces {
            if is_zero(issuer) || *nonce == 0 {
                return Err(AssetRegistryError::InvalidIssuerNonce {
                    expected: 1,
                    actual: *nonce,
                });
            }
        }
        Ok(())
    }

    pub fn state_root(&self) -> Result<[u8; 32], AssetRegistryError> {
        self.verify_invariants()?;
        let mut hash = Sha256::new();
        hash.update(REGISTRY_ROOT_DOMAIN);
        hash.update(self.network_id);
        hash.update((self.max_assets as u64).to_be_bytes());
        hash.update((self.assets.len() as u64).to_be_bytes());
        for (asset_id, metadata) in &self.assets {
            hash.update(asset_id);
            hash.update(metadata.issuer);
            hash.update(metadata.registration_nonce.to_be_bytes());
            put_bytes(&mut hash, metadata.name.as_bytes());
            put_bytes(&mut hash, metadata.symbol.as_bytes());
            hash.update([metadata.decimals]);
            match &metadata.supply_policy {
                AssetSupplyPolicy::Fixed { total_supply } => {
                    hash.update([1]);
                    hash.update(total_supply.to_be_bytes());
                }
                AssetSupplyPolicy::IssuerCapped { max_supply } => {
                    hash.update([2]);
                    hash.update(max_supply.to_be_bytes());
                }
            }
            hash.update(metadata.initial_supply.to_be_bytes());
            hash.update(metadata.current_supply.to_be_bytes());
            hash_trust_policy(&mut hash, &metadata.trust_policy);
            hash.update([u8::from(metadata.transfers_enabled)]);
        }
        hash.update((self.issuer_nonces.len() as u64).to_be_bytes());
        for (issuer, nonce) in &self.issuer_nonces {
            hash.update(issuer);
            hash.update(nonce.to_be_bytes());
        }
        Ok(hash.finalize().into())
    }

    /// Encode the complete registry state in sorted, versioned and checksummed form.
    /// The checksum detects corruption only; external manifest anchoring remains responsible
    /// for freshness and anti-rollback.
    pub fn encode_snapshot(&self) -> Result<Vec<u8>, AssetRegistryError> {
        self.verify_invariants()?;
        let mut out = Vec::with_capacity(256);
        out.extend_from_slice(&REGISTRY_SNAPSHOT_MAGIC);
        out.extend_from_slice(&REGISTRY_SNAPSHOT_VERSION.to_be_bytes());
        out.extend_from_slice(&self.network_id);
        reg_snapshot_put_u32(&mut out, self.max_assets)?;
        reg_snapshot_put_u32(&mut out, self.assets.len())?;

        for (asset_id, metadata) in &self.assets {
            out.extend_from_slice(asset_id);
            out.extend_from_slice(&metadata.issuer);
            out.extend_from_slice(&metadata.registration_nonce.to_be_bytes());
            reg_snapshot_put_bytes(&mut out, metadata.name.as_bytes())?;
            reg_snapshot_put_bytes(&mut out, metadata.symbol.as_bytes())?;
            out.push(metadata.decimals);
            match &metadata.supply_policy {
                AssetSupplyPolicy::Fixed { total_supply } => {
                    out.push(1);
                    out.extend_from_slice(&total_supply.to_be_bytes());
                }
                AssetSupplyPolicy::IssuerCapped { max_supply } => {
                    out.push(2);
                    out.extend_from_slice(&max_supply.to_be_bytes());
                }
            }
            out.extend_from_slice(&metadata.initial_supply.to_be_bytes());
            out.extend_from_slice(&metadata.current_supply.to_be_bytes());
            match &metadata.trust_policy {
                AssetTrustPolicy::Unverified => out.push(0),
                AssetTrustPolicy::IssuerAttested { evidence_hash } => {
                    out.push(1);
                    out.extend_from_slice(evidence_hash);
                }
                AssetTrustPolicy::CustodianAttested {
                    custodian,
                    evidence_hash,
                } => {
                    out.push(2);
                    out.extend_from_slice(custodian);
                    out.extend_from_slice(evidence_hash);
                }
                AssetTrustPolicy::BridgeAttested {
                    bridge_id,
                    evidence_hash,
                } => {
                    out.push(3);
                    out.extend_from_slice(bridge_id);
                    out.extend_from_slice(evidence_hash);
                }
            }
            out.push(u8::from(metadata.transfers_enabled));
            if out.len().saturating_add(32) > MAX_QRUN_V06_REGISTRY_SNAPSHOT_BYTES {
                return Err(AssetRegistryError::SnapshotOversize);
            }
        }

        reg_snapshot_put_u32(&mut out, self.issuer_nonces.len())?;
        for (issuer, nonce) in &self.issuer_nonces {
            out.extend_from_slice(issuer);
            out.extend_from_slice(&nonce.to_be_bytes());
        }
        if out.len().saturating_add(32) > MAX_QRUN_V06_REGISTRY_SNAPSHOT_BYTES {
            return Err(AssetRegistryError::SnapshotOversize);
        }
        let mut checksum = Sha256::new();
        checksum.update(REGISTRY_SNAPSHOT_CHECKSUM_DOMAIN);
        checksum.update(&out);
        out.extend_from_slice(&checksum.finalize());
        Ok(out)
    }

    /// Decode only strictly ordered canonical maps, then rerun all registry invariants.
    pub fn decode_snapshot(
        bytes: &[u8],
        expected_network_id: &NetworkId,
    ) -> Result<Self, AssetRegistryError> {
        if bytes.len() > MAX_QRUN_V06_REGISTRY_SNAPSHOT_BYTES {
            return Err(AssetRegistryError::SnapshotOversize);
        }
        if expected_network_id.iter().all(|byte| *byte == 0)
            || bytes.len() < 4 + 2 + 32 + 4 + 4 + 4 + 32
        {
            return Err(AssetRegistryError::SnapshotMalformed);
        }
        let body_len = bytes.len() - 32;
        let mut checksum = Sha256::new();
        checksum.update(REGISTRY_SNAPSHOT_CHECKSUM_DOMAIN);
        checksum.update(&bytes[..body_len]);
        if checksum.finalize().as_slice() != &bytes[body_len..] {
            return Err(AssetRegistryError::SnapshotChecksumMismatch);
        }

        let body = &bytes[..body_len];
        let mut cursor = 0usize;
        if reg_snapshot_take::<4>(body, &mut cursor)? != REGISTRY_SNAPSHOT_MAGIC {
            return Err(AssetRegistryError::SnapshotMalformed);
        }
        if reg_snapshot_u16(body, &mut cursor)? != REGISTRY_SNAPSHOT_VERSION {
            return Err(AssetRegistryError::SnapshotMalformed);
        }
        let network_id: NetworkId = reg_snapshot_take(body, &mut cursor)?
            .try_into()
            .map_err(|_| AssetRegistryError::SnapshotMalformed)?;
        if network_id != *expected_network_id {
            return Err(AssetRegistryError::WrongNetwork);
        }
        let max_assets = reg_snapshot_u32(body, &mut cursor)? as usize;
        let asset_count = reg_snapshot_u32(body, &mut cursor)? as usize;
        if max_assets == 0
            || max_assets > MAX_REGISTRY_SNAPSHOT_ENTRIES
            || asset_count > max_assets
            || asset_count > MAX_REGISTRY_SNAPSHOT_ENTRIES
        {
            return Err(AssetRegistryError::SnapshotMalformed);
        }

        let mut assets = BTreeMap::new();
        let mut previous_asset: Option<AssetId> = None;
        for _ in 0..asset_count {
            let asset_id: AssetId = reg_snapshot_take(body, &mut cursor)?
                .try_into()
                .map_err(|_| AssetRegistryError::SnapshotMalformed)?;
            if previous_asset.is_some_and(|previous| previous >= asset_id) {
                return Err(AssetRegistryError::SnapshotNonCanonical);
            }
            previous_asset = Some(asset_id);
            let issuer: AccountId = reg_snapshot_take(body, &mut cursor)?
                .try_into()
                .map_err(|_| AssetRegistryError::SnapshotMalformed)?;
            let registration_nonce = reg_snapshot_u64(body, &mut cursor)?;
            let name =
                String::from_utf8(reg_snapshot_bytes(body, &mut cursor, MAX_ASSET_NAME_BYTES)?)
                    .map_err(|_| AssetRegistryError::SnapshotMalformed)?;
            let symbol = String::from_utf8(reg_snapshot_bytes(
                body,
                &mut cursor,
                MAX_ASSET_SYMBOL_BYTES,
            )?)
            .map_err(|_| AssetRegistryError::SnapshotMalformed)?;
            let decimals = reg_snapshot_u8(body, &mut cursor)?;
            let supply_policy = match reg_snapshot_u8(body, &mut cursor)? {
                1 => AssetSupplyPolicy::Fixed {
                    total_supply: reg_snapshot_u128(body, &mut cursor)?,
                },
                2 => AssetSupplyPolicy::IssuerCapped {
                    max_supply: reg_snapshot_u128(body, &mut cursor)?,
                },
                _ => return Err(AssetRegistryError::SnapshotMalformed),
            };
            let initial_supply = reg_snapshot_u128(body, &mut cursor)?;
            let current_supply = reg_snapshot_u128(body, &mut cursor)?;
            let trust_policy = match reg_snapshot_u8(body, &mut cursor)? {
                0 => AssetTrustPolicy::Unverified,
                1 => AssetTrustPolicy::IssuerAttested {
                    evidence_hash: reg_snapshot_take(body, &mut cursor)?
                        .try_into()
                        .map_err(|_| AssetRegistryError::SnapshotMalformed)?,
                },
                2 => AssetTrustPolicy::CustodianAttested {
                    custodian: reg_snapshot_take(body, &mut cursor)?
                        .try_into()
                        .map_err(|_| AssetRegistryError::SnapshotMalformed)?,
                    evidence_hash: reg_snapshot_take(body, &mut cursor)?
                        .try_into()
                        .map_err(|_| AssetRegistryError::SnapshotMalformed)?,
                },
                3 => AssetTrustPolicy::BridgeAttested {
                    bridge_id: reg_snapshot_take(body, &mut cursor)?
                        .try_into()
                        .map_err(|_| AssetRegistryError::SnapshotMalformed)?,
                    evidence_hash: reg_snapshot_take(body, &mut cursor)?
                        .try_into()
                        .map_err(|_| AssetRegistryError::SnapshotMalformed)?,
                },
                _ => return Err(AssetRegistryError::SnapshotMalformed),
            };
            let transfers_enabled = match reg_snapshot_u8(body, &mut cursor)? {
                0 => false,
                1 => true,
                _ => return Err(AssetRegistryError::SnapshotNonCanonical),
            };
            let metadata = AssetMetadata {
                asset_id,
                issuer,
                registration_nonce,
                name,
                symbol,
                decimals,
                supply_policy,
                initial_supply,
                current_supply,
                trust_policy,
                transfers_enabled,
            };
            if assets.insert(asset_id, metadata).is_some() {
                return Err(AssetRegistryError::SnapshotNonCanonical);
            }
        }

        let nonce_count = reg_snapshot_u32(body, &mut cursor)? as usize;
        if nonce_count > MAX_REGISTRY_SNAPSHOT_ENTRIES || nonce_count > max_assets {
            return Err(AssetRegistryError::SnapshotMalformed);
        }
        let mut issuer_nonces = BTreeMap::new();
        let mut previous_issuer: Option<AccountId> = None;
        for _ in 0..nonce_count {
            let issuer: AccountId = reg_snapshot_take(body, &mut cursor)?
                .try_into()
                .map_err(|_| AssetRegistryError::SnapshotMalformed)?;
            if previous_issuer.is_some_and(|previous| previous >= issuer) {
                return Err(AssetRegistryError::SnapshotNonCanonical);
            }
            previous_issuer = Some(issuer);
            let nonce = reg_snapshot_u64(body, &mut cursor)?;
            issuer_nonces.insert(issuer, nonce);
        }
        if cursor != body.len() {
            return Err(AssetRegistryError::SnapshotNonCanonical);
        }
        let restored = Self {
            network_id,
            assets,
            issuer_nonces,
            max_assets,
        };
        restored.verify_invariants()?;
        if restored.encode_snapshot()?.as_slice() != bytes {
            return Err(AssetRegistryError::SnapshotNonCanonical);
        }
        Ok(restored)
    }

    pub fn transfers_enabled(&self, asset_id: &AssetId) -> Result<bool, AssetRegistryError> {
        self.assets
            .get(asset_id)
            .map(|metadata| metadata.transfers_enabled)
            .ok_or(AssetRegistryError::AssetNotFound)
    }

    pub fn current_supply(&self, asset_id: &AssetId) -> Result<u128, AssetRegistryError> {
        self.assets
            .get(asset_id)
            .map(|metadata| metadata.current_supply)
            .ok_or(AssetRegistryError::AssetNotFound)
    }
}

fn validate_registration_fields(
    registration: &AssetRegistration,
) -> Result<(), AssetRegistryError> {
    if is_zero(&registration.network_id) {
        return Err(AssetRegistryError::InvalidNetworkId);
    }
    if is_zero(&registration.issuer) {
        return Err(AssetRegistryError::InvalidIssuer);
    }
    if registration.issuer_nonce == 0 {
        return Err(AssetRegistryError::InvalidIssuerNonce {
            expected: 1,
            actual: 0,
        });
    }
    if is_zero(&registration.salt) {
        return Err(AssetRegistryError::InvalidSalt);
    }
    if is_zero(&registration.initial_recipient) {
        return Err(AssetRegistryError::InvalidRecipient);
    }
    validate_name(&registration.name)?;
    validate_symbol(&registration.symbol)?;
    if registration.decimals > MAX_ASSET_DECIMALS {
        return Err(AssetRegistryError::InvalidDecimals);
    }
    validate_supply_policy(&registration.supply_policy, registration.initial_supply)?;
    validate_trust_policy(&registration.trust_policy)?;
    if registration.expires_at == 0 {
        return Err(AssetRegistryError::Expired);
    }
    if registration.signature.len() > MAX_ASSET_SIGNATURE_BYTES {
        return Err(AssetRegistryError::SignatureOversize);
    }
    Ok(())
}

fn validate_name(name: &str) -> Result<(), AssetRegistryError> {
    if name.is_empty()
        || name.len() > MAX_ASSET_NAME_BYTES
        || name.trim() != name
        || name.chars().any(char::is_control)
    {
        return Err(AssetRegistryError::InvalidName);
    }
    Ok(())
}

fn validate_symbol(symbol: &str) -> Result<(), AssetRegistryError> {
    if symbol.is_empty()
        || symbol.len() > MAX_ASSET_SYMBOL_BYTES
        || !symbol.bytes().all(|byte| {
            byte.is_ascii_uppercase() || byte.is_ascii_digit() || b"._-".contains(&byte)
        })
    {
        return Err(AssetRegistryError::InvalidSymbol);
    }
    Ok(())
}

fn validate_supply_policy(
    policy: &AssetSupplyPolicy,
    initial_supply: u128,
) -> Result<(), AssetRegistryError> {
    match policy {
        AssetSupplyPolicy::Fixed { total_supply } => {
            if *total_supply == 0 || initial_supply != *total_supply {
                return Err(AssetRegistryError::InvalidInitialSupply);
            }
        }
        AssetSupplyPolicy::IssuerCapped { max_supply } => {
            if *max_supply == 0 || initial_supply > *max_supply {
                return Err(AssetRegistryError::InvalidInitialSupply);
            }
        }
    }
    Ok(())
}

fn validate_trust_policy(policy: &AssetTrustPolicy) -> Result<(), AssetRegistryError> {
    match policy {
        AssetTrustPolicy::Unverified => {}
        AssetTrustPolicy::IssuerAttested { evidence_hash } => {
            if is_zero(evidence_hash) {
                return Err(AssetRegistryError::InvalidTrustEvidence);
            }
        }
        AssetTrustPolicy::CustodianAttested {
            custodian,
            evidence_hash,
        } => {
            if is_zero(custodian) || is_zero(evidence_hash) {
                return Err(AssetRegistryError::InvalidTrustEvidence);
            }
        }
        AssetTrustPolicy::BridgeAttested {
            bridge_id,
            evidence_hash,
        } => {
            if is_zero(bridge_id) || is_zero(evidence_hash) {
                return Err(AssetRegistryError::InvalidTrustEvidence);
            }
        }
    }
    Ok(())
}

fn hash_trust_policy(hash: &mut Sha256, policy: &AssetTrustPolicy) {
    match policy {
        AssetTrustPolicy::Unverified => hash.update([0]),
        AssetTrustPolicy::IssuerAttested { evidence_hash } => {
            hash.update([1]);
            hash.update(evidence_hash);
        }
        AssetTrustPolicy::CustodianAttested {
            custodian,
            evidence_hash,
        } => {
            hash.update([2]);
            hash.update(custodian);
            hash.update(evidence_hash);
        }
        AssetTrustPolicy::BridgeAttested {
            bridge_id,
            evidence_hash,
        } => {
            hash.update([3]);
            hash.update(bridge_id);
            hash.update(evidence_hash);
        }
    }
}

fn put_bytes(hash: &mut Sha256, bytes: &[u8]) {
    hash.update((bytes.len() as u16).to_be_bytes());
    hash.update(bytes);
}

fn is_zero(bytes: &[u8; 32]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}

fn reg_snapshot_put_u32(out: &mut Vec<u8>, value: usize) -> Result<(), AssetRegistryError> {
    let value = u32::try_from(value).map_err(|_| AssetRegistryError::SnapshotOversize)?;
    out.extend_from_slice(&value.to_be_bytes());
    Ok(())
}

fn reg_snapshot_put_bytes(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), AssetRegistryError> {
    let length = u16::try_from(bytes.len()).map_err(|_| AssetRegistryError::SnapshotOversize)?;
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

fn reg_snapshot_take<const N: usize>(
    bytes: &[u8],
    cursor: &mut usize,
) -> Result<[u8; N], AssetRegistryError> {
    let end = cursor
        .checked_add(N)
        .ok_or(AssetRegistryError::SnapshotMalformed)?;
    let value = bytes
        .get(*cursor..end)
        .ok_or(AssetRegistryError::SnapshotMalformed)?
        .try_into()
        .map_err(|_| AssetRegistryError::SnapshotMalformed)?;
    *cursor = end;
    Ok(value)
}

fn reg_snapshot_bytes(
    bytes: &[u8],
    cursor: &mut usize,
    limit: usize,
) -> Result<Vec<u8>, AssetRegistryError> {
    let length = reg_snapshot_u16(bytes, cursor)? as usize;
    if length == 0 || length > limit {
        return Err(AssetRegistryError::SnapshotMalformed);
    }
    let end = cursor
        .checked_add(length)
        .ok_or(AssetRegistryError::SnapshotMalformed)?;
    let value = bytes
        .get(*cursor..end)
        .ok_or(AssetRegistryError::SnapshotMalformed)?
        .to_vec();
    *cursor = end;
    Ok(value)
}

fn reg_snapshot_u8(bytes: &[u8], cursor: &mut usize) -> Result<u8, AssetRegistryError> {
    Ok(reg_snapshot_take::<1>(bytes, cursor)?[0])
}
fn reg_snapshot_u16(bytes: &[u8], cursor: &mut usize) -> Result<u16, AssetRegistryError> {
    Ok(u16::from_be_bytes(reg_snapshot_take::<2>(bytes, cursor)?))
}
fn reg_snapshot_u32(bytes: &[u8], cursor: &mut usize) -> Result<u32, AssetRegistryError> {
    Ok(u32::from_be_bytes(reg_snapshot_take::<4>(bytes, cursor)?))
}
fn reg_snapshot_u64(bytes: &[u8], cursor: &mut usize) -> Result<u64, AssetRegistryError> {
    Ok(u64::from_be_bytes(reg_snapshot_take::<8>(bytes, cursor)?))
}
fn reg_snapshot_u128(bytes: &[u8], cursor: &mut usize) -> Result<u128, AssetRegistryError> {
    Ok(u128::from_be_bytes(reg_snapshot_take::<16>(bytes, cursor)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    const NETWORK: NetworkId = [0xA6; 32];
    const ISSUER: AccountId = [0xA1; 32];
    const RECIPIENT: AccountId = [0xA2; 32];

    struct DigestAuthenticator;
    impl TransactionAuthenticator for DigestAuthenticator {
        fn verify(
            &self,
            sender: &AccountId,
            digest: &[u8; 32],
            signature: &[u8],
        ) -> Result<(), ()> {
            if !is_zero(sender) && signature == digest {
                Ok(())
            } else {
                Err(())
            }
        }
    }

    fn registration(
        nonce: u64,
        policy: AssetSupplyPolicy,
        initial_supply: u128,
    ) -> AssetRegistration {
        let mut value = AssetRegistration {
            network_id: NETWORK,
            issuer: ISSUER,
            issuer_nonce: nonce,
            salt: [nonce as u8 + 10; 32],
            name: "QRun Utility Credit".to_string(),
            symbol: "QUC".to_string(),
            decimals: 6,
            supply_policy: policy,
            initial_supply,
            initial_recipient: RECIPIENT,
            trust_policy: AssetTrustPolicy::Unverified,
            expires_at: 10_000,
            signature: Vec::new(),
        };
        value.signature = value.signing_digest().unwrap().to_vec();
        value
    }

    fn admin(nonce: u64, action: AssetAdminAction) -> SignedAssetAdminOperation {
        let mut value = SignedAssetAdminOperation {
            network_id: NETWORK,
            issuer: ISSUER,
            issuer_nonce: nonce,
            expires_at: 10_000,
            action,
            signature: Vec::new(),
        };
        value.signature = value.signing_digest().unwrap().to_vec();
        value
    }

    #[test]
    fn registration_derives_network_bound_id_and_commits_metadata() {
        let mut registry =
            QRunV06AssetRegistryCandidate::new(NETWORK, DEFAULT_MAX_REGISTERED_ASSETS).unwrap();
        let item = registration(
            1,
            AssetSupplyPolicy::IssuerCapped { max_supply: 50_000 },
            10_000,
        );
        let metadata = registry.register(&item, 100, &DigestAuthenticator).unwrap();
        assert_eq!(metadata.asset_id, item.asset_id());
        assert_eq!(metadata.current_supply, 10_000);
        assert!(metadata.transfers_enabled);
        assert_eq!(registry.issuer_nonce(&ISSUER), 1);
        registry.verify_invariants().unwrap();
    }

    #[test]
    fn wrong_network_bad_signature_and_replay_are_rejected_atomically() {
        let mut registry =
            QRunV06AssetRegistryCandidate::new(NETWORK, DEFAULT_MAX_REGISTERED_ASSETS).unwrap();
        let before = registry.state_root().unwrap();
        let mut wrong_network =
            registration(1, AssetSupplyPolicy::IssuerCapped { max_supply: 10 }, 0);
        wrong_network.network_id = [0xB6; 32];
        wrong_network.signature = wrong_network.signing_digest().unwrap().to_vec();
        assert_eq!(
            registry.register(&wrong_network, 100, &DigestAuthenticator),
            Err(AssetRegistryError::WrongNetwork)
        );
        let mut bad_signature =
            registration(1, AssetSupplyPolicy::IssuerCapped { max_supply: 10 }, 0);
        bad_signature.signature[0] ^= 1;
        assert_eq!(
            registry.register(&bad_signature, 100, &DigestAuthenticator),
            Err(AssetRegistryError::InvalidSignature)
        );
        let valid = registration(1, AssetSupplyPolicy::IssuerCapped { max_supply: 10 }, 0);
        registry
            .register(&valid, 100, &DigestAuthenticator)
            .unwrap();
        assert_eq!(
            registry.register(&valid, 100, &DigestAuthenticator),
            Err(AssetRegistryError::InvalidIssuerNonce {
                expected: 2,
                actual: 1
            })
        );
        assert_ne!(registry.state_root().unwrap(), before);
    }

    #[test]
    fn fixed_supply_must_be_fully_issued_and_cannot_be_minted_later() {
        let mut registry =
            QRunV06AssetRegistryCandidate::new(NETWORK, DEFAULT_MAX_REGISTERED_ASSETS).unwrap();
        let fixed = registration(1, AssetSupplyPolicy::Fixed { total_supply: 900 }, 900);
        let metadata = registry
            .register(&fixed, 100, &DigestAuthenticator)
            .unwrap();
        let mint = admin(
            2,
            AssetAdminAction::Mint {
                asset_id: metadata.asset_id,
                recipient: RECIPIENT,
                amount: 1,
            },
        );
        assert_eq!(
            registry.apply_admin_operation(&mint, 101, &DigestAuthenticator),
            Err(AssetRegistryError::MintNotAllowed)
        );
        assert_eq!(registry.issuer_nonce(&ISSUER), 1);
        assert_eq!(registry.current_supply(&metadata.asset_id), Ok(900));
    }

    #[test]
    fn capped_supply_mint_is_issuer_authorized_and_cap_checked() {
        let mut registry =
            QRunV06AssetRegistryCandidate::new(NETWORK, DEFAULT_MAX_REGISTERED_ASSETS).unwrap();
        let item = registration(
            1,
            AssetSupplyPolicy::IssuerCapped { max_supply: 1_000 },
            900,
        );
        let metadata = registry.register(&item, 100, &DigestAuthenticator).unwrap();
        let mint = admin(
            2,
            AssetAdminAction::Mint {
                asset_id: metadata.asset_id,
                recipient: RECIPIENT,
                amount: 100,
            },
        );
        assert_eq!(
            registry
                .apply_admin_operation(&mint, 101, &DigestAuthenticator)
                .unwrap()
                .minted,
            Some((metadata.asset_id, RECIPIENT, 100))
        );
        assert_eq!(registry.current_supply(&metadata.asset_id), Ok(1_000));
        let over_cap = admin(
            3,
            AssetAdminAction::Mint {
                asset_id: metadata.asset_id,
                recipient: RECIPIENT,
                amount: 1,
            },
        );
        assert_eq!(
            registry.apply_admin_operation(&over_cap, 102, &DigestAuthenticator),
            Err(AssetRegistryError::SupplyCapExceeded)
        );
        assert_eq!(registry.issuer_nonce(&ISSUER), 2);
    }

    #[test]
    fn only_issuer_can_change_transfer_policy_and_replay_is_rejected() {
        let mut registry =
            QRunV06AssetRegistryCandidate::new(NETWORK, DEFAULT_MAX_REGISTERED_ASSETS).unwrap();
        let item = registration(1, AssetSupplyPolicy::IssuerCapped { max_supply: 1_000 }, 0);
        let metadata = registry.register(&item, 100, &DigestAuthenticator).unwrap();
        let freeze = admin(
            2,
            AssetAdminAction::SetTransfersEnabled {
                asset_id: metadata.asset_id,
                enabled: false,
            },
        );
        registry
            .apply_admin_operation(&freeze, 101, &DigestAuthenticator)
            .unwrap();
        assert!(!registry.transfers_enabled(&metadata.asset_id).unwrap());
        assert_eq!(
            registry.apply_admin_operation(&freeze, 101, &DigestAuthenticator),
            Err(AssetRegistryError::InvalidIssuerNonce {
                expected: 3,
                actual: 2
            })
        );
        assert_eq!(registry.issuer_nonce(&ISSUER), 2);
    }

    #[test]
    fn registry_snapshot_roundtrips_metadata_issuer_nonces_and_trust_policy() {
        let mut registry =
            QRunV06AssetRegistryCandidate::new(NETWORK, DEFAULT_MAX_REGISTERED_ASSETS).unwrap();
        let mut item = registration(
            1,
            AssetSupplyPolicy::IssuerCapped { max_supply: 50_000 },
            10_000,
        );
        item.trust_policy = AssetTrustPolicy::CustodianAttested {
            custodian: [0xA3; 32],
            evidence_hash: [0xA4; 32],
        };
        item.signature = item.signing_digest().unwrap().to_vec();
        let metadata = registry.register(&item, 100, &DigestAuthenticator).unwrap();
        let freeze = admin(
            2,
            AssetAdminAction::SetTransfersEnabled {
                asset_id: metadata.asset_id,
                enabled: false,
            },
        );
        registry
            .apply_admin_operation(&freeze, 101, &DigestAuthenticator)
            .unwrap();

        let root = registry.state_root().unwrap();
        let encoded = registry.encode_snapshot().unwrap();
        let restored = QRunV06AssetRegistryCandidate::decode_snapshot(&encoded, &NETWORK).unwrap();
        assert_eq!(restored, registry);
        assert_eq!(restored.state_root().unwrap(), root);
        assert_eq!(restored.issuer_nonce(&ISSUER), 2);
        assert!(!restored.transfers_enabled(&metadata.asset_id).unwrap());

        let mut corrupt = encoded.clone();
        let corrupt_index = corrupt.len() / 2;
        corrupt[corrupt_index] ^= 1;
        assert_eq!(
            QRunV06AssetRegistryCandidate::decode_snapshot(&corrupt, &NETWORK),
            Err(AssetRegistryError::SnapshotChecksumMismatch)
        );
        assert_eq!(
            QRunV06AssetRegistryCandidate::decode_snapshot(&encoded, &[0xB6; 32]),
            Err(AssetRegistryError::WrongNetwork)
        );
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert_eq!(
            QRunV06AssetRegistryCandidate::decode_snapshot(&trailing, &NETWORK),
            Err(AssetRegistryError::SnapshotChecksumMismatch)
        );
    }

    #[test]
    fn rejects_bad_decimals_symbol_and_missing_trust_evidence() {
        let mut registry =
            QRunV06AssetRegistryCandidate::new(NETWORK, DEFAULT_MAX_REGISTERED_ASSETS).unwrap();
        let mut bad_decimals =
            registration(1, AssetSupplyPolicy::IssuerCapped { max_supply: 10 }, 0);
        bad_decimals.decimals = 19;
        bad_decimals.signature = Vec::new();
        assert_eq!(
            registry.register(&bad_decimals, 100, &DigestAuthenticator),
            Err(AssetRegistryError::InvalidDecimals)
        );
        let mut bad_symbol = registration(1, AssetSupplyPolicy::IssuerCapped { max_supply: 10 }, 0);
        bad_symbol.symbol = "bad symbol".to_string();
        assert_eq!(
            bad_symbol.signing_digest(),
            Err(AssetRegistryError::InvalidSymbol)
        );
        let mut bad_trust = registration(1, AssetSupplyPolicy::IssuerCapped { max_supply: 10 }, 0);
        bad_trust.trust_policy = AssetTrustPolicy::IssuerAttested {
            evidence_hash: [0; 32],
        };
        assert_eq!(
            bad_trust.signing_digest(),
            Err(AssetRegistryError::InvalidTrustEvidence)
        );
    }
}
