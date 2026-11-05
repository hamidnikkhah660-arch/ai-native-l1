//! Independently pinned external quote-asset qualification bundle candidate.
//!
//! Signed evidence/decision envelope, not proof that reserves exist or remain redeemable.
//! Expected commitment and authority identity must come from a separately provisioned source.
use crate::state_machine::TransactionAuthenticator;
use sha2::{Digest, Sha256};
use std::io::{Cursor, Read};

const MAGIC: [u8; 4] = *b"Q6QA";
const VERSION: u16 = 1;
const RESERVED: u16 = 0;
const SIGN_DOMAIN: &[u8] = b"QRUN-V06-EXTERNAL-QUOTE-ASSET-QUALIFICATION-V1\0";
const COMMITMENT_DOMAIN: &[u8] = b"QRUN-V06-EXTERNAL-QUOTE-ASSET-QUALIFICATION-COMMITMENT-V1\0";
pub const Q6QA_CONTRACT_ADDRESS_BYTES: usize = 64;
pub const Q6QA_SYMBOL_BYTES: usize = 16;
pub const Q6QA_REPRESENTATION_BYTES: usize = 64;
pub const Q6QA_MAX_SIGNATURE_BYTES: usize = 4 * 1024;
pub const Q6QA_FIXED_BYTES: usize = 8 + 32 * 12 + 8 * 3 + 7 + 64 + 16 + 64 + 2;
pub const Q6QA_MAX_BYTES: usize = Q6QA_FIXED_BYTES + Q6QA_MAX_SIGNATURE_BYTES;

pub type AssetId = [u8; 32];
pub type AccountId = [u8; 32];
pub type NetworkId = [u8; 32];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CustodyModel {
    IssuerControlled = 1,
    IndependentCustodian = 2,
    BridgeEscrow = 3,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RedemptionModel {
    DirectIssuerRedemption = 1,
    CustodianRedemption = 2,
    BridgeBurnAndRelease = 3,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum QualificationStatus {
    Approved = 1,
    Revoked = 2,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Q6QaError {
    Malformed,
    UnsupportedVersion(u16),
    NonZeroReserved,
    Oversize,
    InvalidNetwork,
    InvalidProfile,
    InvalidAsset,
    InvalidExternalChain,
    InvalidIssuer,
    InvalidCustodian,
    InvalidEvidence,
    InvalidAuthority,
    InvalidEpoch,
    InvalidValidityWindow,
    Expired,
    NotYetValid,
    Revoked,
    InvalidDecimals,
    InvalidContractAddress,
    InvalidSymbol,
    InvalidRepresentation,
    InvalidSignature,
    MissingIndependentCommitment,
    CommitmentMismatch,
    WrongNetwork,
    WrongProfile,
    WrongAsset,
    WrongAuthorityKey,
    WrongAuthorityAccount,
    WrongQualificationEpoch,
    AuthorizationHeightMismatch,
}
impl std::fmt::Display for Q6QaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for Q6QaError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QRunV06QuoteAssetQualificationCandidate {
    pub network_id: NetworkId,
    pub profile_id: [u8; 32],
    pub asset_id: AssetId,
    /// Domain-separated fingerprint of the exact external chain namespace/identity.
    pub external_chain_id: [u8; 32],
    pub issuer_id: [u8; 32],
    pub custodian_id: [u8; 32],
    pub bridge_id: [u8; 32],
    /// Evidence fingerprints only; they do not prove current reserves or redemption.
    pub reserve_evidence_digest: [u8; 32],
    pub redemption_evidence_digest: [u8; 32],
    pub control_risk_evidence_digest: [u8; 32],
    pub authority_key_id: [u8; 32],
    pub authority_account: AccountId,
    pub qualification_epoch: u64,
    pub valid_from_height: u64,
    /// Exclusive upper bound.
    pub valid_until_height: u64,
    pub decimals: u8,
    pub custody_model: CustodyModel,
    pub redemption_model: RedemptionModel,
    pub status: QualificationStatus,
    pub contract_address: Vec<u8>,
    pub symbol: String,
    /// Exact chain-specific representation label, not just a ticker.
    pub representation: String,
}
impl QRunV06QuoteAssetQualificationCandidate {
    pub fn signing_digest(&self) -> Result<[u8; 32], Q6QaError> {
        validate_record(self)?;
        let mut h = Sha256::new();
        h.update(SIGN_DOMAIN);
        h.update(self.network_id);
        h.update(self.profile_id);
        h.update(self.asset_id);
        h.update(self.external_chain_id);
        h.update(self.issuer_id);
        h.update(self.custodian_id);
        h.update(self.bridge_id);
        h.update(self.reserve_evidence_digest);
        h.update(self.redemption_evidence_digest);
        h.update(self.control_risk_evidence_digest);
        h.update(self.authority_key_id);
        h.update(self.authority_account);
        h.update(self.qualification_epoch.to_be_bytes());
        h.update(self.valid_from_height.to_be_bytes());
        h.update(self.valid_until_height.to_be_bytes());
        h.update([
            self.decimals,
            self.custody_model as u8,
            self.redemption_model as u8,
            self.status as u8,
        ]);
        h.update((self.contract_address.len() as u16).to_be_bytes());
        h.update(&self.contract_address);
        h.update([self.symbol.len() as u8]);
        h.update(self.symbol.as_bytes());
        h.update([self.representation.len() as u8]);
        h.update(self.representation.as_bytes());
        Ok(h.finalize().into())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QRunV06SignedQuoteAssetQualificationCandidate {
    pub record: QRunV06QuoteAssetQualificationCandidate,
    pub signature: Vec<u8>,
}
impl QRunV06SignedQuoteAssetQualificationCandidate {
    pub fn encode(&self) -> Result<Vec<u8>, Q6QaError> {
        let _ = self.record.signing_digest()?;
        if self.signature.is_empty() || self.signature.len() > Q6QA_MAX_SIGNATURE_BYTES {
            return Err(Q6QaError::Oversize);
        }
        let r = &self.record;
        let mut out = Vec::with_capacity(Q6QA_FIXED_BYTES + self.signature.len());
        out.extend_from_slice(&MAGIC);
        out.extend_from_slice(&VERSION.to_be_bytes());
        out.extend_from_slice(&RESERVED.to_be_bytes());
        for field in [
            &r.network_id,
            &r.profile_id,
            &r.asset_id,
            &r.external_chain_id,
            &r.issuer_id,
            &r.custodian_id,
            &r.bridge_id,
            &r.reserve_evidence_digest,
            &r.redemption_evidence_digest,
            &r.control_risk_evidence_digest,
            &r.authority_key_id,
            &r.authority_account,
        ] {
            out.extend_from_slice(field);
        }
        out.extend_from_slice(&r.qualification_epoch.to_be_bytes());
        out.extend_from_slice(&r.valid_from_height.to_be_bytes());
        out.extend_from_slice(&r.valid_until_height.to_be_bytes());
        out.extend_from_slice(&[
            r.decimals,
            r.custody_model as u8,
            r.redemption_model as u8,
            r.status as u8,
            r.contract_address.len() as u8,
        ]);
        put_padded(&mut out, &r.contract_address, Q6QA_CONTRACT_ADDRESS_BYTES);
        out.push(r.symbol.len() as u8);
        put_padded(&mut out, r.symbol.as_bytes(), Q6QA_SYMBOL_BYTES);
        out.push(r.representation.len() as u8);
        put_padded(
            &mut out,
            r.representation.as_bytes(),
            Q6QA_REPRESENTATION_BYTES,
        );
        out.extend_from_slice(&(self.signature.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.signature);
        if out.len() > Q6QA_MAX_BYTES {
            return Err(Q6QaError::Oversize);
        }
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, Q6QaError> {
        if bytes.len() > Q6QA_MAX_BYTES || bytes.len() < Q6QA_FIXED_BYTES {
            return Err(if bytes.len() > Q6QA_MAX_BYTES {
                Q6QaError::Oversize
            } else {
                Q6QaError::Malformed
            });
        }
        let mut c = Cursor::new(bytes);
        if take::<4>(&mut c)? != MAGIC {
            return Err(Q6QaError::Malformed);
        }
        let version = take_u16(&mut c)?;
        if version != VERSION {
            return Err(Q6QaError::UnsupportedVersion(version));
        }
        if take_u16(&mut c)? != RESERVED {
            return Err(Q6QaError::NonZeroReserved);
        }
        let network_id = take::<32>(&mut c)?;
        let profile_id = take::<32>(&mut c)?;
        let asset_id = take::<32>(&mut c)?;
        let external_chain_id = take::<32>(&mut c)?;
        let issuer_id = take::<32>(&mut c)?;
        let custodian_id = take::<32>(&mut c)?;
        let bridge_id = take::<32>(&mut c)?;
        let reserve_evidence_digest = take::<32>(&mut c)?;
        let redemption_evidence_digest = take::<32>(&mut c)?;
        let control_risk_evidence_digest = take::<32>(&mut c)?;
        let authority_key_id = take::<32>(&mut c)?;
        let authority_account = take::<32>(&mut c)?;
        let qualification_epoch = take_u64(&mut c)?;
        let valid_from_height = take_u64(&mut c)?;
        let valid_until_height = take_u64(&mut c)?;
        let decimals = take_u8(&mut c)?;
        let custody_model = match take_u8(&mut c)? {
            1 => CustodyModel::IssuerControlled,
            2 => CustodyModel::IndependentCustodian,
            3 => CustodyModel::BridgeEscrow,
            _ => return Err(Q6QaError::Malformed),
        };
        let redemption_model = match take_u8(&mut c)? {
            1 => RedemptionModel::DirectIssuerRedemption,
            2 => RedemptionModel::CustodianRedemption,
            3 => RedemptionModel::BridgeBurnAndRelease,
            _ => return Err(Q6QaError::Malformed),
        };
        let status = match take_u8(&mut c)? {
            1 => QualificationStatus::Approved,
            2 => QualificationStatus::Revoked,
            _ => return Err(Q6QaError::Malformed),
        };
        let contract_len = take_u8(&mut c)? as usize;
        let contract_address = take_padded(&mut c, Q6QA_CONTRACT_ADDRESS_BYTES, contract_len)?;
        let symbol_len = take_u8(&mut c)? as usize;
        let symbol = String::from_utf8(take_padded(&mut c, Q6QA_SYMBOL_BYTES, symbol_len)?)
            .map_err(|_| Q6QaError::InvalidSymbol)?;
        let representation_len = take_u8(&mut c)? as usize;
        let representation = String::from_utf8(take_padded(
            &mut c,
            Q6QA_REPRESENTATION_BYTES,
            representation_len,
        )?)
        .map_err(|_| Q6QaError::InvalidRepresentation)?;
        let signature_len = take_u16(&mut c)? as usize;
        if signature_len == 0 || signature_len > Q6QA_MAX_SIGNATURE_BYTES {
            return Err(Q6QaError::Oversize);
        }
        let signature = take_vec(&mut c, signature_len)?;
        if c.position() as usize != bytes.len() {
            return Err(Q6QaError::Malformed);
        }
        let value = Self {
            record: QRunV06QuoteAssetQualificationCandidate {
                network_id,
                profile_id,
                asset_id,
                external_chain_id,
                issuer_id,
                custodian_id,
                bridge_id,
                reserve_evidence_digest,
                redemption_evidence_digest,
                control_risk_evidence_digest,
                authority_key_id,
                authority_account,
                qualification_epoch,
                valid_from_height,
                valid_until_height,
                decimals,
                custody_model,
                redemption_model,
                status,
                contract_address,
                symbol,
                representation,
            },
            signature,
        };
        let _ = value.record.signing_digest()?;
        Ok(value)
    }

    pub fn commitment(&self) -> Result<[u8; 32], Q6QaError> {
        qualification_commitment(&self.encode()?)
    }

    /// expected_commitment and all authority identifiers are independently provisioned inputs.
    pub fn verify_pinned<A: TransactionAuthenticator>(
        &self,
        expected_commitment: [u8; 32],
        expected_network_id: [u8; 32],
        expected_profile_id: [u8; 32],
        expected_asset_id: [u8; 32],
        expected_authority_key_id: [u8; 32],
        expected_authority_account: AccountId,
        expected_qualification_epoch: u64,
        current_height: u64,
        authenticator: &A,
    ) -> Result<QRunV06VerifiedQuoteAssetQualificationCandidate, Q6QaError> {
        if is_zero(&expected_commitment) {
            return Err(Q6QaError::MissingIndependentCommitment);
        }
        if qualification_commitment(&self.encode()?)? != expected_commitment {
            return Err(Q6QaError::CommitmentMismatch);
        }
        let r = &self.record;
        if r.network_id != expected_network_id {
            return Err(Q6QaError::WrongNetwork);
        }
        if r.profile_id != expected_profile_id {
            return Err(Q6QaError::WrongProfile);
        }
        if r.asset_id != expected_asset_id {
            return Err(Q6QaError::WrongAsset);
        }
        if r.authority_key_id != expected_authority_key_id {
            return Err(Q6QaError::WrongAuthorityKey);
        }
        if r.authority_account != expected_authority_account {
            return Err(Q6QaError::WrongAuthorityAccount);
        }
        if r.qualification_epoch != expected_qualification_epoch {
            return Err(Q6QaError::WrongQualificationEpoch);
        }
        match r.status {
            QualificationStatus::Approved => {}
            QualificationStatus::Revoked => return Err(Q6QaError::Revoked),
        }
        if current_height < r.valid_from_height {
            return Err(Q6QaError::NotYetValid);
        }
        if current_height >= r.valid_until_height {
            return Err(Q6QaError::Expired);
        }
        let digest = r.signing_digest()?;
        authenticator
            .verify(&r.authority_account, &digest, &self.signature)
            .map_err(|_| Q6QaError::InvalidSignature)?;
        Ok(QRunV06VerifiedQuoteAssetQualificationCandidate {
            network_id: r.network_id,
            profile_id: r.profile_id,
            asset_id: r.asset_id,
            external_chain_id: r.external_chain_id,
            authority_key_id: r.authority_key_id,
            qualification_epoch: r.qualification_epoch,
            valid_from_height: r.valid_from_height,
            valid_until_height: r.valid_until_height,
            commitment: expected_commitment,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QRunV06VerifiedQuoteAssetQualificationCandidate {
    network_id: NetworkId,
    profile_id: [u8; 32],
    asset_id: AssetId,
    external_chain_id: [u8; 32],
    authority_key_id: [u8; 32],
    qualification_epoch: u64,
    valid_from_height: u64,
    valid_until_height: u64,
    commitment: [u8; 32],
}
#[cfg(test)]
pub(crate) fn test_verified_quote_asset_candidate(
    network_id: NetworkId,
    profile_id: [u8; 32],
    asset_id: AssetId,
    commitment: [u8; 32],
    qualification_epoch: u64,
    valid_from_height: u64,
    valid_until_height: u64,
) -> QRunV06VerifiedQuoteAssetQualificationCandidate {
    QRunV06VerifiedQuoteAssetQualificationCandidate {
        network_id,
        profile_id,
        asset_id,
        external_chain_id: [0x44; 32],
        authority_key_id: [0x45; 32],
        qualification_epoch,
        valid_from_height,
        valid_until_height,
        commitment,
    }
}

impl QRunV06VerifiedQuoteAssetQualificationCandidate {
    pub fn network_id(&self) -> NetworkId {
        self.network_id
    }
    pub fn profile_id(&self) -> [u8; 32] {
        self.profile_id
    }
    pub fn asset_id(&self) -> AssetId {
        self.asset_id
    }
    pub fn external_chain_id(&self) -> [u8; 32] {
        self.external_chain_id
    }
    pub fn authority_key_id(&self) -> [u8; 32] {
        self.authority_key_id
    }
    pub fn qualification_epoch(&self) -> u64 {
        self.qualification_epoch
    }
    pub fn valid_from_height(&self) -> u64 {
        self.valid_from_height
    }
    pub fn valid_until_height(&self) -> u64 {
        self.valid_until_height
    }
    pub fn commitment(&self) -> [u8; 32] {
        self.commitment
    }
    pub fn is_valid_for(
        &self,
        network_id: &[u8; 32],
        profile_id: &[u8; 32],
        asset_id: &[u8; 32],
        height: u64,
    ) -> bool {
        self.network_id == *network_id
            && self.profile_id == *profile_id
            && self.asset_id == *asset_id
            && height >= self.valid_from_height
            && height < self.valid_until_height
    }
}
/// Guard for the future canonical CreatePair call site; not wired into QFB6 execution yet.
pub fn require_qualified_quote_asset(
    q: &QRunV06VerifiedQuoteAssetQualificationCandidate,
    network_id: &[u8; 32],
    profile_id: &[u8; 32],
    quote_asset_id: &[u8; 32],
    height: u64,
) -> Result<(), Q6QaError> {
    if !q.is_valid_for(network_id, profile_id, quote_asset_id, height) {
        return Err(Q6QaError::WrongAsset);
    }
    Ok(())
}
pub fn qualification_commitment(bytes: &[u8]) -> Result<[u8; 32], Q6QaError> {
    if bytes.len() > Q6QA_MAX_BYTES {
        return Err(Q6QaError::Oversize);
    }
    let mut h = Sha256::new();
    h.update(COMMITMENT_DOMAIN);
    h.update((bytes.len() as u64).to_be_bytes());
    h.update(bytes);
    Ok(h.finalize().into())
}
fn validate_record(r: &QRunV06QuoteAssetQualificationCandidate) -> Result<(), Q6QaError> {
    if is_zero(&r.network_id) {
        return Err(Q6QaError::InvalidNetwork);
    }
    if is_zero(&r.profile_id) {
        return Err(Q6QaError::InvalidProfile);
    }
    if is_zero(&r.asset_id) {
        return Err(Q6QaError::InvalidAsset);
    }
    if is_zero(&r.external_chain_id) {
        return Err(Q6QaError::InvalidExternalChain);
    }
    if is_zero(&r.issuer_id) {
        return Err(Q6QaError::InvalidIssuer);
    }
    if is_zero(&r.reserve_evidence_digest)
        || is_zero(&r.redemption_evidence_digest)
        || is_zero(&r.control_risk_evidence_digest)
    {
        return Err(Q6QaError::InvalidEvidence);
    }
    if is_zero(&r.authority_key_id) || is_zero(&r.authority_account) {
        return Err(Q6QaError::InvalidAuthority);
    }
    if r.qualification_epoch == 0 {
        return Err(Q6QaError::InvalidEpoch);
    }
    if r.valid_until_height <= r.valid_from_height {
        return Err(Q6QaError::InvalidValidityWindow);
    }
    if r.decimals > 18 {
        return Err(Q6QaError::InvalidDecimals);
    }
    if r.contract_address.is_empty() || r.contract_address.len() > Q6QA_CONTRACT_ADDRESS_BYTES {
        return Err(Q6QaError::InvalidContractAddress);
    }
    if r.symbol.is_empty()
        || r.symbol.len() > Q6QA_SYMBOL_BYTES
        || !r
            .symbol
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'-')
    {
        return Err(Q6QaError::InvalidSymbol);
    }
    if r.representation.is_empty()
        || r.representation.len() > Q6QA_REPRESENTATION_BYTES
        || !r.representation.is_ascii()
    {
        return Err(Q6QaError::InvalidRepresentation);
    }
    match r.custody_model {
        CustodyModel::IssuerControlled if !is_zero(&r.custodian_id) || !is_zero(&r.bridge_id) => {
            return Err(Q6QaError::InvalidCustodian)
        }
        CustodyModel::IndependentCustodian
            if is_zero(&r.custodian_id) || !is_zero(&r.bridge_id) =>
        {
            return Err(Q6QaError::InvalidCustodian)
        }
        CustodyModel::BridgeEscrow if is_zero(&r.bridge_id) || is_zero(&r.custodian_id) => {
            return Err(Q6QaError::InvalidCustodian)
        }
        _ => {}
    }
    Ok(())
}
fn put_padded(out: &mut Vec<u8>, v: &[u8], n: usize) {
    out.extend_from_slice(v);
    out.resize(out.len() + n - v.len(), 0);
}
fn take_padded(c: &mut Cursor<&[u8]>, width: usize, used: usize) -> Result<Vec<u8>, Q6QaError> {
    if used == 0 || used > width {
        return Err(Q6QaError::Malformed);
    }
    let b = take_vec(c, width)?;
    if b[used..].iter().any(|x| *x != 0) {
        return Err(Q6QaError::Malformed);
    }
    Ok(b[..used].to_vec())
}
fn take<const N: usize>(c: &mut Cursor<&[u8]>) -> Result<[u8; N], Q6QaError> {
    let mut o = [0; N];
    c.read_exact(&mut o).map_err(|_| Q6QaError::Malformed)?;
    Ok(o)
}
fn take_vec(c: &mut Cursor<&[u8]>, n: usize) -> Result<Vec<u8>, Q6QaError> {
    let mut o = vec![0; n];
    c.read_exact(&mut o).map_err(|_| Q6QaError::Malformed)?;
    Ok(o)
}
fn take_u8(c: &mut Cursor<&[u8]>) -> Result<u8, Q6QaError> {
    Ok(take::<1>(c)?[0])
}
fn take_u16(c: &mut Cursor<&[u8]>) -> Result<u16, Q6QaError> {
    Ok(u16::from_be_bytes(take(c)?))
}
fn take_u64(c: &mut Cursor<&[u8]>) -> Result<u64, Q6QaError> {
    Ok(u64::from_be_bytes(take(c)?))
}
fn is_zero(b: &[u8]) -> bool {
    b.iter().all(|x| *x == 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    struct TestAuthenticator;
    impl TransactionAuthenticator for TestAuthenticator {
        fn verify(
            &self,
            sender: &AccountId,
            digest: &[u8; 32],
            signature: &[u8],
        ) -> Result<(), ()> {
            if *sender == [0x88; 32] && signature == digest {
                Ok(())
            } else {
                Err(())
            }
        }
    }
    fn signed(status: QualificationStatus) -> QRunV06SignedQuoteAssetQualificationCandidate {
        let record = QRunV06QuoteAssetQualificationCandidate {
            network_id: [0x11; 32],
            profile_id: [0x22; 32],
            asset_id: [0x33; 32],
            external_chain_id: [0x44; 32],
            issuer_id: [0x55; 32],
            custodian_id: [0x66; 32],
            bridge_id: [0; 32],
            reserve_evidence_digest: [0x77; 32],
            redemption_evidence_digest: [0x78; 32],
            control_risk_evidence_digest: [0x79; 32],
            authority_key_id: [0xAA; 32],
            authority_account: [0x88; 32],
            qualification_epoch: 1,
            valid_from_height: 100,
            valid_until_height: 200,
            decimals: 6,
            custody_model: CustodyModel::IndependentCustodian,
            redemption_model: RedemptionModel::CustodianRedemption,
            status,
            contract_address: vec![0xA1; 20],
            symbol: "USDT".into(),
            representation: "USDT ERC-20 on reviewed external chain".into(),
        };
        let signature = record.signing_digest().unwrap().to_vec();
        QRunV06SignedQuoteAssetQualificationCandidate { record, signature }
    }
    fn verify(
        b: &QRunV06SignedQuoteAssetQualificationCandidate,
        h: u64,
    ) -> Result<QRunV06VerifiedQuoteAssetQualificationCandidate, Q6QaError> {
        b.verify_pinned(
            b.commitment().unwrap(),
            [0x11; 32],
            [0x22; 32],
            [0x33; 32],
            [0xAA; 32],
            [0x88; 32],
            1,
            h,
            &TestAuthenticator,
        )
    }
    #[test]
    fn q6qa_cross_language_golden_vector_v1() {
        let b = signed(QualificationStatus::Approved);
        assert_eq!(
            b.record.signing_digest().unwrap(),
            [
                0x1e, 0xb5, 0xff, 0xe9, 0x38, 0x9e, 0xb9, 0x94, 0xeb, 0x6d, 0x68, 0x50, 0x98, 0x5f,
                0x66, 0xf2, 0x93, 0x36, 0x01, 0xa6, 0x53, 0xfa, 0x04, 0xf5, 0xa6, 0x87, 0x23, 0x91,
                0x87, 0xcd, 0x96, 0x63,
            ]
        );
        assert_eq!(
            b.commitment().unwrap(),
            [
                0xaa, 0xf4, 0xd0, 0x01, 0x3d, 0xb7, 0x77, 0x33, 0x97, 0xcb, 0x0e, 0xd7, 0xa8, 0x14,
                0x48, 0xd2, 0x8e, 0x93, 0x05, 0xd1, 0x28, 0x95, 0x5a, 0x31, 0x0e, 0xb9, 0xe8, 0xb5,
                0x11, 0x35, 0xdb, 0xb7,
            ]
        );
        assert_eq!(b.encode().unwrap().len(), 601);
    }

    #[test]
    fn q6qa_fixed_width_bundle_roundtrips_and_requires_independent_context() {
        let b = signed(QualificationStatus::Approved);
        let bytes = b.encode().unwrap();
        assert_eq!(bytes.len(), Q6QA_FIXED_BYTES + 32);
        let d = QRunV06SignedQuoteAssetQualificationCandidate::decode(&bytes).unwrap();
        assert_eq!(d, b);
        assert_eq!(verify(&d, 100).unwrap().asset_id(), [0x33; 32]);
    }
    #[test]
    fn q6qa_refuses_missing_wrong_or_mutated_independent_commitment() {
        let b = signed(QualificationStatus::Approved);
        assert_eq!(
            b.verify_pinned(
                [0; 32],
                [0x11; 32],
                [0x22; 32],
                [0x33; 32],
                [0xAA; 32],
                [0x88; 32],
                1,
                100,
                &TestAuthenticator
            ),
            Err(Q6QaError::MissingIndependentCommitment)
        );
        assert_eq!(
            b.verify_pinned(
                [0xFE; 32],
                [0x11; 32],
                [0x22; 32],
                [0x33; 32],
                [0xAA; 32],
                [0x88; 32],
                1,
                100,
                &TestAuthenticator
            ),
            Err(Q6QaError::CommitmentMismatch)
        );
        let mut bytes = b.encode().unwrap();
        bytes[20] ^= 1;
        let m = QRunV06SignedQuoteAssetQualificationCandidate::decode(&bytes).unwrap();
        assert_eq!(
            m.verify_pinned(
                b.commitment().unwrap(),
                [0x11; 32],
                [0x22; 32],
                [0x33; 32],
                [0xAA; 32],
                [0x88; 32],
                1,
                100,
                &TestAuthenticator
            ),
            Err(Q6QaError::CommitmentMismatch)
        );
    }
    #[test]
    fn q6qa_binds_network_profile_asset_and_authority_identity() {
        let b = signed(QualificationStatus::Approved);
        let c = b.commitment().unwrap();
        assert_eq!(
            b.verify_pinned(
                c,
                [0x12; 32],
                [0x22; 32],
                [0x33; 32],
                [0xAA; 32],
                [0x88; 32],
                1,
                100,
                &TestAuthenticator
            ),
            Err(Q6QaError::WrongNetwork)
        );
        assert_eq!(
            b.verify_pinned(
                c,
                [0x11; 32],
                [0x23; 32],
                [0x33; 32],
                [0xAA; 32],
                [0x88; 32],
                1,
                100,
                &TestAuthenticator
            ),
            Err(Q6QaError::WrongProfile)
        );
        assert_eq!(
            b.verify_pinned(
                c,
                [0x11; 32],
                [0x22; 32],
                [0x34; 32],
                [0xAA; 32],
                [0x88; 32],
                1,
                100,
                &TestAuthenticator
            ),
            Err(Q6QaError::WrongAsset)
        );
        assert_eq!(
            b.verify_pinned(
                c,
                [0x11; 32],
                [0x22; 32],
                [0x33; 32],
                [0xAB; 32],
                [0x88; 32],
                1,
                100,
                &TestAuthenticator
            ),
            Err(Q6QaError::WrongAuthorityKey)
        );
        assert_eq!(
            b.verify_pinned(
                c,
                [0x11; 32],
                [0x22; 32],
                [0x33; 32],
                [0xAA; 32],
                [0x89; 32],
                1,
                100,
                &TestAuthenticator
            ),
            Err(Q6QaError::WrongAuthorityAccount)
        );
    }
    #[test]
    fn q6qa_rejects_expired_future_and_revoked_qualifications() {
        let b = signed(QualificationStatus::Approved);
        assert_eq!(verify(&b, 99), Err(Q6QaError::NotYetValid));
        assert_eq!(verify(&b, 200), Err(Q6QaError::Expired));
        assert_eq!(
            verify(&signed(QualificationStatus::Revoked), 100),
            Err(Q6QaError::Revoked)
        );
    }
    #[test]
    fn q6qa_requires_a_signature_from_the_pinned_authority_account() {
        let mut b = signed(QualificationStatus::Approved);
        b.signature[0] ^= 1;
        assert_eq!(verify(&b, 100), Err(Q6QaError::InvalidSignature));
    }
    #[test]
    fn q6qa_pair_guard_accepts_only_exact_active_quote_asset() {
        let b = signed(QualificationStatus::Approved);
        let q = verify(&b, 150).unwrap();
        assert_eq!(
            require_qualified_quote_asset(&q, &[0x11; 32], &[0x22; 32], &[0x33; 32], 150),
            Ok(())
        );
        assert_eq!(
            require_qualified_quote_asset(&q, &[0x11; 32], &[0x22; 32], &[0x34; 32], 150),
            Err(Q6QaError::WrongAsset)
        );
        assert_eq!(
            require_qualified_quote_asset(&q, &[0x11; 32], &[0x22; 32], &[0x33; 32], 200),
            Err(Q6QaError::WrongAsset)
        );
    }
}
