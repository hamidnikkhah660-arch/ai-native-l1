//! CP-0546 append-only historical Q6TS/Q6PN/Q6QA trust-history candidate.
//!
//! The history authority and its checkpoint head are pinned independently of the Q6TS
//! profile-trust authority and the QFP6 node. Entries are immutable and hash-linked.
//! Each entry's effective_from_height closes the previous entry's interval; therefore
//! a later rotation/revocation does not retroactively invalidate earlier blocks, while
//! an old active receipt cannot authorize blocks at or after the next entry's height.
//!
//! This module supplies verification primitives only. It does not deploy the history
//! authority, source, or separately administered monotonic checkpoint store.
use crate::{
    qrun_v06_profile_trust_candidate::{
        PinnedQRunV06ProfileTrustAuthority, QRunV06ProfileTrustStatus,
    },
    v4_fat1_trust_candidate::{
        MlDsa65Verifier, ED25519_SIGNATURE_BYTES, ML_DSA_65_SIGNATURE_BYTES,
    },
};
use ed25519_dalek::{Signature as EdSignature, VerifyingKey};
use sha2::{Digest, Sha256};
use std::fmt;

pub const QRUN_V06_HISTORICAL_TRUST_ENTRY_BYTES: usize = 352;
pub const QRUN_V06_HISTORICAL_TRUST_CHECKPOINT_BYTES: usize = 120;
pub const QRUN_V06_MAX_HISTORICAL_TRUST_ENTRIES: usize = 4096;

const ENTRY_MAGIC: &[u8; 4] = b"Q6HE";
const CHECKPOINT_MAGIC: &[u8; 4] = b"Q6HC";
const VERSION: u16 = 1;
const ENTRY_ID_DOMAIN: &[u8] = b"QRUN-V06-HISTORICAL-TRUST-ENTRY-ID-V1\0";
const ENTRY_SIGN_DOMAIN: &[u8] = b"QRUN-V06-HISTORICAL-TRUST-ENTRY-SIGN-V1\0";
const CHECKPOINT_ID_DOMAIN: &[u8] = b"QRUN-V06-HISTORICAL-TRUST-CHECKPOINT-ID-V1\0";
const CHECKPOINT_SIGN_DOMAIN: &[u8] = b"QRUN-V06-HISTORICAL-TRUST-CHECKPOINT-SIGN-V1\0";

fn is_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}

fn hash_parts(parts: &[&[u8]]) -> [u8; 32] {
    let mut hash = Sha256::new();
    for part in parts {
        hash.update(part);
    }
    hash.finalize().into()
}

fn take<const N: usize>(
    bytes: &[u8],
    offset: usize,
) -> Result<[u8; N], QRunV06HistoricalTrustError> {
    bytes
        .get(offset..offset + N)
        .ok_or(QRunV06HistoricalTrustError::Malformed)?
        .try_into()
        .map_err(|_| QRunV06HistoricalTrustError::Malformed)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QRunV06HistoricalTrustError {
    Malformed,
    InvalidEntry,
    InvalidCheckpoint,
    WrongAuthorityKeyset,
    WrongNetworkOrProfile,
    InvalidEd25519PublicKey,
    InvalidEd25519Signature,
    InvalidMlDsa65Signature,
    HistoryTooLarge,
    CheckpointMismatch,
    CheckpointNotPrepublished,
    HistoryHeadMismatch,
    SequenceGap,
    PredecessorMismatch,
    RevokedPredecessor,
    NoEffectiveEntry,
    TrustRevoked,
}
impl fmt::Display for QRunV06HistoricalTrustError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for QRunV06HistoricalTrustError {}

/// A signed mapping from one exact Q6TS profile-trust record to its historical
/// Q6PN/Q6QA commitments and the first block height at which that authorization applies.
/// The end of the interval is immutable and derived from the next entry's start height.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QRunV06HistoricalTrustEntryRecord {
    pub sequence: u64,
    pub status: QRunV06ProfileTrustStatus,
    pub network_id: [u8; 32],
    pub profile_id: [u8; 32],
    pub q6ts_record_id: [u8; 32],
    pub q6ts_envelope_id: [u8; 32],
    pub previous_entry_id: [u8; 32],
    pub previous_q6ts_record_id: [u8; 32],
    pub previous_q6ts_envelope_id: [u8; 32],
    pub profile_pin_commitment: [u8; 32],
    pub q6qa_commitment: [u8; 32],
    pub quote_asset_id: [u8; 32],
    pub qualification_epoch: u64,
    pub effective_from_height: u64,
}

impl QRunV06HistoricalTrustEntryRecord {
    pub fn validate(&self) -> Result<(), QRunV06HistoricalTrustError> {
        if self.sequence == 0
            || is_zero(&self.network_id)
            || is_zero(&self.profile_id)
            || is_zero(&self.q6ts_record_id)
            || is_zero(&self.q6ts_envelope_id)
            || is_zero(&self.profile_pin_commitment)
        {
            return Err(QRunV06HistoricalTrustError::InvalidEntry);
        }
        if (self.sequence == 1)
            != (is_zero(&self.previous_entry_id)
                && is_zero(&self.previous_q6ts_record_id)
                && is_zero(&self.previous_q6ts_envelope_id))
        {
            return Err(QRunV06HistoricalTrustError::PredecessorMismatch);
        }
        if self.sequence > 1
            && (is_zero(&self.previous_entry_id)
                || is_zero(&self.previous_q6ts_record_id)
                || is_zero(&self.previous_q6ts_envelope_id))
        {
            return Err(QRunV06HistoricalTrustError::PredecessorMismatch);
        }
        match self.status {
            QRunV06ProfileTrustStatus::Active => {
                if is_zero(&self.q6qa_commitment)
                    || is_zero(&self.quote_asset_id)
                    || self.qualification_epoch == 0
                {
                    return Err(QRunV06HistoricalTrustError::InvalidEntry);
                }
            }
            QRunV06ProfileTrustStatus::Revoked => {
                if !is_zero(&self.q6qa_commitment)
                    || !is_zero(&self.quote_asset_id)
                    || self.qualification_epoch != 0
                {
                    return Err(QRunV06HistoricalTrustError::InvalidEntry);
                }
            }
        }
        Ok(())
    }

    pub fn encode(
        &self,
    ) -> Result<[u8; QRUN_V06_HISTORICAL_TRUST_ENTRY_BYTES], QRunV06HistoricalTrustError> {
        self.validate()?;
        let mut bytes = Vec::with_capacity(QRUN_V06_HISTORICAL_TRUST_ENTRY_BYTES);
        bytes.extend_from_slice(ENTRY_MAGIC);
        bytes.extend_from_slice(&VERSION.to_be_bytes());
        bytes.extend_from_slice(&(self.status as u16).to_be_bytes());
        bytes.extend_from_slice(&self.sequence.to_be_bytes());
        for field in [
            &self.network_id,
            &self.profile_id,
            &self.q6ts_record_id,
            &self.q6ts_envelope_id,
            &self.previous_entry_id,
            &self.previous_q6ts_record_id,
            &self.previous_q6ts_envelope_id,
            &self.profile_pin_commitment,
            &self.q6qa_commitment,
            &self.quote_asset_id,
        ] {
            bytes.extend_from_slice(field);
        }
        bytes.extend_from_slice(&self.qualification_epoch.to_be_bytes());
        bytes.extend_from_slice(&self.effective_from_height.to_be_bytes());
        bytes
            .try_into()
            .map_err(|_| QRunV06HistoricalTrustError::Malformed)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, QRunV06HistoricalTrustError> {
        if bytes.len() != QRUN_V06_HISTORICAL_TRUST_ENTRY_BYTES
            || bytes.get(..4) != Some(ENTRY_MAGIC.as_slice())
        {
            return Err(QRunV06HistoricalTrustError::Malformed);
        }
        if u16::from_be_bytes(take(bytes, 4)?) != VERSION {
            return Err(QRunV06HistoricalTrustError::Malformed);
        }
        let status = match u16::from_be_bytes(take(bytes, 6)?) {
            1 => QRunV06ProfileTrustStatus::Active,
            2 => QRunV06ProfileTrustStatus::Revoked,
            _ => return Err(QRunV06HistoricalTrustError::InvalidEntry),
        };
        let value = Self {
            status,
            sequence: u64::from_be_bytes(take(bytes, 8)?),
            network_id: take(bytes, 16)?,
            profile_id: take(bytes, 48)?,
            q6ts_record_id: take(bytes, 80)?,
            q6ts_envelope_id: take(bytes, 112)?,
            previous_entry_id: take(bytes, 144)?,
            previous_q6ts_record_id: take(bytes, 176)?,
            previous_q6ts_envelope_id: take(bytes, 208)?,
            profile_pin_commitment: take(bytes, 240)?,
            q6qa_commitment: take(bytes, 272)?,
            quote_asset_id: take(bytes, 304)?,
            qualification_epoch: u64::from_be_bytes(take(bytes, 336)?),
            effective_from_height: u64::from_be_bytes(take(bytes, 344)?),
        };
        value.validate()?;
        if value.encode()?.as_slice() != bytes {
            return Err(QRunV06HistoricalTrustError::Malformed);
        }
        Ok(value)
    }

    pub fn entry_id(&self) -> Result<[u8; 32], QRunV06HistoricalTrustError> {
        Ok(hash_parts(&[ENTRY_ID_DOMAIN, &self.encode()?]))
    }

    pub fn signing_digest(
        &self,
        authority_keyset_id: &[u8; 32],
    ) -> Result<[u8; 32], QRunV06HistoricalTrustError> {
        if is_zero(authority_keyset_id) {
            return Err(QRunV06HistoricalTrustError::WrongAuthorityKeyset);
        }
        Ok(hash_parts(&[
            ENTRY_SIGN_DOMAIN,
            &self.encode()?,
            authority_keyset_id,
        ]))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QRunV06SignedHistoricalTrustEntry {
    pub record: QRunV06HistoricalTrustEntryRecord,
    pub authority_keyset_id: [u8; 32],
    pub ed25519_signature: [u8; ED25519_SIGNATURE_BYTES],
    pub mldsa65_signature: [u8; ML_DSA_65_SIGNATURE_BYTES],
}
impl QRunV06SignedHistoricalTrustEntry {
    pub fn entry_id(&self) -> Result<[u8; 32], QRunV06HistoricalTrustError> {
        self.record.entry_id()
    }

    fn verify<V: MlDsa65Verifier>(
        &self,
        authority: &PinnedQRunV06ProfileTrustAuthority,
        verifier: &V,
    ) -> Result<(), QRunV06HistoricalTrustError> {
        if authority
            .keyset_id()
            .map_err(|_| QRunV06HistoricalTrustError::WrongAuthorityKeyset)?
            != self.authority_keyset_id
        {
            return Err(QRunV06HistoricalTrustError::WrongAuthorityKeyset);
        }
        let digest = self.record.signing_digest(&self.authority_keyset_id)?;
        let key = VerifyingKey::from_bytes(&authority.ed25519_public_key)
            .map_err(|_| QRunV06HistoricalTrustError::InvalidEd25519PublicKey)?;
        key.verify_strict(&digest, &EdSignature::from_bytes(&self.ed25519_signature))
            .map_err(|_| QRunV06HistoricalTrustError::InvalidEd25519Signature)?;
        if !verifier.verify(
            &authority.mldsa65_public_key,
            &digest,
            &self.mldsa65_signature,
        ) {
            return Err(QRunV06HistoricalTrustError::InvalidMlDsa65Signature);
        }
        Ok(())
    }
}

/// A signed, exact chain head. A separately administered monotonic store pins this complete
/// checkpoint; the source is never allowed to define or advance its own trusted head.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QRunV06HistoricalTrustCheckpoint {
    pub sequence: u64,
    pub network_id: [u8; 32],
    pub profile_id: [u8; 32],
    pub head_entry_id: [u8; 32],
    /// Independently recorded height at which this complete history prefix was published.
    pub published_at_height: u64,
}
impl QRunV06HistoricalTrustCheckpoint {
    pub fn encode(
        &self,
    ) -> Result<[u8; QRUN_V06_HISTORICAL_TRUST_CHECKPOINT_BYTES], QRunV06HistoricalTrustError> {
        if is_zero(&self.network_id) || is_zero(&self.profile_id) {
            return Err(QRunV06HistoricalTrustError::InvalidCheckpoint);
        }
        if (self.sequence == 0) != is_zero(&self.head_entry_id) {
            return Err(QRunV06HistoricalTrustError::InvalidCheckpoint);
        }
        let mut bytes = Vec::with_capacity(QRUN_V06_HISTORICAL_TRUST_CHECKPOINT_BYTES);
        bytes.extend_from_slice(CHECKPOINT_MAGIC);
        bytes.extend_from_slice(&VERSION.to_be_bytes());
        bytes.extend_from_slice(&0u16.to_be_bytes());
        bytes.extend_from_slice(&self.sequence.to_be_bytes());
        bytes.extend_from_slice(&self.network_id);
        bytes.extend_from_slice(&self.profile_id);
        bytes.extend_from_slice(&self.head_entry_id);
        bytes.extend_from_slice(&self.published_at_height.to_be_bytes());
        bytes
            .try_into()
            .map_err(|_| QRunV06HistoricalTrustError::Malformed)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, QRunV06HistoricalTrustError> {
        if bytes.len() != QRUN_V06_HISTORICAL_TRUST_CHECKPOINT_BYTES
            || bytes.get(..4) != Some(CHECKPOINT_MAGIC.as_slice())
            || u16::from_be_bytes(take(bytes, 4)?) != VERSION
            || u16::from_be_bytes(take(bytes, 6)?) != 0
        {
            return Err(QRunV06HistoricalTrustError::Malformed);
        }
        let value = Self {
            sequence: u64::from_be_bytes(take(bytes, 8)?),
            network_id: take(bytes, 16)?,
            profile_id: take(bytes, 48)?,
            head_entry_id: take(bytes, 80)?,
            published_at_height: u64::from_be_bytes(take(bytes, 112)?),
        };
        if value.encode()?.as_slice() != bytes {
            return Err(QRunV06HistoricalTrustError::Malformed);
        }
        Ok(value)
    }
    pub fn checkpoint_id(&self) -> Result<[u8; 32], QRunV06HistoricalTrustError> {
        Ok(hash_parts(&[CHECKPOINT_ID_DOMAIN, &self.encode()?]))
    }
    pub fn signing_digest(
        &self,
        authority_keyset_id: &[u8; 32],
    ) -> Result<[u8; 32], QRunV06HistoricalTrustError> {
        if is_zero(authority_keyset_id) {
            return Err(QRunV06HistoricalTrustError::WrongAuthorityKeyset);
        }
        Ok(hash_parts(&[
            CHECKPOINT_SIGN_DOMAIN,
            &self.encode()?,
            authority_keyset_id,
        ]))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QRunV06SignedHistoricalTrustCheckpoint {
    pub record: QRunV06HistoricalTrustCheckpoint,
    pub authority_keyset_id: [u8; 32],
    pub ed25519_signature: [u8; ED25519_SIGNATURE_BYTES],
    pub mldsa65_signature: [u8; ML_DSA_65_SIGNATURE_BYTES],
}
impl QRunV06SignedHistoricalTrustCheckpoint {
    fn verify<V: MlDsa65Verifier>(
        &self,
        authority: &PinnedQRunV06ProfileTrustAuthority,
        verifier: &V,
    ) -> Result<(), QRunV06HistoricalTrustError> {
        if authority
            .keyset_id()
            .map_err(|_| QRunV06HistoricalTrustError::WrongAuthorityKeyset)?
            != self.authority_keyset_id
        {
            return Err(QRunV06HistoricalTrustError::WrongAuthorityKeyset);
        }
        let digest = self.record.signing_digest(&self.authority_keyset_id)?;
        let key = VerifyingKey::from_bytes(&authority.ed25519_public_key)
            .map_err(|_| QRunV06HistoricalTrustError::InvalidEd25519PublicKey)?;
        key.verify_strict(&digest, &EdSignature::from_bytes(&self.ed25519_signature))
            .map_err(|_| QRunV06HistoricalTrustError::InvalidEd25519Signature)?;
        if !verifier.verify(
            &authority.mldsa65_public_key,
            &digest,
            &self.mldsa65_signature,
        ) {
            return Err(QRunV06HistoricalTrustError::InvalidMlDsa65Signature);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QRunV06HistoricalTrustHistorySnapshot {
    pub entries: Vec<QRunV06SignedHistoricalTrustEntry>,
    pub checkpoint: QRunV06SignedHistoricalTrustCheckpoint,
}

/// Verified entire history. Fields remain private so callers cannot construct a verified log
/// by copying unauthenticated records into a public type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QRunV06VerifiedHistoricalTrustHistory {
    entries: Vec<QRunV06SignedHistoricalTrustEntry>,
    checkpoint: QRunV06SignedHistoricalTrustCheckpoint,
}
impl QRunV06VerifiedHistoricalTrustHistory {
    pub fn entries(&self) -> &[QRunV06SignedHistoricalTrustEntry] {
        &self.entries
    }
    pub fn checkpoint(&self) -> &QRunV06SignedHistoricalTrustCheckpoint {
        &self.checkpoint
    }

    /// Returns the last entry effective at the requested height and its derived exclusive end.
    pub fn entry_for_height(
        &self,
        height: u64,
    ) -> Result<(&QRunV06SignedHistoricalTrustEntry, u64), QRunV06HistoricalTrustError> {
        let index = self
            .entries
            .iter()
            .rposition(|entry| entry.record.effective_from_height <= height)
            .ok_or(QRunV06HistoricalTrustError::NoEffectiveEntry)?;
        let until = self
            .entries
            .get(index + 1)
            .map(|entry| entry.record.effective_from_height)
            .unwrap_or(u64::MAX);
        Ok((&self.entries[index], until))
    }
}

/// Verify the signed log against the independently pinned checkpoint and keyset.
/// The whole bounded chain is checked so an entry cannot be spliced into a different history.
pub fn verify_qrun_v06_historical_trust_history<V: MlDsa65Verifier>(
    snapshot: &QRunV06HistoricalTrustHistorySnapshot,
    independently_pinned_checkpoint: &QRunV06SignedHistoricalTrustCheckpoint,
    authority: &PinnedQRunV06ProfileTrustAuthority,
    verifier: &V,
    network_id: &[u8; 32],
    profile_id: &[u8; 32],
) -> Result<QRunV06VerifiedHistoricalTrustHistory, QRunV06HistoricalTrustError> {
    if snapshot.entries.len() > QRUN_V06_MAX_HISTORICAL_TRUST_ENTRIES {
        return Err(QRunV06HistoricalTrustError::HistoryTooLarge);
    }
    if &snapshot.checkpoint != independently_pinned_checkpoint {
        return Err(QRunV06HistoricalTrustError::CheckpointMismatch);
    }
    let checkpoint = &snapshot.checkpoint.record;
    if checkpoint.network_id != *network_id || checkpoint.profile_id != *profile_id {
        return Err(QRunV06HistoricalTrustError::WrongNetworkOrProfile);
    }
    snapshot.checkpoint.verify(authority, verifier)?;
    if checkpoint.sequence != snapshot.entries.len() as u64 {
        return Err(QRunV06HistoricalTrustError::SequenceGap);
    }
    if snapshot.entries.is_empty() {
        if !is_zero(&checkpoint.head_entry_id) {
            return Err(QRunV06HistoricalTrustError::HistoryHeadMismatch);
        }
    } else {
        let latest_entry = snapshot.entries.last().unwrap();
        if latest_entry.entry_id()? != checkpoint.head_entry_id {
            return Err(QRunV06HistoricalTrustError::HistoryHeadMismatch);
        }
        if checkpoint.published_at_height >= latest_entry.record.effective_from_height {
            return Err(QRunV06HistoricalTrustError::CheckpointNotPrepublished);
        }
    }

    let mut previous: Option<&QRunV06SignedHistoricalTrustEntry> = None;
    for (index, entry) in snapshot.entries.iter().enumerate() {
        entry.record.validate()?;
        entry.verify(authority, verifier)?;
        if entry.record.network_id != *network_id || entry.record.profile_id != *profile_id {
            return Err(QRunV06HistoricalTrustError::WrongNetworkOrProfile);
        }
        if entry.record.sequence != (index as u64) + 1 {
            return Err(QRunV06HistoricalTrustError::SequenceGap);
        }
        if let Some(prior) = previous {
            if prior.record.status == QRunV06ProfileTrustStatus::Revoked {
                return Err(QRunV06HistoricalTrustError::RevokedPredecessor);
            }
            if entry.record.previous_entry_id != prior.entry_id()?
                || entry.record.previous_q6ts_record_id != prior.record.q6ts_record_id
                || entry.record.previous_q6ts_envelope_id != prior.record.q6ts_envelope_id
            {
                return Err(QRunV06HistoricalTrustError::PredecessorMismatch);
            }
            if entry.record.effective_from_height <= prior.record.effective_from_height {
                return Err(QRunV06HistoricalTrustError::InvalidEntry);
            }
        }
        previous = Some(entry);
    }

    Ok(QRunV06VerifiedHistoricalTrustHistory {
        entries: snapshot.entries.clone(),
        checkpoint: snapshot.checkpoint.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v4_fat1_mldsa65_candidate::LibcruxMlDsa65VerifierCandidate;
    use ed25519_dalek::{Signer, SigningKey};
    use libcrux_ml_dsa::ml_dsa_65::portable;

    const NETWORK: [u8; 32] = [0xB1; 32];
    const PROFILE: [u8; 32] = [0xB2; 32];

    struct Fixture {
        authority: PinnedQRunV06ProfileTrustAuthority,
        ed: SigningKey,
        verifier: LibcruxMlDsa65VerifierCandidate,
    }
    impl Fixture {
        fn new() -> Self {
            let ed = SigningKey::from_bytes(&[0xB3; 32]);
            let pair = portable::generate_key_pair([0xB4; 32]);
            Self {
                authority: PinnedQRunV06ProfileTrustAuthority {
                    ed25519_public_key: ed.verifying_key().to_bytes(),
                    mldsa65_public_key: *pair.verification_key.as_ref(),
                },
                ed,
                verifier: LibcruxMlDsa65VerifierCandidate,
            }
        }
        fn sign_entry(
            &self,
            record: QRunV06HistoricalTrustEntryRecord,
        ) -> QRunV06SignedHistoricalTrustEntry {
            let keyset = self.authority.keyset_id().unwrap();
            let digest = record.signing_digest(&keyset).unwrap();
            let pair = portable::generate_key_pair([0xB4; 32]);
            let signature = portable::sign(&pair.signing_key, &digest, &[], [0xB5; 32]).unwrap();
            QRunV06SignedHistoricalTrustEntry {
                record,
                authority_keyset_id: keyset,
                ed25519_signature: self.ed.sign(&digest).to_bytes(),
                mldsa65_signature: *signature.as_ref(),
            }
        }
        fn sign_checkpoint(
            &self,
            record: QRunV06HistoricalTrustCheckpoint,
        ) -> QRunV06SignedHistoricalTrustCheckpoint {
            let keyset = self.authority.keyset_id().unwrap();
            let digest = record.signing_digest(&keyset).unwrap();
            let pair = portable::generate_key_pair([0xB4; 32]);
            let signature = portable::sign(&pair.signing_key, &digest, &[], [0xB6; 32]).unwrap();
            QRunV06SignedHistoricalTrustCheckpoint {
                record,
                authority_keyset_id: keyset,
                ed25519_signature: self.ed.sign(&digest).to_bytes(),
                mldsa65_signature: *signature.as_ref(),
            }
        }
    }

    fn active_entry(
        sequence: u64,
        effective_from_height: u64,
        previous: Option<&QRunV06SignedHistoricalTrustEntry>,
    ) -> QRunV06HistoricalTrustEntryRecord {
        QRunV06HistoricalTrustEntryRecord {
            sequence,
            status: QRunV06ProfileTrustStatus::Active,
            network_id: NETWORK,
            profile_id: PROFILE,
            q6ts_record_id: [sequence as u8 + 1; 32],
            q6ts_envelope_id: [sequence as u8 + 2; 32],
            previous_entry_id: previous
                .map(|entry| entry.entry_id().unwrap())
                .unwrap_or([0; 32]),
            previous_q6ts_record_id: previous
                .map(|entry| entry.record.q6ts_record_id)
                .unwrap_or([0; 32]),
            previous_q6ts_envelope_id: previous
                .map(|entry| entry.record.q6ts_envelope_id)
                .unwrap_or([0; 32]),
            profile_pin_commitment: [sequence as u8 + 3; 32],
            q6qa_commitment: [sequence as u8 + 4; 32],
            quote_asset_id: [0xC1; 32],
            qualification_epoch: sequence,
            effective_from_height,
        }
    }

    fn revoked_entry(
        sequence: u64,
        effective_from_height: u64,
        previous: &QRunV06SignedHistoricalTrustEntry,
    ) -> QRunV06HistoricalTrustEntryRecord {
        QRunV06HistoricalTrustEntryRecord {
            sequence,
            status: QRunV06ProfileTrustStatus::Revoked,
            network_id: NETWORK,
            profile_id: PROFILE,
            q6ts_record_id: [sequence as u8 + 1; 32],
            q6ts_envelope_id: [sequence as u8 + 2; 32],
            previous_entry_id: previous.entry_id().unwrap(),
            previous_q6ts_record_id: previous.record.q6ts_record_id,
            previous_q6ts_envelope_id: previous.record.q6ts_envelope_id,
            profile_pin_commitment: [sequence as u8 + 3; 32],
            q6qa_commitment: [0; 32],
            quote_asset_id: [0; 32],
            qualification_epoch: 0,
            effective_from_height,
        }
    }

    fn snapshot(f: &Fixture) -> QRunV06HistoricalTrustHistorySnapshot {
        let one = f.sign_entry(active_entry(1, 10, None));
        let two = f.sign_entry(active_entry(2, 20, Some(&one)));
        let three = f.sign_entry(revoked_entry(3, 30, &two));
        let head = f.sign_checkpoint(QRunV06HistoricalTrustCheckpoint {
            sequence: 3,
            network_id: NETWORK,
            profile_id: PROFILE,
            head_entry_id: three.entry_id().unwrap(),
            published_at_height: 29,
        });
        QRunV06HistoricalTrustHistorySnapshot {
            entries: vec![one, two, three],
            checkpoint: head,
        }
    }

    #[test]
    fn cp0546_history_chain_is_canonical_signed_and_height_scoped() {
        let f = Fixture::new();
        let s = snapshot(&f);
        let verified = verify_qrun_v06_historical_trust_history(
            &s,
            &s.checkpoint,
            &f.authority,
            &f.verifier,
            &NETWORK,
            &PROFILE,
        )
        .unwrap();
        let (before_rotation, until_before) = verified.entry_for_height(19).unwrap();
        assert_eq!(before_rotation.record.sequence, 1);
        assert_eq!(until_before, 20);
        let (after_rotation, until_after) = verified.entry_for_height(20).unwrap();
        assert_eq!(after_rotation.record.sequence, 2);
        assert_eq!(until_after, 30);
        let (after_revocation, until_revoked) = verified.entry_for_height(30).unwrap();
        assert_eq!(
            after_revocation.record.status,
            QRunV06ProfileTrustStatus::Revoked
        );
        assert_eq!(until_revoked, u64::MAX);
        assert_eq!(
            QRunV06HistoricalTrustEntryRecord::decode(&s.entries[0].record.encode().unwrap())
                .unwrap(),
            s.entries[0].record
        );
    }

    #[test]
    fn cp0546_old_receipt_interval_ends_at_rotation_and_revocation_boundary() {
        let f = Fixture::new();
        let s = snapshot(&f);
        let verified = verify_qrun_v06_historical_trust_history(
            &s,
            &s.checkpoint,
            &f.authority,
            &f.verifier,
            &NETWORK,
            &PROFILE,
        )
        .unwrap();
        let (at_19, end_19) = verified.entry_for_height(19).unwrap();
        assert_eq!(at_19.record.sequence, 1);
        assert_eq!(end_19, 20);
        let (at_30, _) = verified.entry_for_height(30).unwrap();
        assert_eq!(at_30.record.status, QRunV06ProfileTrustStatus::Revoked);
        assert_eq!(at_30.record.sequence, 3);
    }

    #[test]
    fn cp0546_rejects_unanchored_rollback_and_mutated_history() {
        let f = Fixture::new();
        let mut s = snapshot(&f);
        let pinned = s.checkpoint.clone();
        s.entries.pop();
        assert_eq!(
            verify_qrun_v06_historical_trust_history(
                &s,
                &pinned,
                &f.authority,
                &f.verifier,
                &NETWORK,
                &PROFILE,
            ),
            Err(QRunV06HistoricalTrustError::SequenceGap)
        );

        let mut tampered = snapshot(&f);
        tampered.entries[1].record.effective_from_height = 19;
        assert!(matches!(
            verify_qrun_v06_historical_trust_history(
                &tampered,
                &tampered.checkpoint,
                &f.authority,
                &f.verifier,
                &NETWORK,
                &PROFILE,
            ),
            Err(QRunV06HistoricalTrustError::InvalidEd25519Signature)
                | Err(QRunV06HistoricalTrustError::InvalidMlDsa65Signature)
        ));
    }

    #[test]
    fn cp0546_rejects_gap_or_successor_after_terminal_revocation() {
        let f = Fixture::new();
        let one = f.sign_entry(active_entry(1, 10, None));
        let gap = f.sign_entry(active_entry(3, 20, Some(&one)));
        let head = f.sign_checkpoint(QRunV06HistoricalTrustCheckpoint {
            sequence: 2,
            network_id: NETWORK,
            profile_id: PROFILE,
            head_entry_id: gap.entry_id().unwrap(),
            published_at_height: 19,
        });
        let bad = QRunV06HistoricalTrustHistorySnapshot {
            entries: vec![one.clone(), gap],
            checkpoint: head,
        };
        assert!(matches!(
            verify_qrun_v06_historical_trust_history(
                &bad,
                &bad.checkpoint,
                &f.authority,
                &f.verifier,
                &NETWORK,
                &PROFILE,
            ),
            Err(QRunV06HistoricalTrustError::SequenceGap)
        ));

        let revoked = f.sign_entry(revoked_entry(2, 20, &one));
        let successor = f.sign_entry(active_entry(3, 30, Some(&revoked)));
        let head = f.sign_checkpoint(QRunV06HistoricalTrustCheckpoint {
            sequence: 3,
            network_id: NETWORK,
            profile_id: PROFILE,
            head_entry_id: successor.entry_id().unwrap(),
            published_at_height: 29,
        });
        let bad = QRunV06HistoricalTrustHistorySnapshot {
            entries: vec![one, revoked, successor],
            checkpoint: head,
        };
        assert!(matches!(
            verify_qrun_v06_historical_trust_history(
                &bad,
                &bad.checkpoint,
                &f.authority,
                &f.verifier,
                &NETWORK,
                &PROFILE,
            ),
            Err(QRunV06HistoricalTrustError::RevokedPredecessor)
        ));
    }
    #[test]
    fn cp0546_replay_uses_checkpoint_published_before_each_block_height() {
        let f = Fixture::new();
        let one = f.sign_entry(active_entry(1, 10, None));
        let cp_one = f.sign_checkpoint(QRunV06HistoricalTrustCheckpoint {
            sequence: 1,
            network_id: NETWORK,
            profile_id: PROFILE,
            head_entry_id: one.entry_id().unwrap(),
            published_at_height: 9,
        });
        let prefix_one = QRunV06HistoricalTrustHistorySnapshot {
            entries: vec![one.clone()],
            checkpoint: cp_one,
        };
        let verified_one = verify_qrun_v06_historical_trust_history(
            &prefix_one,
            &prefix_one.checkpoint,
            &f.authority,
            &f.verifier,
            &NETWORK,
            &PROFILE,
        )
        .unwrap();
        assert_eq!(
            verified_one.entry_for_height(19).unwrap().0.record.sequence,
            1
        );

        let two = f.sign_entry(active_entry(2, 20, Some(&one)));
        let cp_two = f.sign_checkpoint(QRunV06HistoricalTrustCheckpoint {
            sequence: 2,
            network_id: NETWORK,
            profile_id: PROFILE,
            head_entry_id: two.entry_id().unwrap(),
            published_at_height: 19,
        });
        let prefix_two = QRunV06HistoricalTrustHistorySnapshot {
            entries: vec![one.clone(), two.clone()],
            checkpoint: cp_two,
        };
        let verified_two = verify_qrun_v06_historical_trust_history(
            &prefix_two,
            &prefix_two.checkpoint,
            &f.authority,
            &f.verifier,
            &NETWORK,
            &PROFILE,
        )
        .unwrap();
        assert_eq!(
            verified_two.entry_for_height(20).unwrap().0.record.sequence,
            2
        );

        let late_checkpoint = f.sign_checkpoint(QRunV06HistoricalTrustCheckpoint {
            sequence: 1,
            network_id: NETWORK,
            profile_id: PROFILE,
            head_entry_id: one.entry_id().unwrap(),
            published_at_height: 10,
        });
        let backdated = QRunV06HistoricalTrustHistorySnapshot {
            entries: vec![one],
            checkpoint: late_checkpoint,
        };
        assert_eq!(
            verify_qrun_v06_historical_trust_history(
                &backdated,
                &backdated.checkpoint,
                &f.authority,
                &f.verifier,
                &NETWORK,
                &PROFILE,
            ),
            Err(QRunV06HistoricalTrustError::CheckpointNotPrepublished)
        );
    }
}
