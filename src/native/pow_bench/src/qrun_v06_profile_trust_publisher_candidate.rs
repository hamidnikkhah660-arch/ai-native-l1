//! CP-0571 Q6TS control-plane publication coordinator.
//!
//! Publication is deliberately ordered: verify the signed envelope and advance the independently
//! administered monotonic floor first, publish the exact bytes second, then read back and compare
//! the exact bytes. A failed publication leaves the floor advanced; retrying the same envelope is
//! idempotent and safe. This module defines the control-plane workflow, not an HTTP server or a
//! deployed authority. Publisher/source transports and the floor backend must be independently
//! operated and authenticated in deployment.

use crate::qrun_v06_profile_trust_candidate::{
    prepublish_qrun_v06_profile_trust_floor, MonotonicQRunV06ProfileTrustFloorStore,
    PinnedQRunV06ProfileTrustAuthority, QRunV06ProfileTrustError, QRunV06ProfileTrustSource,
    QRunV06SignedProfileTrustEnvelope, TrustedQRunV06ProfileTrustFloor,
};
use crate::v4_fat1_trust_candidate::MlDsa65Verifier;
use std::fmt;

pub trait QRunV06ProfileTrustPublisher {
    type Error: fmt::Display;

    fn publish_signed_record(
        &mut self,
        network_id: &[u8; 32],
        profile_id: &[u8; 32],
        envelope_bytes: &[u8],
    ) -> Result<(), Self::Error>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QRunV06ProfileTrustPublicationError {
    Trust(QRunV06ProfileTrustError),
    Publish(String),
    Readback(String),
    ReadbackMismatch,
}

impl fmt::Display for QRunV06ProfileTrustPublicationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Q6TS publication failed: {self:?}")
    }
}
impl std::error::Error for QRunV06ProfileTrustPublicationError {}

impl From<QRunV06ProfileTrustError> for QRunV06ProfileTrustPublicationError {
    fn from(value: QRunV06ProfileTrustError) -> Self {
        Self::Trust(value)
    }
}

/// Advance the independent floor before publishing. The source read-back must return the exact
/// signed envelope, not merely a matching epoch or record ID. Retrying after a publication or
/// read-back failure is safe with the same bytes because prepublication accepts the exact head.
pub fn publish_qrun_v06_profile_trust_envelope<S, V, P, T>(
    envelope_bytes: &[u8],
    authority: &PinnedQRunV06ProfileTrustAuthority,
    pq_verifier: &V,
    floor_store: &mut S,
    publisher: &mut P,
    source: &mut T,
) -> Result<TrustedQRunV06ProfileTrustFloor, QRunV06ProfileTrustPublicationError>
where
    S: MonotonicQRunV06ProfileTrustFloorStore,
    V: MlDsa65Verifier,
    P: QRunV06ProfileTrustPublisher,
    T: QRunV06ProfileTrustSource,
{
    let envelope = QRunV06SignedProfileTrustEnvelope::decode(envelope_bytes)?;
    let network_id = envelope.record.network_id;
    let profile_id = envelope.record.profile_id;

    let floor = prepublish_qrun_v06_profile_trust_floor(
        envelope_bytes,
        authority,
        pq_verifier,
        floor_store,
    )?;

    publisher
        .publish_signed_record(&network_id, &profile_id, envelope_bytes)
        .map_err(|error| QRunV06ProfileTrustPublicationError::Publish(error.to_string()))?;

    let observed = source
        .read_current_signed_record(&network_id, &profile_id)
        .map_err(|error| QRunV06ProfileTrustPublicationError::Readback(error.to_string()))?;
    if observed != envelope_bytes {
        return Err(QRunV06ProfileTrustPublicationError::ReadbackMismatch);
    }

    Ok(floor)
}
