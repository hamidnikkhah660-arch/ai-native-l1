//! CP-0417 candidate: explicit, no-fallback block-family dispatch contract.
//!
//! This module is intentionally not wired to a live node. It selects one decoder family
//! from a configured height schedule and the first four bytes; the chosen family decoder
//! must still validate canonical encoding and then call `verify_identity` with the decoded
//! network / Genesis / policy-profile identity. It never tries a second decoder on failure.
//! All epochs and identity pins are explicit: there is no production activation default.

use std::fmt;

const MAGIC_LEN: usize = 4;
const MAX_ACTIVATION_EPOCHS: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolFamily {
    LegacyBlk2,
    MonetaryPmt3,
    HybridPmt4,
    QzbeV04,
}

/// Context pinned for one protocol epoch, to be checked against the result of its only decoder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProfileIdentity {
    pub network_id: [u8; 32],
    pub genesis_hash: [u8; 32],
    pub policy_profile_fingerprint: [u8; 32],
}

impl ProfileIdentity {
    fn validate(&self) -> Result<(), DispatchError> {
        if self.network_id == [0; 32] {
            return Err(DispatchError::ZeroNetworkId);
        }
        if self.genesis_hash == [0; 32] {
            return Err(DispatchError::ZeroGenesisHash);
        }
        if self.policy_profile_fingerprint == [0; 32] {
            return Err(DispatchError::ZeroProfileFingerprint);
        }
        Ok(())
    }
}

/// Epoch start is inclusive. The first epoch must start at height zero; later entries
/// replace the active family exactly at their start height.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ActivationEpoch {
    pub start_height: u64,
    pub family: ProtocolFamily,
    pub identity: ProfileIdentity,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeDispatchConfig {
    epochs: Vec<ActivationEpoch>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DispatchDecision {
    pub family: ProtocolFamily,
    pub epoch_start_height: u64,
    pub expected_identity: ProfileIdentity,
}

impl DispatchDecision {
    /// Call after the single selected decoder has parsed the family-specific identity fields.
    pub fn verify_identity(&self, observed: ProfileIdentity) -> Result<(), DispatchError> {
        if observed != self.expected_identity {
            return Err(DispatchError::ProfileIdentityMismatch);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DispatchError {
    EmptyActivationSchedule,
    TooManyActivationEpochs,
    FirstEpochMustStartAtGenesis,
    ActivationHeightsNotStrictlyIncreasing,
    AdjacentEpochRepeatsFamily,
    ZeroNetworkId,
    ZeroGenesisHash,
    ZeroProfileFingerprint,
    InputTooShort,
    UnknownMagic([u8; MAGIC_LEN]),
    NonBlockObject([u8; MAGIC_LEN]),
    InnerBlockRequiresPowEnvelope,
    WrongProtocolFamily {
        height: u64,
        expected: ProtocolFamily,
        observed: ProtocolFamily,
    },
    ProfileIdentityMismatch,
}

impl fmt::Display for DispatchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for DispatchError {}

impl RuntimeDispatchConfig {
    /// Construct only from an explicit, reviewed activation schedule. No implicit default exists.
    pub fn new(epochs: Vec<ActivationEpoch>) -> Result<Self, DispatchError> {
        if epochs.is_empty() {
            return Err(DispatchError::EmptyActivationSchedule);
        }
        if epochs.len() > MAX_ACTIVATION_EPOCHS {
            return Err(DispatchError::TooManyActivationEpochs);
        }
        if epochs[0].start_height != 0 {
            return Err(DispatchError::FirstEpochMustStartAtGenesis);
        }

        for (index, epoch) in epochs.iter().enumerate() {
            epoch.identity.validate()?;
            if index == 0 {
                continue;
            }
            let previous = epochs[index - 1];
            if epoch.start_height <= previous.start_height {
                return Err(DispatchError::ActivationHeightsNotStrictlyIncreasing);
            }
            if epoch.family == previous.family {
                return Err(DispatchError::AdjacentEpochRepeatsFamily);
            }
        }

        Ok(Self { epochs })
    }

    /// Classify once, select the one family active at `height`, and reject all mismatches.
    /// The returned identity pin must be checked after decoding; the dispatcher never decodes.
    pub fn select(&self, height: u64, bytes: &[u8]) -> Result<DispatchDecision, DispatchError> {
        let observed = classify_block_family(bytes)?;
        let epoch = self
            .epochs
            .iter()
            .rev()
            .find(|epoch| epoch.start_height <= height)
            .ok_or(DispatchError::EmptyActivationSchedule)?;

        if observed != epoch.family {
            return Err(DispatchError::WrongProtocolFamily {
                height,
                expected: epoch.family,
                observed,
            });
        }

        Ok(DispatchDecision {
            family: epoch.family,
            epoch_start_height: epoch.start_height,
            expected_identity: epoch.identity,
        })
    }

    pub fn epochs(&self) -> &[ActivationEpoch] {
        &self.epochs
    }
}

/// Recognize network block envelopes. Raw QZB4 bodies and QZP4 snapshots are not network
/// envelopes and cannot be sent to a block-family decoder via this entry point.
fn classify_block_family(bytes: &[u8]) -> Result<ProtocolFamily, DispatchError> {
    if bytes.len() < MAGIC_LEN {
        return Err(DispatchError::InputTooShort);
    }
    let magic = [bytes[0], bytes[1], bytes[2], bytes[3]];

    match &magic {
        b"BLK2" => Ok(ProtocolFamily::LegacyBlk2),
        b"PMT3" => Ok(ProtocolFamily::MonetaryPmt3),
        b"PMT4" => Ok(ProtocolFamily::HybridPmt4),
        b"QZBE" => Ok(ProtocolFamily::QzbeV04),
        b"QZB4" => Err(DispatchError::InnerBlockRequiresPowEnvelope),
        b"QZP4" | b"QZGM" | b"QZCP" | b"QZL4" => Err(DispatchError::NonBlockObject(magic)),
        _ => Err(DispatchError::UnknownMagic(magic)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity(seed: u8) -> ProfileIdentity {
        ProfileIdentity {
            network_id: [seed; 32],
            genesis_hash: [seed.wrapping_add(1); 32],
            policy_profile_fingerprint: [seed.wrapping_add(2); 32],
        }
    }

    fn config() -> RuntimeDispatchConfig {
        RuntimeDispatchConfig::new(vec![
            ActivationEpoch {
                start_height: 0,
                family: ProtocolFamily::LegacyBlk2,
                identity: identity(1),
            },
            ActivationEpoch {
                start_height: 40,
                family: ProtocolFamily::MonetaryPmt3,
                identity: identity(4),
            },
            ActivationEpoch {
                start_height: 90,
                family: ProtocolFamily::QzbeV04,
                identity: identity(7),
            },
        ])
        .unwrap()
    }

    #[test]
    fn chooses_exact_family_at_inclusive_activation_boundaries() {
        assert_eq!(
            config().select(0, b"BLK2data").unwrap().family,
            ProtocolFamily::LegacyBlk2
        );
        assert_eq!(
            config().select(39, b"BLK2data").unwrap().family,
            ProtocolFamily::LegacyBlk2
        );
        let pmt3 = config().select(40, b"PMT3data").unwrap();
        assert_eq!(pmt3.family, ProtocolFamily::MonetaryPmt3);
        assert_eq!(pmt3.epoch_start_height, 40);
        assert_eq!(
            config().select(89, b"PMT3data").unwrap().family,
            ProtocolFamily::MonetaryPmt3
        );
        let qzbe = config().select(90, b"QZBEdata").unwrap();
        assert_eq!(qzbe.family, ProtocolFamily::QzbeV04);
        assert_eq!(qzbe.epoch_start_height, 90);
    }

    #[test]
    fn old_family_is_rejected_after_activation_without_fallback() {
        assert_eq!(
            config().select(90, b"PMT4data"),
            Err(DispatchError::WrongProtocolFamily {
                height: 90,
                expected: ProtocolFamily::QzbeV04,
                observed: ProtocolFamily::HybridPmt4,
            })
        );
    }

    #[test]
    fn identity_must_match_the_selected_epoch_after_its_only_decoder() {
        let decision = config().select(90, b"QZBEdata").unwrap();
        assert_eq!(decision.verify_identity(identity(7)), Ok(()));
        assert_eq!(
            decision.verify_identity(identity(4)),
            Err(DispatchError::ProfileIdentityMismatch)
        );
    }

    #[test]
    fn refuses_empty_or_implicit_activation_schedule() {
        assert_eq!(
            RuntimeDispatchConfig::new(vec![]),
            Err(DispatchError::EmptyActivationSchedule)
        );
        assert_eq!(
            RuntimeDispatchConfig::new(vec![ActivationEpoch {
                start_height: 1,
                family: ProtocolFamily::QzbeV04,
                identity: identity(1),
            }]),
            Err(DispatchError::FirstEpochMustStartAtGenesis)
        );
    }

    #[test]
    fn activation_schedule_must_be_strict_and_not_redundant() {
        let base = ActivationEpoch {
            start_height: 0,
            family: ProtocolFamily::LegacyBlk2,
            identity: identity(1),
        };
        assert_eq!(
            RuntimeDispatchConfig::new(vec![
                base,
                ActivationEpoch {
                    start_height: 0,
                    family: ProtocolFamily::QzbeV04,
                    identity: identity(4)
                },
            ]),
            Err(DispatchError::ActivationHeightsNotStrictlyIncreasing)
        );
        assert_eq!(
            RuntimeDispatchConfig::new(vec![
                base,
                ActivationEpoch {
                    start_height: 4,
                    family: ProtocolFamily::LegacyBlk2,
                    identity: identity(4)
                },
            ]),
            Err(DispatchError::AdjacentEpochRepeatsFamily)
        );
    }

    #[test]
    fn rejects_truncated_unknown_and_non_block_inputs() {
        assert_eq!(config().select(0, b"QZ"), Err(DispatchError::InputTooShort));
        assert_eq!(
            config().select(0, b"NOPEdata"),
            Err(DispatchError::UnknownMagic(*b"NOPE"))
        );
        assert_eq!(
            config().select(90, b"QZP4snapshot"),
            Err(DispatchError::NonBlockObject(*b"QZP4"))
        );
        assert_eq!(
            config().select(90, b"QZB4body"),
            Err(DispatchError::InnerBlockRequiresPowEnvelope)
        );
    }

    #[test]
    fn validates_all_identity_pins_at_construction() {
        let mut bad = identity(1);
        bad.network_id = [0; 32];
        assert_eq!(
            RuntimeDispatchConfig::new(vec![ActivationEpoch {
                start_height: 0,
                family: ProtocolFamily::LegacyBlk2,
                identity: bad,
            }]),
            Err(DispatchError::ZeroNetworkId)
        );
    }
}
