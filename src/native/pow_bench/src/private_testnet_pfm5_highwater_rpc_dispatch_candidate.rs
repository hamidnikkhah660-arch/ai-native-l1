//! CP-0402 fail-closed, READ-only QHWR dispatcher core.
//!
//! Not a listener or production service. Integrators must provide an independently qualified
//! provider, durable one-time replay ledger, and isolated signer. COMPARE_AND_ADVANCE is rejected
//! until its independent provider and durable replay path have been separately qualified.
//! Noise peer authentication is performed by the caller.

use crate::{
    external_cas_anchor_candidate::ExternalCasPin,
    private_testnet_pfm5_external_cas_highwater_candidate::{
        Pfm5ExternalCasHighWaterAuthorityPin, Pfm5ExternalCasHighWaterProvider,
    },
    private_testnet_pfm5_external_cas_highwater_wire_candidate::{
        Pfm5ExternalCasHighWaterSignedResponseV1, Pfm5ExternalCasHighWaterWireV1,
        PFM5_HIGHWATER_RESPONSE_SIGNING_DOMAIN,
    },
    private_testnet_pfm5_highwater_rpc_wire_candidate::{
        QhwrErrorStatus, QhwrOperation, QhwrRequest, QhwrResponse,
    },
    v4_fat1_trust_candidate::ML_DSA_65_SIGNATURE_BYTES,
};
use sha2::{Digest, Sha256};
use std::fmt;

/// Production implementations must use durable, atomic, cross-process storage.
/// Ok(true) reserves a new peer/challenge pair; Ok(false) means replay.
pub trait QhwrDurableReplayLedger {
    type Error: fmt::Display;
    fn reserve_once(
        &mut self,
        authenticated_peer: &[u8; 32],
        challenge: &[u8; 32],
    ) -> Result<bool, Self::Error>;
}

/// Signing key material remains behind this interface; implementations must isolate custody.
pub trait QhwrResponseSigner {
    type Error: fmt::Display;
    fn key_id(&self) -> [u8; 32];
    fn key_generation(&self) -> u64;
    fn sign_digest(
        &mut self,
        digest: &[u8; 32],
    ) -> Result<[u8; ML_DSA_65_SIGNATURE_BYTES], Self::Error>;
}

#[derive(Debug)]
pub enum QhwrDispatchError {
    Codec,
    Provider(String),
    ReplayLedger(String),
    Signer(String),
}
impl fmt::Display for QhwrDispatchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Codec => f.write_str("QHWR dispatcher codec failure"),
            Self::Provider(error) => write!(f, "QHWR provider unavailable: {error}"),
            Self::ReplayLedger(error) => write!(f, "QHWR replay ledger unavailable: {error}"),
            Self::Signer(error) => write!(f, "QHWR response signer unavailable: {error}"),
        }
    }
}
impl std::error::Error for QhwrDispatchError {}

fn error_response(status: QhwrErrorStatus) -> Result<Vec<u8>, QhwrDispatchError> {
    QhwrResponse::Error(status)
        .encode()
        .map_err(|_| QhwrDispatchError::Codec)
}

/// Dispatch exactly one already Noise-authenticated application request.
///
/// authenticated_peer must be the remote static key returned by DevnetNoiseSession::accept.
/// The connection owner must close the connection after this one request/response. READ only;
/// COMPARE_AND_ADVANCE is rejected without provider, ledger, or signer side effects.
pub fn dispatch_read_only<P, L, S>(
    request_bytes: &[u8],
    authenticated_peer: &[u8; 32],
    trusted_peers: &[[u8; 32]],
    authority: &Pfm5ExternalCasHighWaterAuthorityPin,
    provider_pin: &ExternalCasPin,
    provider: &mut P,
    replay_ledger: &mut L,
    signer: &mut S,
) -> Result<Vec<u8>, QhwrDispatchError>
where
    P: Pfm5ExternalCasHighWaterProvider,
    L: QhwrDurableReplayLedger,
    S: QhwrResponseSigner,
{
    let request = match QhwrRequest::decode(request_bytes) {
        Ok(request) => request,
        Err(_) => return error_response(QhwrErrorStatus::MalformedRequest),
    };
    let challenge = match &request {
        QhwrRequest::Read { challenge } => challenge,
        QhwrRequest::CompareAndAdvance { .. } => {
            return error_response(QhwrErrorStatus::UnsupportedVersionOrOperation);
        }
    };
    if authenticated_peer.iter().all(|byte| *byte == 0)
        || !trusted_peers.iter().any(|peer| peer == authenticated_peer)
    {
        return error_response(QhwrErrorStatus::UnauthorizedPeer);
    }
    match replay_ledger.reserve_once(authenticated_peer, challenge) {
        Ok(true) => {}
        Ok(false) => return error_response(QhwrErrorStatus::ChallengeReplayOrExpired),
        Err(error) => return Err(QhwrDispatchError::ReplayLedger(error.to_string())),
    }
    let state = provider
        .read_authenticated(authority, provider_pin)
        .map_err(|error| QhwrDispatchError::Provider(error.to_string()))?;
    let wire = Pfm5ExternalCasHighWaterWireV1::from_state(&state, authority, provider_pin)
        .map_err(|error| QhwrDispatchError::Provider(format!("{error:?}")))?;
    let mut response = Pfm5ExternalCasHighWaterSignedResponseV1 {
        challenge: *challenge,
        key_id: signer.key_id(),
        key_generation: signer.key_generation(),
        wire_state: wire.encode(),
        signature: [0; ML_DSA_65_SIGNATURE_BYTES],
    };
    if response.key_id.iter().all(|byte| *byte == 0) || response.key_generation == 0 {
        return Err(QhwrDispatchError::Signer(
            "invalid signing key identity".to_owned(),
        ));
    }
    let mut hasher = Sha256::new();
    hasher.update(PFM5_HIGHWATER_RESPONSE_SIGNING_DOMAIN);
    hasher.update(response.challenge);
    hasher.update(response.key_id);
    hasher.update(response.key_generation.to_be_bytes());
    hasher.update((response.wire_state.len() as u64).to_be_bytes());
    hasher.update(&response.wire_state);
    let digest: [u8; 32] = hasher.finalize().into();
    response.signature = signer
        .sign_digest(&digest)
        .map_err(|error| QhwrDispatchError::Signer(error.to_string()))?;
    QhwrResponse::SignedState {
        operation: QhwrOperation::Read,
        response,
    }
    .encode()
    .map_err(|_| QhwrDispatchError::Codec)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::private_testnet_pfm5_highwater_rpc_wire_candidate::{
        QhwrResponse, QHWA_V1_WIRE_BYTES,
    };

    struct NeverProvider;
    impl Pfm5ExternalCasHighWaterProvider for NeverProvider {
        type Error = String;
        fn read_authenticated(
            &mut self,
            _: &Pfm5ExternalCasHighWaterAuthorityPin,
            _: &ExternalCasPin,
        ) -> Result<crate::private_testnet_pfm5_external_cas_highwater_candidate::Pfm5ExternalCasHighWaterState, Self::Error>{
            panic!("provider must not be called for rejected requests")
        }
        fn compare_and_advance(
            &mut self,
            _: &Pfm5ExternalCasHighWaterAuthorityPin,
            _: &ExternalCasPin,
            _: &crate::private_testnet_pfm5_external_cas_highwater_candidate::Pfm5ExternalCasHighWaterState,
            _: &crate::private_testnet_pfm5_external_cas_highwater_candidate::Pfm5ExternalCasHighWaterState,
        ) -> Result<(), Self::Error> {
            panic!("CAS provider must never be called by READ-only dispatcher")
        }
    }
    struct NeverLedger;
    impl QhwrDurableReplayLedger for NeverLedger {
        type Error = String;
        fn reserve_once(&mut self, _: &[u8; 32], _: &[u8; 32]) -> Result<bool, Self::Error> {
            panic!("ledger must not be called for rejected requests")
        }
    }
    struct NeverSigner;
    impl QhwrResponseSigner for NeverSigner {
        type Error = String;
        fn key_id(&self) -> [u8; 32] {
            panic!("signer must not be called")
        }
        fn key_generation(&self) -> u64 {
            panic!("signer must not be called")
        }
        fn sign_digest(
            &mut self,
            _: &[u8; 32],
        ) -> Result<[u8; ML_DSA_65_SIGNATURE_BYTES], Self::Error> {
            panic!("signer must not be called")
        }
    }

    fn pins() -> (Pfm5ExternalCasHighWaterAuthorityPin, ExternalCasPin) {
        use crate::v4_fat1_trust_candidate::ML_DSA_65_PUBLIC_KEY_BYTES;
        (
            Pfm5ExternalCasHighWaterAuthorityPin {
                authority_id: [1; 32],
            },
            ExternalCasPin {
                provider_id: [2; 32],
                network_id: [3; 32],
                genesis_digest: [4; 32],
                receipt_key_id: [5; 32],
                receipt_public_key: [6; ML_DSA_65_PUBLIC_KEY_BYTES],
            },
        )
    }

    #[test]
    fn compare_and_advance_is_rejected_before_any_side_effect() {
        let (authority, pin) = pins();
        let request = QhwrRequest::CompareAndAdvance {
            challenge: [7; 32],
            expected_state_digest: [8; 32],
            next_state_wire: [9; QHWA_V1_WIRE_BYTES],
        }
        .encode()
        .unwrap();
        let response = dispatch_read_only(
            &request,
            &[10; 32],
            &[[10; 32]],
            &authority,
            &pin,
            &mut NeverProvider,
            &mut NeverLedger,
            &mut NeverSigner,
        )
        .unwrap();
        assert_eq!(
            QhwrResponse::decode(&response).unwrap(),
            QhwrResponse::Error(QhwrErrorStatus::UnsupportedVersionOrOperation)
        );
    }

    #[test]
    fn malformed_request_is_rejected_before_any_side_effect() {
        let (authority, pin) = pins();
        let response = dispatch_read_only(
            b"not-qhwr",
            &[10; 32],
            &[[10; 32]],
            &authority,
            &pin,
            &mut NeverProvider,
            &mut NeverLedger,
            &mut NeverSigner,
        )
        .unwrap();
        assert_eq!(
            QhwrResponse::decode(&response).unwrap(),
            QhwrResponse::Error(QhwrErrorStatus::MalformedRequest)
        );
    }

    #[test]
    fn unauthorized_read_is_rejected_before_ledger_provider_or_signer() {
        let (authority, pin) = pins();
        let request = QhwrRequest::Read {
            challenge: [11; 32],
        }
        .encode()
        .unwrap();
        let response = dispatch_read_only(
            &request,
            &[10; 32],
            &[[12; 32]],
            &authority,
            &pin,
            &mut NeverProvider,
            &mut NeverLedger,
            &mut NeverSigner,
        )
        .unwrap();
        assert_eq!(
            QhwrResponse::decode(&response).unwrap(),
            QhwrResponse::Error(QhwrErrorStatus::UnauthorizedPeer)
        );
    }
}

#[cfg(test)]
mod dispatch_path_tests {
    use super::*;
    use crate::private_testnet_pfm5_highwater_rpc_wire_candidate::QHWA_V1_WIRE_BYTES;
    use crate::v4_fat1_trust_candidate::ML_DSA_65_PUBLIC_KEY_BYTES;

    fn pins() -> (Pfm5ExternalCasHighWaterAuthorityPin, ExternalCasPin) {
        (
            Pfm5ExternalCasHighWaterAuthorityPin {
                authority_id: [1; 32],
            },
            ExternalCasPin {
                provider_id: [2; 32],
                network_id: [3; 32],
                genesis_digest: [4; 32],
                receipt_key_id: [5; 32],
                receipt_public_key: [6; ML_DSA_65_PUBLIC_KEY_BYTES],
            },
        )
    }
    struct FixedProvider {
    state:
        crate::private_testnet_pfm5_external_cas_highwater_candidate::Pfm5ExternalCasHighWaterState,
    fail: bool,
}
    impl Pfm5ExternalCasHighWaterProvider for FixedProvider {
        type Error = String;
    fn read_authenticated(
        &mut self,
        _: &Pfm5ExternalCasHighWaterAuthorityPin,
        _: &ExternalCasPin,
    ) -> Result<
        crate::private_testnet_pfm5_external_cas_highwater_candidate::Pfm5ExternalCasHighWaterState,
        Self::Error,
        >{
            if self.fail {
                Err("provider offline".to_owned())
            } else {
                Ok(self.state.clone())
            }
        }
        fn compare_and_advance(
            &mut self,
            _: &Pfm5ExternalCasHighWaterAuthorityPin,
            _: &ExternalCasPin,
            _: &crate::private_testnet_pfm5_external_cas_highwater_candidate::Pfm5ExternalCasHighWaterState,
            _: &crate::private_testnet_pfm5_external_cas_highwater_candidate::Pfm5ExternalCasHighWaterState,
        ) -> Result<(), Self::Error> {
            panic!("READ-only dispatcher must never perform CAS")
        }
    }
    struct FixedLedger {
        result: Result<bool, String>,
        calls: usize,
    }
    impl QhwrDurableReplayLedger for FixedLedger {
        type Error = String;
        fn reserve_once(&mut self, _: &[u8; 32], _: &[u8; 32]) -> Result<bool, Self::Error> {
            self.calls += 1;
            self.result.clone()
        }
    }
    struct FixedSigner {
        fail: bool,
        calls: usize,
        digest: Option<[u8; 32]>,
    }
    impl QhwrResponseSigner for FixedSigner {
        type Error = String;
        fn key_id(&self) -> [u8; 32] {
            [0x72; 32]
        }
        fn key_generation(&self) -> u64 {
            1
        }
        fn sign_digest(
            &mut self,
            digest: &[u8; 32],
        ) -> Result<[u8; ML_DSA_65_SIGNATURE_BYTES], Self::Error> {
            self.calls += 1;
            self.digest = Some(*digest);
            if self.fail {
                Err("signer offline".to_owned())
            } else {
                Ok([0xA5; ML_DSA_65_SIGNATURE_BYTES])
            }
        }
    }
    fn valid_state(
        authority: &Pfm5ExternalCasHighWaterAuthorityPin,
        pin: &ExternalCasPin,
    ) -> crate::private_testnet_pfm5_external_cas_highwater_candidate::Pfm5ExternalCasHighWaterState
    {
        use crate::external_cas_anchor_candidate::ExternalCasRecord;
        crate::private_testnet_pfm5_external_cas_highwater_candidate::Pfm5ExternalCasHighWaterState {
        authority_id: authority.authority_id,
        provider_id: pin.provider_id,
        network_id: pin.network_id,
        genesis_digest: pin.genesis_digest,
        journal_sequence: 9,
        record: ExternalCasRecord {
            generation: 7,
            provider_id: pin.provider_id,
            network_id: pin.network_id,
            genesis_digest: pin.genesis_digest,
            previous_record_digest: [0x61; 32],
            previous_state_digest: [0x62; 32],
            next_state_digest: [0x63; 32],
            operation_id: [0x64; 32],
            request_digest: [0x65; 32],
        },
        object_generation: 40,
    }
    }
    fn read_request(challenge: [u8; 32]) -> Vec<u8> {
        QhwrRequest::Read { challenge }.encode().unwrap()
    }

    #[test]
    fn replayed_challenge_is_rejected_before_provider_or_signer() {
        let (authority, pin) = pins();
        let mut provider = FixedProvider {
            state: valid_state(&authority, &pin),
            fail: false,
        };
        let mut ledger = FixedLedger {
            result: Ok(false),
            calls: 0,
        };
        let mut signer = FixedSigner {
            fail: false,
            calls: 0,
            digest: None,
        };
        let response = dispatch_read_only(
            &read_request([0x31; 32]),
            &[10; 32],
            &[[10; 32]],
            &authority,
            &pin,
            &mut provider,
            &mut ledger,
            &mut signer,
        )
        .unwrap();
        assert_eq!(
            QhwrResponse::decode(&response).unwrap(),
            QhwrResponse::Error(QhwrErrorStatus::ChallengeReplayOrExpired)
        );
        assert_eq!(ledger.calls, 1);
        assert_eq!(signer.calls, 0);
    }

    #[test]
    fn replay_ledger_failure_fails_closed_before_provider_or_signer() {
        let (authority, pin) = pins();
        let mut provider = FixedProvider {
            state: valid_state(&authority, &pin),
            fail: false,
        };
        let mut ledger = FixedLedger {
            result: Err("ledger unavailable".to_owned()),
            calls: 0,
        };
        let mut signer = FixedSigner {
            fail: false,
            calls: 0,
            digest: None,
        };
        let result = dispatch_read_only(
            &read_request([0x32; 32]),
            &[10; 32],
            &[[10; 32]],
            &authority,
            &pin,
            &mut provider,
            &mut ledger,
            &mut signer,
        );
        assert!(matches!(result, Err(QhwrDispatchError::ReplayLedger(_))));
        assert_eq!(ledger.calls, 1);
        assert_eq!(signer.calls, 0);
    }

    #[test]
    fn provider_failure_happens_after_replay_reservation_and_before_signing() {
        let (authority, pin) = pins();
        let mut provider = FixedProvider {
            state: valid_state(&authority, &pin),
            fail: true,
        };
        let mut ledger = FixedLedger {
            result: Ok(true),
            calls: 0,
        };
        let mut signer = FixedSigner {
            fail: false,
            calls: 0,
            digest: None,
        };
        let result = dispatch_read_only(
            &read_request([0x33; 32]),
            &[10; 32],
            &[[10; 32]],
            &authority,
            &pin,
            &mut provider,
            &mut ledger,
            &mut signer,
        );
        assert!(matches!(result, Err(QhwrDispatchError::Provider(_))));
        assert_eq!(ledger.calls, 1);
        assert_eq!(signer.calls, 0);
    }

    #[test]
    fn signer_failure_does_not_return_an_unsigned_state() {
        let (authority, pin) = pins();
        let mut provider = FixedProvider {
            state: valid_state(&authority, &pin),
            fail: false,
        };
        let mut ledger = FixedLedger {
            result: Ok(true),
            calls: 0,
        };
        let mut signer = FixedSigner {
            fail: true,
            calls: 0,
            digest: None,
        };
        let result = dispatch_read_only(
            &read_request([0x34; 32]),
            &[10; 32],
            &[[10; 32]],
            &authority,
            &pin,
            &mut provider,
            &mut ledger,
            &mut signer,
        );
        assert!(matches!(result, Err(QhwrDispatchError::Signer(_))));
        assert_eq!(ledger.calls, 1);
        assert_eq!(signer.calls, 1);
        assert!(signer.digest.is_some());
    }

    #[test]
    fn read_path_returns_challenge_bound_signed_envelope() {
        let (authority, pin) = pins();
        let mut provider = FixedProvider {
            state: valid_state(&authority, &pin),
            fail: false,
        };
        let mut ledger = FixedLedger {
            result: Ok(true),
            calls: 0,
        };
        let mut signer = FixedSigner {
            fail: false,
            calls: 0,
            digest: None,
        };
        let challenge = [0x35; 32];
        let response = dispatch_read_only(
            &read_request(challenge),
            &[10; 32],
            &[[10; 32]],
            &authority,
            &pin,
            &mut provider,
            &mut ledger,
            &mut signer,
        )
        .unwrap();
        match QhwrResponse::decode(&response).unwrap() {
            QhwrResponse::SignedState {
                operation: QhwrOperation::Read,
                response,
            } => {
                assert_eq!(response.challenge, challenge);
                assert_eq!(response.key_id, [0x72; 32]);
                assert_eq!(response.key_generation, 1);
                assert_eq!(response.signature, [0xA5; ML_DSA_65_SIGNATURE_BYTES]);
                assert_eq!(response.wire_state.len(), QHWA_V1_WIRE_BYTES);
                assert_eq!(signer.digest, Some(response.signing_digest()));
            }
            other => panic!("unexpected response: {other:?}"),
        }
        assert_eq!(ledger.calls, 1);
        assert_eq!(signer.calls, 1);
    }
}
