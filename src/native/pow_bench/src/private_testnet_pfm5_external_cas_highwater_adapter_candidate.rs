use crate::{
    external_cas_anchor_candidate::ExternalCasPin,
    private_testnet_pfm5_external_cas_highwater_candidate::{
        Pfm5ExternalCasHighWaterAuthorityPin, Pfm5ExternalCasHighWaterProvider,
        Pfm5ExternalCasHighWaterState,
    },
    private_testnet_pfm5_external_cas_highwater_wire_candidate::{
        Pfm5ExternalCasHighWaterAuthorityVerifierPin, Pfm5ExternalCasHighWaterSignedResponseV1,
        Pfm5ExternalCasHighWaterWireV1,
    },
    v4_fat1_trust_candidate::MlDsa65Verifier,
};
use std::fmt;

/// Transport boundary only. A production implementation must provide linearizable,
/// durable compare-and-advance outside the node's rollback domain.
pub trait Pfm5AuthenticatedHighWaterTransport {
    type Error: fmt::Display;

    fn read(
        &mut self,
        challenge: [u8; 32],
    ) -> Result<Pfm5ExternalCasHighWaterSignedResponseV1, Self::Error>;

    fn compare_and_advance(
        &mut self,
        challenge: [u8; 32],
        expected_state_digest: [u8; 32],
        next_wire_state: Vec<u8>,
    ) -> Result<Pfm5ExternalCasHighWaterSignedResponseV1, Self::Error>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Pfm5AuthenticatedHighWaterAdapterError {
    RandomnessUnavailable,
    InvalidState,
    InvalidSuccessor,
    AuthenticationFailed,
    Transport(String),
    Conflict,
    ReadbackMismatch,
}
impl fmt::Display for Pfm5AuthenticatedHighWaterAdapterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for Pfm5AuthenticatedHighWaterAdapterError {}

/// Verifies every remote response before exposing state to the PFM5 coordinator.
/// Challenges are generated from the operating-system CSPRNG for each operation.
pub struct Pfm5AuthenticatedHighWaterAdapter<T, V> {
    transport: T,
    authority: Pfm5ExternalCasHighWaterAuthorityPin,
    authority_verifier_pin: Pfm5ExternalCasHighWaterAuthorityVerifierPin,
    provider_pin: ExternalCasPin,
    verifier: V,
}
impl<T, V> Pfm5AuthenticatedHighWaterAdapter<T, V>
where
    T: Pfm5AuthenticatedHighWaterTransport,
    V: MlDsa65Verifier,
{
    pub fn new(
        transport: T,
        authority: Pfm5ExternalCasHighWaterAuthorityPin,
        authority_verifier_pin: Pfm5ExternalCasHighWaterAuthorityVerifierPin,
        provider_pin: ExternalCasPin,
        verifier: V,
    ) -> Self {
        Self {
            transport,
            authority,
            authority_verifier_pin,
            provider_pin,
            verifier,
        }
    }

    pub fn into_transport(self) -> T {
        self.transport
    }

    fn fresh_challenge() -> Result<[u8; 32], Pfm5AuthenticatedHighWaterAdapterError> {
        let mut challenge = [0u8; 32];
        getrandom::getrandom(&mut challenge)
            .map_err(|_| Pfm5AuthenticatedHighWaterAdapterError::RandomnessUnavailable)?;
        if challenge.iter().all(|byte| *byte == 0) {
            return Err(Pfm5AuthenticatedHighWaterAdapterError::RandomnessUnavailable);
        }
        Ok(challenge)
    }

    fn verified_read(
        &mut self,
    ) -> Result<Pfm5ExternalCasHighWaterState, Pfm5AuthenticatedHighWaterAdapterError> {
        let challenge = Self::fresh_challenge()?;
        let response = self.transport.read(challenge).map_err(|error| {
            Pfm5AuthenticatedHighWaterAdapterError::Transport(error.to_string())
        })?;
        let wire = response
            .verify(
                &challenge,
                &self.authority,
                &self.authority_verifier_pin,
                &self.provider_pin,
                &self.verifier,
            )
            .map_err(|_| Pfm5AuthenticatedHighWaterAdapterError::AuthenticationFailed)?;
        Ok(wire.state)
    }
}

impl<T, V> Pfm5ExternalCasHighWaterProvider for Pfm5AuthenticatedHighWaterAdapter<T, V>
where
    T: Pfm5AuthenticatedHighWaterTransport,
    V: MlDsa65Verifier,
{
    type Error = Pfm5AuthenticatedHighWaterAdapterError;

    fn read_authenticated(
        &mut self,
        authority: &Pfm5ExternalCasHighWaterAuthorityPin,
        pin: &ExternalCasPin,
    ) -> Result<Pfm5ExternalCasHighWaterState, Self::Error> {
        if authority != &self.authority || pin != &self.provider_pin {
            return Err(Pfm5AuthenticatedHighWaterAdapterError::InvalidState);
        }
        let state = self.verified_read()?;
        state
            .validate(authority, pin)
            .map_err(|_| Pfm5AuthenticatedHighWaterAdapterError::InvalidState)?;
        Ok(state)
    }

    fn compare_and_advance(
        &mut self,
        authority: &Pfm5ExternalCasHighWaterAuthorityPin,
        pin: &ExternalCasPin,
        expected: &Pfm5ExternalCasHighWaterState,
        next: &Pfm5ExternalCasHighWaterState,
    ) -> Result<(), Self::Error> {
        if authority != &self.authority || pin != &self.provider_pin {
            return Err(Pfm5AuthenticatedHighWaterAdapterError::InvalidState);
        }
        expected
            .validate(authority, pin)
            .and_then(|_| next.validate(authority, pin))
            .map_err(|_| Pfm5AuthenticatedHighWaterAdapterError::InvalidState)?;

        let sequence_advances_once =
            expected.journal_sequence.checked_add(1) == Some(next.journal_sequence);
        // Prepared preserves ECR1/object generation; Finalized advances both.
        let prepared_transition =
            expected.record == next.record && expected.object_generation == next.object_generation;
        let finalized_transition = expected.object_generation < next.object_generation
            && expected.record.validate_successor(&next.record).is_ok();
        if !sequence_advances_once || !(prepared_transition || finalized_transition) {
            return Err(Pfm5AuthenticatedHighWaterAdapterError::InvalidSuccessor);
        }

        let expected_wire = Pfm5ExternalCasHighWaterWireV1::from_state(expected, authority, pin)
            .map_err(|_| Pfm5AuthenticatedHighWaterAdapterError::InvalidState)?;
        let next_wire = Pfm5ExternalCasHighWaterWireV1::from_state(next, authority, pin)
            .map_err(|_| Pfm5AuthenticatedHighWaterAdapterError::InvalidState)?;
        let challenge = Self::fresh_challenge()?;
        let cas_result = self.transport.compare_and_advance(
            challenge,
            expected_wire.state_digest(),
            next_wire.encode(),
        );
        match cas_result {
            Ok(response) => {
                let observed = response
                    .verify(
                        &challenge,
                        authority,
                        &self.authority_verifier_pin,
                        pin,
                        &self.verifier,
                    )
                    .map_err(|_| Pfm5AuthenticatedHighWaterAdapterError::AuthenticationFailed)?;
                if observed.state != *next {
                    return Err(Pfm5AuthenticatedHighWaterAdapterError::ReadbackMismatch);
                }
                Ok(())
            }
            Err(cas_error) => {
                // Resolve an ambiguous reply only through a fresh authenticated read.
                let observed = self.verified_read()?;
                if observed == *next {
                    return Ok(());
                }
                if observed == *expected {
                    return Err(Pfm5AuthenticatedHighWaterAdapterError::Transport(
                        cas_error.to_string(),
                    ));
                }
                Err(Pfm5AuthenticatedHighWaterAdapterError::Conflict)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        external_cas_anchor_candidate::ExternalCasRecord,
        v4_fat1_mldsa65_candidate::LibcruxMlDsa65VerifierCandidate,
        v4_fat1_trust_candidate::{ML_DSA_65_PUBLIC_KEY_BYTES, ML_DSA_65_SIGNATURE_BYTES},
    };
    use libcrux_ml_dsa::ml_dsa_65::portable;

    struct SigningTransport {
        authority: Pfm5ExternalCasHighWaterAuthorityPin,
        provider: ExternalCasPin,
        state: Pfm5ExternalCasHighWaterState,
        key_id: [u8; 32],
        key_generation: u64,
        signing_key: libcrux_ml_dsa::ml_dsa_65::MLDSA65SigningKey,
        tamper_signature: bool,
        seen_challenges: Vec<[u8; 32]>,
    }

    impl SigningTransport {
        fn response(&mut self, challenge: [u8; 32]) -> Pfm5ExternalCasHighWaterSignedResponseV1 {
            let wire = Pfm5ExternalCasHighWaterWireV1::from_state(
                &self.state,
                &self.authority,
                &self.provider,
            )
            .unwrap();
            let mut response = Pfm5ExternalCasHighWaterSignedResponseV1 {
                challenge,
                key_id: self.key_id,
                key_generation: self.key_generation,
                wire_state: wire.encode(),
                signature: [0; ML_DSA_65_SIGNATURE_BYTES],
            };
            let digest = response.signing_digest();
            response.signature = *portable::sign(&self.signing_key, &digest, &[], [0x74; 32])
                .unwrap()
                .as_ref();
            if self.tamper_signature {
                response.signature[0] ^= 1;
            }
            response
        }
    }

    impl Pfm5AuthenticatedHighWaterTransport for SigningTransport {
        type Error = &'static str;

        fn read(
            &mut self,
            challenge: [u8; 32],
        ) -> Result<Pfm5ExternalCasHighWaterSignedResponseV1, Self::Error> {
            self.seen_challenges.push(challenge);
            Ok(self.response(challenge))
        }

        fn compare_and_advance(
            &mut self,
            challenge: [u8; 32],
            expected_state_digest: [u8; 32],
            next_wire_state: Vec<u8>,
        ) -> Result<Pfm5ExternalCasHighWaterSignedResponseV1, Self::Error> {
            self.seen_challenges.push(challenge);
            let current = Pfm5ExternalCasHighWaterWireV1::from_state(
                &self.state,
                &self.authority,
                &self.provider,
            )
            .unwrap();
            if current.state_digest() != expected_state_digest {
                return Err("CAS conflict");
            }
            let next = Pfm5ExternalCasHighWaterWireV1::decode(
                &next_wire_state,
                &self.authority,
                &self.provider,
            )
            .unwrap();
            self.state = next.state;
            Ok(self.response(challenge))
        }
    }

    fn adapter_fixture(
        tamper_signature: bool,
    ) -> (
        Pfm5AuthenticatedHighWaterAdapter<SigningTransport, LibcruxMlDsa65VerifierCandidate>,
        Pfm5ExternalCasHighWaterAuthorityPin,
        ExternalCasPin,
    ) {
        let authority = Pfm5ExternalCasHighWaterAuthorityPin {
            authority_id: [0xA1; 32],
        };
        let provider = ExternalCasPin {
            provider_id: [0x11; 32],
            network_id: [0x22; 32],
            genesis_digest: [0x33; 32],
            receipt_key_id: [0x44; 32],
            receipt_public_key: [0x55; ML_DSA_65_PUBLIC_KEY_BYTES],
        };
        let state = Pfm5ExternalCasHighWaterState {
            authority_id: authority.authority_id,
            provider_id: provider.provider_id,
            network_id: provider.network_id,
            genesis_digest: provider.genesis_digest,
            journal_sequence: 9,
            record: ExternalCasRecord {
                generation: 7,
                provider_id: provider.provider_id,
                network_id: provider.network_id,
                genesis_digest: provider.genesis_digest,
                previous_record_digest: [0x61; 32],
                previous_state_digest: [0x62; 32],
                next_state_digest: [0x63; 32],
                operation_id: [0x64; 32],
                request_digest: [0x65; 32],
            },
            object_generation: 40,
        };
        let pair = portable::generate_key_pair([0x71; 32]);
        let public_key: [u8; ML_DSA_65_PUBLIC_KEY_BYTES] = *pair.verification_key.as_ref();
        let key_id = [0x72; 32];
        let key_generation = 1;
        let verifier_pin = Pfm5ExternalCasHighWaterAuthorityVerifierPin {
            authority_id: authority.authority_id,
            key_id,
            key_generation,
            public_key,
        };
        let transport = SigningTransport {
            authority: authority.clone(),
            provider: provider.clone(),
            state,
            key_id,
            key_generation,
            signing_key: pair.signing_key,
            tamper_signature,
            seen_challenges: Vec::new(),
        };
        (
            Pfm5AuthenticatedHighWaterAdapter::new(
                transport,
                authority.clone(),
                verifier_pin,
                provider.clone(),
                LibcruxMlDsa65VerifierCandidate,
            ),
            authority,
            provider,
        )
    }

    #[test]
    fn adapter_returns_state_only_after_real_signature_verification() {
        let (mut adapter, authority, provider) = adapter_fixture(false);
        let state = adapter.read_authenticated(&authority, &provider).unwrap();
        assert_eq!(state.journal_sequence, 9);
        let transport = adapter.into_transport();
        assert_eq!(transport.seen_challenges.len(), 1);
        assert_ne!(transport.seen_challenges[0], [0; 32]);
    }

    #[test]
    fn adapter_rejects_tampered_signature_before_exposing_state() {
        let (mut adapter, authority, provider) = adapter_fixture(true);
        assert_eq!(
            adapter.read_authenticated(&authority, &provider),
            Err(Pfm5AuthenticatedHighWaterAdapterError::AuthenticationFailed),
        );
    }

    #[test]
    fn adapter_rejects_wrong_authority_before_transport_io() {
        let (mut adapter, mut authority, provider) = adapter_fixture(false);
        authority.authority_id[0] ^= 1;
        assert_eq!(
            adapter.read_authenticated(&authority, &provider),
            Err(Pfm5AuthenticatedHighWaterAdapterError::InvalidState),
        );
        assert!(adapter.into_transport().seen_challenges.is_empty());
    }

    #[test]
    fn adapter_response_binds_fresh_challenge_per_read() {
        let (mut adapter, authority, provider) = adapter_fixture(false);
        adapter.read_authenticated(&authority, &provider).unwrap();
        adapter.read_authenticated(&authority, &provider).unwrap();
        let transport = adapter.into_transport();
        assert_eq!(transport.seen_challenges.len(), 2);
        assert_ne!(transport.seen_challenges[0], transport.seen_challenges[1]);
    }

    #[test]
    fn adapter_accepts_prepared_transition_without_advancing_record_or_object_generation() {
        let (mut adapter, authority, provider) = adapter_fixture(false);
        let expected = adapter.read_authenticated(&authority, &provider).unwrap();
        let mut prepared = expected.clone();
        prepared.journal_sequence += 1;
        Pfm5ExternalCasHighWaterProvider::compare_and_advance(
            &mut adapter,
            &authority,
            &provider,
            &expected,
            &prepared,
        )
        .unwrap();
        let observed = adapter.read_authenticated(&authority, &provider).unwrap();
        assert_eq!(observed, prepared);
        assert_eq!(observed.record, expected.record);
        assert_eq!(observed.object_generation, expected.object_generation);
    }
}
