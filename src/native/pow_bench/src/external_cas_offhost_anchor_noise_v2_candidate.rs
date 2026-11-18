//! CP-0767 QAR2/QBT1-bound Noise transport candidate.
//!
//! QAR2 is carried over a separately domain-separated Noise profile and wire envelope.
//! There is deliberately no QAR1 fallback, negotiation, or automatic downgrade path.
//! The QAR2 outer receipt is verified against the exact VerifiedBootstrapTrust capability
//! before the QAP1 adapter exposes its inner QAR1 receipt to the existing coordinator.
use crate::{
    external_cas_anchor_candidate::{
        ExternalCasPin, ExternalCasReceipt, ExternalCasRecord, EXTERNAL_CAS_RECEIPT_BYTES,
        EXTERNAL_CAS_RECORD_BYTES,
    },
    external_cas_bootstrap_trust_candidate::{mldsa65_key_fingerprint, VerifiedBootstrapTrust},
    external_cas_offhost_anchor_noise_transport_candidate::OffhostAnchorNoiseError,
    external_cas_offhost_anchor_protocol_candidate::{
        ExternalCasOffhostAnchorCasRequest, ExternalCasOffhostAnchorPin,
        ExternalCasOffhostAnchorReadRequest, ExternalCasOffhostAnchorReceipt,
    },
    external_cas_offhost_anchor_protocol_v2_candidate::{
        QAR2BootstrapBoundReceipt, QAR2BoundAnchorService, QAR2_RECEIPT_BYTES,
    },
    qrun_v05_noise_transport_candidate::QRunV05NoiseSession,
    qrun_v06_qap1_coordinator_candidate::QRunV06Qap1AnchorTransport,
    v4_fat1_trust_candidate::MlDsa65Verifier,
};
use sha2::{Digest, Sha256};
use std::{
    fmt,
    net::{SocketAddr, TcpStream},
    time::Duration,
};

const REQUEST_MAGIC: &[u8; 4] = b"Q2RQ";
const RESPONSE_MAGIC: &[u8; 4] = b"Q2RS";
const WIRE_VERSION: u16 = 2;
const KIND_READ: u16 = 1;
const KIND_CAS: u16 = 2;
const STATUS_OK: u16 = 0;
const STATUS_REJECTED: u16 = 1;
const REQUEST_HEADER_BYTES: usize = 8;
const RESPONSE_HEADER_BYTES: usize = 10;
const READ_REQUEST_BYTES: usize = 96;
const CAS_FIXED_REQUEST_BYTES: usize = 168;
const CAS_REQUEST_BYTES: usize =
    CAS_FIXED_REQUEST_BYTES + EXTERNAL_CAS_RECORD_BYTES + EXTERNAL_CAS_RECEIPT_BYTES;
const PROFILE_DOMAIN: &[u8] = b"QRUN-OFFHOST-ANCHOR-NOISE-QAR2-QBT1-PROFILE-V2\0";
const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
const IO_TIMEOUT: Duration = Duration::from_secs(20);

fn is_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}

/// Validate that the sealed QBT1 capability is for these exact Provider and Anchor keys,
/// and derive a Noise prologue that cannot match the QAR1 profile or another QBT1 receipt.
pub fn qar2_qbt1_noise_profile_id(
    trust: &VerifiedBootstrapTrust,
    anchor: &ExternalCasOffhostAnchorPin,
    provider: &ExternalCasPin,
) -> Result<[u8; 32], OffhostAnchorNoiseError> {
    anchor
        .validate(provider)
        .map_err(|_| OffhostAnchorNoiseError::InvalidConfiguration)?;
    let receipt = trust.receipt();
    let initial_digest = trust
        .initial_anchor_state()
        .digest()
        .map_err(|_| OffhostAnchorNoiseError::InvalidConfiguration)?;
    if receipt.provider_id != provider.provider_id
        || receipt.anchor_id != anchor.anchor_id
        || receipt.network_id != provider.network_id
        || receipt.genesis_digest != provider.genesis_digest
        || receipt.provider_receipt_key_id != provider.receipt_key_id
        || receipt.anchor_receipt_key_id != anchor.receipt_key_id
        || receipt.provider_receipt_key_fingerprint
            != mldsa65_key_fingerprint(&provider.receipt_public_key)
        || receipt.anchor_receipt_key_fingerprint
            != mldsa65_key_fingerprint(&anchor.receipt_public_key)
        || receipt.initial_anchor_state_digest != initial_digest
        || initial_digest == [0; 32]
        || trust.receipt_digest() == [0; 32]
    {
        return Err(OffhostAnchorNoiseError::InvalidConfiguration);
    }

    let mut hash = Sha256::new();
    hash.update(PROFILE_DOMAIN);
    hash.update(anchor.anchor_id);
    hash.update(provider.provider_id);
    hash.update(provider.network_id);
    hash.update(provider.genesis_digest);
    hash.update(provider.receipt_key_id);
    hash.update(Sha256::digest(provider.receipt_public_key));
    hash.update(anchor.receipt_key_id);
    hash.update(Sha256::digest(anchor.receipt_public_key));
    hash.update(trust.receipt_digest());
    let profile: [u8; 32] = hash.finalize().into();
    if is_zero(&profile) {
        return Err(OffhostAnchorNoiseError::InvalidConfiguration);
    }
    Ok(profile)
}

/// QAR2 client transport. Each call opens one authenticated Noise XX connection.
/// Its Noise prologue binds QAR2, exact chain/anchor key identities, and the QBT1 digest.
pub struct NoiseTcpQar2OffhostAnchorTransport {
    address: SocketAddr,
    local_static_private_key: [u8; 32],
    trusted_server_static_public_key: [u8; 32],
    anchor_pin: ExternalCasOffhostAnchorPin,
    provider_pin: ExternalCasPin,
    trust: VerifiedBootstrapTrust,
    profile_id: [u8; 32],
    connect_timeout: Duration,
}

impl fmt::Debug for NoiseTcpQar2OffhostAnchorTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NoiseTcpQar2OffhostAnchorTransport")
            .field("address", &self.address)
            .field("local_static_private_key", &"<redacted>")
            .field("trusted_server_static_public_key", &"<pinned-key>")
            .field("anchor_id", &self.anchor_pin.anchor_id)
            .field("provider_id", &self.provider_pin.provider_id)
            .field("network_id", &self.provider_pin.network_id)
            .field("genesis_digest", &self.provider_pin.genesis_digest)
            .field("qbt1_receipt_digest", &self.trust.receipt_digest())
            .field("connect_timeout", &self.connect_timeout)
            .finish()
    }
}

impl Drop for NoiseTcpQar2OffhostAnchorTransport {
    fn drop(&mut self) {
        self.local_static_private_key.fill(0);
    }
}

impl NoiseTcpQar2OffhostAnchorTransport {
    pub fn new(
        address: SocketAddr,
        mut local_static_private_key: [u8; 32],
        trusted_server_static_public_key: [u8; 32],
        anchor_pin: ExternalCasOffhostAnchorPin,
        provider_pin: ExternalCasPin,
        trust: VerifiedBootstrapTrust,
    ) -> Result<Self, OffhostAnchorNoiseError> {
        let result = Self::with_timeout(
            address,
            local_static_private_key,
            trusted_server_static_public_key,
            anchor_pin,
            provider_pin,
            trust,
            DEFAULT_CONNECT_TIMEOUT,
        );
        local_static_private_key.fill(0);
        result
    }

    pub fn with_timeout(
        address: SocketAddr,
        mut local_static_private_key: [u8; 32],
        trusted_server_static_public_key: [u8; 32],
        anchor_pin: ExternalCasOffhostAnchorPin,
        provider_pin: ExternalCasPin,
        trust: VerifiedBootstrapTrust,
        connect_timeout: Duration,
    ) -> Result<Self, OffhostAnchorNoiseError> {
        if is_zero(&local_static_private_key)
            || is_zero(&trusted_server_static_public_key)
            || connect_timeout.is_zero()
            || connect_timeout > MAX_CONNECT_TIMEOUT
        {
            local_static_private_key.fill(0);
            return Err(OffhostAnchorNoiseError::InvalidConfiguration);
        }
        let profile_id = match qar2_qbt1_noise_profile_id(&trust, &anchor_pin, &provider_pin) {
            Ok(profile) => profile,
            Err(error) => {
                local_static_private_key.fill(0);
                return Err(error);
            }
        };
        Ok(Self {
            address,
            local_static_private_key,
            trusted_server_static_public_key,
            anchor_pin,
            provider_pin,
            trust,
            profile_id,
            connect_timeout,
        })
    }

    pub fn is_pinned_to(
        &self,
        anchor_pin: &ExternalCasOffhostAnchorPin,
        provider_pin: &ExternalCasPin,
        trust: &VerifiedBootstrapTrust,
    ) -> bool {
        &self.anchor_pin == anchor_pin
            && &self.provider_pin == provider_pin
            && self.trust.receipt_digest() == trust.receipt_digest()
            && self.profile_id
                == qar2_qbt1_noise_profile_id(trust, anchor_pin, provider_pin).unwrap_or([0; 32])
    }

    fn exchange(&self, kind: u16, payload: &[u8]) -> Result<Vec<u8>, OffhostAnchorNoiseError> {
        let expected = match kind {
            KIND_READ if payload.len() == READ_REQUEST_BYTES => QAR2_RECEIPT_BYTES,
            KIND_CAS if payload.len() == CAS_REQUEST_BYTES => QAR2_RECEIPT_BYTES,
            _ => return Err(OffhostAnchorNoiseError::Protocol),
        };
        let mut stream = TcpStream::connect_timeout(&self.address, self.connect_timeout)?;
        stream.set_nodelay(true)?;
        stream.set_read_timeout(Some(IO_TIMEOUT))?;
        stream.set_write_timeout(Some(IO_TIMEOUT))?;
        let mut session = QRunV05NoiseSession::connect(
            &mut stream,
            &self.local_static_private_key,
            &self.trusted_server_static_public_key,
            &self.provider_pin.network_id,
            &self.profile_id,
        )?;

        let mut request = Vec::with_capacity(REQUEST_HEADER_BYTES + payload.len());
        request.extend_from_slice(REQUEST_MAGIC);
        request.extend_from_slice(&WIRE_VERSION.to_be_bytes());
        request.extend_from_slice(&kind.to_be_bytes());
        request.extend_from_slice(payload);
        session.write_record(&mut stream, &request)?;

        let response = session.read_record(&mut stream)?;
        if response.len() == RESPONSE_HEADER_BYTES
            && &response[..4] == RESPONSE_MAGIC
            && u16::from_be_bytes([response[4], response[5]]) == WIRE_VERSION
            && u16::from_be_bytes([response[6], response[7]]) == kind
            && u16::from_be_bytes([response[8], response[9]]) == STATUS_REJECTED
        {
            return Err(OffhostAnchorNoiseError::AnchorRejected);
        }
        if response.len() != RESPONSE_HEADER_BYTES + expected
            || &response[..4] != RESPONSE_MAGIC
            || u16::from_be_bytes([response[4], response[5]]) != WIRE_VERSION
            || u16::from_be_bytes([response[6], response[7]]) != kind
            || u16::from_be_bytes([response[8], response[9]]) != STATUS_OK
        {
            return Err(OffhostAnchorNoiseError::Protocol);
        }
        Ok(response[RESPONSE_HEADER_BYTES..].to_vec())
    }

    pub fn read<V: MlDsa65Verifier>(
        &self,
        request: &ExternalCasOffhostAnchorReadRequest,
        verifier: &V,
    ) -> Result<QAR2BootstrapBoundReceipt, OffhostAnchorNoiseError> {
        request
            .validate()
            .map_err(|error| OffhostAnchorNoiseError::Contract(error.to_string()))?;
        let mut payload = Vec::with_capacity(READ_REQUEST_BYTES);
        payload.extend_from_slice(&request.challenge);
        payload.extend_from_slice(&request.operation_id);
        payload.extend_from_slice(&request.request_digest);
        let response = self.exchange(KIND_READ, &payload)?;
        let receipt = QAR2BootstrapBoundReceipt::decode(&response)
            .map_err(|error| OffhostAnchorNoiseError::Contract(error.to_string()))?;
        receipt
            .verify_read(
                &self.trust,
                &self.anchor_pin,
                &self.provider_pin,
                request,
                verifier,
            )
            .map_err(|error| OffhostAnchorNoiseError::Contract(error.to_string()))?;
        Ok(receipt)
    }

    pub fn compare_and_swap(
        &self,
        request: &ExternalCasOffhostAnchorCasRequest,
        next_record_bytes: &[u8],
        provider_receipt_bytes: &[u8],
        verifier: &impl MlDsa65Verifier,
    ) -> Result<QAR2BootstrapBoundReceipt, OffhostAnchorNoiseError> {
        request
            .validate()
            .map_err(|error| OffhostAnchorNoiseError::Contract(error.to_string()))?;
        if next_record_bytes.len() != EXTERNAL_CAS_RECORD_BYTES
            || provider_receipt_bytes.len() != EXTERNAL_CAS_RECEIPT_BYTES
        {
            return Err(OffhostAnchorNoiseError::Protocol);
        }
        ExternalCasRecord::decode(next_record_bytes)
            .map_err(|error| OffhostAnchorNoiseError::Contract(error.to_string()))?;
        ExternalCasReceipt::decode(provider_receipt_bytes)
            .map_err(|error| OffhostAnchorNoiseError::Contract(error.to_string()))?;

        let mut payload = Vec::with_capacity(CAS_REQUEST_BYTES);
        payload.extend_from_slice(&request.challenge);
        payload.extend_from_slice(&request.operation_id);
        payload.extend_from_slice(&request.request_digest);
        payload.extend_from_slice(&request.expected_sequence.to_be_bytes());
        payload.extend_from_slice(&request.expected_state_digest);
        payload.extend_from_slice(&request.target_state_digest);
        payload.extend_from_slice(next_record_bytes);
        payload.extend_from_slice(provider_receipt_bytes);
        if payload.len() != CAS_REQUEST_BYTES {
            return Err(OffhostAnchorNoiseError::Protocol);
        }

        let response = self.exchange(KIND_CAS, &payload)?;
        let receipt = QAR2BootstrapBoundReceipt::decode(&response)
            .map_err(|error| OffhostAnchorNoiseError::Contract(error.to_string()))?;
        receipt
            .verify_cas(
                &self.trust,
                &self.anchor_pin,
                &self.provider_pin,
                request,
                verifier,
            )
            .map_err(|error| OffhostAnchorNoiseError::Contract(error.to_string()))?;
        Ok(receipt)
    }
}

/// Serve exactly one QAR2 request on an already authenticated Noise connection.
/// The function accepts only Q2RQ version 2 and returns only Q2RS/QAR2 bytes.
/// A QAR1 client fails during the distinct Noise prologue or the strict QAR2 frame check.
pub fn serve_qar2_offhost_anchor_noise_connection<S, V>(
    stream: &mut TcpStream,
    local_static_private_key: &[u8; 32],
    trusted_client_static_public_keys: &[[u8; 32]],
    anchor_pin: &ExternalCasOffhostAnchorPin,
    provider_pin: &ExternalCasPin,
    trust: &VerifiedBootstrapTrust,
    service: &QAR2BoundAnchorService,
    provider_verifier: &V,
    anchor_signer: &S,
) -> Result<(), OffhostAnchorNoiseError>
where
    S: crate::external_cas_offhost_anchor_protocol_candidate::OffhostAnchorReceiptSigner,
    V: MlDsa65Verifier,
{
    if !service.matches_pins(anchor_pin, provider_pin)
        || service.bootstrap_trust_digest() != trust.receipt_digest()
    {
        return Err(OffhostAnchorNoiseError::InvalidConfiguration);
    }
    let profile_id = qar2_qbt1_noise_profile_id(trust, anchor_pin, provider_pin)?;
    stream.set_nodelay(true)?;
    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    stream.set_write_timeout(Some(IO_TIMEOUT))?;
    let mut session = QRunV05NoiseSession::accept(
        stream,
        local_static_private_key,
        trusted_client_static_public_keys,
        &provider_pin.network_id,
        &profile_id,
    )?;

    let frame = session.read_record(stream)?;
    if frame.len() < REQUEST_HEADER_BYTES
        || &frame[..4] != REQUEST_MAGIC
        || u16::from_be_bytes([frame[4], frame[5]]) != WIRE_VERSION
    {
        return Err(OffhostAnchorNoiseError::Protocol);
    }
    let kind = u16::from_be_bytes([frame[6], frame[7]]);
    let payload = &frame[REQUEST_HEADER_BYTES..];
    let receipt = match kind {
        KIND_READ => {
            if payload.len() != READ_REQUEST_BYTES {
                return Err(OffhostAnchorNoiseError::Protocol);
            }
            let request = ExternalCasOffhostAnchorReadRequest {
                challenge: payload[0..32]
                    .try_into()
                    .map_err(|_| OffhostAnchorNoiseError::Protocol)?,
                operation_id: payload[32..64]
                    .try_into()
                    .map_err(|_| OffhostAnchorNoiseError::Protocol)?,
                request_digest: payload[64..96]
                    .try_into()
                    .map_err(|_| OffhostAnchorNoiseError::Protocol)?,
            };
            service
                .read(&request, anchor_signer)
                .map_err(|error| OffhostAnchorNoiseError::Contract(error.to_string()))?
        }
        KIND_CAS => {
            if payload.len() != CAS_REQUEST_BYTES {
                return Err(OffhostAnchorNoiseError::Protocol);
            }
            let request = ExternalCasOffhostAnchorCasRequest {
                challenge: payload[0..32]
                    .try_into()
                    .map_err(|_| OffhostAnchorNoiseError::Protocol)?,
                operation_id: payload[32..64]
                    .try_into()
                    .map_err(|_| OffhostAnchorNoiseError::Protocol)?,
                request_digest: payload[64..96]
                    .try_into()
                    .map_err(|_| OffhostAnchorNoiseError::Protocol)?,
                expected_sequence: u64::from_be_bytes(
                    payload[96..104]
                        .try_into()
                        .map_err(|_| OffhostAnchorNoiseError::Protocol)?,
                ),
                expected_state_digest: payload[104..136]
                    .try_into()
                    .map_err(|_| OffhostAnchorNoiseError::Protocol)?,
                target_state_digest: payload[136..168]
                    .try_into()
                    .map_err(|_| OffhostAnchorNoiseError::Protocol)?,
            };
            let record_end = CAS_FIXED_REQUEST_BYTES + EXTERNAL_CAS_RECORD_BYTES;
            service
                .compare_and_swap(
                    &request,
                    &payload[CAS_FIXED_REQUEST_BYTES..record_end],
                    &payload[record_end..],
                    provider_verifier,
                    anchor_signer,
                )
                .map_err(|error| OffhostAnchorNoiseError::Contract(error.to_string()))?
        }
        _ => return Err(OffhostAnchorNoiseError::Protocol),
    };
    let encoded = receipt
        .encode()
        .map_err(|error| OffhostAnchorNoiseError::Contract(error.to_string()))?;
    let mut response = Vec::with_capacity(RESPONSE_HEADER_BYTES + encoded.len());
    response.extend_from_slice(RESPONSE_MAGIC);
    response.extend_from_slice(&WIRE_VERSION.to_be_bytes());
    response.extend_from_slice(&kind.to_be_bytes());
    response.extend_from_slice(&STATUS_OK.to_be_bytes());
    response.extend_from_slice(&encoded);
    session.write_record(stream, &response)?;
    Ok(())
}

/// Adapter for the existing QAP1 coordinator. It exposes inner QAR1 receipts only after it has
/// verified the outer QAR2 signature, the exact QBT1 digest, and the inner QAR1 signature.
pub struct QAR2Qap1AnchorTransport<V> {
    transport: NoiseTcpQar2OffhostAnchorTransport,
    trust: VerifiedBootstrapTrust,
    anchor_pin: ExternalCasOffhostAnchorPin,
    provider_pin: ExternalCasPin,
    verifier: V,
}

impl<V: MlDsa65Verifier> QAR2Qap1AnchorTransport<V> {
    pub fn new(
        transport: NoiseTcpQar2OffhostAnchorTransport,
        trust: VerifiedBootstrapTrust,
        anchor_pin: ExternalCasOffhostAnchorPin,
        provider_pin: ExternalCasPin,
        verifier: V,
    ) -> Result<Self, String> {
        if !transport.is_pinned_to(&anchor_pin, &provider_pin, &trust) {
            return Err("QAR2 transport is not pinned to the exact QBT1 capability".into());
        }
        qar2_qbt1_noise_profile_id(&trust, &anchor_pin, &provider_pin)
            .map_err(|error| error.to_string())?;
        Ok(Self {
            transport,
            trust,
            anchor_pin,
            provider_pin,
            verifier,
        })
    }
}

impl<V: MlDsa65Verifier> QRunV06Qap1AnchorTransport for QAR2Qap1AnchorTransport<V> {
    fn is_pinned_to(
        &self,
        anchor_pin: &ExternalCasOffhostAnchorPin,
        provider_pin: &ExternalCasPin,
    ) -> bool {
        &self.anchor_pin == anchor_pin
            && &self.provider_pin == provider_pin
            && self
                .transport
                .is_pinned_to(anchor_pin, provider_pin, &self.trust)
    }

    fn read(
        &mut self,
        request: &ExternalCasOffhostAnchorReadRequest,
    ) -> Result<ExternalCasOffhostAnchorReceipt, String> {
        let receipt = self
            .transport
            .read(request, &self.verifier)
            .map_err(|error| error.to_string())?;
        // Verify both layers before returning the legacy-shaped inner receipt to QAP1.
        receipt
            .verify_read(
                &self.trust,
                &self.anchor_pin,
                &self.provider_pin,
                request,
                &self.verifier,
            )
            .map_err(|error| error.to_string())?;
        Ok(receipt.inner_qar1)
    }

    fn compare_and_swap(
        &mut self,
        request: &ExternalCasOffhostAnchorCasRequest,
        next_record_bytes: &[u8],
        provider_receipt_bytes: &[u8],
    ) -> Result<ExternalCasOffhostAnchorReceipt, String> {
        let receipt = self
            .transport
            .compare_and_swap(
                request,
                next_record_bytes,
                provider_receipt_bytes,
                &self.verifier,
            )
            .map_err(|error| error.to_string())?;
        // The QAR2 outer signature and QBT1 binding are verified before QAP1 sees inner QAR1.
        receipt
            .verify_cas(
                &self.trust,
                &self.anchor_pin,
                &self.provider_pin,
                request,
                &self.verifier,
            )
            .map_err(|error| error.to_string())?;
        Ok(receipt.inner_qar1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        external_cas_anchor_candidate::{
            ExternalCasReceipt, ExternalCasReceiptKind, ExternalCasReceiptOutcome,
            ExternalCasWriteRequest,
        },
        external_cas_bootstrap_trust_candidate::tests::verified_test_fixture,
        external_cas_offhost_anchor_noise_transport_candidate::{
            serve_offhost_anchor_noise_connection, NoiseTcpOffhostAnchorTransport,
        },
        external_cas_offhost_anchor_protocol_candidate::ExternalCasOffhostAnchorReceiptOutcome,
        external_cas_offhost_anchor_protocol_v2_candidate::QAR2BoundAnchorService,
        v4_fat1_mldsa65_candidate::LibcruxMlDsa65VerifierCandidate,
        v4_fat1_trust_candidate::ML_DSA_65_SIGNATURE_BYTES,
    };
    use libcrux_ml_dsa::ml_dsa_65::{portable, MLDSA65SigningKey};
    use snow::{params::NoiseParams, Builder};
    use std::{net::TcpListener, sync::Arc, thread};

    #[derive(Clone)]
    struct TestSigner(Arc<MLDSA65SigningKey>);

    impl crate::external_cas_offhost_anchor_protocol_candidate::OffhostAnchorReceiptSigner
        for TestSigner
    {
        fn sign_digest(
            &self,
            digest: &[u8; 32],
        ) -> Result<[u8; ML_DSA_65_SIGNATURE_BYTES], String> {
            Ok(*portable::sign(&self.0, digest, &[], [0xD7; 32])
                .map_err(|error| format!("{error:?}"))?
                .as_ref())
        }
    }

    fn noise_keypair() -> ([u8; 32], [u8; 32]) {
        let mut pair = Builder::new(
            "Noise_XX_25519_ChaChaPoly_SHA256"
                .parse::<NoiseParams>()
                .unwrap(),
        )
        .generate_keypair()
        .unwrap();
        let private = pair.private.as_slice().try_into().unwrap();
        let public = pair.public.as_slice().try_into().unwrap();
        pair.private.fill(0);
        pair.public.fill(0);
        (private, public)
    }

    struct Fixture {
        provider: ExternalCasPin,
        anchor: ExternalCasOffhostAnchorPin,
        trust: VerifiedBootstrapTrust,
        provider_signer: TestSigner,
        anchor_signer: TestSigner,
        service: Arc<QAR2BoundAnchorService>,
    }

    fn fixture() -> Fixture {
        let (provider, anchor, trust) = verified_test_fixture();
        let provider_keys = portable::generate_key_pair([0x11; 32]);
        let anchor_keys = portable::generate_key_pair([0x22; 32]);
        assert_eq!(
            provider.receipt_public_key.as_slice(),
            provider_keys.verification_key.as_ref()
        );
        assert_eq!(
            anchor.receipt_public_key.as_slice(),
            anchor_keys.verification_key.as_ref()
        );
        let model = crate::external_cas_offhost_anchor_protocol_candidate::ExternalCasOffhostAnchorMemoryModel::new(
            anchor.clone(),
            provider.clone(),
            trust.initial_anchor_state().clone(),
        )
        .unwrap();
        let service = Arc::new(
            QAR2BoundAnchorService::from_test_model(
                model,
                trust.clone(),
                anchor.clone(),
                provider.clone(),
            )
            .unwrap(),
        );
        Fixture {
            provider,
            anchor,
            trust,
            provider_signer: TestSigner(Arc::new(provider_keys.signing_key)),
            anchor_signer: TestSigner(Arc::new(anchor_keys.signing_key)),
            service,
        }
    }

    fn start_q2_server(
        f: &Fixture,
        expected_connections: usize,
    ) -> (
        SocketAddr,
        [u8; 32],
        [u8; 32],
        thread::JoinHandle<Vec<Result<(), OffhostAnchorNoiseError>>>,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let (server_private, server_public) = noise_keypair();
        let (client_private, client_public) = noise_keypair();
        let anchor = f.anchor.clone();
        let provider = f.provider.clone();
        let trust = f.trust.clone();
        let service = Arc::clone(&f.service);
        let signer = f.anchor_signer.clone();
        let join = thread::spawn(move || {
            let mut results = Vec::new();
            for _ in 0..expected_connections {
                let (mut stream, _) = listener.accept().unwrap();
                results.push(serve_qar2_offhost_anchor_noise_connection(
                    &mut stream,
                    &server_private,
                    &[client_public],
                    &anchor,
                    &provider,
                    &trust,
                    &service,
                    &LibcruxMlDsa65VerifierCandidate,
                    &signer,
                ));
            }
            results
        });
        (address, server_public, client_private, join)
    }

    fn start_q1_server(
        f: &Fixture,
    ) -> (
        SocketAddr,
        [u8; 32],
        [u8; 32],
        thread::JoinHandle<Result<(), OffhostAnchorNoiseError>>,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let (server_private, server_public) = noise_keypair();
        let (client_private, client_public) = noise_keypair();
        let anchor = f.anchor.clone();
        let provider = f.provider.clone();
        let model = crate::external_cas_offhost_anchor_protocol_candidate::ExternalCasOffhostAnchorMemoryModel::new(
            anchor.clone(), provider.clone(), f.trust.initial_anchor_state().clone(),
        ).unwrap();
        let signer = f.anchor_signer.clone();
        let join = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            serve_offhost_anchor_noise_connection(
                &mut stream,
                &server_private,
                &[client_public],
                &anchor,
                &provider,
                &model,
                &LibcruxMlDsa65VerifierCandidate,
                &signer,
            )
        });
        (address, server_public, client_private, join)
    }

    fn client(
        f: &Fixture,
        address: SocketAddr,
        server_public: [u8; 32],
        client_private: [u8; 32],
    ) -> NoiseTcpQar2OffhostAnchorTransport {
        NoiseTcpQar2OffhostAnchorTransport::new(
            address,
            client_private,
            server_public,
            f.anchor.clone(),
            f.provider.clone(),
            f.trust.clone(),
        )
        .unwrap()
    }

    fn write_request(f: &Fixture) -> (ExternalCasWriteRequest, ExternalCasReceipt) {
        let initial = f.trust.initial_anchor_state();
        let operation_id = [0xB2; 32];
        let mut request = ExternalCasWriteRequest {
            request_nonce: [0xB1; 32],
            operation_id,
            request_digest: [1; 32],
            expected_generation: initial.provider_record.generation,
            expected_object_generation: initial.provider_object_generation,
            expected_record_digest: initial.provider_record.digest().unwrap(),
            expected_state_digest: initial.provider_record.next_state_digest,
            next_record: ExternalCasRecord {
                generation: initial.provider_record.generation + 1,
                provider_id: f.provider.provider_id,
                network_id: f.provider.network_id,
                genesis_digest: f.provider.genesis_digest,
                previous_record_digest: initial.provider_record.digest().unwrap(),
                previous_state_digest: initial.provider_record.next_state_digest,
                next_state_digest: [0xC1; 32],
                operation_id,
                request_digest: [1; 32],
            },
        };
        request.bind_request_digest(&f.provider).unwrap();
        let mut receipt = ExternalCasReceipt {
            kind: ExternalCasReceiptKind::Commit,
            outcome: ExternalCasReceiptOutcome::Applied,
            generation: request.next_record.generation,
            object_generation: initial.provider_object_generation + 1,
            provider_id: f.provider.provider_id,
            network_id: f.provider.network_id,
            genesis_digest: f.provider.genesis_digest,
            receipt_key_id: f.provider.receipt_key_id,
            request_nonce: request.request_nonce,
            record_digest: request.next_record.digest().unwrap(),
            previous_record_digest: request.next_record.previous_record_digest,
            previous_state_digest: request.next_record.previous_state_digest,
            state_digest: request.next_record.next_state_digest,
            operation_id,
            request_digest: request.request_digest,
            signature: [0; ML_DSA_65_SIGNATURE_BYTES],
        };
        let digest = receipt.signing_digest().unwrap();
        receipt.signature = *portable::sign(&f.provider_signer.0, &digest, &[], [0xD8; 32])
            .unwrap()
            .as_ref();
        (request, receipt)
    }

    #[test]
    fn qar2_noise_read_binds_the_qbt1_capability_and_verifies_the_outer_receipt() {
        let f = fixture();
        let (address, server_public, client_private, join) = start_q2_server(&f, 1);
        let transport = client(&f, address, server_public, client_private);
        let request = ExternalCasOffhostAnchorReadRequest {
            challenge: [0xA1; 32],
            operation_id: [0xA2; 32],
            request_digest: [0xA3; 32],
        };
        let receipt = transport
            .read(&request, &LibcruxMlDsa65VerifierCandidate)
            .unwrap();
        assert_eq!(
            receipt
                .verify_read(
                    &f.trust,
                    &f.anchor,
                    &f.provider,
                    &request,
                    &LibcruxMlDsa65VerifierCandidate,
                )
                .unwrap(),
            *f.trust.initial_anchor_state()
        );
        let results = join.join().unwrap();
        assert_eq!(results.len(), 1);
        assert!(results[0].is_ok());
    }

    #[test]
    fn qar2_noise_cas_verifies_outer_receipt_and_subsequent_read() {
        let f = fixture();
        let (address, server_public, client_private, join) = start_q2_server(&f, 2);
        let transport = client(&f, address, server_public, client_private);
        let (write, provider_receipt) = write_request(&f);
        let verifier = LibcruxMlDsa65VerifierCandidate;
        let expected_next = crate::external_cas_offhost_anchor_candidate::verify_provider_commit_for_offhost_anchor(
            &f.provider,
            f.trust.initial_anchor_state(),
            &write.next_record.encode().unwrap(),
            &provider_receipt.encode().unwrap(),
            &verifier,
        ).unwrap().next_state;
        let request = ExternalCasOffhostAnchorCasRequest {
            challenge: [0xB3; 32],
            operation_id: write.operation_id,
            request_digest: write.request_digest,
            expected_sequence: f.trust.initial_anchor_state().sequence,
            expected_state_digest: f.trust.initial_anchor_state().digest().unwrap(),
            target_state_digest: expected_next.digest().unwrap(),
        };
        let cas_receipt = transport
            .compare_and_swap(
                &request,
                &write.next_record.encode().unwrap(),
                &provider_receipt.encode().unwrap(),
                &verifier,
            )
            .unwrap();
        assert_eq!(
            cas_receipt
                .verify_cas(&f.trust, &f.anchor, &f.provider, &request, &verifier,)
                .unwrap(),
            (
                ExternalCasOffhostAnchorReceiptOutcome::Applied,
                expected_next.clone()
            )
        );
        let read_request = ExternalCasOffhostAnchorReadRequest {
            challenge: [0xC1; 32],
            operation_id: [0xC2; 32],
            request_digest: [0xC3; 32],
        };
        let read_receipt = transport.read(&read_request, &verifier).unwrap();
        assert_eq!(
            read_receipt
                .verify_read(&f.trust, &f.anchor, &f.provider, &read_request, &verifier,)
                .unwrap(),
            expected_next
        );
        let results = join.join().unwrap();
        assert_eq!(results.len(), 2);
        assert!(results.iter().all(Result::is_ok));
    }

    #[test]
    fn qar1_transport_cannot_downgrade_into_qbt1_bound_qar2_noise_server() {
        let f = fixture();
        let (address, server_public, client_private, join) = start_q2_server(&f, 1);
        let q1 = NoiseTcpOffhostAnchorTransport::new(
            address,
            client_private,
            server_public,
            f.anchor.clone(),
            f.provider.clone(),
        )
        .unwrap();
        let request = ExternalCasOffhostAnchorReadRequest {
            challenge: [0xD1; 32],
            operation_id: [0xD2; 32],
            request_digest: [0xD3; 32],
        };
        assert!(q1.read(&request).is_err());
        let results = join.join().unwrap();
        assert_eq!(results.len(), 1);
        assert!(results[0].is_err());
    }

    #[test]
    fn qbt1_bound_qar2_client_cannot_silently_fallback_to_q1_server() {
        let f = fixture();
        let (address, server_public, client_private, join) = start_q1_server(&f);
        let q2 = client(&f, address, server_public, client_private);
        let request = ExternalCasOffhostAnchorReadRequest {
            challenge: [0xE1; 32],
            operation_id: [0xE2; 32],
            request_digest: [0xE3; 32],
        };
        assert!(q2.read(&request, &LibcruxMlDsa65VerifierCandidate).is_err());
        assert!(join.join().unwrap().is_err());
    }

    #[test]
    fn qap1_adapter_exposes_inner_receipt_only_after_qbt1_outer_verification() {
        let f = fixture();
        let (address, server_public, client_private, join) = start_q2_server(&f, 1);
        let transport = client(&f, address, server_public, client_private);
        let mut adapter = QAR2Qap1AnchorTransport::new(
            transport,
            f.trust.clone(),
            f.anchor.clone(),
            f.provider.clone(),
            LibcruxMlDsa65VerifierCandidate,
        )
        .unwrap();
        let request = ExternalCasOffhostAnchorReadRequest {
            challenge: [0xF1; 32],
            operation_id: [0xF2; 32],
            request_digest: [0xF3; 32],
        };
        let receipt = adapter.read(&request).unwrap();
        assert_eq!(receipt.challenge, request.challenge);
        assert_eq!(receipt.kind, crate::external_cas_offhost_anchor_protocol_candidate::ExternalCasOffhostAnchorReceiptKind::Read);
        assert!(adapter.is_pinned_to(&f.anchor, &f.provider));
        assert!(join.join().unwrap()[0].is_ok());
    }
}
