//! Candidate-only authenticated Noise/TCP transport for the off-host QRun Anchor.
//!
//! One bounded request is served per connection. Noise authenticates the client/server static
//! keys and binds the complete Anchor/Provider/Network/Genesis/key identity into its prologue.
//! ML-DSA Anchor receipts remain independently verified by the caller; encrypted transport is
//! not a substitute for receipt verification or an independent administrative trust domain.
use crate::{
    external_cas_anchor_candidate::{
        ExternalCasPin, ExternalCasReceipt, ExternalCasRecord, EXTERNAL_CAS_RECORD_BYTES,
    },
    external_cas_offhost_anchor_protocol_candidate::{
        ExternalCasOffhostAnchorCasRequest, ExternalCasOffhostAnchorMemoryModel,
        ExternalCasOffhostAnchorReadRequest, ExternalCasOffhostAnchorReceipt,
        OffhostAnchorReceiptSigner, OFFHOST_ANCHOR_RECEIPT_BYTES,
    },
    qrun_v05_noise_transport_candidate::{QRunV05NoiseError, QRunV05NoiseSession},
    v4_fat1_trust_candidate::MlDsa65Verifier,
};
use sha2::{Digest, Sha256};
use std::{
    fmt, io,
    net::{SocketAddr, TcpStream},
    time::Duration,
};

const REQUEST_MAGIC: &[u8; 4] = b"QARQ";
const RESPONSE_MAGIC: &[u8; 4] = b"QARS";
const WIRE_VERSION: u16 = 1;
const KIND_READ: u16 = 1;
const KIND_CAS: u16 = 2;
const STATUS_OK: u16 = 0;
const STATUS_REJECTED: u16 = 1;
const REQUEST_HEADER_BYTES: usize = 8;
const RESPONSE_HEADER_BYTES: usize = 10;
const READ_REQUEST_BYTES: usize = 96;
const CAS_FIXED_REQUEST_BYTES: usize = 168;
const CAS_REQUEST_BYTES: usize = CAS_FIXED_REQUEST_BYTES
    + EXTERNAL_CAS_RECORD_BYTES
    + crate::external_cas_anchor_candidate::EXTERNAL_CAS_RECEIPT_BYTES;
const PROFILE_DOMAIN: &[u8] = b"QRUN-OFFHOST-ANCHOR-NOISE-PROFILE-V1\0";
const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
const IO_TIMEOUT: Duration = Duration::from_secs(20);

#[derive(Debug)]
pub enum OffhostAnchorNoiseError {
    InvalidConfiguration,
    Io(String),
    Noise(String),
    Protocol,
    AnchorRejected,
    Contract(String),
}
impl fmt::Display for OffhostAnchorNoiseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfiguration => write!(f, "invalid off-host Anchor Noise configuration"),
            Self::Io(error) => write!(f, "off-host Anchor TCP transport failed: {error}"),
            Self::Noise(error) => write!(f, "off-host Anchor Noise session failed: {error}"),
            Self::Protocol => write!(f, "off-host Anchor wire frame is malformed"),
            Self::AnchorRejected => write!(f, "off-host Anchor rejected the request"),
            Self::Contract(error) => {
                write!(f, "off-host Anchor contract rejected the request: {error}")
            }
        }
    }
}
impl std::error::Error for OffhostAnchorNoiseError {}
impl From<QRunV05NoiseError> for OffhostAnchorNoiseError {
    fn from(value: QRunV05NoiseError) -> Self {
        Self::Noise(value.to_string())
    }
}
impl From<io::Error> for OffhostAnchorNoiseError {
    fn from(value: io::Error) -> Self {
        Self::Io(value.to_string())
    }
}

fn is_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}

/// Domain-separate Noise sessions across both receipt authorities and the full chain identity.
pub fn offhost_anchor_noise_profile_id(
    anchor: &crate::external_cas_offhost_anchor_protocol_candidate::ExternalCasOffhostAnchorPin,
    provider: &ExternalCasPin,
) -> Result<[u8; 32], OffhostAnchorNoiseError> {
    anchor
        .validate(provider)
        .map_err(|error| OffhostAnchorNoiseError::Contract(error.to_string()))?;
    let mut hash = Sha256::new();
    hash.update(PROFILE_DOMAIN);
    hash.update(anchor.anchor_id);
    hash.update(anchor.provider_id);
    hash.update(anchor.network_id);
    hash.update(anchor.genesis_digest);
    hash.update(provider.receipt_key_id);
    hash.update(Sha256::digest(provider.receipt_public_key));
    hash.update(anchor.receipt_key_id);
    hash.update(Sha256::digest(anchor.receipt_public_key));
    let profile: [u8; 32] = hash.finalize().into();
    if is_zero(&profile) {
        return Err(OffhostAnchorNoiseError::InvalidConfiguration);
    }
    Ok(profile)
}

/// One request per connection. The client static private key and trusted Anchor Noise key are
/// transport keys; the ML-DSA Anchor receipt key is separately pinned in anchor_pin.
pub struct NoiseTcpOffhostAnchorTransport {
    address: SocketAddr,
    local_static_private_key: [u8; 32],
    trusted_server_static_public_key: [u8; 32],
    anchor_pin: crate::external_cas_offhost_anchor_protocol_candidate::ExternalCasOffhostAnchorPin,
    provider_pin: ExternalCasPin,
    profile_id: [u8; 32],
    connect_timeout: Duration,
}
impl fmt::Debug for NoiseTcpOffhostAnchorTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NoiseTcpOffhostAnchorTransport")
            .field("address", &self.address)
            .field("local_static_private_key", &"<redacted>")
            .field("trusted_server_static_public_key", &"<pinned-key>")
            .field("anchor_id", &self.anchor_pin.anchor_id)
            .field("provider_id", &self.provider_pin.provider_id)
            .field("network_id", &self.provider_pin.network_id)
            .field("genesis_digest", &self.provider_pin.genesis_digest)
            .field("connect_timeout", &self.connect_timeout)
            .finish()
    }
}
impl Drop for NoiseTcpOffhostAnchorTransport {
    fn drop(&mut self) {
        self.local_static_private_key.fill(0);
    }
}
impl NoiseTcpOffhostAnchorTransport {
    pub fn new(
        address: SocketAddr,
        local_static_private_key: [u8; 32],
        trusted_server_static_public_key: [u8; 32],
        anchor_pin: crate::external_cas_offhost_anchor_protocol_candidate::ExternalCasOffhostAnchorPin,
        provider_pin: ExternalCasPin,
    ) -> Result<Self, OffhostAnchorNoiseError> {
        Self::with_timeout(
            address,
            local_static_private_key,
            trusted_server_static_public_key,
            anchor_pin,
            provider_pin,
            DEFAULT_CONNECT_TIMEOUT,
        )
    }

    pub fn with_timeout(
        address: SocketAddr,
        local_static_private_key: [u8; 32],
        trusted_server_static_public_key: [u8; 32],
        anchor_pin: crate::external_cas_offhost_anchor_protocol_candidate::ExternalCasOffhostAnchorPin,
        provider_pin: ExternalCasPin,
        connect_timeout: Duration,
    ) -> Result<Self, OffhostAnchorNoiseError> {
        if is_zero(&local_static_private_key)
            || is_zero(&trusted_server_static_public_key)
            || connect_timeout.is_zero()
            || connect_timeout > MAX_CONNECT_TIMEOUT
        {
            return Err(OffhostAnchorNoiseError::InvalidConfiguration);
        }
        let profile_id = offhost_anchor_noise_profile_id(&anchor_pin, &provider_pin)?;
        Ok(Self {
            address,
            local_static_private_key,
            trusted_server_static_public_key,
            anchor_pin,
            provider_pin,
            profile_id,
            connect_timeout,
        })
    }

    fn exchange(&self, kind: u16, payload: &[u8]) -> Result<Vec<u8>, OffhostAnchorNoiseError> {
        let expected = match kind {
            KIND_READ if payload.len() == READ_REQUEST_BYTES => OFFHOST_ANCHOR_RECEIPT_BYTES,
            KIND_CAS if payload.len() == CAS_REQUEST_BYTES => OFFHOST_ANCHOR_RECEIPT_BYTES,
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
        if response.len() != RESPONSE_HEADER_BYTES + expected
            || &response[..4] != RESPONSE_MAGIC
            || u16::from_be_bytes([response[4], response[5]]) != WIRE_VERSION
            || u16::from_be_bytes([response[6], response[7]]) != kind
        {
            if response.len() == RESPONSE_HEADER_BYTES
                && &response[..4] == RESPONSE_MAGIC
                && u16::from_be_bytes([response[4], response[5]]) == WIRE_VERSION
                && u16::from_be_bytes([response[6], response[7]]) == kind
                && u16::from_be_bytes([response[8], response[9]]) == STATUS_REJECTED
            {
                return Err(OffhostAnchorNoiseError::AnchorRejected);
            }
            return Err(OffhostAnchorNoiseError::Protocol);
        }
        let status = u16::from_be_bytes([response[8], response[9]]);
        if status != STATUS_OK {
            return Err(OffhostAnchorNoiseError::AnchorRejected);
        }
        Ok(response[RESPONSE_HEADER_BYTES..].to_vec())
    }

    pub fn read(
        &self,
        request: &ExternalCasOffhostAnchorReadRequest,
    ) -> Result<ExternalCasOffhostAnchorReceipt, OffhostAnchorNoiseError> {
        request
            .validate()
            .map_err(|error| OffhostAnchorNoiseError::Contract(error.to_string()))?;
        let mut payload = Vec::with_capacity(READ_REQUEST_BYTES);
        payload.extend_from_slice(&request.challenge);
        payload.extend_from_slice(&request.operation_id);
        payload.extend_from_slice(&request.request_digest);
        let response = self.exchange(KIND_READ, &payload)?;
        ExternalCasOffhostAnchorReceipt::decode(&response)
            .map_err(|error| OffhostAnchorNoiseError::Contract(error.to_string()))
    }

    pub fn compare_and_swap(
        &self,
        request: &ExternalCasOffhostAnchorCasRequest,
        next_record_bytes: &[u8],
        provider_receipt_bytes: &[u8],
    ) -> Result<ExternalCasOffhostAnchorReceipt, OffhostAnchorNoiseError> {
        request
            .validate()
            .map_err(|error| OffhostAnchorNoiseError::Contract(error.to_string()))?;
        if next_record_bytes.len() != EXTERNAL_CAS_RECORD_BYTES
            || provider_receipt_bytes.len()
                != crate::external_cas_anchor_candidate::EXTERNAL_CAS_RECEIPT_BYTES
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
        ExternalCasOffhostAnchorReceipt::decode(&response)
            .map_err(|error| OffhostAnchorNoiseError::Contract(error.to_string()))
    }
}

/// Serve one authenticated Anchor Read or CAS request. The Anchor model's storage adapter is
/// the authority; this connection handler never writes local state or falls back to QCF1.
pub fn serve_offhost_anchor_noise_connection<S, V>(
    stream: &mut TcpStream,
    local_static_private_key: &[u8; 32],
    trusted_client_static_public_keys: &[[u8; 32]],
    anchor_pin: &crate::external_cas_offhost_anchor_protocol_candidate::ExternalCasOffhostAnchorPin,
    provider_pin: &ExternalCasPin,
    model: &ExternalCasOffhostAnchorMemoryModel,
    provider_verifier: &V,
    anchor_signer: &S,
) -> Result<(), OffhostAnchorNoiseError>
where
    S: OffhostAnchorReceiptSigner,
    V: MlDsa65Verifier,
{
    let profile_id = offhost_anchor_noise_profile_id(anchor_pin, provider_pin)?;
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
    let request = session.read_record(stream)?;
    if request.len() < REQUEST_HEADER_BYTES
        || &request[..4] != REQUEST_MAGIC
        || u16::from_be_bytes([request[4], request[5]]) != WIRE_VERSION
    {
        return Err(OffhostAnchorNoiseError::Protocol);
    }
    let kind = u16::from_be_bytes([request[6], request[7]]);
    let payload = &request[REQUEST_HEADER_BYTES..];
    let receipt = match kind {
        KIND_READ => {
            if payload.len() != READ_REQUEST_BYTES {
                return Err(OffhostAnchorNoiseError::Protocol);
            }
            let read = ExternalCasOffhostAnchorReadRequest {
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
            read.validate()
                .map_err(|error| OffhostAnchorNoiseError::Contract(error.to_string()))?;
            model
                .read(&read, anchor_signer)
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
            request
                .validate()
                .map_err(|error| OffhostAnchorNoiseError::Contract(error.to_string()))?;
            let record_end = CAS_FIXED_REQUEST_BYTES + EXTERNAL_CAS_RECORD_BYTES;
            model
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        external_cas_anchor_candidate::{
            ExternalCasReceiptKind, ExternalCasReceiptOutcome, ExternalCasWriteRequest,
        },
        external_cas_offhost_anchor_candidate::{
            verify_provider_commit_for_offhost_anchor, ExternalCasOffhostAnchorState,
        },
        external_cas_offhost_anchor_protocol_candidate::{
            ExternalCasOffhostAnchorPin, ExternalCasOffhostAnchorReceiptOutcome,
        },
        v4_fat1_mldsa65_candidate::LibcruxMlDsa65VerifierCandidate,
        v4_fat1_trust_candidate::ML_DSA_65_SIGNATURE_BYTES,
    };
    use libcrux_ml_dsa::ml_dsa_65::{portable, MLDSA65SigningKey};
    use snow::{params::NoiseParams, Builder};
    use std::{net::TcpListener, sync::Arc, thread};

    #[derive(Clone)]
    struct TestSigner {
        key: Arc<MLDSA65SigningKey>,
    }
    impl OffhostAnchorReceiptSigner for TestSigner {
        fn sign_digest(
            &self,
            digest: &[u8; 32],
        ) -> Result<[u8; ML_DSA_65_SIGNATURE_BYTES], String> {
            let signature = portable::sign(&self.key, digest, &[], [0xD1; 32])
                .map_err(|error| format!("{error:?}"))?;
            Ok(*signature.as_ref())
        }
    }

    struct Fixture {
        provider_pin: ExternalCasPin,
        anchor_pin: ExternalCasOffhostAnchorPin,
        bootstrap_record: ExternalCasRecord,
        bootstrap_state: ExternalCasOffhostAnchorState,
        provider_signer: TestSigner,
        anchor_signer: TestSigner,
    }
    fn fixture() -> Fixture {
        let provider_keys = portable::generate_key_pair([0xA1; 32]);
        let anchor_keys = portable::generate_key_pair([0xB2; 32]);
        let provider_public = *provider_keys.verification_key.as_ref();
        let anchor_public = *anchor_keys.verification_key.as_ref();
        let provider_pin = ExternalCasPin {
            provider_id: [0x11; 32],
            network_id: [0x22; 32],
            genesis_digest: [0x33; 32],
            receipt_key_id: [0x44; 32],
            receipt_public_key: provider_public,
        };
        let anchor_pin = ExternalCasOffhostAnchorPin {
            anchor_id: [0x91; 32],
            provider_id: provider_pin.provider_id,
            network_id: provider_pin.network_id,
            genesis_digest: provider_pin.genesis_digest,
            receipt_key_id: [0x92; 32],
            receipt_public_key: anchor_public,
        };
        let bootstrap_record = ExternalCasRecord {
            generation: 0,
            provider_id: provider_pin.provider_id,
            network_id: provider_pin.network_id,
            genesis_digest: provider_pin.genesis_digest,
            previous_record_digest: [0; 32],
            previous_state_digest: [0; 32],
            next_state_digest: [0x55; 32],
            operation_id: [0x66; 32],
            request_digest: [0x77; 32],
        };
        let bootstrap_state = ExternalCasOffhostAnchorState::provision_bootstrap(
            &provider_pin,
            bootstrap_record.clone(),
            1,
        )
        .unwrap();
        Fixture {
            provider_pin,
            anchor_pin,
            bootstrap_record,
            bootstrap_state,
            provider_signer: TestSigner {
                key: Arc::new(provider_keys.signing_key),
            },
            anchor_signer: TestSigner {
                key: Arc::new(anchor_keys.signing_key),
            },
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

    fn spawn_server(
        fixture: &Fixture,
        model: Arc<ExternalCasOffhostAnchorMemoryModel>,
        server_private: [u8; 32],
        trusted_client_public: [u8; 32],
    ) -> (
        SocketAddr,
        thread::JoinHandle<Result<(), OffhostAnchorNoiseError>>,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let anchor_pin = fixture.anchor_pin.clone();
        let provider_pin = fixture.provider_pin.clone();
        let signer = fixture.anchor_signer.clone();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            serve_offhost_anchor_noise_connection(
                &mut stream,
                &server_private,
                &[trusted_client_public],
                &anchor_pin,
                &provider_pin,
                &model,
                &LibcruxMlDsa65VerifierCandidate,
                &signer,
            )
        });
        (address, server)
    }

    fn model(f: &Fixture) -> Arc<ExternalCasOffhostAnchorMemoryModel> {
        Arc::new(
            ExternalCasOffhostAnchorMemoryModel::new(
                f.anchor_pin.clone(),
                f.provider_pin.clone(),
                f.bootstrap_state.clone(),
            )
            .unwrap(),
        )
    }

    fn write_request(f: &Fixture) -> ExternalCasWriteRequest {
        let operation_id = [0xA2; 32];
        let mut request = ExternalCasWriteRequest {
            request_nonce: [0xA1; 32],
            operation_id,
            request_digest: [1; 32],
            expected_generation: 0,
            expected_object_generation: 1,
            expected_record_digest: f.bootstrap_record.digest().unwrap(),
            expected_state_digest: f.bootstrap_record.next_state_digest,
            next_record: ExternalCasRecord {
                generation: 1,
                provider_id: f.provider_pin.provider_id,
                network_id: f.provider_pin.network_id,
                genesis_digest: f.provider_pin.genesis_digest,
                previous_record_digest: f.bootstrap_record.digest().unwrap(),
                previous_state_digest: f.bootstrap_record.next_state_digest,
                next_state_digest: [0xA3; 32],
                operation_id,
                request_digest: [1; 32],
            },
        };
        request.bind_request_digest(&f.provider_pin).unwrap();
        request
    }

    fn provider_commit_receipt(
        f: &Fixture,
        request: &ExternalCasWriteRequest,
    ) -> ExternalCasReceipt {
        let mut receipt = ExternalCasReceipt {
            kind: ExternalCasReceiptKind::Commit,
            outcome: ExternalCasReceiptOutcome::Applied,
            generation: request.next_record.generation,
            object_generation: 2,
            provider_id: f.provider_pin.provider_id,
            network_id: f.provider_pin.network_id,
            genesis_digest: f.provider_pin.genesis_digest,
            receipt_key_id: f.provider_pin.receipt_key_id,
            request_nonce: request.request_nonce,
            record_digest: request.next_record.digest().unwrap(),
            previous_record_digest: request.next_record.previous_record_digest,
            previous_state_digest: request.next_record.previous_state_digest,
            state_digest: request.next_record.next_state_digest,
            operation_id: request.operation_id,
            request_digest: request.request_digest,
            signature: [0; ML_DSA_65_SIGNATURE_BYTES],
        };
        let digest = receipt.signing_digest().unwrap();
        let signature = portable::sign(&f.provider_signer.key, &digest, &[], [0xC3; 32]).unwrap();
        receipt.signature = *signature.as_ref();
        receipt
    }

    #[test]
    fn authenticated_noise_read_returns_challenge_bound_signed_anchor_state() {
        let f = fixture();
        let model = model(&f);
        let (server_private, server_public) = noise_keypair();
        let (client_private, client_public) = noise_keypair();
        let (address, server) = spawn_server(&f, model, server_private, client_public);
        let transport = NoiseTcpOffhostAnchorTransport::new(
            address,
            client_private,
            server_public,
            f.anchor_pin.clone(),
            f.provider_pin.clone(),
        )
        .unwrap();
        let request = ExternalCasOffhostAnchorReadRequest {
            challenge: [0xB1; 32],
            operation_id: [0xB2; 32],
            request_digest: [0xB3; 32],
        };
        let receipt = transport.read(&request).unwrap();
        let observed = receipt
            .verify_read(
                &f.anchor_pin,
                &f.provider_pin,
                &request,
                &LibcruxMlDsa65VerifierCandidate,
            )
            .unwrap();
        assert_eq!(observed, f.bootstrap_state);
        server.join().unwrap().unwrap();
    }

    #[test]
    fn authenticated_noise_cas_verifies_provider_proof_and_returns_anchor_receipt() {
        let f = fixture();
        let verifier = LibcruxMlDsa65VerifierCandidate;
        let write = write_request(&f);
        let provider_receipt = provider_commit_receipt(&f, &write);
        let verified = verify_provider_commit_for_offhost_anchor(
            &f.provider_pin,
            &f.bootstrap_state,
            &write.next_record.encode().unwrap(),
            &provider_receipt.encode().unwrap(),
            &verifier,
        )
        .unwrap();
        let cas = ExternalCasOffhostAnchorCasRequest {
            challenge: [0xB4; 32],
            operation_id: write.operation_id,
            request_digest: write.request_digest,
            expected_sequence: f.bootstrap_state.sequence,
            expected_state_digest: f.bootstrap_state.digest().unwrap(),
            target_state_digest: verified.next_state.digest().unwrap(),
        };
        let model = model(&f);
        let (server_private, server_public) = noise_keypair();
        let (client_private, client_public) = noise_keypair();
        let (address, server) = spawn_server(&f, model, server_private, client_public);
        let transport = NoiseTcpOffhostAnchorTransport::new(
            address,
            client_private,
            server_public,
            f.anchor_pin.clone(),
            f.provider_pin.clone(),
        )
        .unwrap();
        let receipt = transport
            .compare_and_swap(
                &cas,
                &write.next_record.encode().unwrap(),
                &provider_receipt.encode().unwrap(),
            )
            .unwrap();
        let (outcome, accepted) = receipt
            .verify_cas(&f.anchor_pin, &f.provider_pin, &cas, &verifier)
            .unwrap();
        assert_eq!(outcome, ExternalCasOffhostAnchorReceiptOutcome::Applied);
        assert_eq!(accepted, verified.next_state);
        server.join().unwrap().unwrap();
    }

    #[test]
    fn unpinned_noise_client_is_rejected_before_anchor_state_is_observed() {
        let f = fixture();
        let model = model(&f);
        let expected = f.bootstrap_state.clone();
        let (server_private, server_public) = noise_keypair();
        let (_trusted_private, trusted_client_public) = noise_keypair();
        let (rogue_private, _rogue_public) = noise_keypair();
        let (address, server) =
            spawn_server(&f, model.clone(), server_private, trusted_client_public);
        let transport = NoiseTcpOffhostAnchorTransport::new(
            address,
            rogue_private,
            server_public,
            f.anchor_pin.clone(),
            f.provider_pin.clone(),
        )
        .unwrap();
        let request = ExternalCasOffhostAnchorReadRequest {
            challenge: [0xC1; 32],
            operation_id: [0xC2; 32],
            request_digest: [0xC3; 32],
        };
        assert!(transport.read(&request).is_err());
        assert!(server.join().unwrap().is_err());
        assert_eq!(model.snapshot().unwrap(), expected);
    }

    #[test]
    fn noise_profile_binds_anchor_provider_network_genesis_and_both_receipt_keys() {
        let f = fixture();
        let profile = offhost_anchor_noise_profile_id(&f.anchor_pin, &f.provider_pin).unwrap();
        let mut changed_anchor = f.anchor_pin.clone();
        changed_anchor.anchor_id[0] ^= 1;
        assert_ne!(
            profile,
            offhost_anchor_noise_profile_id(&changed_anchor, &f.provider_pin).unwrap()
        );
        let mut changed_provider = f.provider_pin.clone();
        changed_provider.network_id[0] ^= 1;
        assert!(offhost_anchor_noise_profile_id(&f.anchor_pin, &changed_provider).is_err());
    }
}
