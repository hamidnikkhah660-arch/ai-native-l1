//! Pinned Noise/TCP transport for the QRun external-CAS protocol.
//!
//! The server handler delegates atomicity and durable generation control to its backend. This
//! module does not by itself qualify a provider, its operator, or its persistent storage.

use crate::{
    external_cas_anchor_candidate::{
        ExternalCasPin, ExternalCasProviderTransport, ExternalCasReadRequest, ExternalCasReceipt,
        ExternalCasRecord, ExternalCasWriteRequest, EXTERNAL_CAS_RECEIPT_BYTES,
        EXTERNAL_CAS_RECORD_BYTES,
    },
    qrun_v05_noise_transport_candidate::{QRunV05NoiseError, QRunV05NoiseSession},
};
use sha2::{Digest, Sha256};
use std::{
    fmt, io,
    net::{SocketAddr, TcpStream},
    time::Duration,
};

const REQUEST_MAGIC: &[u8; 4] = b"QCRQ";
const RESPONSE_MAGIC: &[u8; 4] = b"QCRS";
const WIRE_VERSION: u16 = 1;
const KIND_READ: u16 = 1;
const KIND_COMPARE_AND_SWAP: u16 = 2;
const STATUS_OK: u16 = 0;
const STATUS_REJECTED: u16 = 1;
const REQUEST_HEADER_BYTES: usize = 8;
const RESPONSE_HEADER_BYTES: usize = 10;
const READ_REQUEST_BYTES: usize = 96;
const WRITE_REQUEST_BYTES: usize = 448;
const PROFILE_DOMAIN: &[u8] = b"QRUN-V05-EXTERNAL-CAS-NOISE-PROFILE-V1\0";
const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug)]
pub enum ExternalCasNoiseError {
    InvalidConfiguration,
    Io(String),
    Noise(String),
    Protocol,
    ProviderRejected,
    Contract(String),
}
impl fmt::Display for ExternalCasNoiseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfiguration => write!(f, "invalid external-CAS Noise configuration"),
            Self::Io(error) => write!(f, "external-CAS TCP transport failed: {error}"),
            Self::Noise(error) => write!(f, "external-CAS Noise session failed: {error}"),
            Self::Protocol => write!(f, "external-CAS Noise wire frame is malformed"),
            Self::ProviderRejected => write!(f, "external-CAS provider rejected the operation"),
            Self::Contract(error) => {
                write!(f, "external-CAS contract rejected the operation: {error}")
            }
        }
    }
}
impl std::error::Error for ExternalCasNoiseError {}
impl From<QRunV05NoiseError> for ExternalCasNoiseError {
    fn from(value: QRunV05NoiseError) -> Self {
        Self::Noise(value.to_string())
    }
}
impl From<io::Error> for ExternalCasNoiseError {
    fn from(value: io::Error) -> Self {
        Self::Io(value.to_string())
    }
}

fn is_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}

/// Derive the Noise prologue profile from the full receipt pin. Client and service use the same
/// value so a Noise session cannot be replayed across providers, Genesis identities, or receipt keys.
pub fn external_cas_noise_profile_id(
    pin: &ExternalCasPin,
) -> Result<[u8; 32], ExternalCasNoiseError> {
    pin.validate()
        .map_err(|error| ExternalCasNoiseError::Contract(error.to_string()))?;
    let mut hash = Sha256::new();
    hash.update(PROFILE_DOMAIN);
    hash.update(pin.provider_id);
    hash.update(pin.network_id);
    hash.update(pin.genesis_digest);
    hash.update(pin.receipt_key_id);
    hash.update(pin.receipt_public_key);
    let id: [u8; 32] = hash.finalize().into();
    if is_zero(&id) {
        return Err(ExternalCasNoiseError::InvalidConfiguration);
    }
    Ok(id)
}

/// One request per TCP connection. The Noise server static key and the ML-DSA receipt pin are
/// distinct out-of-band trust anchors.
pub struct NoiseTcpExternalCasProviderTransport {
    address: SocketAddr,
    local_static_private_key: [u8; 32],
    trusted_server_static_public_key: [u8; 32],
    pin: ExternalCasPin,
    profile_id: [u8; 32],
    connect_timeout: Duration,
}
impl fmt::Debug for NoiseTcpExternalCasProviderTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NoiseTcpExternalCasProviderTransport")
            .field("address", &self.address)
            .field("local_static_private_key", &"<redacted>")
            .field("trusted_server_static_public_key", &"<pinned-key>")
            .field("provider_id", &self.pin.provider_id)
            .field("network_id", &self.pin.network_id)
            .field("genesis_digest", &self.pin.genesis_digest)
            .field("connect_timeout", &self.connect_timeout)
            .finish()
    }
}
impl Drop for NoiseTcpExternalCasProviderTransport {
    fn drop(&mut self) {
        self.local_static_private_key.fill(0);
    }
}
impl NoiseTcpExternalCasProviderTransport {
    pub fn new(
        address: SocketAddr,
        local_static_private_key: [u8; 32],
        trusted_server_static_public_key: [u8; 32],
        pin: ExternalCasPin,
    ) -> Result<Self, ExternalCasNoiseError> {
        Self::with_timeout(
            address,
            local_static_private_key,
            trusted_server_static_public_key,
            pin,
            DEFAULT_CONNECT_TIMEOUT,
        )
    }

    pub fn with_timeout(
        address: SocketAddr,
        local_static_private_key: [u8; 32],
        trusted_server_static_public_key: [u8; 32],
        pin: ExternalCasPin,
        connect_timeout: Duration,
    ) -> Result<Self, ExternalCasNoiseError> {
        if is_zero(&local_static_private_key)
            || is_zero(&trusted_server_static_public_key)
            || connect_timeout.is_zero()
            || connect_timeout > MAX_CONNECT_TIMEOUT
        {
            return Err(ExternalCasNoiseError::InvalidConfiguration);
        }
        pin.validate()
            .map_err(|error| ExternalCasNoiseError::Contract(error.to_string()))?;
        let profile_id = external_cas_noise_profile_id(&pin)?;
        Ok(Self {
            address,
            local_static_private_key,
            trusted_server_static_public_key,
            pin,
            profile_id,
            connect_timeout,
        })
    }

    fn exchange(&self, kind: u16, payload: &[u8]) -> Result<Vec<u8>, ExternalCasNoiseError> {
        if !matches!(kind, KIND_READ | KIND_COMPARE_AND_SWAP) {
            return Err(ExternalCasNoiseError::Protocol);
        }
        let mut stream = TcpStream::connect_timeout(&self.address, self.connect_timeout)?;
        stream.set_nodelay(true)?;
        let mut session = QRunV05NoiseSession::connect(
            &mut stream,
            &self.local_static_private_key,
            &self.trusted_server_static_public_key,
            &self.pin.network_id,
            &self.profile_id,
        )?;
        let mut request = Vec::with_capacity(REQUEST_HEADER_BYTES + payload.len());
        request.extend_from_slice(REQUEST_MAGIC);
        request.extend_from_slice(&WIRE_VERSION.to_be_bytes());
        request.extend_from_slice(&kind.to_be_bytes());
        request.extend_from_slice(payload);
        session.write_record(&mut stream, &request)?;
        let response = session.read_record(&mut stream)?;
        if response.len() < RESPONSE_HEADER_BYTES
            || &response[..4] != RESPONSE_MAGIC
            || u16::from_be_bytes([response[4], response[5]]) != WIRE_VERSION
            || u16::from_be_bytes([response[6], response[7]]) != kind
        {
            return Err(ExternalCasNoiseError::Protocol);
        }
        let status = u16::from_be_bytes([response[8], response[9]]);
        if status == STATUS_REJECTED {
            if response.len() != RESPONSE_HEADER_BYTES {
                return Err(ExternalCasNoiseError::Protocol);
            }
            return Err(ExternalCasNoiseError::ProviderRejected);
        }
        if status != STATUS_OK {
            return Err(ExternalCasNoiseError::Protocol);
        }
        Ok(response[RESPONSE_HEADER_BYTES..].to_vec())
    }
}

impl ExternalCasProviderTransport for NoiseTcpExternalCasProviderTransport {
    type Error = ExternalCasNoiseError;

    fn read_current(
        &mut self,
        request: &ExternalCasReadRequest,
    ) -> Result<(ExternalCasRecord, ExternalCasReceipt), Self::Error> {
        if is_zero(&request.request_nonce)
            || is_zero(&request.operation_id)
            || is_zero(&request.request_digest)
        {
            return Err(ExternalCasNoiseError::Protocol);
        }
        let mut payload = Vec::with_capacity(READ_REQUEST_BYTES);
        payload.extend_from_slice(&request.request_nonce);
        payload.extend_from_slice(&request.operation_id);
        payload.extend_from_slice(&request.request_digest);
        let response = self.exchange(KIND_READ, &payload)?;
        if response.len() != EXTERNAL_CAS_RECORD_BYTES + EXTERNAL_CAS_RECEIPT_BYTES {
            return Err(ExternalCasNoiseError::Protocol);
        }
        let record = ExternalCasRecord::decode(&response[..EXTERNAL_CAS_RECORD_BYTES])
            .map_err(|error| ExternalCasNoiseError::Contract(error.to_string()))?;
        let receipt = ExternalCasReceipt::decode(&response[EXTERNAL_CAS_RECORD_BYTES..])
            .map_err(|error| ExternalCasNoiseError::Contract(error.to_string()))?;
        Ok((record, receipt))
    }

    fn compare_and_swap(
        &mut self,
        request: &ExternalCasWriteRequest,
    ) -> Result<ExternalCasReceipt, Self::Error> {
        request
            .validate(&self.pin)
            .map_err(|error| ExternalCasNoiseError::Contract(error.to_string()))?;
        let mut payload = Vec::with_capacity(WRITE_REQUEST_BYTES);
        payload.extend_from_slice(&request.request_nonce);
        payload.extend_from_slice(&request.operation_id);
        payload.extend_from_slice(&request.request_digest);
        payload.extend_from_slice(&request.expected_generation.to_be_bytes());
        payload.extend_from_slice(&request.expected_object_generation.to_be_bytes());
        payload.extend_from_slice(&request.expected_record_digest);
        payload.extend_from_slice(&request.expected_state_digest);
        payload.extend_from_slice(
            &request
                .next_record
                .encode()
                .map_err(|error| ExternalCasNoiseError::Contract(error.to_string()))?,
        );
        if payload.len() != WRITE_REQUEST_BYTES {
            return Err(ExternalCasNoiseError::Protocol);
        }
        let response = self.exchange(KIND_COMPARE_AND_SWAP, &payload)?;
        if response.len() != EXTERNAL_CAS_RECEIPT_BYTES {
            return Err(ExternalCasNoiseError::Protocol);
        }
        ExternalCasReceipt::decode(&response)
            .map_err(|error| ExternalCasNoiseError::Contract(error.to_string()))
    }
}

/// Handle one authenticated CAS request. The backend MUST implement durable, atomic server-side
/// compare-and-swap; a read followed by an unconditional write does not satisfy the contract.
/// The caller's VerifiedExternalCasClient remains responsible for verifying receipt signatures.
pub fn serve_external_cas_noise_connection<B>(
    stream: &mut TcpStream,
    local_static_private_key: &[u8; 32],
    trusted_client_static_public_keys: &[[u8; 32]],
    pin: &ExternalCasPin,
    backend: &mut B,
) -> Result<(), ExternalCasNoiseError>
where
    B: ExternalCasProviderTransport,
{
    pin.validate()
        .map_err(|error| ExternalCasNoiseError::Contract(error.to_string()))?;
    let profile_id = external_cas_noise_profile_id(pin)?;
    let mut session = QRunV05NoiseSession::accept(
        stream,
        local_static_private_key,
        trusted_client_static_public_keys,
        &pin.network_id,
        &profile_id,
    )?;
    let request = session.read_record(stream)?;
    if request.len() < REQUEST_HEADER_BYTES
        || &request[..4] != REQUEST_MAGIC
        || u16::from_be_bytes([request[4], request[5]]) != WIRE_VERSION
    {
        return Err(ExternalCasNoiseError::Protocol);
    }
    let kind = u16::from_be_bytes([request[6], request[7]]);
    let payload = &request[REQUEST_HEADER_BYTES..];

    let body = match kind {
        KIND_READ => {
            if payload.len() != READ_REQUEST_BYTES {
                return Err(ExternalCasNoiseError::Protocol);
            }
            let read = ExternalCasReadRequest {
                request_nonce: payload[0..32]
                    .try_into()
                    .map_err(|_| ExternalCasNoiseError::Protocol)?,
                operation_id: payload[32..64]
                    .try_into()
                    .map_err(|_| ExternalCasNoiseError::Protocol)?,
                request_digest: payload[64..96]
                    .try_into()
                    .map_err(|_| ExternalCasNoiseError::Protocol)?,
            };
            if is_zero(&read.request_nonce)
                || is_zero(&read.operation_id)
                || is_zero(&read.request_digest)
            {
                return Err(ExternalCasNoiseError::Protocol);
            }
            match backend.read_current(&read) {
                Ok((record, receipt)) => {
                    let record = record
                        .encode()
                        .map_err(|error| ExternalCasNoiseError::Contract(error.to_string()))?;
                    let receipt = receipt
                        .encode()
                        .map_err(|error| ExternalCasNoiseError::Contract(error.to_string()))?;
                    let mut body = Vec::with_capacity(record.len() + receipt.len());
                    body.extend_from_slice(&record);
                    body.extend_from_slice(&receipt);
                    Some(body)
                }
                Err(_) => None,
            }
        }
        KIND_COMPARE_AND_SWAP => {
            if payload.len() != WRITE_REQUEST_BYTES {
                return Err(ExternalCasNoiseError::Protocol);
            }
            let write = decode_write_request(payload)?;
            write
                .validate(pin)
                .map_err(|error| ExternalCasNoiseError::Contract(error.to_string()))?;
            match backend.compare_and_swap(&write) {
                Ok(receipt) => Some(
                    receipt
                        .encode()
                        .map_err(|error| ExternalCasNoiseError::Contract(error.to_string()))?
                        .to_vec(),
                ),
                Err(_) => None,
            }
        }
        _ => return Err(ExternalCasNoiseError::Protocol),
    };

    let (status, payload) = match body {
        Some(body) => (STATUS_OK, body),
        None => (STATUS_REJECTED, Vec::new()),
    };
    let mut response = Vec::with_capacity(RESPONSE_HEADER_BYTES + payload.len());
    response.extend_from_slice(RESPONSE_MAGIC);
    response.extend_from_slice(&WIRE_VERSION.to_be_bytes());
    response.extend_from_slice(&kind.to_be_bytes());
    response.extend_from_slice(&status.to_be_bytes());
    response.extend_from_slice(&payload);
    session.write_record(stream, &response)?;
    Ok(())
}

fn decode_write_request(payload: &[u8]) -> Result<ExternalCasWriteRequest, ExternalCasNoiseError> {
    if payload.len() != WRITE_REQUEST_BYTES {
        return Err(ExternalCasNoiseError::Protocol);
    }
    let next_record = ExternalCasRecord::decode(&payload[176..])
        .map_err(|error| ExternalCasNoiseError::Contract(error.to_string()))?;
    Ok(ExternalCasWriteRequest {
        request_nonce: payload[0..32]
            .try_into()
            .map_err(|_| ExternalCasNoiseError::Protocol)?,
        operation_id: payload[32..64]
            .try_into()
            .map_err(|_| ExternalCasNoiseError::Protocol)?,
        request_digest: payload[64..96]
            .try_into()
            .map_err(|_| ExternalCasNoiseError::Protocol)?,
        expected_generation: u64::from_be_bytes(
            payload[96..104]
                .try_into()
                .map_err(|_| ExternalCasNoiseError::Protocol)?,
        ),
        expected_object_generation: u64::from_be_bytes(
            payload[104..112]
                .try_into()
                .map_err(|_| ExternalCasNoiseError::Protocol)?,
        ),
        expected_record_digest: payload[112..144]
            .try_into()
            .map_err(|_| ExternalCasNoiseError::Protocol)?,
        expected_state_digest: payload[144..176]
            .try_into()
            .map_err(|_| ExternalCasNoiseError::Protocol)?,
        next_record,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        external_cas_anchor_candidate::{
            ExternalCasReceiptKind, ExternalCasReceiptOutcome, ExternalCasWriteRequest,
            VerifiedExternalCasClient,
        },
        v4_fat1_mldsa65_candidate::LibcruxMlDsa65VerifierCandidate,
        v4_fat1_trust_candidate::ML_DSA_65_SIGNATURE_BYTES,
    };
    use libcrux_ml_dsa::ml_dsa_65::portable;
    use snow::{params::NoiseParams, Builder};
    use std::{net::TcpListener, sync::Arc, thread};

    type ReceiptSignature = [u8; ML_DSA_65_SIGNATURE_BYTES];

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

    struct FixtureProvider {
        pin: ExternalCasPin,
        record: ExternalCasRecord,
        object_generation: u64,
        signer: Box<dyn Fn(&[u8; 32]) -> ReceiptSignature + Send + Sync>,
    }
    impl FixtureProvider {
        fn receipt(
            &self,
            kind: ExternalCasReceiptKind,
            outcome: ExternalCasReceiptOutcome,
            nonce: [u8; 32],
            operation_id: [u8; 32],
            request_digest: [u8; 32],
        ) -> ExternalCasReceipt {
            let mut receipt = ExternalCasReceipt {
                kind,
                outcome,
                generation: self.record.generation,
                object_generation: self.object_generation,
                provider_id: self.pin.provider_id,
                network_id: self.pin.network_id,
                genesis_digest: self.pin.genesis_digest,
                receipt_key_id: self.pin.receipt_key_id,
                request_nonce: nonce,
                record_digest: self.record.digest().unwrap(),
                previous_record_digest: self.record.previous_record_digest,
                previous_state_digest: self.record.previous_state_digest,
                state_digest: self.record.next_state_digest,
                operation_id,
                request_digest,
                signature: [0; ML_DSA_65_SIGNATURE_BYTES],
            };
            let digest = receipt.signing_digest().unwrap();
            receipt.signature = (self.signer)(&digest);
            receipt
        }
    }
    impl ExternalCasProviderTransport for FixtureProvider {
        type Error = String;

        fn read_current(
            &mut self,
            request: &ExternalCasReadRequest,
        ) -> Result<(ExternalCasRecord, ExternalCasReceipt), Self::Error> {
            let receipt = self.receipt(
                ExternalCasReceiptKind::Read,
                ExternalCasReceiptOutcome::Observed,
                request.request_nonce,
                request.operation_id,
                request.request_digest,
            );
            Ok((self.record.clone(), receipt))
        }

        fn compare_and_swap(
            &mut self,
            request: &ExternalCasWriteRequest,
        ) -> Result<ExternalCasReceipt, Self::Error> {
            request
                .validate(&self.pin)
                .map_err(|error| error.to_string())?;
            if self.record.digest().map_err(|error| error.to_string())?
                != request.expected_record_digest
                || self.object_generation != request.expected_object_generation
            {
                return Err("compare-and-swap conflict".into());
            }
            self.record = request.next_record.clone();
            self.object_generation = self
                .object_generation
                .checked_add(1)
                .ok_or_else(|| "object generation overflow".to_string())?;
            Ok(self.receipt(
                ExternalCasReceiptKind::Commit,
                ExternalCasReceiptOutcome::Applied,
                request.request_nonce,
                request.operation_id,
                request.request_digest,
            ))
        }
    }

    #[test]
    fn noise_tcp_transport_verifies_signed_read_and_atomic_cas_receipts() {
        let receipt_keys = portable::generate_key_pair([0x5A; 32]);
        let signing_key = Arc::new(receipt_keys.signing_key);
        let receipt_public_key: [u8; crate::v4_fat1_trust_candidate::ML_DSA_65_PUBLIC_KEY_BYTES] =
            *receipt_keys.verification_key.as_ref();
        let signer = Box::new(move |digest: &[u8; 32]| {
            *portable::sign(&signing_key, digest, &[], [0x73; 32])
                .unwrap()
                .as_ref()
        });
        let pin = ExternalCasPin {
            provider_id: [0x11; 32],
            network_id: [0x22; 32],
            genesis_digest: [0x33; 32],
            receipt_key_id: [0x44; 32],
            receipt_public_key,
        };
        let bootstrap = ExternalCasRecord {
            generation: 0,
            provider_id: pin.provider_id,
            network_id: pin.network_id,
            genesis_digest: pin.genesis_digest,
            previous_record_digest: [0; 32],
            previous_state_digest: [0; 32],
            next_state_digest: [0x66; 32],
            operation_id: [0x77; 32],
            request_digest: [0x88; 32],
        };
        let (server_private, server_public) = noise_keypair();
        let (client_private, client_public) = noise_keypair();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server_pin = pin.clone();
        let server_thread = thread::spawn(move || {
            let mut backend = FixtureProvider {
                pin: server_pin.clone(),
                record: bootstrap,
                object_generation: 1,
                signer,
            };
            for _ in 0..2 {
                let (mut stream, _) = listener.accept().unwrap();
                serve_external_cas_noise_connection(
                    &mut stream,
                    &server_private,
                    &[client_public],
                    &server_pin,
                    &mut backend,
                )
                .unwrap();
            }
            (backend.record, backend.object_generation)
        });

        let transport = NoiseTcpExternalCasProviderTransport::new(
            address,
            client_private,
            server_public,
            pin.clone(),
        )
        .unwrap();
        let mut client =
            VerifiedExternalCasClient::new(pin.clone(), transport, LibcruxMlDsa65VerifierCandidate)
                .unwrap();
        let read = ExternalCasReadRequest {
            request_nonce: [0x91; 32],
            operation_id: [0x92; 32],
            request_digest: [0x93; 32],
        };
        let observed = client.read_current(&read, 0, 1, None).unwrap();
        assert_eq!(observed.record.generation, 0);
        assert_eq!(observed.record.next_state_digest, [0x66; 32]);
        assert_eq!(observed.object_generation, 1);

        let mut write = ExternalCasWriteRequest {
            request_nonce: [0xA1; 32],
            operation_id: [0xA2; 32],
            request_digest: [0; 32],
            expected_generation: observed.record.generation,
            expected_object_generation: observed.object_generation,
            expected_record_digest: observed.record.digest().unwrap(),
            expected_state_digest: observed.record.next_state_digest,
            next_record: ExternalCasRecord {
                generation: 1,
                provider_id: pin.provider_id,
                network_id: pin.network_id,
                genesis_digest: pin.genesis_digest,
                previous_record_digest: observed.record.digest().unwrap(),
                previous_state_digest: observed.record.next_state_digest,
                next_state_digest: [0xB1; 32],
                operation_id: [0xA2; 32],
                request_digest: [0; 32],
            },
        };
        write.bind_request_digest(&pin).unwrap();
        let committed = client.compare_and_swap(&write).unwrap();
        assert_eq!(committed.kind, ExternalCasReceiptKind::Commit);
        assert_eq!(committed.outcome, ExternalCasReceiptOutcome::Applied);
        assert_eq!(committed.generation, 1);
        assert_eq!(committed.object_generation, 2);
        let (stored, generation) = server_thread.join().unwrap();
        assert_eq!(stored, write.next_record);
        assert_eq!(generation, 2);
    }
}
