//! CP-0580 candidate: QFP6 self-contained hybrid transaction authentication.
//!
//! Every accepted signature envelope carries an Ed25519 public key and an ML-DSA-65 public
//! key, followed by signatures over the same TXN2 signing digest. The sender account is
//! domain-separated from legacy Ed25519 accounts and binds both public keys. There is no
//! Ed25519-only fallback in this authenticator.
//!
//! ML-DSA verification is injected through the existing verifier boundary. The bundled
//! Libcrux adapter remains a candidate and is not production/security approved. This module
//! does not activate the QFP6 node binary or freeze the account-identity protocol.

use crate::{
    state_machine::{transaction_signing_digest, AccountId, Transaction, TransactionAuthenticator},
    v4_fat1_trust_candidate::{
        MlDsa65Verifier, ML_DSA_65_PUBLIC_KEY_BYTES, ML_DSA_65_SIGNATURE_BYTES,
    },
};
use ed25519_dalek::{Signature as Ed25519Signature, Signer, SigningKey, VerifyingKey};
use libcrux_ml_dsa::ml_dsa_65::{portable, MLDSA65SigningKey};
use sha2::{Digest, Sha256};
use std::fmt;

pub const QRUN_V06_HYBRID_ACCOUNT_ID_DOMAIN: &[u8] = b"AIN1-QFP6-ACCOUNT-ID-HYBRID-V1\0";
pub const QRUN_V06_HYBRID_SIGNATURE_MAGIC: [u8; 4] = *b"Q6HA";
pub const QRUN_V06_HYBRID_SIGNATURE_VERSION: u16 = 1;
pub const QRUN_V06_HYBRID_SIGNATURE_SUITE: u16 = 1;
pub const QRUN_V06_ED25519_PUBLIC_KEY_BYTES: usize = 32;
pub const QRUN_V06_ED25519_SIGNATURE_BYTES: usize = 64;
pub const QRUN_V06_HYBRID_SIGNATURE_HEADER_BYTES: usize = 8;
pub const QRUN_V06_HYBRID_SIGNATURE_ENVELOPE_BYTES: usize = QRUN_V06_HYBRID_SIGNATURE_HEADER_BYTES
    + QRUN_V06_ED25519_PUBLIC_KEY_BYTES
    + ML_DSA_65_PUBLIC_KEY_BYTES
    + QRUN_V06_ED25519_SIGNATURE_BYTES
    + ML_DSA_65_SIGNATURE_BYTES;

/// Maximum signature wire size after CP-0580. The QFP6 block byte budget remains the
/// tighter aggregate bound, so a block cannot contain 1024 maximum-size hybrid transactions.
pub const QRUN_V06_HYBRID_MAX_SIGNATURE_BYTES: usize = 8 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QRunV06HybridAuthError {
    InvalidSeed,
    RandomnessUnavailable,
    MlDsaSigningFailed,
    WrongSigner,
    InvalidTransaction,
}

impl fmt::Display for QRunV06HybridAuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for QRunV06HybridAuthError {}

/// Derive a QFP6-native account ID from both public keys. This is intentionally not the
/// legacy Ed25519-only account-ID formula and not the V4 hybrid account-ID domain.
pub fn qrun_v06_hybrid_account_id(
    ed25519_public_key: &[u8; QRUN_V06_ED25519_PUBLIC_KEY_BYTES],
    mldsa65_public_key: &[u8; ML_DSA_65_PUBLIC_KEY_BYTES],
) -> AccountId {
    let mut hash = Sha256::new();
    hash.update(QRUN_V06_HYBRID_ACCOUNT_ID_DOMAIN);
    hash.update(QRUN_V06_HYBRID_SIGNATURE_SUITE.to_be_bytes());
    hash.update(ed25519_public_key);
    hash.update(mldsa65_public_key);
    hash.finalize().into()
}

/// Local hybrid signer. The ML-DSA secret key is created from an independently domain-derived
/// 32-byte seed; callers remain responsible for secure custody and backup of the seed material.
pub struct QRunV06HybridTransactionSigner {
    ed25519_signing_key: SigningKey,
    mldsa65_signing_key: MLDSA65SigningKey,
    ed25519_public_key: [u8; QRUN_V06_ED25519_PUBLIC_KEY_BYTES],
    mldsa65_public_key: [u8; ML_DSA_65_PUBLIC_KEY_BYTES],
}

impl QRunV06HybridTransactionSigner {
    /// Construct from two distinct, nonzero secret seeds. A mnemonic wallet should derive
    /// the two inputs with separate domain labels; do not reuse the same raw seed for both.
    pub fn from_seeds(
        mut ed25519_seed: [u8; 32],
        mut mldsa65_seed: [u8; 32],
    ) -> Result<Self, QRunV06HybridAuthError> {
        if ed25519_seed.iter().all(|byte| *byte == 0)
            || mldsa65_seed.iter().all(|byte| *byte == 0)
            || ed25519_seed == mldsa65_seed
        {
            ed25519_seed.fill(0);
            mldsa65_seed.fill(0);
            return Err(QRunV06HybridAuthError::InvalidSeed);
        }
        let ed25519_signing_key = SigningKey::from_bytes(&ed25519_seed);
        ed25519_seed.fill(0);

        let mldsa65_key_pair = portable::generate_key_pair(mldsa65_seed);
        mldsa65_seed.fill(0);
        let ed25519_public_key = ed25519_signing_key.verifying_key().to_bytes();
        let mldsa65_public_key: [u8; ML_DSA_65_PUBLIC_KEY_BYTES] =
            *mldsa65_key_pair.verification_key.as_ref();

        Ok(Self {
            ed25519_signing_key,
            mldsa65_signing_key: mldsa65_key_pair.signing_key,
            ed25519_public_key,
            mldsa65_public_key,
        })
    }

    pub fn ed25519_public_key(&self) -> [u8; QRUN_V06_ED25519_PUBLIC_KEY_BYTES] {
        self.ed25519_public_key
    }

    pub fn mldsa65_public_key(&self) -> [u8; ML_DSA_65_PUBLIC_KEY_BYTES] {
        self.mldsa65_public_key
    }

    pub fn account_id(&self) -> AccountId {
        qrun_v06_hybrid_account_id(&self.ed25519_public_key, &self.mldsa65_public_key)
    }

    /// Sign a normal QFP6 TXN2 transaction. Both algorithms sign the exact same domain-separated
    /// digest, which already commits network, sender, recipient, nonce, amount, fee and expiry.
    pub fn sign_transaction(
        &self,
        transaction: &mut Transaction,
    ) -> Result<(), QRunV06HybridAuthError> {
        if transaction.sender != self.account_id() {
            return Err(QRunV06HybridAuthError::WrongSigner);
        }
        let digest = transaction_signing_digest(transaction)
            .map_err(|_| QRunV06HybridAuthError::InvalidTransaction)?;

        let ed25519_signature = self.ed25519_signing_key.sign(&digest).to_bytes();
        let mut optrand = [0u8; 32];
        getrandom::getrandom(&mut optrand)
            .map_err(|_| QRunV06HybridAuthError::RandomnessUnavailable)?;
        let mldsa65_signature = portable::sign(&self.mldsa65_signing_key, &digest, &[], optrand)
            .map_err(|_| {
                optrand.fill(0);
                QRunV06HybridAuthError::MlDsaSigningFailed
            })?;
        optrand.fill(0);

        let mut envelope = Vec::with_capacity(QRUN_V06_HYBRID_SIGNATURE_ENVELOPE_BYTES);
        envelope.extend_from_slice(&QRUN_V06_HYBRID_SIGNATURE_MAGIC);
        envelope.extend_from_slice(&QRUN_V06_HYBRID_SIGNATURE_VERSION.to_be_bytes());
        envelope.extend_from_slice(&QRUN_V06_HYBRID_SIGNATURE_SUITE.to_be_bytes());
        envelope.extend_from_slice(&self.ed25519_public_key);
        envelope.extend_from_slice(&self.mldsa65_public_key);
        envelope.extend_from_slice(&ed25519_signature);
        envelope.extend_from_slice(mldsa65_signature.as_ref());
        if envelope.len() != QRUN_V06_HYBRID_SIGNATURE_ENVELOPE_BYTES
            || envelope.len() > QRUN_V06_HYBRID_MAX_SIGNATURE_BYTES
        {
            return Err(QRunV06HybridAuthError::InvalidTransaction);
        }
        transaction.signature = envelope;
        Ok(())
    }
}

/// Stateless, self-contained QFP6 transaction verifier. A signature is accepted only when:
/// - the exact Q6HA v1 / suite 1 envelope is present;
/// - both embedded public keys are nonzero and derive the supplied sender account ID;
/// - strict Ed25519 verification succeeds; and
/// - the injected ML-DSA-65 verifier accepts the same signing digest.
pub struct QRunV06HybridTransactionAuthenticator<V> {
    mldsa65_verifier: V,
}

impl<V> QRunV06HybridTransactionAuthenticator<V> {
    pub fn new(mldsa65_verifier: V) -> Self {
        Self { mldsa65_verifier }
    }
}

impl<V: MlDsa65Verifier> TransactionAuthenticator for QRunV06HybridTransactionAuthenticator<V> {
    fn verify(
        &self,
        sender: &AccountId,
        signing_digest: &[u8; 32],
        signature: &[u8],
    ) -> Result<(), ()> {
        if signature.len() != QRUN_V06_HYBRID_SIGNATURE_ENVELOPE_BYTES
            || signature.len() > QRUN_V06_HYBRID_MAX_SIGNATURE_BYTES
            || signature[..4] != QRUN_V06_HYBRID_SIGNATURE_MAGIC
            || u16::from_be_bytes([signature[4], signature[5]]) != QRUN_V06_HYBRID_SIGNATURE_VERSION
            || u16::from_be_bytes([signature[6], signature[7]]) != QRUN_V06_HYBRID_SIGNATURE_SUITE
        {
            return Err(());
        }

        let mut offset = QRUN_V06_HYBRID_SIGNATURE_HEADER_BYTES;
        let ed25519_public_key: [u8; QRUN_V06_ED25519_PUBLIC_KEY_BYTES] = signature
            [offset..offset + QRUN_V06_ED25519_PUBLIC_KEY_BYTES]
            .try_into()
            .map_err(|_| ())?;
        offset += QRUN_V06_ED25519_PUBLIC_KEY_BYTES;
        let mldsa65_public_key: [u8; ML_DSA_65_PUBLIC_KEY_BYTES] = signature
            [offset..offset + ML_DSA_65_PUBLIC_KEY_BYTES]
            .try_into()
            .map_err(|_| ())?;
        offset += ML_DSA_65_PUBLIC_KEY_BYTES;
        let ed25519_signature: [u8; QRUN_V06_ED25519_SIGNATURE_BYTES] = signature
            [offset..offset + QRUN_V06_ED25519_SIGNATURE_BYTES]
            .try_into()
            .map_err(|_| ())?;
        offset += QRUN_V06_ED25519_SIGNATURE_BYTES;
        let mldsa65_signature: [u8; ML_DSA_65_SIGNATURE_BYTES] = signature
            [offset..offset + ML_DSA_65_SIGNATURE_BYTES]
            .try_into()
            .map_err(|_| ())?;

        if ed25519_public_key.iter().all(|byte| *byte == 0)
            || mldsa65_public_key.iter().all(|byte| *byte == 0)
            || qrun_v06_hybrid_account_id(&ed25519_public_key, &mldsa65_public_key) != *sender
        {
            return Err(());
        }

        let ed25519_verifying_key =
            VerifyingKey::from_bytes(&ed25519_public_key).map_err(|_| ())?;
        let ed25519_signature = Ed25519Signature::from_bytes(&ed25519_signature);
        ed25519_verifying_key
            .verify_strict(signing_digest, &ed25519_signature)
            .map_err(|_| ())?;

        if !self
            .mldsa65_verifier
            .verify(&mldsa65_public_key, signing_digest, &mldsa65_signature)
        {
            return Err(());
        }
        Ok(())
    }

    fn verification_cache_scope(&self) -> Option<[u8; 32]> {
        Some(
            Sha256::digest(
                b"AIN1-QFP6-HYBRID-TXN-AUTH-CACHE-V1\0"
                    .iter()
                    .copied()
                    .chain(QRUN_V06_HYBRID_SIGNATURE_VERSION.to_be_bytes())
                    .chain(QRUN_V06_HYBRID_SIGNATURE_SUITE.to_be_bytes())
                    .collect::<Vec<_>>(),
            )
            .into(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        qrun_v06_canonical_execution_candidate::{
            decode_qrun_v06_block, encode_qrun_v06_block, QRunV06Block, QRunV06BlockOperation,
        },
        state_machine::{
            decode_transaction, decode_transaction_with_signature_limit, encode_transaction,
            encode_transaction_with_signature_limit, transaction_id_with_signature_limit,
            QRUN_V06_MAX_NATIVE_TX_SIGNATURE_BYTES,
        },
        v4_fat1_mldsa65_candidate::LibcruxMlDsa65VerifierCandidate,
    };

    fn unsigned_transaction(sender: AccountId) -> Transaction {
        Transaction {
            network_id: [0xA1; 32],
            sender,
            recipient: [0xC3; 32],
            nonce: 1,
            amount: 123_456,
            fee: 789,
            expires_at: 1_900_000_000,
            signature: Vec::new(),
        }
    }

    fn signer() -> QRunV06HybridTransactionSigner {
        QRunV06HybridTransactionSigner::from_seeds([0x42; 32], [0x53; 32]).unwrap()
    }

    fn authenticator() -> QRunV06HybridTransactionAuthenticator<LibcruxMlDsa65VerifierCandidate> {
        QRunV06HybridTransactionAuthenticator::new(LibcruxMlDsa65VerifierCandidate)
    }

    #[test]
    fn real_hybrid_signatures_roundtrip_through_txn2_and_verify() {
        let signer = signer();
        let mut transaction = unsigned_transaction(signer.account_id());
        signer.sign_transaction(&mut transaction).unwrap();

        assert_eq!(
            transaction.signature.len(),
            QRUN_V06_HYBRID_SIGNATURE_ENVELOPE_BYTES
        );
        assert!(transaction.signature.len() > 4 * 1024);
        assert!(transaction.signature.len() <= QRUN_V06_MAX_NATIVE_TX_SIGNATURE_BYTES);
        assert_eq!(
            authenticator().verify(
                &transaction.sender,
                &transaction_signing_digest(&transaction).unwrap(),
                &transaction.signature,
            ),
            Ok(())
        );

        // Legacy/unversioned TXN2 remains capped at 4 KiB; only QFP6 QFB6 native transfers
        // use the explicitly version-scoped 8 KiB codec for the hybrid envelope.
        assert!(encode_transaction(&transaction).is_err());
        let wire = encode_transaction_with_signature_limit(
            &transaction,
            QRUN_V06_MAX_NATIVE_TX_SIGNATURE_BYTES,
        )
        .unwrap();
        assert!(decode_transaction(&wire).is_err());
        let decoded =
            decode_transaction_with_signature_limit(&wire, QRUN_V06_MAX_NATIVE_TX_SIGNATURE_BYTES)
                .unwrap();
        assert_eq!(decoded, transaction);
        assert_eq!(
            transaction_id_with_signature_limit(&decoded, QRUN_V06_MAX_NATIVE_TX_SIGNATURE_BYTES,)
                .unwrap(),
            transaction_id_with_signature_limit(
                &transaction,
                QRUN_V06_MAX_NATIVE_TX_SIGNATURE_BYTES,
            )
            .unwrap()
        );
    }

    #[test]
    fn qfp6_canonical_block_codec_accepts_hybrid_native_transfer_without_widening_legacy_txn2() {
        let signer = signer();
        let mut transaction = unsigned_transaction(signer.account_id());
        signer.sign_transaction(&mut transaction).unwrap();
        let block = QRunV06Block {
            network_id: transaction.network_id,
            profile_id: [0xB2; 32],
            height: 1,
            timestamp: 100,
            parent_hash: [0xC3; 32],
            state_root: [0xD4; 32],
            producer: [0xE5; 32],
            operations: vec![QRunV06BlockOperation::NativeTransfer(transaction)],
        };
        let wire = encode_qrun_v06_block(&block).unwrap();
        let decoded = decode_qrun_v06_block(&wire).unwrap();
        assert_eq!(decoded, block);
        assert!(wire.len() > 5_365);
    }

    #[test]
    fn both_signatures_are_required_and_tampering_fails_closed() {
        let signer = signer();
        let auth = authenticator();
        let mut transaction = unsigned_transaction(signer.account_id());
        signer.sign_transaction(&mut transaction).unwrap();
        let digest = transaction_signing_digest(&transaction).unwrap();

        let mut bad_ed25519 = transaction.signature.clone();
        let ed_offset = QRUN_V06_HYBRID_SIGNATURE_HEADER_BYTES
            + QRUN_V06_ED25519_PUBLIC_KEY_BYTES
            + ML_DSA_65_PUBLIC_KEY_BYTES;
        bad_ed25519[ed_offset] ^= 1;
        assert!(auth
            .verify(&transaction.sender, &digest, &bad_ed25519)
            .is_err());

        let mut bad_mldsa65 = transaction.signature.clone();
        *bad_mldsa65.last_mut().unwrap() ^= 1;
        assert!(auth
            .verify(&transaction.sender, &digest, &bad_mldsa65)
            .is_err());

        let mut bad_public_key = transaction.signature.clone();
        bad_public_key
            [QRUN_V06_HYBRID_SIGNATURE_HEADER_BYTES + QRUN_V06_ED25519_PUBLIC_KEY_BYTES + 7] ^= 1;
        assert!(auth
            .verify(&transaction.sender, &digest, &bad_public_key)
            .is_err());
    }

    #[test]
    fn account_binding_and_signing_digest_prevent_sender_or_transaction_replay() {
        let signer = signer();
        let auth = authenticator();
        let mut transaction = unsigned_transaction(signer.account_id());
        signer.sign_transaction(&mut transaction).unwrap();

        let mut wrong_sender = transaction.sender;
        wrong_sender[0] ^= 1;
        let digest = transaction_signing_digest(&transaction).unwrap();
        assert!(auth
            .verify(&wrong_sender, &digest, &transaction.signature)
            .is_err());

        let mut changed_transaction = transaction.clone();
        changed_transaction.amount += 1;
        let changed_digest = transaction_signing_digest(&changed_transaction).unwrap();
        assert!(auth
            .verify(
                &changed_transaction.sender,
                &changed_digest,
                &transaction.signature
            )
            .is_err());
    }

    #[test]
    fn rejects_legacy_ed25519_only_and_noncanonical_hybrid_envelopes() {
        let signer = signer();
        let auth = authenticator();
        let mut transaction = unsigned_transaction(signer.account_id());
        signer.sign_transaction(&mut transaction).unwrap();
        let digest = transaction_signing_digest(&transaction).unwrap();

        assert!(auth
            .verify(
                &transaction.sender,
                &digest,
                &transaction.signature[..transaction.signature.len() - 1]
            )
            .is_err());
        assert!(auth
            .verify(&transaction.sender, &digest, &transaction.signature[..64])
            .is_err());

        let mut wrong_version = transaction.signature.clone();
        wrong_version[5] ^= 1;
        assert!(auth
            .verify(&transaction.sender, &digest, &wrong_version)
            .is_err());
        let mut wrong_suite = transaction.signature.clone();
        wrong_suite[7] ^= 1;
        assert!(auth
            .verify(&transaction.sender, &digest, &wrong_suite)
            .is_err());
        let mut trailing = transaction.signature.clone();
        trailing.push(0);
        assert!(auth
            .verify(&transaction.sender, &digest, &trailing)
            .is_err());
    }

    #[test]
    fn signer_rejects_invalid_or_reused_seed_inputs_and_wrong_sender() {
        assert!(QRunV06HybridTransactionSigner::from_seeds([0; 32], [1; 32]).is_err());
        assert!(QRunV06HybridTransactionSigner::from_seeds([1; 32], [1; 32]).is_err());
        let signer = signer();
        let mut transaction = unsigned_transaction([0x77; 32]);
        assert_eq!(
            signer.sign_transaction(&mut transaction),
            Err(QRunV06HybridAuthError::WrongSigner)
        );
    }

    #[test]
    fn hybrid_account_identity_is_domain_separated_and_cache_scope_is_stable() {
        let signer = signer();
        let auth = authenticator();
        assert_ne!(signer.account_id(), [0; 32]);
        assert_eq!(
            qrun_v06_hybrid_account_id(&signer.ed25519_public_key(), &signer.mldsa65_public_key()),
            signer.account_id()
        );
        assert_eq!(
            auth.verification_cache_scope(),
            auth.verification_cache_scope()
        );
        assert!(QRUN_V06_HYBRID_SIGNATURE_ENVELOPE_BYTES <= QRUN_V06_HYBRID_MAX_SIGNATURE_BYTES);
    }
}
