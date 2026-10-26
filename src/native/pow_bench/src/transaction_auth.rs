//! Explicit Ed25519 transaction authentication for the CP-0026-D research gate.
//!
//! The ledger-facing account ID is derived from the registered public key. TXN2's
//! signing digest already binds network ID, sender, receiver, nonce, amount, fee,
//! and exclusive expiry. No fake/default authenticator is exposed by this module.
//! Production key custody, migration, and independent cryptographic review remain open.
use crate::state_machine::{
    transaction_signing_digest, AccountId, Transaction, TransactionAuthenticator,
};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub const ED25519_SIGNATURE_LEN: usize = 64;
pub const ED25519_PUBLIC_KEY_LEN: usize = 32;
pub const ED25519_SELF_CONTAINED_SIGNATURE_LEN: usize =
    ED25519_PUBLIC_KEY_LEN + ED25519_SIGNATURE_LEN;
pub const ACCOUNT_ID_DOMAIN: &[u8] = b"AIN1-ACCOUNT-ID-ED25519-V1\0";

/// Explicit algorithm selector. Unknown values must be rejected; never auto-fallback.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum TransactionAuthenticatorKind {
    Ed25519V1 = 1,
}

impl TryFrom<u16> for TransactionAuthenticatorKind {
    type Error = AuthenticatorConfigError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Ed25519V1),
            other => Err(AuthenticatorConfigError::UnsupportedKind(other)),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthenticatorConfigError {
    UnsupportedKind(u16),
    EmptyRegistry,
    InvalidPublicKey,
    AccountKeyMismatch,
    DuplicateAccount,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthenticatorError {
    WrongSignerAccount,
    InvalidTransaction,
}

/// Operator/config-supplied binding between one account and its Ed25519 public key.
/// account_id must be the domain-separated hash of public_key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountPublicKey {
    pub account_id: AccountId,
    pub public_key: [u8; ED25519_PUBLIC_KEY_LEN],
}

/// Stable account derivation. Network replay protection is independently provided by
/// network_id in the TXN2 signing preimage; account IDs need not vary between networks.
pub fn account_id_from_public_key(public_key: &[u8; ED25519_PUBLIC_KEY_LEN]) -> AccountId {
    let mut hash = Sha256::new();
    hash.update(ACCOUNT_ID_DOMAIN);
    hash.update(public_key);
    hash.finalize().into()
}

/// Signing helper. Keep this object in caller-controlled key custody; the ledger only
/// needs Ed25519TransactionAuthenticator and its public-key registry.
pub struct Ed25519TransactionSigner {
    signing_key: SigningKey,
}

impl Ed25519TransactionSigner {
    /// Construct from a caller-supplied 32-byte Ed25519 secret seed.
    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self {
            signing_key: SigningKey::from_bytes(&seed),
        }
    }

    pub fn public_key(&self) -> [u8; ED25519_PUBLIC_KEY_LEN] {
        self.signing_key.verifying_key().to_bytes()
    }

    pub fn account_id(&self) -> AccountId {
        account_id_from_public_key(&self.public_key())
    }

    /// Sign a TXN2 transaction using the legacy 64-byte registry-bound signature form.
    pub fn sign_transaction(&self, tx: &mut Transaction) -> Result<(), AuthenticatorError> {
        if tx.sender != self.account_id() {
            return Err(AuthenticatorError::WrongSignerAccount);
        }
        let digest =
            transaction_signing_digest(tx).map_err(|_| AuthenticatorError::InvalidTransaction)?;
        tx.signature = self.sign_digest(&digest);
        Ok(())
    }

    /// Sign a TXN2 transaction with a self-contained `[public_key || signature]` envelope.
    /// This lets any validating node derive the sender account from the transaction itself,
    /// rather than requiring every account's key to be provisioned out-of-band.
    pub fn sign_transaction_self_contained(
        &self,
        tx: &mut Transaction,
    ) -> Result<(), AuthenticatorError> {
        if tx.sender != self.account_id() {
            return Err(AuthenticatorError::WrongSignerAccount);
        }
        let digest =
            transaction_signing_digest(tx).map_err(|_| AuthenticatorError::InvalidTransaction)?;
        let public_key = self.public_key();
        let signature = self.sign_digest(&digest);
        let mut envelope = Vec::with_capacity(ED25519_SELF_CONTAINED_SIGNATURE_LEN);
        envelope.extend_from_slice(&public_key);
        envelope.extend_from_slice(&signature);
        tx.signature = envelope;
        Ok(())
    }

    pub fn sign_digest(&self, digest: &[u8; 32]) -> Vec<u8> {
        self.signing_key.sign(digest).to_bytes().to_vec()
    }
}

/// Immutable selected verifier. Construct explicitly with an algorithm identifier and
/// a complete account/public-key binding set; there is no test-fixture fallback.
pub struct Ed25519TransactionAuthenticator {
    selected_kind: TransactionAuthenticatorKind,
    keys: BTreeMap<AccountId, VerifyingKey>,
    // Immutable scope is computed once at configuration time, not on every transaction.
    verification_scope: [u8; 32],
}

impl Ed25519TransactionAuthenticator {
    fn compute_verification_cache_scope(
        kind: TransactionAuthenticatorKind,
        keys: &BTreeMap<AccountId, VerifyingKey>,
    ) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(b"AIN1-TX-AUTH-VERIFY-CACHE-SCOPE-V1\0");
        hash.update((kind as u16).to_be_bytes());
        hash.update((keys.len() as u64).to_be_bytes());
        for (account_id, public_key) in keys {
            hash.update(account_id);
            hash.update(public_key.to_bytes());
        }
        hash.finalize().into()
    }

    pub fn select_by_id<I>(kind_id: u16, entries: I) -> Result<Self, AuthenticatorConfigError>
    where
        I: IntoIterator<Item = AccountPublicKey>,
    {
        let kind = TransactionAuthenticatorKind::try_from(kind_id)?;
        Self::select(kind, entries)
    }

    pub fn select<I>(
        kind: TransactionAuthenticatorKind,
        entries: I,
    ) -> Result<Self, AuthenticatorConfigError>
    where
        I: IntoIterator<Item = AccountPublicKey>,
    {
        // Match explicitly so adding an algorithm later cannot silently reuse Ed25519.
        match kind {
            TransactionAuthenticatorKind::Ed25519V1 => {}
        }
        let mut keys = BTreeMap::new();
        for entry in entries {
            if account_id_from_public_key(&entry.public_key) != entry.account_id {
                return Err(AuthenticatorConfigError::AccountKeyMismatch);
            }
            let key = VerifyingKey::from_bytes(&entry.public_key)
                .map_err(|_| AuthenticatorConfigError::InvalidPublicKey)?;
            if key.is_weak() {
                return Err(AuthenticatorConfigError::InvalidPublicKey);
            }
            if keys.insert(entry.account_id, key).is_some() {
                return Err(AuthenticatorConfigError::DuplicateAccount);
            }
        }
        if keys.is_empty() {
            return Err(AuthenticatorConfigError::EmptyRegistry);
        }
        let verification_scope = Self::compute_verification_cache_scope(kind, &keys);
        Ok(Self {
            selected_kind: kind,
            keys,
            verification_scope,
        })
    }

    pub fn selected_kind(&self) -> TransactionAuthenticatorKind {
        self.selected_kind
    }

    pub fn registered_account_count(&self) -> usize {
        self.keys.len()
    }

    /// Verify a supplied digest for an account without mutating registry or ledger state.
    pub fn verify_account_digest(
        &self,
        sender: &AccountId,
        signing_digest: &[u8; 32],
        signature: &[u8],
    ) -> Result<(), ()> {
        if signature.len() == ED25519_SIGNATURE_LEN {
            let key = self.keys.get(sender).ok_or(())?;
            let signature = Signature::from_slice(signature).map_err(|_| ())?;
            return key
                .verify_strict(signing_digest, &signature)
                .map_err(|_| ());
        }
        if signature.len() != ED25519_SELF_CONTAINED_SIGNATURE_LEN {
            return Err(());
        }
        let public_key_bytes: [u8; ED25519_PUBLIC_KEY_LEN] = signature[..ED25519_PUBLIC_KEY_LEN]
            .try_into()
            .map_err(|_| ())?;
        if account_id_from_public_key(&public_key_bytes) != *sender {
            return Err(());
        }
        let key = VerifyingKey::from_bytes(&public_key_bytes).map_err(|_| ())?;
        if key.is_weak() {
            return Err(());
        }
        let signature =
            Signature::from_slice(&signature[ED25519_PUBLIC_KEY_LEN..]).map_err(|_| ())?;
        key.verify_strict(signing_digest, &signature)
            .map_err(|_| ())
    }
}

impl TransactionAuthenticator for Ed25519TransactionAuthenticator {
    fn verify(
        &self,
        sender: &AccountId,
        signing_digest: &[u8; 32],
        signature: &[u8],
    ) -> Result<(), ()> {
        self.verify_account_digest(sender, signing_digest, signature)
    }

    fn verification_cache_scope(&self) -> Option<[u8; 32]> {
        Some(self.verification_scope)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state_machine::{Block, LedgerState, NetworkId};

    const TEST_NETWORK_ID: NetworkId = [0xA1; 32];
    const TEST_SEED: [u8; 32] = [
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c,
        0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae,
        0x7f, 0x60,
    ];

    fn selected(signer: &Ed25519TransactionSigner) -> Ed25519TransactionAuthenticator {
        Ed25519TransactionAuthenticator::select_by_id(
            TransactionAuthenticatorKind::Ed25519V1 as u16,
            [AccountPublicKey {
                account_id: signer.account_id(),
                public_key: signer.public_key(),
            }],
        )
        .unwrap()
    }

    fn unsigned_transaction(sender: AccountId) -> Transaction {
        Transaction {
            network_id: TEST_NETWORK_ID,
            sender,
            recipient: [0x22; 32],
            nonce: 1,
            amount: 100,
            fee: 2,
            expires_at: 2_000,
            signature: Vec::new(),
        }
    }

    #[test]
    fn explicit_ed25519_selection_binds_account_and_verifies_signature() {
        let signer = Ed25519TransactionSigner::from_seed(TEST_SEED);
        let authenticator = selected(&signer);
        assert_eq!(
            authenticator.selected_kind(),
            TransactionAuthenticatorKind::Ed25519V1
        );
        assert_eq!(authenticator.registered_account_count(), 1);

        let mut tx = unsigned_transaction(signer.account_id());
        signer.sign_transaction(&mut tx).unwrap();
        let digest = transaction_signing_digest(&tx).unwrap();
        assert_eq!(
            authenticator.verify(&tx.sender, &digest, &tx.signature),
            Ok(())
        );
        assert_eq!(tx.signature.len(), ED25519_SIGNATURE_LEN);
    }

    #[test]
    fn self_contained_ed25519_signature_derives_sender_without_registry_provisioning() {
        let sender_signer = Ed25519TransactionSigner::from_seed(TEST_SEED);
        let unrelated_signer = Ed25519TransactionSigner::from_seed([0x42; 32]);
        let authenticator = selected(&unrelated_signer);
        let mut tx = unsigned_transaction(sender_signer.account_id());
        sender_signer
            .sign_transaction_self_contained(&mut tx)
            .unwrap();
        assert_eq!(tx.signature.len(), ED25519_SELF_CONTAINED_SIGNATURE_LEN);
        let digest = transaction_signing_digest(&tx).unwrap();
        assert_eq!(
            authenticator.verify(&tx.sender, &digest, &tx.signature),
            Ok(())
        );

        let mut bad_signature = tx.signature.clone();
        *bad_signature.last_mut().unwrap() ^= 1;
        assert_eq!(
            authenticator.verify(&tx.sender, &digest, &bad_signature),
            Err(())
        );
        let mut wrong_embedded_key = tx.signature.clone();
        wrong_embedded_key[0] ^= 1;
        assert_eq!(
            authenticator.verify(&tx.sender, &digest, &wrong_embedded_key),
            Err(())
        );
        assert_eq!(
            authenticator.verify(&[0x77; 32], &digest, &tx.signature),
            Err(())
        );
    }

    #[test]
    fn ed25519_verification_cache_scope_is_stable_and_binds_full_key_registry() {
        let signer_a = Ed25519TransactionSigner::from_seed(TEST_SEED);
        let signer_b = Ed25519TransactionSigner::from_seed([0x42; 32]);
        let same_registry_a = selected(&signer_a);
        let same_registry_b = selected(&signer_a);
        let different_registry = selected(&signer_b);

        let scope_a = same_registry_a.verification_cache_scope().unwrap();
        assert_eq!(Some(scope_a), same_registry_b.verification_cache_scope());
        assert_ne!(Some(scope_a), different_registry.verification_cache_scope());
    }

    #[test]
    fn ed25519_rejects_tampered_signature_digest_and_unknown_account() {
        let signer = Ed25519TransactionSigner::from_seed(TEST_SEED);
        let authenticator = selected(&signer);
        let mut tx = unsigned_transaction(signer.account_id());
        signer.sign_transaction(&mut tx).unwrap();
        let digest = transaction_signing_digest(&tx).unwrap();

        let mut bad_signature = tx.signature.clone();
        bad_signature[0] ^= 1;
        assert_eq!(
            authenticator.verify(&tx.sender, &digest, &bad_signature),
            Err(())
        );
        let mut bad_digest = digest;
        bad_digest[0] ^= 1;
        assert_eq!(
            authenticator.verify(&tx.sender, &bad_digest, &tx.signature),
            Err(())
        );
        assert_eq!(
            authenticator.verify(&[0x77; 32], &digest, &tx.signature),
            Err(())
        );
        assert_eq!(authenticator.verify(&tx.sender, &digest, &[0; 63]), Err(()));
    }

    #[test]
    fn registry_rejects_account_key_mismatch_duplicates_and_unknown_selector() {
        let signer = Ed25519TransactionSigner::from_seed(TEST_SEED);
        assert_eq!(
            Ed25519TransactionAuthenticator::select_by_id(999, std::iter::empty()).err(),
            Some(AuthenticatorConfigError::UnsupportedKind(999))
        );
        assert_eq!(
            Ed25519TransactionAuthenticator::select_by_id(1, std::iter::empty()).err(),
            Some(AuthenticatorConfigError::EmptyRegistry)
        );
        let weak_public_key = [0u8; ED25519_PUBLIC_KEY_LEN];
        assert_eq!(
            Ed25519TransactionAuthenticator::select_by_id(
                1,
                [AccountPublicKey {
                    account_id: account_id_from_public_key(&weak_public_key),
                    public_key: weak_public_key,
                }],
            )
            .err(),
            Some(AuthenticatorConfigError::InvalidPublicKey)
        );
        assert_eq!(
            Ed25519TransactionAuthenticator::select_by_id(
                1,
                [AccountPublicKey {
                    account_id: [0x55; 32],
                    public_key: signer.public_key(),
                }],
            )
            .err(),
            Some(AuthenticatorConfigError::AccountKeyMismatch)
        );
        let entry = AccountPublicKey {
            account_id: signer.account_id(),
            public_key: signer.public_key(),
        };
        assert_eq!(
            Ed25519TransactionAuthenticator::select(
                TransactionAuthenticatorKind::Ed25519V1,
                [entry.clone(), entry],
            )
            .err(),
            Some(AuthenticatorConfigError::DuplicateAccount)
        );
    }

    #[test]
    fn ed25519_transaction_executes_atomically_and_rejects_tampering() {
        let signer = Ed25519TransactionSigner::from_seed(TEST_SEED);
        let authenticator = selected(&signer);
        let sender = signer.account_id();
        let recipient = [0x22; 32];
        let mut state =
            LedgerState::genesis(TEST_NETWORK_ID, vec![(sender, 1_000), (recipient, 0)]).unwrap();
        let mut tx = unsigned_transaction(sender);
        signer.sign_transaction(&mut tx).unwrap();
        let mut block = Block {
            height: 1,
            timestamp: 1_999,
            parent_hash: state.tip_hash(),
            state_root: [0; 32],
            transactions: vec![tx.clone()],
        };
        block.state_root = state
            .preview_state_root_after(&block, &authenticator)
            .unwrap();
        state.apply_block(&block, &authenticator).unwrap();
        assert_eq!(state.account(&sender).unwrap().nonce, 1);
        assert_eq!(state.account(&sender).unwrap().balance, 898);
        assert_eq!(state.account(&recipient).unwrap().balance, 100);

        let mut replay_state =
            LedgerState::genesis(TEST_NETWORK_ID, vec![(sender, 1_000), (recipient, 0)]).unwrap();
        let mut tampered = tx;
        tampered.amount += 1;
        let mut rejected = Block {
            height: 1,
            timestamp: 1_999,
            parent_hash: replay_state.tip_hash(),
            state_root: [0; 32],
            transactions: vec![tampered],
        };
        let before = replay_state.encode_snapshot().unwrap();
        assert!(replay_state
            .preview_state_root_after(&rejected, &authenticator)
            .is_err());
        rejected.state_root = [0; 32];
        assert!(replay_state.apply_block(&rejected, &authenticator).is_err());
        assert_eq!(replay_state.encode_snapshot().unwrap(), before);
    }

    #[test]
    fn independent_python_ed25519_txn2_vector_matches_rust() {
        use std::collections::BTreeMap;
        use std::path::PathBuf;

        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../../simulations/cp0026d_ed25519_auth_vectors.txt");
        let text = std::fs::read_to_string(path).expect("read shared CP-0026-D vector");
        let mut values = BTreeMap::new();
        let mut lines = text.lines();
        assert_eq!(lines.next(), Some("CP0026D_ED25519_AUTH_V1"));
        for line in lines.take_while(|line| *line != "END") {
            let (key, value) = line.split_once('=').expect("key=value vector line");
            assert!(values.insert(key.to_string(), value.to_string()).is_none());
        }
        let value = |key: &str| {
            values
                .get(key)
                .unwrap_or_else(|| panic!("missing CP-0026-D vector field {key}"))
                .clone()
        };
        let unhex = |hex: &str| -> Vec<u8> {
            assert_eq!(hex.len() % 2, 0);
            (0..hex.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex byte"))
                .collect()
        };

        let signer = Ed25519TransactionSigner::from_seed(TEST_SEED);
        assert_eq!(value("AUTH_SCHEME"), "1");
        assert_eq!(value("AUTH_SCHEME_NAME"), "Ed25519V1");
        assert_eq!(signer.public_key().to_vec(), unhex(&value("PUBLIC_KEY")));
        assert_eq!(signer.account_id().to_vec(), unhex(&value("ACCOUNT_ID")));
        let network_id: NetworkId = unhex(&value("NETWORK_ID"))
            .try_into()
            .expect("32-byte network ID");
        let sender: AccountId = unhex(&value("ACCOUNT_ID"))
            .try_into()
            .expect("32-byte account ID");
        let recipient: AccountId = unhex(&value("RECIPIENT"))
            .try_into()
            .expect("32-byte recipient");
        let mut tx = Transaction {
            network_id,
            sender,
            recipient,
            nonce: value("NONCE").parse().unwrap(),
            amount: value("AMOUNT").parse().unwrap(),
            fee: value("FEE").parse().unwrap(),
            expires_at: value("EXPIRES_AT").parse().unwrap(),
            signature: Vec::new(),
        };
        assert_eq!(
            transaction_signing_digest(&tx).unwrap().to_vec(),
            unhex(&value("TX_SIGNING_DIGEST"))
        );
        signer.sign_transaction(&mut tx).unwrap();
        assert_eq!(tx.signature, unhex(&value("TX_SIGNATURE")));
        let encoded = crate::state_machine::encode_transaction(&tx).unwrap();
        assert_eq!(&encoded[..134], unhex(&value("TX_UNSIGNED_HEX")).as_slice());
        assert_eq!(encoded, unhex(&value("TX_HEX")));
        assert_eq!(
            crate::state_machine::transaction_id(&tx).unwrap().to_vec(),
            unhex(&value("TX_ID"))
        );

        let authenticator = Ed25519TransactionAuthenticator::select_by_id(
            value("AUTH_SCHEME").parse().unwrap(),
            [AccountPublicKey {
                account_id: sender,
                public_key: signer.public_key(),
            }],
        )
        .unwrap();
        let digest = transaction_signing_digest(&tx).unwrap();
        assert_eq!(
            authenticator.verify(&sender, &digest, &tx.signature),
            Ok(())
        );

        let mut changed_network = tx.clone();
        changed_network.network_id = unhex(&value("OTHER_NETWORK_ID"))
            .try_into()
            .expect("other network ID");
        let other_digest = transaction_signing_digest(&changed_network).unwrap();
        assert_eq!(
            other_digest.to_vec(),
            unhex(&value("OTHER_NETWORK_SIGNING_DIGEST"))
        );
        assert_ne!(digest, other_digest);
        assert_eq!(
            authenticator.verify(&sender, &other_digest, &tx.signature),
            Err(())
        );

        let mut changed_signature = tx.signature.clone();
        changed_signature[0] ^= 1;
        assert_eq!(
            authenticator.verify(&sender, &digest, &changed_signature),
            Err(())
        );
        let mut changed_digest = digest;
        changed_digest[0] ^= 1;
        assert_eq!(
            authenticator.verify(&sender, &changed_digest, &tx.signature),
            Err(())
        );
        assert_eq!(
            authenticator.verify(&[0x55; 32], &digest, &tx.signature),
            Err(())
        );
        assert_eq!(values.len(), 25);
    }

    #[test]
    fn wrong_sender_cannot_be_signed_by_another_account_key() {
        let signer_a = Ed25519TransactionSigner::from_seed(TEST_SEED);
        let signer_b = Ed25519TransactionSigner::from_seed([0x42; 32]);
        let mut tx = unsigned_transaction(signer_b.account_id());
        assert_eq!(
            signer_a.sign_transaction(&mut tx),
            Err(AuthenticatorError::WrongSignerAccount)
        );
    }
}
