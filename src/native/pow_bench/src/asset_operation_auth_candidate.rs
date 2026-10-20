//! Candidate binding between a TXN2 transaction identity and one canonical AOP1 operation.
//!
//! This module is deliberately not wired into consensus or the TXN2 production path.
//! It exists to test the proposed pre-activation signing rule without silently changing
//! the current wire format.

use crate::{
    asset_transactions::{encode_operation, AssetOperation, AssetOperationError},
    state_machine::{transaction_signing_digest, StateError, Transaction},
};
use sha2::{Digest, Sha256};

pub const ASSET_TX_BINDING_DOMAIN: &[u8] = b"AIN1-TX-ASSET-SIGN-V1\0";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AssetOperationAuthError {
    Transaction(StateError),
    AssetOperation(AssetOperationError),
}

impl From<StateError> for AssetOperationAuthError {
    fn from(value: StateError) -> Self {
        Self::Transaction(value)
    }
}

impl From<AssetOperationError> for AssetOperationAuthError {
    fn from(value: AssetOperationError) -> Self {
        Self::AssetOperation(value)
    }
}

/// Candidate signing digest that binds the existing TXN2 signing digest to the
/// complete canonical AOP1 operation bytes. Signature bytes are never included.
pub fn asset_operation_signing_digest(
    tx: &Transaction,
    operation: &AssetOperation,
) -> Result<[u8; 32], AssetOperationAuthError> {
    let tx_digest = transaction_signing_digest(tx)?;
    let operation_bytes = encode_operation(operation)?;
    let mut hasher = Sha256::new();
    hasher.update(ASSET_TX_BINDING_DOMAIN);
    hasher.update(tx_digest);
    hasher.update(&operation_bytes);
    Ok(hasher.finalize().into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::asset_transactions::AssetOperation;
    use crate::state_machine::{AccountId, NetworkId};

    fn tx() -> Transaction {
        Transaction {
            network_id: [0xA1; 32],
            sender: [0x11; 32],
            recipient: [0x22; 32],
            nonce: 7,
            amount: 123_456,
            fee: 9,
            expires_at: 9_999,
            signature: vec![0xAA; 64],
        }
    }

    fn operation() -> AssetOperation {
        AssetOperation::Mint {
            asset_id: [0x44; 32],
            amount: 123_456_789_012_345,
        }
    }

    #[test]
    fn binding_changes_when_transaction_identity_changes() {
        let base = asset_operation_signing_digest(&tx(), &operation()).unwrap();
        let mut network = tx();
        network.network_id = [0xA2; 32];
        assert_ne!(
            base,
            asset_operation_signing_digest(&network, &operation()).unwrap()
        );

        let mut sender = tx();
        sender.sender = [0x33; 32];
        assert_ne!(
            base,
            asset_operation_signing_digest(&sender, &operation()).unwrap()
        );

        let mut nonce = tx();
        nonce.nonce += 1;
        assert_ne!(
            base,
            asset_operation_signing_digest(&nonce, &operation()).unwrap()
        );

        let mut signature = tx();
        signature.signature[0] ^= 1;
        assert_eq!(
            base,
            asset_operation_signing_digest(&signature, &operation()).unwrap()
        );
    }

    #[test]
    fn binding_changes_when_operation_changes_and_rejects_invalid_operation() {
        let base = asset_operation_signing_digest(&tx(), &operation()).unwrap();
        let changed = AssetOperation::Mint {
            asset_id: [0x44; 32],
            amount: 123_456_789_012_346,
        };
        assert_ne!(
            base,
            asset_operation_signing_digest(&tx(), &changed).unwrap()
        );
        let invalid = AssetOperation::Mint {
            asset_id: [0x44; 32],
            amount: 0,
        };
        assert!(matches!(
            asset_operation_signing_digest(&tx(), &invalid),
            Err(AssetOperationAuthError::AssetOperation(_))
        ));
    }

    #[test]
    fn independent_vector_matches_candidate_digest() {
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../../simulations/cpw_asset_operation_auth_vectors.txt");
        let text = std::fs::read_to_string(path).expect("read candidate vector");
        let mut values = std::collections::BTreeMap::new();
        let mut lines = text.lines();
        assert_eq!(lines.next(), Some("CPW_ASSET_OPERATION_AUTH_V1"));
        for line in lines.take_while(|line| *line != "END") {
            let (k, v) = line.split_once('=').expect("vector key=value");
            values.insert(k.to_string(), v.to_string());
        }
        let hex = |name: &str| -> Vec<u8> {
            let value = values.get(name).expect("vector field");
            (0..value.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&value[i..i + 2], 16).unwrap())
                .collect()
        };
        let network_id: NetworkId = hex("NETWORK_ID").try_into().unwrap();
        let sender: AccountId = hex("SENDER").try_into().unwrap();
        let recipient: AccountId = hex("RECIPIENT").try_into().unwrap();
        let asset_id: [u8; 32] = hex("ASSET_ID").try_into().unwrap();
        let tx = Transaction {
            network_id,
            sender,
            recipient,
            nonce: values["NONCE"].parse().unwrap(),
            amount: values["AMOUNT"].parse().unwrap(),
            fee: values["FEE"].parse().unwrap(),
            expires_at: values["EXPIRES_AT"].parse().unwrap(),
            signature: vec![0xAA; 64],
        };
        let operation = AssetOperation::Mint {
            asset_id,
            amount: values["ASSET_AMOUNT"].parse().unwrap(),
        };
        assert_eq!(
            hex("TX_SIGNING_DIGEST"),
            transaction_signing_digest(&tx).unwrap()
        );
        assert_eq!(
            hex("OP_HEX"),
            crate::asset_transactions::encode_operation(&operation).unwrap()
        );
        assert_eq!(
            hex("BINDING_DIGEST"),
            asset_operation_signing_digest(&tx, &operation).unwrap()
        );
        assert_eq!(values.len(), 12);
    }
}
