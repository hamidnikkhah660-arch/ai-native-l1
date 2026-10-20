//! Bounded native-asset operation payloads for the CP-W Token Forge.
//!
//! Research/testbed wire layer only. These payloads are not yet embedded into TXN2
//! or LedgerState. The operation envelope is intentionally independent so its canonical
//! encoding can be frozen and independently implemented before state integration.

use crate::token_forge::{
    decode_definition, encode_definition, AssetDefinition, AssetId, TokenForgeError,
};
use std::io::{Cursor, Read};

pub const ASSET_OPERATION_MAGIC: [u8; 4] = *b"AOP1";
pub const ASSET_OPERATION_VERSION: u16 = 1;
pub const MAX_ASSET_OPERATION_BYTES: usize = 512;
pub const MAX_CREATE_DEFINITION_BYTES: usize = 256;
pub const ASSET_ID_LEN: usize = 32;
pub const ACCOUNT_ID_LEN: usize = 32;

const FIXED_HEADER_LEN: usize = 8;
const MINT_PAYLOAD_LEN: usize = 32 + 16;
const BURN_PAYLOAD_LEN: usize = 32 + 16;
const FREEZE_PAYLOAD_LEN: usize = 32 + 1;
const TRANSFER_PAYLOAD_LEN: usize = 32 + 32 + 16;

pub type AccountId = [u8; 32];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AssetOperation {
    Create {
        definition: AssetDefinition,
    },
    Mint {
        asset_id: AssetId,
        amount: u128,
    },
    Burn {
        asset_id: AssetId,
        amount: u128,
    },
    Freeze {
        asset_id: AssetId,
        frozen: bool,
    },
    Transfer {
        asset_id: AssetId,
        recipient: AccountId,
        amount: u128,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AssetOperationError {
    TokenForge(TokenForgeError),
    Malformed,
    BadMagic,
    UnsupportedVersion(u16),
    UnknownOperation(u8),
    Oversize { actual: usize, limit: usize },
    LengthOverflow,
    InvalidLength { expected: usize, actual: usize },
    InvalidAssetId,
    InvalidAccountId,
    ZeroAmount,
    InvalidFreezeFlag(u8),
    NonCanonicalDefinition,
    TrailingBytes,
}

impl From<TokenForgeError> for AssetOperationError {
    fn from(value: TokenForgeError) -> Self {
        Self::TokenForge(value)
    }
}

impl std::fmt::Display for AssetOperationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TokenForge(error) => write!(f, "token forge error: {error}"),
            Self::Malformed => write!(f, "malformed asset operation"),
            Self::BadMagic => write!(f, "bad asset operation magic"),
            Self::UnsupportedVersion(version) => {
                write!(f, "unsupported asset operation version {version}")
            }
            Self::UnknownOperation(tag) => write!(f, "unknown asset operation tag {tag}"),
            Self::Oversize { actual, limit } => {
                write!(f, "asset operation is {actual} bytes; maximum is {limit}")
            }
            Self::LengthOverflow => write!(f, "asset operation length overflow"),
            Self::InvalidLength { expected, actual } => {
                write!(
                    f,
                    "invalid operation length: expected {expected}, got {actual}"
                )
            }
            Self::InvalidAssetId => write!(f, "asset ID must not be all zero"),
            Self::InvalidAccountId => write!(f, "account ID must not be all zero"),
            Self::ZeroAmount => write!(f, "amount must be positive"),
            Self::InvalidFreezeFlag(value) => write!(f, "invalid freeze flag {value}"),
            Self::NonCanonicalDefinition => write!(f, "asset definition is not canonical"),
            Self::TrailingBytes => write!(f, "asset operation has trailing bytes"),
        }
    }
}

impl std::error::Error for AssetOperationError {}

impl AssetOperation {
    pub fn tag(&self) -> u8 {
        match self {
            Self::Create { .. } => 1,
            Self::Mint { .. } => 2,
            Self::Burn { .. } => 3,
            Self::Freeze { .. } => 4,
            Self::Transfer { .. } => 5,
        }
    }
}

fn ensure_nonzero_32(value: &[u8; 32]) -> Result<(), AssetOperationError> {
    if value.iter().all(|byte| *byte == 0) {
        return Err(AssetOperationError::InvalidAssetId);
    }
    Ok(())
}

fn ensure_nonzero_account(value: &[u8; 32]) -> Result<(), AssetOperationError> {
    if value.iter().all(|byte| *byte == 0) {
        return Err(AssetOperationError::InvalidAccountId);
    }
    Ok(())
}

fn write_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn write_u128(out: &mut Vec<u8>, value: u128) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn read_array<const N: usize>(cursor: &mut Cursor<&[u8]>) -> Result<[u8; N], AssetOperationError> {
    let mut value = [0u8; N];
    cursor
        .read_exact(&mut value)
        .map_err(|_| AssetOperationError::Malformed)?;
    Ok(value)
}

fn read_u16(cursor: &mut Cursor<&[u8]>) -> Result<u16, AssetOperationError> {
    Ok(u16::from_be_bytes(read_array(cursor)?))
}

fn read_u128(cursor: &mut Cursor<&[u8]>) -> Result<u128, AssetOperationError> {
    Ok(u128::from_be_bytes(read_array(cursor)?))
}

/// Canonical operation envelope:
/// magic(4) || version(2) || tag(1) || reserved(1) || operation payload.
pub fn encode_operation(operation: &AssetOperation) -> Result<Vec<u8>, AssetOperationError> {
    let mut out = Vec::with_capacity(MAX_ASSET_OPERATION_BYTES);
    out.extend_from_slice(&ASSET_OPERATION_MAGIC);
    write_u16(&mut out, ASSET_OPERATION_VERSION);
    out.push(operation.tag());
    out.push(0);

    match operation {
        AssetOperation::Create { definition } => {
            let definition_bytes = encode_definition(definition)?;
            if definition_bytes.len() > MAX_CREATE_DEFINITION_BYTES {
                return Err(AssetOperationError::Oversize {
                    actual: definition_bytes.len(),
                    limit: MAX_CREATE_DEFINITION_BYTES,
                });
            }
            let len = u16::try_from(definition_bytes.len())
                .map_err(|_| AssetOperationError::LengthOverflow)?;
            write_u16(&mut out, len);
            out.extend_from_slice(&definition_bytes);
        }
        AssetOperation::Mint { asset_id, amount } => {
            ensure_nonzero_32(asset_id)?;
            if *amount == 0 {
                return Err(AssetOperationError::ZeroAmount);
            }
            out.extend_from_slice(asset_id);
            write_u128(&mut out, *amount);
        }
        AssetOperation::Burn { asset_id, amount } => {
            ensure_nonzero_32(asset_id)?;
            if *amount == 0 {
                return Err(AssetOperationError::ZeroAmount);
            }
            out.extend_from_slice(asset_id);
            write_u128(&mut out, *amount);
        }
        AssetOperation::Freeze { asset_id, frozen } => {
            ensure_nonzero_32(asset_id)?;
            out.extend_from_slice(asset_id);
            out.push(u8::from(*frozen));
        }
        AssetOperation::Transfer {
            asset_id,
            recipient,
            amount,
        } => {
            ensure_nonzero_32(asset_id)?;
            ensure_nonzero_account(recipient)?;
            if *amount == 0 {
                return Err(AssetOperationError::ZeroAmount);
            }
            out.extend_from_slice(asset_id);
            out.extend_from_slice(recipient);
            write_u128(&mut out, *amount);
        }
    }

    if out.len() > MAX_ASSET_OPERATION_BYTES {
        return Err(AssetOperationError::Oversize {
            actual: out.len(),
            limit: MAX_ASSET_OPERATION_BYTES,
        });
    }
    Ok(out)
}

pub fn decode_operation(bytes: &[u8]) -> Result<AssetOperation, AssetOperationError> {
    if bytes.len() > MAX_ASSET_OPERATION_BYTES {
        return Err(AssetOperationError::Oversize {
            actual: bytes.len(),
            limit: MAX_ASSET_OPERATION_BYTES,
        });
    }
    if bytes.len() < FIXED_HEADER_LEN {
        return Err(AssetOperationError::Malformed);
    }

    let mut cursor = Cursor::new(bytes);
    if read_array::<4>(&mut cursor)? != ASSET_OPERATION_MAGIC {
        return Err(AssetOperationError::BadMagic);
    }
    let version = read_u16(&mut cursor)?;
    if version != ASSET_OPERATION_VERSION {
        return Err(AssetOperationError::UnsupportedVersion(version));
    }
    let tag = read_array::<1>(&mut cursor)?[0];
    let reserved = read_array::<1>(&mut cursor)?[0];
    if reserved != 0 {
        return Err(AssetOperationError::Malformed);
    }

    let operation = match tag {
        1 => {
            let definition_len = read_u16(&mut cursor)? as usize;
            if definition_len > MAX_CREATE_DEFINITION_BYTES {
                return Err(AssetOperationError::Oversize {
                    actual: definition_len,
                    limit: MAX_CREATE_DEFINITION_BYTES,
                });
            }
            let mut definition_bytes = vec![0u8; definition_len];
            cursor
                .read_exact(&mut definition_bytes)
                .map_err(|_| AssetOperationError::Malformed)?;
            let definition = decode_definition(&definition_bytes)?;
            AssetOperation::Create { definition }
        }
        2 => {
            let expected = FIXED_HEADER_LEN + MINT_PAYLOAD_LEN;
            if bytes.len() != expected {
                return Err(AssetOperationError::InvalidLength {
                    expected,
                    actual: bytes.len(),
                });
            }
            let asset_id = read_array::<32>(&mut cursor)?;
            ensure_nonzero_32(&asset_id)?;
            let amount = read_u128(&mut cursor)?;
            if amount == 0 {
                return Err(AssetOperationError::ZeroAmount);
            }
            AssetOperation::Mint { asset_id, amount }
        }
        3 => {
            let expected = FIXED_HEADER_LEN + BURN_PAYLOAD_LEN;
            if bytes.len() != expected {
                return Err(AssetOperationError::InvalidLength {
                    expected,
                    actual: bytes.len(),
                });
            }
            let asset_id = read_array::<32>(&mut cursor)?;
            ensure_nonzero_32(&asset_id)?;
            let amount = read_u128(&mut cursor)?;
            if amount == 0 {
                return Err(AssetOperationError::ZeroAmount);
            }
            AssetOperation::Burn { asset_id, amount }
        }
        4 => {
            let expected = FIXED_HEADER_LEN + FREEZE_PAYLOAD_LEN;
            if bytes.len() != expected {
                return Err(AssetOperationError::InvalidLength {
                    expected,
                    actual: bytes.len(),
                });
            }
            let asset_id = read_array::<32>(&mut cursor)?;
            ensure_nonzero_32(&asset_id)?;
            let flag = read_array::<1>(&mut cursor)?[0];
            let frozen = match flag {
                0 => false,
                1 => true,
                other => return Err(AssetOperationError::InvalidFreezeFlag(other)),
            };
            AssetOperation::Freeze { asset_id, frozen }
        }
        5 => {
            let expected = FIXED_HEADER_LEN + TRANSFER_PAYLOAD_LEN;
            if bytes.len() != expected {
                return Err(AssetOperationError::InvalidLength {
                    expected,
                    actual: bytes.len(),
                });
            }
            let asset_id = read_array::<32>(&mut cursor)?;
            let recipient = read_array::<32>(&mut cursor)?;
            ensure_nonzero_32(&asset_id)?;
            ensure_nonzero_account(&recipient)?;
            let amount = read_u128(&mut cursor)?;
            if amount == 0 {
                return Err(AssetOperationError::ZeroAmount);
            }
            AssetOperation::Transfer {
                asset_id,
                recipient,
                amount,
            }
        }
        other => return Err(AssetOperationError::UnknownOperation(other)),
    };

    if cursor.position() as usize != bytes.len() {
        return Err(AssetOperationError::TrailingBytes);
    }

    let canonical = encode_operation(&operation)?;
    if canonical != bytes {
        return Err(AssetOperationError::NonCanonicalDefinition);
    }
    Ok(operation)
}

/// Canonical bytes for the operation hash/signing layer. This stays separate from AssetId.
pub fn operation_id(operation: &AssetOperation) -> Result<[u8; 32], AssetOperationError> {
    use sha2::{Digest, Sha256};
    let canonical = encode_operation(operation)?;
    let mut hash = Sha256::new();
    hash.update(b"AIN1-ASSET-OP-ID-V1\0");
    hash.update(&canonical);
    Ok(hash.finalize().into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::token_forge::{BurnAuthority, FreezePolicy, MintAuthority, NetworkId, SupplyPolicy};

    const NETWORK: NetworkId = [0x11; 32];
    const CREATOR: AccountId = [0x22; 32];
    const RECIPIENT: AccountId = [0x33; 32];
    const ASSET: AssetId = [0x44; 32];

    fn definition() -> AssetDefinition {
        AssetDefinition {
            network_id: NETWORK,
            creator: CREATOR,
            creation_nonce: 7,
            name: "SafeWork Credit".to_owned(),
            symbol: "SWC".to_owned(),
            decimals: 8,
            metadata_hash: [0x55; 32],
            supply_policy: SupplyPolicy::Capped {
                initial_supply: 1_000,
                max_supply: 10_000,
            },
            mint_authority: MintAuthority::Creator,
            burn_authority: BurnAuthority::Holder,
            freeze_policy: FreezePolicy::Creator,
        }
    }

    #[test]
    fn each_operation_roundtrips_canonically() {
        let operations = [
            AssetOperation::Create {
                definition: definition(),
            },
            AssetOperation::Mint {
                asset_id: ASSET,
                amount: 123,
            },
            AssetOperation::Burn {
                asset_id: ASSET,
                amount: 17,
            },
            AssetOperation::Freeze {
                asset_id: ASSET,
                frozen: true,
            },
            AssetOperation::Transfer {
                asset_id: ASSET,
                recipient: RECIPIENT,
                amount: 77,
            },
        ];

        for operation in operations {
            let bytes = encode_operation(&operation).unwrap();
            assert!(bytes.len() <= MAX_ASSET_OPERATION_BYTES);
            assert_eq!(decode_operation(&bytes).unwrap(), operation);
            assert_eq!(
                encode_operation(&decode_operation(&bytes).unwrap()).unwrap(),
                bytes
            );
        }
    }

    #[test]
    fn create_payload_stays_bounded_and_freeze_encoding_is_single_byte() {
        let create = encode_operation(&AssetOperation::Create {
            definition: definition(),
        })
        .unwrap();
        assert_eq!(create.len(), 8 + 2 + 167);
        let freeze = encode_operation(&AssetOperation::Freeze {
            asset_id: ASSET,
            frozen: false,
        })
        .unwrap();
        assert_eq!(freeze.len(), 41);
    }

    #[test]
    fn wrong_reserved_byte_unknown_tag_and_bad_lengths_fail_closed() {
        let base = encode_operation(&AssetOperation::Mint {
            asset_id: ASSET,
            amount: 1,
        })
        .unwrap();

        let mut reserved = base.clone();
        reserved[7] = 1;
        assert_eq!(
            decode_operation(&reserved),
            Err(AssetOperationError::Malformed)
        );

        let mut unknown = base.clone();
        unknown[6] = 99;
        assert_eq!(
            decode_operation(&unknown),
            Err(AssetOperationError::UnknownOperation(99))
        );

        let truncated = &base[..base.len() - 1];
        assert!(decode_operation(truncated).is_err());

        let mut trailing = base.clone();
        trailing.push(0);
        assert!(decode_operation(&trailing).is_err());
    }

    #[test]
    fn zero_ids_zero_amount_and_invalid_freeze_are_rejected() {
        assert_eq!(
            encode_operation(&AssetOperation::Mint {
                asset_id: [0; 32],
                amount: 1,
            }),
            Err(AssetOperationError::InvalidAssetId)
        );
        assert_eq!(
            encode_operation(&AssetOperation::Transfer {
                asset_id: ASSET,
                recipient: [0; 32],
                amount: 1,
            }),
            Err(AssetOperationError::InvalidAccountId)
        );
        assert_eq!(
            encode_operation(&AssetOperation::Burn {
                asset_id: ASSET,
                amount: 0,
            }),
            Err(AssetOperationError::ZeroAmount)
        );

        let mut freeze = encode_operation(&AssetOperation::Freeze {
            asset_id: ASSET,
            frozen: true,
        })
        .unwrap();
        freeze[40] = 2;
        assert_eq!(
            decode_operation(&freeze),
            Err(AssetOperationError::InvalidFreezeFlag(2))
        );
    }

    #[test]
    fn operation_id_is_deterministic_and_binds_operation_type() {
        let mint = AssetOperation::Mint {
            asset_id: ASSET,
            amount: 1,
        };
        let burn = AssetOperation::Burn {
            asset_id: ASSET,
            amount: 1,
        };
        assert_eq!(operation_id(&mint).unwrap(), operation_id(&mint).unwrap());
        assert_ne!(operation_id(&mint).unwrap(), operation_id(&burn).unwrap());
    }

    #[test]
    fn malformed_byte_campaign_never_panics() {
        let valid = [
            AssetOperation::Create {
                definition: definition(),
            },
            AssetOperation::Mint {
                asset_id: ASSET,
                amount: 123,
            },
            AssetOperation::Burn {
                asset_id: ASSET,
                amount: 17,
            },
            AssetOperation::Freeze {
                asset_id: ASSET,
                frozen: true,
            },
            AssetOperation::Transfer {
                asset_id: ASSET,
                recipient: RECIPIENT,
                amount: 77,
            },
        ];
        for operation in valid {
            let bytes = encode_operation(&operation).unwrap();
            for index in 0..bytes.len() {
                for bit in 0..8 {
                    let mut mutated = bytes.clone();
                    mutated[index] ^= 1u8 << bit;
                    let _ = decode_operation(&mutated);
                }
            }
        }
    }

    #[test]
    fn oversize_bytes_are_rejected_before_deep_parse() {
        let bytes = vec![0u8; MAX_ASSET_OPERATION_BYTES + 1];
        assert_eq!(
            decode_operation(&bytes),
            Err(AssetOperationError::Oversize {
                actual: MAX_ASSET_OPERATION_BYTES + 1,
                limit: MAX_ASSET_OPERATION_BYTES
            })
        );
    }
}
