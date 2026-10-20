//! CP-0130-Z disposable transaction-rejection and atomic-rollback exporter.
//!
//! Harness-only reference input generator. It calls the state-machine's crate-private
//! atomic apply method but is not used by the node, canonical consensus, or release builds.
//! All signer seeds below are public disposable fixtures, never production key material.

use crate::{
    state_machine::{
        encode_transaction, AccountId, Block, BlockApplySummary, LedgerState, NetworkId,
        StateError, Transaction, MAX_TOTAL_SUPPLY_ATOMS,
    },
    transaction_auth::{
        AccountPublicKey, Ed25519TransactionAuthenticator, Ed25519TransactionSigner,
        TransactionAuthenticatorKind,
    },
};

const NETWORK_ID: NetworkId = [0xD3; 32];
const OTHER_NETWORK_ID: NetworkId = [0xD4; 32];
const SIGNER_A_SEED: [u8; 32] = [0x10; 32];
const SIGNER_B_SEED: [u8; 32] = [0x20; 32];
const MISSING_SIGNER_SEED: [u8; 32] = [0x30; 32];
const RECIPIENT_C: AccountId = [0x33; 32];
const RECIPIENT_D: AccountId = [0x34; 32];
const MAX_RECIPIENT: AccountId = [0x44; 32];
const BLOCK_TIMESTAMP: u64 = 1_999;
const NORMAL_EXPIRY: u64 = 2_000;

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    out
}

fn signed_tx(
    signer: &Ed25519TransactionSigner,
    network_id: NetworkId,
    recipient: AccountId,
    nonce: u64,
    amount: u64,
    fee: u64,
    expires_at: u64,
) -> Transaction {
    let mut tx = Transaction {
        network_id,
        sender: signer.account_id(),
        recipient,
        nonce,
        amount,
        fee,
        expires_at,
        signature: Vec::new(),
    };
    signer
        .sign_transaction(&mut tx)
        .expect("fixture signer must bind the transaction sender");
    tx
}

fn authenticator(
    signer_a: &Ed25519TransactionSigner,
    signer_b: &Ed25519TransactionSigner,
    missing_signer: &Ed25519TransactionSigner,
) -> Ed25519TransactionAuthenticator {
    Ed25519TransactionAuthenticator::select(
        TransactionAuthenticatorKind::Ed25519V1,
        [
            AccountPublicKey {
                account_id: signer_a.account_id(),
                public_key: signer_a.public_key(),
            },
            AccountPublicKey {
                account_id: signer_b.account_id(),
                public_key: signer_b.public_key(),
            },
            AccountPublicKey {
                account_id: missing_signer.account_id(),
                public_key: missing_signer.public_key(),
            },
        ],
    )
    .expect("fixed test public-key registry must be internally consistent")
}

fn genesis(
    signer_a: &Ed25519TransactionSigner,
    signer_b: &Ed25519TransactionSigner,
) -> LedgerState {
    LedgerState::genesis(
        NETWORK_ID,
        vec![
            (signer_a.account_id(), 1_000_000),
            (signer_b.account_id(), 800_000),
            (RECIPIENT_C, 100),
            (RECIPIENT_D, 50),
            // Put this recipient at the remaining supply headroom so a one-unit transfer
            // exercises the cap-boundary ledger without using an invalid over-cap Genesis.
            (MAX_RECIPIENT, MAX_TOTAL_SUPPLY_ATOMS as u64 - 1_800_150),
        ],
    )
    .expect("fixture Genesis must be valid")
}

fn status_label(result: &Result<BlockApplySummary, StateError>) -> String {
    match result {
        Ok(_) => "accepted".to_owned(),
        Err(error) => match error {
            StateError::WrongNetwork => "wrong_network".to_owned(),
            StateError::Unauthorized => "unauthorized".to_owned(),
            StateError::DuplicateTransaction => "duplicate_transaction".to_owned(),
            StateError::NonceMismatch { .. } => "nonce_mismatch".to_owned(),
            StateError::TransactionExpired { .. } => "transaction_expired".to_owned(),
            StateError::InsufficientBalance => "insufficient_balance".to_owned(),
            StateError::AmountOverflow => "amount_overflow".to_owned(),
            StateError::BalanceOverflow => "balance_overflow".to_owned(),
            StateError::MissingSender => "missing_sender".to_owned(),
            StateError::StateRootMismatch => "state_root_mismatch".to_owned(),
            StateError::ParentHashMismatch => "parent_hash_mismatch".to_owned(),
            other => format!("unexpected_{other:?}").to_ascii_lowercase(),
        },
    }
}

fn run_case(
    case_id: &str,
    state: &mut LedgerState,
    auth: &Ed25519TransactionAuthenticator,
    transactions: Vec<Transaction>,
    valid_root: bool,
    wrong_parent: bool,
) -> Result<(), String> {
    let before_snapshot = state
        .encode_snapshot()
        .map_err(|error| format!("{case_id}: encode before snapshot: {error:?}"))?;
    let before_root = state.state_root();
    let parent_hash = if wrong_parent {
        [0x99; 32]
    } else {
        state.tip_hash()
    };
    let mut block = Block {
        height: state
            .height()
            .checked_add(1)
            .ok_or_else(|| format!("{case_id}: height overflow"))?,
        timestamp: BLOCK_TIMESTAMP,
        parent_hash,
        state_root: [0; 32],
        transactions,
    };

    if valid_root {
        block.state_root = state
            .preview_state_root_after(&block, auth)
            .map_err(|error| format!("{case_id}: expected-valid preview rejected: {error:?}"))?;
    }

    let tx_hex = block
        .transactions
        .iter()
        .map(|tx| {
            encode_transaction(tx)
                .map(|bytes| hex(&bytes))
                .map_err(|error| format!("{case_id}: encode fixture TXN2: {error:?}"))
        })
        .collect::<Result<Vec<_>, _>>()?
        .join(",");

    let result = state.apply_block(&block, auth);
    let status = status_label(&result);
    let after_snapshot = state
        .encode_snapshot()
        .map_err(|error| format!("{case_id}: encode after snapshot: {error:?}"))?;
    let after_root = state.state_root();

    println!(
        "ROW\t{case_id}\t{status}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
        hex(&before_root),
        hex(&after_root),
        hex(&before_snapshot),
        hex(&after_snapshot),
        tx_hex,
        block.timestamp,
        hex(&block.parent_hash),
        hex(&block.state_root),
    );
    Ok(())
}

/// Emit deterministic candidate-only records for an independent Python/OpenSSL checker.
pub fn export_results() -> Result<(), String> {
    let signer_a = Ed25519TransactionSigner::from_seed(SIGNER_A_SEED);
    let signer_b = Ed25519TransactionSigner::from_seed(SIGNER_B_SEED);
    let missing_signer = Ed25519TransactionSigner::from_seed(MISSING_SIGNER_SEED);
    let auth = authenticator(&signer_a, &signer_b, &missing_signer);
    println!("CP0130Z_TX_ADMISSION_V1");

    let make_state = || genesis(&signer_a, &signer_b);

    run_case(
        "valid_single",
        &mut make_state(),
        &auth,
        vec![signed_tx(
            &signer_a,
            NETWORK_ID,
            RECIPIENT_C,
            1,
            1_000,
            3,
            NORMAL_EXPIRY,
        )],
        true,
        false,
    )?;

    run_case(
        "valid_two_tx_sequential_nonce",
        &mut make_state(),
        &auth,
        vec![
            signed_tx(
                &signer_a,
                NETWORK_ID,
                RECIPIENT_C,
                1,
                1_000,
                3,
                NORMAL_EXPIRY,
            ),
            signed_tx(
                &signer_a,
                NETWORK_ID,
                RECIPIENT_D,
                2,
                2_000,
                4,
                NORMAL_EXPIRY,
            ),
        ],
        true,
        false,
    )?;

    run_case(
        "wrong_network",
        &mut make_state(),
        &auth,
        vec![signed_tx(
            &signer_a,
            OTHER_NETWORK_ID,
            RECIPIENT_C,
            1,
            1_000,
            3,
            NORMAL_EXPIRY,
        )],
        false,
        false,
    )?;

    let mut bad_signature = signed_tx(
        &signer_a,
        NETWORK_ID,
        RECIPIENT_C,
        1,
        1_000,
        3,
        NORMAL_EXPIRY,
    );
    bad_signature.signature[0] ^= 1;
    run_case(
        "bad_signature",
        &mut make_state(),
        &auth,
        vec![bad_signature],
        false,
        false,
    )?;

    let duplicate = signed_tx(
        &signer_a,
        NETWORK_ID,
        RECIPIENT_C,
        1,
        1_000,
        3,
        NORMAL_EXPIRY,
    );
    run_case(
        "duplicate_tx",
        &mut make_state(),
        &auth,
        vec![duplicate.clone(), duplicate],
        false,
        false,
    )?;

    run_case(
        "nonce_mismatch",
        &mut make_state(),
        &auth,
        vec![signed_tx(
            &signer_a,
            NETWORK_ID,
            RECIPIENT_C,
            2,
            1_000,
            3,
            NORMAL_EXPIRY,
        )],
        false,
        false,
    )?;

    run_case(
        "expiry_boundary",
        &mut make_state(),
        &auth,
        vec![signed_tx(
            &signer_a,
            NETWORK_ID,
            RECIPIENT_C,
            1,
            1_000,
            3,
            BLOCK_TIMESTAMP,
        )],
        false,
        false,
    )?;

    run_case(
        "insufficient_balance",
        &mut make_state(),
        &auth,
        vec![signed_tx(
            &signer_a,
            NETWORK_ID,
            RECIPIENT_C,
            1,
            1_000_000,
            1,
            NORMAL_EXPIRY,
        )],
        false,
        false,
    )?;

    run_case(
        "amount_overflow",
        &mut make_state(),
        &auth,
        vec![signed_tx(
            &signer_a,
            NETWORK_ID,
            RECIPIENT_C,
            1,
            u64::MAX,
            1,
            NORMAL_EXPIRY,
        )],
        false,
        false,
    )?;

    run_case(
        "cap_boundary_transfer",
        &mut make_state(),
        &auth,
        vec![signed_tx(
            &signer_a,
            NETWORK_ID,
            MAX_RECIPIENT,
            1,
            1,
            1,
            NORMAL_EXPIRY,
        )],
        true,
        false,
    )?;

    run_case(
        "missing_sender",
        &mut make_state(),
        &auth,
        vec![signed_tx(
            &missing_signer,
            NETWORK_ID,
            RECIPIENT_C,
            1,
            10,
            1,
            NORMAL_EXPIRY,
        )],
        false,
        false,
    )?;

    run_case(
        "state_root_mismatch",
        &mut make_state(),
        &auth,
        vec![signed_tx(
            &signer_a,
            NETWORK_ID,
            RECIPIENT_C,
            1,
            1_000,
            3,
            NORMAL_EXPIRY,
        )],
        false,
        false,
    )?;

    run_case(
        "rollback_late_nonce",
        &mut make_state(),
        &auth,
        vec![
            signed_tx(
                &signer_a,
                NETWORK_ID,
                RECIPIENT_C,
                1,
                1_000,
                3,
                NORMAL_EXPIRY,
            ),
            signed_tx(
                &signer_a,
                NETWORK_ID,
                RECIPIENT_D,
                3,
                2_000,
                4,
                NORMAL_EXPIRY,
            ),
        ],
        false,
        false,
    )?;

    let mut late_bad_signature =
        signed_tx(&signer_b, NETWORK_ID, RECIPIENT_D, 1, 100, 2, NORMAL_EXPIRY);
    late_bad_signature.signature[0] ^= 1;
    run_case(
        "rollback_late_signature",
        &mut make_state(),
        &auth,
        vec![
            signed_tx(
                &signer_a,
                NETWORK_ID,
                RECIPIENT_C,
                1,
                1_000,
                3,
                NORMAL_EXPIRY,
            ),
            late_bad_signature,
        ],
        false,
        false,
    )?;

    run_case(
        "wrong_parent",
        &mut make_state(),
        &auth,
        vec![signed_tx(
            &signer_a,
            NETWORK_ID,
            RECIPIENT_C,
            1,
            1_000,
            3,
            NORMAL_EXPIRY,
        )],
        false,
        true,
    )?;

    Ok(())
}
