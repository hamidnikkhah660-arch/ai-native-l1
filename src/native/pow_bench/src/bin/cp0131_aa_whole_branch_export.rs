//! CP-0131-AA whole-branch transaction replay fixture. Candidate-only; not consensus activation.
use ai_native_l1_pow_bench::{
    chain_admission::{
        ReferenceTimeError, ReferenceTimeProvenance, ReferenceTimeProvider, ReferenceTimeSample,
    },
    consensus::{pow_digest, ConsensusParameters, PowHeader, Uint256},
    private_testnet_driver::PrivateTestnetChain,
    private_testnet_fork_choice::PrivateTestnetForkChoice,
    private_testnet_wire::{decode_candidate_network_block, encode_candidate_network_block},
    state_machine::{AccountId, Block, LedgerState, Transaction, TransactionAuthenticator},
    transaction_auth::{
        AccountPublicKey, Ed25519TransactionAuthenticator, Ed25519TransactionSigner,
        TransactionAuthenticatorKind,
    },
};

const NETWORK_ID: [u8; 32] = [0xD3; 32];
const RECIPIENT_C: AccountId = [0x33; 32];
const RECIPIENT_D: AccountId = [0x34; 32];
const MAX_ACCOUNT: AccountId = [0x44; 32];
const SEED_A: [u8; 32] = [0x10; 32];
const SEED_B: [u8; 32] = [0x20; 32];
const SEED_MISSING: [u8; 32] = [0x30; 32];

struct FixedClock;
impl ReferenceTimeProvider for FixedClock {
    fn sample(&self) -> Result<ReferenceTimeSample, ReferenceTimeError> {
        Ok(ReferenceTimeSample {
            unix_seconds: 1_000_000,
            provenance: ReferenceTimeProvenance::ConfiguredProvider,
            source_id: "cp0131-fixed-private-fixture-clock",
        })
    }
}

struct FixtureKeys {
    a: Ed25519TransactionSigner,
    b: Ed25519TransactionSigner,
    auth: Ed25519TransactionAuthenticator,
}

fn keys() -> FixtureKeys {
    let a = Ed25519TransactionSigner::from_seed(SEED_A);
    let b = Ed25519TransactionSigner::from_seed(SEED_B);
    let missing = Ed25519TransactionSigner::from_seed(SEED_MISSING);
    let auth = Ed25519TransactionAuthenticator::select(
        TransactionAuthenticatorKind::Ed25519V1,
        [
            AccountPublicKey {
                account_id: a.account_id(),
                public_key: a.public_key(),
            },
            AccountPublicKey {
                account_id: b.account_id(),
                public_key: b.public_key(),
            },
            AccountPublicKey {
                account_id: missing.account_id(),
                public_key: missing.public_key(),
            },
        ],
    )
    .expect("fixed test key registry");
    FixtureKeys { a, b, auth }
}

fn genesis(keys: &FixtureKeys) -> LedgerState {
    LedgerState::genesis(
        NETWORK_ID,
        vec![
            (keys.a.account_id(), 1_000_000),
            (keys.b.account_id(), 800_000),
            (RECIPIENT_C, 100),
            (RECIPIENT_D, 50),
            // Keep the legacy fixture Genesis valid under the enforced 10B-coin cap.
            (MAX_ACCOUNT, 1_000),
        ],
    )
    .expect("fixed valid Genesis")
}

fn params() -> ConsensusParameters {
    let mut params = ConsensusParameters::candidate_testnet().expect("candidate profile");
    params.initial_target = Uint256::MAX;
    params.pow_limit = Uint256::MAX;
    params
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        result.push(DIGITS[(b >> 4) as usize] as char);
        result.push(DIGITS[(b & 15) as usize] as char);
    }
    result
}

fn tx(
    signer: &Ed25519TransactionSigner,
    recipient: AccountId,
    nonce: u64,
    amount: u64,
    fee: u64,
) -> Transaction {
    let mut tx = Transaction {
        network_id: NETWORK_ID,
        sender: signer.account_id(),
        recipient,
        nonce,
        amount,
        fee,
        expires_at: 10_000,
        signature: Vec::new(),
    };
    signer
        .sign_transaction(&mut tx)
        .expect("fixture transaction signature");
    tx
}

fn build_candidate<A: TransactionAuthenticator>(
    parent: &PrivateTestnetChain,
    params: &ConsensusParameters,
    auth: &A,
    timestamp: u64,
    pow_nonce: u64,
    transaction: Transaction,
) -> (Vec<u8>, [u8; 32]) {
    let mut block = Block {
        height: parent.state().height() + 1,
        timestamp,
        parent_hash: parent.state().tip_hash(),
        state_root: [0; 32],
        transactions: vec![transaction],
    };
    block.state_root = parent
        .state()
        .preview_state_root_after(&block, auth)
        .expect("valid fixture transition");
    let header = PowHeader {
        protocol_version: params.protocol_version,
        network_id: parent.state().network_id(),
        height: block.height,
        timestamp,
        parent_hash: block.parent_hash,
        previous_consensus_hash: parent.chain_tip().tip_hash,
        state_root: block.state_root,
        target: parent
            .expected_target(None)
            .expect("expected target")
            .into(),
        nonce: pow_nonce,
    };
    let digest = pow_digest(&header, params.pow).expect("PoW digest");
    let envelope =
        encode_candidate_network_block(&header, &block).expect("canonical PTB2 envelope");
    (envelope, digest)
}

fn append_to_branch<A: TransactionAuthenticator>(
    branch: &mut PrivateTestnetChain,
    envelope: &[u8],
    auth: &A,
    clock: &dyn ReferenceTimeProvider,
) {
    let decoded = decode_candidate_network_block(envelope).expect("decode own envelope");
    branch
        .append_live(&decoded.block, &decoded.header, None, auth, clock)
        .expect("append valid branch block");
}

fn emit_row(label: &str, envelope: &[u8], digest: [u8; 32], archive: &PrivateTestnetForkChoice) {
    let canonical = archive.canonical_chain();
    let tip = canonical.chain_tip();
    let snapshot = canonical
        .state()
        .encode_snapshot()
        .expect("canonical state snapshot");
    println!(
        "ROW\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
        label,
        hex(envelope),
        hex(&digest),
        hex(&tip.tip_hash),
        tip.height,
        hex(&canonical.state().state_root()),
        hex(&snapshot),
        hex(&tip.cumulative_work.to_be_bytes()),
        archive.archive_len(),
        archive.reorg_count(),
    );
}

fn emit_negative(
    label: &str,
    result_label: &str,
    accepted: bool,
    envelope: &[u8],
    digest: [u8; 32],
    archive_before: &PrivateTestnetForkChoice,
    archive_after: &PrivateTestnetForkChoice,
) {
    let before = archive_before.canonical_chain();
    let after = archive_after.canonical_chain();
    println!(
        "NEG\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
        label,
        result_label,
        if accepted { 1 } else { 0 },
        hex(envelope),
        hex(&digest),
        hex(&before.chain_tip().tip_hash),
        hex(&after.chain_tip().tip_hash),
        hex(&before.state().state_root()),
        hex(&after.state().state_root()),
        hex(&before.state().encode_snapshot().expect("before snapshot")),
        hex(&after.state().encode_snapshot().expect("after snapshot")),
        archive_before.archive_len(),
        archive_after.archive_len(),
    );
}

fn main() {
    let keys = keys();
    let params = params();
    let clock = FixedClock;
    let genesis_state = genesis(&keys);
    let genesis_chain =
        PrivateTestnetChain::new(genesis_state.clone(), params.clone()).expect("genesis chain");
    let mut archive =
        PrivateTestnetForkChoice::new(genesis_state.clone(), params.clone()).expect("fork archive");

    let (a1, da1) = build_candidate(
        &genesis_chain,
        &params,
        &keys.auth,
        100,
        0x101,
        tx(&keys.a, RECIPIENT_C, 1, 1_000, 3),
    );
    let (b1, db1) = build_candidate(
        &genesis_chain,
        &params,
        &keys.auth,
        100,
        0x201,
        tx(&keys.b, RECIPIENT_D, 1, 1_500, 2),
    );
    let mut branch_a = genesis_chain.clone();
    let mut branch_b = genesis_chain.clone();

    archive
        .insert_encoded(&a1, &keys.auth, &clock)
        .expect("insert A1");
    emit_row("A1", &a1, da1, &archive);
    append_to_branch(&mut branch_a, &a1, &keys.auth, &clock);

    archive
        .insert_encoded(&b1, &keys.auth, &clock)
        .expect("insert B1");
    emit_row("B1", &b1, db1, &archive);
    append_to_branch(&mut branch_b, &b1, &keys.auth, &clock);

    let (a2, da2) = build_candidate(
        &branch_a,
        &params,
        &keys.auth,
        101,
        0x102,
        tx(&keys.a, RECIPIENT_D, 2, 2_000, 4),
    );
    let (b2, db2) = build_candidate(
        &branch_b,
        &params,
        &keys.auth,
        101,
        0x202,
        tx(&keys.b, RECIPIENT_C, 2, 2_500, 5),
    );

    archive
        .insert_encoded(&a2, &keys.auth, &clock)
        .expect("insert A2");
    emit_row("A2", &a2, da2, &archive);
    append_to_branch(&mut branch_a, &a2, &keys.auth, &clock);

    archive
        .insert_encoded(&b2, &keys.auth, &clock)
        .expect("insert B2");
    emit_row("B2", &b2, db2, &archive);
    append_to_branch(&mut branch_b, &b2, &keys.auth, &clock);

    let replay = PrivateTestnetForkChoice::rebuild_from_envelopes(
        genesis_state,
        params.clone(),
        archive.archive_envelopes(),
        &keys.auth,
        &clock,
    )
    .expect("replay every accepted branch envelope");
    let replay_chain = replay.canonical_chain();
    let live_chain = archive.canonical_chain();
    println!(
        "REPLAY\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
        hex(&replay_chain.chain_tip().tip_hash),
        replay_chain.state().height(),
        hex(&replay_chain.state().state_root()),
        hex(&replay_chain
            .state()
            .encode_snapshot()
            .expect("replay snapshot")),
        hex(&replay_chain.chain_tip().cumulative_work.to_be_bytes()),
        replay.archive_len(),
        replay.reorg_count(),
    );
    println!(
        "LIVE_REPLAY_EQUAL\t{}",
        if replay_chain.chain_tip() == live_chain.chain_tip()
            && replay_chain.state().encode_snapshot().ok()
                == live_chain.state().encode_snapshot().ok()
        {
            1
        } else {
            0
        }
    );

    // A linked body with a modified root must be rejected without altering archive/state.
    let mut decoded_a2 = decode_candidate_network_block(&a2).expect("decode A2");
    decoded_a2.block.state_root[0] ^= 1;
    decoded_a2.header.state_root[0] ^= 1;
    let bad_root = encode_candidate_network_block(&decoded_a2.header, &decoded_a2.block)
        .expect("encode mutated root candidate");
    let bad_root_digest = pow_digest(&decoded_a2.header, params.pow).expect("mutated root digest");
    let before_bad_root = archive.clone();
    let bad_root_result = archive.insert_encoded(&bad_root, &keys.auth, &clock);
    let bad_root_accepted = bad_root_result.is_ok();
    let bad_root_label = match bad_root_result {
        Ok(_) => "unexpected_accept".to_owned(),
        Err(error) => format!("{error:?}").replace('\t', "_"),
    };
    let bad_root_after = archive.clone();
    emit_negative(
        "mutated_state_root",
        &bad_root_label,
        bad_root_accepted,
        &bad_root,
        bad_root_digest,
        &before_bad_root,
        &bad_root_after,
    );

    // A candidate referencing a non-existent consensus parent must also fail atomically.
    let mut decoded_a2 = decode_candidate_network_block(&a2).expect("decode A2");
    decoded_a2.header.previous_consensus_hash = [0xFE; 32];
    let unknown_parent = encode_candidate_network_block(&decoded_a2.header, &decoded_a2.block)
        .expect("encode unknown-parent candidate");
    let unknown_parent_digest =
        pow_digest(&decoded_a2.header, params.pow).expect("unknown-parent digest");
    let before_unknown = archive.clone();
    let unknown_result = archive.insert_encoded(&unknown_parent, &keys.auth, &clock);
    let unknown_accepted = unknown_result.is_ok();
    let unknown_label = match unknown_result {
        Ok(_) => "unexpected_accept".to_owned(),
        Err(error) => format!("{error:?}").replace('\t', "_"),
    };
    let unknown_after = archive.clone();
    emit_negative(
        "unknown_parent",
        &unknown_label,
        unknown_accepted,
        &unknown_parent,
        unknown_parent_digest,
        &before_unknown,
        &unknown_after,
    );
}
