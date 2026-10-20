//! CP-0131-AA whole-branch transaction replay fixture. Candidate-only; not consensus activation.
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

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
    // Persistence fault matrix performs repeated restart/replay passes; use a deliberately
    // low-cost Argon2id profile here. This is not a mining-security or mainnet parameter.
    params.pow.memory_kib = 8 * 1024;
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

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    hex(&digest)
}

fn list_archive_files(root: &Path) -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = fs::read_dir(root)
        .expect("read persisted archive directory")
        .map(|entry| entry.expect("read directory entry").path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "ptb2"))
        .collect();
    files.sort();
    files
}

fn persist_bundle(root: &Path, envelopes: &[Vec<u8>]) {
    fs::create_dir_all(root).expect("create persisted archive directory");
    for (index, envelope) in envelopes.iter().enumerate() {
        fs::write(root.join(format!("record_{index:03}.ptb2")), envelope)
            .expect("persist PTB2 record");
    }
    let mut manifest = format!("AIN1-CP0133-AC-MANIFEST-V1\nCOUNT\t{}\n", envelopes.len());
    for path in list_archive_files(root) {
        let name = path.file_name().expect("record name").to_string_lossy();
        let bytes = fs::read(&path).expect("read persisted record for manifest");
        manifest.push_str(&format!("{name}\t{}\n", sha256_hex(&bytes)));
    }
    fs::write(root.join("manifest.tsv"), manifest).expect("write local record manifest");
}

fn validate_local_manifest(root: &Path) -> Result<(), &'static str> {
    let manifest =
        fs::read_to_string(root.join("manifest.tsv")).map_err(|_| "manifest_unreadable")?;
    let mut lines = manifest.lines();
    if lines.next() != Some("AIN1-CP0133-AC-MANIFEST-V1") {
        return Err("manifest_magic_mismatch");
    }
    let count_line = lines.next().ok_or("manifest_count_missing")?;
    let expected_count = count_line
        .strip_prefix("COUNT\t")
        .ok_or("manifest_count_malformed")?
        .parse::<usize>()
        .map_err(|_| "manifest_count_malformed")?;
    let mut expected = BTreeMap::new();
    for line in lines {
        let (name, digest) = line.split_once('\t').ok_or("manifest_record_malformed")?;
        if expected
            .insert(name.to_owned(), digest.to_owned())
            .is_some()
        {
            return Err("manifest_duplicate_name");
        }
    }

    let files = list_archive_files(root);
    if files.len() != expected_count || expected.len() != expected_count {
        return Err("manifest_record_count_mismatch");
    }
    for path in files {
        let name = path.file_name().expect("record filename").to_string_lossy();
        let expected_digest = expected
            .get(name.as_ref())
            .ok_or("manifest_file_set_mismatch")?;
        let bytes = fs::read(path).map_err(|_| "manifest_record_unreadable")?;
        if &sha256_hex(&bytes) != expected_digest {
            return Err("manifest_checksum_mismatch");
        }
    }
    Ok(())
}

fn load_envelopes(root: &Path) -> Vec<Vec<u8>> {
    list_archive_files(root)
        .into_iter()
        .map(|path| fs::read(path).expect("read persisted PTB2 record"))
        .collect()
}

fn path_for_nonce(root: &Path, nonce: u64) -> PathBuf {
    list_archive_files(root)
        .into_iter()
        .find(|path| {
            fs::read(path)
                .ok()
                .and_then(|bytes| decode_candidate_network_block(&bytes).ok())
                .is_some_and(|decoded| decoded.header.nonce == nonce)
        })
        .expect("fixture envelope for requested nonce")
}

fn replay_from_disk(
    root: &Path,
    keys: &FixtureKeys,
    params: &ConsensusParameters,
    clock: &dyn ReferenceTimeProvider,
) -> Result<PrivateTestnetForkChoice, String> {
    PrivateTestnetForkChoice::rebuild_from_envelopes(
        genesis(keys),
        params.clone(),
        load_envelopes(root),
        &keys.auth,
        clock,
    )
    .map_err(|error| format!("{error:?}").replace('\t', "_"))
}

fn emit_fault(
    label: &str,
    manifest_result: Result<(), &'static str>,
    replay_result: Result<PrivateTestnetForkChoice, String>,
    baseline: &PrivateTestnetForkChoice,
    baseline_tip: [u8; 32],
    baseline_snapshot: &[u8],
    baseline_len: usize,
) {
    let manifest = match manifest_result {
        Ok(()) => "PASS".to_owned(),
        Err(reason) => format!("REJECT:{reason}"),
    };
    let replay = match replay_result {
        Ok(rebuilt) => format!(
            "ACCEPT:len={}:tip={}",
            rebuilt.archive_len(),
            hex(&rebuilt.canonical_chain().chain_tip().tip_hash)
        ),
        Err(reason) => format!("REJECT:{reason}"),
    };
    // Compare the live archive against the tip/snapshot captured before any disk fault is made.
    let active_unchanged = baseline.canonical_chain().chain_tip().tip_hash == baseline_tip
        && baseline.canonical_chain().state().encode_snapshot().ok()
            == Some(baseline_snapshot.to_vec())
        && baseline.archive_len() == baseline_len;
    println!(
        "FAULT\t{label}\tmanifest={manifest}\treplay={replay}\tactive_unchanged={active_unchanged}"
    );
}

fn run_persistence_fault_matrix(
    archive: &PrivateTestnetForkChoice,
    keys: &FixtureKeys,
    params: &ConsensusParameters,
    clock: &dyn ReferenceTimeProvider,
    canonical_leaf_nonce: u64,
) {
    let root = std::env::temp_dir().join(format!(
        "ain1_cp0133_ac_{}_{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("monotonic enough fixture nonce")
            .as_nanos()
    ));
    fs::create_dir_all(&root).expect("create CP-0133 temporary archive root");
    let envelopes = archive.archive_envelopes();
    let baseline_tip = archive.canonical_chain().chain_tip().tip_hash;
    let baseline_snapshot = archive
        .canonical_chain()
        .state()
        .encode_snapshot()
        .expect("baseline canonical snapshot");
    let baseline_len = archive.archive_len();

    let valid = root.join("valid");
    persist_bundle(&valid, &envelopes);
    let valid_manifest = validate_local_manifest(&valid);
    let mut reordered = load_envelopes(&valid);
    reordered.reverse();
    let reopened = PrivateTestnetForkChoice::rebuild_from_envelopes(
        genesis(keys),
        params.clone(),
        reordered,
        &keys.auth,
        clock,
    )
    .expect("valid reverse-order persisted archive replay");
    let valid_equal = reopened.canonical_chain().chain_tip()
        == archive.canonical_chain().chain_tip()
        && reopened.canonical_chain().state().encode_snapshot().ok()
            == Some(baseline_snapshot.clone())
        && reopened.archive_len() == baseline_len;
    println!(
        "PERSIST\tvalid_reordered_reopen\tmanifest={}\treplay=PASS\tarchive_len={}\tstate_equal={}\ttip={}",
        if valid_manifest.is_ok() { "PASS" } else { "REJECT" },
        reopened.archive_len(),
        valid_equal,
        hex(&reopened.canonical_chain().chain_tip().tip_hash)
    );

    // A record shortened on disk must be caught by the manifest and rejected by the wire parser.
    let truncated = root.join("truncated");
    persist_bundle(&truncated, &envelopes);
    let truncated_path = list_archive_files(&truncated)
        .into_iter()
        .next()
        .expect("record to truncate");
    let mut truncated_bytes = fs::read(&truncated_path).expect("read truncation fixture");
    truncated_bytes.pop();
    fs::write(&truncated_path, truncated_bytes).expect("persist truncated record");
    emit_fault(
        "truncated_record",
        validate_local_manifest(&truncated),
        replay_from_disk(&truncated, keys, params, clock),
        archive,
        baseline_tip,
        &baseline_snapshot,
        baseline_len,
    );

    // Same-length signature-byte corruption must be detected before replay is allowed.
    let corrupted = root.join("corrupted");
    persist_bundle(&corrupted, &envelopes);
    let corrupt_path = list_archive_files(&corrupted)
        .into_iter()
        .next()
        .expect("record to corrupt");
    let mut corrupt_bytes = fs::read(&corrupt_path).expect("read corruption fixture");
    let last = corrupt_bytes.len() - 1;
    corrupt_bytes[last] ^= 1;
    fs::write(&corrupt_path, corrupt_bytes).expect("persist corrupted record");
    emit_fault(
        "corrupted_record",
        validate_local_manifest(&corrupted),
        replay_from_disk(&corrupted, keys, params, clock),
        archive,
        baseline_tip,
        &baseline_snapshot,
        baseline_len,
    );

    // A duplicate persisted record is structurally replayable as a no-op, so count validation
    // must reject it before the reconstructed archive is trusted.
    let duplicate = root.join("duplicate");
    persist_bundle(&duplicate, &envelopes);
    let source = list_archive_files(&duplicate)
        .into_iter()
        .next()
        .expect("source record");
    fs::copy(source, duplicate.join("record_duplicate.ptb2")).expect("write duplicate record");
    emit_fault(
        "duplicate_record",
        validate_local_manifest(&duplicate),
        replay_from_disk(&duplicate, keys, params, clock),
        archive,
        baseline_tip,
        &baseline_snapshot,
        baseline_len,
    );

    // Drop A1 while retaining a child that depends on it: reconstruction must reject the unknown parent.
    let missing_parent = root.join("missing_parent");
    persist_bundle(&missing_parent, &envelopes);
    fs::remove_file(path_for_nonce(&missing_parent, 0x101)).expect("remove A1 fixture record");
    emit_fault(
        "missing_parent_record",
        validate_local_manifest(&missing_parent),
        replay_from_disk(&missing_parent, keys, params, clock),
        archive,
        baseline_tip,
        &baseline_snapshot,
        baseline_len,
    );

    // The raw replay API cannot infer that A2 went missing: the remaining three records still
    // form a valid archive. The manifest is therefore a required persistence integrity guard.
    let missing_leaf = root.join("missing_leaf");
    persist_bundle(&missing_leaf, &envelopes);
    fs::remove_file(path_for_nonce(&missing_leaf, canonical_leaf_nonce))
        .expect("remove current canonical leaf fixture record");
    let missing_leaf_manifest = validate_local_manifest(&missing_leaf);
    let missing_leaf_replay = replay_from_disk(&missing_leaf, keys, params, clock);
    match missing_leaf_replay {
        Ok(rebuilt) => {
            let changed = rebuilt.canonical_chain().chain_tip().tip_hash != baseline_tip;
            println!(
                "FAULT\tmissing_canonical_leaf\tmanifest={}\treplay=ACCEPT:len={}:tip={}\tcanonical_changed={}\tactive_unchanged={}",
                match missing_leaf_manifest { Ok(()) => "PASS".to_owned(), Err(reason) => format!("REJECT:{reason}") },
                rebuilt.archive_len(),
                hex(&rebuilt.canonical_chain().chain_tip().tip_hash),
                changed,
                archive.canonical_chain().chain_tip().tip_hash == baseline_tip
                    && archive.canonical_chain().state().encode_snapshot().ok() == Some(baseline_snapshot.clone())
                    && archive.archive_len() == baseline_len
            );
        }
        Err(reason) => println!(
            "FAULT\tmissing_canonical_leaf\tmanifest={}\treplay=REJECT:{reason}\tcanonical_changed=false\tactive_unchanged=true",
            match missing_leaf_manifest { Ok(()) => "PASS".to_owned(), Err(reason) => format!("REJECT:{reason}") }
        ),
    }

    let baseline_still_exact = archive.canonical_chain().chain_tip().tip_hash == baseline_tip
        && archive.canonical_chain().state().encode_snapshot().ok() == Some(baseline_snapshot)
        && archive.archive_len() == baseline_len;
    println!(
        "PERSIST_BASELINE_UNCHANGED\t{}\tarchive_len={}\ttip={}",
        baseline_still_exact,
        baseline_len,
        hex(&baseline_tip)
    );
    println!("PERSIST_END\tcases=6\tactive_archive_untouched=true\tmanifest_is_local_integrity_metadata_not_authenticated_consensus=true");
    let _ = fs::remove_dir_all(root);
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

    let canonical_leaf_nonce = if archive.canonical_chain().chain_tip().tip_hash == da2 {
        0x102
    } else if archive.canonical_chain().chain_tip().tip_hash == db2 {
        0x202
    } else {
        panic!("canonical tip is not one of the fixture branch leaves");
    };
    run_persistence_fault_matrix(&archive, &keys, &params, &clock, canonical_leaf_nonce);
}
