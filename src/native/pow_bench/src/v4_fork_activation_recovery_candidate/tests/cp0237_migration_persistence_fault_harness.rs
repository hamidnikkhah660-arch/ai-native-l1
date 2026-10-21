//! CP-0237: test-only filesystem fault harness for STV4 prepare/intent/CAS/install/clear.
//!
//! It deliberately stores the "external" anchor in a distinct test directory on the
//! same host. The harness checks restart behavior and fail-closed decisions, not provider
//! independence, real power-loss durability, directory-fsync guarantees, or consensus.

use super::*;
use std::fs::{self, OpenOptions};
use std::io::{Error, ErrorKind, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_LAB_ID: AtomicU64 = AtomicU64::new(1);
const LOCAL_MAGIC: &[u8; 4] = b"LST1";
const FLOOR_MAGIC: &[u8; 4] = b"AFR1";
const PREPARED_MAGIC: &[u8; 4] = b"PBA1";
const INTENT_MAGIC: &[u8; 4] = b"MCI1";

struct Lab {
    root: PathBuf,
    local_dir: PathBuf,
    anchor_dir: PathBuf,
}

impl Lab {
    fn new() -> Self {
        let id = NEXT_LAB_ID.fetch_add(1, Ordering::Relaxed);
        let root =
            std::env::temp_dir().join(format!("ain1-cp0237-persist-{}-{id}", std::process::id()));
        let local_dir = root.join("local-volume");
        let anchor_dir = root.join("separate-anchor-test-double");
        fs::create_dir_all(&local_dir).unwrap();
        fs::create_dir_all(&anchor_dir).unwrap();
        Self {
            root,
            local_dir,
            anchor_dir,
        }
    }

    fn local_state(&self) -> PathBuf {
        self.local_dir.join("state.bin")
    }
    fn prepared(&self) -> PathBuf {
        self.local_dir.join("prepared.bin")
    }
    fn intent(&self) -> PathBuf {
        self.local_dir.join("intent.bin")
    }
    fn floor(&self) -> PathBuf {
        self.anchor_dir.join("floor.bin")
    }

    fn cleanup_temporary_files(&self) {
        for target in [
            self.local_state(),
            self.prepared(),
            self.intent(),
            self.floor(),
        ] {
            let temporary = target.with_extension("tmp");
            let _ = fs::remove_file(temporary);
        }
    }
}

impl Drop for Lab {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum WriteFault {
    None,
    BeforeRename,
    AfterRename,
}

fn injected_io_error(stage: &str) -> Error {
    Error::new(
        ErrorKind::Other,
        format!("CP-0237 injected fault at {stage}"),
    )
}

/// Writes and syncs a same-directory temp file, then renames it. BeforeRename models
/// a crash with a complete temp but old destination; AfterRename models a lost/ambiguous
/// response after the destination has changed. This does not simulate physical power loss.
fn write_atomic(path: &Path, bytes: &[u8], fault: WriteFault) -> std::io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| Error::new(ErrorKind::InvalidInput, "missing parent"))?;
    fs::create_dir_all(parent)?;
    let temp = path.with_extension("tmp");
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(&temp)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);

    if fault == WriteFault::BeforeRename {
        return Err(injected_io_error("before rename"));
    }
    fs::rename(&temp, path)?;
    if fault == WriteFault::AfterRename {
        return Err(injected_io_error("after rename"));
    }
    Ok(())
}

fn seal(body: &[u8]) -> Vec<u8> {
    let digest: [u8; 32] = Sha256::digest(body).into();
    let mut out = body.to_vec();
    out.extend_from_slice(&digest);
    out
}

fn unseal(bytes: &[u8]) -> Option<Vec<u8>> {
    if bytes.len() < 32 {
        return None;
    }
    let split = bytes.len() - 32;
    let (body, checksum) = bytes.split_at(split);
    let expected: [u8; 32] = Sha256::digest(body).into();
    if checksum != expected {
        return None;
    }
    Some(body.to_vec())
}

fn encode_floor(floor: &TrustedFat1Floor) -> Vec<u8> {
    let mut body = FLOOR_MAGIC.to_vec();
    body.extend_from_slice(&floor.network_id);
    body.extend_from_slice(&floor.trust_epoch.to_be_bytes());
    body.extend_from_slice(&floor.record_id);
    body.extend_from_slice(&floor.envelope_id);
    seal(&body)
}

fn decode_floor(bytes: &[u8]) -> Option<TrustedFat1Floor> {
    let body = unseal(bytes)?;
    if body.len() != 108 || &body[..4] != FLOOR_MAGIC {
        return None;
    }
    Some(TrustedFat1Floor {
        network_id: body[4..36].try_into().ok()?,
        trust_epoch: u64::from_be_bytes(body[36..44].try_into().ok()?),
        record_id: body[44..76].try_into().ok()?,
        envelope_id: body[76..108].try_into().ok()?,
    })
}

fn encode_prepared(prepared: &MigrationBoundaryArtifact) -> Vec<u8> {
    let mut body = PREPARED_MAGIC.to_vec();
    body.extend_from_slice(&prepared.network_id);
    body.extend_from_slice(&prepared.manifest_id);
    body.extend_from_slice(&prepared.migration_plan_id);
    body.extend_from_slice(&prepared.trust_record_id);
    body.extend_from_slice(&prepared.activation_height.to_be_bytes());
    body.extend_from_slice(&prepared.parent_block_id);
    body.extend_from_slice(&prepared.pre_stv3_root);
    body.extend_from_slice(&prepared.post_stv4_root);
    seal(&body)
}

fn encode_intent(intent: &MigrationCommitIntent) -> Vec<u8> {
    let mut body = INTENT_MAGIC.to_vec();
    body.extend_from_slice(&intent.from_height.to_be_bytes());
    body.extend_from_slice(&intent.from_root);
    body.extend_from_slice(&intent.to_height.to_be_bytes());
    body.extend_from_slice(&intent.to_root);
    body.extend_from_slice(&intent.target_trust_epoch.to_be_bytes());
    body.extend_from_slice(&intent.target_trust_record_id);
    seal(&body)
}

fn encode_local(local: &LocalActivationState) -> Vec<u8> {
    let mut body = LOCAL_MAGIC.to_vec();
    match local {
        LocalActivationState::LegacyParent {
            height,
            block_id,
            state_root,
        } => {
            body.push(0);
            body.extend_from_slice(&height.to_be_bytes());
            body.extend_from_slice(block_id);
            body.extend_from_slice(state_root);
        }
        LocalActivationState::Boundary {
            network_id,
            manifest_id,
            trust_record_id,
            height,
            activation_block_id,
            state_root,
        } => {
            body.push(1);
            body.extend_from_slice(network_id);
            body.extend_from_slice(manifest_id);
            body.extend_from_slice(trust_record_id);
            body.extend_from_slice(&height.to_be_bytes());
            body.extend_from_slice(activation_block_id);
            body.extend_from_slice(state_root);
        }
        LocalActivationState::Descendant {
            network_id,
            manifest_id,
            trust_record_id,
            activation_height,
            activation_ancestor_id,
            activation_state_root,
            tip_height,
            tip_block_id,
            tip_state_root,
        } => {
            body.push(2);
            body.extend_from_slice(network_id);
            body.extend_from_slice(manifest_id);
            body.extend_from_slice(trust_record_id);
            body.extend_from_slice(&activation_height.to_be_bytes());
            body.extend_from_slice(activation_ancestor_id);
            body.extend_from_slice(activation_state_root);
            body.extend_from_slice(&tip_height.to_be_bytes());
            body.extend_from_slice(tip_block_id);
            body.extend_from_slice(tip_state_root);
        }
        LocalActivationState::Conflict { height, state_root } => {
            body.push(3);
            body.extend_from_slice(&height.to_be_bytes());
            body.extend_from_slice(state_root);
        }
    }
    seal(&body)
}

fn put_file(path: &Path, bytes: &[u8]) {
    write_atomic(path, bytes, WriteFault::None).unwrap();
}

fn remove_if_present(path: &Path) {
    match fs::remove_file(path) {
        Ok(()) => {}
        Err(e) if e.kind() == ErrorKind::NotFound => {}
        Err(e) => panic!("remove {}: {e}", path.display()),
    }
}

fn corrupt_marker(local: &Path) {
    let mut bytes = fs::read(local).unwrap();
    let offset = bytes.len() / 2;
    bytes[offset] ^= 0x40;
    fs::write(local, bytes).unwrap();
}

fn read_optional(path: &Path) -> Option<Vec<u8>> {
    match fs::read(path) {
        Ok(bytes) => Some(bytes),
        Err(e) if e.kind() == ErrorKind::NotFound => None,
        Err(e) => panic!("read {}: {e}", path.display()),
    }
}

fn initialize(lab: &Lab, trust: &ActivationTrust) {
    put_file(&lab.local_state(), &encode_local(&legacy(trust)));
    put_file(&lab.floor(), &encode_floor(&old_floor(trust)));
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StopPoint {
    BeforePrepareRename,
    AfterPrepare,
    BeforeIntentRename,
    AfterIntent,
    BeforeAnchorRename,
    AfterAnchorCommit,
    BeforeInstallRename,
    AfterInstall,
    BeforeIntentClear,
    AfterIntentClear,
    AfterClear,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum VisibleState {
    Legacy,
    Boundary,
    Quarantine,
}

fn execute_until(lab: &Lab, trust: &ActivationTrust, stop: StopPoint) {
    initialize(lab, trust);
    let prepared_record = encode_prepared(&prepared(trust));
    let intent_record = encode_intent(&intent(trust));
    let floor_record = encode_floor(&advanced_floor(trust));
    let boundary_record = encode_local(&boundary(trust));

    if stop == StopPoint::BeforePrepareRename {
        assert!(write_atomic(&lab.prepared(), &prepared_record, WriteFault::BeforeRename).is_err());
        return;
    }
    let fault = if stop == StopPoint::AfterPrepare {
        WriteFault::AfterRename
    } else {
        WriteFault::None
    };
    let result = write_atomic(&lab.prepared(), &prepared_record, fault);
    if stop == StopPoint::AfterPrepare {
        assert!(result.is_err());
        return;
    }
    result.unwrap();

    if stop == StopPoint::BeforeIntentRename {
        assert!(write_atomic(&lab.intent(), &intent_record, WriteFault::BeforeRename).is_err());
        return;
    }
    let fault = if stop == StopPoint::AfterIntent {
        WriteFault::AfterRename
    } else {
        WriteFault::None
    };
    let result = write_atomic(&lab.intent(), &intent_record, fault);
    if stop == StopPoint::AfterIntent {
        assert!(result.is_err());
        return;
    }
    result.unwrap();

    if stop == StopPoint::BeforeAnchorRename {
        assert!(write_atomic(&lab.floor(), &floor_record, WriteFault::BeforeRename).is_err());
        return;
    }
    let fault = if stop == StopPoint::AfterAnchorCommit {
        WriteFault::AfterRename
    } else {
        WriteFault::None
    };
    let result = write_atomic(&lab.floor(), &floor_record, fault);
    if stop == StopPoint::AfterAnchorCommit {
        assert!(result.is_err());
        return;
    }
    result.unwrap();

    if stop == StopPoint::BeforeInstallRename {
        assert!(write_atomic(
            &lab.local_state(),
            &boundary_record,
            WriteFault::BeforeRename
        )
        .is_err());
        return;
    }
    let fault = if stop == StopPoint::AfterInstall {
        WriteFault::AfterRename
    } else {
        WriteFault::None
    };
    let result = write_atomic(&lab.local_state(), &boundary_record, fault);
    if stop == StopPoint::AfterInstall {
        assert!(result.is_err());
        return;
    }
    result.unwrap();

    if stop == StopPoint::BeforeIntentClear {
        return;
    }
    remove_if_present(&lab.intent());
    if stop == StopPoint::AfterIntentClear {
        return;
    }
    remove_if_present(&lab.prepared());
    assert_eq!(stop, StopPoint::AfterClear);
}

fn load_prepared(lab: &Lab, trust: &ActivationTrust) -> Option<MigrationBoundaryArtifact> {
    let bytes = read_optional(&lab.prepared())?;
    let expected = prepared(trust);
    if unseal(&bytes).is_some_and(|body| body == encode_prepared_body(&expected)) {
        Some(expected)
    } else {
        let mut mismatch = expected;
        mismatch.post_stv4_root[0] ^= 1;
        Some(mismatch)
    }
}

fn encode_prepared_body(prepared: &MigrationBoundaryArtifact) -> Vec<u8> {
    let mut body = PREPARED_MAGIC.to_vec();
    body.extend_from_slice(&prepared.network_id);
    body.extend_from_slice(&prepared.manifest_id);
    body.extend_from_slice(&prepared.migration_plan_id);
    body.extend_from_slice(&prepared.trust_record_id);
    body.extend_from_slice(&prepared.activation_height.to_be_bytes());
    body.extend_from_slice(&prepared.parent_block_id);
    body.extend_from_slice(&prepared.pre_stv3_root);
    body.extend_from_slice(&prepared.post_stv4_root);
    body
}

fn load_intent(lab: &Lab, trust: &ActivationTrust) -> Option<MigrationCommitIntent> {
    let bytes = read_optional(&lab.intent())?;
    let expected = intent(trust);
    if unseal(&bytes).is_some_and(|body| body == encode_intent_body(&expected)) {
        Some(expected)
    } else {
        let mut mismatch = expected;
        mismatch.to_root[0] ^= 1;
        Some(mismatch)
    }
}

fn encode_intent_body(intent: &MigrationCommitIntent) -> Vec<u8> {
    let mut body = INTENT_MAGIC.to_vec();
    body.extend_from_slice(&intent.from_height.to_be_bytes());
    body.extend_from_slice(&intent.from_root);
    body.extend_from_slice(&intent.to_height.to_be_bytes());
    body.extend_from_slice(&intent.to_root);
    body.extend_from_slice(&intent.target_trust_epoch.to_be_bytes());
    body.extend_from_slice(&intent.target_trust_record_id);
    body
}

fn load_local(lab: &Lab, trust: &ActivationTrust) -> LocalActivationState {
    match read_optional(&lab.local_state()) {
        Some(bytes) if bytes == encode_local(&legacy(trust)) => legacy(trust),
        Some(bytes) if bytes == encode_local(&boundary(trust)) => boundary(trust),
        _ => LocalActivationState::Conflict {
            height: trust.record.activation_height,
            state_root: [0x99; 32],
        },
    }
}

fn clear_migration_artifacts(lab: &Lab) {
    remove_if_present(&lab.intent());
    remove_if_present(&lab.prepared());
}

/// Reopens the durable test fixture, invokes the production-candidate recovery classifier,
/// then performs only the local repairs prescribed by that classifier.
fn recover_after_restart(lab: &Lab, trust: &ActivationTrust) -> (VisibleState, RecoveryDecision) {
    lab.cleanup_temporary_files();
    let floor = read_optional(&lab.floor()).and_then(|bytes| decode_floor(&bytes));
    let local = load_local(lab, trust);
    let prepared_value = load_prepared(lab, trust);
    let intent_value = load_intent(lab, trust);
    let decision = recover_activation(
        trust,
        floor.as_ref(),
        &local,
        prepared_value.as_ref(),
        intent_value.as_ref(),
    );

    match decision {
        RecoveryDecision::ContinueLegacyBeforeActivation => (VisibleState::Legacy, decision),
        RecoveryDecision::DiscardUncommittedPrepareAndKeepLegacy
        | RecoveryDecision::ClearUnanchoredIntentAndKeepLegacy => {
            clear_migration_artifacts(lab);
            (VisibleState::Legacy, decision)
        }
        RecoveryDecision::RollForwardPreparedBoundaryAfterAnchorAdvance => {
            put_file(&lab.local_state(), &encode_local(&boundary(trust)));
            clear_migration_artifacts(lab);
            (VisibleState::Boundary, decision)
        }
        RecoveryDecision::AcceptCommittedBoundary
        | RecoveryDecision::AcceptCommittedBoundaryAndClearIntent => {
            clear_migration_artifacts(lab);
            (VisibleState::Boundary, decision)
        }
        _ => (VisibleState::Quarantine, decision),
    }
}

fn artifacts_absent(lab: &Lab) -> bool {
    !lab.prepared().exists()
        && !lab.intent().exists()
        && !lab.prepared().with_extension("tmp").exists()
        && !lab.intent().with_extension("tmp").exists()
        && !lab.local_state().with_extension("tmp").exists()
        && !lab.floor().with_extension("tmp").exists()
}

#[test]
fn cp0237_real_file_crash_matrix_recovers_old_or_anchored_boundary() {
    let stops = [
        (
            StopPoint::BeforePrepareRename,
            VisibleState::Legacy,
            RecoveryDecision::ContinueLegacyBeforeActivation,
        ),
        (
            StopPoint::AfterPrepare,
            VisibleState::Legacy,
            RecoveryDecision::DiscardUncommittedPrepareAndKeepLegacy,
        ),
        (
            StopPoint::BeforeIntentRename,
            VisibleState::Legacy,
            RecoveryDecision::DiscardUncommittedPrepareAndKeepLegacy,
        ),
        (
            StopPoint::AfterIntent,
            VisibleState::Legacy,
            RecoveryDecision::ClearUnanchoredIntentAndKeepLegacy,
        ),
        (
            StopPoint::BeforeAnchorRename,
            VisibleState::Legacy,
            RecoveryDecision::ClearUnanchoredIntentAndKeepLegacy,
        ),
        (
            StopPoint::AfterAnchorCommit,
            VisibleState::Boundary,
            RecoveryDecision::RollForwardPreparedBoundaryAfterAnchorAdvance,
        ),
        (
            StopPoint::BeforeInstallRename,
            VisibleState::Boundary,
            RecoveryDecision::RollForwardPreparedBoundaryAfterAnchorAdvance,
        ),
        (
            StopPoint::AfterInstall,
            VisibleState::Boundary,
            RecoveryDecision::AcceptCommittedBoundaryAndClearIntent,
        ),
        (
            StopPoint::BeforeIntentClear,
            VisibleState::Boundary,
            RecoveryDecision::AcceptCommittedBoundaryAndClearIntent,
        ),
        (
            StopPoint::AfterIntentClear,
            VisibleState::Boundary,
            RecoveryDecision::AcceptCommittedBoundary,
        ),
        (
            StopPoint::AfterClear,
            VisibleState::Boundary,
            RecoveryDecision::AcceptCommittedBoundary,
        ),
    ];
    for (stop, expected_visible, expected_decision) in stops.iter().cloned() {
        let (trust, _, _, _, _) = trusted();
        let lab = Lab::new();
        execute_until(&lab, &trust, stop);
        let (visible, decision) = recover_after_restart(&lab, &trust);
        assert_eq!(visible, expected_visible, "stage {stop:?}");
        assert_eq!(decision, expected_decision, "stage {stop:?}");
        assert!(
            artifacts_absent(&lab),
            "stage {stop:?} left orphan artifacts"
        );
        let (again, _) = recover_after_restart(&lab, &trust);
        assert_eq!(
            again, expected_visible,
            "recovery must be idempotent after {stop:?}"
        );
        assert!(
            artifacts_absent(&lab),
            "second recovery left artifacts after {stop:?}"
        );
        let persisted_floor = decode_floor(&fs::read(lab.floor()).unwrap()).unwrap();
        if expected_visible == VisibleState::Legacy {
            assert_eq!(
                persisted_floor,
                old_floor(&trust),
                "pre-anchor fault advanced trust floor"
            );
        } else {
            assert_eq!(
                persisted_floor,
                advanced_floor(&trust),
                "post-anchor fault regressed trust floor"
            );
        }
    }
    eprintln!("CP-0237_FILE_CRASH_MATRIX=PASS stages={} local_visibility=old_or_exact_anchored_boundary idempotent_reopen=true", stops.len());
}

#[test]
fn cp0237_corruption_restore_and_anchor_unavailability_fail_closed() {
    // Corrupt the prepared payload after the anchor target became durable.
    {
        let (trust, _, _, _, _) = trusted();
        let lab = Lab::new();
        execute_until(&lab, &trust, StopPoint::AfterAnchorCommit);
        corrupt_marker(&lab.prepared());
        let (visible, decision) = recover_after_restart(&lab, &trust);
        assert_eq!(visible, VisibleState::Quarantine);
        assert_eq!(
            decision,
            RecoveryDecision::QuarantinePreparedBoundaryMismatch
        );
    }
    // Corrupt the commit intent: neither checksum failure nor partial intent is guessed.
    {
        let (trust, _, _, _, _) = trusted();
        let lab = Lab::new();
        execute_until(&lab, &trust, StopPoint::AfterAnchorCommit);
        corrupt_marker(&lab.intent());
        let (visible, decision) = recover_after_restart(&lab, &trust);
        assert_eq!(visible, VisibleState::Quarantine);
        assert_eq!(decision, RecoveryDecision::QuarantineIntentMismatch);
    }
    // A pre-migration local-volume restore loses local evidence, not the anchor floor.
    {
        let (trust, _, _, _, _) = trusted();
        let lab = Lab::new();
        execute_until(&lab, &trust, StopPoint::AfterAnchorCommit);
        put_file(&lab.local_state(), &encode_local(&legacy(&trust)));
        remove_if_present(&lab.prepared());
        remove_if_present(&lab.intent());
        let (visible, decision) = recover_after_restart(&lab, &trust);
        assert_eq!(visible, VisibleState::Quarantine);
        assert_eq!(
            decision,
            RecoveryDecision::QuarantineAnchorAdvancedWithoutPreparedBoundary
        );
        assert_eq!(
            decode_floor(&fs::read(lab.floor()).unwrap()).unwrap(),
            advanced_floor(&trust)
        );
    }
    // Restoring an old floor against a committed local boundary is equally unsafe.
    {
        let (trust, _, _, _, _) = trusted();
        let lab = Lab::new();
        execute_until(&lab, &trust, StopPoint::AfterClear);
        put_file(&lab.floor(), &encode_floor(&old_floor(&trust)));
        let (visible, decision) = recover_after_restart(&lab, &trust);
        assert_eq!(visible, VisibleState::Quarantine);
        assert_eq!(
            decision,
            RecoveryDecision::QuarantineLocalStateAheadOfTrustFloor
        );
    }
    // Missing the anchor is not equivalent to an initial epoch-zero state.
    {
        let (trust, _, _, _, _) = trusted();
        let lab = Lab::new();
        initialize(&lab, &trust);
        remove_if_present(&lab.floor());
        let (visible, decision) = recover_after_restart(&lab, &trust);
        assert_eq!(visible, VisibleState::Quarantine);
        assert_eq!(decision, RecoveryDecision::QuarantineTrustFloorUnavailable);
    }
    eprintln!("CP-0237_FAIL_CLOSED=PASS prepared_corruption=true intent_corruption=true local_restore=true floor_restore=true anchor_missing=true");
}

#[test]
fn cp0237_atomic_write_faults_preserve_old_or_complete_new_file() {
    let (trust, _, _, _, _) = trusted();
    let lab = Lab::new();
    initialize(&lab, &trust);
    let path = lab.local_state();
    let old = fs::read(&path).unwrap();
    let new = encode_local(&boundary(&trust));

    assert!(write_atomic(&path, &new, WriteFault::BeforeRename).is_err());
    assert_eq!(
        fs::read(&path).unwrap(),
        old,
        "pre-rename error must preserve old destination"
    );
    assert!(
        path.with_extension("tmp").exists(),
        "pre-rename fault should leave an orphan temp"
    );

    assert!(write_atomic(&path, &new, WriteFault::AfterRename).is_err());
    assert_eq!(
        fs::read(&path).unwrap(),
        new,
        "post-rename ambiguous error means full new file is visible"
    );
    assert!(!path.with_extension("tmp").exists());
    eprintln!("CP-0237_ATOMIC_FILE_FAULTS=PASS before_rename=old_after_rename=complete_new");
}
