//! CP-0682 local single-owner dual-disk QFP6 high-water vault.
//! Detects data-volume-only rollback while the separately mounted local system volume survives.
//! Not a TPM monotonic counter, independent operator, or protection against full-machine rollback.

use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};

const SCHEMA: &str = "qfp6-local-anchor-vault/v1";
const DOMAIN: &[u8] = b"QFP6-LOCAL-ANCHOR-VAULT-RECORD-V1\x00";
const PREFIX: &str = "q6av-";
const SUFFIX: &str = ".json";
const MAX_RECORDS: usize = 100_000;
const MAX_BYTES: u64 = 4096;
const WITNESS_SCHEMA: &str = "qfp6-checkpoint-segment-witness/v1";
const WITNESS_DOMAIN: &[u8] = b"QFP6-CHECKPOINT-SEGMENT-WITNESS-V1\x00";
const WITNESS_PREFIX: &str = "q6sw-";
const WITNESS_MAX_BYTES: u64 = 8192;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QRunV06CheckpointSegmentWitness {
    pub sequence: u64,
    pub predecessor_vault_sequence: u64,
    pub predecessor_global_generation: u64,
    pub predecessor_manifest_anchor: [u8; 32],
    pub predecessor_record_digest: [u8; 32],
    pub checkpoint_commitment: [u8; 32],
    pub segment_root_manifest_anchor: [u8; 32],
    pub checkpoint_base_height: u64,
    pub checkpoint_tip_hash: [u8; 32],
    pub checkpoint_state_root: [u8; 32],
    pub checkpoint_cumulative_work: [u8; 32],
    pub network_id: [u8; 32],
    pub profile_id: [u8; 32],
    pub genesis_descriptor_commitment: [u8; 32],
    pub consensus_fingerprint: [u8; 32],
    pub previous_witness_digest: [u8; 32],
    pub witness_digest: [u8; 32],
}

fn witness_digest(w: &QRunV06CheckpointSegmentWitness) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(WITNESS_DOMAIN);
    h.update(w.sequence.to_be_bytes());
    h.update(w.predecessor_vault_sequence.to_be_bytes());
    h.update(w.predecessor_global_generation.to_be_bytes());
    h.update(w.predecessor_manifest_anchor);
    h.update(w.predecessor_record_digest);
    h.update(w.checkpoint_commitment);
    h.update(w.segment_root_manifest_anchor);
    h.update(w.checkpoint_base_height.to_be_bytes());
    h.update(w.checkpoint_tip_hash);
    h.update(w.checkpoint_state_root);
    h.update(w.checkpoint_cumulative_work);
    h.update(w.network_id);
    h.update(w.profile_id);
    h.update(w.genesis_descriptor_commitment);
    h.update(w.consensus_fingerprint);
    h.update(w.previous_witness_digest);
    h.finalize().into()
}

fn witness_file_name(sequence: u64) -> String {
    format!("{WITNESS_PREFIX}{sequence:020}{SUFFIX}")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QRunV06LocalAnchorVaultTip {
    pub sequence: u64,
    pub manifest_generation: u64,
    pub manifest_anchor: [u8; 32],
    pub record_digest: [u8; 32],
}

#[derive(Debug)]
pub struct QRunV06LocalAnchorVault {
    root: PathBuf,
    records_dir: PathBuf,
    witnesses_dir: PathBuf,
    network_id: [u8; 32],
    profile_id: [u8; 32],
    root_generation: u64,
    root_anchor: [u8; 32],
    tip: QRunV06LocalAnchorVaultTip,
    latest_checkpoint_segment_witness: Option<QRunV06CheckpointSegmentWitness>,
}

fn hex(bytes: &[u8]) -> String {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(H[(b >> 4) as usize] as char);
        s.push(H[(b & 15) as usize] as char);
    }
    s
}

fn parse_hex32(s: &str, label: &str) -> Result<[u8; 32], String> {
    if s.len() != 64
        || !s.is_ascii()
        || !s
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(format!(
            "{label} must be 64 lowercase hexadecimal characters"
        ));
    }
    let mut out = [0u8; 32];
    for (i, v) in out.iter_mut().enumerate() {
        *v =
            u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).map_err(|_| format!("invalid {label}"))?;
    }
    Ok(out)
}

fn digest(
    seq: u64,
    network: &[u8; 32],
    profile: &[u8; 32],
    generation: u64,
    anchor: &[u8; 32],
    previous: &[u8; 32],
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(DOMAIN);
    h.update(seq.to_be_bytes());
    h.update(network);
    h.update(profile);
    h.update(generation.to_be_bytes());
    h.update(anchor);
    h.update(previous);
    h.finalize().into()
}

fn real_dir(path: &Path, label: &str) -> Result<(), String> {
    let m = fs::symlink_metadata(path).map_err(|e| format!("{label} unavailable: {e}"))?;
    if m.file_type().is_symlink() || !m.is_dir() {
        return Err(format!("{label} must be a real directory"));
    }
    Ok(())
}

fn str_field(v: &serde_json::Value, key: &str) -> Result<String, String> {
    v.get(key)
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| format!("local anchor record {key} is missing"))
}
fn u64_field(v: &serde_json::Value, key: &str) -> Result<u64, String> {
    v.get(key)
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| format!("local anchor record {key} is invalid"))
}
fn read_witness(path: &Path) -> Result<QRunV06CheckpointSegmentWitness, String> {
    let metadata = fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() > WITNESS_MAX_BYTES
    {
        return Err("checkpoint segment witness must be a bounded regular file".into());
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    File::open(path)
        .map_err(|e| e.to_string())?
        .take(WITNESS_MAX_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() as u64 > WITNESS_MAX_BYTES {
        return Err("checkpoint segment witness exceeds size limit".into());
    }
    let v: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|e| format!("invalid segment witness JSON: {e}"))?;
    if str_field(&v, "schema")? != WITNESS_SCHEMA {
        return Err("checkpoint segment witness schema mismatch".into());
    }
    Ok(QRunV06CheckpointSegmentWitness {
        sequence: u64_field(&v, "sequence")?,
        predecessor_vault_sequence: u64_field(&v, "predecessor_vault_sequence")?,
        predecessor_global_generation: u64_field(&v, "predecessor_global_generation")?,
        predecessor_manifest_anchor: parse_hex32(
            &str_field(&v, "predecessor_manifest_anchor_hex")?,
            "predecessor_manifest_anchor_hex",
        )?,
        predecessor_record_digest: parse_hex32(
            &str_field(&v, "predecessor_record_digest_hex")?,
            "predecessor_record_digest_hex",
        )?,
        checkpoint_commitment: parse_hex32(
            &str_field(&v, "checkpoint_commitment_hex")?,
            "checkpoint_commitment_hex",
        )?,
        segment_root_manifest_anchor: parse_hex32(
            &str_field(&v, "segment_root_manifest_anchor_hex")?,
            "segment_root_manifest_anchor_hex",
        )?,
        checkpoint_base_height: u64_field(&v, "checkpoint_base_height")?,
        checkpoint_tip_hash: parse_hex32(
            &str_field(&v, "checkpoint_tip_hash_hex")?,
            "checkpoint_tip_hash_hex",
        )?,
        checkpoint_state_root: parse_hex32(
            &str_field(&v, "checkpoint_state_root_hex")?,
            "checkpoint_state_root_hex",
        )?,
        checkpoint_cumulative_work: parse_hex32(
            &str_field(&v, "checkpoint_cumulative_work_hex")?,
            "checkpoint_cumulative_work_hex",
        )?,
        network_id: parse_hex32(&str_field(&v, "network_id_hex")?, "network_id_hex")?,
        profile_id: parse_hex32(&str_field(&v, "profile_id_hex")?, "profile_id_hex")?,
        genesis_descriptor_commitment: parse_hex32(
            &str_field(&v, "genesis_descriptor_commitment_hex")?,
            "genesis_descriptor_commitment_hex",
        )?,
        consensus_fingerprint: parse_hex32(
            &str_field(&v, "consensus_fingerprint_hex")?,
            "consensus_fingerprint_hex",
        )?,
        previous_witness_digest: parse_hex32(
            &str_field(&v, "previous_witness_digest_hex")?,
            "previous_witness_digest_hex",
        )?,
        witness_digest: parse_hex32(&str_field(&v, "witness_digest_hex")?, "witness_digest_hex")?,
    })
}

fn load_witnesses(
    root: &Path,
    records_dir: &Path,
    network: [u8; 32],
    profile: [u8; 32],
    vault_tip: QRunV06LocalAnchorVaultTip,
) -> Result<Option<QRunV06CheckpointSegmentWitness>, String> {
    let directory = root.join("checkpoint-segment-witnesses");
    match fs::symlink_metadata(&directory) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.to_string()),
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            return Err("checkpoint segment witness path must be a real directory".into())
        }
        Ok(_) => {}
    }
    let mut files = Vec::<(u64, PathBuf)>::new();
    for entry in fs::read_dir(&directory).map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        let name = entry.file_name().to_string_lossy().into_owned();
        let sequence = name
            .strip_prefix(WITNESS_PREFIX)
            .and_then(|v| v.strip_suffix(SUFFIX))
            .filter(|v| v.len() == 20 && v.bytes().all(|b| b.is_ascii_digit()))
            .ok_or_else(|| format!("unexpected checkpoint witness entry: {name}"))?
            .parse::<u64>()
            .map_err(|_| "invalid checkpoint witness sequence")?;
        files.push((sequence, entry.path()));
    }
    files.sort_by_key(|entry| entry.0);
    if files.len() > MAX_RECORDS {
        return Err("checkpoint segment witness count limit reached".into());
    }
    let mut previous_witness = [0u8; 32];
    let mut latest = None;
    for (index, (sequence, path)) in files.iter().enumerate() {
        let expected_sequence = index as u64 + 1;
        if *sequence != expected_sequence {
            return Err(format!(
                "checkpoint witness sequence gap: expected {expected_sequence}, found {sequence}"
            ));
        }
        let witness = read_witness(path)?;
        if witness.sequence != *sequence
            || witness.previous_witness_digest != previous_witness
            || witness.witness_digest != witness_digest(&witness)
            || witness.network_id != network
            || witness.profile_id != profile
            || witness.checkpoint_commitment == [0; 32]
            || witness.segment_root_manifest_anchor == [0; 32]
            || witness.genesis_descriptor_commitment == [0; 32]
            || witness.consensus_fingerprint == [0; 32]
        {
            return Err(format!(
                "checkpoint witness identity/hash mismatch at sequence {sequence}"
            ));
        }
        let predecessor_path = records_dir.join(format!(
            "{PREFIX}{:020}{SUFFIX}",
            witness.predecessor_vault_sequence
        ));
        if witness.predecessor_vault_sequence == 0
            || witness.predecessor_vault_sequence > vault_tip.sequence
        {
            return Err(
                "checkpoint witness predecessor sequence is outside the vault chain".into(),
            );
        }
        let predecessor = read_record(&predecessor_path)?;
        let predecessor_generation = u64_field(&predecessor, "manifest_generation")?;
        let predecessor_anchor = parse_hex32(
            &str_field(&predecessor, "manifest_anchor_hex")?,
            "manifest_anchor_hex",
        )?;
        let predecessor_digest =
            parse_hex32(&str_field(&predecessor, "record_sha256")?, "record_sha256")?;
        if predecessor_generation != witness.predecessor_global_generation
            || predecessor_anchor != witness.predecessor_manifest_anchor
            || predecessor_digest != witness.predecessor_record_digest
            || witness
                .predecessor_global_generation
                .checked_add(1)
                .is_none()
        {
            return Err(format!(
                "checkpoint witness does not bind its exact C: predecessor at sequence {sequence}"
            ));
        }
        if let Some(previous) = latest {
            let previous: QRunV06CheckpointSegmentWitness = previous;
            if witness.predecessor_vault_sequence <= previous.predecessor_vault_sequence
                || witness.predecessor_global_generation <= previous.predecessor_global_generation
            {
                return Err("checkpoint witness predecessor does not advance".into());
            }
        }
        previous_witness = witness.witness_digest;
        latest = Some(witness);
    }
    if let Some(witness) = latest {
        let root_generation = witness.predecessor_global_generation + 1;
        if vault_tip.manifest_generation < witness.predecessor_global_generation
            || (vault_tip.manifest_generation == root_generation
                && vault_tip.manifest_anchor != witness.segment_root_manifest_anchor)
        {
            return Err("C: vault tip conflicts with the latest checkpoint segment witness".into());
        }
        Ok(Some(witness))
    } else {
        Ok(None)
    }
}

fn read_record(path: &Path) -> Result<serde_json::Value, String> {
    let m = fs::symlink_metadata(path).map_err(|e| format!("cannot inspect anchor record: {e}"))?;
    if m.file_type().is_symlink() || !m.is_file() || m.len() > MAX_BYTES {
        return Err(format!(
            "anchor record is not a bounded regular file: {}",
            path.display()
        ));
    }
    let f = File::open(path).map_err(|e| e.to_string())?;
    let mut b = Vec::with_capacity(m.len() as usize);
    f.take(MAX_BYTES + 1)
        .read_to_end(&mut b)
        .map_err(|e| e.to_string())?;
    if b.len() as u64 > MAX_BYTES {
        return Err("anchor record exceeds size limit".into());
    }
    serde_json::from_slice(&b).map_err(|e| format!("invalid anchor record JSON: {e}"))
}

impl QRunV06LocalAnchorVault {
    /// Create a brand-new generation-zero anchor root for a fresh Genesis-only node.
    /// The root directory and first record are create-new only; an existing or partial root
    /// is never repaired, truncated, or overwritten automatically.
    pub fn provision_genesis_root(
        root: impl AsRef<Path>,
        network: [u8; 32],
        profile: [u8; 32],
        genesis_manifest_anchor: [u8; 32],
    ) -> Result<Self, String> {
        let root = root.as_ref();
        if !root.is_absolute() {
            return Err("fresh Genesis anchor vault path must be absolute".into());
        }
        if genesis_manifest_anchor == [0; 32] {
            return Err("fresh Genesis manifest anchor must not be zero".into());
        }
        let parent = root
            .parent()
            .ok_or("fresh Genesis anchor vault path has no parent")?;
        real_dir(parent, "fresh Genesis anchor vault parent")?;
        let name = root
            .file_name()
            .filter(|value| !value.is_empty())
            .ok_or("fresh Genesis anchor vault path has no final component")?;
        let _ = name;
        fs::create_dir(root).map_err(|error| {
            format!("cannot create fresh Genesis anchor vault without overwrite: {error}")
        })?;
        let records_dir = root.join("records");
        fs::create_dir(&records_dir).map_err(|error| {
            format!("cannot create fresh Genesis anchor records directory: {error}")
        })?;
        let record_digest = digest(1, &network, &profile, 0, &genesis_manifest_anchor, &[0; 32]);
        let value = serde_json::json!({
            "schema": SCHEMA,
            "sequence": 1,
            "network_id_hex": hex(&network),
            "profile_id_hex": hex(&profile),
            "manifest_generation": 0,
            "manifest_anchor_hex": hex(&genesis_manifest_anchor),
            "previous_record_sha256": hex(&[0; 32]),
            "record_sha256": hex(&record_digest),
        });
        let mut bytes = serde_json::to_vec_pretty(&value).map_err(|error| error.to_string())?;
        bytes.push(b'\n');
        let record_path = records_dir.join(format!("{PREFIX}{:020}{SUFFIX}", 1));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&record_path)
            .map_err(|error| {
                format!("cannot create Genesis anchor record without overwrite: {error}")
            })?;
        file.write_all(&bytes)
            .map_err(|error| format!("cannot write Genesis anchor record: {error}"))?;
        file.sync_all()
            .map_err(|error| format!("cannot flush Genesis anchor record: {error}"))?;
        drop(file);
        let checked = Self::open(root, network, profile)?;
        if checked.tip().manifest_generation != 0
            || checked.tip().manifest_anchor != genesis_manifest_anchor
            || checked.tip().sequence != 1
        {
            return Err(
                "reopened fresh Genesis anchor root differs from the requested root".into(),
            );
        }
        Ok(checked)
    }

    /// Load and verify all append-only C:-side records, including sequence, identity and hashes.
    pub fn open(
        root: impl AsRef<Path>,
        network: [u8; 32],
        profile: [u8; 32],
    ) -> Result<Self, String> {
        let root = root.as_ref().to_path_buf();
        real_dir(&root, "local QFP6 anchor vault")?;
        let records_dir = root.join("records");
        real_dir(&records_dir, "local QFP6 anchor records directory")?;
        let mut files = Vec::<(u64, PathBuf)>::new();
        for e in fs::read_dir(&records_dir).map_err(|e| e.to_string())? {
            let e = e.map_err(|e| e.to_string())?;
            let name = e.file_name().to_string_lossy().into_owned();
            let n = name
                .strip_prefix(PREFIX)
                .and_then(|x| x.strip_suffix(SUFFIX))
                .ok_or_else(|| format!("unexpected anchor vault entry: {name}"))?;
            if n.len() != 20 || !n.bytes().all(|b| b.is_ascii_digit()) {
                return Err(format!("invalid record filename: {name}"));
            }
            let seq = n.parse::<u64>().map_err(|_| "invalid anchor sequence")?;
            let path = e.path();
            let m = fs::symlink_metadata(&path).map_err(|e| e.to_string())?;
            if m.file_type().is_symlink() || !m.is_file() || m.len() > MAX_BYTES {
                return Err(format!(
                    "anchor record must be a bounded regular file: {name}"
                ));
            }
            files.push((seq, path));
        }
        files.sort_by_key(|x| x.0);
        if files.is_empty() || files.len() > MAX_RECORDS {
            return Err("anchor vault empty or over record limit".into());
        }
        let mut previous = [0u8; 32];
        let mut last_generation = None::<u64>;
        let mut root_record = None;
        let mut last = None;
        for (i, (seq, path)) in files.iter().enumerate() {
            let expected = i as u64 + 1;
            if *seq != expected {
                return Err(format!(
                    "anchor sequence gap: expected {expected}, found {seq}"
                ));
            }
            let v = read_record(path)?;
            if str_field(&v, "schema")? != SCHEMA || u64_field(&v, "sequence")? != *seq {
                return Err(format!(
                    "anchor record schema/sequence mismatch: {}",
                    path.display()
                ));
            }
            let net = parse_hex32(&str_field(&v, "network_id_hex")?, "network_id_hex")?;
            let prof = parse_hex32(&str_field(&v, "profile_id_hex")?, "profile_id_hex")?;
            let generation = u64_field(&v, "manifest_generation")?;
            let anchor = parse_hex32(
                &str_field(&v, "manifest_anchor_hex")?,
                "manifest_anchor_hex",
            )?;
            let prev = parse_hex32(
                &str_field(&v, "previous_record_sha256")?,
                "previous_record_sha256",
            )?;
            let saved = parse_hex32(&str_field(&v, "record_sha256")?, "record_sha256")?;
            if net != network || prof != profile {
                return Err("anchor vault network/profile mismatch".into());
            }
            if prev != previous {
                return Err(format!(
                    "anchor predecessor digest mismatch at sequence {seq}"
                ));
            }
            if let Some(previous_generation) = last_generation {
                let expected_generation = previous_generation
                    .checked_add(1)
                    .ok_or("anchor generation overflow")?;
                if generation != expected_generation {
                    return Err(format!(
                        "anchor generation gap: expected {expected_generation}, found {generation}"
                    ));
                }
            }
            if anchor == [0; 32] || saved != digest(*seq, &net, &prof, generation, &anchor, &prev) {
                return Err(format!(
                    "anchor record checksum/value mismatch at sequence {seq}"
                ));
            }
            let tip = QRunV06LocalAnchorVaultTip {
                sequence: *seq,
                manifest_generation: generation,
                manifest_anchor: anchor,
                record_digest: saved,
            };
            if root_record.is_none() {
                root_record = Some(tip);
            }
            last = Some(tip);
            previous = saved;
            last_generation = Some(generation);
        }
        let first = root_record.ok_or("vault has no root record")?;
        let tip = last.ok_or("vault has no tip")?;
        let witnesses_dir = root.join("checkpoint-segment-witnesses");
        let latest_checkpoint_segment_witness =
            load_witnesses(&root, &records_dir, network, profile, tip)?;
        Ok(Self {
            root,
            records_dir,
            witnesses_dir,
            network_id: network,
            profile_id: profile,
            root_generation: first.manifest_generation,
            root_anchor: first.manifest_anchor,
            tip,
            latest_checkpoint_segment_witness,
        })
    }

    pub fn tip(&self) -> QRunV06LocalAnchorVaultTip {
        self.tip
    }
    pub fn root_generation(&self) -> u64 {
        self.root_generation
    }
    pub fn root_anchor(&self) -> [u8; 32] {
        self.root_anchor
    }

    pub fn latest_checkpoint_segment_witness(&self) -> Option<QRunV06CheckpointSegmentWitness> {
        self.latest_checkpoint_segment_witness
    }

    /// Append a separately hash-chained witness before publishing the checkpoint segment root
    /// into the global manifest-anchor chain. The predecessor must be this exact current C: tip.
    pub fn append_checkpoint_segment_witness(
        &mut self,
        mut witness: QRunV06CheckpointSegmentWitness,
    ) -> Result<QRunV06CheckpointSegmentWitness, String> {
        if witness.predecessor_vault_sequence != self.tip.sequence
            || witness.predecessor_global_generation != self.tip.manifest_generation
            || witness.predecessor_manifest_anchor != self.tip.manifest_anchor
            || witness.predecessor_record_digest != self.tip.record_digest
            || witness.network_id != self.network_id
            || witness.profile_id != self.profile_id
            || witness.checkpoint_commitment == [0; 32]
            || witness.segment_root_manifest_anchor == [0; 32]
            || witness.genesis_descriptor_commitment == [0; 32]
            || witness.consensus_fingerprint == [0; 32]
        {
            return Err(
                "checkpoint witness does not bind the exact current C: vault tip and profile"
                    .into(),
            );
        }
        if let Some(previous) = self.latest_checkpoint_segment_witness {
            let expected = previous
                .sequence
                .checked_add(1)
                .ok_or("witness sequence overflow")?;
            if witness.sequence != expected
                || witness.previous_witness_digest != previous.witness_digest
            {
                return Err("checkpoint witness sequence/hash-chain predecessor mismatch".into());
            }
            if self.tip.manifest_generation < previous.predecessor_global_generation + 1 {
                return Err("previous checkpoint segment root has not been anchored".into());
            }
        } else if witness.sequence != 1 || witness.previous_witness_digest != [0; 32] {
            return Err(
                "first checkpoint witness must start at sequence one and zero predecessor".into(),
            );
        }
        let expected_root_generation = self
            .tip
            .manifest_generation
            .checked_add(1)
            .ok_or("global anchor generation overflow")?;
        if witness.segment_root_manifest_anchor == self.tip.manifest_anchor
            || expected_root_generation == 0
        {
            return Err("invalid checkpoint segment root anchor".into());
        }
        real_dir(&self.root, "local QFP6 anchor vault")?;
        if !self.witnesses_dir.exists() {
            fs::create_dir(&self.witnesses_dir)
                .map_err(|e| format!("cannot create checkpoint witness directory: {e}"))?;
        }
        real_dir(&self.witnesses_dir, "checkpoint segment witness directory")?;
        let expected_sequence = self
            .latest_checkpoint_segment_witness
            .map(|w| w.sequence + 1)
            .unwrap_or(1);
        if witness.sequence != expected_sequence {
            return Err("checkpoint witness sequence is not the next append-only sequence".into());
        }
        witness.witness_digest = witness_digest(&witness);
        let value = serde_json::json!({
            "schema": WITNESS_SCHEMA,
            "sequence": witness.sequence,
            "predecessor_vault_sequence": witness.predecessor_vault_sequence,
            "predecessor_global_generation": witness.predecessor_global_generation,
            "predecessor_manifest_anchor_hex": hex(&witness.predecessor_manifest_anchor),
            "predecessor_record_digest_hex": hex(&witness.predecessor_record_digest),
            "checkpoint_commitment_hex": hex(&witness.checkpoint_commitment),
            "segment_root_manifest_anchor_hex": hex(&witness.segment_root_manifest_anchor),
            "checkpoint_base_height": witness.checkpoint_base_height,
            "checkpoint_tip_hash_hex": hex(&witness.checkpoint_tip_hash),
            "checkpoint_state_root_hex": hex(&witness.checkpoint_state_root),
            "checkpoint_cumulative_work_hex": hex(&witness.checkpoint_cumulative_work),
            "network_id_hex": hex(&witness.network_id),
            "profile_id_hex": hex(&witness.profile_id),
            "genesis_descriptor_commitment_hex": hex(&witness.genesis_descriptor_commitment),
            "consensus_fingerprint_hex": hex(&witness.consensus_fingerprint),
            "previous_witness_digest_hex": hex(&witness.previous_witness_digest),
            "witness_digest_hex": hex(&witness.witness_digest),
        });
        let mut bytes = serde_json::to_vec_pretty(&value).map_err(|e| e.to_string())?;
        bytes.push(b'\n');
        let path = self.witnesses_dir.join(witness_file_name(witness.sequence));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .map_err(|e| format!("cannot create checkpoint witness without overwrite: {e}"))?;
        file.write_all(&bytes).map_err(|e| e.to_string())?;
        file.sync_all().map_err(|e| e.to_string())?;
        drop(file);
        let checked = Self::open(&self.root, self.network_id, self.profile_id)?;
        if checked.latest_checkpoint_segment_witness != Some(witness) {
            return Err("reopened checkpoint witness differs from appended witness".into());
        }
        self.latest_checkpoint_segment_witness = checked.latest_checkpoint_segment_witness;
        Ok(witness)
    }

    /// Finish or idempotently recover the witness-to-root publication step after a crash.
    pub fn reconcile_checkpoint_segment_root(
        &mut self,
    ) -> Result<QRunV06LocalAnchorVaultTip, String> {
        let witness = self
            .latest_checkpoint_segment_witness
            .ok_or("no checkpoint segment witness is present")?;
        let root_generation = witness
            .predecessor_global_generation
            .checked_add(1)
            .ok_or("global anchor generation overflow")?;
        if self.tip.manifest_generation == witness.predecessor_global_generation
            && self.tip.sequence == witness.predecessor_vault_sequence
            && self.tip.manifest_anchor == witness.predecessor_manifest_anchor
            && self.tip.record_digest == witness.predecessor_record_digest
        {
            return self.append_successor(root_generation, witness.segment_root_manifest_anchor);
        }
        if self.tip.manifest_generation == root_generation
            && self.tip.manifest_anchor == witness.segment_root_manifest_anchor
        {
            return Ok(self.tip);
        }
        if self.tip.manifest_generation > root_generation {
            return Ok(self.tip);
        }
        Err("vault tip is inconsistent with pending checkpoint segment witness".into())
    }

    /// Map segment-local generation zero to the witness root and all later local generations
    /// to the global C: sequence. The offset is never inferred from a segment path or manifest.
    pub fn append_segment_successor(
        &mut self,
        segment_local_generation: u64,
        anchor: [u8; 32],
    ) -> Result<QRunV06LocalAnchorVaultTip, String> {
        let witness = self
            .latest_checkpoint_segment_witness
            .ok_or("segment-local append requires a checkpoint witness")?;
        let global_generation = witness
            .predecessor_global_generation
            .checked_add(1)
            .and_then(|base| base.checked_add(segment_local_generation))
            .ok_or("global segment generation overflow")?;
        if segment_local_generation == 0 {
            if anchor != witness.segment_root_manifest_anchor {
                return Err(
                    "segment generation-zero anchor differs from checkpoint witness".into(),
                );
            }
            if self.tip.manifest_generation
                > witness.predecessor_global_generation.saturating_add(1)
            {
                return Err("C: vault is ahead of segment-local generation zero".into());
            }
            return self.reconcile_checkpoint_segment_root();
        }
        if self.tip.manifest_generation == global_generation && self.tip.manifest_anchor == anchor {
            return Ok(self.tip);
        }
        if self.tip.manifest_generation.checked_add(1) != Some(global_generation) {
            return Err(
                "segment-local/global generation mapping is not the exact next successor".into(),
            );
        }
        self.append_successor(global_generation, anchor)
    }

    /// Persist exactly one successor. Exact retries are idempotent; generation gaps fail closed.
    pub fn append_successor(
        &mut self,
        generation: u64,
        anchor: [u8; 32],
    ) -> Result<QRunV06LocalAnchorVaultTip, String> {
        if generation == self.tip.manifest_generation && anchor == self.tip.manifest_anchor {
            return Ok(self.tip);
        }
        let expected = self
            .tip
            .manifest_generation
            .checked_add(1)
            .ok_or("anchor generation overflow")?;
        if generation != expected || anchor == [0; 32] {
            return Err(format!(
                "anchor successor must be exactly generation {expected}; refusing gap/divergence"
            ));
        }
        real_dir(&self.root, "local QFP6 anchor vault")?;
        real_dir(&self.records_dir, "local QFP6 anchor records directory")?;
        let seq = self
            .tip
            .sequence
            .checked_add(1)
            .ok_or("anchor sequence overflow")?;
        if seq as usize > MAX_RECORDS {
            return Err("anchor record count limit reached".into());
        }
        let saved = digest(
            seq,
            &self.network_id,
            &self.profile_id,
            generation,
            &anchor,
            &self.tip.record_digest,
        );
        let value = serde_json::json!({
            "schema": SCHEMA, "sequence": seq, "network_id_hex": hex(&self.network_id),
            "profile_id_hex": hex(&self.profile_id), "manifest_generation": generation,
            "manifest_anchor_hex": hex(&anchor), "previous_record_sha256": hex(&self.tip.record_digest),
            "record_sha256": hex(&saved)
        });
        let mut bytes = serde_json::to_vec_pretty(&value).map_err(|e| e.to_string())?;
        bytes.push(b'\n');
        let path = self.records_dir.join(format!("{PREFIX}{seq:020}{SUFFIX}"));
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .map_err(|e| format!("cannot create anchor successor without overwrite: {e}"))?;
        f.write_all(&bytes)
            .map_err(|e| format!("cannot write anchor successor: {e}"))?;
        f.sync_all()
            .map_err(|e| format!("cannot flush anchor successor: {e}"))?;
        drop(f);
        let checked = Self::open(&self.root, self.network_id, self.profile_id)?;
        if checked.tip.manifest_generation != generation || checked.tip.manifest_anchor != anchor {
            return Err("re-opened anchor tip differs from appended successor".into());
        }
        self.tip = checked.tip;
        Ok(self.tip)
    }

    /// Called only after the store has replayed and authenticated the manifest chain from this exact C: tip.
    pub fn reconcile_replayed_tip(
        &mut self,
        generation: u64,
        anchor: [u8; 32],
    ) -> Result<QRunV06LocalAnchorVaultTip, String> {
        if generation == self.tip.manifest_generation {
            if anchor != self.tip.manifest_anchor {
                return Err("manifest at anchored generation diverges from C: vault".into());
            }
            return Ok(self.tip);
        }
        if generation < self.tip.manifest_generation {
            return Err("D: history is behind the C: anchor; possible rollback".into());
        }
        if generation != self.tip.manifest_generation + 1 {
            return Err(
                "D: history is more than one generation ahead; manual audit required".into(),
            );
        }
        self.append_successor(generation, anchor)
    }
}

#[cfg(test)]
pub(crate) fn provision_test_root(
    root: &Path,
    network: [u8; 32],
    profile: [u8; 32],
    generation: u64,
    anchor: [u8; 32],
) -> Result<(), String> {
    fs::create_dir_all(root.join("records")).map_err(|error| error.to_string())?;
    let record_digest = digest(1, &network, &profile, generation, &anchor, &[0; 32]);
    let value = serde_json::json!({
        "schema": SCHEMA,
        "sequence": 1,
        "network_id_hex": hex(&network),
        "profile_id_hex": hex(&profile),
        "manifest_generation": generation,
        "manifest_anchor_hex": hex(&anchor),
        "previous_record_sha256": hex(&[0; 32]),
        "record_sha256": hex(&record_digest),
    });
    let bytes = serde_json::to_vec_pretty(&value).map_err(|error| error.to_string())?;
    fs::write(
        root.join("records")
            .join(format!("{PREFIX}{:020}{SUFFIX}", 1)),
        bytes,
    )
    .map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(1);
    fn dir() -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "qfp6-vault-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(p.join("records")).unwrap();
        p
    }
    fn provision(p: &Path, net: [u8; 32], prof: [u8; 32], gen: u64, anchor: [u8; 32]) {
        let d = digest(1, &net, &prof, gen, &anchor, &[0; 32]);
        let v = serde_json::json!({"schema":SCHEMA,"sequence":1,"network_id_hex":hex(&net),"profile_id_hex":hex(&prof),
            "manifest_generation":gen,"manifest_anchor_hex":hex(&anchor),"previous_record_sha256":hex(&[0;32]),"record_sha256":hex(&d)});
        let mut b = serde_json::to_vec_pretty(&v).unwrap();
        b.push(b'\n');
        fs::write(
            p.join("records").join(format!("{PREFIX}{:020}{SUFFIX}", 1)),
            b,
        )
        .unwrap();
    }
    #[test]
    fn fresh_genesis_root_is_create_new_network_bound_and_reopenable() {
        let parent = dir();
        let root = parent.join("fresh-genesis-vault");
        let network = [71; 32];
        let profile = [72; 32];
        let anchor = [73; 32];
        let vault =
            QRunV06LocalAnchorVault::provision_genesis_root(&root, network, profile, anchor)
                .unwrap();
        assert_eq!(vault.tip().sequence, 1);
        assert_eq!(vault.tip().manifest_generation, 0);
        assert_eq!(vault.tip().manifest_anchor, anchor);
        assert_eq!(
            QRunV06LocalAnchorVault::open(&root, network, profile)
                .unwrap()
                .tip(),
            vault.tip()
        );
        assert!(
            QRunV06LocalAnchorVault::provision_genesis_root(&root, network, profile, anchor)
                .is_err()
        );
        assert!(QRunV06LocalAnchorVault::open(&root, [74; 32], profile).is_err());
        assert!(QRunV06LocalAnchorVault::provision_genesis_root(
            parent.join("zero"),
            network,
            profile,
            [0; 32]
        )
        .is_err());
        fs::remove_dir_all(parent).unwrap();
    }

    #[test]
    fn fresh_genesis_root_refuses_partial_existing_directory_without_repair() {
        let parent = dir();
        let root = parent.join("partial-vault");
        fs::create_dir(&root).unwrap();
        assert!(QRunV06LocalAnchorVault::provision_genesis_root(
            &root, [81; 32], [82; 32], [83; 32],
        )
        .is_err());
        assert_eq!(fs::read_dir(&root).unwrap().count(), 0);
        fs::remove_dir_all(parent).unwrap();
    }
    #[test]
    fn checkpoint_witness_recovers_root_publication_and_maps_segment_generations_globally() {
        let p = dir();
        let network = [31; 32];
        let profile = [32; 32];
        let predecessor_anchor = [33; 32];
        provision(&p, network, profile, 1024, predecessor_anchor);
        let mut vault = QRunV06LocalAnchorVault::open(&p, network, profile).unwrap();
        let predecessor = vault.tip();
        let witness = QRunV06CheckpointSegmentWitness {
            sequence: 1,
            predecessor_vault_sequence: predecessor.sequence,
            predecessor_global_generation: predecessor.manifest_generation,
            predecessor_manifest_anchor: predecessor.manifest_anchor,
            predecessor_record_digest: predecessor.record_digest,
            checkpoint_commitment: [34; 32],
            segment_root_manifest_anchor: [35; 32],
            checkpoint_base_height: 1024,
            checkpoint_tip_hash: [36; 32],
            checkpoint_state_root: [37; 32],
            checkpoint_cumulative_work: [38; 32],
            network_id: network,
            profile_id: profile,
            genesis_descriptor_commitment: [39; 32],
            consensus_fingerprint: [40; 32],
            previous_witness_digest: [0; 32],
            witness_digest: [0; 32],
        };
        let saved = vault.append_checkpoint_segment_witness(witness).unwrap();
        assert_ne!(saved.witness_digest, [0; 32]);
        assert_eq!(
            vault.tip(),
            predecessor,
            "witness append must precede root publication"
        );

        // Simulate a crash after the durable witness but before the global root anchor append.
        let mut recovered = QRunV06LocalAnchorVault::open(&p, network, profile).unwrap();
        assert_eq!(recovered.latest_checkpoint_segment_witness(), Some(saved));
        let root_tip = recovered.reconcile_checkpoint_segment_root().unwrap();
        assert_eq!(root_tip.manifest_generation, 1025);
        assert_eq!(root_tip.manifest_anchor, [35; 32]);

        // Segment-local generation 1 maps to global generation 1026, not local generation 1.
        let next = recovered.append_segment_successor(1, [41; 32]).unwrap();
        assert_eq!(next.manifest_generation, 1026);
        drop(recovered);

        let reopened = QRunV06LocalAnchorVault::open(&p, network, profile).unwrap();
        assert_eq!(reopened.tip().manifest_generation, 1026);
        assert_eq!(reopened.latest_checkpoint_segment_witness(), Some(saved));
        fs::remove_dir_all(p).unwrap();
    }

    #[test]
    fn checkpoint_witness_tampering_is_rejected_on_every_vault_open() {
        let p = dir();
        let network = [51; 32];
        let profile = [52; 32];
        provision(&p, network, profile, 8, [53; 32]);
        let mut vault = QRunV06LocalAnchorVault::open(&p, network, profile).unwrap();
        let predecessor = vault.tip();
        let witness = QRunV06CheckpointSegmentWitness {
            sequence: 1,
            predecessor_vault_sequence: predecessor.sequence,
            predecessor_global_generation: predecessor.manifest_generation,
            predecessor_manifest_anchor: predecessor.manifest_anchor,
            predecessor_record_digest: predecessor.record_digest,
            checkpoint_commitment: [54; 32],
            segment_root_manifest_anchor: [55; 32],
            checkpoint_base_height: 8,
            checkpoint_tip_hash: [56; 32],
            checkpoint_state_root: [57; 32],
            checkpoint_cumulative_work: [58; 32],
            network_id: network,
            profile_id: profile,
            genesis_descriptor_commitment: [59; 32],
            consensus_fingerprint: [60; 32],
            previous_witness_digest: [0; 32],
            witness_digest: [0; 32],
        };
        vault.append_checkpoint_segment_witness(witness).unwrap();
        let path = p
            .join("checkpoint-segment-witnesses")
            .join(witness_file_name(1));
        let mut value: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        value["checkpoint_base_height"] = serde_json::Value::from(9u64);
        fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        assert!(QRunV06LocalAnchorVault::open(&p, network, profile).is_err());
        fs::remove_dir_all(p).unwrap();
    }

    #[test]
    fn append_is_chained_idempotent_and_reopenable() {
        let p = dir();
        let n = [1; 32];
        let prof = [2; 32];
        let a = [3; 32];
        let b = [4; 32];
        provision(&p, n, prof, 1024, a);
        let mut v = QRunV06LocalAnchorVault::open(&p, n, prof).unwrap();
        let tip = v.append_successor(1025, b).unwrap();
        assert_eq!(tip.sequence, 2);
        assert_eq!(v.append_successor(1025, b).unwrap(), tip);
        assert!(v.append_successor(1027, [5; 32]).is_err());
        assert_eq!(
            QRunV06LocalAnchorVault::open(&p, n, prof).unwrap().tip(),
            tip
        );
        fs::remove_dir_all(p).unwrap();
    }
    #[test]
    fn rejects_network_or_checksum_tampering() {
        let p = dir();
        let n = [11; 32];
        let prof = [12; 32];
        provision(&p, n, prof, 7, [13; 32]);
        assert!(QRunV06LocalAnchorVault::open(&p, [14; 32], prof).is_err());
        let path = p.join("records").join(format!("{PREFIX}{:020}{SUFFIX}", 1));
        let mut v: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        v["record_sha256"] = serde_json::Value::String("ff".repeat(32));
        fs::write(&path, serde_json::to_vec(&v).unwrap()).unwrap();
        assert!(QRunV06LocalAnchorVault::open(&p, n, prof).is_err());
        fs::remove_dir_all(p).unwrap();
    }
    #[test]
    fn startup_catches_up_one_commit_and_rejects_rollback() {
        let p = dir();
        let n = [21; 32];
        let prof = [22; 32];
        provision(&p, n, prof, 4, [23; 32]);
        let mut v = QRunV06LocalAnchorVault::open(&p, n, prof).unwrap();
        assert_eq!(
            v.reconcile_replayed_tip(5, [24; 32])
                .unwrap()
                .manifest_generation,
            5
        );
        assert!(v.reconcile_replayed_tip(4, [23; 32]).is_err());
        fs::remove_dir_all(p).unwrap();
    }
}
