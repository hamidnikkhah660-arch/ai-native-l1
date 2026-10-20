use ai_native_l1_pow_bench::asset_state_adaptive_commitment_candidate::AdaptiveAssetStateCommitment;
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
    process::{self, Command},
};

const NETWORK: [u8; 32] = [0xC7; 32];
const MAGIC: &[u8; 7] = b"ASADP2\0";
const LEAF_COUNT: usize = 128;
const VALUE_LEN: usize = 32;

type Hash = [u8; 32];
type Leaf = (Hash, Vec<u8>);

#[derive(Clone, Copy)]
struct CrashStage {
    label: &'static str,
    code: i32,
    replace_expected: bool,
}

const STAGES: [CrashStage; 5] = [
    CrashStage {
        label: "after-temp-create",
        code: 71,
        replace_expected: false,
    },
    CrashStage {
        label: "after-partial-write",
        code: 72,
        replace_expected: false,
    },
    CrashStage {
        label: "after-full-write",
        code: 73,
        replace_expected: false,
    },
    CrashStage {
        label: "after-file-sync",
        code: 74,
        replace_expected: false,
    },
    CrashStage {
        label: "after-atomic-replace",
        code: 75,
        replace_expected: true,
    },
];

fn leaves(version: u8) -> Vec<Leaf> {
    (0..LEAF_COUNT)
        .map(|suffix| {
            let mut key = [0u8; 32];
            key[..2].copy_from_slice(&[0x5A, 0xA5]);
            key[24..].copy_from_slice(&(suffix as u64).to_be_bytes());
            (key, vec![version; VALUE_LEN])
        })
        .collect()
}

fn root_for(leaves: &[Leaf]) -> Result<Hash, Box<dyn std::error::Error>> {
    let mut commitment = AdaptiveAssetStateCommitment::new(NETWORK, 100)?;
    commitment.rebuild_from_raw_leaves(leaves)?;
    Ok(commitment.root())
}

fn encode_snapshot(leaves: &[Leaf]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut sorted = leaves.to_vec();
    sorted.sort_by_key(|(key, _)| *key);
    for (index, (key, value)) in sorted.iter().enumerate() {
        if key.iter().all(|byte| *byte == 0) || value.is_empty() {
            return Err("invalid test leaf".into());
        }
        if index > 0 && sorted[index - 1].0 >= *key {
            return Err("duplicate or unordered test leaf".into());
        }
    }

    let root = root_for(&sorted)?;
    let mut bytes = Vec::with_capacity(7 + 32 + 32 + 4 + sorted.len() * (32 + 4 + VALUE_LEN));
    bytes.extend_from_slice(MAGIC);
    bytes.extend_from_slice(&NETWORK);
    bytes.extend_from_slice(&root);
    bytes.extend_from_slice(&(sorted.len() as u32).to_be_bytes());
    for (key, value) in &sorted {
        bytes.extend_from_slice(key);
        bytes.extend_from_slice(&(value.len() as u32).to_be_bytes());
        bytes.extend_from_slice(value);
    }
    Ok(bytes)
}

fn take<'a>(bytes: &'a [u8], position: &mut usize, count: usize) -> io::Result<&'a [u8]> {
    let end = position
        .checked_add(count)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "length overflow"))?;
    if end > bytes.len() {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "truncated candidate snapshot",
        ));
    }
    let value = &bytes[*position..end];
    *position = end;
    Ok(value)
}

fn read_u32(bytes: &[u8], position: &mut usize) -> io::Result<u32> {
    Ok(u32::from_be_bytes(
        take(bytes, position, 4)?.try_into().unwrap(),
    ))
}

fn decode_snapshot(bytes: &[u8]) -> Result<(Vec<Leaf>, Hash), Box<dyn std::error::Error>> {
    if bytes.len() < 7 + 32 + 32 + 4 || &bytes[..7] != MAGIC {
        return Err("bad candidate snapshot magic/length".into());
    }
    let mut position = 7usize;
    let network: Hash = take(bytes, &mut position, 32)?.try_into().unwrap();
    if network != NETWORK {
        return Err("candidate snapshot network mismatch".into());
    }
    let stored_root: Hash = take(bytes, &mut position, 32)?.try_into().unwrap();
    let count = read_u32(bytes, &mut position)? as usize;
    if count > LEAF_COUNT * 4 {
        return Err("candidate snapshot leaf count out of bounds".into());
    }

    let mut result = Vec::with_capacity(count);
    for _ in 0..count {
        let key: Hash = take(bytes, &mut position, 32)?.try_into().unwrap();
        let value_len = read_u32(bytes, &mut position)? as usize;
        if value_len == 0 || value_len > 1_048_576 {
            return Err("candidate snapshot value length out of bounds".into());
        }
        let value = take(bytes, &mut position, value_len)?.to_vec();
        if key.iter().all(|byte| *byte == 0) {
            return Err("candidate snapshot contains zero key".into());
        }
        if result
            .last()
            .is_some_and(|(prior, _): &(Hash, Vec<u8>)| *prior >= key)
        {
            return Err("candidate snapshot key ordering invalid".into());
        }
        result.push((key, value));
    }
    if position != bytes.len() {
        return Err("candidate snapshot has trailing bytes".into());
    }

    let rebuilt_root = root_for(&result)?;
    if rebuilt_root != stored_root {
        return Err("candidate snapshot commitment root mismatch".into());
    }
    Ok((result, rebuilt_root))
}

fn load_snapshot(path: &Path) -> Result<(Vec<Leaf>, Hash), Box<dyn std::error::Error>> {
    let mut file = File::open(path)?;
    let length = file.metadata()?.len();
    if length > 8 * 1024 * 1024 {
        return Err("candidate snapshot oversize".into());
    }
    let mut bytes = Vec::with_capacity(length as usize);
    file.read_to_end(&mut bytes)?;
    decode_snapshot(&bytes)
}

#[cfg(windows)]
fn atomic_replace(source: &Path, destination: &Path) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;

    const MOVEFILE_REPLACE_EXISTING: u32 = 0x1;
    const MOVEFILE_WRITE_THROUGH: u32 = 0x8;
    let source_wide: Vec<u16> = source
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let destination_wide: Vec<u16> = destination
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    #[link(name = "Kernel32")]
    extern "system" {
        fn MoveFileExW(existing: *const u16, new_name: *const u16, flags: u32) -> i32;
    }
    let success = unsafe {
        MoveFileExW(
            source_wide.as_ptr(),
            destination_wide.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if success == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(not(windows))]
fn atomic_replace(source: &Path, destination: &Path) -> io::Result<()> {
    fs::rename(source, destination)?;
    #[cfg(unix)]
    File::open(destination.parent().unwrap_or_else(|| Path::new(".")))?.sync_all()?;
    Ok(())
}

fn complete_atomic_write(final_path: &Path, temp_path: &Path, bytes: &[u8]) -> io::Result<()> {
    let _ = fs::remove_file(temp_path);
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(temp_path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    atomic_replace(temp_path, final_path)
}

fn crash_child(
    stage: &str,
    final_path: &Path,
    temp_path: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let new_bytes = encode_snapshot(&leaves(0x22))?;
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(temp_path)?;

    if stage == "after-temp-create" {
        process::exit(71);
    }

    let midpoint = (new_bytes.len() / 2).max(1);
    file.write_all(&new_bytes[..midpoint])?;
    file.flush()?;
    if stage == "after-partial-write" {
        process::exit(72);
    }

    file.write_all(&new_bytes[midpoint..])?;
    file.flush()?;
    if stage == "after-full-write" {
        process::exit(73);
    }

    file.sync_all()?;
    if stage == "after-file-sync" {
        process::exit(74);
    }

    drop(file);
    atomic_replace(temp_path, final_path)?;
    if stage == "after-atomic-replace" {
        process::exit(75);
    }
    Err(format!("unknown crash stage: {stage}").into())
}

fn hex(hash: &Hash) -> String {
    let mut out = String::with_capacity(64);
    for byte in hash {
        use std::fmt::Write as _;
        let _ = write!(&mut out, "{byte:02x}");
    }
    out
}

fn remove_if_exists(path: &Path) {
    let _ = fs::remove_file(path);
}

fn run_parent() -> Result<(), Box<dyn std::error::Error>> {
    let old_leaves = leaves(0x11);
    let new_leaves = leaves(0x22);
    let old_bytes = encode_snapshot(&old_leaves)?;
    let new_bytes = encode_snapshot(&new_leaves)?;
    let old_root = root_for(&old_leaves)?;
    let new_root = root_for(&new_leaves)?;
    if old_root == new_root {
        return Err("crash harness setup roots unexpectedly equal".into());
    }

    let dir = std::env::temp_dir();
    let final_path = dir.join(format!("ain1-adaptive-crash-{}.asdp", process::id()));
    let executable = std::env::current_exe()?;
    println!("CPW_ASSET_ADAPTIVE_PERSISTENCE_CHAOS_V1");
    println!(
        "BASE_ROOT={} NEW_ROOT={} SNAPSHOT_BYTES={}",
        hex(&old_root),
        hex(&new_root),
        old_bytes.len()
    );

    for stage in STAGES {
        let temp_path = dir.join(format!(
            "ain1-adaptive-crash-{}-{}.tmp",
            process::id(),
            stage.label
        ));
        remove_if_exists(&final_path);
        remove_if_exists(&temp_path);
        complete_atomic_write(&final_path, &temp_path, &old_bytes)?;

        let output = Command::new(&executable)
            .arg("--child-crash")
            .arg(stage.label)
            .arg(&final_path)
            .arg(&temp_path)
            .output()?;
        let code = output.status.code().unwrap_or(-1);
        if code != stage.code {
            return Err(format!(
                "{}: expected child exit {}, got {}; stderr={}",
                stage.label,
                stage.code,
                code,
                String::from_utf8_lossy(&output.stderr)
            )
            .into());
        }

        let (restored_leaves, restored_root) = load_snapshot(&final_path)?;
        let expected_root = if stage.replace_expected {
            new_root
        } else {
            old_root
        };
        if restored_root != expected_root {
            return Err(format!("{}: final snapshot root mismatch", stage.label).into());
        }
        if stage.replace_expected {
            if restored_leaves != new_leaves
                || temp_path.exists()
                || fs::read(&final_path)? != new_bytes
            {
                return Err("post-replace state was not a complete new snapshot".into());
            }
        } else {
            if restored_leaves != old_leaves || !temp_path.exists() {
                return Err(
                    format!("{}: old snapshot/temp expectation failed", stage.label).into(),
                );
            }
            let temp_bytes = fs::read(&temp_path)?;
            if stage.label == "after-temp-create" && !temp_bytes.is_empty() {
                return Err("new temp should be empty at creation crash".into());
            }
            if stage.label == "after-partial-write"
                && (temp_bytes.is_empty() || temp_bytes.len() >= new_bytes.len())
            {
                return Err("partial-write crash did not leave a partial temp".into());
            }
            if (stage.label == "after-full-write" || stage.label == "after-file-sync")
                && temp_bytes != new_bytes
            {
                return Err("fully written temp did not match candidate snapshot".into());
            }
            remove_if_exists(&temp_path);
            let (_, root_after_cleanup) = load_snapshot(&final_path)?;
            if root_after_cleanup != old_root {
                return Err("orphan-temp cleanup altered final snapshot".into());
            }
        }
        println!("CRASH_STAGE={} CHILD_EXIT={} FINAL_ROOT_MATCH={} FINAL_IS_ATOMIC={} TEMP_EXPECTATION=PASS",
            stage.label, code, restored_root == expected_root, true);
    }

    let corruption_base = encode_snapshot(&old_leaves)?;
    let corruption_path = dir.join(format!("ain1-adaptive-corrupt-{}.asdp", process::id()));
    let cuts = [
        0usize,
        6,
        7 + 32 + 32 + 4 - 1,
        corruption_base.len() / 2,
        corruption_base.len() - 1,
    ];
    for (index, cut) in cuts.into_iter().enumerate() {
        fs::write(&corruption_path, &corruption_base[..cut])?;
        if load_snapshot(&corruption_path).is_ok() {
            return Err(format!("truncation corpus case {} unexpectedly loaded", index).into());
        }
    }
    let mut bad_root = corruption_base.clone();
    bad_root[7 + 32] ^= 0x80;
    fs::write(&corruption_path, &bad_root)?;
    if load_snapshot(&corruption_path).is_ok() {
        return Err("root-tampered snapshot unexpectedly loaded".into());
    }
    remove_if_exists(&corruption_path);
    remove_if_exists(&final_path);

    println!("TRUNCATION_CASES=5 ROOT_TAMPER_REJECTED=true");
    println!("CRASH_STAGES={} RESULT=PASS", STAGES.len());
    Ok(())
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some("--child-crash") {
        if args.len() != 5 {
            eprintln!("CHILD_ARGUMENT_ERROR");
            process::exit(2);
        }
        let stage = &args[2];
        let final_path = PathBuf::from(&args[3]);
        let temp_path = PathBuf::from(&args[4]);
        if let Err(error) = crash_child(stage, &final_path, &temp_path) {
            eprintln!("CHILD_CRASH_FAILED ERROR={error}");
            process::exit(3);
        }
        process::exit(4);
    }

    if let Err(error) = run_parent() {
        eprintln!("ADAPTIVE_PERSISTENCE_CHAOS_FAILED ERROR={error}");
        process::exit(1);
    }
}
