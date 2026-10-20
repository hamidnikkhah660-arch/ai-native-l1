use ai_native_l1_pow_bench::asset_state_adaptive_commitment_candidate::AdaptiveAssetStateCommitment;
use std::{
    collections::BTreeMap,
    fs,
    io::{self, Cursor, Read},
    path::PathBuf,
    sync::{Arc, Mutex},
    thread,
    time::Instant,
};

const NETWORK: [u8; 32] = [0xC7; 32];
const BUCKET: [u8; 2] = [0x5A, 0xA5];
const STATE_SIZE: usize = 10_000;
const REORG_OPS: usize = 256;
const CONCURRENT_WORKERS: usize = 8;
const CONCURRENT_UPDATES_PER_WORKER: usize = 512;

fn synthetic_key(suffix: u64) -> [u8; 32] {
    let mut key = [0u8; 32];
    key[..2].copy_from_slice(&BUCKET);
    key[24..].copy_from_slice(&suffix.to_be_bytes());
    key
}

fn leaves(size: usize) -> Vec<([u8; 32], Vec<u8>)> {
    (0..size)
        .map(|suffix| (synthetic_key(suffix as u64), vec![0x01; 32]))
        .collect()
}

fn hex(bytes: &[u8; 32]) -> String {
    let mut out = String::with_capacity(64);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut out, "{byte:02x}");
    }
    out
}

fn persist_leaves(path: &PathBuf, leaves: &[([u8; 32], Vec<u8>)]) -> io::Result<usize> {
    let mut bytes = Vec::with_capacity(8 + leaves.len() * 68);
    bytes.extend_from_slice(b"ASADP1\0");
    bytes.extend_from_slice(&(leaves.len() as u32).to_be_bytes());
    for (key, value) in leaves {
        bytes.extend_from_slice(key);
        bytes.extend_from_slice(&(value.len() as u32).to_be_bytes());
        bytes.extend_from_slice(value);
    }
    fs::write(path, &bytes)?;
    Ok(bytes.len())
}

fn read_leaves(path: &PathBuf) -> io::Result<Vec<([u8; 32], Vec<u8>)>> {
    let bytes = fs::read(path)?;
    if bytes.len() < 11 || &bytes[..7] != b"ASADP1\0" {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "bad magic"));
    }

    let mut cursor = Cursor::new(&bytes[7..]);
    let count = read_u32(&mut cursor)? as usize;
    let mut out = Vec::with_capacity(count);

    for _ in 0..count {
        let mut key = [0u8; 32];
        cursor.read_exact(&mut key)?;
        let value_len = read_u32(&mut cursor)? as usize;
        if value_len == 0 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "empty value"));
        }
        let mut value = vec![0u8; value_len];
        cursor.read_exact(&mut value)?;
        out.push((key, value));
    }

    if cursor.position() as usize != bytes.len() - 7 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "trailing bytes"));
    }
    Ok(out)
}

fn read_u32(cursor: &mut Cursor<&[u8]>) -> io::Result<u32> {
    let mut buf = [0u8; 4];
    cursor.read_exact(&mut buf)?;
    Ok(u32::from_be_bytes(buf))
}

fn restore_child(path: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    let leaves = read_leaves(path)?;
    let start = Instant::now();
    let commitment = AdaptiveAssetStateCommitment::new(NETWORK, 100)?;
    let mut commitment = commitment;
    commitment.rebuild_from_raw_leaves(&leaves)?;
    println!(
        "RESTORED_ROOT={} RESTORE_LEAVES={} RESTORE_MS={:.3}",
        hex(&commitment.root()),
        leaves.len(),
        start.elapsed().as_secs_f64() * 1000.0
    );
    Ok(())
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let base_leaves = leaves(STATE_SIZE);
    let mut base = AdaptiveAssetStateCommitment::new(NETWORK, 100)?;
    base.rebuild_from_raw_leaves(&base_leaves)?;
    let base_root = base.root();

    let path = std::env::temp_dir().join(format!(
        "ain1-adaptive-resilience-{}-{}.bin",
        std::process::id(),
        base_root[..8]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    ));

    let persist_start = Instant::now();
    let persisted_bytes = persist_leaves(&path, &base_leaves)?;
    let persist_ms = persist_start.elapsed().as_secs_f64() * 1000.0;

    let exe = std::env::current_exe()?;
    let restore = std::process::Command::new(exe)
        .arg("--restore")
        .arg(&path)
        .output()?;
    if !restore.status.success() {
        return Err(format!(
            "restore child failed: status={} stderr={}",
            restore.status,
            String::from_utf8_lossy(&restore.stderr)
        )
        .into());
    }
    let restore_stdout = String::from_utf8(restore.stdout)?;
    let expected_marker = format!("RESTORED_ROOT={}", hex(&base_root));
    if !restore_stdout.contains(&expected_marker) {
        return Err(format!(
            "restore root mismatch: expected={} output={}",
            expected_marker, restore_stdout
        )
        .into());
    }

    let persisted = read_leaves(&path)?;
    let read_bytes = fs::metadata(&path)?.len() as usize;
    if persisted != base_leaves || read_bytes != persisted_bytes {
        return Err("persisted leaf state did not round-trip byte-for-byte".into());
    }

    let mut reorg = base.clone();
    let mut final_map: BTreeMap<[u8; 32], Vec<u8>> = base_leaves.iter().cloned().collect();
    let mut journal = Vec::with_capacity(REORG_OPS);

    for index in 0..REORG_OPS {
        let key = synthetic_key((STATE_SIZE - REORG_OPS + index) as u64);
        let old = final_map.get(&key).cloned().ok_or("reorg target missing")?;
        if index % 2 == 0 {
            let new_value = vec![0x20 + (index % 31) as u8; 32];
            reorg.set_raw_leaf_value(key, Some(&new_value))?;
            final_map.insert(key, new_value.clone());
            journal.push((key, Some(old), Some(new_value)));
        } else {
            reorg.set_raw_leaf_value(key, None)?;
            final_map.remove(&key);
            journal.push((key, Some(old), None));
        }
    }

    let final_leaves: Vec<_> = final_map
        .iter()
        .map(|(key, value)| (*key, value.clone()))
        .collect();
    let mut final_rebuild = AdaptiveAssetStateCommitment::new(NETWORK, 100)?;
    final_rebuild.rebuild_from_raw_leaves(&final_leaves)?;
    if reorg.root() != final_rebuild.root() {
        return Err("reorg forward root mismatch".into());
    }

    for (key, old, new) in journal.iter().rev() {
        match new {
            Some(_) => {
                reorg.set_raw_leaf_value(*key, old.as_deref())?;
            }
            None => {
                reorg.set_raw_leaf_value(*key, old.as_deref())?;
            }
        }
    }
    if reorg.root() != base_root {
        return Err("reorg rollback root mismatch".into());
    }

    let concurrent = Arc::new(Mutex::new(base.clone()));
    let mut handles = Vec::with_capacity(CONCURRENT_WORKERS);
    let concurrent_start = Instant::now();

    for worker in 0..CONCURRENT_WORKERS {
        let commitment = Arc::clone(&concurrent);
        handles.push(thread::spawn(move || -> Result<(), String> {
            for round in 0..CONCURRENT_UPDATES_PER_WORKER {
                let slot = worker * CONCURRENT_UPDATES_PER_WORKER + round;
                let key = synthetic_key(slot as u64);
                let value = [0x40 + (worker % 16) as u8; 32];
                let mut guard = commitment
                    .lock()
                    .map_err(|_| "mutex poisoned".to_string())?;
                guard
                    .set_raw_leaf_value(key, Some(&value))
                    .map_err(|error| error.to_string())?;
            }
            Ok(())
        }));
    }

    for handle in handles {
        handle.join().map_err(|_| "concurrent worker panicked")??;
    }
    let concurrent_ms = concurrent_start.elapsed().as_secs_f64() * 1000.0;

    let mut concurrent_map: BTreeMap<[u8; 32], Vec<u8>> = base_leaves.iter().cloned().collect();
    for worker in 0..CONCURRENT_WORKERS {
        for round in 0..CONCURRENT_UPDATES_PER_WORKER {
            let slot = worker * CONCURRENT_UPDATES_PER_WORKER + round;
            concurrent_map.insert(
                synthetic_key(slot as u64),
                vec![0x40 + (worker % 16) as u8; 32],
            );
        }
    }
    let concurrent_leaves: Vec<_> = concurrent_map
        .iter()
        .map(|(key, value)| (*key, value.clone()))
        .collect();
    let mut concurrent_rebuild = AdaptiveAssetStateCommitment::new(NETWORK, 100)?;
    concurrent_rebuild.rebuild_from_raw_leaves(&concurrent_leaves)?;
    let concurrent_root = concurrent.lock().map_err(|_| "mutex poisoned")?.root();
    if concurrent_root != concurrent_rebuild.root() {
        return Err("concurrent ingress root mismatch".into());
    }

    let total_concurrent_ops = (CONCURRENT_WORKERS * CONCURRENT_UPDATES_PER_WORKER) as f64;
    let ops_per_sec = total_concurrent_ops / (concurrent_ms / 1000.0);

    println!("CPW_ASSET_STATE_ADAPTIVE_RESILIENCE_BENCH_V1");
    println!(
        "PERSIST_RESTART STATE_SIZE={} PERSIST_BYTES={} PERSIST_MS={:.3} RESTORE_CHILD_EXIT=0 ROOT_MATCH=true",
        STATE_SIZE, persisted_bytes, persist_ms
    );
    println!(
        "REORG_ROLLBACK OPS={} FORWARD_ROOT_MATCH=true ROLLBACK_ROOT_MATCH=true",
        REORG_OPS
    );
    println!(
        "CONCURRENT_INGRESS WORKERS={} UPDATES_PER_WORKER={} TOTAL_OPS={} ELAPSED_MS={:.3} OPS_PER_SEC={:.1} ROOT_MATCH=true",
        CONCURRENT_WORKERS,
        CONCURRENT_UPDATES_PER_WORKER,
        total_concurrent_ops as usize,
        concurrent_ms,
        ops_per_sec
    );

    let _ = fs::remove_file(&path);
    Ok(())
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some("--restore") {
        let path = args.get(2).map(PathBuf::from).ok_or("missing restore path");
        match path {
            Ok(path) => {
                if let Err(error) = restore_child(&path) {
                    eprintln!("RESTORE_FAILED ERROR={error}");
                    std::process::exit(1);
                }
            }
            Err(error) => {
                eprintln!("RESTORE_FAILED ERROR={error}");
                std::process::exit(2);
            }
        }
        return;
    }

    if let Err(error) = run() {
        eprintln!("RESILIENCE_BENCHMARK_FAILED ERROR={error}");
        std::process::exit(1);
    }
}
