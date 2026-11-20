//! Offline validator for the QFP6 candidate package's canonical Q6GD/Q6CP pair.
//! Hash pins must be supplied independently; this tool never creates signatures or authorizes Mainnet.
use ai_native_l1_pow_bench::{
    qrun_v06_consensus_profile_candidate::QRunV06ConsensusProfile,
    qrun_v06_genesis_descriptor_candidate::QRunV06GenesisDescriptor,
};
use sha2::{Digest, Sha256};
use std::{env, fs, path::PathBuf, process::ExitCode};

fn read_arg(args: &[String], name: &str) -> Result<String, String> {
    let i = args
        .iter()
        .position(|arg| arg == name)
        .ok_or_else(|| format!("missing {name}"))?;
    args.get(i + 1)
        .cloned()
        .filter(|v| !v.starts_with("--"))
        .ok_or_else(|| format!("missing value for {name}"))
}
fn parse_hash(name: &str, value: &str) -> Result<[u8; 32], String> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err(format!(
            "{name} must be 64 lowercase hexadecimal characters"
        ));
    }
    let mut out = [0u8; 32];
    for (i, slot) in out.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&value[i * 2..i * 2 + 2], 16)
            .map_err(|_| format!("invalid {name}"))?;
    }
    if out == [0; 32] {
        return Err(format!("{name} must not be zero"));
    }
    Ok(out)
}
fn load_pinned(path: &PathBuf, expected: &[u8; 32], label: &str) -> Result<Vec<u8>, String> {
    let meta = fs::symlink_metadata(path).map_err(|e| format!("cannot inspect {label}: {e}"))?;
    if !meta.file_type().is_file() || meta.len() == 0 || meta.len() > 64 * 1024 * 1024 {
        return Err(format!(
            "{label} must be a nonempty regular file no larger than 64 MiB"
        ));
    }
    let bytes = fs::read(path).map_err(|e| format!("cannot read {label}: {e}"))?;
    let actual: [u8; 32] = Sha256::digest(&bytes).into();
    if &actual != expected {
        return Err(format!(
            "{label} SHA-256 does not match the independently supplied pin"
        ));
    }
    Ok(bytes)
}
fn run() -> Result<(), String> {
    let args: Vec<String> = env::args().skip(1).collect();
    let gd_path = PathBuf::from(read_arg(&args, "--q6gd")?);
    let cp_path = PathBuf::from(read_arg(&args, "--q6cp")?);
    let gd_pin = parse_hash("--q6gd-sha256", &read_arg(&args, "--q6gd-sha256")?)?;
    let cp_pin = parse_hash("--q6cp-sha256", &read_arg(&args, "--q6cp-sha256")?)?;
    let gd_bytes = load_pinned(&gd_path, &gd_pin, "Q6GD")?;
    let cp_bytes = load_pinned(&cp_path, &cp_pin, "Q6CP")?;
    let descriptor = QRunV06GenesisDescriptor::decode(&gd_bytes)
        .map_err(|e| format!("Q6GD decode failed: {e}"))?;
    let profile = QRunV06ConsensusProfile::decode(&cp_bytes)
        .map_err(|e| format!("Q6CP decode failed: {e}"))?;
    profile
        .validate_against(&descriptor)
        .map_err(|e| format!("Q6CP/Q6GD binding failed: {e}"))?;
    println!("q6gd_sha256={}", hex(&gd_pin));
    println!("q6cp_sha256={}", hex(&cp_pin));
    println!(
        "genesis_descriptor_commitment={}",
        hex(&descriptor.commitment())
    );
    println!(
        "consensus_fingerprint={}",
        hex(&profile.consensus_fingerprint())
    );
    println!("q6gd_q6cp_binding=VALID");
    println!("qualification=CANDIDATE_ONLY_NOT_MAINNET_APPROVED");
    println!("mainnet_authorized=false");
    Ok(())
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("INVALID: {error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_only_nonzero_lowercase_sha256_pins() {
        assert!(parse_hash("pin", &"ab".repeat(32)).is_ok());
        assert!(parse_hash("pin", &"AB".repeat(32)).is_err());
        assert!(parse_hash("pin", &"00".repeat(32)).is_err());
        assert!(parse_hash("pin", "abcd").is_err());
    }

    #[test]
    fn requires_every_explicit_artifact_argument() {
        assert!(read_arg(&[], "--q6gd").is_err());
        assert!(read_arg(&["--q6gd".into()], "--q6gd").is_err());
        assert_eq!(
            read_arg(&["--q6gd".into(), "genesis.q6gd".into()], "--q6gd").unwrap(),
            "genesis.q6gd"
        );
    }
}
