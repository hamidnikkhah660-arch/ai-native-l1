//! Windows-local native QZXB wallet for Ed25519 TXN2 transactions.
//!
//! The QZKW1 file contains a CurrentUser-DPAPI protected 32-byte seed and public identifiers.
//! It never accepts secret material on the command line or emits the seed. DPAPI is local desktop
//! custody, not an HSM or a portable backup format; this binary does not submit transactions.
#[cfg(windows)]
mod windows_wallet {
    use ai_native_l1_pow_bench::{
        state_machine::{encode_transaction, transaction_signing_digest, Transaction},
        transaction_auth::Ed25519TransactionSigner,
    };
    use std::{
        env,
        ffi::c_void,
        fs::{self, File, OpenOptions},
        io::{self, Read, Write},
        path::{Path, PathBuf},
        process, ptr,
        sync::atomic::{AtomicU64, Ordering},
    };

    const MAGIC: &[u8; 4] = b"QZKW";
    const VERSION: u16 = 1;
    const HEADER_LEN: usize = 4 + 2 + 32 + 32 + 4;
    const MAX_PROTECTED_BLOB: usize = 64 * 1024;
    const MAX_FILE_LEN: usize = HEADER_LEN + MAX_PROTECTED_BLOB;
    const WALLET_DOMAIN: &[u8] = b"QUANTUMZXB-ED25519-WALLET-DPAPI-V1\0";
    const CRYPTPROTECT_UI_FORBIDDEN: u32 = 0x1;
    static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(1);

    struct SecretSeed([u8; 32]);

    impl Drop for SecretSeed {
        fn drop(&mut self) {
            self.0.fill(0);
        }
    }

    enum Command {
        Create {
            output: PathBuf,
        },
        Address {
            wallet: PathBuf,
        },
        SignTransfer {
            wallet: PathBuf,
            network_id: [u8; 32],
            recipient: [u8; 32],
            nonce: u64,
            amount: u64,
            fee: u64,
            expires_at: u64,
        },
        Help,
    }

    fn parse_hex32(value: &str, label: &str) -> Result<[u8; 32], String> {
        if value.len() != 64 || !value.is_ascii() {
            return Err(format!(
                "{label} must be exactly 64 ASCII hexadecimal characters"
            ));
        }
        let mut bytes = [0u8; 32];
        for (index, byte) in bytes.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
                .map_err(|_| format!("{label} contains a non-hexadecimal character"))?;
        }
        Ok(bytes)
    }

    fn hex(bytes: &[u8]) -> String {
        const DIGITS: &[u8; 16] = b"0123456789abcdef";
        let mut output = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            output.push(DIGITS[(byte >> 4) as usize] as char);
            output.push(DIGITS[(byte & 15) as usize] as char);
        }
        output
    }

    fn options(
        tokens: &[String],
        allowed: &[&str],
    ) -> Result<std::collections::BTreeMap<String, String>, String> {
        let mut values = std::collections::BTreeMap::new();
        let mut index = 0usize;
        while index < tokens.len() {
            let key = tokens[index].as_str();
            if !allowed.contains(&key) {
                if matches!(
                    key,
                    "--private-key-hex" | "--seed" | "--seed-hex" | "--seed-file"
                ) {
                    return Err(
                        "secret-key input is not accepted; wallet keys are generated locally"
                            .into(),
                    );
                }
                return Err(format!("unknown option: {key}"));
            }
            let value = tokens
                .get(index + 1)
                .ok_or_else(|| format!("missing value for {key}"))?;
            if value.starts_with("--") {
                return Err(format!("missing value for {key}"));
            }
            if values.insert(key.to_string(), value.clone()).is_some() {
                return Err(format!("duplicate option: {key}"));
            }
            index += 2;
        }
        Ok(values)
    }

    fn required<'a>(
        values: &'a std::collections::BTreeMap<String, String>,
        name: &str,
    ) -> Result<&'a str, String> {
        values
            .get(name)
            .map(String::as_str)
            .ok_or_else(|| format!("required option missing: {name}"))
    }

    fn parse_command() -> Result<Command, String> {
        let args = env::args().skip(1).collect::<Vec<_>>();
        let Some(subcommand) = args.first().map(String::as_str) else {
            return Ok(Command::Help);
        };
        if matches!(subcommand, "--help" | "-h" | "help") {
            return Ok(Command::Help);
        }
        match subcommand {
            "create" => {
                let values = options(&args[1..], &["--output"])?;
                let output = PathBuf::from(required(&values, "--output")?);
                if !output.is_absolute() || output.file_name().is_none() {
                    return Err("--output must be an absolute file path".into());
                }
                Ok(Command::Create { output })
            }
            "address" => {
                let values = options(&args[1..], &["--wallet"])?;
                let wallet = PathBuf::from(required(&values, "--wallet")?);
                if !wallet.is_absolute() {
                    return Err("--wallet must be an absolute file path".into());
                }
                Ok(Command::Address { wallet })
            }
            "sign-transfer" => {
                let values = options(
                    &args[1..],
                    &[
                        "--wallet",
                        "--network-id-hex",
                        "--recipient-id-hex",
                        "--nonce",
                        "--amount-atoms",
                        "--fee-atoms",
                        "--expires-at",
                    ],
                )?;
                let wallet = PathBuf::from(required(&values, "--wallet")?);
                if !wallet.is_absolute() {
                    return Err("--wallet must be an absolute file path".into());
                }
                let network_id = parse_hex32(required(&values, "--network-id-hex")?, "network ID")?;
                let recipient = parse_hex32(required(&values, "--recipient-id-hex")?, "recipient")?;
                let nonce = required(&values, "--nonce")?
                    .parse::<u64>()
                    .map_err(|_| "nonce must be an unsigned 64-bit integer".to_string())?;
                let amount = required(&values, "--amount-atoms")?
                    .parse::<u64>()
                    .map_err(|_| {
                        "amount must be an unsigned 64-bit integer in atoms".to_string()
                    })?;
                let fee = required(&values, "--fee-atoms")?
                    .parse::<u64>()
                    .map_err(|_| "fee must be an unsigned 64-bit integer in atoms".to_string())?;
                let expires_at = required(&values, "--expires-at")?
                    .parse::<u64>()
                    .map_err(|_| "expiry must be an unsigned 64-bit timestamp".to_string())?;
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_err(|_| "system clock is before the Unix epoch".to_string())?
                    .as_secs();
                if network_id.iter().all(|byte| *byte == 0)
                    || recipient.iter().all(|byte| *byte == 0)
                    || nonce == 0
                    || amount == 0
                    || expires_at <= now
                {
                    return Err("network, recipient, nonce and amount must be nonzero; expiry must be in the future".into());
                }
                Ok(Command::SignTransfer {
                    wallet,
                    network_id,
                    recipient,
                    nonce,
                    amount,
                    fee,
                    expires_at,
                })
            }
            _ => Err(format!("unknown subcommand: {subcommand}")),
        }
    }

    fn entropy(public_key: &[u8; 32], account_id: &[u8; 32]) -> Vec<u8> {
        let mut value = Vec::with_capacity(WALLET_DOMAIN.len() + 64);
        value.extend_from_slice(WALLET_DOMAIN);
        value.extend_from_slice(public_key);
        value.extend_from_slice(account_id);
        value
    }

    #[repr(C)]
    struct DataBlob {
        cb_data: u32,
        pb_data: *mut u8,
    }

    #[link(name = "Crypt32")]
    extern "system" {
        fn CryptProtectData(
            input: *const DataBlob,
            description: *const u16,
            optional_entropy: *const DataBlob,
            reserved: *mut c_void,
            prompt: *mut c_void,
            flags: u32,
            output: *mut DataBlob,
        ) -> i32;
        fn CryptUnprotectData(
            input: *const DataBlob,
            description: *mut *mut u16,
            optional_entropy: *const DataBlob,
            reserved: *mut c_void,
            prompt: *mut c_void,
            flags: u32,
            output: *mut DataBlob,
        ) -> i32;
    }

    #[link(name = "Kernel32")]
    extern "system" {
        fn LocalFree(memory: *mut c_void) -> *mut c_void;
        fn GetLastError() -> u32;
    }

    fn dpapi_protect(
        seed: &[u8; 32],
        public_key: &[u8; 32],
        account_id: &[u8; 32],
    ) -> Result<Vec<u8>, String> {
        let entropy_bytes = entropy(public_key, account_id);
        let input = DataBlob {
            cb_data: seed.len() as u32,
            pb_data: seed.as_ptr() as *mut u8,
        };
        let optional_entropy = DataBlob {
            cb_data: entropy_bytes.len() as u32,
            pb_data: entropy_bytes.as_ptr() as *mut u8,
        };
        let mut output = DataBlob {
            cb_data: 0,
            pb_data: ptr::null_mut(),
        };
        let ok = unsafe {
            CryptProtectData(
                &input,
                ptr::null(),
                &optional_entropy,
                ptr::null_mut(),
                ptr::null_mut(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output,
            )
        };
        if ok == 0 {
            return Err(format!(
                "Windows CurrentUser DPAPI protection failed (Win32 error {})",
                unsafe { GetLastError() }
            ));
        }
        if output.pb_data.is_null()
            || output.cb_data == 0
            || output.cb_data as usize > MAX_PROTECTED_BLOB
        {
            if !output.pb_data.is_null() {
                unsafe {
                    LocalFree(output.pb_data as *mut c_void);
                }
            }
            return Err("DPAPI returned an invalid protected wallet blob".into());
        }
        let protected =
            unsafe { std::slice::from_raw_parts(output.pb_data, output.cb_data as usize).to_vec() };
        unsafe {
            LocalFree(output.pb_data as *mut c_void);
        }
        Ok(protected)
    }

    fn dpapi_unprotect(
        blob: &[u8],
        public_key: &[u8; 32],
        account_id: &[u8; 32],
    ) -> Result<Vec<u8>, String> {
        if blob.len() > u32::MAX as usize {
            return Err("protected wallet blob is too large".into());
        }
        let entropy_bytes = entropy(public_key, account_id);
        let input = DataBlob {
            cb_data: blob.len() as u32,
            pb_data: blob.as_ptr() as *mut u8,
        };
        let optional_entropy = DataBlob {
            cb_data: entropy_bytes.len() as u32,
            pb_data: entropy_bytes.as_ptr() as *mut u8,
        };
        let mut output = DataBlob {
            cb_data: 0,
            pb_data: ptr::null_mut(),
        };
        let ok = unsafe {
            CryptUnprotectData(
                &input,
                ptr::null_mut(),
                &optional_entropy,
                ptr::null_mut(),
                ptr::null_mut(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output,
            )
        };
        if ok == 0 {
            return Err(format!(
                "wallet could not be unprotected for the current Windows user (Win32 error {})",
                unsafe { GetLastError() }
            ));
        }
        if output.pb_data.is_null() || output.cb_data != 32 {
            if !output.pb_data.is_null() {
                unsafe {
                    ptr::write_bytes(output.pb_data, 0, output.cb_data as usize);
                    LocalFree(output.pb_data as *mut c_void);
                }
            }
            return Err("unprotected wallet seed has an invalid length".into());
        }
        let mut seed =
            unsafe { std::slice::from_raw_parts(output.pb_data, output.cb_data as usize).to_vec() };
        unsafe {
            ptr::write_bytes(output.pb_data, 0, output.cb_data as usize);
            LocalFree(output.pb_data as *mut c_void);
        }
        Ok(std::mem::take(&mut seed))
    }

    fn save_new_wallet(path: &Path, envelope: &[u8]) -> Result<(), String> {
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        fs::create_dir_all(parent).map_err(|_| "could not create wallet directory".to_string())?;
        if path.exists() {
            return Err("wallet output already exists; refusing to overwrite a key".into());
        }
        let name = path
            .file_name()
            .ok_or("invalid wallet path")?
            .to_string_lossy();
        let id = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
        let temporary = parent.join(format!(".{name}.{}.{}.tmp", process::id(), id));
        let result = (|| -> io::Result<()> {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temporary)?;
            file.write_all(envelope)?;
            file.flush()?;
            file.sync_all()?;
            drop(file);
            // Hard-link creation is atomic and fails if the destination already exists.
            fs::hard_link(&temporary, path)?;
            fs::remove_file(&temporary)?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
            return Err(
                "failed to persist wallet atomically without overwriting an existing file".into(),
            );
        }
        Ok(())
    }

    fn create_wallet(path: &Path) -> Result<(), String> {
        let mut seed = SecretSeed([0u8; 32]);
        getrandom::getrandom(&mut seed.0)
            .map_err(|_| "operating-system random key generation failed".to_string())?;
        if seed.0.iter().all(|byte| *byte == 0) {
            return Err("operating-system random source returned an invalid seed".into());
        }
        let signer = Ed25519TransactionSigner::from_seed(seed.0);
        let public_key = signer.public_key();
        let account_id = signer.account_id();
        let protected = dpapi_protect(&seed.0, &public_key, &account_id)?;
        if protected.is_empty() || protected.len() > MAX_PROTECTED_BLOB {
            return Err("protected wallet blob length is invalid".into());
        }
        let mut envelope = Vec::with_capacity(HEADER_LEN + protected.len());
        envelope.extend_from_slice(MAGIC);
        envelope.extend_from_slice(&VERSION.to_be_bytes());
        envelope.extend_from_slice(&public_key);
        envelope.extend_from_slice(&account_id);
        envelope.extend_from_slice(&(protected.len() as u32).to_be_bytes());
        envelope.extend_from_slice(&protected);
        save_new_wallet(path, &envelope)?;
        println!("wallet_file={}", path.display());
        println!("wallet_format=QZKW1_Windows_CurrentUser_DPAPI");
        println!("public_key_hex={}", hex(&public_key));
        println!("account_id_hex={}", hex(&account_id));
        println!("private_key_output=none");
        println!("mainnet_balance=not_created");
        Ok(())
    }

    fn load_wallet(path: &Path) -> Result<(SecretSeed, [u8; 32], [u8; 32]), String> {
        let metadata = fs::symlink_metadata(path)
            .map_err(|_| "wallet file could not be inspected".to_string())?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err("wallet path must be a regular non-symlink file".into());
        }
        if metadata.len() < (HEADER_LEN + 1) as u64 || metadata.len() > MAX_FILE_LEN as u64 {
            return Err("wallet file length is invalid".into());
        }
        let file = File::open(path).map_err(|_| "wallet file could not be opened".to_string())?;
        let mut envelope = Vec::with_capacity(metadata.len() as usize);
        file.take((MAX_FILE_LEN + 1) as u64)
            .read_to_end(&mut envelope)
            .map_err(|_| "wallet file could not be read".to_string())?;
        if envelope.len() < HEADER_LEN + 1
            || envelope.len() > MAX_FILE_LEN
            || &envelope[..4] != MAGIC
        {
            return Err("wallet envelope magic, length, or format is invalid".into());
        }
        let version = u16::from_be_bytes([envelope[4], envelope[5]]);
        if version != VERSION {
            return Err(format!("unsupported wallet version: {version}"));
        }
        let public_key: [u8; 32] = envelope[6..38]
            .try_into()
            .map_err(|_| "wallet public key is malformed")?;
        let account_id: [u8; 32] = envelope[38..70]
            .try_into()
            .map_err(|_| "wallet account ID is malformed")?;
        if public_key.iter().all(|byte| *byte == 0) || account_id.iter().all(|byte| *byte == 0) {
            return Err("wallet public identifiers must be nonzero".into());
        }
        let protected_len = u32::from_be_bytes(
            envelope[70..74]
                .try_into()
                .map_err(|_| "wallet length is malformed")?,
        ) as usize;
        if protected_len == 0
            || protected_len > MAX_PROTECTED_BLOB
            || HEADER_LEN.checked_add(protected_len) != Some(envelope.len())
        {
            return Err("wallet protected payload length is invalid".into());
        }
        let mut raw = dpapi_unprotect(&envelope[HEADER_LEN..], &public_key, &account_id)?;
        if raw.len() != 32 || raw.iter().all(|byte| *byte == 0) {
            raw.fill(0);
            return Err("wallet seed is invalid".into());
        }
        let mut seed_bytes = [0u8; 32];
        seed_bytes.copy_from_slice(&raw);
        raw.fill(0);
        let seed = SecretSeed(seed_bytes);
        let signer = Ed25519TransactionSigner::from_seed(seed.0);
        if signer.public_key() != public_key || signer.account_id() != account_id {
            return Err("wallet seed does not match the stored public identity".into());
        }
        Ok((seed, public_key, account_id))
    }

    fn address(path: &Path) -> Result<(), String> {
        let (_seed, public_key, account_id) = load_wallet(path)?;
        println!("wallet_file={}", path.display());
        println!("public_key_hex={}", hex(&public_key));
        println!("account_id_hex={}", hex(&account_id));
        println!("private_key_output=none");
        Ok(())
    }

    fn sign_transfer(
        path: &Path,
        network_id: [u8; 32],
        recipient: [u8; 32],
        nonce: u64,
        amount: u64,
        fee: u64,
        expires_at: u64,
    ) -> Result<(), String> {
        let (seed, public_key, account_id) = load_wallet(path)?;
        if account_id == recipient {
            return Err("recipient must differ from the wallet account".into());
        }
        let signer = Ed25519TransactionSigner::from_seed(seed.0);
        let mut transaction = Transaction {
            network_id,
            sender: account_id,
            recipient,
            nonce,
            amount,
            fee,
            expires_at,
            signature: Vec::new(),
        };
        signer
            .sign_transaction(&mut transaction)
            .map_err(|error| format!("transaction signing failed: {error:?}"))?;
        let digest = transaction_signing_digest(&transaction)
            .map_err(|error| format!("transaction signing digest failed: {error:?}"))?;
        let encoded = encode_transaction(&transaction)
            .map_err(|error| format!("transaction encoding failed: {error:?}"))?;
        println!("tx_network_id_hex={}", hex(&network_id));
        println!("tx_sender_account_id_hex={}", hex(&account_id));
        println!("tx_sender_public_key_hex={}", hex(&public_key));
        println!("tx_recipient_id_hex={}", hex(&recipient));
        println!("tx_nonce={nonce}");
        println!("tx_amount_atoms={amount}");
        println!("tx_fee_atoms={fee}");
        println!("tx_expires_at={expires_at}");
        println!("tx_signing_digest_hex={}", hex(&digest));
        println!("tx_signature_hex={}", hex(&transaction.signature));
        println!("tx_wire_hex={}", hex(&encoded));
        println!("broadcast=not_attempted_no_public_rpc");
        Ok(())
    }

    pub fn run() {
        let result = match parse_command() {
            Ok(Command::Help) => {
                println!("QZXB native wallet (Windows CurrentUser DPAPI)\n\
Usage:\n\
  qzxb_wallet create --output ABSOLUTE_PATH\n\
  qzxb_wallet address --wallet ABSOLUTE_PATH\n\
  qzxb_wallet sign-transfer --wallet ABSOLUTE_PATH --network-id-hex HEX64 --recipient-id-hex HEX64 --nonce U64 --amount-atoms U64 --fee-atoms U64 --expires-at UNIX_SECONDS\n\
Notes: this local wallet does not submit transactions; mainnet balance is not implied.");
                Ok(())
            }
            Ok(Command::Create { output }) => create_wallet(&output),
            Ok(Command::Address { wallet }) => address(&wallet),
            Ok(Command::SignTransfer {
                wallet,
                network_id,
                recipient,
                nonce,
                amount,
                fee,
                expires_at,
            }) => sign_transfer(
                &wallet, network_id, recipient, nonce, amount, fee, expires_at,
            ),
            Err(error) => Err(error),
        };
        if let Err(error) = result {
            eprintln!("QZXB_WALLET_ERROR: {error}");
            process::exit(2);
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn wallet_identity_offsets_are_consistent() {
            assert_eq!(HEADER_LEN, 74);
            assert_eq!(MAX_FILE_LEN, HEADER_LEN + MAX_PROTECTED_BLOB);
        }

        #[test]
        fn hex32_rejects_short_and_non_hex_values() {
            assert!(parse_hex32("12", "test").is_err());
            assert!(parse_hex32(&"g0".repeat(32), "test").is_err());
            assert_eq!(parse_hex32(&"ab".repeat(32), "test").unwrap(), [0xab; 32]);
        }

        #[test]
        fn wallet_options_reject_private_key_arguments_and_duplicates() {
            let args = vec![
                "--output".to_string(),
                "C:\\wallet.qzw1".to_string(),
                "--output".to_string(),
                "C:\\other.qzw1".to_string(),
            ];
            assert!(options(&args, &["--output"]).is_err());
            let secret = vec!["--seed-hex".to_string(), "00".repeat(32)];
            assert!(options(&secret, &["--output"])
                .unwrap_err()
                .contains("not accepted"));
        }
    }
}

#[cfg(windows)]
fn main() {
    windows_wallet::run();
}

#[cfg(not(windows))]
fn main() {
    eprintln!("QZXB local wallet provisioning requires Windows CurrentUser DPAPI; no fallback plaintext wallet is provided.");
    std::process::exit(2);
}
