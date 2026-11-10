//! Windows-local native QZXB wallet for Ed25519 TXN2 transactions.
//!
//! The QZKW1 file contains a CurrentUser-DPAPI protected 32-byte seed and public identifiers.
//! It never accepts secret material on the command line or emits the seed. DPAPI is local desktop
//! custody, not an HSM or a portable backup format. `--submit-to` uses the versioned QZTS/1
//! transaction-ingress protocol; the destination's admission acknowledgement is printed.
#[cfg(windows)]
mod windows_wallet {
    use ai_native_l1_pow_bench::{
        qrun_v06_hybrid_auth_candidate::QRunV06HybridTransactionSigner,
        qrun_v06_noise_transport_candidate::QRunV06NoiseSession,
        qrun_v06_transaction_ingress_candidate::{
            decode_q6ta_response, encode_q6ti_transaction_request,
            QRunV06TransactionSubmitResponse, QRunV06TransactionSubmitStatus,
        },
        qzbe_tx_ingress_candidate::{decode_ack, encode_request, TxIngressStatus, ACK_BYTES},
        state_machine::{
            encode_transaction, encode_transaction_with_signature_limit, transaction_id,
            transaction_id_with_signature_limit, transaction_signing_digest, Transaction,
            QRUN_V06_MAX_NATIVE_TX_SIGNATURE_BYTES,
        },
        transaction_auth::Ed25519TransactionSigner,
    };
    use sha2::{Digest, Sha256};
    use std::{
        env,
        ffi::c_void,
        fs::{self, File, OpenOptions},
        io::{self, Read, Write},
        net::{Shutdown, SocketAddr, TcpStream},
        path::{Path, PathBuf},
        process, ptr,
        sync::atomic::{AtomicU64, Ordering},
    };

    const MAGIC: &[u8; 4] = b"QZKW";
    const VERSION: u16 = 1;
    const HYBRID_VERSION: u16 = 2;
    const HYBRID_HEADER_LEN: usize = 4 + 2 + 32 + 1_952 + 32 + 4;
    const HEADER_LEN: usize = 4 + 2 + 32 + 32 + 4;
    const HYBRID_WALLET_DOMAIN: &[u8] = b"QUANTUMZXB-QFP6-HYBRID-WALLET-DPAPI-V1\0";
    const HYBRID_ED25519_SEED_DOMAIN: &[u8] = b"QUANTUMZXB-ED25519-SEED-FROM-BIP39-V1\0";
    const HYBRID_MLDSA65_SEED_DOMAIN: &[u8] = b"QUANTUMZXB-QFP6-MLDSA65-SEED-FROM-BIP39-V1\0";
    const MAX_PROTECTED_BLOB: usize = 64 * 1024;
    const MAX_FILE_LEN: usize = HEADER_LEN + MAX_PROTECTED_BLOB;
    const WALLET_DOMAIN: &[u8] = b"QUANTUMZXB-ED25519-WALLET-DPAPI-V1\0";
    const Q6NK_MAGIC: &[u8; 4] = b"Q6NK";
    const Q6NK_VERSION: u16 = 1;
    const Q6NK_HEADER_LEN: usize = 4 + 2 + 32 + 32 + 4;
    const Q6NK_ID_DOMAIN: &[u8] = b"QUANTUMZXB-QFP6-NOISE-IDENTITY-V1\0";
    const CRYPTPROTECT_UI_FORBIDDEN: u32 = 0x1;
    static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(1);

    struct SecretSeed([u8; 32]);

    impl Drop for SecretSeed {
        fn drop(&mut self) {
            self.0.fill(0);
        }
    }

    fn wipe_string(value: &mut String) {
        unsafe {
            value.as_mut_vec().fill(0);
        }
        value.clear();
    }

    struct Qfp6SubmitOptions {
        endpoint: SocketAddr,
        profile_id: [u8; 32],
        noise_identity_file: PathBuf,
        trusted_peer_static_public_key: [u8; 32],
    }

    enum Command {
        Create {
            output: PathBuf,
        },
        CreateNoiseIdentity {
            output: PathBuf,
        },
        NoiseIdentity {
            identity: PathBuf,
        },
        Restore {
            output: PathBuf,
        },
        CreateHybrid {
            output: PathBuf,
        },
        RestoreHybrid {
            output: PathBuf,
        },
        HybridAddress {
            wallet: PathBuf,
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
            self_contained: bool,
            submit_to: Option<SocketAddr>,
            qfp6_submit: Option<Qfp6SubmitOptions>,
        },
        RpcStatus {
            rpc: SocketAddr,
        },
        Balance {
            rpc: SocketAddr,
            account_id: [u8; 32],
        },
        TransactionStatus {
            rpc: SocketAddr,
            txid: [u8; 32],
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

    const MAX_RPC_RESPONSE_BYTES: usize = 16 * 1024;

    fn parse_rpc_address(value: &str) -> Result<SocketAddr, String> {
        let address = value
            .parse::<SocketAddr>()
            .map_err(|_| "--rpc must be a numeric IP:port socket address".to_string())?;
        if !address.ip().is_loopback() {
            return Err("wallet RPC queries are restricted to numeric loopback addresses; public RPC is not enabled".into());
        }
        Ok(address)
    }

    fn parse_rpc_http_response(bytes: &[u8]) -> Result<serde_json::Value, String> {
        if bytes.is_empty() || bytes.len() > MAX_RPC_RESPONSE_BYTES {
            return Err("read-only RPC response is empty or oversized".into());
        }
        let header_end = bytes
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .ok_or_else(|| "read-only RPC response has no complete HTTP headers".to_string())?;
        let header_text = std::str::from_utf8(&bytes[..header_end])
            .map_err(|_| "read-only RPC response headers are not UTF-8".to_string())?;
        if !header_text.is_ascii() {
            return Err("read-only RPC response headers must be ASCII".into());
        }
        let mut lines = header_text.split("\r\n");
        if lines.next() != Some("HTTP/1.1 200 OK") {
            return Err("read-only RPC returned a non-200 HTTP status".into());
        }
        let mut content_length = None;
        let mut content_type_ok = false;
        for line in lines {
            let Some((name, value)) = line.split_once(':') else {
                return Err("read-only RPC returned a malformed HTTP header".into());
            };
            if name.eq_ignore_ascii_case("content-length") {
                if content_length.is_some() {
                    return Err("read-only RPC returned duplicate Content-Length headers".into());
                }
                content_length =
                    Some(value.trim().parse::<usize>().map_err(|_| {
                        "read-only RPC returned an invalid Content-Length".to_string()
                    })?);
            } else if name.eq_ignore_ascii_case("content-type") {
                content_type_ok = value
                    .trim()
                    .to_ascii_lowercase()
                    .starts_with("application/json");
            } else if name.eq_ignore_ascii_case("transfer-encoding") {
                return Err("chunked RPC responses are not accepted".into());
            }
        }
        if !content_type_ok {
            return Err("read-only RPC response is not JSON".into());
        }
        let body_start = header_end + 4;
        let declared =
            content_length.ok_or_else(|| "read-only RPC omitted Content-Length".to_string())?;
        if declared > MAX_RPC_RESPONSE_BYTES || bytes.len().saturating_sub(body_start) != declared {
            return Err("read-only RPC response length does not match Content-Length".into());
        }
        let value: serde_json::Value = serde_json::from_slice(&bytes[body_start..])
            .map_err(|_| "read-only RPC response contains invalid JSON".to_string())?;
        if value.get("ok") != Some(&serde_json::Value::Bool(true))
            || value
                .get("mainnet")
                .and_then(serde_json::Value::as_bool)
                .is_none()
            || value.get("read_only") != Some(&serde_json::Value::Bool(true))
        {
            return Err(
                "RPC response is not explicitly an OK, read-only response with a network mode"
                    .into(),
            );
        }
        Ok(value)
    }

    fn rpc_get(rpc: SocketAddr, path: &str) -> Result<serde_json::Value, String> {
        if !rpc.ip().is_loopback() {
            return Err("wallet RPC queries are restricted to loopback".into());
        }
        if !path.starts_with("/v1/")
            || path.contains(' ')
            || path.contains('?')
            || path.contains('#')
            || path.contains('\r')
            || path.contains('\n')
        {
            return Err("invalid internal candidate RPC path".into());
        }
        let mut stream = TcpStream::connect_timeout(&rpc, std::time::Duration::from_secs(3))
            .map_err(|error| format!("connect to loopback candidate RPC {rpc}: {error}"))?;
        stream
            .set_nodelay(true)
            .map_err(|error| format!("configure wallet RPC TCP_NODELAY: {error}"))?;
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .map_err(|error| format!("set wallet RPC read timeout: {error}"))?;
        stream
            .set_write_timeout(Some(std::time::Duration::from_secs(2)))
            .map_err(|error| format!("set wallet RPC write timeout: {error}"))?;
        let request =
            format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
        stream
            .write_all(request.as_bytes())
            .map_err(|error| format!("send wallet RPC query: {error}"))?;
        stream
            .shutdown(Shutdown::Write)
            .map_err(|error| format!("finish wallet RPC request: {error}"))?;
        let mut response = Vec::with_capacity(1024);
        let mut chunk = [0u8; 1024];
        loop {
            let count = stream
                .read(&mut chunk)
                .map_err(|error| format!("read wallet RPC response: {error}"))?;
            if count == 0 {
                break;
            }
            if response.len().saturating_add(count) > MAX_RPC_RESPONSE_BYTES {
                return Err("wallet RPC response exceeded the 16 KiB limit".into());
            }
            response.extend_from_slice(&chunk[..count]);
        }
        parse_rpc_http_response(&response)
    }

    fn json_string<'a>(value: &'a serde_json::Value, key: &str) -> Result<&'a str, String> {
        value
            .get(key)
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| format!("candidate RPC omitted string field {key}"))
    }

    fn rpc_network_class(value: &serde_json::Value) -> String {
        if let Some(class) = value
            .get("network_class")
            .and_then(serde_json::Value::as_str)
        {
            return class.to_string();
        }
        if value.get("mainnet").and_then(serde_json::Value::as_bool) == Some(true) {
            "qzxb_mainnet".to_string()
        } else {
            "candidate_not_mainnet".to_string()
        }
    }

    fn json_u64(value: &serde_json::Value, key: &str) -> Result<u64, String> {
        value
            .get(key)
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| format!("candidate RPC omitted integer field {key}"))
    }

    fn rpc_status(rpc: SocketAddr) -> Result<(), String> {
        let value = rpc_get(rpc, "/v1/status")?;
        println!("wallet_rpc_status=ok");
        println!("network_id_hex={}", json_string(&value, "network_id")?);
        println!("genesis_id_hex={}", json_string(&value, "genesis_id")?);
        println!("profile_id_hex={}", json_string(&value, "profile_id")?);
        println!("height={}", json_u64(&value, "height")?);
        println!("tip_hex={}", json_string(&value, "tip")?);
        println!("state_root_hex={}", json_string(&value, "state_root")?);
        println!("generation={}", json_u64(&value, "generation")?);
        println!("network_class={}", rpc_network_class(&value));
        Ok(())
    }

    fn rpc_balance(rpc: SocketAddr, account_id: [u8; 32]) -> Result<(), String> {
        let value = rpc_get(rpc, &format!("/v1/balance/{}", hex(&account_id)))?;
        if json_string(&value, "account_id")? != hex(&account_id) {
            return Err("candidate RPC returned a balance for a different account".into());
        }
        println!("wallet_rpc_balance_status=ok");
        println!("account_id_hex={}", hex(&account_id));
        println!("balance_atoms={}", json_u64(&value, "balance_atoms")?);
        println!("height={}", json_u64(&value, "height")?);
        println!("tip_hex={}", json_string(&value, "tip")?);
        println!("state_root_hex={}", json_string(&value, "state_root")?);
        println!("network_class={}", rpc_network_class(&value));
        Ok(())
    }

    fn rpc_transaction_status(rpc: SocketAddr, txid: [u8; 32]) -> Result<(), String> {
        let value = rpc_get(rpc, &format!("/v1/transaction/{}", hex(&txid)))?;
        if json_string(&value, "txid")? != hex(&txid) {
            return Err("candidate RPC returned a receipt for a different TXID".into());
        }
        let status = json_string(&value, "status")?;
        if !matches!(
            status,
            "confirmed" | "pending" | "not_found_in_retained_suffix"
        ) {
            return Err("candidate RPC returned an unknown transaction status".into());
        }
        println!("wallet_tx_status={status}");
        println!("txid_hex={}", hex(&txid));
        println!("confirmations={}", json_u64(&value, "confirmations")?);
        if let Some(height) = value
            .get("block_height")
            .and_then(serde_json::Value::as_u64)
        {
            println!("block_height={height}");
        } else {
            println!("block_height=none");
        }
        if let Some(floor) = value
            .get("search_floor_height")
            .and_then(serde_json::Value::as_u64)
        {
            println!("search_floor_height={floor}");
        }
        println!("height={}", json_u64(&value, "height")?);
        println!("tip_hex={}", json_string(&value, "tip")?);
        println!("state_root_hex={}", json_string(&value, "state_root")?);
        println!("finality=probabilistic_candidate_chain_reorg_possible");
        println!("network_class={}", rpc_network_class(&value));
        Ok(())
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
            "create-qfp6-noise-identity" => {
                let values = options(&args[1..], &["--output"])?;
                let output = PathBuf::from(required(&values, "--output")?);
                if !output.is_absolute() || output.file_name().is_none() {
                    return Err("--output must be an absolute file path".into());
                }
                Ok(Command::CreateNoiseIdentity { output })
            }
            "noise-identity" => {
                let values = options(&args[1..], &["--identity"])?;
                let identity = PathBuf::from(required(&values, "--identity")?);
                if !identity.is_absolute() {
                    return Err("--identity must be an absolute file path".into());
                }
                Ok(Command::NoiseIdentity { identity })
            }
            "create" => {
                let values = options(&args[1..], &["--output"])?;
                let output = PathBuf::from(required(&values, "--output")?);
                if !output.is_absolute() || output.file_name().is_none() {
                    return Err("--output must be an absolute file path".into());
                }
                Ok(Command::Create { output })
            }
            "restore" => {
                let values = options(&args[1..], &["--output"])?;
                let output = PathBuf::from(required(&values, "--output")?);
                if !output.is_absolute() || output.file_name().is_none() {
                    return Err("--output must be an absolute file path".into());
                }
                Ok(Command::Restore { output })
            }
            "create-qfp6-hybrid" => {
                let values = options(&args[1..], &["--output"])?;
                let output = PathBuf::from(required(&values, "--output")?);
                if !output.is_absolute() || output.file_name().is_none() {
                    return Err("--output must be an absolute file path".into());
                }
                Ok(Command::CreateHybrid { output })
            }
            "restore-qfp6-hybrid" => {
                let values = options(&args[1..], &["--output"])?;
                let output = PathBuf::from(required(&values, "--output")?);
                if !output.is_absolute() || output.file_name().is_none() {
                    return Err("--output must be an absolute file path".into());
                }
                Ok(Command::RestoreHybrid { output })
            }
            "address-qfp6-hybrid" => {
                let values = options(&args[1..], &["--wallet"])?;
                let wallet = PathBuf::from(required(&values, "--wallet")?);
                if !wallet.is_absolute() {
                    return Err("--wallet must be an absolute file path".into());
                }
                Ok(Command::HybridAddress { wallet })
            }
            "address" => {
                let values = options(&args[1..], &["--wallet"])?;
                let wallet = PathBuf::from(required(&values, "--wallet")?);
                if !wallet.is_absolute() {
                    return Err("--wallet must be an absolute file path".into());
                }
                Ok(Command::Address { wallet })
            }
            "rpc-status" => {
                let values = options(&args[1..], &["--rpc"])?;
                let rpc = parse_rpc_address(required(&values, "--rpc")?)?;
                Ok(Command::RpcStatus { rpc })
            }
            "balance" => {
                let values = options(&args[1..], &["--rpc", "--account-id-hex"])?;
                let rpc = parse_rpc_address(required(&values, "--rpc")?)?;
                let account_id = parse_hex32(required(&values, "--account-id-hex")?, "account ID")?;
                Ok(Command::Balance { rpc, account_id })
            }
            "tx-status" => {
                let values = options(&args[1..], &["--rpc", "--txid-hex"])?;
                let rpc = parse_rpc_address(required(&values, "--rpc")?)?;
                let txid = parse_hex32(required(&values, "--txid-hex")?, "transaction ID")?;
                Ok(Command::TransactionStatus { rpc, txid })
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
                        "--signature-mode",
                        "--submit-to",
                        "--qfp6-submit-to",
                        "--qfp6-profile-id-hex",
                        "--qfp6-noise-identity-file",
                        "--qfp6-peer-static-public-key-hex",
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
                let self_contained = match values.get("--signature-mode").map(String::as_str) {
                    None | Some("self-contained") => true,
                    Some("registered") => false,
                    Some(_) => {
                        return Err("--signature-mode must be self-contained or registered".into())
                    }
                };
                let submit_to = values
                    .get("--submit-to")
                    .map(|value| {
                        value.parse::<SocketAddr>().map_err(|_| {
                            "--submit-to must be a numeric IP:port socket address".to_string()
                        })
                    })
                    .transpose()?;
                let qfp6_fields = [
                    "--qfp6-submit-to",
                    "--qfp6-profile-id-hex",
                    "--qfp6-noise-identity-file",
                    "--qfp6-peer-static-public-key-hex",
                ];
                let qfp6_present = qfp6_fields
                    .iter()
                    .filter(|key| values.contains_key(**key))
                    .count();
                let qfp6_submit = if qfp6_present == 0 {
                    None
                } else if qfp6_present != qfp6_fields.len() {
                    return Err(
                        "QFP6 submission requires all four --qfp6-* options together".into(),
                    );
                } else {
                    let endpoint = required(&values, "--qfp6-submit-to")?
                        .parse::<SocketAddr>()
                        .map_err(|_| {
                            "--qfp6-submit-to must be a numeric IP:port socket address".to_string()
                        })?;
                    let noise_identity_file =
                        PathBuf::from(required(&values, "--qfp6-noise-identity-file")?);
                    if !noise_identity_file.is_absolute() {
                        return Err(
                            "--qfp6-noise-identity-file must be an absolute file path".into()
                        );
                    }
                    Some(Qfp6SubmitOptions {
                        endpoint,
                        profile_id: parse_hex32(
                            required(&values, "--qfp6-profile-id-hex")?,
                            "QFP6 profile ID",
                        )?,
                        noise_identity_file,
                        trusted_peer_static_public_key: parse_hex32(
                            required(&values, "--qfp6-peer-static-public-key-hex")?,
                            "pinned QFP6 peer static public key",
                        )?,
                    })
                };
                if submit_to.is_some() && qfp6_submit.is_some() {
                    return Err(
                        "legacy --submit-to and QFP6 Noise submission cannot be combined".into(),
                    );
                }
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
                    self_contained,
                    submit_to,
                    qfp6_submit,
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
        fn GetStdHandle(std_handle: u32) -> *mut c_void;
        fn GetConsoleMode(handle: *mut c_void, mode: *mut u32) -> i32;
        fn SetConsoleMode(handle: *mut c_void, mode: u32) -> i32;
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

    fn hybrid_entropy(ed: &[u8; 32], pq: &[u8; 1_952], account: &[u8; 32]) -> Vec<u8> {
        let mut value = Vec::with_capacity(HYBRID_WALLET_DOMAIN.len() + 32 + 1_952 + 32);
        value.extend_from_slice(HYBRID_WALLET_DOMAIN);
        value.extend_from_slice(ed);
        value.extend_from_slice(pq);
        value.extend_from_slice(account);
        value
    }

    fn dpapi_protect_hybrid(
        payload: &[u8; 64],
        ed: &[u8; 32],
        pq: &[u8; 1_952],
        account: &[u8; 32],
    ) -> Result<Vec<u8>, String> {
        let entropy_bytes = hybrid_entropy(ed, pq, account);
        let input = DataBlob {
            cb_data: payload.len() as u32,
            pb_data: payload.as_ptr() as *mut u8,
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
                "Windows CurrentUser DPAPI hybrid-wallet protection failed (Win32 error {})",
                unsafe { GetLastError() }
            ));
        }
        if output.pb_data.is_null()
            || output.cb_data == 0
            || output.cb_data as usize > MAX_PROTECTED_BLOB
        {
            if !output.pb_data.is_null() {
                unsafe {
                    ptr::write_bytes(output.pb_data, 0, output.cb_data as usize);
                    LocalFree(output.pb_data as *mut c_void);
                }
            }
            return Err("DPAPI returned an invalid protected hybrid-wallet blob".into());
        }
        let protected =
            unsafe { std::slice::from_raw_parts(output.pb_data, output.cb_data as usize).to_vec() };
        unsafe {
            ptr::write_bytes(output.pb_data, 0, output.cb_data as usize);
            LocalFree(output.pb_data as *mut c_void);
        }
        Ok(protected)
    }

    fn dpapi_unprotect_hybrid(
        blob: &[u8],
        ed: &[u8; 32],
        pq: &[u8; 1_952],
        account: &[u8; 32],
    ) -> Result<Vec<u8>, String> {
        if blob.is_empty() || blob.len() > u32::MAX as usize {
            return Err("protected hybrid-wallet blob has an invalid length".into());
        }
        let entropy_bytes = hybrid_entropy(ed, pq, account);
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
            return Err(format!("hybrid wallet could not be unprotected for the current Windows user (Win32 error {})", unsafe { GetLastError() }));
        }
        if output.pb_data.is_null() || output.cb_data != 64 {
            if !output.pb_data.is_null() {
                unsafe {
                    ptr::write_bytes(output.pb_data, 0, output.cb_data as usize);
                    LocalFree(output.pb_data as *mut c_void);
                }
            }
            return Err("unprotected hybrid-wallet seed payload must be exactly 64 bytes".into());
        }
        let mut secret =
            unsafe { std::slice::from_raw_parts(output.pb_data, output.cb_data as usize).to_vec() };
        unsafe {
            ptr::write_bytes(output.pb_data, 0, output.cb_data as usize);
            LocalFree(output.pb_data as *mut c_void);
        }
        Ok(std::mem::take(&mut secret))
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

    /// Derive a QZXB signing seed deterministically from a standard 12-word English BIP39 phrase.
    /// This is chain-specific and is not the Bitcoin/EVM BIP32 derivation path.
    fn derive_signing_seed(mnemonic: &bip39::Mnemonic) -> SecretSeed {
        let mut mnemonic_seed = mnemonic.to_seed("");
        let mut hasher = Sha256::new();
        hasher.update(b"QUANTUMZXB-ED25519-SEED-FROM-BIP39-V1\0");
        hasher.update(&mnemonic_seed);
        let digest = hasher.finalize();
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&digest);
        mnemonic_seed.fill(0);
        SecretSeed(seed)
    }

    fn save_wallet_from_seed(
        path: &Path,
        seed: SecretSeed,
        recovery_phrase: Option<&str>,
    ) -> Result<(), String> {
        if seed.0.iter().all(|byte| *byte == 0) {
            return Err("wallet signing seed is invalid".into());
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
        println!("wallet_derivation=QZXB-BIP39-12-Ed25519-v1");
        println!("public_key_hex={}", hex(&public_key));
        println!("account_id_hex={}", hex(&account_id));
        println!("private_key_output=none");
        println!("mainnet_balance=not_created");
        if let Some(phrase) = recovery_phrase {
            println!("recovery_phrase_words=12");
            println!("recovery_phrase={phrase}");
            println!("recovery_phrase_warning=write_on_paper; never_share_or_store_in_cloud");
        }
        Ok(())
    }

    struct HybridSecretSeeds {
        ed25519: [u8; 32],
        mldsa65: [u8; 32],
    }
    impl Drop for HybridSecretSeeds {
        fn drop(&mut self) {
            self.ed25519.fill(0);
            self.mldsa65.fill(0);
        }
    }
    struct LoadedHybridWallet {
        seeds: HybridSecretSeeds,
        ed25519_public_key: [u8; 32],
        mldsa65_public_key: [u8; 1_952],
        account_id: [u8; 32],
    }

    fn derive_domain_seed(domain: &[u8], mnemonic_seed: &[u8; 64]) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(domain);
        hash.update(mnemonic_seed);
        hash.finalize().into()
    }
    fn derive_hybrid_seeds(mnemonic: &bip39::Mnemonic) -> HybridSecretSeeds {
        let mut mnemonic_seed = mnemonic.to_seed("");
        let ed25519 = derive_domain_seed(HYBRID_ED25519_SEED_DOMAIN, &mnemonic_seed);
        let mldsa65 = derive_domain_seed(HYBRID_MLDSA65_SEED_DOMAIN, &mnemonic_seed);
        mnemonic_seed.fill(0);
        HybridSecretSeeds { ed25519, mldsa65 }
    }

    fn save_hybrid_wallet(
        path: &Path,
        seeds: &HybridSecretSeeds,
        phrase: Option<&str>,
    ) -> Result<(), String> {
        let signer = QRunV06HybridTransactionSigner::from_seeds(seeds.ed25519, seeds.mldsa65)
            .map_err(|e| format!("QFP6 hybrid key derivation failed: {e:?}"))?;
        let ed = signer.ed25519_public_key();
        let pq = signer.mldsa65_public_key();
        let account = signer.account_id();
        let mut secret_payload = [0u8; 64];
        secret_payload[..32].copy_from_slice(&seeds.ed25519);
        secret_payload[32..].copy_from_slice(&seeds.mldsa65);
        let protected_result = dpapi_protect_hybrid(&secret_payload, &ed, &pq, &account);
        secret_payload.fill(0);
        let protected = protected_result?;
        if protected.is_empty() || protected.len() > MAX_PROTECTED_BLOB {
            return Err("protected QFP6 hybrid-wallet blob length is invalid".into());
        }
        let mut envelope = Vec::with_capacity(HYBRID_HEADER_LEN + protected.len());
        envelope.extend_from_slice(MAGIC);
        envelope.extend_from_slice(&HYBRID_VERSION.to_be_bytes());
        envelope.extend_from_slice(&ed);
        envelope.extend_from_slice(&pq);
        envelope.extend_from_slice(&account);
        envelope.extend_from_slice(&(protected.len() as u32).to_be_bytes());
        envelope.extend_from_slice(&protected);
        save_new_wallet(path, &envelope)?;
        println!("wallet_file={}", path.display());
        println!("wallet_format=QZKW2_QFP6_HYBRID_Windows_CurrentUser_DPAPI");
        println!("wallet_derivation=QFP6-BIP39-12-HYBRID-ED25519-MLDSA65-v1");
        println!("public_account_id_hex={}", hex(&account));
        println!("ed25519_public_key_hex={}", hex(&ed));
        println!("mldsa65_public_key_hex={}", hex(&pq));
        println!("private_key_output=none");
        println!("mainnet_balance=not_created");
        if let Some(phrase) = phrase {
            println!("recovery_phrase_words=12");
            println!("recovery_phrase={phrase}");
            println!("recovery_phrase_warning=write_on_paper; never_share_or_store_in_cloud");
        }
        Ok(())
    }

    fn create_hybrid_wallet(path: &Path) -> Result<(), String> {
        let mut entropy = [0u8; 16];
        getrandom::getrandom(&mut entropy)
            .map_err(|_| "operating-system random entropy generation failed".to_string())?;
        if entropy.iter().all(|b| *b == 0) {
            entropy.fill(0);
            return Err("operating-system random source returned invalid entropy".into());
        }
        let mnemonic = bip39::Mnemonic::from_entropy_in(bip39::Language::English, &entropy)
            .map_err(|_| {
                "could not create a standard 12-word English BIP39 mnemonic".to_string()
            })?;
        entropy.fill(0);
        let mut phrase = mnemonic.to_string();
        let seeds = derive_hybrid_seeds(&mnemonic);
        let result = save_hybrid_wallet(path, &seeds, Some(&phrase));
        wipe_string(&mut phrase);
        result
    }

    fn restore_hybrid_wallet(path: &Path) -> Result<(), String> {
        eprintln!("Enter the 12-word English BIP39 recovery phrase. Console input is masked.");
        let mut phrase = read_secret_line()?;
        let mut normalized = phrase.split_whitespace().collect::<Vec<_>>().join(" ");
        wipe_string(&mut phrase);
        let mnemonic = match bip39::Mnemonic::parse_in(bip39::Language::English, &normalized) {
            Ok(value) => value,
            Err(_) => {
                wipe_string(&mut normalized);
                return Err("recovery phrase is invalid: expected a valid 12-word English BIP39 phrase and checksum".into());
            }
        };
        wipe_string(&mut normalized);
        let seeds = derive_hybrid_seeds(&mnemonic);
        save_hybrid_wallet(path, &seeds, None)?;
        println!("restore_status=success");
        println!("recovery_phrase_saved_to_disk=no");
        Ok(())
    }

    fn load_hybrid_wallet(path: &Path) -> Result<LoadedHybridWallet, String> {
        let metadata = fs::symlink_metadata(path)
            .map_err(|_| "hybrid wallet file could not be inspected".to_string())?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err("hybrid wallet path must be a regular non-symlink file".into());
        }
        if metadata.len() < (HYBRID_HEADER_LEN + 1) as u64
            || metadata.len() > (HYBRID_HEADER_LEN + MAX_PROTECTED_BLOB) as u64
        {
            return Err("QZKW2 hybrid wallet file length is invalid".into());
        }
        let file =
            File::open(path).map_err(|_| "hybrid wallet file could not be opened".to_string())?;
        let mut envelope = Vec::with_capacity(metadata.len() as usize);
        file.take((HYBRID_HEADER_LEN + MAX_PROTECTED_BLOB + 1) as u64)
            .read_to_end(&mut envelope)
            .map_err(|_| "hybrid wallet file could not be read".to_string())?;
        if envelope.len() < HYBRID_HEADER_LEN + 1
            || envelope.len() > HYBRID_HEADER_LEN + MAX_PROTECTED_BLOB
            || &envelope[..4] != MAGIC
            || u16::from_be_bytes([envelope[4], envelope[5]]) != HYBRID_VERSION
        {
            return Err("QZKW2 hybrid wallet magic, version or length is invalid".into());
        }
        let ed: [u8; 32] = envelope[6..38]
            .try_into()
            .map_err(|_| "QZKW2 Ed25519 public key is malformed")?;
        let pq: [u8; 1_952] = envelope[38..1_990]
            .try_into()
            .map_err(|_| "QZKW2 ML-DSA-65 public key is malformed")?;
        let account: [u8; 32] = envelope[1_990..2_022]
            .try_into()
            .map_err(|_| "QZKW2 account ID is malformed")?;
        if ed.iter().all(|b| *b == 0)
            || pq.iter().all(|b| *b == 0)
            || account.iter().all(|b| *b == 0)
        {
            return Err("QZKW2 public identifiers must be nonzero".into());
        }
        let protected_len = u32::from_be_bytes(
            envelope[2_022..2_026]
                .try_into()
                .map_err(|_| "QZKW2 protected length is malformed")?,
        ) as usize;
        if protected_len == 0
            || protected_len > MAX_PROTECTED_BLOB
            || HYBRID_HEADER_LEN.checked_add(protected_len) != Some(envelope.len())
        {
            return Err("QZKW2 protected payload length is invalid".into());
        }
        let mut raw = dpapi_unprotect_hybrid(&envelope[HYBRID_HEADER_LEN..], &ed, &pq, &account)?;
        if raw.len() != 64
            || raw[..32].iter().all(|b| *b == 0)
            || raw[32..].iter().all(|b| *b == 0)
            || raw[..32] == raw[32..]
        {
            raw.fill(0);
            return Err("QZKW2 hybrid seed payload is invalid".into());
        }
        let mut ed_seed = [0u8; 32];
        let mut pq_seed = [0u8; 32];
        ed_seed.copy_from_slice(&raw[..32]);
        pq_seed.copy_from_slice(&raw[32..]);
        raw.fill(0);
        let seeds = HybridSecretSeeds {
            ed25519: ed_seed,
            mldsa65: pq_seed,
        };
        let signer = QRunV06HybridTransactionSigner::from_seeds(seeds.ed25519, seeds.mldsa65)
            .map_err(|e| format!("QZKW2 key reconstruction failed: {e:?}"))?;
        if signer.ed25519_public_key() != ed
            || signer.mldsa65_public_key() != pq
            || signer.account_id() != account
        {
            return Err(
                "QZKW2 protected seeds do not match both public keys and account ID".into(),
            );
        }
        Ok(LoadedHybridWallet {
            seeds,
            ed25519_public_key: ed,
            mldsa65_public_key: pq,
            account_id: account,
        })
    }

    fn hybrid_address(path: &Path) -> Result<(), String> {
        let wallet = load_hybrid_wallet(path)?;
        println!("wallet_file={}", path.display());
        println!("wallet_format=QZKW2_QFP6_HYBRID_Windows_CurrentUser_DPAPI");
        println!("account_id_hex={}", hex(&wallet.account_id));
        println!("ed25519_public_key_hex={}", hex(&wallet.ed25519_public_key));
        println!("mldsa65_public_key_hex={}", hex(&wallet.mldsa65_public_key));
        println!("private_key_output=none");
        Ok(())
    }

    fn create_wallet(path: &Path) -> Result<(), String> {
        let mut entropy = [0u8; 16];
        getrandom::getrandom(&mut entropy)
            .map_err(|_| "operating-system random entropy generation failed".to_string())?;
        if entropy.iter().all(|byte| *byte == 0) {
            entropy.fill(0);
            return Err("operating-system random source returned invalid entropy".into());
        }
        let mnemonic = bip39::Mnemonic::from_entropy_in(bip39::Language::English, &entropy)
            .map_err(|_| "could not create a standard 12-word BIP39 mnemonic".to_string())?;
        entropy.fill(0);
        let mut phrase = mnemonic.to_string();
        let seed = derive_signing_seed(&mnemonic);
        let result = save_wallet_from_seed(path, seed, Some(&phrase));
        wipe_string(&mut phrase);
        result
    }

    fn read_secret_line() -> Result<String, String> {
        const STD_INPUT_HANDLE: u32 = (-10i32) as u32;
        const ENABLE_ECHO_INPUT: u32 = 0x0004;
        let handle = unsafe { GetStdHandle(STD_INPUT_HANDLE) };
        let mut original_mode = 0u32;
        let has_console =
            !handle.is_null() && unsafe { GetConsoleMode(handle, &mut original_mode) } != 0;
        if has_console && unsafe { SetConsoleMode(handle, original_mode & !ENABLE_ECHO_INPUT) } == 0
        {
            return Err("could not disable console echo; recovery phrase input aborted".into());
        }
        let mut phrase = String::new();
        let read_result = io::stdin().read_line(&mut phrase);
        if has_console {
            let restored = unsafe { SetConsoleMode(handle, original_mode) } != 0;
            println!();
            if !restored {
                wipe_string(&mut phrase);
                return Err("could not restore console mode after secret input".into());
            }
        }
        read_result.map_err(|_| {
            wipe_string(&mut phrase);
            "could not read recovery phrase from standard input".to_string()
        })?;
        if phrase.trim().is_empty() {
            wipe_string(&mut phrase);
            return Err("recovery phrase input was empty".into());
        }
        Ok(phrase)
    }

    fn restore_wallet(path: &Path) -> Result<(), String> {
        eprintln!("Enter the 12-word English BIP39 recovery phrase. Console input is masked.");
        let mut phrase = read_secret_line()?;
        let mut normalized = phrase.split_whitespace().collect::<Vec<_>>().join(" ");
        wipe_string(&mut phrase);
        let mnemonic = match bip39::Mnemonic::parse_in(bip39::Language::English, &normalized) {
            Ok(value) => value,
            Err(_) => {
                wipe_string(&mut normalized);
                return Err("recovery phrase is invalid: expected a valid 12-word English BIP39 phrase and checksum".into());
            }
        };
        wipe_string(&mut normalized);
        let seed = derive_signing_seed(&mnemonic);
        save_wallet_from_seed(path, seed, None)?;
        println!("restore_status=success");
        println!("recovery_phrase_saved_to_disk=no");
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

    fn wallet_version(path: &Path) -> Result<u16, String> {
        let metadata = fs::symlink_metadata(path)
            .map_err(|_| "wallet file could not be inspected".to_string())?;
        if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() < 6 {
            return Err("wallet must be a regular file with a complete QZKW header".into());
        }
        let mut file =
            File::open(path).map_err(|_| "wallet file could not be opened".to_string())?;
        let mut header = [0u8; 6];
        file.read_exact(&mut header)
            .map_err(|_| "wallet header could not be read".to_string())?;
        if &header[..4] != MAGIC {
            return Err("wallet file has an unsupported magic value".into());
        }
        Ok(u16::from_be_bytes([header[4], header[5]]))
    }

    fn q6nk_identity_id(public_key: &[u8; 32]) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(Q6NK_ID_DOMAIN);
        hash.update(public_key);
        hash.finalize().into()
    }

    struct LoadedNoiseIdentity {
        private_key: SecretSeed,
        public_key: [u8; 32],
        identity_id: [u8; 32],
    }

    fn create_noise_identity(path: &Path) -> Result<(), String> {
        let params: snow::params::NoiseParams = "Noise_XX_25519_ChaChaPoly_SHA256"
            .parse()
            .map_err(|_| "QFP6 Noise XX parameters could not be parsed".to_string())?;
        let mut pair = snow::Builder::new(params)
            .generate_keypair()
            .map_err(|error| format!("QFP6 Noise X25519 key generation failed: {error}"))?;
        if pair.private.len() != 32 || pair.public.len() != 32 {
            pair.private.fill(0);
            pair.public.fill(0);
            return Err("QFP6 Noise key generator returned an invalid key length".into());
        }
        let mut private_bytes = [0u8; 32];
        let mut public_key = [0u8; 32];
        private_bytes.copy_from_slice(&pair.private);
        public_key.copy_from_slice(&pair.public);
        pair.private.fill(0);
        pair.public.fill(0);
        if private_bytes.iter().all(|b| *b == 0) || public_key.iter().all(|b| *b == 0) {
            private_bytes.fill(0);
            return Err("QFP6 Noise key generator returned a zero key".into());
        }
        let identity_id = q6nk_identity_id(&public_key);
        let private_key = SecretSeed(private_bytes);
        let protected = dpapi_protect(&private_key.0, &public_key, &identity_id)?;
        if protected.is_empty() || protected.len() > MAX_PROTECTED_BLOB {
            return Err("Q6NK1 DPAPI-protected key payload length is invalid".into());
        }
        let mut envelope = Vec::with_capacity(Q6NK_HEADER_LEN + protected.len());
        envelope.extend_from_slice(Q6NK_MAGIC);
        envelope.extend_from_slice(&Q6NK_VERSION.to_be_bytes());
        envelope.extend_from_slice(&public_key);
        envelope.extend_from_slice(&identity_id);
        envelope.extend_from_slice(&(protected.len() as u32).to_be_bytes());
        envelope.extend_from_slice(&protected);
        save_new_wallet(path, &envelope)?;
        println!("noise_identity_file={}", path.display());
        println!("noise_identity_format=Q6NK1_Windows_CurrentUser_DPAPI");
        println!("noise_static_public_key_hex={}", hex(&public_key));
        println!("noise_identity_id_hex={}", hex(&identity_id));
        println!("noise_private_key_output=none");
        println!("noise_peer_pin_action=register_the_public_key_with_the_QFP6_node_operator");
        Ok(())
    }

    fn load_noise_identity(path: &Path) -> Result<LoadedNoiseIdentity, String> {
        let metadata = fs::symlink_metadata(path)
            .map_err(|_| "QFP6 Noise identity file could not be inspected".to_string())?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err("QFP6 Noise identity path must be a regular non-symlink file".into());
        }
        if metadata.len() < (Q6NK_HEADER_LEN + 1) as u64
            || metadata.len() > (Q6NK_HEADER_LEN + MAX_PROTECTED_BLOB) as u64
        {
            return Err("Q6NK1 identity file length is invalid".into());
        }
        let file = File::open(path)
            .map_err(|_| "QFP6 Noise identity file could not be opened".to_string())?;
        let mut envelope = Vec::with_capacity(metadata.len() as usize);
        file.take((Q6NK_HEADER_LEN + MAX_PROTECTED_BLOB + 1) as u64)
            .read_to_end(&mut envelope)
            .map_err(|_| "QFP6 Noise identity file could not be read".to_string())?;
        if envelope.len() < Q6NK_HEADER_LEN + 1
            || envelope.len() > Q6NK_HEADER_LEN + MAX_PROTECTED_BLOB
            || &envelope[..4] != Q6NK_MAGIC
            || u16::from_be_bytes([envelope[4], envelope[5]]) != Q6NK_VERSION
        {
            return Err("Q6NK1 magic, version or file length is invalid".into());
        }
        let public_key: [u8; 32] = envelope[6..38]
            .try_into()
            .map_err(|_| "Q6NK1 Noise public key is malformed")?;
        let identity_id: [u8; 32] = envelope[38..70]
            .try_into()
            .map_err(|_| "Q6NK1 identity ID is malformed")?;
        if public_key.iter().all(|b| *b == 0)
            || identity_id.iter().all(|b| *b == 0)
            || q6nk_identity_id(&public_key) != identity_id
        {
            return Err("Q6NK1 public key/identity binding is invalid".into());
        }
        let protected_len = u32::from_be_bytes(
            envelope[70..74]
                .try_into()
                .map_err(|_| "Q6NK1 protected length is malformed")?,
        ) as usize;
        if protected_len == 0
            || protected_len > MAX_PROTECTED_BLOB
            || Q6NK_HEADER_LEN.checked_add(protected_len) != Some(envelope.len())
        {
            return Err("Q6NK1 protected payload length is invalid".into());
        }
        let mut raw = dpapi_unprotect(&envelope[Q6NK_HEADER_LEN..], &public_key, &identity_id)?;
        if raw.len() != 32 || raw.iter().all(|b| *b == 0) {
            raw.fill(0);
            return Err("Q6NK1 unprotected X25519 private key is invalid".into());
        }
        let mut private_bytes = [0u8; 32];
        private_bytes.copy_from_slice(&raw);
        raw.fill(0);
        Ok(LoadedNoiseIdentity {
            private_key: SecretSeed(private_bytes),
            public_key,
            identity_id,
        })
    }

    fn noise_identity_info(path: &Path) -> Result<(), String> {
        let identity = load_noise_identity(path)?;
        println!("noise_identity_file={}", path.display());
        println!("noise_identity_format=Q6NK1_Windows_CurrentUser_DPAPI");
        println!("noise_static_public_key_hex={}", hex(&identity.public_key));
        println!("noise_identity_id_hex={}", hex(&identity.identity_id));
        println!("noise_private_key_output=none");
        Ok(())
    }

    fn qfp6_submit_endpoint_is_private(address: SocketAddr) -> bool {
        match address.ip() {
            std::net::IpAddr::V4(ip) => {
                let o = ip.octets();
                ip.is_loopback()
                    || ip.is_private()
                    || ip.is_link_local()
                    || (o[0] == 100 && (64..=127).contains(&o[1]))
            }
            std::net::IpAddr::V6(ip) => {
                let o = ip.octets();
                ip.is_loopback() || (o[0] & 0xFE == 0xFC) || (o[0] == 0xFE && o[1] & 0xC0 == 0x80)
            }
        }
    }

    fn submit_q6ti_over_noise(
        options: &Qfp6SubmitOptions,
        network_id: &[u8; 32],
        transaction: &Transaction,
        expected_txid: &[u8; 32],
    ) -> Result<QRunV06TransactionSubmitResponse, String> {
        if !qfp6_submit_endpoint_is_private(options.endpoint) {
            return Err(
                "QFP6 transaction submission is restricted to loopback/private/NetBird endpoints"
                    .into(),
            );
        }
        if network_id.iter().all(|b| *b == 0)
            || options.profile_id.iter().all(|b| *b == 0)
            || options
                .trusted_peer_static_public_key
                .iter()
                .all(|b| *b == 0)
        {
            return Err("QFP6 network/profile and pinned Noise peer key must be nonzero".into());
        }
        let mut request_bytes = [0u8; 8];
        getrandom::getrandom(&mut request_bytes)
            .map_err(|_| "operating-system random request-ID generation failed".to_string())?;
        let mut request_id = u64::from_be_bytes(request_bytes);
        if request_id == 0 {
            request_id = 1;
        }
        request_bytes.fill(0);
        let request = encode_q6ti_transaction_request(request_id, transaction)
            .map_err(|error| format!("encode Q6TI transaction request: {error:?}"))?;
        let identity = load_noise_identity(&options.noise_identity_file)?;
        let mut stream =
            TcpStream::connect_timeout(&options.endpoint, std::time::Duration::from_secs(5))
                .map_err(|error| {
                    format!(
                        "connect to pinned QFP6 transaction endpoint {}: {error}",
                        options.endpoint
                    )
                })?;
        stream
            .set_nodelay(true)
            .map_err(|error| format!("configure QFP6 Noise TCP_NODELAY: {error}"))?;
        let mut noise = QRunV06NoiseSession::connect(
            &mut stream,
            &identity.private_key.0,
            &options.trusted_peer_static_public_key,
            network_id,
            &options.profile_id,
        )
        .map_err(|error| format!("authenticate pinned QFP6 Noise peer: {error}"))?;
        if noise.remote_static_public_key() != &options.trusted_peer_static_public_key {
            return Err("QFP6 Noise remote static identity changed after the handshake".into());
        }
        noise
            .write_record(&mut stream, &request)
            .map_err(|error| format!("send encrypted Q6TI transaction: {error}"))?;
        let response = noise
            .read_admission_response(&mut stream)
            .map_err(|error| format!("read encrypted Q6TA response: {error}"))?;
        let acknowledgement = decode_q6ta_response(&response, request_id)
            .map_err(|error| format!("decode Q6TA response: {error:?}"))?;
        if &acknowledgement.transaction_id != expected_txid {
            return Err(
                "Q6TA response TXID does not match the locally signed Q6HA transaction".into(),
            );
        }
        Ok(acknowledgement)
    }

    fn sign_transfer(
        path: &Path,
        network_id: [u8; 32],
        recipient: [u8; 32],
        nonce: u64,
        amount: u64,
        fee: u64,
        expires_at: u64,
        self_contained: bool,
        submit_to: Option<SocketAddr>,
        qfp6_submit: Option<Qfp6SubmitOptions>,
    ) -> Result<(), String> {
        match wallet_version(path)? {
            VERSION => {
                if qfp6_submit.is_some() {
                    return Err(
                        "Q6TI/Q6TA requires a QZKW2 hybrid wallet; QZKW1 remains on legacy TXN2"
                            .into(),
                    );
                }
                sign_transfer_legacy(
                    path,
                    network_id,
                    recipient,
                    nonce,
                    amount,
                    fee,
                    expires_at,
                    self_contained,
                    submit_to,
                )
            }
            HYBRID_VERSION => {
                if !self_contained {
                    return Err(
                        "QZKW2 Q6HA requires self-contained hybrid account authentication".into(),
                    );
                }
                if submit_to.is_some() {
                    return Err("QZKW2 Q6HA transactions cannot use legacy QZTS/1; use the Q6TI Noise options".into());
                }
                sign_transfer_hybrid(
                    path,
                    network_id,
                    recipient,
                    nonce,
                    amount,
                    fee,
                    expires_at,
                    qfp6_submit,
                )
            }
            other => Err(format!("unsupported QZKW wallet version: {other}")),
        }
    }

    fn sign_transfer_legacy(
        path: &Path,
        network_id: [u8; 32],
        recipient: [u8; 32],
        nonce: u64,
        amount: u64,
        fee: u64,
        expires_at: u64,
        self_contained: bool,
        submit_to: Option<SocketAddr>,
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
        if self_contained {
            signer
                .sign_transaction_self_contained(&mut transaction)
                .map_err(|error| format!("self-contained transaction signing failed: {error:?}"))?;
        } else {
            signer
                .sign_transaction(&mut transaction)
                .map_err(|error| format!("registered transaction signing failed: {error:?}"))?;
        }
        let digest = transaction_signing_digest(&transaction)
            .map_err(|error| format!("transaction signing digest failed: {error:?}"))?;
        let txid = transaction_id(&transaction)
            .map_err(|error| format!("transaction ID derivation failed: {error:?}"))?;
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
        println!("tx_id_hex={}", hex(&txid));
        println!("tx_signature_hex={}", hex(&transaction.signature));
        println!("tx_wire_hex={}", hex(&encoded));
        println!(
            "tx_signature_mode={}",
            if self_contained {
                "self-contained-ed25519-v1"
            } else {
                "registered-ed25519-v1"
            }
        );
        if let Some(address) = submit_to {
            let request = encode_request(&encoded)
                .map_err(|error| format!("encode bounded QZTS/1 transaction request: {error:?}"))?;
            let mut stream =
                TcpStream::connect_timeout(&address, std::time::Duration::from_secs(5)).map_err(
                    |error| format!("connect to transaction-ingress endpoint {address}: {error}"),
                )?;
            stream
                .set_nodelay(true)
                .map_err(|error| format!("configure TXN2 submission TCP_NODELAY: {error}"))?;
            stream
                .set_read_timeout(Some(std::time::Duration::from_secs(180)))
                .map_err(|error| format!("set TXN2 submission ACK timeout: {error}"))?;
            stream
                .set_write_timeout(Some(std::time::Duration::from_secs(10)))
                .map_err(|error| format!("set TXN2 submission write timeout: {error}"))?;
            stream
                .write_all(&request)
                .map_err(|error| format!("send signed TXN2 request: {error}"))?;
            let mut ack_bytes = [0u8; ACK_BYTES];
            stream
                .read_exact(&mut ack_bytes)
                .map_err(|error| format!("read QZTS/1 admission acknowledgement: {error}"))?;
            let ack = decode_ack(&ack_bytes)
                .map_err(|error| format!("decode QZTS/1 admission acknowledgement: {error:?}"))?;
            if ack.transaction_id != txid {
                return Err(
                    "QZTS/1 admission ACK TXID does not match the signed transaction".into(),
                );
            }
            println!("tx_submit_mempool_count={}", ack.mempool_count);
            println!("tx_submit_transaction_id_hex={}", hex(&ack.transaction_id));
            match ack.status {
                TxIngressStatus::Accepted => println!("tx_submit_status=accepted"),
                TxIngressStatus::Duplicate => println!("tx_submit_status=duplicate"),
                TxIngressStatus::Rejected => {
                    println!("tx_submit_status=rejected");
                    return Err("node transaction ingress rejected the signed transaction".into());
                }
            }
        } else {
            println!("tx_submit_status=not_attempted_submit_to_not_set");
        }
        Ok(())
    }

    fn sign_transfer_hybrid(
        path: &Path,
        network_id: [u8; 32],
        recipient: [u8; 32],
        nonce: u64,
        amount: u64,
        fee: u64,
        expires_at: u64,
        qfp6_submit: Option<Qfp6SubmitOptions>,
    ) -> Result<(), String> {
        let wallet = load_hybrid_wallet(path)?;
        if wallet.account_id == recipient {
            return Err("recipient must differ from the wallet account".into());
        }
        let signer =
            QRunV06HybridTransactionSigner::from_seeds(wallet.seeds.ed25519, wallet.seeds.mldsa65)
                .map_err(|e| format!("QFP6 hybrid signer initialization failed: {e:?}"))?;
        let mut tx = Transaction {
            network_id,
            sender: wallet.account_id,
            recipient,
            nonce,
            amount,
            fee,
            expires_at,
            signature: Vec::new(),
        };
        signer
            .sign_transaction(&mut tx)
            .map_err(|e| format!("QFP6 Q6HA transaction signing failed: {e:?}"))?;
        let digest = transaction_signing_digest(&tx)
            .map_err(|e| format!("transaction digest failed: {e:?}"))?;
        let txid = transaction_id_with_signature_limit(&tx, QRUN_V06_MAX_NATIVE_TX_SIGNATURE_BYTES)
            .map_err(|e| format!("QFP6 transaction ID derivation failed: {e:?}"))?;
        let encoded =
            encode_transaction_with_signature_limit(&tx, QRUN_V06_MAX_NATIVE_TX_SIGNATURE_BYTES)
                .map_err(|e| format!("QFP6 NativeTransfer encoding failed: {e:?}"))?;
        println!("wallet_protocol=QFP6_Q6HA_v1");
        println!("tx_network_id_hex={}", hex(&network_id));
        println!("tx_sender_account_id_hex={}", hex(&wallet.account_id));
        println!(
            "tx_sender_ed25519_public_key_hex={}",
            hex(&wallet.ed25519_public_key)
        );
        println!(
            "tx_sender_mldsa65_public_key_hex={}",
            hex(&wallet.mldsa65_public_key)
        );
        println!("tx_recipient_id_hex={}", hex(&recipient));
        println!("tx_nonce={nonce}");
        println!("tx_amount_atoms={amount}");
        println!("tx_fee_atoms={fee}");
        println!("tx_expires_at={expires_at}");
        println!("tx_signing_digest_hex={}", hex(&digest));
        println!("tx_id_hex={}", hex(&txid));
        println!("tx_signature_scheme=Q6HA-v1-suite-1-requires-Ed25519-and-ML-DSA-65");
        println!("tx_signature_bytes={}", tx.signature.len());
        println!("tx_wire_bytes={}", encoded.len());
        println!("tx_wire_sha256={}", hex(&Sha256::digest(&encoded)));
        println!("tx_signature_hex={}", hex(&tx.signature));
        println!("tx_wire_hex={}", hex(&encoded));
        if let Some(options) = qfp6_submit {
            let acknowledgement = submit_q6ti_over_noise(&options, &network_id, &tx, &txid)?;
            println!("tx_submit_protocol=Q6TI_Q6TA_over_pinned_Noise_XX");
            println!("tx_submit_request_id_status=one_shot_random_nonzero");
            println!(
                "tx_submit_transaction_id_hex={}",
                hex(&acknowledgement.transaction_id)
            );
            println!("tx_submit_mempool_count={}", acknowledgement.mempool_count);
            println!("tx_submit_mempool_bytes={}", acknowledgement.mempool_bytes);
            println!(
                "tx_submit_canonical_height={}",
                acknowledgement.canonical_height
            );
            println!(
                "tx_submit_canonical_tip_hex={}",
                hex(&acknowledgement.canonical_tip)
            );
            println!(
                "tx_submit_canonical_state_root_hex={}",
                hex(&acknowledgement.canonical_state_root)
            );
            match acknowledgement.status {
                QRunV06TransactionSubmitStatus::Accepted => {
                    println!("tx_submit_status=accepted_pending_mempool");
                    println!("tx_submit_finality=pending_only_not_confirmed");
                }
                QRunV06TransactionSubmitStatus::Duplicate => {
                    println!("tx_submit_status=duplicate_pending");
                    println!("tx_submit_finality=pending_only_not_confirmed");
                }
                QRunV06TransactionSubmitStatus::Rejected => {
                    println!("tx_submit_status=rejected");
                    return Err("QFP6 Q6TI ingress rejected the signed hybrid transaction".into());
                }
            }
        } else {
            println!("tx_submit_status=not_attempted_qfp6_noise_options_not_set");
            println!("network_status=offline_signed_candidate_not_broadcast");
        }
        Ok(())
    }

    pub fn run() {
        let result = match parse_command() {
            Ok(Command::Help) => {
                println!("QZXB native wallet (Windows CurrentUser DPAPI)\n\
Usage:\n\
  qzxb_wallet create --output ABSOLUTE_PATH\n\
  qzxb_wallet address --wallet ABSOLUTE_PATH\n\
  qzxb_wallet sign-transfer --wallet ABSOLUTE_PATH --network-id-hex HEX64 --recipient-id-hex HEX64 --nonce U64 --amount-atoms U64 --fee-atoms U64 --expires-at UNIX_SECONDS [--signature-mode self-contained|registered] [--submit-to IP:PORT]\n\
Default signature mode embeds the public key with its Ed25519 signature so the sender account can be derived and checked by any validating node. `--signature-mode registered` is for legacy fixtures. `--submit-to` sends signed TXN2 using QZTS/1 and waits for the node's admission ACK; this does not imply Mainnet status or that the transaction was mined.");
                println!("QZKW2 commands: create-qfp6-hybrid, restore-qfp6-hybrid, address-qfp6-hybrid. They use Q6HA dual signatures; sign-transfer creates an offline candidate only and refuses QZTS/1 broadcast.");
                println!("Read-only local RPC: rpc-status --rpc 127.0.0.1:PORT; balance --rpc 127.0.0.1:PORT --account-id-hex HEX64; tx-status --rpc 127.0.0.1:PORT --txid-hex HEX64. These queries are restricted to loopback and require an explicitly read-only RPC response.");
                Ok(())
            }
            Ok(Command::Create { output }) => create_wallet(&output),
            Ok(Command::Restore { output }) => restore_wallet(&output),
            Ok(Command::CreateHybrid { output }) => create_hybrid_wallet(&output),
            Ok(Command::RestoreHybrid { output }) => restore_hybrid_wallet(&output),
            Ok(Command::HybridAddress { wallet }) => hybrid_address(&wallet),
            Ok(Command::Address { wallet }) => address(&wallet),
            Ok(Command::RpcStatus { rpc }) => rpc_status(rpc),
            Ok(Command::Balance { rpc, account_id }) => rpc_balance(rpc, account_id),
            Ok(Command::TransactionStatus { rpc, txid }) => rpc_transaction_status(rpc, txid),
            Ok(Command::SignTransfer {
                wallet,
                network_id,
                recipient,
                nonce,
                amount,
                fee,
                expires_at,
                self_contained,
                submit_to,
                qfp6_submit,
            }) => sign_transfer(
                &wallet,
                network_id,
                recipient,
                nonce,
                amount,
                fee,
                expires_at,
                self_contained,
                submit_to,
                qfp6_submit,
            ),
            Ok(Command::CreateNoiseIdentity { output }) => create_noise_identity(&output),
            Ok(Command::NoiseIdentity { identity }) => noise_identity_info(&identity),
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
        fn candidate_rpc_client_rejects_non_loopback_addresses() {
            assert!(parse_rpc_address("127.0.0.1:49339").is_ok());
            assert!(parse_rpc_address("[::1]:49339").is_ok());
            assert!(parse_rpc_address("0.0.0.0:49339").is_err());
            assert!(parse_rpc_address("192.0.2.1:49339").is_err());
            assert!(parse_rpc_address("localhost:49339").is_err());
        }

        #[test]
        fn candidate_rpc_client_requires_bounded_canonical_json_response() {
            let body = r#"{"ok":true,"mainnet":false,"read_only":true,"height":2}"#;
            let good = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(), body
            );
            let value = parse_rpc_http_response(good.as_bytes()).unwrap();
            assert_eq!(value["height"].as_u64(), Some(2));

            let mainnet = r#"{"ok":true,"mainnet":true,"read_only":true}"#;
            let mainnet_response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                mainnet.len(),
                mainnet
            );
            let parsed_mainnet = parse_rpc_http_response(mainnet_response.as_bytes()).unwrap();
            assert_eq!(parsed_mainnet["mainnet"].as_bool(), Some(true));

            let too_short = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 99\r\n\r\n{}";
            assert!(parse_rpc_http_response(too_short).is_err());
            let error_status = b"HTTP/1.1 503 Service Unavailable\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}";
            assert!(parse_rpc_http_response(error_status).is_err());
            assert!(parse_rpc_http_response(&vec![65u8; MAX_RPC_RESPONSE_BYTES + 1]).is_err());
        }

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
        fn bip39_recovery_derivation_is_deterministic_and_checks_the_phrase() {
            let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
            let a = bip39::Mnemonic::parse_in(bip39::Language::English, phrase).unwrap();
            let b = bip39::Mnemonic::parse_in(bip39::Language::English, phrase).unwrap();
            let seed_a = derive_signing_seed(&a);
            let seed_b = derive_signing_seed(&b);
            let signer_a = Ed25519TransactionSigner::from_seed(seed_a.0);
            let signer_b = Ed25519TransactionSigner::from_seed(seed_b.0);
            assert_eq!(signer_a.public_key(), signer_b.public_key());
            assert_eq!(signer_a.account_id(), signer_b.account_id());
            assert!(bip39::Mnemonic::parse_in(
                bip39::Language::English,
                "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon"
            ).is_err());
        }

        #[test]
        fn qfp6_hybrid_bip39_derivation_is_deterministic_and_separate_from_legacy_identity() {
            let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
            let a = bip39::Mnemonic::parse_in(bip39::Language::English, phrase).unwrap();
            let b = bip39::Mnemonic::parse_in(bip39::Language::English, phrase).unwrap();
            let seeds_a = derive_hybrid_seeds(&a);
            let seeds_b = derive_hybrid_seeds(&b);
            assert_ne!(seeds_a.ed25519, seeds_a.mldsa65);
            assert_eq!(seeds_a.ed25519, seeds_b.ed25519);
            assert_eq!(seeds_a.mldsa65, seeds_b.mldsa65);
            let signer_a =
                QRunV06HybridTransactionSigner::from_seeds(seeds_a.ed25519, seeds_a.mldsa65)
                    .unwrap();
            let signer_b =
                QRunV06HybridTransactionSigner::from_seeds(seeds_b.ed25519, seeds_b.mldsa65)
                    .unwrap();
            assert_eq!(signer_a.ed25519_public_key(), signer_b.ed25519_public_key());
            assert_eq!(signer_a.mldsa65_public_key(), signer_b.mldsa65_public_key());
            assert_eq!(signer_a.account_id(), signer_b.account_id());
            let legacy_seed = derive_signing_seed(&a);
            let legacy_signer = Ed25519TransactionSigner::from_seed(legacy_seed.0);
            assert_ne!(signer_a.account_id(), legacy_signer.account_id());
        }

        #[test]
        fn qfp6_hybrid_wallet_dpapi_roundtrip_and_public_identity_binding() {
            let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
            let mnemonic = bip39::Mnemonic::parse_in(bip39::Language::English, phrase).unwrap();
            let seeds = derive_hybrid_seeds(&mnemonic);
            let path = std::env::temp_dir().join(format!(
                "qzkw2-hybrid-{}-{}.qzw",
                process::id(),
                NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed)
            ));
            let _ = fs::remove_file(&path);
            save_hybrid_wallet(&path, &seeds, None).unwrap();
            let loaded = load_hybrid_wallet(&path).unwrap();
            assert_eq!(loaded.seeds.ed25519, seeds.ed25519);
            assert_eq!(loaded.seeds.mldsa65, seeds.mldsa65);
            assert_eq!(wallet_version(&path).unwrap(), HYBRID_VERSION);
            let mut tampered = fs::read(&path).unwrap();
            tampered[38] ^= 1;
            fs::write(&path, tampered).unwrap();
            assert!(load_hybrid_wallet(&path).is_err());
            fs::remove_file(&path).unwrap();
        }

        #[test]
        fn qfp6_hybrid_wallet_signs_and_verifies_qfb6_transfer_but_legacy_codec_rejects_it() {
            use ai_native_l1_pow_bench::{
                qrun_v06_hybrid_auth_candidate::QRunV06HybridTransactionAuthenticator,
                state_machine::TransactionAuthenticator,
                v4_fat1_mldsa65_candidate::LibcruxMlDsa65VerifierCandidate,
            };
            let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
            let mnemonic = bip39::Mnemonic::parse_in(bip39::Language::English, phrase).unwrap();
            let seeds = derive_hybrid_seeds(&mnemonic);
            let signer =
                QRunV06HybridTransactionSigner::from_seeds(seeds.ed25519, seeds.mldsa65).unwrap();
            let mut tx = Transaction {
                network_id: [0xA1; 32],
                sender: signer.account_id(),
                recipient: [0xC3; 32],
                nonce: 1,
                amount: 10_000,
                fee: 100,
                expires_at: 2_000_000_000,
                signature: Vec::new(),
            };
            signer.sign_transaction(&mut tx).unwrap();
            let digest = transaction_signing_digest(&tx).unwrap();
            let verifier =
                QRunV06HybridTransactionAuthenticator::new(LibcruxMlDsa65VerifierCandidate);
            assert_eq!(verifier.verify(&tx.sender, &digest, &tx.signature), Ok(()));
            assert_eq!(tx.signature.len(), 5_365);
            assert!(encode_transaction(&tx).is_err());
            let qfp6_wire = encode_transaction_with_signature_limit(
                &tx,
                QRUN_V06_MAX_NATIVE_TX_SIGNATURE_BYTES,
            )
            .unwrap();
            assert!(!qfp6_wire.is_empty());
            assert!(transaction_id_with_signature_limit(
                &tx,
                QRUN_V06_MAX_NATIVE_TX_SIGNATURE_BYTES
            )
            .is_ok());
            let wallet_path = std::env::temp_dir().join(format!(
                "qzkw2-legacy-submit-{}-{}.qzw",
                process::id(),
                NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed)
            ));
            let _ = fs::remove_file(&wallet_path);
            save_hybrid_wallet(&wallet_path, &seeds, None).unwrap();
            assert!(sign_transfer(
                &wallet_path,
                [0xA1; 32],
                [0xC3; 32],
                1,
                10_000,
                100,
                2_000_000_000,
                true,
                Some("127.0.0.1:49340".parse().unwrap()),
                None,
            )
            .unwrap_err()
            .contains("legacy QZTS/1"));
            fs::remove_file(&wallet_path).unwrap();
        }

        #[test]
        fn qfp6_noise_identity_dpapi_roundtrip_binds_private_key_to_public_key() {
            let identity_path = std::env::temp_dir().join(format!(
                "q6nk-noise-identity-{}-{}.q6nk",
                process::id(),
                NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed)
            ));
            let _ = fs::remove_file(&identity_path);
            create_noise_identity(&identity_path).unwrap();
            let identity = load_noise_identity(&identity_path).unwrap();
            assert_eq!(identity.identity_id, q6nk_identity_id(&identity.public_key));

            let params: snow::params::NoiseParams =
                "Noise_XX_25519_ChaChaPoly_SHA256".parse().unwrap();
            let mut pair = snow::Builder::new(params).generate_keypair().unwrap();
            let mut server_private = [0u8; 32];
            let mut server_public = [0u8; 32];
            server_private.copy_from_slice(&pair.private);
            server_public.copy_from_slice(&pair.public);
            pair.private.fill(0);
            pair.public.fill(0);

            let network_id = [0xD1; 32];
            let profile_id = [0xD2; 32];
            let trusted_client_public = identity.public_key;
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            let server = std::thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                let trusted = [trusted_client_public];
                QRunV06NoiseSession::accept(
                    &mut stream,
                    &server_private,
                    &trusted,
                    &network_id,
                    &profile_id,
                )
                .unwrap()
                .remote_static_public_key()
                .to_owned()
            });

            let mut stream = std::net::TcpStream::connect(address).unwrap();
            let client = QRunV06NoiseSession::connect(
                &mut stream,
                &identity.private_key.0,
                &server_public,
                &network_id,
                &profile_id,
            )
            .unwrap();
            assert_eq!(client.remote_static_public_key(), &server_public);
            assert_eq!(server.join().unwrap(), identity.public_key);
            fs::remove_file(&identity_path).unwrap();
        }

        #[test]
        fn qzkw2_header_and_secret_lengths_are_stable() {
            assert_eq!(HYBRID_HEADER_LEN, 2_026);
            assert_eq!(HYBRID_HEADER_LEN + MAX_PROTECTED_BLOB, MAX_FILE_LEN + 1_952);
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
