//! Local candidate client for signing and submitting QZXB-native AMM operations.
//!
//! This is an explicit-submit, zero-value-testnet candidate tool. A QZAS acknowledgement means
//! only "accepted to the node's in-memory mempool", not block inclusion or settlement. Keep seed
//! files out of source control and use a dedicated testnet-only key.
use ai_native_l1_pow_bench::qzbe_amm_ingress_candidate::{
    decode_ack, encode_request, operation_id, AmmIngressStatus, AMM_INGRESS_ACK_BYTES,
};
use ai_native_l1_pow_bench::qzxb_amm_candidate::{AmmOperation, AmmSignedOperation};
use ai_native_l1_pow_bench::transaction_auth::Ed25519TransactionSigner;
use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::error::Error;
use std::fs;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::time::Duration;

const DEFAULT_ENDPOINT: &str = "127.0.0.1:49337";
const SELF_CONTAINED_SIGNATURE_BYTES: usize = 32 + 64;

fn usage() -> &'static str {
    "qzxb_amm_client --seed-file PATH [--show-account | --operation ACTION ...] [--submit]\n\
     Actions: register-asset --asset-id HEX64 | create-pair --token-a HEX64 --token-b HEX64 |\n\
     transfer-asset --asset-id HEX64 --recipient HEX64 --amount U128 |\n\
     add-liquidity --pair-id HEX64 --amount0 U128 --amount1 U128 --min-lp U128 |\n\
     remove-liquidity --pair-id HEX64 --shares U128 --min-amount0 U128 --min-amount1 U128 |\n\
     swap-exact-in --token-in HEX64 --token-out HEX64 --amount-in U128 --min-amount-out U128\n\
     Submission additionally requires --network-id HEX64 --nonce U64 --expires-at U64.\n\
     Endpoint defaults to 127.0.0.1:49337; non-loopback requires --allow-remote-testnet.\n\
     This tool targets the unaudited QZBE candidate/testnet only; it does not create or back USDT."
}

fn parse_options(
    args: impl Iterator<Item = String>,
) -> Result<(BTreeMap<String, String>, BTreeSet<String>), String> {
    let value_options: BTreeSet<&'static str> = [
        "--seed-file",
        "--network-id",
        "--nonce",
        "--expires-at",
        "--operation",
        "--endpoint",
        "--asset-id",
        "--token-a",
        "--token-b",
        "--recipient",
        "--amount",
        "--pair-id",
        "--amount0",
        "--amount1",
        "--min-lp",
        "--shares",
        "--min-amount0",
        "--min-amount1",
        "--token-in",
        "--token-out",
        "--amount-in",
        "--min-amount-out",
    ]
    .into_iter()
    .collect();
    let boolean_options: BTreeSet<&'static str> =
        ["--show-account", "--submit", "--allow-remote-testnet"]
            .into_iter()
            .collect();
    let mut values = BTreeMap::new();
    let mut flags = BTreeSet::new();
    let args: Vec<String> = args.collect();
    let mut i = 0usize;
    while i < args.len() {
        let key = args[i].as_str();
        if boolean_options.contains(key) {
            if !flags.insert(key.to_string()) {
                return Err(format!("duplicate option: {key}"));
            }
            i += 1;
            continue;
        }
        if !value_options.contains(key) {
            return Err(format!("unknown option: {key}"));
        }
        let value = args
            .get(i + 1)
            .ok_or_else(|| format!("missing value for {key}"))?;
        if value.starts_with("--") {
            return Err(format!("missing value for {key}"));
        }
        if values.insert(key.to_string(), value.clone()).is_some() {
            return Err(format!("duplicate option: {key}"));
        }
        i += 2;
    }
    Ok((values, flags))
}

fn required<'a>(values: &'a BTreeMap<String, String>, key: &str) -> Result<&'a str, String> {
    values
        .get(key)
        .map(String::as_str)
        .ok_or_else(|| format!("missing required option: {key}"))
}

fn parse_hex32(value: &str, name: &str) -> Result<[u8; 32], String> {
    let value = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .unwrap_or(value);
    if value.len() != 64 || !value.is_ascii() {
        return Err(format!("{name} must be exactly 64 hexadecimal characters"));
    }
    let mut out = [0u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let hi =
            hex_nibble(pair[0]).ok_or_else(|| format!("{name} contains non-hex characters"))?;
        let lo =
            hex_nibble(pair[1]).ok_or_else(|| format!("{name} contains non-hex characters"))?;
        out[index] = (hi << 4) | lo;
    }
    if out.iter().all(|byte| *byte == 0) {
        return Err(format!("{name} must not be zero"));
    }
    Ok(out)
}

fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

fn hex(bytes: &[u8]) -> String {
    const TABLE: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(TABLE[(byte >> 4) as usize] as char);
        out.push(TABLE[(byte & 0x0f) as usize] as char);
    }
    out
}

fn parse_u64(values: &BTreeMap<String, String>, key: &str) -> Result<u64, String> {
    required(values, key)?
        .parse::<u64>()
        .map_err(|_| format!("{key} must be a decimal u64"))
}

fn parse_u128(values: &BTreeMap<String, String>, key: &str) -> Result<u128, String> {
    required(values, key)?
        .parse::<u128>()
        .map_err(|_| format!("{key} must be a decimal u128"))
}

fn parse_seed(path: &str) -> Result<[u8; 32], String> {
    let raw = fs::read_to_string(path).map_err(|error| format!("read seed file: {error}"))?;
    let raw = raw.trim();
    if raw.len() != 64 || !raw.is_ascii() {
        return Err(
            "seed file must contain exactly 64 hex characters (a 32-byte Ed25519 seed)".into(),
        );
    }
    let mut seed = [0u8; 32];
    for (index, pair) in raw.as_bytes().chunks_exact(2).enumerate() {
        let hi = hex_nibble(pair[0])
            .ok_or_else(|| "seed file contains non-hex characters".to_string())?;
        let lo = hex_nibble(pair[1])
            .ok_or_else(|| "seed file contains non-hex characters".to_string())?;
        seed[index] = (hi << 4) | lo;
    }
    if seed.iter().all(|byte| *byte == 0) {
        return Err("all-zero seed is rejected".into());
    }
    Ok(seed)
}

fn build_operation(values: &BTreeMap<String, String>) -> Result<AmmOperation, String> {
    match required(values, "--operation")? {
        "register-asset" => Ok(AmmOperation::RegisterAsset {
            asset_id: parse_hex32(required(values, "--asset-id")?, "--asset-id")?,
        }),
        "create-pair" => Ok(AmmOperation::CreatePair {
            token_a: parse_hex32(required(values, "--token-a")?, "--token-a")?,
            token_b: parse_hex32(required(values, "--token-b")?, "--token-b")?,
        }),
        "transfer-asset" => Ok(AmmOperation::TransferAsset {
            asset_id: parse_hex32(required(values, "--asset-id")?, "--asset-id")?,
            recipient: parse_hex32(required(values, "--recipient")?, "--recipient")?,
            amount: parse_u128(values, "--amount")?,
        }),
        "add-liquidity" => Ok(AmmOperation::AddLiquidity {
            pair_id: parse_hex32(required(values, "--pair-id")?, "--pair-id")?,
            amount0_desired: parse_u128(values, "--amount0")?,
            amount1_desired: parse_u128(values, "--amount1")?,
            min_lp_shares: parse_u128(values, "--min-lp")?,
        }),
        "remove-liquidity" => Ok(AmmOperation::RemoveLiquidity {
            pair_id: parse_hex32(required(values, "--pair-id")?, "--pair-id")?,
            shares: parse_u128(values, "--shares")?,
            min_amount0_out: parse_u128(values, "--min-amount0")?,
            min_amount1_out: parse_u128(values, "--min-amount1")?,
        }),
        "swap-exact-in" => Ok(AmmOperation::SwapExactIn {
            token_in: parse_hex32(required(values, "--token-in")?, "--token-in")?,
            token_out: parse_hex32(required(values, "--token-out")?, "--token-out")?,
            amount_in: parse_u128(values, "--amount-in")?,
            min_amount_out: parse_u128(values, "--min-amount-out")?,
        }),
        action => Err(format!("unknown operation: {action}")),
    }
}

fn sign_operation(
    signer: &Ed25519TransactionSigner,
    network_id: [u8; 32],
    nonce: u64,
    expires_at: u64,
    operation: AmmOperation,
) -> Result<AmmSignedOperation, String> {
    let mut signed = AmmSignedOperation {
        network_id,
        sender: signer.account_id(),
        nonce,
        expires_at,
        operation,
        signature: vec![1], // placeholder only while deriving the digest; not encoded/submitted
    };
    let digest = signed.signing_digest().map_err(|error| error.to_string())?;
    let signature = signer.sign_digest(&digest);
    if signature.len() != 64 {
        return Err("unexpected Ed25519 signature width".into());
    }
    let public_key = signer.public_key();
    let mut self_contained = Vec::with_capacity(SELF_CONTAINED_SIGNATURE_BYTES);
    self_contained.extend_from_slice(&public_key);
    self_contained.extend_from_slice(&signature);
    signed.signature = self_contained;
    Ok(signed)
}

fn resolve_endpoint(endpoint: &str, allow_remote: bool) -> Result<SocketAddr, String> {
    let mut resolved = endpoint
        .to_socket_addrs()
        .map_err(|error| format!("resolve --endpoint: {error}"))?;
    let address = resolved
        .next()
        .ok_or_else(|| "endpoint resolved to no address".to_string())?;
    if !allow_remote && !address.ip().is_loopback() {
        return Err(
            "non-loopback endpoint requires --allow-remote-testnet (zero-value testnet only)"
                .into(),
        );
    }
    if address.port() == 0 || address.ip().is_multicast() || address.ip().is_unspecified() {
        return Err("endpoint must use a nonzero port and a concrete unicast address".into());
    }
    Ok(address)
}

fn submit(
    endpoint: &str,
    allow_remote: bool,
    signed: &AmmSignedOperation,
) -> Result<(), Box<dyn Error>> {
    let address = resolve_endpoint(endpoint, allow_remote)?;
    let signed_wire = signed.encode()?;
    let expected_id = operation_id(&signed_wire);
    let request = encode_request(signed)?;
    let mut stream = TcpStream::connect_timeout(&address, Duration::from_secs(5))?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    stream.write_all(&request)?;
    let mut ack_bytes = [0u8; AMM_INGRESS_ACK_BYTES];
    stream.read_exact(&mut ack_bytes)?;
    let ack = decode_ack(&ack_bytes)?;
    if ack.operation_id != expected_id {
        return Err(
            "node acknowledgement operation ID does not match the submitted operation".into(),
        );
    }
    println!(
        "ACK status={:?} mempool_count={} operation_id={}",
        ack.status,
        ack.mempool_count,
        hex(&ack.operation_id)
    );
    match ack.status {
        AmmIngressStatus::Accepted | AmmIngressStatus::Duplicate => {
            println!("NOTE: mempool acceptance is not block inclusion or finality.");
            Ok(())
        }
        AmmIngressStatus::Rejected | AmmIngressStatus::PoolFull => {
            Err(format!("node did not accept operation: {:?}", ack.status).into())
        }
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let args = env::args().skip(1);
    let (values, flags) = parse_options(args).map_err(|error| format!("{error}\n\n{}", usage()))?;
    let seed_path =
        required(&values, "--seed-file").map_err(|error| format!("{error}\n\n{}", usage()))?;
    let mut seed = parse_seed(seed_path)?;
    let signer = Ed25519TransactionSigner::from_seed(seed);
    seed.fill(0);

    if flags.contains("--show-account") {
        println!("account_id={}", hex(&signer.account_id()));
        println!("public_key={}", hex(&signer.public_key()));
        println!("signature_mode=self_contained_ed25519_96_bytes");
        println!("warning=keep the seed local; the account must have canonical QZXB and any quote asset balance needed by the requested operation");
        if values.contains_key("--operation") || flags.contains("--submit") {
            return Err("--show-account cannot be combined with --operation or --submit".into());
        }
        return Ok(());
    }

    let network_id = parse_hex32(required(&values, "--network-id")?, "--network-id")?;
    let nonce = parse_u64(&values, "--nonce")?;
    let expires_at = parse_u64(&values, "--expires-at")?;
    if nonce == 0 || expires_at == 0 {
        return Err("--nonce and --expires-at must be positive".into());
    }
    let operation = build_operation(&values)?;
    let signed = sign_operation(&signer, network_id, nonce, expires_at, operation)?;
    let signed_wire = signed.encode()?;
    let operation_digest = operation_id(&signed_wire);
    println!("network_id={}", hex(&network_id));
    println!("sender={}", hex(&signed.sender));
    println!("nonce={}", signed.nonce);
    println!("expires_at={}", signed.expires_at);
    println!("operation={:?}", signed.operation);
    println!("operation_id={}", hex(&operation_digest));
    println!("signed_qax1_hex={}", hex(&signed_wire));
    if flags.contains("--submit") {
        let endpoint = values
            .get("--endpoint")
            .map(String::as_str)
            .unwrap_or(DEFAULT_ENDPOINT);
        submit(endpoint, flags.contains("--allow-remote-testnet"), &signed)?;
    } else {
        println!("mode=dry-run; pass --submit to transmit to QZAS/1");
    }
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("qzxb_amm_client: {error}");
        std::process::exit(2);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ai_native_l1_pow_bench::state_machine::TransactionAuthenticator;
    use ai_native_l1_pow_bench::transaction_auth::{
        AccountPublicKey, Ed25519TransactionAuthenticator, Ed25519TransactionSigner,
        TransactionAuthenticatorKind, ED25519_SIGNATURE_LEN,
    };

    #[test]
    fn builds_self_contained_ed25519_qax1_and_verifies_digest() {
        let signer = Ed25519TransactionSigner::from_seed([0x42; 32]);
        let operation = AmmOperation::RegisterAsset {
            asset_id: [0x55; 32],
        };
        let signed = sign_operation(&signer, [0x31; 32], 1, 100, operation).unwrap();
        assert_eq!(signed.sender, signer.account_id());
        assert_eq!(signed.signature.len(), SELF_CONTAINED_SIGNATURE_BYTES);
        let digest = signed.signing_digest().unwrap();
        let authenticator = Ed25519TransactionAuthenticator::select_by_id(
            TransactionAuthenticatorKind::Ed25519V1 as u16,
            [AccountPublicKey {
                account_id: signer.account_id(),
                public_key: signer.public_key(),
            }],
        )
        .unwrap();
        assert_eq!(
            authenticator.verify(&signed.sender, &digest, &signed.signature),
            Ok(())
        );
        assert_eq!(signed.encode().unwrap().len() > 140, true);
        assert_eq!(ED25519_SIGNATURE_LEN, 64);
    }

    #[test]
    fn operation_encodings_bind_different_payloads_and_account_nonces() {
        let signer = Ed25519TransactionSigner::from_seed([0x42; 32]);
        let base = sign_operation(
            &signer,
            [0x31; 32],
            1,
            100,
            AmmOperation::SwapExactIn {
                token_in: [0x11; 32],
                token_out: [0x22; 32],
                amount_in: 1_000,
                min_amount_out: 1,
            },
        )
        .unwrap();
        let changed_nonce = sign_operation(
            &signer,
            [0x31; 32],
            2,
            100,
            AmmOperation::SwapExactIn {
                token_in: [0x11; 32],
                token_out: [0x22; 32],
                amount_in: 1_000,
                min_amount_out: 1,
            },
        )
        .unwrap();
        assert_ne!(
            base.signing_digest().unwrap(),
            changed_nonce.signing_digest().unwrap()
        );
        assert_ne!(base.encode().unwrap(), changed_nonce.encode().unwrap());
    }

    #[test]
    fn loopback_is_required_unless_remote_testnet_is_explicit() {
        assert!(resolve_endpoint("127.0.0.1:49337", false).is_ok());
        assert!(resolve_endpoint("0.0.0.0:49337", true).is_err());
    }
}
