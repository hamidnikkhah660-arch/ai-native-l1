use ai_native_l1_pow_bench::{
    canonical_provider::CanonicalPublicKeyProvider,
    identity_policy::{CryptoPolicy, KeyAlgorithm, KeyPurpose, KeyRecord, KeyState, SecurityClass},
    key_provider::{InMemoryPublicKeyProvider, PublicKeyProvider},
};
use sha2::{Digest, Sha256};
use snow::Builder;
use std::{
    env,
    io::{self, Read, Write},
    net::TcpStream,
    time::{Duration, Instant},
};
const PATTERN: &str = "Noise_NNpsk0_25519_ChaChaPoly_SHA256";
const PROLOGUE: &[u8] = b"AI-NATIVE-L1/transport-v0.1";
const PSK: [u8; 32] = [0x61; 32];
const MAX_HS: usize = 1024;
const MAX_NOISE: usize = 4 * 1024 * 1024 + 128;
const CTX_LEN: usize = 32;
const REQ: u8 = 0xC1;
const RESP: u8 = 0xC2;
fn arg(a: &[String], n: &str) -> Option<String> {
    a.windows(2).find(|x| x[0] == n).map(|x| x[1].clone())
}
fn num<T: std::str::FromStr>(a: &[String], n: &str, d: T) -> T {
    arg(a, n).and_then(|x| x.parse().ok()).unwrap_or(d)
}
fn full(s: &mut TcpStream, b: &mut [u8]) -> io::Result<()> {
    let d = Instant::now() + Duration::from_millis(1800);
    let mut p = 0;
    while p < b.len() {
        if Instant::now() >= d {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "deadline"));
        }
        match s.read(&mut b[p..]) {
            Ok(0) => return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "closed")),
            Ok(n) => p += n,
            Err(e) if e.kind() == io::ErrorKind::TimedOut => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(())
}
fn wb(s: &mut TcpStream, b: &[u8]) -> io::Result<()> {
    s.write_all(&(b.len() as u16).to_be_bytes())?;
    s.write_all(b)
}
fn rb(s: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut h = [0u8; 2];
    full(s, &mut h)?;
    let n = u16::from_be_bytes(h) as usize;
    if n > MAX_HS {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "hs_oversize"));
    }
    let mut b = vec![0u8; n];
    full(s, &mut b)?;
    Ok(b)
}
fn wr(s: &mut TcpStream, b: &[u8]) -> io::Result<()> {
    if b.len() > MAX_NOISE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "noise_oversize",
        ));
    }
    s.write_all(&(b.len() as u32).to_be_bytes())?;
    s.write_all(b)
}
fn rr(s: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut h = [0u8; 4];
    full(s, &mut h)?;
    let n = u32::from_be_bytes(h) as usize;
    if n > MAX_NOISE {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "noise_oversize"));
    }
    let mut b = vec![0u8; n];
    full(s, &mut b)?;
    Ok(b)
}
fn sha(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p)
    }
    h.finalize().into()
}

fn expected_context(generation: u32) -> [u8; 32] {
    let transport = sha(&[b"AIN1-PEER-KEY\0", &(2u16).to_be_bytes(), &[8, 9]]);
    sha(&[
        b"AIN1-IDENTITY\0",
        &(99u128).to_be_bytes(),
        &(5u32).to_be_bytes(),
        &(7u32).to_be_bytes(),
        &generation.to_be_bytes(),
        &(100u16).to_be_bytes(),
        &transport,
    ])
}
fn session_context(generation: u32, hh: &[u8]) -> [u8; 32] {
    let id = expected_context(generation);
    sha(&[b"AIN1-IDENTITY-SESSION\0", &id, hh])
}
fn frame(msg: u16, id: u64) -> Vec<u8> {
    let mut f = Vec::with_capacity(20);
    f.extend_from_slice(b"AIN1");
    f.extend_from_slice(&1u16.to_be_bytes());
    f.extend_from_slice(&msg.to_be_bytes());
    f.extend_from_slice(&id.to_be_bytes());
    f.extend_from_slice(&0u32.to_be_bytes());
    f
}
fn main() {
    let a: Vec<String> = env::args().collect();
    let port: u16 = num(&a, "--port", 44831);
    let generation: u32 = num(&a, "--generation", 2);
    let attack = arg(&a, "--attack").unwrap_or_else(|| "none".to_string());
    let provider_generation: u32 = num(&a, "--provider-generation", generation);
    let provider_revoked = a.iter().any(|x| x == "--provider-revoked");
    let provider_mode = arg(&a, "--provider").unwrap_or_else(|| "memory".to_string());
    let record = KeyRecord {
        key_id: 7,
        generation: provider_generation,
        algorithm: KeyAlgorithm::MlDsa65,
        purpose: KeyPurpose::PeerAuth,
        state: if provider_revoked {
            KeyState::Revoked
        } else {
            KeyState::Active
        },
        not_before: 10,
        not_after: 100,
        public_key: vec![1, 2, 3],
    };
    let provider: Box<dyn PublicKeyProvider> = match provider_mode.as_str() {
        "canonical" => Box::new(
            CanonicalPublicKeyProvider::from_encoded(vec![
                ai_native_l1_pow_bench::identity_policy::encode(&record).unwrap(),
            ])
            .unwrap(),
        ),
        "memory" => Box::new(InMemoryPublicKeyProvider::new(vec![record]).unwrap()),
        _ => {
            eprintln!("event=unknown_provider mode={provider_mode}");
            std::process::exit(2);
        }
    };
    let record = match provider.authorize(
        7,
        provider_generation,
        KeyPurpose::PeerAuth,
        20,
        CryptoPolicy {
            min_class: SecurityClass::Pq,
            pq_lock_epoch: Some(50),
        },
    ) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("event=provider_authorization_rejected reason={e:?}");
            std::process::exit(2);
        }
    };
    let mut s = match TcpStream::connect(("127.0.0.1", port)) {
        Ok(x) => x,
        Err(e) => {
            eprintln!("event=connect_fail err={e}");
            std::process::exit(2)
        }
    };
    let _ = s.set_read_timeout(Some(Duration::from_millis(1800)));
    let _ = s.set_write_timeout(Some(Duration::from_millis(1800)));
    let b = Builder::new(PATTERN.parse().unwrap())
        .prologue(PROLOGUE)
        .psk(0, &PSK);
    let mut hs = b.build_initiator().unwrap();
    let mut hb = [0u8; MAX_HS];
    let n = match hs.write_message(&[], &mut hb) {
        Ok(x) => x,
        Err(e) => {
            eprintln!("event=handshake_write_fail err={e}");
            std::process::exit(2)
        }
    };
    if let Err(e) = wb(&mut s, &hb[..n]) {
        eprintln!("event=handshake_send_fail err={e}");
        std::process::exit(2)
    }
    let m = match rb(&mut s) {
        Ok(x) => x,
        Err(e) => {
            eprintln!("event=handshake_read_fail err={e}");
            std::process::exit(2)
        }
    };
    if let Err(e) = hs.read_message(&m, &mut hb) {
        eprintln!("event=handshake_verify_fail err={e}");
        std::process::exit(2)
    }
    let hh = hs.get_handshake_hash().to_vec();
    if record.generation != generation {
        eprintln!(
            "event=provider_generation_mismatch provider_generation={} requested_generation={}",
            record.generation, generation
        );
        std::process::exit(2);
    }
    let ctx = session_context(record.generation, &hh);
    let mut t = match hs.into_transport_mode() {
        Ok(x) => x,
        Err(e) => {
            eprintln!("event=transport_mode_fail err={e}");
            std::process::exit(2)
        }
    };
    let q = frame(10, 9001);
    let mut app = Vec::with_capacity(1 + CTX_LEN + q.len());
    match attack.as_str() {
        "none" => {
            app.push(REQ);
            app.extend_from_slice(&ctx);
            app.extend_from_slice(&q);
        }
        "short" => {
            app.push(REQ);
        }
        "magic" => {
            app.push(0x7E);
            app.extend_from_slice(&ctx);
            app.extend_from_slice(&q);
        }
        "context" => {
            app.push(REQ);
            app.extend_from_slice(&[0xAA; CTX_LEN]);
            app.extend_from_slice(&q);
        }
        "frame" => {
            app.push(REQ);
            app.extend_from_slice(&ctx);
            app.extend_from_slice(b"bad");
        }
        "message" => {
            app.push(REQ);
            app.extend_from_slice(&ctx);
            app.extend_from_slice(&frame(2, 9001));
        }
        _ => {
            eprintln!("event=unknown_attack attack={attack}");
            std::process::exit(2);
        }
    }
    if attack != "none" {
        println!(
            "CP-0025-I-ATTACK SENT attack={} app_bytes={}",
            attack,
            app.len()
        );
    }
    let mut cb = vec![0u8; app.len() + 64];
    let n = match t.write_message(&app, &mut cb) {
        Ok(x) => x,
        Err(e) => {
            eprintln!("event=record_write_fail err={e}");
            std::process::exit(2)
        }
    };
    if let Err(e) = wr(&mut s, &cb[..n]) {
        eprintln!("event=record_send_fail err={e}");
        std::process::exit(2)
    }
    if attack != "none" {
        match rr(&mut s) {
            Ok(_) => {
                eprintln!("event=attack_unexpected_response attack={attack}");
                std::process::exit(2);
            }
            Err(_) => {
                println!(
                    "CP-0025-I-ATTACK PASS attack={} app_bytes={}",
                    attack,
                    app.len()
                );
                return;
            }
        }
    }
    let rec = match rr(&mut s) {
        Ok(x) => x,
        Err(e) => {
            eprintln!("event=no_response err={e}");
            std::process::exit(2)
        }
    };
    let mut plain = vec![0u8; MAX_NOISE];
    let n = match t.read_message(&rec, &mut plain) {
        Ok(x) => x,
        Err(e) => {
            eprintln!("event=decrypt_fail err={e}");
            std::process::exit(2)
        }
    };
    if n < 1 + CTX_LEN || plain[0] != RESP || plain[1..33] != ctx {
        eprintln!("event=context_mismatch");
        std::process::exit(2)
    }
    if plain.len() < n {
        std::process::exit(2)
    }
    if n < 55 {
        eprintln!("event=response_short");
        std::process::exit(2)
    }
    println!(
        "CP-0025-E-ALT PASS generation={} provider_generation={} response_bytes={} context_bound=1",
        generation, record.generation, n
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn context_changes_on_rotation() {
        assert_ne!(expected_context(2), expected_context(3));
    }
    #[test]
    fn frame_is_canonical() {
        assert_eq!(frame(10, 9001).len(), 20);
        assert_eq!(&frame(10, 9001)[0..4], b"AIN1");
    }
}
