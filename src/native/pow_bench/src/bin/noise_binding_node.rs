use ai_native_l1_pow_bench::{
    credential_binding::{session_identity_context, CredentialBinding},
    identity_policy::{KeyAlgorithm, KeyPurpose, KeyRecord, KeyState},
};
use snow::Builder;
use std::{
    env,
    io::{self, Read, Write},
    net::{TcpListener, TcpStream},
    time::{Duration, Instant},
};
const PATTERN: &str = "Noise_NNpsk0_25519_ChaChaPoly_SHA256";
const PROLOGUE: &[u8] = b"AI-NATIVE-L1/transport-v0.1";
const PSK: [u8; 32] = [0x61; 32];
const IO_MS: u64 = 1500;
fn val(a: &[String], n: &str) -> Option<String> {
    a.windows(2).find(|x| x[0] == n).map(|x| x[1].clone())
}
fn num<T: std::str::FromStr>(a: &[String], n: &str, d: T) -> T {
    val(a, n).and_then(|x| x.parse().ok()).unwrap_or(d)
}
fn binding(id: u128) -> CredentialBinding {
    let k = KeyRecord {
        key_id: 7,
        generation: 2,
        algorithm: KeyAlgorithm::MlDsa65,
        purpose: KeyPurpose::PeerAuth,
        state: KeyState::Active,
        not_before: 10,
        not_after: 100,
        public_key: vec![1, 2, 3],
    };
    CredentialBinding::from_key(id, 5, &k, &[8, 9])
}
fn build(init: bool) -> snow::HandshakeState {
    let b = Builder::new(PATTERN.parse().unwrap())
        .prologue(PROLOGUE)
        .psk(0, &PSK);
    if init {
        b.build_initiator().unwrap()
    } else {
        b.build_responder().unwrap()
    }
}

fn read_full(s: &mut TcpStream, b: &mut [u8]) -> io::Result<()> {
    let d = Instant::now() + Duration::from_millis(IO_MS);
    let mut p = 0;
    while p < b.len() {
        if Instant::now() >= d {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "budget"));
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
fn write_rec(s: &mut TcpStream, b: &[u8]) -> io::Result<()> {
    s.write_all(&(b.len() as u32).to_be_bytes())?;
    s.write_all(b)
}
fn read_rec(s: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut h = [0u8; 4];
    read_full(s, &mut h)?;
    let n = u32::from_be_bytes(h) as usize;
    if n > 128 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "context too large",
        ));
    }
    let mut b = vec![0u8; n];
    read_full(s, &mut b)?;
    Ok(b)
}
fn server(mut s: TcpStream, id: u128) {
    let mut hs = build(false);
    let mut inb = [0u8; 1024];
    let mut out = [0u8; 1024];
    let mut l = [0u8; 2];
    if read_full(&mut s, &mut l).is_err() {
        return;
    }
    let n = u16::from_be_bytes(l) as usize;
    if n > 1024 {
        return;
    }
    if read_full(&mut s, &mut inb[..n]).is_err() {
        return;
    }
    let hn = match hs.read_message(&inb[..n], &mut out) {
        Ok(x) => x,
        Err(_) => {
            eprintln!("event=handshake_reject");
            return;
        }
    };
    let _ = hn;
    let n = hs.write_message(&[], &mut out).unwrap();
    let _ = s.write_all(&(n as u16).to_be_bytes());
    let _ = s.write_all(&out[..n]);
    let hh = hs.get_handshake_hash().to_vec();
    let mut t = match hs.into_transport_mode() {
        Ok(x) => x,
        Err(_) => return,
    };
    let b = binding(id);
    let ctx = session_identity_context(&b, &hh);
    let mut app = vec![1u8];
    app.extend_from_slice(&ctx);
    let mut c = [0u8; 128];
    let n = t.write_message(&app, &mut c).unwrap();
    let _ = write_rec(&mut s, &c[..n]);
    eprintln!("event=binding_context_sent");
}

fn client(port: u16, expected_id: u128) -> bool {
    let mut s = match TcpStream::connect(("127.0.0.1", port)) {
        Ok(x) => x,
        Err(_) => return false,
    };
    let mut hs = build(true);
    let mut out = [0u8; 1024];
    let n = hs.write_message(&[], &mut out).unwrap();
    if s.write_all(&(n as u16).to_be_bytes())
        .and_then(|_| s.write_all(&out[..n]))
        .is_err()
    {
        return false;
    }
    let mut l = [0u8; 2];
    if read_full(&mut s, &mut l).is_err() {
        return false;
    }
    let n = u16::from_be_bytes(l) as usize;
    if read_full(&mut s, &mut out[..n]).is_err() {
        return false;
    }
    if hs.read_message(&out[..n], &mut [0u8; 1024]).is_err() {
        return false;
    }
    let hh = hs.get_handshake_hash().to_vec();
    let mut t = match hs.into_transport_mode() {
        Ok(x) => x,
        Err(_) => return false,
    };
    let b = binding(expected_id);
    let expected = session_identity_context(&b, &hh);
    let rec = match read_rec(&mut s) {
        Ok(x) => x,
        Err(_) => return false,
    };
    let mut plain = [0u8; 128];
    let n = match t.read_message(&rec, &mut plain) {
        Ok(x) => x,
        Err(_) => return false,
    };
    if n != 33 || plain[0] != 1 || plain[1..n] != expected {
        return false;
    }
    true
}

fn main() {
    let a: Vec<String> = env::args().collect();
    let is_server = a.iter().any(|x| x == "--server");
    let port = num(&a, "--port", 44801);
    let id = val(&a, "--credential-id")
        .and_then(|x| x.parse().ok())
        .unwrap_or(99u128);
    if is_server {
        let l = TcpListener::bind(("127.0.0.1", port)).unwrap();
        l.set_nonblocking(true).unwrap();
        let d = Instant::now() + Duration::from_millis(4000);
        eprintln!("event=ready");
        while Instant::now() < d {
            match l.accept() {
                Ok((s, _)) => {
                    server(s, id);
                    break;
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(10))
                }
                Err(_) => break,
            }
        }
    } else {
        if client(port, id) {
            eprintln!("event=binding_context_match")
        } else {
            eprintln!("event=binding_context_mismatch_or_fail");
            std::process::exit(2)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_context_changes_with_credential() {
        let b = binding(99);
        let c = binding(100);
        let h = [7u8; 32];
        assert_ne!(
            session_identity_context(&b, &h),
            session_identity_context(&c, &h)
        );
    }

    #[test]
    fn initiator_and_responder_share_handshake_bound_context() {
        let mut i = build(true);
        let mut r = build(false);
        let mut ib = [0u8; 1024];
        let mut rb = [0u8; 1024];
        let n1 = i.write_message(&[], &mut ib).unwrap();
        r.read_message(&ib[..n1], &mut rb).unwrap();
        let n2 = r.write_message(&[], &mut rb).unwrap();
        i.read_message(&rb[..n2], &mut ib).unwrap();
        let hi = i.get_handshake_hash().to_vec();
        let hr = r.get_handshake_hash().to_vec();
        assert_eq!(hi, hr);
        let b = binding(99);
        assert_eq!(
            session_identity_context(&b, &hi),
            session_identity_context(&b, &hr)
        );
    }
}
