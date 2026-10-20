use ai_native_l1_pow_bench::{
    chain_view::Header,
    credential_binding::{session_identity_context, CredentialBinding},
    decode_frame, encode_frame,
    identity_policy::{CryptoPolicy, KeyAlgorithm, KeyPurpose, KeyRecord, KeyState, SecurityClass},
    identity_session::{BoundSession, SessionError},
    key_provider::{InMemoryPublicKeyProvider, PublicKeyProvider},
    MessageType,
};
use snow::Builder;
use std::{
    io::{self, Read, Write},
    net::{TcpListener, TcpStream},
    sync::{mpsc, Arc, Mutex},
    thread,
    time::{Duration, Instant},
};

const PATTERN: &str = "Noise_NNpsk0_25519_ChaChaPoly_SHA256";
const PROLOGUE: &[u8] = b"AI-NATIVE-L1/transport-v0.1";
const PSK: [u8; 32] = [0x61; 32];
const IO_MS: u64 = 1500;
const MAX_HANDSHAKE: usize = 1024;
const MAX_NOISE: usize = 4 * 1024 * 1024 + 128;
const CTX_LEN: usize = 32;
const REQ_MAGIC: u8 = 0xC1;
const RESP_MAGIC: u8 = 0xC2;
const PORT: u16 = 44911;
fn key(generation: u32, state: KeyState) -> KeyRecord {
    KeyRecord {
        key_id: 7,
        generation,
        algorithm: KeyAlgorithm::MlDsa65,
        purpose: KeyPurpose::PeerAuth,
        state,
        not_before: 10,
        not_after: 100,
        public_key: vec![1, 2, 3],
    }
}

fn policy() -> CryptoPolicy {
    CryptoPolicy {
        min_class: SecurityClass::Pq,
        pq_lock_epoch: Some(50),
    }
}

fn bind(record: &KeyRecord) -> CredentialBinding {
    CredentialBinding::from_key(99, 5, record, &[8, 9])
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

fn full(s: &mut TcpStream, b: &mut [u8]) -> io::Result<()> {
    let deadline = Instant::now() + Duration::from_millis(IO_MS);
    let mut p = 0;
    while p < b.len() {
        if Instant::now() >= deadline {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "budget"));
        }
        match s.read(&mut b[p..]) {
            Ok(0) => return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "closed")),
            Ok(n) => p += n,
            Err(e)
                if e.kind() == io::ErrorKind::TimedOut || e.kind() == io::ErrorKind::WouldBlock =>
            {
                thread::sleep(Duration::from_millis(1))
            }
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

fn wb(s: &mut TcpStream, b: &[u8]) -> io::Result<()> {
    if b.len() > MAX_HANDSHAKE {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "oversize"));
    }
    s.write_all(&(b.len() as u16).to_be_bytes())?;
    s.write_all(b)
}
fn rb(s: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut h = [0u8; 2];
    full(s, &mut h)?;
    let n = u16::from_be_bytes(h) as usize;
    if n > MAX_HANDSHAKE {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "oversize"));
    }
    let mut b = vec![0u8; n];
    full(s, &mut b)?;
    Ok(b)
}

fn wr(s: &mut TcpStream, b: &[u8]) -> io::Result<()> {
    if b.len() > MAX_NOISE {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "oversize"));
    }
    s.write_all(&(b.len() as u32).to_be_bytes())?;
    s.write_all(b)
}

fn arm_io(s: &TcpStream) -> io::Result<()> {
    s.set_read_timeout(Some(Duration::from_millis(IO_MS)))?;
    s.set_write_timeout(Some(Duration::from_millis(IO_MS)))?;
    Ok(())
}

fn rr(s: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut h = [0u8; 4];
    full(s, &mut h)?;
    let n = u32::from_be_bytes(h) as usize;
    if n > MAX_NOISE {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "oversize"));
    }
    let mut b = vec![0u8; n];
    full(s, &mut b)?;
    Ok(b)
}

fn hs(s: &mut TcpStream, init: bool) -> Result<(snow::TransportState, Vec<u8>), String> {
    let mut h = build(init);
    let mut b = [0u8; MAX_HANDSHAKE];
    if init {
        let n = h.write_message(&[], &mut b).map_err(|e| e.to_string())?;
        wb(s, &b[..n]).map_err(|e| e.to_string())?;
        let m = rb(s).map_err(|e| e.to_string())?;
        h.read_message(&m, &mut b).map_err(|e| e.to_string())?;
    } else {
        let m = rb(s).map_err(|e| e.to_string())?;
        h.read_message(&m, &mut b).map_err(|e| e.to_string())?;
        let n = h.write_message(&[], &mut b).map_err(|e| e.to_string())?;
        wb(s, &b[..n]).map_err(|e| e.to_string())?;
    }
    let hash = h.get_handshake_hash().to_vec();
    let t = h.into_transport_mode().map_err(|e| e.to_string())?;
    Ok((t, hash))
}

fn headers() -> Vec<Header> {
    vec![
        Header {
            id: 0,
            prev: None,
            work: 1,
            claimed_valid: true,
        },
        Header {
            id: 1,
            prev: Some(0),
            work: 5,
            claimed_valid: true,
        },
        Header {
            id: 2,
            prev: Some(1),
            work: 5,
            claimed_valid: true,
        },
        Header {
            id: 3,
            prev: Some(2),
            work: 5,
            claimed_valid: true,
        },
    ]
}

fn encode_headers(h: &[Header]) -> Vec<u8> {
    let mut p = Vec::with_capacity(2 + h.len() * 25);
    p.extend_from_slice(&(h.len() as u16).to_be_bytes());
    for x in h {
        p.extend_from_slice(&x.id.to_be_bytes());
        p.extend_from_slice(&x.prev.unwrap_or(u64::MAX).to_be_bytes());
        p.extend_from_slice(&x.work.to_be_bytes());
        p.push(u8::from(x.claimed_valid));
    }
    p
}
fn send_encrypted(s: &mut TcpStream, t: &mut snow::TransportState, app: &[u8]) -> io::Result<()> {
    let mut out = vec![0u8; app.len() + 64];
    let n = t
        .write_message(app, &mut out)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
    wr(s, &out[..n])
}

fn send_request(
    s: &mut TcpStream,
    t: &mut snow::TransportState,
    ctx: [u8; 32],
    request_id: u64,
) -> io::Result<()> {
    let frame = encode_frame(1, MessageType::GetHeaders as u16, request_id, &[])
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("{e:?}")))?;
    let mut app = Vec::with_capacity(1 + CTX_LEN + frame.len());
    app.push(REQ_MAGIC);
    app.extend_from_slice(&ctx);
    app.extend_from_slice(&frame);
    send_encrypted(s, t, &app)
}

fn send_response(s: &mut TcpStream, t: &mut snow::TransportState, ctx: [u8; 32]) -> io::Result<()> {
    let mut app = Vec::with_capacity(1 + CTX_LEN + 2 + 100);
    app.push(RESP_MAGIC);
    app.extend_from_slice(&ctx);
    app.extend_from_slice(&encode_headers(&headers()));
    send_encrypted(s, t, &app)
}

fn receive_request(
    s: &mut TcpStream,
    t: &mut snow::TransportState,
    expected_ctx: [u8; 32],
) -> Result<u64, String> {
    let rec = rr(s).map_err(|e| e.to_string())?;
    let mut plain = vec![0u8; MAX_NOISE];
    let n = t
        .read_message(&rec, &mut plain)
        .map_err(|e| e.to_string())?;
    if n < 1 + CTX_LEN || plain[0] != REQ_MAGIC {
        return Err("request format".into());
    }
    if plain[1..33] != expected_ctx {
        return Err("context mismatch".into());
    }
    let frame = decode_frame(&plain[33..n]).map_err(|e| format!("{e:?}"))?;
    if frame.message_type != MessageType::GetHeaders as u16 || !frame.payload.is_empty() {
        return Err("unexpected message".into());
    }
    Ok(frame.request_id)
}

fn client_response(
    s: &mut TcpStream,
    t: &mut snow::TransportState,
    expected_ctx: [u8; 32],
) -> Result<(), String> {
    let rec = rr(s).map_err(|e| e.to_string())?;
    let mut plain = vec![0u8; MAX_NOISE];
    let n = t
        .read_message(&rec, &mut plain)
        .map_err(|e| e.to_string())?;
    if n < 33 || plain[0] != RESP_MAGIC || plain[1..33] != expected_ctx {
        return Err("response context".into());
    }
    if plain[33..].len() < 2 + 25 * 4 {
        return Err("headers payload".into());
    }
    Ok(())
}
fn serve(provider: Arc<Mutex<InMemoryPublicKeyProvider>>, ready: mpsc::Sender<()>) -> bool {
    let listener = match TcpListener::bind(("127.0.0.1", PORT)) {
        Ok(x) => x,
        Err(_) => return false,
    };
    let _ = ready.send(());
    let (mut s, _) = match listener.accept() {
        Ok(x) => x,
        Err(_) => return false,
    };
    if arm_io(&s).is_err() {
        return false;
    }
    let (mut t, hash) = match hs(&mut s, false) {
        Ok(x) => x,
        Err(e) => {
            eprintln!("event=server_handshake_fail reason={e}");
            return false;
        }
    };
    let old = match provider.lock().unwrap().current(7, KeyPurpose::PeerAuth) {
        Ok(x) => x,
        Err(_) => return false,
    };
    let b = bind(&old);
    let mut session = match BoundSession::bind(&old, session_identity_context(&b, &hash)) {
        Ok(x) => x,
        Err(_) => return false,
    };
    let ctx = session.context();
    let _ = receive_request(&mut s, &mut t, ctx);
    if session
        .revalidate(&*provider.lock().unwrap(), 20, policy())
        .is_ok()
    {
        if send_response(&mut s, &mut t, ctx).is_err() {
            return false;
        }
        eprintln!("event=server_initial_sync_ok");
    } else {
        return false;
    }
    {
        let mut p = provider.lock().unwrap();
        let bad = key(1, KeyState::Active);
        if p.provision_rotation(&old, bad, policy()).is_ok() {
            eprintln!("event=rollback_unexpected_success");
            return false;
        }
        p.provision_rotation(&old, key(3, KeyState::Active), policy())
            .unwrap();
    }
    if receive_request(&mut s, &mut t, ctx).is_ok() {
        let result = session.revalidate(&*provider.lock().unwrap(), 20, policy());
        if matches!(
            result,
            Err(SessionError::RefreshRequired {
                current_generation: 3
            })
        ) {
            eprintln!("event=server_rotation_reject");
        } else {
            eprintln!("event=server_rotation_unexpected result={result:?}");
            return false;
        }
    } else {
        return false;
    }
    drop(s);

    let (mut s, _) = match listener.accept() {
        Ok(x) => x,
        Err(_) => return false,
    };
    if arm_io(&s).is_err() {
        return false;
    }
    let (mut t, hash) = match hs(&mut s, false) {
        Ok(x) => x,
        Err(_) => return false,
    };
    let current = provider
        .lock()
        .unwrap()
        .current(7, KeyPurpose::PeerAuth)
        .unwrap();
    let nb = bind(&current);
    let mut ns = BoundSession::bind(&current, session_identity_context(&nb, &hash)).unwrap();
    let nctx = ns.context();
    if receive_request(&mut s, &mut t, nctx).is_err() {
        return false;
    }
    if ns
        .revalidate(&*provider.lock().unwrap(), 20, policy())
        .is_err()
    {
        return false;
    }
    send_response(&mut s, &mut t, nctx).unwrap();
    eprintln!("event=server_refreshed_sync_ok");
    provider
        .lock()
        .unwrap()
        .revoke(current.key_id, current.generation, current.purpose)
        .unwrap();
    if receive_request(&mut s, &mut t, nctx).is_ok() {
        let result = ns.revalidate(&*provider.lock().unwrap(), 20, policy());
        if result == Err(SessionError::Revoked) {
            eprintln!("event=server_revocation_reject");
            return true;
        }
    }
    false
}

fn connect_and_handshake() -> Result<(TcpStream, snow::TransportState, Vec<u8>), String> {
    let mut s = TcpStream::connect(("127.0.0.1", PORT)).map_err(|e| e.to_string())?;
    arm_io(&s).map_err(|e| e.to_string())?;
    let (t, hash) = hs(&mut s, true)?;
    Ok((s, t, hash))
}

fn main() {
    let initial = key(2, KeyState::Active);
    let server_provider = Arc::new(Mutex::new(
        InMemoryPublicKeyProvider::new(vec![initial.clone()]).unwrap(),
    ));
    let (ready_tx, ready_rx) = mpsc::channel();
    let sp = Arc::clone(&server_provider);
    let server = thread::spawn(move || serve(sp, ready_tx));
    ready_rx.recv().unwrap();

    let mut client_provider = InMemoryPublicKeyProvider::new(vec![initial.clone()]).unwrap();
    let (mut s, mut t, hash) = connect_and_handshake().unwrap();
    let b = bind(&initial);
    let mut session = BoundSession::bind(&initial, session_identity_context(&b, &hash)).unwrap();
    send_request(&mut s, &mut t, session.context(), 1).unwrap();
    client_response(&mut s, &mut t, session.context()).unwrap();
    eprintln!("event=client_initial_sync_ok");
    client_provider
        .provision_rotation(&initial, key(3, KeyState::Active), policy())
        .unwrap();
    let r = session.revalidate(&client_provider, 20, policy());
    assert_eq!(
        r,
        Err(SessionError::RefreshRequired {
            current_generation: 3
        })
    );
    eprintln!("event=client_refresh_required");

    send_request(&mut s, &mut t, session.context(), 2).unwrap();
    let stale = rr(&mut s);
    assert!(stale.is_err());
    eprintln!("event=stale_session_wire_rejected");
    drop(s);

    let rotated = key(3, KeyState::Active);
    let (mut s2, mut t2, hash2) = connect_and_handshake().unwrap();
    let b2 = bind(&rotated);
    let mut session2 = BoundSession::bind(&rotated, session_identity_context(&b2, &hash2)).unwrap();
    send_request(&mut s2, &mut t2, session2.context(), 3).unwrap();
    client_response(&mut s2, &mut t2, session2.context()).unwrap();
    eprintln!("event=client_refreshed_sync_ok");

    client_provider.revoke(7, 3, KeyPurpose::PeerAuth).unwrap();
    assert_eq!(
        session2.revalidate(&client_provider, 20, policy()),
        Err(SessionError::Revoked)
    );
    eprintln!("event=client_revocation_guard");
    send_request(&mut s2, &mut t2, session2.context(), 4).unwrap();
    let revoked_wire = rr(&mut s2);
    assert!(revoked_wire.is_err());
    eprintln!("event=revoked_session_wire_rejected");

    drop(s2);
    assert!(server.join().unwrap());
    println!("RESULT provider-backed identity session PASS");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constants_are_bounded() {
        assert!(MAX_HANDSHAKE <= 2048);
        assert!(MAX_NOISE <= 4 * 1024 * 1024 + 128);
        assert_eq!(REQ_MAGIC, 0xC1);
        assert_eq!(RESP_MAGIC, 0xC2);
    }
}
