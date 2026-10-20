use ai_native_l1_pow_bench::{
    chain_view::{client_a_best, Header},
    decode_frame, encode_frame, MessageType, MAX_FRAME,
};
use snow::Builder;
use std::{
    env,
    error::Error,
    io::{self, Read, Write},
    net::{TcpListener, TcpStream},
    thread,
    time::{Duration, Instant},
};

const PATTERN: &str = "Noise_NNpsk0_25519_ChaChaPoly_SHA256";
const PROLOGUE: &[u8] = b"AI-NATIVE-L1/transport-v0.1";
const PSK: [u8; 32] = [0x61; 32];
const WRONG: [u8; 32] = [0x62; 32];
const HANDSHAKE_MAX: usize = 1024;
const MAX_NOISE: usize = MAX_FRAME + 128;
const IO_MS: u64 = 1500;
const HLEN: usize = 25;
const MAX_HEADERS: usize = 64;

#[derive(Clone)]
struct C {
    id: u64,
    listen: u16,
    peers: Vec<u16>,
    role: String,
    variant: String,
    wrong: bool,
    duration: u64,
}
fn val(a: &[String], n: &str) -> Option<String> {
    a.windows(2).find(|x| x[0] == n).map(|x| x[1].clone())
}
fn num<T: std::str::FromStr>(a: &[String], n: &str, d: T) -> T {
    val(a, n).and_then(|x| x.parse().ok()).unwrap_or(d)
}
fn cfg() -> C {
    let a: Vec<String> = env::args().collect();
    C {
        id: num(&a, "--id", 1),
        listen: num(&a, "--listen", 44701),
        peers: val(&a, "--peers")
            .unwrap_or_default()
            .split(',')
            .filter_map(|x| x.parse().ok())
            .collect(),
        role: val(&a, "--role").unwrap_or("server".into()),
        variant: val(&a, "--variant").unwrap_or("honest".into()),
        wrong: a.iter().any(|x| x == "--wrong-psk"),
        duration: num(&a, "--duration-ms", 6500),
    }
}

fn build(init: bool, psk: &[u8; 32]) -> Result<snow::HandshakeState, Box<dyn Error + Send + Sync>> {
    let b = Builder::new(PATTERN.parse()?)
        .prologue(PROLOGUE)
        .psk(0, psk);
    Ok(if init {
        b.build_initiator()?
    } else {
        b.build_responder()?
    })
}

fn read_full(s: &mut TcpStream, b: &mut [u8], ms: u64) -> io::Result<()> {
    let d = Instant::now() + Duration::from_millis(ms);
    let mut p = 0;
    while p < b.len() {
        if Instant::now() >= d {
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
fn write_blob(s: &mut TcpStream, b: &[u8]) -> io::Result<()> {
    if b.len() > HANDSHAKE_MAX {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "oversize"));
    }
    s.write_all(&(b.len() as u16).to_be_bytes())?;
    s.write_all(b)
}
fn read_blob(s: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut h = [0u8; 2];
    read_full(s, &mut h, IO_MS)?;
    let n = u16::from_be_bytes(h) as usize;
    if n > HANDSHAKE_MAX {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "oversize"));
    }
    let mut b = vec![0u8; n];
    read_full(s, &mut b, IO_MS)?;
    Ok(b)
}
fn write_record(s: &mut TcpStream, b: &[u8]) -> io::Result<()> {
    if b.len() > MAX_NOISE {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "oversize"));
    }
    s.write_all(&(b.len() as u32).to_be_bytes())?;
    s.write_all(b)
}
fn read_record(s: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut h = [0u8; 4];
    read_full(s, &mut h, IO_MS)?;
    let n = u32::from_be_bytes(h) as usize;
    if n > MAX_NOISE {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "oversize"));
    }
    let mut b = vec![0u8; n];
    read_full(s, &mut b, IO_MS)?;
    Ok(b)
}

fn headers(variant: &str) -> Vec<Header> {
    let mut h = vec![
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
    ];
    if variant == "invalid-long" {
        h.push(Header {
            id: 99,
            prev: Some(3),
            work: 1000,
            claimed_valid: false,
        });
    }
    h
}
fn enc_headers(h: &[Header]) -> Vec<u8> {
    let mut p = Vec::with_capacity(2 + h.len() * HLEN);
    p.extend_from_slice(&(h.len() as u16).to_be_bytes());
    for x in h {
        p.extend_from_slice(&x.id.to_be_bytes());
        p.extend_from_slice(&x.prev.unwrap_or(u64::MAX).to_be_bytes());
        p.extend_from_slice(&x.work.to_be_bytes());
        p.push(u8::from(x.claimed_valid));
    }
    p
}
fn dec_headers(p: &[u8]) -> Option<Vec<Header>> {
    if p.len() < 2 {
        return None;
    }
    let n = u16::from_be_bytes([p[0], p[1]]) as usize;
    if n > MAX_HEADERS || p.len() != 2 + n * HLEN {
        return None;
    }
    let mut o = Vec::with_capacity(n);
    for i in 0..n {
        let z = 2 + i * HLEN;
        let id = u64::from_be_bytes(p[z..z + 8].try_into().ok()?);
        let q = u64::from_be_bytes(p[z + 8..z + 16].try_into().ok()?);
        let w = u64::from_be_bytes(p[z + 16..z + 24].try_into().ok()?);
        if p[z + 24] > 1 {
            return None;
        }
        o.push(Header {
            id,
            prev: if q == u64::MAX { None } else { Some(q) },
            work: w,
            claimed_valid: p[z + 24] == 1,
        });
    }
    Some(o)
}

fn serve(mut s: TcpStream, c: C) {
    let psk = if c.wrong { &WRONG } else { &PSK };
    let _ = s.set_read_timeout(Some(Duration::from_millis(IO_MS)));
    let _ = s.set_write_timeout(Some(Duration::from_millis(IO_MS)));
    let mut hs = match build(false, psk) {
        Ok(x) => x,
        Err(_) => return,
    };
    let msg = match read_blob(&mut s) {
        Ok(x) => x,
        Err(e) => {
            eprintln!("peer={} event=handshake_fail err={e}", c.id);
            return;
        }
    };
    let mut hb = [0u8; HANDSHAKE_MAX];
    if hs.read_message(&msg, &mut hb).is_err() {
        eprintln!("peer={} event=handshake_reject", c.id);
        return;
    }
    let n = match hs.write_message(&[], &mut hb) {
        Ok(x) => x,
        Err(_) => return,
    };
    if write_blob(&mut s, &hb[..n]).is_err() {
        return;
    }
    let mut t = match hs.into_transport_mode() {
        Ok(x) => x,
        Err(_) => return,
    };
    let r = match read_record(&mut s) {
        Ok(x) => x,
        Err(_) => return,
    };
    let mut plain = vec![0u8; MAX_FRAME + 64];
    if let Ok(n) = t.read_message(&r, &mut plain) {
        if let Ok(f) = decode_frame(&plain[..n]) {
            if f.message_type == MessageType::GetHeaders as u16 && f.payload.is_empty() {
                let out = encode_frame(
                    1,
                    MessageType::Headers as u16,
                    f.request_id,
                    &enc_headers(&headers(&c.variant)),
                )
                .unwrap();
                let mut cb = vec![0u8; out.len() + 64];
                if let Ok(m) = t.write_message(&out, &mut cb) {
                    let _ = write_record(&mut s, &cb[..m]);
                    eprintln!("peer={} event=sync_reply variant={}", c.id, c.variant)
                }
            }
        }
    }
}

fn connect_once(port: u16, id: u64) -> Result<Vec<Header>, String> {
    let mut s = TcpStream::connect(("127.0.0.1", port)).map_err(|e| format!("connect:{e}"))?;
    let _ = s.set_read_timeout(Some(Duration::from_millis(IO_MS)));
    let _ = s.set_write_timeout(Some(Duration::from_millis(IO_MS)));
    let mut hs = build(true, &PSK).map_err(|e| format!("build:{e}"))?;
    let mut hb = [0u8; HANDSHAKE_MAX];
    let n = hs
        .write_message(&[], &mut hb)
        .map_err(|e| format!("hs:{e}"))?;
    write_blob(&mut s, &hb[..n]).map_err(|e| format!("sendhs:{e}"))?;
    let msg = read_blob(&mut s).map_err(|e| format!("readhs:{e}"))?;
    hs.read_message(&msg, &mut hb)
        .map_err(|e| format!("verifyhs:{e}"))?;
    let mut t = hs
        .into_transport_mode()
        .map_err(|e| format!("transport:{e}"))?;
    let q = encode_frame(1, MessageType::GetHeaders as u16, id, &[]).unwrap();
    let mut cb = vec![0u8; q.len() + 64];
    let n = t
        .write_message(&q, &mut cb)
        .map_err(|e| format!("write:{e}"))?;
    write_record(&mut s, &cb[..n]).map_err(|e| format!("send:{e}"))?;
    let r = read_record(&mut s).map_err(|e| format!("record:{e}"))?;
    let mut plain = vec![0u8; MAX_FRAME + 64];
    let n = t
        .read_message(&r, &mut plain)
        .map_err(|e| format!("decrypt:{e}"))?;
    let f = decode_frame(&plain[..n]).map_err(|e| format!("frame:{e:?}"))?;
    if f.message_type != MessageType::Headers as u16 {
        return Err("unexpected message".into());
    }
    dec_headers(&f.payload).ok_or_else(|| "bad headers".into())
}
fn client(c: &C) {
    let mut all = Vec::new();
    let mut tips = Vec::new();
    let mut ok = 0;
    let mut fail = 0;
    for (i, p) in c.peers.iter().enumerate() {
        match connect_once(*p, c.id * 100 + i as u64) {
            Ok(h) => {
                ok += 1;
                if let Some(x) = h.last() {
                    tips.push(x.id)
                }
                all.extend(h)
            }
            Err(e) => {
                fail += 1;
                eprintln!("node={} event=peer_failed peer={} err={}", c.id, p, e)
            }
        }
    }
    match client_a_best(&all, &tips) {
        Some(v) => eprintln!(
            "node={} event=sync_result tip={} work={} peers_ok={} peer_fail={}",
            c.id, v.tip, v.total_work, ok, fail
        ),
        None => eprintln!(
            "node={} event=sync_result none peers_ok={} peer_fail={}",
            c.id, ok, fail
        ),
    }
}

fn main() {
    let c = cfg();
    if c.role == "client" {
        client(&c);
        return;
    }
    let l = TcpListener::bind(("127.0.0.1", c.listen)).expect("bind");
    l.set_nonblocking(true).unwrap();
    let d = Instant::now() + Duration::from_millis(c.duration);
    eprintln!(
        "peer={} event=ready variant={} wrong={}",
        c.id, c.variant, c.wrong
    );
    while Instant::now() < d {
        match l.accept() {
            Ok((s, _)) => serve(s, c.clone()),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(10))
            }
            Err(_) => break,
        }
    }
    eprintln!("peer={} event=done", c.id)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn headers_roundtrip() {
        let h = headers("invalid-long");
        assert_eq!(dec_headers(&enc_headers(&h)), Some(h))
    }
}
