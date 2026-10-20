use ai_native_l1_pow_bench::{
    auth_transport::{
        derive_direction_key, make_auth_ack, make_auth_hello, open_record, random_nonce,
        seal_record, verify_auth_ack, verify_auth_hello, AuthError, MAX_AUTH_RECORD,
    },
    chain_view::{client_a_best, Header},
    encode_frame, MessageType, HEADER_LEN, MAX_FRAME,
};
use std::{
    env,
    io::{self, Read, Write},
    net::{TcpListener, TcpStream},
    thread,
    time::{Duration, Instant},
};
const PSK: [u8; 32] = [0x42; 32];
const WRONG: [u8; 32] = [0x43; 32];
const IO_MS: u64 = 1500;
const MAX_HEADERS: usize = 64;
const HLEN: usize = 25;
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
fn v(a: &[String], n: &str) -> Option<String> {
    a.windows(2).find(|x| x[0] == n).map(|x| x[1].clone())
}
fn n<T: std::str::FromStr>(a: &[String], k: &str, d: T) -> T {
    v(a, k).and_then(|x| x.parse().ok()).unwrap_or(d)
}
fn cfg() -> C {
    let a: Vec<String> = env::args().collect();
    C {
        id: n(&a, "--id", 1),
        listen: n(&a, "--listen", 43801),
        peers: v(&a, "--peers")
            .unwrap_or_default()
            .split(',')
            .filter_map(|x| x.parse().ok())
            .collect(),
        role: v(&a, "--role").unwrap_or("server".into()),
        variant: v(&a, "--variant").unwrap_or("honest".into()),
        wrong: a.iter().any(|x| x == "--wrong-key"),
        duration: n(&a, "--duration-ms", 5200),
    }
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
    let c = u16::from_be_bytes([p[0], p[1]]) as usize;
    if c > MAX_HEADERS || p.len() != 2 + c * HLEN {
        return None;
    }
    let mut o = Vec::with_capacity(c);
    for i in 0..c {
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

fn read_full(s: &mut TcpStream, b: &mut [u8], ms: u64) -> io::Result<()> {
    let d = Instant::now() + Duration::from_millis(ms);
    let mut p = 0;
    while p < b.len() {
        if Instant::now() >= d {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "budget"));
        }
        match s.read(&mut b[p..]) {
            Ok(0) => return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "closed")),
            Ok(k) => p += k,
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
fn read_record(s: &mut TcpStream) -> Result<Vec<u8>, AuthError> {
    let mut h = [0u8; 18];
    read_full(s, &mut h, 2500).map_err(|_| AuthError::Truncated)?;
    let len = u32::from_be_bytes(h[14..18].try_into().unwrap()) as usize;
    if len > MAX_FRAME {
        return Err(AuthError::Oversize(len));
    }
    let total = 18usize
        .checked_add(len)
        .and_then(|x| x.checked_add(32))
        .ok_or(AuthError::InvalidRecordLength)?;
    if total > MAX_AUTH_RECORD {
        return Err(AuthError::Oversize(len));
    }
    let mut rest = vec![0u8; len + 32];
    read_full(s, &mut rest, 2500).map_err(|_| AuthError::Truncated)?;
    let mut r = h.to_vec();
    r.extend_from_slice(&rest);
    Ok(r)
}
fn key(w: bool) -> &'static [u8; 32] {
    if w {
        &WRONG
    } else {
        &PSK
    }
}

fn serve(mut s: TcpStream, c: C) {
    let k = key(c.wrong);
    let _ = s.set_read_timeout(Some(Duration::from_millis(IO_MS)));
    let _ = s.set_write_timeout(Some(Duration::from_millis(IO_MS)));
    let mut he = vec![0u8; 65];
    if read_full(&mut s, &mut he, 2500).is_err() {
        eprintln!("peer={} event=auth_fail kind=hello_read", c.id);
        return;
    }
    let Ok((role, cn)) = verify_auth_hello(k, &he) else {
        eprintln!("peer={} event=auth_fail kind=bad_mac", c.id);
        return;
    };
    if role != 1 {
        eprintln!("peer={} event=auth_fail kind=bad_role", c.id);
        return;
    }
    let Ok(sn) = random_nonce() else { return };
    if s.write_all(&make_auth_ack(k, cn, sn)).is_err() {
        return;
    }
    let rk = derive_direction_key(k, cn, sn, 0);
    let sk = derive_direction_key(k, cn, sn, 1);
    match read_record(&mut s).and_then(|r| open_record(&rk, 0, &r)) {
        Ok(inner)
            if inner.len() >= HEADER_LEN
                && u16::from_be_bytes(inner[6..8].try_into().unwrap())
                    == MessageType::GetHeaders as u16 =>
        {
            let f = encode_frame(
                1,
                MessageType::Headers as u16,
                0,
                &enc_headers(&headers(&c.variant)),
            )
            .unwrap();
            let _ = s.write_all(&seal_record(&sk, 0, &f).unwrap());
            eprintln!("peer={} event=sync_reply variant={}", c.id, c.variant)
        }
        Err(e) => eprintln!("peer={} event=auth_fail kind={e:?}", c.id),
        _ => eprintln!("peer={} event=sync_request_invalid", c.id),
    }
}

fn request(peer: u16, id: u64) -> Result<Vec<Header>, String> {
    let mut s = TcpStream::connect(("127.0.0.1", peer)).map_err(|e| format!("connect:{e}"))?;
    let _ = s.set_read_timeout(Some(Duration::from_millis(IO_MS)));
    let _ = s.set_write_timeout(Some(Duration::from_millis(IO_MS)));
    let cn = random_nonce().map_err(|e| format!("random:{e:?}"))?;
    s.write_all(&make_auth_hello(&PSK, 1, cn).map_err(|e| format!("hello:{e:?}"))?)
        .map_err(|e| format!("send:{e}"))?;
    let mut ack = vec![0u8; 97];
    read_full(&mut s, &mut ack, 2500).map_err(|e| format!("ack:{e}"))?;
    let sn = verify_auth_ack(&PSK, &ack, cn).map_err(|e| format!("verify:{e:?}"))?;
    let out = derive_direction_key(&PSK, cn, sn, 0);
    let inn = derive_direction_key(&PSK, cn, sn, 1);
    let f = encode_frame(1, MessageType::GetHeaders as u16, id, &[]).unwrap();
    s.write_all(&seal_record(&out, 0, &f).unwrap())
        .map_err(|e| format!("request:{e}"))?;
    let r = read_record(&mut s).map_err(|e| format!("record:{e:?}"))?;
    let inner = open_record(&inn, 0, &r).map_err(|e| format!("mac:{e:?}"))?;
    if u16::from_be_bytes(inner[6..8].try_into().map_err(|_| "type")?)
        != MessageType::Headers as u16
    {
        return Err("unexpected response".into());
    }
    dec_headers(&inner[HEADER_LEN..]).ok_or_else(|| "bad headers payload".into())
}
fn client(c: &C) {
    let mut all = Vec::new();
    let mut tips = Vec::new();
    let mut ok = 0;
    let mut auth_fail = 0;
    for (i, p) in c.peers.iter().enumerate() {
        match request(*p, c.id * 100 + i as u64) {
            Ok(h) => {
                ok += 1;
                if let Some(x) = h.last() {
                    tips.push(x.id)
                }
                all.extend(h)
            }
            Err(e) => {
                auth_fail += 1;
                eprintln!("node={} event=peer_failed peer={} err={}", c.id, p, e)
            }
        }
    }
    let selected = client_a_best(&all, &tips);
    if let Some(v) = selected {
        eprintln!(
            "node={} event=sync_result tip={} work={} peers_ok={} peer_fail={}",
            c.id, v.tip, v.total_work, ok, auth_fail
        )
    } else {
        eprintln!(
            "node={} event=sync_result none peers_ok={} peer_fail={}",
            c.id, ok, auth_fail
        )
    }
}
fn main() {
    let c = cfg();
    if c.role == "client" {
        client(&c)
    } else {
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
                    thread::sleep(Duration::from_millis(20))
                }
                Err(_) => break,
            }
        }
        eprintln!("peer={} event=done", c.id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn wire_headers_roundtrip() {
        let h = headers("invalid-long");
        assert_eq!(dec_headers(&enc_headers(&h)), Some(h))
    }
}
