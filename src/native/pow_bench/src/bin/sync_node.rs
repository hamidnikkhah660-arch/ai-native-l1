use ai_native_l1_pow_bench::{
    chain_view::{client_a_best, Header},
    encode_frame,
    stream::StreamDecoder,
    MessageType, HEADER_LEN, MAX_FRAME,
};
use std::env;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::{Duration, Instant};

const HEADER_WIRE_LEN: usize = 25;
const MAX_HEADERS: usize = 64;
const IO_TIMEOUT_MS: u64 = 500;

#[derive(Clone)]
struct Config {
    id: u64,
    listen: u16,
    peers: Vec<u16>,
    role: String,
    variant: String,
    duration_ms: u64,
}
fn val(a: &[String], n: &str) -> Option<String> {
    a.windows(2).find(|w| w[0] == n).map(|w| w[1].clone())
}
fn num<T: std::str::FromStr>(a: &[String], n: &str, d: T) -> T {
    val(a, n).and_then(|v| v.parse().ok()).unwrap_or(d)
}
fn cfg() -> Config {
    let a: Vec<String> = env::args().collect();
    Config {
        id: num(&a, "--id", 1),
        listen: num(&a, "--listen", 43601),
        peers: val(&a, "--peers")
            .unwrap_or_default()
            .split(',')
            .filter_map(|x| x.parse().ok())
            .collect(),
        role: val(&a, "--role").unwrap_or("server".into()),
        variant: val(&a, "--variant").unwrap_or("honest".into()),
        duration_ms: num(&a, "--duration-ms", 5000),
    }
}

fn chain(variant: &str) -> Vec<Header> {
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
    if variant == "valid-long" {
        h.push(Header {
            id: 4,
            prev: Some(3),
            work: 5,
            claimed_valid: true,
        });
    }
    h
}
fn encode_headers(headers: &[Header]) -> Vec<u8> {
    let mut p = Vec::with_capacity(2 + headers.len() * HEADER_WIRE_LEN);
    p.extend_from_slice(&(headers.len() as u16).to_be_bytes());
    for h in headers {
        p.extend_from_slice(&h.id.to_be_bytes());
        p.extend_from_slice(&h.prev.unwrap_or(u64::MAX).to_be_bytes());
        p.extend_from_slice(&h.work.to_be_bytes());
        p.push(u8::from(h.claimed_valid));
    }
    p
}
fn decode_headers(p: &[u8]) -> Option<Vec<Header>> {
    if p.len() < 2 {
        return None;
    }
    let n = u16::from_be_bytes([p[0], p[1]]) as usize;
    if n > MAX_HEADERS {
        return None;
    }
    let need = 2 + n * HEADER_WIRE_LEN;
    if p.len() != need {
        return None;
    }
    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        let o = 2 + i * HEADER_WIRE_LEN;
        let id = u64::from_be_bytes(p[o..o + 8].try_into().ok()?);
        let prev_raw = u64::from_be_bytes(p[o + 8..o + 16].try_into().ok()?);
        let work = u64::from_be_bytes(p[o + 16..o + 24].try_into().ok()?);
        let valid = p[o + 24];
        if valid > 1 {
            return None;
        }
        out.push(Header {
            id,
            prev: if prev_raw == u64::MAX {
                None
            } else {
                Some(prev_raw)
            },
            work,
            claimed_valid: valid == 1,
        });
    }
    Some(out)
}

fn send(s: &mut TcpStream, ty: MessageType, req: u64, p: &[u8]) -> bool {
    encode_frame(1, ty as u16, req, p)
        .ok()
        .map(|b| s.write_all(&b).is_ok())
        .unwrap_or(false)
}
fn serve(mut s: TcpStream, cfg: Config) {
    let _ = s.set_read_timeout(Some(Duration::from_millis(IO_TIMEOUT_MS)));
    let _ = s.set_write_timeout(Some(Duration::from_millis(IO_TIMEOUT_MS)));
    let mut d = StreamDecoder::new(MAX_FRAME + HEADER_LEN);
    let mut b = [0u8; 4096];
    loop {
        match s.read(&mut b) {
            Ok(0) => break,
            Ok(n) => {
                let Ok(frames) = d.push(&b[..n]) else { break };
                for f in frames {
                    if f.message_type == MessageType::GetHeaders as u16 {
                        let headers = chain(&cfg.variant);
                        if !send(
                            &mut s,
                            MessageType::Headers,
                            f.request_id,
                            &encode_headers(&headers),
                        ) {
                            return;
                        }
                        eprintln!(
                            "node={} event=headers_sent variant={} count={}",
                            cfg.id,
                            cfg.variant,
                            headers.len()
                        );
                    }
                }
            }
            Err(e)
                if e.kind() == std::io::ErrorKind::TimedOut
                    || e.kind() == std::io::ErrorKind::WouldBlock =>
            {
                continue
            }
            Err(_) => break,
        }
    }
}
fn connect_retry(port: u16, deadline: Instant) -> Option<TcpStream> {
    while Instant::now() < deadline {
        if let Ok(s) = TcpStream::connect(("127.0.0.1", port)) {
            return Some(s);
        }
        thread::sleep(Duration::from_millis(40));
    }
    None
}

fn request(port: u16, req: u64) -> Option<Vec<Header>> {
    let deadline = Instant::now() + Duration::from_millis(2200);
    let mut s = connect_retry(port, deadline)?;
    let _ = s.set_read_timeout(Some(Duration::from_millis(IO_TIMEOUT_MS)));
    let _ = s.set_write_timeout(Some(Duration::from_millis(IO_TIMEOUT_MS)));
    if !send(&mut s, MessageType::GetHeaders, req, &[]) {
        return None;
    }
    let mut d = StreamDecoder::new(MAX_FRAME + HEADER_LEN);
    let mut b = [0u8; 4096];
    let until = Instant::now() + Duration::from_millis(1500);
    while Instant::now() < until {
        match s.read(&mut b) {
            Ok(0) => break,
            Ok(n) => {
                let frames = d.push(&b[..n]).ok()?;
                for f in frames {
                    if f.message_type == MessageType::Headers as u16 {
                        if let Some(h) = decode_headers(&f.payload) {
                            return Some(h);
                        }
                    }
                }
            }
            Err(e)
                if e.kind() == std::io::ErrorKind::TimedOut
                    || e.kind() == std::io::ErrorKind::WouldBlock =>
            {
                continue
            }
            Err(_) => break,
        }
    }
    None
}

fn client(cfg: &Config) {
    let mut all = Vec::new();
    let mut tips = Vec::new();
    for (i, peer) in cfg.peers.iter().enumerate() {
        match request(*peer, cfg.id * 100 + i as u64) {
            Some(h) => {
                if let Some(t) = h.last() {
                    tips.push(t.id)
                };
                all.extend(h.clone());
                eprintln!(
                    "node={} event=headers_rx peer={} count={}",
                    cfg.id,
                    peer,
                    h.len()
                );
            }
            None => eprintln!("node={} event=peer_unavailable peer={}", cfg.id, peer),
        }
    }
    let selected = client_a_best(&all, &tips);
    match selected {
        Some(v) => eprintln!(
            "node={} event=sync_result tip={} work={}",
            cfg.id, v.tip, v.total_work
        ),
        None => eprintln!("node={} event=sync_result none", cfg.id),
    }
}

fn main() {
    let c = cfg();
    let deadline = Instant::now() + Duration::from_millis(c.duration_ms);
    eprintln!(
        "node={} role={} variant={} event=ready",
        c.id, c.role, c.variant
    );
    if c.role == "client" {
        client(&c);
        eprintln!("node={} event=done", c.id);
        return;
    }
    let l = TcpListener::bind(("127.0.0.1", c.listen)).expect("bind");
    l.set_nonblocking(true).expect("nonblocking");
    while Instant::now() < deadline {
        match l.accept() {
            Ok((s, _)) => {
                let cc = c.clone();
                thread::spawn(move || serve(s, cc));
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(20))
            }
            Err(_) => break,
        }
    }
    eprintln!("node={} event=done", c.id)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn headers_roundtrip_and_bound() {
        let h = chain("honest");
        let p = encode_headers(&h);
        assert_eq!(decode_headers(&p), Some(h));
        let mut bad = p.clone();
        bad[0] = 0;
        bad[1] = 65;
        assert!(decode_headers(&bad).is_none())
    }
}
