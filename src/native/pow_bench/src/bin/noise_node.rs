use ai_native_l1_pow_bench::{decode_frame, encode_frame, MessageType, MAX_FRAME};
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
const WRONG_PSK: [u8; 32] = [0x62; 32];
const HANDSHAKE_MAX: usize = 1024;
const MAX_NOISE_MESSAGE: usize = MAX_FRAME + 128;
const IO_TIMEOUT_MS: u64 = 2000;
type E = Box<dyn Error + Send + Sync>;

#[derive(Clone, Copy)]
struct Config {
    id: u64,
    listen: u16,
    peer: u16,
    server: bool,
    wrong_psk: bool,
    tamper: bool,
    replay: bool,
    duration_ms: u64,
}
fn val(a: &[String], n: &str) -> Option<String> {
    a.windows(2).find(|x| x[0] == n).map(|x| x[1].clone())
}
fn num<T: std::str::FromStr>(a: &[String], n: &str, d: T) -> T {
    val(a, n).and_then(|x| x.parse().ok()).unwrap_or(d)
}
fn cfg() -> Config {
    let a: Vec<String> = env::args().collect();
    Config {
        id: num(&a, "--id", 1),
        listen: num(&a, "--listen", 44301),
        peer: num(&a, "--peer", 44301),
        server: a.iter().any(|x| x == "--server"),
        wrong_psk: a.iter().any(|x| x == "--wrong-psk"),
        tamper: a.iter().any(|x| x == "--tamper"),
        replay: a.iter().any(|x| x == "--replay"),
        duration_ms: num(&a, "--duration-ms", 5000),
    }
}
fn build(initiator: bool, psk: &[u8; 32]) -> Result<snow::HandshakeState, E> {
    let b = Builder::new(PATTERN.parse()?)
        .prologue(PROLOGUE)
        .psk(0, psk);
    Ok(if initiator {
        b.build_initiator()?
    } else {
        b.build_responder()?
    })
}

fn read_full(s: &mut TcpStream, b: &mut [u8], ms: u64) -> io::Result<()> {
    let deadline = Instant::now() + Duration::from_millis(ms);
    let mut p = 0usize;
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
fn write_blob(s: &mut TcpStream, data: &[u8]) -> io::Result<()> {
    if data.len() > HANDSHAKE_MAX {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "handshake blob too large",
        ));
    }
    let len = (data.len() as u16).to_be_bytes();
    s.write_all(&len)?;
    s.write_all(data)
}
fn read_blob(s: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut h = [0u8; 2];
    read_full(s, &mut h, IO_TIMEOUT_MS)?;
    let n = u16::from_be_bytes(h) as usize;
    if n > HANDSHAKE_MAX {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "handshake too large",
        ));
    }
    let mut b = vec![0u8; n];
    read_full(s, &mut b, IO_TIMEOUT_MS)?;
    Ok(b)
}
fn write_record(s: &mut TcpStream, data: &[u8]) -> io::Result<()> {
    if data.len() > MAX_NOISE_MESSAGE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "noise record too large",
        ));
    }
    let len = (data.len() as u32).to_be_bytes();
    s.write_all(&len)?;
    s.write_all(data)
}
fn read_record(s: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut h = [0u8; 4];
    read_full(s, &mut h, IO_TIMEOUT_MS)?;
    let n = u32::from_be_bytes(h) as usize;
    if n > MAX_NOISE_MESSAGE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "noise record too large",
        ));
    }
    let mut b = vec![0u8; n];
    read_full(s, &mut b, IO_TIMEOUT_MS)?;
    Ok(b)
}

fn server(c: Config) {
    let l = TcpListener::bind(("127.0.0.1", c.listen)).expect("bind");
    l.set_nonblocking(true).unwrap();
    let d = Instant::now() + Duration::from_millis(c.duration_ms);
    eprintln!("node={} event=ready role=server", c.id);
    while Instant::now() < d {
        match l.accept() {
            Ok((mut s, _)) => {
                let _ = s.set_read_timeout(Some(Duration::from_millis(IO_TIMEOUT_MS)));
                let _ = s.set_write_timeout(Some(Duration::from_millis(IO_TIMEOUT_MS)));
                let psk = if c.wrong_psk { &WRONG_PSK } else { &PSK };
                let mut hs = match build(false, psk) {
                    Ok(x) => x,
                    Err(e) => {
                        eprintln!("node={} event=handshake_fail err={e}", c.id);
                        continue;
                    }
                };
                let msg = match read_blob(&mut s) {
                    Ok(x) => x,
                    Err(e) => {
                        eprintln!("node={} event=handshake_fail err={e}", c.id);
                        continue;
                    }
                };
                let mut out = [0u8; HANDSHAKE_MAX];
                if hs.read_message(&msg, &mut out).is_err() {
                    eprintln!("node={} event=handshake_reject", c.id);
                    continue;
                }
                let n = match hs.write_message(&[], &mut out) {
                    Ok(x) => x,
                    Err(e) => {
                        eprintln!("node={} event=handshake_fail err={e}", c.id);
                        continue;
                    }
                };
                if write_blob(&mut s, &out[..n]).is_err() {
                    continue;
                }
                let mut t = match hs.into_transport_mode() {
                    Ok(x) => x,
                    Err(e) => {
                        eprintln!("node={} event=handshake_fail err={e}", c.id);
                        continue;
                    }
                };
                let cipher = match read_record(&mut s) {
                    Ok(x) => x,
                    Err(e) => {
                        eprintln!("node={} event=noise_fail io={e}", c.id);
                        continue;
                    }
                };
                let mut plain = vec![0u8; MAX_FRAME + 64];
                match t.read_message(&cipher, &mut plain) {
                    Ok(n) => {
                        let f = decode_frame(&plain[..n]);
                        match f {
                            Ok(frame)
                                if frame.message_type == MessageType::Ping as u16
                                    && frame.payload.len() == 8 =>
                            {
                                let pong = encode_frame(
                                    1,
                                    MessageType::Pong as u16,
                                    frame.request_id,
                                    &frame.payload,
                                )
                                .unwrap();
                                let mut cbuf = vec![0u8; pong.len() + 64];
                                let m = t.write_message(&pong, &mut cbuf).unwrap();
                                let _ = write_record(&mut s, &cbuf[..m]);
                                eprintln!("node={} event=noise_authenticated_pong", c.id);
                                if c.replay {
                                    match read_record(&mut s).and_then(|r| {
                                        let mut p = vec![0u8; MAX_FRAME + 64];
                                        t.read_message(&r, &mut p).map(|_| ()).map_err(|_| {
                                            io::Error::new(
                                                io::ErrorKind::InvalidData,
                                                "replay rejected",
                                            )
                                        })
                                    }) {
                                        Ok(_) => eprintln!("node={} event=replay_ACCEPTED", c.id),
                                        Err(_) => eprintln!("node={} event=replay_rejected", c.id),
                                    }
                                }
                            }
                            Ok(_) => eprintln!("node={} event=protocol_reject", c.id),
                            Err(e) => eprintln!("node={} event=inner_frame_reject err={e:?}", c.id),
                        }
                    }
                    Err(_) => eprintln!("node={} event=tamper_or_replay_rejected", c.id),
                }
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(20))
            }
            Err(_) => break,
        }
    }
    eprintln!("node={} event=done", c.id)
}

fn client(c: Config) {
    let d = Instant::now() + Duration::from_millis(c.duration_ms);
    while Instant::now() < d {
        if let Ok(mut s) = TcpStream::connect(("127.0.0.1", c.peer)) {
            let _ = s.set_read_timeout(Some(Duration::from_millis(IO_TIMEOUT_MS)));
            let _ = s.set_write_timeout(Some(Duration::from_millis(IO_TIMEOUT_MS)));
            let psk = if c.wrong_psk { &WRONG_PSK } else { &PSK };
            let mut hs = match build(true, psk) {
                Ok(x) => x,
                Err(e) => {
                    eprintln!("node={} event=handshake_fail err={e}", c.id);
                    return;
                }
            };
            let mut out = [0u8; HANDSHAKE_MAX];
            let n1 = hs.write_message(&[], &mut out).unwrap();
            if write_blob(&mut s, &out[..n1]).is_err() {
                return;
            }
            let msg = match read_blob(&mut s) {
                Ok(x) => x,
                Err(e) => {
                    eprintln!("node={} event=handshake_fail err={e}", c.id);
                    return;
                }
            };
            hs.read_message(&msg, &mut out).unwrap_or(0);
            let mut t = match hs.into_transport_mode() {
                Ok(x) => x,
                Err(e) => {
                    eprintln!("node={} event=handshake_fail err={e}", c.id);
                    return;
                }
            };
            let ping = encode_frame(
                1,
                MessageType::Ping as u16,
                77,
                &0x123456789ABCDEF0u64.to_be_bytes(),
            )
            .unwrap();
            let mut cbuf = vec![0u8; ping.len() + 64];
            let n = t.write_message(&ping, &mut cbuf).unwrap();
            let first = cbuf[..n].to_vec();
            let sendbuf = if c.tamper {
                let mut x = first.clone();
                x[0] ^= 1;
                x
            } else {
                first.clone()
            };
            if write_record(&mut s, &sendbuf).is_err() {
                return;
            }
            if c.tamper {
                return;
            }
            let resp = match read_record(&mut s) {
                Ok(x) => x,
                Err(e) => {
                    eprintln!("node={} event=noise_fail io={e}", c.id);
                    return;
                }
            };
            let mut plain = vec![0u8; MAX_FRAME + 64];
            match t.read_message(&resp, &mut plain) {
                Ok(n) => {
                    if decode_frame(&plain[..n]).is_ok() {
                        eprintln!("node={} event=noise_authenticated_pong_ack", c.id);
                        if c.replay {
                            let _ = write_record(&mut s, &first);
                        }
                    }
                }
                Err(_) => eprintln!("node={} event=noise_fail decrypt", c.id),
            }
            return;
        }
        thread::sleep(Duration::from_millis(40))
    }
    eprintln!("node={} event=done", c.id)
}

fn main() {
    let c = cfg();
    if c.server {
        server(c)
    } else {
        client(c)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bounded_constants() {
        assert!(HANDSHAKE_MAX < MAX_NOISE_MESSAGE);
        assert!(MAX_NOISE_MESSAGE > MAX_FRAME)
    }
}
