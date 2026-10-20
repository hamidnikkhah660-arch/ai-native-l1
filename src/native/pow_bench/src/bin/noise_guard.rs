use ai_native_l1_pow_bench::{decode_frame, encode_frame, MessageType, MAX_FRAME};
use snow::Builder;
use std::{
    env,
    error::Error,
    io::{self, Read, Write},
    net::{TcpListener, TcpStream},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
    thread,
    time::{Duration, Instant},
};

const PATTERN: &str = "Noise_NNpsk0_25519_ChaChaPoly_SHA256";
const PROLOGUE: &[u8] = b"AI-NATIVE-L1/transport-v0.1";
const PSK: [u8; 32] = [0x61; 32];
const HANDSHAKE_MAX: usize = 1024;
const MAX_NOISE: usize = MAX_FRAME + 128;
const READ_MS: u64 = 1200;

#[derive(Clone, Copy)]
struct C {
    listen: u16,
    duration: u64,
    max_sessions: usize,
    max_handshakes: u32,
    failure_window_ms: u64,
}
fn val(a: &[String], n: &str) -> Option<String> {
    a.windows(2).find(|x| x[0] == n).map(|x| x[1].clone())
}
fn num<T: std::str::FromStr>(a: &[String], k: &str, d: T) -> T {
    val(a, k).and_then(|x| x.parse().ok()).unwrap_or(d)
}
fn cfg() -> C {
    let a: Vec<String> = env::args().collect();
    C {
        listen: num(&a, "--listen", 44501),
        duration: num(&a, "--duration-ms", 5000),
        max_sessions: num(&a, "--max-sessions", 2),
        max_handshakes: num(&a, "--max-handshakes", 4),
        failure_window_ms: num(&a, "--failure-window-ms", 1000),
    }
}

struct FailureBudget {
    start: Instant,
    attempts: u32,
    failures: u32,
}
#[derive(Clone)]
struct Admission {
    active: Arc<AtomicUsize>,
    budget: Arc<Mutex<FailureBudget>>,
    cfg: C,
}
impl Admission {
    fn new(c: C) -> Self {
        Self {
            active: Arc::new(AtomicUsize::new(0)),
            budget: Arc::new(Mutex::new(FailureBudget {
                start: Instant::now(),
                attempts: 0,
                failures: 0,
            })),
            cfg: c,
        }
    }
    fn admit_session(&self) -> bool {
        self.active
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |x| {
                if x < self.cfg.max_sessions {
                    Some(x + 1)
                } else {
                    None
                }
            })
            .is_ok()
    }
    fn done(&self) {
        self.active.fetch_sub(1, Ordering::AcqRel);
    }
    fn admit_handshake(&self) -> bool {
        let mut b = self.budget.lock().unwrap();
        if b.start.elapsed() > Duration::from_millis(self.cfg.failure_window_ms) {
            b.start = Instant::now();
            b.attempts = 0;
            b.failures = 0;
        }
        if b.attempts >= self.cfg.max_handshakes {
            return false;
        }
        b.attempts += 1;
        true
    }
    fn record_failure(&self) {
        let mut b = self.budget.lock().unwrap();
        if b.start.elapsed() > Duration::from_millis(self.cfg.failure_window_ms) {
            b.start = Instant::now();
            b.attempts = 0;
            b.failures = 0;
        }
        b.failures = b.failures.saturating_add(1);
    }
}

fn build() -> Result<snow::HandshakeState, Box<dyn Error + Send + Sync>> {
    Ok(Builder::new(PATTERN.parse()?)
        .prologue(PROLOGUE)
        .psk(0, &PSK)
        .build_responder()?)
}

fn read_full(s: &mut TcpStream, b: &mut [u8], ms: u64) -> io::Result<()> {
    let d = Instant::now() + Duration::from_millis(ms);
    let mut p = 0usize;
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
fn read_blob(s: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut h = [0u8; 2];
    read_full(s, &mut h, READ_MS)?;
    let n = u16::from_be_bytes(h) as usize;
    if n > HANDSHAKE_MAX {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "oversize handshake",
        ));
    }
    let mut b = vec![0u8; n];
    read_full(s, &mut b, READ_MS)?;
    Ok(b)
}
fn write_blob(s: &mut TcpStream, b: &[u8]) -> io::Result<()> {
    if b.len() > HANDSHAKE_MAX {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "oversize"));
    }
    s.write_all(&(b.len() as u16).to_be_bytes())?;
    s.write_all(b)
}
fn read_record(s: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut h = [0u8; 4];
    read_full(s, &mut h, READ_MS)?;
    let n = u32::from_be_bytes(h) as usize;
    if n > MAX_NOISE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "oversize record",
        ));
    }
    let mut b = vec![0u8; n];
    read_full(s, &mut b, READ_MS)?;
    Ok(b)
}
fn write_record(s: &mut TcpStream, b: &[u8]) -> io::Result<()> {
    if b.len() > MAX_NOISE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "oversize record",
        ));
    }
    s.write_all(&(b.len() as u32).to_be_bytes())?;
    s.write_all(b)
}

fn serve(mut s: TcpStream, adm: Admission, id: u64) {
    let _ = s.set_read_timeout(Some(Duration::from_millis(READ_MS)));
    let _ = s.set_write_timeout(Some(Duration::from_millis(READ_MS)));
    let mut hs = match build() {
        Ok(x) => x,
        Err(_) => {
            adm.done();
            return;
        }
    };
    let msg = match read_blob(&mut s) {
        Ok(x) => x,
        Err(e) => {
            eprintln!("node={id} event=handshake_fail kind={e}");
            adm.record_failure();
            adm.done();
            return;
        }
    };
    let mut out = [0u8; HANDSHAKE_MAX];
    if hs.read_message(&msg, &mut out).is_err() {
        eprintln!("node={id} event=handshake_fail kind=bad_handshake");
        adm.record_failure();
        adm.done();
        return;
    }
    let n = match hs.write_message(&[], &mut out) {
        Ok(x) => x,
        Err(_) => {
            adm.record_failure();
            adm.done();
            return;
        }
    };
    if write_blob(&mut s, &out[..n]).is_err() {
        adm.done();
        return;
    }
    let mut t = match hs.into_transport_mode() {
        Ok(x) => x,
        Err(_) => {
            adm.record_failure();
            adm.done();
            return;
        }
    };
    let rec = match read_record(&mut s) {
        Ok(x) => x,
        Err(e) => {
            eprintln!("node={id} event=session_fail kind={e}");
            adm.done();
            return;
        }
    };
    let mut plain = vec![0u8; MAX_FRAME + 64];
    match t.read_message(&rec, &mut plain) {
        Ok(n) => match decode_frame(&plain[..n]) {
            Ok(f) if f.message_type == MessageType::Ping as u16 && f.payload.len() == 8 => {
                let pong =
                    encode_frame(1, MessageType::Pong as u16, f.request_id, &f.payload).unwrap();
                let mut cb = vec![0u8; pong.len() + 64];
                let m = t.write_message(&pong, &mut cb).unwrap();
                let _ = write_record(&mut s, &cb[..m]);
                eprintln!("node={id} event=session_ok");
            }
            Ok(_) => eprintln!("node={id} event=protocol_reject"),
            Err(_) => eprintln!("node={id} event=inner_reject"),
        },
        Err(_) => {
            eprintln!("node={id} event=noise_record_rejected");
            adm.record_failure()
        }
    }
    adm.done();
}

fn main() {
    let c = cfg();
    let l = TcpListener::bind(("127.0.0.1", c.listen)).expect("bind");
    l.set_nonblocking(true).unwrap();
    let adm = Admission::new(c);
    let d = Instant::now() + Duration::from_millis(c.duration);
    eprintln!(
        "event=ready listen={} max_sessions={} max_handshakes={} window_ms={}",
        c.listen, c.max_sessions, c.max_handshakes, c.failure_window_ms
    );
    let mut id = 0u64;
    while Instant::now() < d {
        match l.accept() {
            Ok((s, addr)) => {
                id += 1;
                if !adm.admit_handshake() {
                    eprintln!("event=admission_throttled addr={addr}");
                    continue;
                }
                if !adm.admit_session() {
                    eprintln!("event=session_reject_capacity addr={addr}");
                    continue;
                }
                let a = adm.clone();
                let sid = id;
                thread::spawn(move || serve(s, a, sid));
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(5))
            }
            Err(_) => break,
        }
    }
    eprintln!("event=done");
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn admission_caps_sessions() {
        let c = C {
            listen: 1,
            duration: 1,
            max_sessions: 2,
            max_handshakes: 4,
            failure_window_ms: 1000,
        };
        let a = Admission::new(c);
        assert!(a.admit_session());
        assert!(a.admit_session());
        assert!(!a.admit_session());
        a.done();
        assert!(a.admit_session());
    }
    #[test]
    fn failure_budget_caps_window() {
        let c = C {
            listen: 1,
            duration: 1,
            max_sessions: 2,
            max_handshakes: 2,
            failure_window_ms: 1000,
        };
        let a = Admission::new(c);
        assert!(a.admit_handshake());
        assert!(a.admit_handshake());
        assert!(!a.admit_handshake());
    }
}
