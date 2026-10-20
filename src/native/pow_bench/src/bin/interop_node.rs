use ai_native_l1_pow_bench::{
    encode_frame, stream::StreamDecoder, Frame, MessageType, ParseError, HEADER_LEN, MAGIC,
    MAX_CONTROL, PROTOCOL_VERSION,
};
use std::env;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::thread;
use std::time::{Duration, Instant};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Mode {
    A,
    B,
}
#[derive(Clone, Copy)]
struct Config {
    node_id: u64,
    listen: u16,
    peer: u16,
    mode: Mode,
    duration_ms: u64,
}

fn val(a: &[String], n: &str) -> Option<String> {
    a.windows(2).find(|w| w[0] == n).map(|w| w[1].clone())
}
fn num<T: std::str::FromStr>(a: &[String], n: &str, d: T) -> T {
    val(a, n).and_then(|v| v.parse().ok()).unwrap_or(d)
}
fn config() -> Config {
    let a: Vec<String> = env::args().collect();
    let mode = match val(&a, "--mode").as_deref() {
        Some("b") => Mode::B,
        _ => Mode::A,
    };
    Config {
        node_id: num(&a, "--node-id", 1),
        listen: num(&a, "--listen", 43301),
        peer: num(&a, "--peer", 43302),
        mode,
        duration_ms: num(&a, "--duration-ms", 4200),
    }
}

fn hello(id: u64) -> Vec<u8> {
    id.to_be_bytes()
        .into_iter()
        .chain(1u64.to_be_bytes())
        .chain([1u8])
        .collect()
}
fn u64p(v: u64) -> Vec<u8> {
    v.to_be_bytes().to_vec()
}
fn send_frame(s: &mut TcpStream, mode: Mode, ty: MessageType, req: u64, payload: &[u8]) -> bool {
    let bytes = match mode {
        Mode::A => encode_frame(PROTOCOL_VERSION, ty as u16, req, payload),
        Mode::B => manual_encode(ty as u16, req, payload),
    };
    bytes.ok().map(|b| s.write_all(&b).is_ok()).unwrap_or(false)
}

fn manual_encode(ty: u16, req: u64, payload: &[u8]) -> Result<Vec<u8>, ParseError> {
    if payload.len() > MAX_CONTROL {
        return Err(ParseError::PayloadTooLarge {
            declared: payload.len(),
            limit: MAX_CONTROL,
        });
    }
    let mut out = Vec::with_capacity(HEADER_LEN + payload.len());
    out.extend_from_slice(&MAGIC.to_be_bytes());
    out.extend_from_slice(&PROTOCOL_VERSION.to_be_bytes());
    out.extend_from_slice(&ty.to_be_bytes());
    out.extend_from_slice(&req.to_be_bytes());
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

fn manual_push(buffer: &mut Vec<u8>, bytes: &[u8]) -> Result<Vec<Frame>, ParseError> {
    buffer.extend_from_slice(bytes);
    let mut out = Vec::new();
    loop {
        if buffer.len() < HEADER_LEN {
            break;
        }
        let magic = u32::from_be_bytes(buffer[0..4].try_into().unwrap());
        if magic != MAGIC {
            return Err(ParseError::BadMagic);
        }
        let version = u16::from_be_bytes(buffer[4..6].try_into().unwrap());
        if version != PROTOCOL_VERSION {
            return Err(ParseError::UnsupportedVersion(version));
        }
        let ty = u16::from_be_bytes(buffer[6..8].try_into().unwrap());
        let req = u64::from_be_bytes(buffer[8..16].try_into().unwrap());
        let len = u32::from_be_bytes(buffer[16..20].try_into().unwrap()) as usize;
        let known = MessageType::from_u16(ty)
            .map(|m| m.is_control())
            .unwrap_or(false);
        let limit = if known {
            MAX_CONTROL
        } else {
            ai_native_l1_pow_bench::MAX_FRAME
        };
        if len > limit {
            return Err(ParseError::PayloadTooLarge {
                declared: len,
                limit,
            });
        }
        let total = HEADER_LEN
            .checked_add(len)
            .ok_or(ParseError::LengthOverflow)?;
        if buffer.len() < total {
            break;
        }
        out.push(Frame {
            version,
            message_type: ty,
            request_id: req,
            payload: buffer[HEADER_LEN..total].to_vec(),
        });
        buffer.drain(..total);
    }
    Ok(out)
}

fn handle(mut stream: TcpStream, cfg: Config) {
    let _ = stream.set_read_timeout(Some(Duration::from_millis(300)));
    let _ = stream.set_write_timeout(Some(Duration::from_millis(300)));
    let mut manual = Vec::new();
    let mut decoder_a = StreamDecoder::new(MAX_CONTROL + HEADER_LEN);
    let mut buf = [0u8; 2048];
    let mut count = 0usize;
    loop {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                let frames = match cfg.mode {
                    Mode::A => decoder_a.push(&buf[..n]).map_err(|e| format!("{e:?}")),
                    Mode::B => manual_push(&mut manual, &buf[..n]).map_err(|e| format!("{e:?}")),
                };
                let Ok(frames) = frames else {
                    eprintln!(
                        "node={} mode={:?} event=decode_error",
                        cfg.node_id, cfg.mode
                    );
                    break;
                };
                for f in frames {
                    count += 1;
                    match MessageType::from_u16(f.message_type) {
                        Some(MessageType::Hello) if f.payload.len() == 17 => {
                            eprintln!("node={} mode={:?} event=hello", cfg.node_id, cfg.mode);
                            let _ = send_frame(
                                &mut stream,
                                cfg.mode,
                                MessageType::Status,
                                f.request_id,
                                &[0u8; 16],
                            );
                            let _ = send_frame(
                                &mut stream,
                                cfg.mode,
                                MessageType::Hello,
                                f.request_id,
                                &hello(cfg.node_id),
                            );
                        }
                        Some(MessageType::Ping) if f.payload.len() == 8 => {
                            let nonce = u64::from_be_bytes(f.payload.try_into().unwrap());
                            eprintln!("node={} mode={:?} event=ping", cfg.node_id, cfg.mode);
                            let _ = send_frame(
                                &mut stream,
                                cfg.mode,
                                MessageType::Pong,
                                f.request_id,
                                &u64p(nonce),
                            );
                        }
                        Some(MessageType::Pong) if f.payload.len() == 8 => {
                            eprintln!("node={} mode={:?} event=pong_rx", cfg.node_id, cfg.mode)
                        }
                        _ => {}
                    }
                    if count > 32 {
                        let _ = stream.shutdown(Shutdown::Both);
                        return;
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

fn connect(cfg: Config, deadline: Instant) {
    while Instant::now() < deadline {
        if let Ok(mut s) = TcpStream::connect(("127.0.0.1", cfg.peer)) {
            let _ = s.set_read_timeout(Some(Duration::from_millis(300)));
            let _ = s.set_write_timeout(Some(Duration::from_millis(300)));
            eprintln!(
                "node={} mode={:?} event=connected peer={}",
                cfg.node_id, cfg.mode, cfg.peer
            );
            if !send_frame(
                &mut s,
                cfg.mode,
                MessageType::Hello,
                cfg.node_id,
                &hello(cfg.node_id),
            ) {
                return;
            }
            if !send_frame(
                &mut s,
                cfg.mode,
                MessageType::Ping,
                cfg.node_id + 1000,
                &u64p(cfg.node_id ^ 0xC0DE),
            ) {
                return;
            }
            let mut manual = Vec::new();
            let mut decoder_a = StreamDecoder::new(MAX_CONTROL + HEADER_LEN);
            let mut buf = [0u8; 2048];
            let until = Instant::now() + Duration::from_millis(1600);
            while Instant::now() < until {
                match s.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        let frames = match cfg.mode {
                            Mode::A => decoder_a.push(&buf[..n]).unwrap_or_default(),
                            Mode::B => manual_push(&mut manual, &buf[..n]).unwrap_or_default(),
                        };
                        for f in frames {
                            if f.message_type == MessageType::Pong as u16 {
                                eprintln!(
                                    "node={} mode={:?} event=pong_ack",
                                    cfg.node_id, cfg.mode
                                );
                                return;
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
            return;
        }
        thread::sleep(Duration::from_millis(50));
    }
}

fn main() {
    let cfg = config();
    let listener = TcpListener::bind(("127.0.0.1", cfg.listen)).expect("bind");
    listener.set_nonblocking(true).expect("nonblocking");
    let deadline = Instant::now() + Duration::from_millis(cfg.duration_ms);
    eprintln!(
        "node={} mode={:?} event=ready listen={} peer={}",
        cfg.node_id, cfg.mode, cfg.listen, cfg.peer
    );
    let c = cfg;
    thread::spawn(move || connect(c, deadline));
    while Instant::now() < deadline {
        match listener.accept() {
            Ok((s, _)) => {
                let c = cfg;
                thread::spawn(move || handle(s, c));
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(20))
            }
            Err(_) => break,
        }
    }
    eprintln!("node={} mode={:?} event=done", cfg.node_id, cfg.mode);
}
