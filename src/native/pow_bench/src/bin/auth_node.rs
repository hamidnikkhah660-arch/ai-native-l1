use ai_native_l1_pow_bench::{
    auth_transport::{
        derive_direction_key, make_auth_ack, make_auth_hello, open_record, random_nonce,
        seal_record, verify_auth_ack, verify_auth_hello, AuthError, MAX_AUTH_RECORD,
    },
    encode_frame, MessageType, HEADER_LEN,
};
use std::env;
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::{Duration, Instant};

const PSK: [u8; 32] = [0x42; 32];
const WRONG_PSK: [u8; 32] = [0x43; 32];
const IO_TIMEOUT_MS: u64 = 2000;

#[derive(Clone, Copy)]
struct Config {
    id: u64,
    listen: u16,
    peer: u16,
    role: u8,
    wrong_key: bool,
    duration_ms: u64,
}

fn val(a: &[String], name: &str) -> Option<String> {
    a.windows(2).find(|w| w[0] == name).map(|w| w[1].clone())
}
fn num<T: std::str::FromStr>(a: &[String], name: &str, default: T) -> T {
    val(a, name).and_then(|v| v.parse().ok()).unwrap_or(default)
}
fn cfg() -> Config {
    let a: Vec<String> = env::args().collect();
    Config {
        id: num(&a, "--id", 1),
        listen: num(&a, "--listen", 43701),
        peer: num(&a, "--peer", 43702),
        role: num(&a, "--role", 2),
        wrong_key: a.iter().any(|x| x == "--wrong-key"),
        duration_ms: num(&a, "--duration-ms", 4500),
    }
}
fn key(wrong: bool) -> &'static [u8; 32] {
    if wrong {
        &WRONG_PSK
    } else {
        &PSK
    }
}

fn read_full(s: &mut TcpStream, buf: &mut [u8], budget_ms: u64) -> io::Result<()> {
    let deadline = Instant::now() + Duration::from_millis(budget_ms);
    let mut filled = 0usize;
    while filled < buf.len() {
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "read budget exhausted",
            ));
        }
        match s.read(&mut buf[filled..]) {
            Ok(0) => return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "peer closed")),
            Ok(n) => filled += n,
            Err(e)
                if e.kind() == io::ErrorKind::TimedOut || e.kind() == io::ErrorKind::WouldBlock =>
            {
                thread::sleep(Duration::from_millis(1));
            }
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

fn read_record(s: &mut TcpStream) -> Result<Vec<u8>, AuthError> {
    let mut h = [0u8; 18];
    read_full(s, &mut h, 3000).map_err(|_| AuthError::Truncated)?;
    let len = u32::from_be_bytes(h[14..18].try_into().unwrap()) as usize;
    if len > ai_native_l1_pow_bench::MAX_FRAME {
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
    read_full(s, &mut rest, 3000).map_err(|_| AuthError::Truncated)?;
    let mut out = h.to_vec();
    out.extend_from_slice(&rest);
    Ok(out)
}

fn serve_once(mut s: TcpStream, c: Config) {
    let _ = s.set_read_timeout(Some(Duration::from_millis(IO_TIMEOUT_MS)));
    let _ = s.set_write_timeout(Some(Duration::from_millis(IO_TIMEOUT_MS)));
    let mut hello = vec![0u8; 65];
    if read_full(&mut s, &mut hello, 3000).is_err() {
        eprintln!("node={} event=auth_fail kind=truncated_hello", c.id);
        return;
    }
    let Ok((role, client_nonce)) = verify_auth_hello(key(c.wrong_key), &hello) else {
        eprintln!("node={} event=auth_fail kind=bad_mac", c.id);
        return;
    };
    if role != 1 {
        eprintln!("node={} event=auth_fail kind=bad_role", c.id);
        return;
    }
    let Ok(server_nonce) = random_nonce() else {
        eprintln!("node={} event=auth_fail kind=randomness", c.id);
        return;
    };
    let ack = make_auth_ack(key(c.wrong_key), client_nonce, server_nonce);
    if s.write_all(&ack).is_err() {
        return;
    }
    let recv_key = derive_direction_key(key(c.wrong_key), client_nonce, server_nonce, 0);
    match read_record(&mut s).and_then(|r| open_record(&recv_key, 0, &r)) {
        Ok(inner)
            if inner.len() >= HEADER_LEN + 8
                && u16::from_be_bytes(inner[6..8].try_into().unwrap())
                    == MessageType::Ping as u16 =>
        {
            let send_key = derive_direction_key(key(c.wrong_key), client_nonce, server_nonce, 1);
            let pong = encode_frame(
                1,
                MessageType::Pong as u16,
                0,
                &inner[HEADER_LEN..HEADER_LEN + 8],
            )
            .unwrap();
            let record = seal_record(&send_key, 0, &pong).unwrap();
            let _ = s.write_all(&record);
            eprintln!("node={} event=auth_ok event=authenticated_pong", c.id);
        }
        Ok(_) => eprintln!("node={} event=auth_fail kind=unexpected_message", c.id),
        Err(e) => eprintln!("node={} event=auth_fail kind={e:?}", c.id),
    }
}

fn server(c: Config) {
    let l = TcpListener::bind(("127.0.0.1", c.listen)).expect("bind");
    l.set_nonblocking(true).unwrap();
    let deadline = Instant::now() + Duration::from_millis(c.duration_ms);
    eprintln!("node={} role=server event=ready", c.id);
    while Instant::now() < deadline {
        match l.accept() {
            Ok((s, _)) => serve_once(s, c),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(20))
            }
            Err(_) => break,
        }
    }
    eprintln!("node={} event=done", c.id);
}

fn client(c: Config) {
    let deadline = Instant::now() + Duration::from_millis(c.duration_ms);
    while Instant::now() < deadline {
        if let Ok(mut s) = TcpStream::connect(("127.0.0.1", c.peer)) {
            let _ = s.set_read_timeout(Some(Duration::from_millis(IO_TIMEOUT_MS)));
            let _ = s.set_write_timeout(Some(Duration::from_millis(IO_TIMEOUT_MS)));
            let client_nonce = random_nonce().unwrap();
            let hello = make_auth_hello(&PSK, 1, client_nonce).unwrap();
            if s.write_all(&hello).is_err() {
                return;
            }
            let mut ack = vec![0u8; 97];
            if read_full(&mut s, &mut ack, 3000).is_err() {
                eprintln!("node={} event=auth_fail kind=ack_read", c.id);
                return;
            }
            let server_nonce = match verify_auth_ack(&PSK, &ack, client_nonce) {
                Ok(x) => x,
                Err(e) => {
                    eprintln!("node={} event=auth_fail kind={e:?}", c.id);
                    return;
                }
            };
            let out_key = derive_direction_key(&PSK, client_nonce, server_nonce, 0);
            let in_key = derive_direction_key(&PSK, client_nonce, server_nonce, 1);
            let ping = encode_frame(
                1,
                MessageType::Ping as u16,
                1,
                &(0xABCDu64 + c.id).to_be_bytes(),
            )
            .unwrap();
            let record = seal_record(&out_key, 0, &ping).unwrap();
            if s.write_all(&record).is_err() {
                return;
            }
            match read_record(&mut s).and_then(|r| open_record(&in_key, 0, &r)) {
                Ok(inner)
                    if inner.len() >= HEADER_LEN + 8
                        && u16::from_be_bytes(inner[6..8].try_into().unwrap())
                            == MessageType::Pong as u16 =>
                {
                    eprintln!("node={} event=authenticated_pong_ack", c.id);
                    return;
                }
                Ok(_) => eprintln!("node={} event=auth_fail kind=unexpected_response", c.id),
                Err(e) => eprintln!("node={} event=auth_fail kind={e:?}", c.id),
            }
            return;
        }
        thread::sleep(Duration::from_millis(40));
    }
    eprintln!("node={} event=done", c.id);
}

fn main() {
    let c = cfg();
    if c.role == 2 {
        server(c)
    } else {
        client(c)
    }
}
