use ai_native_l1_pow_bench::auth_transport::{
    AUTH_ACK_LEN, AUTH_HELLO_LEN, AUTH_MAGIC, AUTH_TAG_LEN, AUTH_VERSION, MAX_AUTH_RECORD,
    RECORD_HEADER_LEN,
};
use ai_native_l1_pow_bench::MAX_FRAME;
use std::{
    env,
    io::{self, Read, Write},
    net::{TcpListener, TcpStream},
    thread,
    time::{Duration, Instant},
};
#[derive(Clone)]
struct C {
    listen: u16,
    upstream: u16,
    mode: String,
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
        listen: n(&a, "--listen", 43901),
        upstream: n(&a, "--upstream", 43902),
        mode: v(&a, "--mode").unwrap_or("clean".into()),
        duration: n(&a, "--duration-ms", 6500),
    }
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
fn read_record(s: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut h = [0u8; 18];
    read_full(s, &mut h, 2500)?;
    if u32::from_be_bytes(h[0..4].try_into().unwrap()) != AUTH_MAGIC
        || u16::from_be_bytes(h[4..6].try_into().unwrap()) != AUTH_VERSION
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "bad auth header",
        ));
    }
    let len = u32::from_be_bytes(h[14..18].try_into().unwrap()) as usize;
    if len > MAX_FRAME {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "oversize"));
    }
    let total = RECORD_HEADER_LEN
        .checked_add(len)
        .and_then(|x| x.checked_add(AUTH_TAG_LEN))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "overflow"))?;
    if total > MAX_AUTH_RECORD {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "oversize"));
    }
    let mut rest = vec![0u8; len + AUTH_TAG_LEN];
    read_full(s, &mut rest, 2500)?;
    let mut out = h.to_vec();
    out.extend_from_slice(&rest);
    Ok(out)
}

fn connect_upstream(port: u16, deadline: Instant) -> io::Result<TcpStream> {
    while Instant::now() < deadline {
        if let Ok(s) = TcpStream::connect(("127.0.0.1", port)) {
            return Ok(s);
        }
        thread::sleep(Duration::from_millis(30))
    }
    Err(io::Error::new(io::ErrorKind::TimedOut, "upstream"))
}
fn relay(mut down: TcpStream, c: C) {
    let deadline = Instant::now() + Duration::from_millis(c.duration);
    let mut up = match connect_upstream(c.upstream, deadline) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("relay event=upstream_error err={e}");
            return;
        }
    };
    let _ = down.set_read_timeout(Some(Duration::from_millis(2000)));
    let _ = up.set_read_timeout(Some(Duration::from_millis(2000)));
    let _ = down.set_write_timeout(Some(Duration::from_millis(2000)));
    let _ = up.set_write_timeout(Some(Duration::from_millis(2000)));
    let mut hello = vec![0u8; AUTH_HELLO_LEN];
    if read_full(&mut down, &mut hello, 2500).is_err() {
        return;
    }
    if up.write_all(&hello).is_err() {
        return;
    }
    let mut ack = vec![0u8; AUTH_ACK_LEN];
    if read_full(&mut up, &mut ack, 2500).is_err() {
        return;
    }
    if down.write_all(&ack).is_err() {
        return;
    }
    eprintln!("relay event=handshake_forwarded mode={}", c.mode);
    let mut req = match read_record(&mut down) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("relay event=request_read_error err={e}");
            return;
        }
    };
    match c.mode.as_str() {
        "drop" => {
            eprintln!("relay event=drop_authenticated_record");
            return;
        }
        "tamper" => {
            let pos = RECORD_HEADER_LEN;
            req[pos] ^= 1;
            eprintln!("relay event=tamper_authenticated_record");
        }
        _ => {}
    }
    if up.write_all(&req).is_err() {
        return;
    }
    eprintln!("relay event=request_forwarded bytes={}", req.len());
    match read_record(&mut up) {
        Ok(resp) => {
            let _ = down.write_all(&resp);
            eprintln!("relay event=response_forwarded bytes={}", resp.len())
        }
        Err(e) => eprintln!("relay event=no_valid_response err={e}"),
    }
}
fn main() {
    let c = cfg();
    let l = TcpListener::bind(("127.0.0.1", c.listen)).expect("bind");
    l.set_nonblocking(true).unwrap();
    let d = Instant::now() + Duration::from_millis(c.duration);
    eprintln!(
        "relay event=ready listen={} upstream={} mode={}",
        c.listen, c.upstream, c.mode
    );
    while Instant::now() < d {
        match l.accept() {
            Ok((s, _)) => {
                relay(s, c.clone());
                break;
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(20))
            }
            Err(_) => break,
        }
    }
    eprintln!("relay event=done")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn max_record_constant_is_consistent() {
        assert!(MAX_AUTH_RECORD > RECORD_HEADER_LEN + AUTH_TAG_LEN);
        assert_eq!(AUTH_HELLO_LEN, 65);
        assert_eq!(AUTH_ACK_LEN, 97)
    }
}
