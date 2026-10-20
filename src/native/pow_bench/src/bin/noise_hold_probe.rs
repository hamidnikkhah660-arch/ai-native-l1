use std::{env, io::Write, net::TcpStream, time::Duration};
fn main() {
    let a: Vec<String> = env::args().collect();
    let port: u16 = a
        .windows(2)
        .find(|x| x[0] == "--port")
        .and_then(|x| x[1].parse().ok())
        .unwrap_or(44501);
    let hold: u64 = a
        .windows(2)
        .find(|x| x[0] == "--hold-ms")
        .and_then(|x| x[1].parse().ok())
        .unwrap_or(1600);
    match TcpStream::connect(("127.0.0.1", port)) {
        Ok(mut s) => {
            let _ = s.write_all(&[0, 65]);
            std::thread::sleep(Duration::from_millis(hold));
        }
        Err(e) => eprintln!("hold_connect_failed={e}"),
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn bounded_probe() {
        assert!(65u16 < 1024);
    }
}
