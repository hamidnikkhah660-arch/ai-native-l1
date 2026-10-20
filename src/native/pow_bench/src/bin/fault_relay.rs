use ai_native_l1_pow_bench::{
    encode_frame,
    stream::StreamDecoder,
    transport::{FaultConfig, FaultInjector},
    MessageType, HEADER_LEN, MAX_CONTROL,
};
use std::collections::VecDeque;
use std::env;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::{Duration, Instant};

#[derive(Clone, Copy)]
struct Config {
    listen: u16,
    upstream: u16,
    duration_ms: u64,
    seed: u64,
    fault: FaultConfig,
}

fn val(args: &[String], name: &str) -> Option<String> {
    args.windows(2).find(|w| w[0] == name).map(|w| w[1].clone())
}
fn num<T: std::str::FromStr>(args: &[String], name: &str, default: T) -> T {
    val(args, name)
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}
fn config() -> Config {
    let a: Vec<String> = env::args().collect();
    Config {
        listen: num(&a, "--listen", 43210),
        upstream: num(&a, "--upstream", 43212),
        duration_ms: num(&a, "--duration-ms", 4000),
        seed: num(&a, "--seed", 7),
        fault: FaultConfig {
            drop_per_mille: num(&a, "--drop-per-mille", 0),
            base_delay_ms: num(&a, "--delay-ms", 0),
            jitter_ms: num(&a, "--jitter-ms", 0),
            reorder_per_mille: num(&a, "--reorder-per-mille", 0),
        },
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

fn main() {
    let cfg = config();
    assert!(
        cfg.fault.validate(),
        "fault probabilities must be <= 1000 per-mille"
    );
    let listener = TcpListener::bind(("127.0.0.1", cfg.listen)).expect("relay bind");
    listener.set_nonblocking(true).expect("relay nonblocking");
    let start = Instant::now();
    let deadline = start + Duration::from_millis(cfg.duration_ms);
    eprintln!(
        "relay event=ready listen={} upstream={} drop={} delay={} jitter={} reorder={}",
        cfg.listen,
        cfg.upstream,
        cfg.fault.drop_per_mille,
        cfg.fault.base_delay_ms,
        cfg.fault.jitter_ms,
        cfg.fault.reorder_per_mille
    );

    let downstream = loop {
        match listener.accept() {
            Ok((stream, addr)) => {
                eprintln!("relay event=accepted addr={addr}");
                break stream;
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock && Instant::now() < deadline => {
                thread::sleep(Duration::from_millis(20))
            }
            Err(_) => {
                eprintln!("relay event=accept_timeout");
                return;
            }
        }
    };
    let Some(upstream) = connect_retry(cfg.upstream, deadline) else {
        eprintln!("relay event=upstream_timeout");
        return;
    };
    run_relay(downstream, upstream, cfg);
}

fn run_relay(mut downstream: TcpStream, mut upstream: TcpStream, cfg: Config) {
    let _ = downstream.set_nonblocking(true);
    let _ = upstream.set_nonblocking(true);
    let mut decoder_down = StreamDecoder::new(MAX_CONTROL + HEADER_LEN);
    let mut decoder_up = StreamDecoder::new(MAX_CONTROL + HEADER_LEN);
    let mut fx = FaultInjector::new(cfg.fault, cfg.seed);
    let start = Instant::now();
    let deadline = start + Duration::from_millis(cfg.duration_ms);
    let mut queue: VecDeque<(Instant, Vec<u8>, u64)> = VecDeque::new();
    let mut sequence = 0u64;
    let mut buf = [0u8; 4096];
    let mut dropped = 0usize;

    while Instant::now() < deadline {
        match downstream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => match decoder_down.push(&buf[..n]) {
                Ok(frames) => {
                    for frame in frames {
                        let raw = match encode_frame(
                            frame.version,
                            frame.message_type,
                            frame.request_id,
                            &frame.payload,
                        ) {
                            Ok(raw) => raw,
                            Err(_) => continue,
                        };
                        let now_ms = start.elapsed().as_millis() as u64;
                        match fx.inject(sequence, now_ms) {
                            Some(scheduled) => {
                                let at = start + Duration::from_millis(scheduled.deliver_at_ms);
                                queue.push_back((at, raw, sequence));
                            }
                            None => {
                                dropped += 1;
                                eprintln!(
                                    "relay event=drop seq={sequence} type={:?}",
                                    MessageType::from_u16(frame.message_type)
                                );
                            }
                        }
                        sequence += 1;
                    }
                }
                Err(err) => {
                    eprintln!("relay event=decode_error direction=down err={err:?}");
                    break;
                }
            },
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(_) => break,
        }

        let now = Instant::now();
        let mut ready = Vec::new();
        while let Some((at, _, _)) = queue.front() {
            if *at > now {
                break;
            }
            ready.push(queue.pop_front().unwrap());
        }
        ready.sort_by_key(|(at, _, seq)| (*at, *seq));
        for (_, bytes, seq) in ready {
            if upstream.write_all(&bytes).is_err() {
                return;
            }
            eprintln!("relay event=forward seq={seq} bytes={}", bytes.len());
        }

        match upstream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => match decoder_up.push(&buf[..n]) {
                Ok(frames) => {
                    for frame in frames {
                        let Ok(raw) = encode_frame(
                            frame.version,
                            frame.message_type,
                            frame.request_id,
                            &frame.payload,
                        ) else {
                            continue;
                        };
                        if downstream.write_all(&raw).is_err() {
                            return;
                        }
                        eprintln!(
                            "relay event=reverse type={:?} bytes={}",
                            MessageType::from_u16(frame.message_type),
                            raw.len()
                        );
                    }
                }
                Err(err) => {
                    eprintln!("relay event=decode_error direction=up err={err:?}");
                    break;
                }
            },
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(_) => break,
        }
        thread::sleep(Duration::from_millis(5));
    }

    eprintln!(
        "relay event=done injected={} dropped={} queued={}",
        sequence,
        dropped,
        queue.len()
    );
}

#[allow(dead_code)]
fn _control_roundtrip_limit() -> usize {
    HEADER_LEN + MAX_CONTROL
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn config_defaults_are_bounded() {
        let c = Config {
            listen: 1,
            upstream: 2,
            duration_ms: 1,
            seed: 1,
            fault: FaultConfig {
                drop_per_mille: 0,
                base_delay_ms: 0,
                jitter_ms: 0,
                reorder_per_mille: 0,
            },
        };
        assert!(c.fault.validate());
    }
}
