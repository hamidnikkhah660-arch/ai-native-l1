use ai_native_l1_pow_bench::{
    encode_frame,
    p2p_contract::{
        decode_capabilities, decode_error, decode_ping, decode_pong, encode_capabilities,
        encode_error, encode_ping, encode_pong, verify_pong_echo, Capability, ErrorCode,
        RequestTracker,
    },
    protocol_profile::{CAPS_MAX_PAYLOAD_TESTNET, PONG_PAYLOAD_LEN},
    stream::StreamDecoder,
    Frame, MessageType, HEADER_LEN, MAX_CONTROL,
};
use std::env;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::thread;
use std::time::{Duration, Instant};

const READ_TIMEOUT_MS: u64 = 350;
const RETRY_MS: u64 = 80;
const PING_REQUEST_TIMEOUT_MS: u64 = 800;
const PING_RESPONSE_WINDOW_MS: u64 = 1200;
const MAX_MESSAGES_PER_CONN: usize = 32;
const LOCAL_CAPABILITIES: [Capability; 2] = [Capability::ChainHeaders, Capability::IdentityAware];

#[derive(Debug, Clone)]
struct Config {
    node_id: u64,
    listen: u16,
    peer: Option<u16>,
    duration_ms: u64,
    validator: char,
}

fn arg_value(args: &[String], name: &str) -> Option<String> {
    args.windows(2).find(|w| w[0] == name).map(|w| w[1].clone())
}

fn parse_u64(args: &[String], name: &str, default: u64) -> u64 {
    arg_value(args, name)
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn parse_u16(args: &[String], name: &str) -> Option<u16> {
    arg_value(args, name).and_then(|v| v.parse().ok())
}

fn config() -> Config {
    let args: Vec<String> = env::args().collect();
    let validator = arg_value(&args, "--validator")
        .and_then(|v| v.chars().next())
        .filter(|c| *c == 'a' || *c == 'b')
        .unwrap_or('a');
    Config {
        node_id: parse_u64(&args, "--node-id", 1),
        listen: parse_u16(&args, "--listen").unwrap_or(43101),
        peer: parse_u16(&args, "--peer"),
        duration_ms: parse_u64(&args, "--duration-ms", 3500),
        validator,
    }
}
fn hello_payload(node_id: u64, validator: char) -> Vec<u8> {
    let mut p = Vec::with_capacity(17);
    p.extend_from_slice(&node_id.to_be_bytes());
    p.extend_from_slice(&1u64.to_be_bytes());
    p.push(validator as u8);
    p
}

fn status_payload(node_id: u64) -> Vec<u8> {
    let mut p = Vec::with_capacity(16);
    p.extend_from_slice(&1u64.to_be_bytes());
    p.extend_from_slice(&node_id.to_be_bytes());
    p
}

fn send_frame(stream: &mut TcpStream, msg: MessageType, request_id: u64, payload: &[u8]) -> bool {
    match encode_frame(1, msg as u16, request_id, payload) {
        Ok(bytes) if bytes.len() <= HEADER_LEN + MAX_CONTROL => stream.write_all(&bytes).is_ok(),
        _ => false,
    }
}

fn handle_frame(stream: &mut TcpStream, node_id: u64, validator: char, frame: Frame) -> bool {
    let Some(kind) = MessageType::from_u16(frame.message_type) else {
        eprintln!(
            "node={node_id} event=unknown_type type={}",
            frame.message_type
        );
        return true;
    };
    match kind {
        MessageType::Hello => {
            if frame.payload.len() != 17 {
                return false;
            }
            eprintln!(
                "node={node_id} event=hello rx_peer={}",
                u64::from_be_bytes(frame.payload[0..8].try_into().unwrap())
            );
            send_frame(
                stream,
                MessageType::Status,
                frame.request_id,
                &status_payload(node_id),
            ) && send_frame(
                stream,
                MessageType::Hello,
                frame.request_id,
                &hello_payload(node_id, validator),
            )
        }
        MessageType::Ping => {
            let Ok(nonce) = decode_ping(&frame.payload) else {
                return false;
            };
            eprintln!("node={node_id} event=ping nonce={nonce}");
            send_frame(
                stream,
                MessageType::Pong,
                frame.request_id,
                &encode_pong(nonce),
            )
        }
        MessageType::Status => frame.payload.len() == 16,
        MessageType::Pong => decode_pong(&frame.payload).is_ok(),
        MessageType::Caps => {
            if frame.request_id == 0 {
                let sent = encode_error(ErrorCode::BadRequest, MessageType::Caps as u16)
                    .map(|payload| {
                        send_frame(stream, MessageType::Error, frame.request_id, &payload)
                    })
                    .unwrap_or(false);
                eprintln!("node={node_id} event=caps_rejected reason=zero_request_id");
                eprintln!(
                    "node={node_id} event=protocol_error_sent code=BadRequest offending_type={} sent={sent}",
                    MessageType::Caps as u16
                );
                return false;
            }
            let remote_caps = match decode_capabilities(&frame.payload) {
                Ok(caps) => caps,
                Err(err) => {
                    eprintln!("node={node_id} event=caps_rejected reason={err:?}");
                    let sent =
                        encode_error(ErrorCode::CapabilityMalformed, MessageType::Caps as u16)
                            .map(|payload| {
                                send_frame(stream, MessageType::Error, frame.request_id, &payload)
                            })
                            .unwrap_or(false);
                    eprintln!(
                        "node={node_id} event=protocol_error_sent code=CapabilityMalformed offending_type={} sent={sent}",
                        MessageType::Caps as u16
                    );
                    return false;
                }
            };
            let negotiated: Vec<Capability> = remote_caps
                .into_iter()
                .filter(|cap| LOCAL_CAPABILITIES.contains(cap))
                .collect();
            let Ok(payload) = encode_capabilities(&negotiated) else {
                return false;
            };
            eprintln!(
                "node={node_id} event=caps_negotiated request_id={} count={}",
                frame.request_id,
                negotiated.len()
            );
            send_frame(stream, MessageType::Caps, frame.request_id, &payload)
        }
        MessageType::Error => {
            match decode_error(&frame.payload) {
                Ok((code, offending_type)) => eprintln!(
                    "node={node_id} event=unsolicited_error code={code:?} offending_type={offending_type}"
                ),
                Err(err) => eprintln!("node={node_id} event=error_rejected reason={err:?}"),
            }
            false
        }
        _ => true,
    }
}
fn serve_connection(mut stream: TcpStream, node_id: u64, validator: char) {
    let _ = stream.set_read_timeout(Some(Duration::from_millis(READ_TIMEOUT_MS)));
    let _ = stream.set_write_timeout(Some(Duration::from_millis(READ_TIMEOUT_MS)));
    let mut decoder = StreamDecoder::new(MAX_CONTROL + HEADER_LEN);
    let mut buf = [0u8; 4096];
    let mut messages = 0usize;
    loop {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                let frames = match decoder.push(&buf[..n]) {
                    Ok(frames) => frames,
                    Err(err) => {
                        eprintln!("node={node_id} event=decode_error err={err:?}");
                        break;
                    }
                };
                for frame in frames {
                    messages += 1;
                    if messages > MAX_MESSAGES_PER_CONN
                        || !handle_frame(&mut stream, node_id, validator, frame)
                    {
                        let _ = stream.shutdown(Shutdown::Both);
                        return;
                    }
                }
            }
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                continue
            }
            Err(_) => break,
        }
    }
}

fn connect_and_probe(cfg: Config, peer: u16, deadline: Instant) {
    while Instant::now() < deadline {
        match TcpStream::connect(("127.0.0.1", peer)) {
            Ok(mut stream) => {
                let _ = stream.set_read_timeout(Some(Duration::from_millis(READ_TIMEOUT_MS)));
                let _ = stream.set_write_timeout(Some(Duration::from_millis(READ_TIMEOUT_MS)));
                eprintln!("node={} event=connected peer={}", cfg.node_id, peer);
                if !send_frame(
                    &mut stream,
                    MessageType::Hello,
                    cfg.node_id,
                    &hello_payload(cfg.node_id, cfg.validator),
                ) {
                    return;
                }
                let Some(caps_request_id) = cfg.node_id.checked_add(2000) else {
                    eprintln!(
                        "node={} event=caps_open_rejected reason=request_id_overflow",
                        cfg.node_id
                    );
                    return;
                };
                let offered_caps = [
                    Capability::ChainHeaders,
                    Capability::Blocks,
                    Capability::IdentityAware,
                ];
                let caps_payload = match encode_capabilities(&offered_caps) {
                    Ok(payload) => payload,
                    Err(err) => {
                        eprintln!(
                            "node={} event=caps_encode_failed reason={err:?}",
                            cfg.node_id
                        );
                        return;
                    }
                };
                let caps_clock = Instant::now();
                let mut caps_tracker = RequestTracker::new();
                if let Err(err) = caps_tracker.open(
                    caps_request_id,
                    MessageType::Caps as u16,
                    PING_REQUEST_TIMEOUT_MS,
                    CAPS_MAX_PAYLOAD_TESTNET,
                ) {
                    eprintln!(
                        "node={} event=caps_open_rejected reason={err:?}",
                        cfg.node_id
                    );
                    return;
                }
                if !send_frame(
                    &mut stream,
                    MessageType::Caps,
                    caps_request_id,
                    &caps_payload,
                ) {
                    eprintln!("node={} event=caps_send_failed", cfg.node_id);
                    return;
                }
                let caps_deadline = caps_clock + Duration::from_millis(PING_RESPONSE_WINDOW_MS);
                let mut caps_decoder = StreamDecoder::new(MAX_CONTROL + HEADER_LEN);
                let mut caps_buf = [0u8; 4096];
                let mut caps_accepted = false;
                while Instant::now() < caps_deadline {
                    match stream.read(&mut caps_buf) {
                        Ok(0) => break,
                        Ok(n) => match caps_decoder.push(&caps_buf[..n]) {
                            Ok(frames) => {
                                for frame in frames {
                                    let is_caps_terminal = frame.message_type
                                        == MessageType::Caps as u16
                                        || frame.message_type == MessageType::Error as u16
                                        || frame.request_id == caps_request_id;
                                    if is_caps_terminal {
                                        let now_ms = caps_clock.elapsed().as_millis() as u64;
                                        if frame.message_type == MessageType::Error as u16 {
                                            if let Err(err) = caps_tracker.complete_error(
                                                frame.request_id,
                                                frame.payload.len(),
                                                now_ms,
                                            ) {
                                                eprintln!(
                                                    "node={} event=capability_rejected reason={err:?}",
                                                    cfg.node_id
                                                );
                                                return;
                                            }
                                            match decode_error(&frame.payload) {
                                                Ok((code, offending_type))
                                                    if offending_type == MessageType::Caps as u16 =>
                                                {
                                                    eprintln!(
                                                        "node={} event=capability_rejected reason={code:?}",
                                                        cfg.node_id
                                                    );
                                                }
                                                Ok((_, offending_type)) => eprintln!(
                                                    "node={} event=capability_rejected reason=OffendingTypeMismatch actual={offending_type}",
                                                    cfg.node_id
                                                ),
                                                Err(err) => eprintln!(
                                                    "node={} event=capability_rejected reason={err:?}",
                                                    cfg.node_id
                                                ),
                                            }
                                            return;
                                        }
                                        if let Err(err) = caps_tracker.complete(
                                            frame.request_id,
                                            frame.message_type,
                                            frame.payload.len(),
                                            now_ms,
                                        ) {
                                            eprintln!(
                                                "node={} event=response_rejected reason={err:?}",
                                                cfg.node_id
                                            );
                                            return;
                                        }
                                        let negotiated = match decode_capabilities(&frame.payload) {
                                            Ok(caps) => caps,
                                            Err(err) => {
                                                eprintln!(
                                                    "node={} event=capability_rejected reason={err:?}",
                                                    cfg.node_id
                                                );
                                                return;
                                            }
                                        };
                                        if negotiated.iter().any(|cap| !offered_caps.contains(cap))
                                        {
                                            eprintln!(
                                                "node={} event=capability_rejected reason=PeerCapabilityNotOffered",
                                                cfg.node_id
                                            );
                                            return;
                                        }
                                        eprintln!(
                                            "node={} event=caps_ack count={}",
                                            cfg.node_id,
                                            negotiated.len()
                                        );
                                        caps_accepted = true;
                                        break;
                                    }
                                    match MessageType::from_u16(frame.message_type) {
                                        Some(MessageType::Hello) => eprintln!(
                                            "node={} event=hello_ack peer={peer}",
                                            cfg.node_id
                                        ),
                                        Some(MessageType::Status) => eprintln!(
                                            "node={} event=status_ack peer={peer}",
                                            cfg.node_id
                                        ),
                                        _ => {}
                                    }
                                }
                                if caps_accepted {
                                    break;
                                }
                            }
                            Err(err) => {
                                eprintln!("node={} event=decode_error err={err:?}", cfg.node_id);
                                return;
                            }
                        },
                        Err(e)
                            if e.kind() == std::io::ErrorKind::WouldBlock
                                || e.kind() == std::io::ErrorKind::TimedOut =>
                        {
                            continue
                        }
                        Err(_) => break,
                    }
                }
                if !caps_accepted {
                    let now_ms = caps_clock.elapsed().as_millis() as u64;
                    if caps_tracker.expire(now_ms) > 0 {
                        eprintln!(
                            "node={} event=capability_timeout request_id={caps_request_id}",
                            cfg.node_id
                        );
                    }
                    return;
                }

                let Some(ping_request_id) = cfg.node_id.checked_add(1000) else {
                    eprintln!(
                        "node={} event=request_open_rejected reason=request_id_overflow",
                        cfg.node_id
                    );
                    return;
                };
                let challenge = cfg.node_id ^ 0xA11CE;
                let tracker_clock = Instant::now();
                let request_timeout_ms = PING_REQUEST_TIMEOUT_MS;
                let mut tracker = RequestTracker::new();
                if let Err(err) = tracker.open(
                    ping_request_id,
                    MessageType::Pong as u16,
                    request_timeout_ms,
                    PONG_PAYLOAD_LEN,
                ) {
                    eprintln!(
                        "node={} event=request_open_rejected reason={err:?}",
                        cfg.node_id
                    );
                    return;
                }
                if !send_frame(
                    &mut stream,
                    MessageType::Ping,
                    ping_request_id,
                    &encode_ping(challenge),
                ) {
                    eprintln!("node={} event=request_send_failed", cfg.node_id);
                    return;
                }

                let mut decoder = StreamDecoder::new(MAX_CONTROL + HEADER_LEN);
                let mut buf = [0u8; 4096];
                let receive_deadline =
                    tracker_clock + Duration::from_millis(PING_RESPONSE_WINDOW_MS);
                while Instant::now() < receive_deadline {
                    match stream.read(&mut buf) {
                        Ok(0) => break,
                        Ok(n) => match decoder.push(&buf[..n]) {
                            Ok(frames) => {
                                for frame in frames {
                                    let is_tracked_response = frame.message_type
                                        == MessageType::Pong as u16
                                        || frame.request_id == ping_request_id;
                                    if is_tracked_response {
                                        let now_ms = tracker_clock.elapsed().as_millis() as u64;
                                        if let Err(err) = tracker.complete(
                                            frame.request_id,
                                            frame.message_type,
                                            frame.payload.len(),
                                            now_ms,
                                        ) {
                                            eprintln!(
                                                "node={} event=response_rejected reason={err:?}",
                                                cfg.node_id
                                            );
                                            return;
                                        }
                                        if let Err(err) =
                                            verify_pong_echo(challenge, &frame.payload)
                                        {
                                            eprintln!(
                                                "node={} event=response_rejected reason={err:?}",
                                                cfg.node_id
                                            );
                                            return;
                                        }
                                        eprintln!(
                                            "node={} event=pong_ack peer={peer}",
                                            cfg.node_id
                                        );
                                        return;
                                    }

                                    match MessageType::from_u16(frame.message_type) {
                                        Some(MessageType::Hello) => eprintln!(
                                            "node={} event=hello_ack peer={peer}",
                                            cfg.node_id
                                        ),
                                        Some(MessageType::Status) => eprintln!(
                                            "node={} event=status_ack peer={peer}",
                                            cfg.node_id
                                        ),
                                        _ => {}
                                    }
                                }
                            }
                            Err(err) => {
                                eprintln!("node={} event=decode_error err={err:?}", cfg.node_id);
                                return;
                            }
                        },
                        Err(e)
                            if e.kind() == std::io::ErrorKind::WouldBlock
                                || e.kind() == std::io::ErrorKind::TimedOut =>
                        {
                            continue
                        }
                        Err(_) => break,
                    }
                }
                let now_ms = tracker_clock.elapsed().as_millis() as u64;
                if tracker.expire(now_ms) > 0 {
                    eprintln!(
                        "node={} event=request_timeout request_id={ping_request_id}",
                        cfg.node_id
                    );
                }
                return;
            }
            Err(_) => thread::sleep(Duration::from_millis(RETRY_MS)),
        }
    }
}
fn main() {
    let cfg = config();
    let listener = TcpListener::bind(("127.0.0.1", cfg.listen)).expect("bind loopback listener");
    listener
        .set_nonblocking(true)
        .expect("set listener nonblocking");
    eprintln!(
        "node={} event=ready listen={} validator={}",
        cfg.node_id, cfg.listen, cfg.validator
    );
    let deadline = Instant::now() + Duration::from_millis(cfg.duration_ms);

    if let Some(peer) = cfg.peer {
        let client_cfg = cfg.clone();
        thread::spawn(move || connect_and_probe(client_cfg, peer, deadline));
    }

    while Instant::now() < deadline {
        match listener.accept() {
            Ok((stream, addr)) => {
                eprintln!("node={} event=accepted addr={addr}", cfg.node_id);
                let node_id = cfg.node_id;
                let validator = cfg.validator;
                thread::spawn(move || serve_connection(stream, node_id, validator));
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(20))
            }
            Err(e) => {
                eprintln!("node={} event=accept_error err={e}", cfg.node_id);
                break;
            }
        }
    }
    eprintln!("node={} event=done", cfg.node_id);
}
