use std::{env, fs, path::PathBuf};

const MAGIC: [u8; 4] = *b"AIN1";
const VERSION: u16 = 1;
const FRAME_LEN: usize = 20;
const CTX_LEN: usize = 32;
const REQ_MARK: u8 = 0xC1;
const RESP_MARK: u8 = 0xC2;
const GET_HEADERS: u16 = 10;
const HEADERS: u16 = 11;
const HEADER_RECORD_LEN: usize = 25;
const MAX_HEADERS: usize = 64;

fn hex(s: &str) -> Vec<u8> {
    let b = s.as_bytes();
    assert!(b.len() % 2 == 0);
    let mut o = Vec::with_capacity(b.len() / 2);
    for i in (0..b.len()).step_by(2) {
        o.push((n(b[i]) << 4) | n(b[i + 1]));
    }
    o
}

fn n(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        b'A'..=b'F' => c - b'A' + 10,
        _ => panic!("bad hex"),
    }
}

fn u16be(b: &[u8]) -> u16 {
    u16::from_be_bytes([b[0], b[1]])
}

fn u32be(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}

fn valid_inner_frame(frame: &[u8], expected_type: u16) -> bool {
    if frame.len() < FRAME_LEN || frame[..4] != MAGIC {
        return false;
    }
    if u16be(&frame[4..6]) != VERSION || u16be(&frame[6..8]) != expected_type {
        return false;
    }
    u32be(&frame[16..20]) as usize == frame.len() - FRAME_LEN
}

fn decode_request(wire: &[u8]) -> bool {
    if wire.len() < 1 + CTX_LEN + FRAME_LEN || wire[0] != REQ_MARK {
        return false;
    }
    let frame = &wire[1 + CTX_LEN..];
    valid_inner_frame(frame, GET_HEADERS) && u32be(&frame[16..20]) as usize == 0
}

fn decode_response(wire: &[u8]) -> bool {
    if wire.len() < 1 + CTX_LEN + 2 || wire[0] != RESP_MARK {
        return false;
    }
    let payload = &wire[1 + CTX_LEN..];
    let count = u16be(&payload[..2]) as usize;
    if count > MAX_HEADERS {
        return false;
    }
    if payload.len() != 2 + count * HEADER_RECORD_LEN {
        return false;
    }
    for i in 0..count {
        let off = 2 + i * HEADER_RECORD_LEN;
        if payload[off + 24] > 1 {
            return false;
        }
    }
    true
}

fn encode_request(context: &[u8; 32], request_id: u64) -> Vec<u8> {
    let mut o = Vec::with_capacity(1 + CTX_LEN + FRAME_LEN);
    o.push(REQ_MARK);
    o.extend_from_slice(context);
    o.extend_from_slice(&MAGIC);
    o.extend_from_slice(&VERSION.to_be_bytes());
    o.extend_from_slice(&GET_HEADERS.to_be_bytes());
    o.extend_from_slice(&request_id.to_be_bytes());
    o.extend_from_slice(&0u32.to_be_bytes());
    o
}

fn encode_response_empty(context: &[u8; 32]) -> Vec<u8> {
    let mut o = Vec::with_capacity(1 + CTX_LEN + 2);
    o.push(RESP_MARK);
    o.extend_from_slice(context);
    o.extend_from_slice(&0u16.to_be_bytes());
    o
}

fn main() {
    let root = env::var_os("AI_NATIVE_L1_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../.."));
    let vector_path = root.join("simulations/cp0025k_identity_wire_vectors.txt");
    let text = fs::read_to_string(vector_path).unwrap();
    let mut accepted = 0usize;
    let mut rejected = 0usize;
    let mut count = 0usize;

    for raw in text
        .lines()
        .filter(|x| !x.is_empty() && !x.starts_with('#'))
    {
        let p: Vec<&str> = raw.split('|').collect();
        assert_eq!(p.len(), 3);
        let name = p[0];
        let wire = hex(p[1]);
        let expected = p[2] == "accept";
        let got = if name.starts_with("request_") || name == "request_with_payload" {
            decode_request(&wire)
        } else {
            decode_response(&wire)
        };
        assert_eq!(got, expected, "{name}");
        accepted += got as usize;
        rejected += (!got) as usize;
        count += 1;
    }

    let ctx: [u8; 32] = core::array::from_fn(|i| i as u8);
    assert_eq!(
        encode_request(&ctx, 42),
        hex("c1000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f41494e310001000a000000000000002a00000000")
    );
    assert_eq!(
        encode_response_empty(&ctx),
        hex("c2000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f0000")
    );

    assert_eq!(HEADERS, 11);
    println!(
        "CP-0025-K RUST PASS vectors={} accepted={} rejected={}",
        count, accepted, rejected
    );
}
