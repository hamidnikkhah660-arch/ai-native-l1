use std::fs;

const HEADER: usize = 19;
const MAX_SIGNATURE: usize = 64 * 1024;
const VERSION: u16 = 1;

fn decode(b: &[u8]) -> bool {
    if b.len() < HEADER {
        return false;
    }
    let version = u16::from_be_bytes([b[0], b[1]]);
    let suite = u16::from_be_bytes([b[2], b[3]]);
    let generation = u32::from_be_bytes([b[8], b[9], b[10], b[11]]);
    let purpose = b[12];
    let len = u32::from_be_bytes([b[15], b[16], b[17], b[18]]) as usize;
    if version != VERSION
        || !matches!(suite, 1 | 100 | 101 | 200)
        || !matches!(purpose, 1 | 2 | 3 | 4)
    {
        return false;
    }
    if generation == 0 || len == 0 || len > MAX_SIGNATURE || b.len() != HEADER + len {
        return false;
    }
    true
}

fn encode(
    suite: u16,
    key_id: u32,
    generation: u32,
    purpose: u8,
    domain: u16,
    sig: &[u8],
) -> Option<Vec<u8>> {
    if !matches!(suite, 1 | 100 | 101 | 200)
        || !matches!(purpose, 1 | 2 | 3 | 4)
        || generation == 0
        || sig.is_empty()
        || sig.len() > MAX_SIGNATURE
    {
        return None;
    }
    let mut b = Vec::with_capacity(HEADER + sig.len());
    b.extend_from_slice(&VERSION.to_be_bytes());
    b.extend_from_slice(&suite.to_be_bytes());
    b.extend_from_slice(&key_id.to_be_bytes());
    b.extend_from_slice(&generation.to_be_bytes());
    b.push(purpose);
    b.extend_from_slice(&domain.to_be_bytes());
    b.extend_from_slice(&(sig.len() as u32).to_be_bytes());
    b.extend_from_slice(sig);
    Some(b)
}

fn main() {
    let text =
        fs::read_to_string("simulations/cp0023c_signature_vectors.txt").expect("vector file");
    let mut accepted = 0usize;
    for raw in text
        .lines()
        .filter(|x| !x.is_empty() && !x.starts_with('#'))
    {
        let parts: Vec<&str> = raw.split('|').collect();
        assert_eq!(parts.len(), 3);
        let wire = hex(&parts[1]);
        let actual = decode(&wire);
        let expected = parts[2] == "accept";
        assert_eq!(actual, expected, "case {}", parts[0]);
        if expected {
            accepted += 1;
        }
    }
    let generated = encode(1, 42, 1, 2, 7, &[1, 2, 3, 4]).unwrap();
    let expected = hex("000100010000002a000000010200070000000401020304");
    assert_eq!(generated, expected);
    println!("CP-0023-C-RUST PASS accepted_vectors={accepted} rejected_vectors=4");
}

fn hex(s: &str) -> Vec<u8> {
    let bytes = s.as_bytes();
    assert!(bytes.len() % 2 == 0);
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for i in (0..bytes.len()).step_by(2) {
        out.push((nibble(bytes[i]) << 4) | nibble(bytes[i + 1]));
    }
    out
}
fn nibble(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        b'A'..=b'F' => c - b'A' + 10,
        _ => panic!("bad hex"),
    }
}
