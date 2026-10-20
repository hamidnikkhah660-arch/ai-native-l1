use snow::Builder;
use std::error::Error;

const PATTERN: &str = "Noise_NNpsk0_25519_ChaChaPoly_SHA256";
const PROLOGUE: &[u8] = b"AI-NATIVE-L1/transport-v0.1";

type BoxError = Box<dyn Error + Send + Sync>;

fn build(is_initiator: bool, psk: &[u8; 32]) -> Result<snow::HandshakeState, BoxError> {
    let builder = Builder::new(PATTERN.parse()?)
        .prologue(PROLOGUE)
        .psk(0, psk);
    Ok(if is_initiator {
        builder.build_initiator()?
    } else {
        builder.build_responder()?
    })
}

fn handshake(
    initiator_psk: &[u8; 32],
    responder_psk: &[u8; 32],
) -> Result<(snow::TransportState, snow::TransportState), BoxError> {
    let mut i = build(true, initiator_psk)?;
    let mut r = build(false, responder_psk)?;
    let mut ib = [0u8; 1024];
    let mut rb = [0u8; 1024];
    let n1 = i.write_message(&[], &mut ib)?;
    r.read_message(&ib[..n1], &mut rb)?;
    let n2 = r.write_message(&[], &mut rb)?;
    i.read_message(&rb[..n2], &mut ib)?;
    Ok((i.into_transport_mode()?, r.into_transport_mode()?))
}

fn main() -> Result<(), BoxError> {
    let psk = [0x55u8; 32];
    let (mut i, mut r) = handshake(&psk, &psk)?;
    let mut wire = [0u8; 256];
    let n = i.write_message(b"noise-probe", &mut wire)?;
    let mut plain = [0u8; 256];
    let m = r.read_message(&wire[..n], &mut plain)?;
    println!("noise_roundtrip={} bytes", m);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_psk_roundtrip() {
        let psk = [0x55u8; 32];
        let (mut i, mut r) = handshake(&psk, &psk).unwrap();
        let mut wire = [0u8; 256];
        let n = i.write_message(b"hello", &mut wire).unwrap();
        let mut plain = [0u8; 256];
        let m = r.read_message(&wire[..n], &mut plain).unwrap();
        assert_eq!(&plain[..m], b"hello");
    }

    #[test]
    fn wrong_psk_rejects_handshake() {
        let good = [1u8; 32];
        let bad = [2u8; 32];
        assert!(handshake(&good, &bad).is_err());
    }

    #[test]
    fn tamper_rejected() {
        let psk = [3u8; 32];
        let (mut i, mut r) = handshake(&psk, &psk).unwrap();
        let mut wire = [0u8; 256];
        let n = i.write_message(b"tamper", &mut wire).unwrap();
        wire[n - 1] ^= 1;
        let mut plain = [0u8; 256];
        assert!(r.read_message(&wire[..n], &mut plain).is_err());
    }

    #[test]
    fn replay_rejected() {
        let psk = [4u8; 32];
        let (mut i, mut r) = handshake(&psk, &psk).unwrap();
        let mut wire = [0u8; 256];
        let n = i.write_message(b"once", &mut wire).unwrap();
        let mut plain = [0u8; 256];
        assert_eq!(r.read_message(&wire[..n], &mut plain).unwrap(), 4);
        assert!(r.read_message(&wire[..n], &mut plain).is_err());
    }

    #[test]
    fn bidirectional_transport_states_work() {
        let psk = [5u8; 32];
        let (mut i, mut r) = handshake(&psk, &psk).unwrap();
        let mut wire = [0u8; 256];
        let mut plain = [0u8; 256];
        let n = i.write_message(b"from-i", &mut wire).unwrap();
        assert_eq!(r.read_message(&wire[..n], &mut plain).unwrap(), 6);
        let n = r.write_message(b"from-r", &mut wire).unwrap();
        assert_eq!(i.read_message(&wire[..n], &mut plain).unwrap(), 6);
    }
}
