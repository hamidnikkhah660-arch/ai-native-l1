//! Incremental stream framing for adversarial transport tests.
//! Research component; it is not production socket code.

use crate::{
    decode_frame, Frame, MessageType, ParseError, HEADER_LEN, MAGIC, MAX_CONTROL, MAX_FRAME,
    PROTOCOL_VERSION,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamError {
    Frame(ParseError),
    BufferLimit,
}

pub struct StreamDecoder {
    buffer: Vec<u8>,
    max_buffer: usize,
}

impl StreamDecoder {
    pub fn new(max_buffer: usize) -> Self {
        Self {
            buffer: Vec::new(),
            max_buffer,
        }
    }

    pub fn buffered_len(&self) -> usize {
        self.buffer.len()
    }

    pub fn push(&mut self, bytes: &[u8]) -> Result<Vec<Frame>, StreamError> {
        if self.buffer.len().saturating_add(bytes.len()) > self.max_buffer {
            return Err(StreamError::BufferLimit);
        }

        self.buffer.extend_from_slice(bytes);
        let mut frames = Vec::new();

        loop {
            if self.buffer.len() < HEADER_LEN {
                break;
            }

            let magic = u32::from_be_bytes([
                self.buffer[0],
                self.buffer[1],
                self.buffer[2],
                self.buffer[3],
            ]);
            if magic != MAGIC {
                return Err(StreamError::Frame(ParseError::BadMagic));
            }

            let version = u16::from_be_bytes([self.buffer[4], self.buffer[5]]);
            if version != PROTOCOL_VERSION {
                return Err(StreamError::Frame(ParseError::UnsupportedVersion(version)));
            }

            let message_type = u16::from_be_bytes([self.buffer[6], self.buffer[7]]);
            let declared = u32::from_be_bytes([
                self.buffer[16],
                self.buffer[17],
                self.buffer[18],
                self.buffer[19],
            ]) as usize;

            let control = MessageType::from_u16(message_type)
                .map(|m| m.is_control())
                .unwrap_or(false);
            let limit = if control { MAX_CONTROL } else { MAX_FRAME };

            if declared > limit {
                return Err(StreamError::Frame(ParseError::PayloadTooLarge {
                    declared,
                    limit,
                }));
            }

            let total = HEADER_LEN
                .checked_add(declared)
                .ok_or(StreamError::Frame(ParseError::LengthOverflow))?;

            if self.buffer.len() < total {
                break;
            }

            let frame = decode_frame(&self.buffer[..total]).map_err(StreamError::Frame)?;
            frames.push(frame);
            self.buffer.drain(..total);
        }

        Ok(frames)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encode_frame;

    #[test]
    fn one_byte_chunks_reassemble_a_frame() {
        let encoded = encode_frame(1, 2, 77, b"hello").unwrap();
        let mut decoder = StreamDecoder::new(MAX_FRAME + HEADER_LEN);

        let mut out = Vec::new();
        for byte in encoded {
            out.extend(decoder.push(&[byte]).unwrap());
        }

        assert_eq!(out.len(), 1);
        assert_eq!(out[0].request_id, 77);
        assert_eq!(out[0].payload, b"hello");
        assert_eq!(decoder.buffered_len(), 0);
    }

    #[test]
    fn multiple_frames_in_one_chunk_are_split() {
        let a = encode_frame(1, 2, 1, b"a").unwrap();
        let b = encode_frame(1, 3, 2, b"bc").unwrap();
        let mut both = a;
        both.extend_from_slice(&b);

        let mut decoder = StreamDecoder::new(MAX_FRAME * 2 + HEADER_LEN * 2);
        let out = decoder.push(&both).unwrap();

        assert_eq!(out.len(), 2);
        assert_eq!(out[0].request_id, 1);
        assert_eq!(out[1].request_id, 2);
    }

    #[test]
    fn incomplete_frame_is_buffered_without_error() {
        let encoded = encode_frame(1, 2, 9, b"payload").unwrap();
        let cut = encoded.len() - 2;
        let mut decoder = StreamDecoder::new(MAX_FRAME + HEADER_LEN);

        let out = decoder.push(&encoded[..cut]).unwrap();
        assert!(out.is_empty());
        assert_eq!(decoder.buffered_len(), cut);

        let out = decoder.push(&encoded[cut..]).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(decoder.buffered_len(), 0);
    }

    #[test]
    fn oversize_is_rejected_from_header_before_waiting_for_payload() {
        let mut header = vec![0u8; HEADER_LEN];
        header[0..4].copy_from_slice(&MAGIC.to_be_bytes());
        header[4..6].copy_from_slice(&PROTOCOL_VERSION.to_be_bytes());
        header[6..8].copy_from_slice(&(2u16).to_be_bytes());
        header[16..20].copy_from_slice(&((MAX_FRAME + 1) as u32).to_be_bytes());

        let mut decoder = StreamDecoder::new(MAX_FRAME + HEADER_LEN);
        assert!(matches!(
            decoder.push(&header),
            Err(StreamError::Frame(ParseError::PayloadTooLarge { .. }))
        ));
    }

    #[test]
    fn buffer_budget_is_bounded() {
        let mut decoder = StreamDecoder::new(32);
        assert!(decoder.push(&[0u8; 32]).is_err() || decoder.buffered_len() <= 32);
        assert!(matches!(decoder.push(&[1]), Err(StreamError::BufferLimit)));
    }

    #[test]
    fn malformed_magic_is_fail_closed() {
        let mut decoder = StreamDecoder::new(128);
        assert!(matches!(
            decoder.push(&[0xAA; HEADER_LEN]),
            Err(StreamError::Frame(ParseError::BadMagic))
        ));
    }

    fn next_u64(state: &mut u64) -> u64 {
        let mut x = *state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        *state = x;
        x
    }

    #[test]
    fn arbitrary_bytes_do_not_panic() {
        let mut state = 0xD1CE_F00D_1234_5678u64;

        for _case in 0..5_000 {
            let len = (next_u64(&mut state) as usize) % 256;
            let mut input = vec![0u8; len];
            for byte in &mut input {
                *byte = next_u64(&mut state) as u8;
            }

            let mut decoder = StreamDecoder::new(8 * 1024);
            let _ = decoder.push(&input);
        }
    }

    #[test]
    fn split_points_preserve_valid_frame() {
        let encoded = encode_frame(1, 2, 123, b"property-test-payload").unwrap();

        for split in 0..=encoded.len() {
            let mut decoder = StreamDecoder::new(MAX_FRAME + HEADER_LEN);
            let first = decoder.push(&encoded[..split]).unwrap();
            let second = decoder.push(&encoded[split..]).unwrap();

            let mut all = first;
            all.extend(second);

            assert_eq!(all.len(), 1, "split={split}");
            assert_eq!(all[0].request_id, 123);
            assert_eq!(all[0].payload, b"property-test-payload");
        }
    }

    #[test]
    fn single_byte_mutations_never_panic() {
        let encoded = encode_frame(1, 2, 123, b"mutation-test").unwrap();

        for position in 0..encoded.len() {
            let mut mutated = encoded.clone();
            mutated[position] ^= 0xFF;

            let mut decoder = StreamDecoder::new(MAX_FRAME + HEADER_LEN);
            let _ = decoder.push(&mutated);
        }
    }
}
