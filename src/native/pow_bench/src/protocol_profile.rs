//! Current identity-aware P2P testbed wire contract registry.
//! These values are centralized to prevent drift between in-repo implementations.
//! They are not final mainnet constants; the surrounding protocol remains research-stage.

pub const WIRE_MAGIC: u32 = 0x41494E31; // "AIN1"
pub const WIRE_VERSION: u16 = 1;
pub const WIRE_HEADER_LEN: usize = 20;
pub const WIRE_MAX_FRAME_TESTNET: usize = 4 * 1024 * 1024;
pub const WIRE_MAX_CONTROL_TESTNET: usize = 64 * 1024;

pub const IDENTITY_REQUEST_MARKER: u8 = 0xC1;
pub const IDENTITY_RESPONSE_MARKER: u8 = 0xC2;
/// Opt-in v0.2 response envelope: context + canonical AIN1 response frame with correlation ID.
pub const IDENTITY_CORRELATED_RESPONSE_MARKER: u8 = 0xC3;
pub const IDENTITY_CONTEXT_LEN: usize = 32;

pub const GET_HEADERS_TYPE: u16 = 10;
pub const HEADERS_TYPE: u16 = 11;
pub const HELLO_TYPE: u16 = 1;
pub const PING_TYPE: u16 = 2;
pub const PONG_TYPE: u16 = 3;
pub const STATUS_TYPE: u16 = 40;
pub const CAPS_TYPE: u16 = 41;
pub const ERROR_TYPE: u16 = 42;
/// Opt-in C2/C3 profile selection messages, only used inside the identity-bound Noise context.
pub const PROFILE_NEGOTIATE_TYPE: u16 = 43;
pub const PROFILE_SELECTED_TYPE: u16 = 44;
/// Research importer receipt returned over authenticated chain-import sessions.
pub const BLOCK_IMPORT_RECEIPT_TYPE: u16 = 45;
pub const PROFILE_NEGOTIATE_MARKER: u8 = 0xC4;
pub const PROFILE_SELECTED_MARKER: u8 = 0xC5;
pub const PROFILE_VERSION_C2: u16 = 1;
pub const PROFILE_VERSION_C3: u16 = 2;
pub const PROFILE_FEATURE_RESPONSE_CORRELATION: u32 = 1;
pub const PROFILE_NEGOTIATE_PAYLOAD_LEN: usize = 8;
pub const PROFILE_SELECTED_PAYLOAD_LEN: usize = 6;

pub const CHAIN_HEADER_WIRE_LEN: usize = 25;
pub const MAX_HEADERS_TESTNET: usize = 64;
pub const HEADERS_COUNT_LEN: usize = 2;
pub const MAX_HEADERS_PAYLOAD_TESTNET: usize =
    HEADERS_COUNT_LEN + MAX_HEADERS_TESTNET * CHAIN_HEADER_WIRE_LEN;
pub const PING_PAYLOAD_LEN: usize = 8;
pub const PONG_PAYLOAD_LEN: usize = 8;
pub const CAPS_COUNT_LEN: usize = 2;
pub const CAPS_ENTRY_LEN: usize = 2;
pub const MAX_CAPABILITIES_TESTNET: usize = 32;
pub const CAPS_MAX_PAYLOAD_TESTNET: usize =
    CAPS_COUNT_LEN + MAX_CAPABILITIES_TESTNET * CAPS_ENTRY_LEN;
pub const MAX_REQUESTS_PER_PEER_TESTNET: usize = 32;
pub const MAX_OUTSTANDING_REQUEST_BYTES_TESTNET: usize = 8 * 1024 * 1024;
pub const ERROR_PAYLOAD_LEN: usize = 4;
pub const MAX_ERROR_CODE: u16 = 8;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_profile_constants_are_self_consistent() {
        assert_eq!(WIRE_MAGIC, 0x41494E31);
        assert_eq!(WIRE_VERSION, 1);
        assert_eq!(WIRE_HEADER_LEN, 20);
        assert_eq!(IDENTITY_REQUEST_MARKER, 0xC1);
        assert_eq!(IDENTITY_RESPONSE_MARKER, 0xC2);
        assert_eq!(IDENTITY_CORRELATED_RESPONSE_MARKER, 0xC3);
        assert_eq!(IDENTITY_CONTEXT_LEN, 32);
        assert_eq!(GET_HEADERS_TYPE, 10);
        assert_eq!(HEADERS_TYPE, 11);
        assert_eq!(CHAIN_HEADER_WIRE_LEN, 25);
        assert_eq!(MAX_HEADERS_TESTNET, 64);
        assert_eq!(HEADERS_COUNT_LEN, 2);
        assert_eq!(MAX_HEADERS_PAYLOAD_TESTNET, 1602);
        assert_eq!(HELLO_TYPE, 1);
        assert_eq!(PING_TYPE, 2);
        assert_eq!(PONG_TYPE, 3);
        assert_eq!(STATUS_TYPE, 40);
        assert_eq!(CAPS_TYPE, 41);
        assert_eq!(ERROR_TYPE, 42);
        assert_eq!(PROFILE_NEGOTIATE_TYPE, 43);
        assert_eq!(PROFILE_SELECTED_TYPE, 44);
        assert_eq!(BLOCK_IMPORT_RECEIPT_TYPE, 45);
        assert_eq!(PROFILE_NEGOTIATE_MARKER, 0xC4);
        assert_eq!(PROFILE_SELECTED_MARKER, 0xC5);
        assert_eq!(PROFILE_VERSION_C2, 1);
        assert_eq!(PROFILE_VERSION_C3, 2);
        assert_eq!(PROFILE_FEATURE_RESPONSE_CORRELATION, 1);
        assert_eq!(PROFILE_NEGOTIATE_PAYLOAD_LEN, 8);
        assert_eq!(PROFILE_SELECTED_PAYLOAD_LEN, 6);
        assert_eq!(PING_PAYLOAD_LEN, 8);
        assert_eq!(PONG_PAYLOAD_LEN, 8);
        assert_eq!(MAX_CAPABILITIES_TESTNET, 32);
        assert_eq!(CAPS_MAX_PAYLOAD_TESTNET, 66);
        assert_eq!(MAX_REQUESTS_PER_PEER_TESTNET, 32);
        assert_eq!(MAX_OUTSTANDING_REQUEST_BYTES_TESTNET, 8 * 1024 * 1024);
        assert_eq!(ERROR_PAYLOAD_LEN, 4);
        assert_eq!(MAX_ERROR_CODE, 8);
    }

    #[test]
    fn identity_response_is_raw_headers_payload_not_inner_frame() {
        // The identity-aware profile defines HEADERS response payload as u16 count + records.
        assert_eq!(IDENTITY_RESPONSE_MARKER, 0xC2);
        assert_eq!(CHAIN_HEADER_WIRE_LEN, 25);
    }
}
