use ai_native_l1_pow_bench::asset_transactions::{decode_operation, operation_id};

use std::{collections::BTreeMap, fs};

fn parse_vector() -> BTreeMap<String, String> {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../simulations/cpw_asset_operation_vectors.txt");
    let text = fs::read_to_string(path).expect("read CP-W asset-operation vector");
    let mut values = BTreeMap::new();
    let mut lines = text.lines();
    assert_eq!(lines.next(), Some("CPW_ASSET_OPERATION_V1"));
    for line in lines.take_while(|line| *line != "END") {
        let (key, value) = line.split_once('=').expect("key=value vector line");
        assert!(values.insert(key.to_owned(), value.to_owned()).is_none());
    }
    values
}

fn hex(value: &str) -> Vec<u8> {
    assert_eq!(value.len() % 2, 0);
    (0..value.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&value[i..i + 2], 16).expect("hex byte"))
        .collect()
}

#[test]
fn shared_asset_operation_vectors_match_rust() {
    let v = parse_vector();
    let cases = [
        ("CREATE_CANONICAL_HEX", "CREATE_OPERATION_ID"),
        ("MINT_CANONICAL_HEX", "MINT_OPERATION_ID"),
        ("BURN_CANONICAL_HEX", "BURN_OPERATION_ID"),
        ("FREEZE_CANONICAL_HEX", "FREEZE_OPERATION_ID"),
        ("TRANSFER_CANONICAL_HEX", "TRANSFER_OPERATION_ID"),
    ];

    for (bytes_key, id_key) in cases {
        let bytes = hex(&v[bytes_key]);
        let operation = decode_operation(&bytes).expect(bytes_key);
        assert_eq!(
            operation_id(&operation).unwrap(),
            hex(&v[id_key]).as_slice()
        );
        assert_eq!(
            operation_id(&operation).unwrap().as_slice(),
            hex(&v[id_key]).as_slice()
        );
        assert_eq!(
            ai_native_l1_pow_bench::asset_transactions::encode_operation(&operation).unwrap(),
            bytes
        );
    }
}

#[test]
fn operation_tags_cover_exactly_create_through_transfer() {
    let v = parse_vector();
    let expected = [1u8, 2, 3, 4, 5];
    for (bytes_key, tag) in [
        ("CREATE_CANONICAL_HEX", 1u8),
        ("MINT_CANONICAL_HEX", 2u8),
        ("BURN_CANONICAL_HEX", 3u8),
        ("FREEZE_CANONICAL_HEX", 4u8),
        ("TRANSFER_CANONICAL_HEX", 5u8),
    ] {
        let op = decode_operation(&hex(&v[bytes_key])).unwrap();
        assert_eq!(op.tag(), tag);
    }
    assert_eq!(expected, [1, 2, 3, 4, 5]);
}
