use ai_native_l1_pow_bench::token_forge::{
    asset_id, encode_definition, AccountId, AssetDefinition, BurnAuthority, FreezePolicy,
    MintAuthority, NetworkId, SupplyPolicy,
};
use std::{collections::BTreeMap, fs};

fn parse_vector() -> BTreeMap<String, String> {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../simulations/cpw_token_forge_vectors.txt");
    let text = fs::read_to_string(path).expect("read CP-W Token Forge vector");
    let mut values = BTreeMap::new();
    let mut lines = text.lines();
    assert_eq!(lines.next(), Some("CPW_TOKEN_FORGE_V1"));
    for line in lines.take_while(|line| *line != "END") {
        let (key, value) = line.split_once('=').expect("key=value vector line");
        assert!(values.insert(key.to_owned(), value.to_owned()).is_none());
    }
    values
}

fn hex<const N: usize>(value: &str) -> [u8; N] {
    assert_eq!(value.len(), N * 2);
    let bytes: Vec<u8> = (0..value.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&value[i..i + 2], 16).expect("hex byte"))
        .collect();
    bytes.try_into().expect("fixed-size hex")
}

#[test]
fn independent_shared_asset_vector_matches_rust() {
    let v = parse_vector();
    let definition = AssetDefinition {
        network_id: hex::<32>(&v["NETWORK_ID"]),
        creator: hex::<32>(&v["CREATOR"]),
        creation_nonce: v["CREATION_NONCE"].parse().unwrap(),
        name: v["NAME"].clone(),
        symbol: v["SYMBOL"].clone(),
        decimals: v["DECIMALS"].parse().unwrap(),
        metadata_hash: hex::<32>(&v["METADATA_HASH"]),
        supply_policy: SupplyPolicy::Capped {
            initial_supply: v["INITIAL_SUPPLY"].parse().unwrap(),
            max_supply: v["MAX_SUPPLY"].parse().unwrap(),
        },
        mint_authority: MintAuthority::Creator,
        burn_authority: BurnAuthority::Holder,
        freeze_policy: FreezePolicy::Creator,
    };
    let canonical = encode_definition(&definition).unwrap();
    assert_eq!(canonical.len(), 167);
    assert_eq!(
        canonical,
        (0..v["CANONICAL_HEX"].len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&v["CANONICAL_HEX"][i..i + 2], 16).unwrap())
            .collect::<Vec<_>>()
    );
    assert_eq!(asset_id(&definition).unwrap(), hex::<32>(&v["ASSET_ID"]));
}

#[test]
fn fixed_width_id_types_are_32_bytes() {
    let network: NetworkId = [0x11; 32];
    let account: AccountId = [0x22; 32];
    assert_eq!(network.len(), 32);
    assert_eq!(account.len(), 32);
}
