use std::fs;
fn pq(a: &str) -> bool {
    matches!(a, "mldsa65" | "slhdsa128s")
}
fn main() {
    let s = fs::read_to_string("simulations/cp0025c_key_provider_vectors.txt").unwrap();
    let mut a = 0;
    let mut r = 0;
    for raw in s.lines().filter(|x| !x.is_empty() && !x.starts_with('#')) {
        let p: Vec<&str> = raw.split('|').collect();
        assert_eq!(p.len(), 12);
        let kind = p[0];
        let old_alg = p[2];
        let new_alg = p[3];
        let og: u32 = p[4].parse().unwrap();
        let ng: u32 = p[5].parse().unwrap();
        let revoked: u8 = p[6].parse().unwrap();
        let purpose: u8 = p[7].parse().unwrap();
        let epoch: u64 = p[8].parse().unwrap();
        let lock: u64 = p[9].parse().unwrap();
        let expected = p[11] == "accept";
        let got = if kind == "rotation" {
            let mut ok = revoked == 0 && purpose == 1 && ng > og;
            if epoch >= lock && !pq(new_alg) {
                ok = false
            }
            ok
        } else {
            let mut ok = revoked == 0 && purpose == 1 && og == ng;
            if epoch >= lock && !pq(old_alg) {
                ok = false
            }
            ok
        };
        assert_eq!(got, expected, "{}", p[1]);
        a += expected as usize;
        r += (!expected) as usize;
    }
    println!(
        "CP-0025-C-RUST PASS accepted_vectors={} rejected_vectors={}",
        a, r
    );
}
