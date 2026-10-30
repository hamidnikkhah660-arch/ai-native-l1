#!/usr/bin/env python3
"""Historical CP-0422/v0.4 proposal preflight; does not validate current CP-0437 Genesis policy."""
from html.parser import HTMLParser
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CAP = 10_000_000_000
ATOMS_PER_COIN = 100_000_000
BUCKETS = {
    "Mining / network security": (30, 3_000_000_000),
    "Community airdrop": (10, 1_000_000_000),
    "Exchange, market-integration and liquidity partnerships": (10, 1_000_000_000),
    "Major marketing and promotional partners": (10, 1_000_000_000),
    "Developers and security contributors": (10, 1_000_000_000),
    "Financial and strategic supporters": (10, 1_000_000_000),
    "Protocol burn reserve": (10, 1_000_000_000),
    "Owner allocation": (10, 1_000_000_000),
}


def load(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


assert sum(percent for percent, _ in BUCKETS.values()) == 100
assert sum(amount for _, amount in BUCKETS.values()) == CAP
assert BUCKETS["Owner allocation"] == (10, 1_000_000_000)
assert CAP * ATOMS_PER_COIN == 1_000_000_000_000_000_000

policy = load("docs/FOUNDER_SPONSOR_CONTRIBUTOR_ALLOCATION_POLICY_V04_2026-10-24.md")
readme = load("README.md")
site = load("index.html")
whitepaper = load("docs/QUANTUMZXB_NATIVE_COIN_WHITEPAPER_V03.md")
roadmap = load("docs/QUANTUMZXB_MASTER_ROADMAP_V04_2026-10-24.md")
decision = load("docs/CP-0422_CANONICAL_TOKENOMICS_DECISION_2026-10-26.md")
historical_checker = load("simulations/sponsor_allocation_checker.py")
issuance_source = load("src/native/pow_bench/src/monetary_issuance_v04_candidate.rs")
pow_source = load("src/native/pow_bench/src/monetary_pow_v04_candidate.rs")
qzbe_node_source = load("src/native/pow_bench/src/bin/qzbe_v04_peer_node.rs")
loopback_0414 = load("simulations/cp0414_qzbe_authenticated_transaction_loopback.ps1")
loopback_0415 = load("simulations/cp0415_devnet_qzbe_dispatch_transaction_loopback.ps1")
loopback_0418 = load("simulations/cp0418_qzbe_three_node_multi_peer_loopback.ps1")
checkpoint_source = load("src/native/pow_bench/src/monetary_pow_v04_checkpoint_candidate.rs")
checkpoint_fork_choice = load("src/native/pow_bench/src/monetary_pow_v04_candidate.rs")
checkpoint_store = load("src/native/pow_bench/src/monetary_pow_v04_checkpoint_store_candidate.rs")
checkpoint_oracle = load("simulations/cp0419_qzbe_checkpoint_oracle.py")
peer_runtime = load("src/native/pow_bench/src/bin/qzbe_v04_peer_node.rs")
workflow = load(".github/workflows/rust-ci.yml")
assert "pub const QZXB_V04_INITIAL_SUBSIDY_ATOMS: u128 = 35_673_515_981;" in issuance_source
assert "pub const QZXB_V04_BLOCKS_PER_HALVING: u64 = 4_204_800;" in issuance_source
assert "validate_canonical_v04_launch_parameters()" in qzbe_node_source
assert "pub const MAX_QZBE_MINING_ATTEMPTS: u32 = 4_096;" in pow_source
assert "if args.test_easy_pow" in qzbe_node_source
assert "QZXB_V04_ARGON2ID_64MIB" in qzbe_node_source
assert "next_block_timestamp(previous_timestamp, SystemTime::now())" in qzbe_node_source
assert "--test-easy-pow" in loopback_0414 and "--test-easy-pow" in loopback_0415
assert "peer_values = Vec::<String>::new()" in qzbe_node_source
assert "trusted_peer_values = Vec::<String>::new()" in qzbe_node_source
assert "for (index, peer) in args.peers.iter().enumerate()" in qzbe_node_source
assert "CP-0418 QZBE_THREE_NODE_MULTI_PEER_PASS" in loopback_0418
assert "cp0418_qzbe_three_node_multi_peer_loopback.ps1" in workflow
assert "pub const QZBE_CHECKPOINT_MAGIC: [u8; 4] = *b\"QZCP\";" in checkpoint_source
assert "pub const QZBE_CHECKPOINT_SCHEMA_VERSION: u16 = 1;" in checkpoint_source
assert "bounded_history_checkpoint_restores_exact_default_retarget_at_height_2017" in checkpoint_source
assert "EXPECTED_COMMITMENT" in checkpoint_oracle
assert "cp0419_qzbe_checkpoint_oracle.py" in workflow
assert "pub fn from_checkpoint_record(" in checkpoint_fork_choice
assert "pub fn rebuild_from_checkpoint(" in checkpoint_fork_choice
assert "pub fn canonical_checkpoint_record(" in checkpoint_fork_choice
assert "checkpoint_fork_choice_mines_and_accepts_actual_qzbe_block_at_height_2017" in checkpoint_source
assert "next_checkpoint.cumulative_chainwork" in checkpoint_source
assert "MAX_V04_CHECKPOINT_SUFFIX_ARCHIVE_BYTES" in checkpoint_fork_choice
assert "pub fn open_from_trusted_checkpoint" in checkpoint_store
assert "pub fn submit" in checkpoint_store
assert "checkpoint_store_commits_suffix_and_reopens_only_with_exact_trusted_checkpoint" in checkpoint_store
assert "checkpoint_store_persists_and_replays_block_2017_from_trusted_checkpoint_2016" in checkpoint_store
assert "monetary_pow_v04_checkpoint_store_candidate" in workflow
assert "V04ExecutionCheckpointForkStoreCandidate::open_from_trusted_checkpoint" in peer_runtime
assert "QzbeCheckpointRecord::from_state" in peer_runtime
assert ".submit(&encoded, &checkpoint_context, &authenticator)" in peer_runtime
assert "V04ExecutionForkStoreCandidate" not in peer_runtime
assert '"branches" | "manifests" | "checkpoints"' in peer_runtime
assert '"qzbe-store.lock" | "qzbe-checkpoint-store.lock"' in peer_runtime

for label, (percent, amount) in BUCKETS.items():
    assert label in policy and f"{amount:,}" in policy, f"policy missing {label}/{amount}"
    assert label in site and f"{amount:,}" in site, f"site missing {label}/{amount}"

assert "1B / 10%" in policy and "1B / 10%" in readme
assert "CP-0422" in readme and "CP-0422" in roadmap and "CP-0422" in policy
assert "HISTORICAL_V03_ONLY" in historical_checker
assert "historical CP-0422/v0.4 proposal preflight only" in readme
assert "never restores mint headroom" in policy.lower()
assert "historical" in decision.lower() and "1,000,000,000 QZXB (10%" in decision
current_genesis = load("docs/CP-0437_QRUN_FULL_SUPPLY_GENESIS_DIRECTION_2026-10-28.md")
assert "10,000,000,000 QZXB (100% of supply)" in current_genesis
assert "Subsequent minting and miner subsidy: **zero**" in current_genesis
assert "CP-0437" in readme and "zero block subsidy" in readme.lower()
assert "Historical v0.4 mining and halving research model" in site
assert "superseded for current QRun Genesis by CP-0437" in site
assert "CP-0437 (2026-10-28) later supersedes" in roadmap
assert "Gate 2" in policy and "Gate 8" in policy

# Independent arithmetic parity with the recorded v0.4 issuance oracle:
# subsidy atoms are integer-halved per 4,204,800-block era; no top-up is applied.
initial_subsidy_atoms = 35_673_515_981
halving_interval = 4_204_800
reward_atoms = initial_subsidy_atoms
cumulative_mining_atoms = 0
while reward_atoms:
    cumulative_mining_atoms += reward_atoms * halving_interval
    reward_atoms //= 2
assert cumulative_mining_atoms == 299_999_999_913_926_400
mining_cap_atoms = 3_000_000_000 * ATOMS_PER_COIN
assert cumulative_mining_atoms <= mining_cap_atoms
mining_residual_atoms = mining_cap_atoms - cumulative_mining_atoms
assert mining_residual_atoms == 86_073_600

class HTMLSmokeParser(HTMLParser):
    pass


HTMLSmokeParser().feed(site)
print("QZXB_TOKENOMICS_V04_HISTORICAL_CHECK=PASS")
print(f"cap={CAP}; buckets={len(BUCKETS)}; percentages={sum(p for p, _ in BUCKETS.values())}; amounts={sum(n for _, n in BUCKETS.values())}")
print("historical_CP-0422_founder=1000000000 (10%); superseded_by_CP-0437=10B_genesis; zero_post_genesis_issuance_and_subsidy")
print(f"mining_emission_atoms={cumulative_mining_atoms}; unissued_mining_residual_atoms={mining_residual_atoms}")
print("readme_site_whitepaper_roadmap_policy=checked; rust_schedule_is_pinned; qzbe_checkpoint_store_runtime_multi_peer_durable_replay=checked; gate_2_and_gate_8_remain_open")
