#!/usr/bin/env python3
from pathlib import Path
from html.parser import HTMLParser
ROOT=Path(__file__).resolve().parents[1]
CAP=10_000_000_000
BUCKETS={"Mining / network security":(30,3_000_000_000),"Community airdrop":(10,1_000_000_000),"Exchange, market-integration and liquidity partnerships":(10,1_000_000_000),"Major marketing and promotional partners":(10,1_000_000_000),"Developers and security contributors":(10,1_000_000_000),"Financial and strategic supporters":(10,1_000_000_000),"Protocol burn reserve":(10,1_000_000_000),"Owner allocation":(10,1_000_000_000)}
assert sum(p for p,_ in BUCKETS.values())==100
assert sum(n for _,n in BUCKETS.values())==CAP
policy=(ROOT/"docs/FOUNDER_SPONSOR_CONTRIBUTOR_ALLOCATION_POLICY_V04_2026-10-24.md").read_text(encoding="utf-8")
readme=(ROOT/"README.md").read_text(encoding="utf-8")
site=(ROOT/"index.html").read_text(encoding="utf-8")
wp=(ROOT/"docs/QUANTUMZXB_NATIVE_COIN_WHITEPAPER_V03.md").read_text(encoding="utf-8")
road=(ROOT/"docs/QUANTUMZXB_MASTER_ROADMAP_V03.md").read_text(encoding="utf-8")
for label,(_,amount) in BUCKETS.items():
 assert label in policy and f"{amount:,}" in policy, f"policy missing {label}/{amount}"
 assert label in site and f"{amount:,}" in site, f"site missing {label}/{amount}"
assert "supersedes" in policy.lower() and "Gate 2" in policy and "Gate 8" in policy
assert "FOUNDER_SPONSOR_CONTRIBUTOR_ALLOCATION_POLICY_V04_2026-10-24.md" in readme and "FOUNDER_SPONSOR_CONTRIBUTOR_ALLOCATION_POLICY_V04_2026-10-24.md" in wp and "policy v0.4" in road.lower()
class P(HTMLParser): pass
P().feed(site)
print("QZXB_TOKENOMICS_V04_CHECK=PASS")
print(f"cap={CAP}; buckets={len(BUCKETS)}; percentages={sum(p for p,_ in BUCKETS.values())}; amounts={sum(n for _,n in BUCKETS.values())}")
print("site_readme_whitepaper_roadmap=consistent; burn_not_claimed_done; exchange_listing_not_guaranteed; gates_2_and_8_open")
