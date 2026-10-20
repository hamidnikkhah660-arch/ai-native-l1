#!/usr/bin/env python3
"""Generate/check the candidate native mining-subsidy curve.

All outputs are arithmetic from a not-yet-ratified profile. This tool does not
read node state, broadcast transactions, or imply live issuance.
"""
from __future__ import annotations

import argparse
import csv
import io
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HTML_PATH = ROOT / "index.html"
CSV_PATH = ROOT / "simulations" / "candidate_halving_curve.csv"
START = "<!-- CANDIDATE_HALVING_CHART_START -->"
END = "<!-- CANDIDATE_HALVING_CHART_END -->"
ATOMS = 100_000_000
SUPPLY_CAP = 10_000_000_000
MINING_BUDGET = 3_000_000_000
HALVING_BLOCKS = 4_204_800
INITIAL_SUBSIDY = 35_673_515_981
EXPECTED_TOTAL_ATOMS = 299_999_999_913_926_400
EXPECTED_REMAINDER_ATOMS = 86_073_600
def coins8(atoms: int) -> str:
    whole, fractional = divmod(atoms, ATOMS)
    return f"{whole}.{fractional:08d}"


CSV_FIELDS = [
    "epoch", "start_height", "end_height_inclusive",
    "target_year_start", "target_year_end", "subsidy_atoms_per_block",
    "subsidy_coins_per_block", "era_emission_atoms", "era_emission_coins",
    "cumulative_emission_atoms", "cumulative_emission_coins",
]


def build_rows() -> list[dict[str, str | int]]:
    rows: list[dict[str, str | int]] = []
    cumulative = 0
    for epoch in range(INITIAL_SUBSIDY.bit_length()):
        reward = INITIAL_SUBSIDY >> epoch
        if reward == 0:
            break
        era = reward * HALVING_BLOCKS
        cumulative += era
        rows.append({
            "epoch": epoch,
            "start_height": epoch * HALVING_BLOCKS,
            "end_height_inclusive": (epoch + 1) * HALVING_BLOCKS - 1,
            "target_year_start": epoch * 4,
            "target_year_end": (epoch + 1) * 4,
            "subsidy_atoms_per_block": reward,
            "subsidy_coins_per_block": coins8(reward),
            "era_emission_atoms": era,
            "era_emission_coins": coins8(era),
            "cumulative_emission_atoms": cumulative,
            "cumulative_emission_coins": coins8(cumulative),
        })
    if cumulative != EXPECTED_TOTAL_ATOMS:
        raise AssertionError(f"emission total mismatch: {cumulative}")
    budget_atoms = MINING_BUDGET * ATOMS
    if budget_atoms - cumulative != EXPECTED_REMAINDER_ATOMS:
        raise AssertionError(f"mining-budget remainder mismatch: {budget_atoms - cumulative}")
    if MINING_BUDGET > SUPPLY_CAP:
        raise AssertionError("mining budget exceeds the high-level total-cap design")
    return rows


def serialize_csv(rows: list[dict[str, str | int]]) -> str:
    buff = io.StringIO(newline="")
    writer = csv.DictWriter(buff, fieldnames=CSV_FIELDS, lineterminator="\n")
    writer.writeheader()
    writer.writerows(rows)
    return buff.getvalue()


def make_chart_block(rows: list[dict[str, str | int]]) -> str:
    # Native mining subsidy steps: one step for each four-target-year era.
    left, right = 90, 690
    dx = (right - left) / 10
    y0, dy = 34, 19
    step_parts = [f"M {left} {y0}"]
    for epoch in range(10):
        x_next = left + dx * (epoch + 1)
        y_current = y0 + dy * epoch
        y_next = y0 + dy * (epoch + 1)
        step_parts.extend([f"H {x_next:.1f}", f"V {y_next:.1f}"])
    reward_svg = [
        '<svg viewBox="0 0 760 300" role="img" aria-labelledby="reward-chart-title reward-chart-desc">',
        '<title id="reward-chart-title">Illustrative candidate block subsidy by halving era</title>',
        '<desc id="reward-chart-desc">A staircase halves every 4,204,800 blocks. The vertical axis is logarithmic in powers of two. Values are modelled candidates, not observed or live issuance.</desc>',
    ]
    for i, epoch in enumerate(range(0, 11, 2)):
        y = y0 + dy * epoch
        reward = INITIAL_SUBSIDY >> epoch
        label = f"{reward / ATOMS:.3f}"
        reward_svg.append(f'<line x1="90" y1="{y:.1f}" x2="690" y2="{y:.1f}" stroke="#2a3b54" stroke-width="1"/>')
        reward_svg.append(f'<text x="80" y="{y + 4:.1f}" text-anchor="end" font-size="12" fill="#b4c2d6">{label}</text>')
    reward_svg.append(f'<path d="{" ".join(step_parts)}" fill="none" stroke="#8be0ff" stroke-width="3" stroke-linejoin="round" stroke-linecap="round"/>')
    for year in range(0, 41, 8):
        x = left + (right - left) * year / 40
        reward_svg.append(f'<line x1="{x:.1f}" y1="34" x2="{x:.1f}" y2="244" stroke="#2a3b54" stroke-dasharray="3 5"/>')
        reward_svg.append(f'<text x="{x:.1f}" y="266" text-anchor="middle" font-size="12" fill="#b4c2d6">{year}</text>')
    reward_svg.append('<text x="390" y="291" text-anchor="middle" font-size="12" fill="#b4c2d6">Target-year equivalent (30-second average target)</text>')
    reward_svg.append('<text x="20" y="143" transform="rotate(-90 20 143)" text-anchor="middle" font-size="12" fill="#b4c2d6">Subsidy / block, coins (log₂ steps)</text>')
    reward_svg.append('</svg>')

    # Cumulative issuance: show year zero plus ten exact halving-era endpoints.
    budget_atoms = MINING_BUDGET * ATOMS
    milestones: list[tuple[int, int]] = [(0, 0)]
    cumulative = 0
    for epoch in range(10):
        cumulative += HALVING_BLOCKS * (INITIAL_SUBSIDY >> epoch)
        milestones.append((4 * (epoch + 1), cumulative))
    top, bottom = 34, 244
    yspan = bottom - top
    coords = []
    for year, atoms in milestones:
        x = left + (right - left) * year / 40
        y = bottom - yspan * atoms / budget_atoms
        coords.append((year, x, y, atoms))
    cumulative_svg = [
        '<svg viewBox="0 0 760 300" role="img" aria-labelledby="cumulative-chart-title cumulative-chart-desc">',
        '<title id="cumulative-chart-title">Modelled cumulative mining subsidy</title>',
        '<desc id="cumulative-chart-desc">Cumulative coin subsidy approaches the proposed 3 billion coin mining and network-security budget under the candidate integer-halving schedule. This is a model, not live supply data.</desc>',
    ]
    for coins in (0, 750_000_000, 1_500_000_000, 2_250_000_000, 3_000_000_000):
        y = bottom - yspan * coins / MINING_BUDGET
        label = "0" if coins == 0 else f"{coins / 1_000_000_000:.2f}B"
        cumulative_svg.append(f'<line x1="90" y1="{y:.1f}" x2="690" y2="{y:.1f}" stroke="#2a3b54" stroke-width="1"/>')
        cumulative_svg.append(f'<text x="80" y="{y + 4:.1f}" text-anchor="end" font-size="12" fill="#b4c2d6">{label}</text>')
    points = " ".join(f"{x:.1f},{y:.1f}" for _, x, y, _ in coords)
    cumulative_svg.append(f'<polyline points="{points}" fill="none" stroke="#b4a2ff" stroke-width="3" stroke-linejoin="round" stroke-linecap="round"/>')
    for year, x, y, _atoms in coords:
        cumulative_svg.append(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="3.5" fill="#b4a2ff"/>')
    for year in range(0, 41, 8):
        x = left + (right - left) * year / 40
        cumulative_svg.append(f'<line x1="{x:.1f}" y1="34" x2="{x:.1f}" y2="244" stroke="#2a3b54" stroke-dasharray="3 5"/>')
        cumulative_svg.append(f'<text x="{x:.1f}" y="266" text-anchor="middle" font-size="12" fill="#b4c2d6">{year}</text>')
    cumulative_svg.append('<text x="390" y="291" text-anchor="middle" font-size="12" fill="#b4c2d6">Target-year equivalent (30-second average target)</text>')
    cumulative_svg.append('<text x="20" y="143" transform="rotate(-90 20 143)" text-anchor="middle" font-size="12" fill="#b4c2d6">Cumulative modelled subsidy (coins)</text>')
    cumulative_svg.append('</svg>')

    milestone_cards = []
    for year, percent, label in (
        (4, "50%", "by 4 target-years"),
        (8, "75%", "by 8 target-years"),
        (12, "87.5%", "by 12 target-years"),
        (16, "93.75%", "by 16 target-years"),
    ):
        milestone_cards.append(
            f'<div class="metric"><strong>{percent}</strong><span>Of the 3B mining budget modelled as emitted {label}</span></div>'
        )

    return f"""{START}
<div id="candidate-halving-curve" class="panel" style="margin-top:18px">
  <span class="tag">Candidate monetary simulation · not a live chart</span>
  <h3>How the proposed four-year halving would behave</h3>
  <p class="small">Both charts are generated from integer arithmetic using the candidate initial subsidy of 35,673,515,981 atomic units, 4,204,800 blocks per halving, eight decimals, and a 30-second target. The x-axis is a target-time equivalent, not a promised calendar schedule.</p>
  <div class="grid">
    <figure class="card chart-card">
      <h3>Block subsidy per era</h3>
      <p class="small">A logarithmic base-2 vertical scale makes every halving visible as an equal step. Values are native coins per valid block.</p>
      {"".join(reward_svg)}
      <figcaption class="small">The subsidy drops at exact block-height boundaries. Actual dates depend on observed block production.</figcaption>
    </figure>
    <figure class="card chart-card">
      <h3>Cumulative mining-budget emission</h3>
      <p class="small">Modelled share of the proposed 3B mining/security envelope, not circulating supply or on-chain issuance.</p>
      {"".join(cumulative_svg)}
      <figcaption class="small">The model front-loads 50% of the mining budget into the first target four-year era.</figcaption>
    </figure>
  </div>
  <div class="metrics">
    {"".join(milestone_cards)}
  </div>
  <p class="small">Reproduce the exact integer schedule with <a href="https://github.com/hamidnikkhah660-arch/ai-native-l1/blob/main/simulations/candidate_halving_curve.py">the offline checker</a> and inspect <a href="https://github.com/hamidnikkhah660-arch/ai-native-l1/blob/main/simulations/candidate_halving_curve.csv">the per-era CSV</a>. These are candidate-only projections: Gate 2 remains open and no live native supply or miner revenue is implied.</p>
</div>
{END}"""


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--write", action="store_true", help="regenerate the candidate CSV and chart section")
    args = parser.parse_args()
    rows = build_rows()
    expected_csv = serialize_csv(rows)
    html = HTML_PATH.read_text(encoding="utf-8")
    expected_block = make_chart_block(rows)

    if args.write:
        CSV_PATH.write_text(expected_csv, encoding="utf-8", newline="")
        if START not in html or END not in html:
            raise SystemExit("chart marker boundary is missing from index.html")
        before, rest = html.split(START, 1)
        _old, after = rest.split(END, 1)
        HTML_PATH.write_text(before + expected_block + after, encoding="utf-8", newline="")
        print(f"HALVING_CURVE_GENERATED=PASS eras={len(rows)}")
        print("CHART_BLOCK_GENERATED=PASS")
        print(f"modeled_total_emission_coins={coins8(EXPECTED_TOTAL_ATOMS)}")
        print(f"unused_mining_budget_coins={coins8(EXPECTED_REMAINDER_ATOMS)}")
        return 0

    if not CSV_PATH.exists() or CSV_PATH.read_text(encoding="utf-8") != expected_csv:
        raise SystemExit("HALVING_CURVE_CSV=FAIL; run with --write")
    if START not in html or END not in html:
        raise SystemExit("HALVING_CURVE_HTML=FAIL; chart markers missing")
    before, rest = html.split(START, 1)
    _old, after = rest.split(END, 1)
    if before + START + _old + END + after != before + expected_block + after:
        raise SystemExit("HALVING_CURVE_HTML=FAIL; rendered chart differs; run with --write")
    print(f"HALVING_CURVE_CSV=PASS eras={len(rows)}")
    print("HALVING_CURVE_HTML=PASS")
    print(f"halving_interval_blocks={HALVING_BLOCKS}")
    print(f"initial_subsidy_coins={coins8(INITIAL_SUBSIDY)}")
    print(f"modeled_total_emission_atoms={EXPECTED_TOTAL_ATOMS}")
    print(f"modeled_total_emission_coins={coins8(EXPECTED_TOTAL_ATOMS)}")
    print(f"unused_mining_budget_atoms={EXPECTED_REMAINDER_ATOMS}")
    print("NOTE=Candidate simulation only; not live issuance or a frozen consensus rule")
    return 0


def serialize_csv(rows: list[dict[str, str | int]]) -> str:
    buff = io.StringIO(newline="")
    writer = csv.DictWriter(buff, fieldnames=CSV_FIELDS, lineterminator="\n")
    writer.writeheader()
    writer.writerows(rows)
    return buff.getvalue()


if __name__ == "__main__":
    raise SystemExit(main())
