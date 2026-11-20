# CP-0787 — README historical Gate 2 / Gate 8 status scope correction

Date: 2026-11-20
Parent: CP-0786 / `fdcf9fdaaf8acc93b21c2293ebf35677ace11d6c`
Branch: `feat/q6ga-v3-mainnet-scope-20261119`
Scope: documentation-only clarification

## Reason
The README's collapsed historical v0.4 token-allocation section contained an undated bullet saying Gate 2 and Gate 8 "remain open". That phrasing could be read as current, even though the same Unified continuation handoff and CP-0780 (2026-11-19) later record the owner's status as OWNER-REPORTED COMPLETE / NOT RETESTED and explicitly direct that those qualifications must not be repeated.

## Change
The bullet is now scoped as a historical 2026-10-29 / v0.4 release-gate statement. It also points to the later CP-0780 owner report and preserves the current release boundary:
- Gate 2 and Gate 8 are owner-reported complete / not retested under the current continuation instruction.
- This is not a new independent verification and no Gate test was repeated by CP-0787.
- The Public Testnet is still not live: the unified package's bootstrap peer list is empty and previously approved endpoint/operator/Noise receipts still require reconciliation to the exact release package.
- Mainnet/value-bearing transfer and market activity remain unauthorized.

No historical checkpoint was edited. CP-0747..CP-0775 retain their contemporaneous open statuses and exact scopes.

## Validation
- Confirmed CP-0780 lines 140–141 state OWNER-REPORTED COMPLETE / NOT RETESTED for Gate 2 and Gate 8.
- Confirmed the current handoff states the same and directs no retest.
- Documentation string check: the README contains the dated historical wording and the later owner-reported status.
- `git diff --check`: PASS.
- No Rust tests, network tests, Gate 2/8 tests, runtime operations or public endpoint checks were run.

## Safety
No source/runtime behavior, Genesis, Q6GA/Q6CP/Q6PN artifact, peer pin, key, listener, Seed process or firewall was changed. This is a documentation clarification only.
