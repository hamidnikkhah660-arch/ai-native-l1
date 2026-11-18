QFP6 UNIFIED CANDIDATE PACKAGE

Status: INTEGRATION CANDIDATE ONLY — NOT RELEASE READY.

The active owner-directed monetary policy is CP-0651 (recorded in CP-0650/CP-0651):
- Maximum gross supply ceiling: 7,000,000,000 QZXB.
- Owner Genesis allocation: 1,000,000,000 QZXB.
- Six accounting labels: 1,000,000,000 QZXB each (6,000,000,000 QZXB total).
- Block subsidy / mining issuance: exactly zero at every height.
- Producers receive canonical transaction fees only.
- The six labels are ceilings, not Genesis balances, spendable accounts, or mint authority.

CP-0566D/CP-0566E are preserved as historical prior 10B/3B-mining policy records.
CP-0651 is the later owner-requested 7B/fee-only policy and is the only policy accepted
by the permissionless launcher. CP-0528 and CP-0604 remain legacy compatibility paths
and must not initialize this permissionless runtime.

This package is intentionally incomplete. Do not start a public node or describe this
folder as a deployable public Testnet/Mainnet release.

Required canonical release inputs remain absent:
- CP-0651 Genesis snapshot (.q6sn)
- Genesis descriptor (.q6gd)
- Consensus profile (.q6cp)
- Network profile (.q6pn)
- Approved bootstrap peer set
- Founder/owner signature and independently pinned release authorization
- External operator/host identity and endpoint attestations

No placeholder artifact, invented identifier, fabricated signature, or empty bootstrap
list is accepted as proof of public readiness. Mainnet, public mining, value-bearing
transfers, exchange listing and trading remain unauthorized.

Run:
  python tools/qfp6_candidate_package.py self-test
  python tools/qfp6_candidate_package.py validate <package-directory>