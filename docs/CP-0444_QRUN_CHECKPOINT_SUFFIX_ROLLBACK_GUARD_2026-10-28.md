# CP-0444 - QRun checkpoint-suffix anti-rollback guard

Date: 2026-10-28

Status: implementation added; cargo +stable fmt --all -- --check and the focused checkpoint-rooted runtime regression test pass in an isolated target directory. Exact-head CI is pending. This is a candidate-store hardening change, not Mainnet activation.

## Change

A checkpoint-rooted QRun suffix store now refuses to reopen an existing manifest when the caller does not provide the expected manifest commitment. The commitment must be retained outside the mutable archive directory and re-supplied at restart. The existing manifest checksum is not treated as an anti-rollback trust anchor.

A new suffix store may still be initialized from a supplied, independently authenticated checkpoint without a suffix-manifest anchor because no prior manifest exists yet. Subsequent opens must supply the anchor. Existing Genesis-rooted candidate-store behavior is unchanged by this guard.

The QRun runtime test now attempts to reopen a populated checkpoint-rooted suffix without the anchor and asserts that it fails, then reopens it with the matching anchor and checks that canonical height and state root are preserved.

## Security boundary and remaining work

This guards a specific unsafe restart path; it does not implement an external compare-and-swap anchor provider, signed receipts, automatic checkpoint rollover, archive migration/pruning, or power-loss fault-injection coverage. The caller/operator still has to securely retain the latest manifest commitment outside the store. Restoring both the store and the external anchor from an old snapshot remains outside what this local candidate can independently detect.

The QRun PoW/fork-store path is still a candidate. Its bounded segment limits are not evidence of a production-ready automatic rollover mechanism. No public Mainnet or value-bearing launch is claimed.
