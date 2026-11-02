# CP-0497 — QRun v0.5 Mainnet Genesis epoch fail-closed contract

Date: 2026-11-02

Status: **Mainnet CLI epoch requirement hardened and identity-manifest policy metadata added. The real epoch and anchored Mainnet identity remain deliberately unfrozen.**

## Finding

CP-0496 added a committed Genesis timestamp and required it for `--public-alpha`. The Mainnet help text already described `--genesis-time-unix-secs` as required, but the parser helper only enforced the requirement for public-alpha. The Mainnet release gate currently rejects startup before argument parsing, so this was a latent contract gap rather than an observed Mainnet startup.

If the release gate were later opened without correcting the parser, Mainnet could otherwise proceed with the legacy timestamp-zero Genesis path until another identity check rejected or accepted it. The CLI contract must not depend on that secondary check.

## Changes

- `parse_genesis_timestamp_option` now receives both public-alpha and Mainnet mode flags.
- Both public modes require an explicit, unsigned, nonzero `--genesis-time-unix-secs` value.
- Local loopback compatibility mode may still omit the timestamp; when supplied, it is parsed and validated identically.
- Added a Rust regression test that independently exercises missing-epoch rejection for both `--public-alpha` and `--mainnet`, accepts a shared nonzero value, and rejects zero/malformed values.
- The wallet-bound identity manifest now explicitly records that no Mainnet epoch is selected, that anchored identity regeneration has not happened, and that the candidate activation policy is earliest-activation-only with no expiry (delayed launch permitted).
- The manifest checker rejects an invented epoch, a false claim that the local 120-second freshness guard is a frozen cross-node consensus time source, or inconsistent timestamp/Genesis/profile binding metadata. Mutation tests run under `python -O`.

## Candidate activation semantics (not frozen)

The current proposal is:

1. The committed Genesis timestamp is the earliest permitted activation point, not a promise that the first block must be mined at that exact second.
2. There is no expiry window tied to the Genesis timestamp. A delayed launch remains possible, avoiding a brittle launch deadline.
3. The first accepted block must have a timestamp strictly greater than the committed Genesis timestamp.
4. The existing plus/minus 120-second live freshness check is node-local and depends on each node's local reference clock. It is not a deterministic cross-node consensus clock and must not be described as one.
5. The timestamp is included in the Genesis commitment; because the profile fingerprint includes that Genesis commitment, the timestamp is transitively committed by the profile ID. The wallet-bound Network ID itself is not changed by the Genesis timestamp.

This is a candidate policy only. A production-grade time-source / clock-skew contract and operator approval remain open decisions.

## Identity and release boundary

- The current wallet-bound Genesis ID, profile ID, state root, Network ID and External-CAS pins remain unchanged and still refer to the legacy unanchored candidate.
- The manifest field `timestamp_unix_seconds` is intentionally `null`; no build date or checkpoint date is substituted.
- Before using an anchored Mainnet identity, select the real epoch, regenerate the Genesis commitment/state root/profile ID, update the manifest and independent cross-language oracle, and re-provision matching ECR1/QCF1/checkpoint parent pins from the same exact Genesis.
- The parser requirement is future-facing; the current Mainnet release gate remains closed and blocks all Mainnet startup before parsing.
- `QRUN_MAINNET_RELEASE_APPROVED = false`; no Mainnet/public trading activation is authorized by this checkpoint.

## Validation

- Wallet-bound identity manifest checker mutation suite under `python -O`: **5/5 PASS**.
- Rust CLI timestamp-policy regression: **1/1 PASS**.
- Existing unrelated compiler warnings remain; no warning was reclassified as a release approval.

**Decision:** preserve the current identity and release gate. Advance the epoch/identity migration only after one real operator-selected epoch and the network's time-source policy are approved.
