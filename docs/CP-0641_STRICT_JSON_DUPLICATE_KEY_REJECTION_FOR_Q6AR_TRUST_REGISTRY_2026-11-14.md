# CP-0641 — Strict JSON Duplicate-Key Rejection for Q6AR Trust Registry

Date: 2026-11-14  
Project: AI-NATIVE L1 / QRUN-QFP6  
Depends on: CP-0639, CP-0640A, CP-0640B  
Status: implementation and targeted validation complete; local working tree only

## Finding

The operator registry was parsed into `serde_json::Value`. That representation does not preserve duplicate object member names, so ambiguous input such as two `version` properties could be reduced to one value before the allowlist and schema checks saw it. Duplicate relay assignments were already rejected by the policy constructor, but duplicated JSON property names needed a separate guard.

## Change

Before materializing the registry as `Value`, `reject_duplicate_json_object_keys` now scans every JSON object and rejects repeated decoded key strings.

- JSON property names are decoded with `serde_json::from_slice::<String>`, so equivalent escaped spellings (for example `version` and `ver\\u0073ion`) are considered duplicates.
- The scanner walks nested objects and arrays, not only the registry's outer object.
- Nesting deeper than 16 levels is rejected. The overall registry remains byte-bounded to 64 KiB.
- Existing version-1 schema validation, unknown-field rejection, SHA-256 pin validation, assignment limits, and active-relay completeness checks remain in place.
- No new Cargo dependency or lockfile change was needed.

## Regression evidence

Targeted command:

```powershell
cargo test --manifest-path src/native/pow_bench/Cargo.toml --bin qrun_v06_node q6ar_trust_domain_registry --locked --offline
```

Result: **2 passed, 0 failed**. Coverage includes:
- wrong pinned digest and missing active relay assignment rejection;
- duplicate relay assignment and unknown-field rejection;
- duplicate top-level key rejection, including Unicode-escaped equivalent spelling;
- duplicate nested `relay_static_public_key` field rejection.

Additional checks:
- `cargo fmt --manifest-path src/native/pow_bench/Cargo.toml -- --check`: passed.
- `git diff --check`: passed; only existing LF/CRLF normalization warnings were emitted.

## Security boundary

This prevents ambiguous JSON object member names from being silently collapsed during registry parsing. It does not prove that different trust-domain IDs represent independent operators. Real administrative independence still requires out-of-band verification, and the runtime remains a candidate engineering path pending independent adversarial, transport, consensus, and operational audits.

No node was started, no listener was opened, and no Public Testnet operation was performed. No commit or push was made.
