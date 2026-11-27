# CP-0695 — Versioned Prepare-Only Noise Identity Rotation — 2026-11-16

## Scope and repository state
- Project: AI-NATIVE L1
- Active worktree: `D:\Temp\ASUS\QRUN_QFP6_CP0596_20261111`
- Branch: `feat/cp0600-bootstrap-sync-startup`
- HEAD before and after this work: `5aba5f69d24fce03af742fd1bebf13ad00e5d9c3`
- This checkpoint records a local prepare-only identity rotation tool, a reproducible PowerShell regression harness, and two real local staging bundles.
- No production identity, protected key, Seed config, Joining config, bootstrap peer set or live trust pin was replaced or activated.

## New tools

### Prepare-only rotation builder
Path:
`tools/qfp6-prepare-noise-identity-rotation.ps1`

SHA-256 (after final staging-path hardening):
`99d845ae461d7ff665cb65b30eddbeb2b037492bf62885646874d1c6d805db908`

PowerShell parser: 0 errors.

The protected-key path stored in the prepared identity is now derived from the actual selected generation directory, so an explicitly supplied package-contained staging root does not leave a stale default path.

Behavior:
- Supports Seed and Joining roles with separate generation counters and staging directories.
- Generates a fresh random Noise XX identity using the existing `noise_key_provisioner.exe` and Windows CurrentUser DPAPI NPK1.
- Creates a distinct versioned protected-key file; it does not overwrite the active key.
- Validates the active source identity schema/role, network/profile values, active public-key fingerprint, Seed config hash binding, protected-key path and file hash.
- Writes the new public identity, a copy of the previous public identity, and a rotation manifest with hashes and an explicit `PREPARED_NOT_ACTIVATED` state.
- For Seed, also writes a proposed Seed config pointing to the new versioned protected key and binds its exact SHA-256 into the new Seed identity.
- For Joining, writes only the new public identity and protected key. It deliberately does not generate a Joining runtime config while the Seed endpoint remains missing/unverified.
- Uses CreateNew writes; an incomplete generation is removed on failure.
- No node startup, listener bind, firewall/router changes, or identity activation is performed.

The tool is prepare-only. Its successful output is not authorization to deploy, activate, or rotate either production role.

### Reproducible regression harness
Path:
`tools/test-qfp6-prepare-noise-identity-rotation.ps1`

SHA-256:
`19a1c52436dae5c4d5dd7f06ed1d75a0fe239cdb648e377b9fb6a0775f0beb43`

PowerShell parser: 0 errors.

Test run:
```text
IDENTITY_ROTATION_PREPARATION_TESTS=PASS
PASSED_CASES=3
PASS: Seed prepare-only generations 1 and 2; active identity/key unchanged
PASS: Joining prepare-only generations 1 and 2; endpoint blocker retained; no runtime config
PASS: Negative mismatched-key-hash rejection; no partial generation
```
Exit code: 0. The harness creates only disposable fixture packages and synthetic DPAPI test keys; its temporary root is removed after completion.

## Real local staging bundles — generation 1

Package:
`release/qfp6-local-single-operator-devnet-2026-11-15/identity-rotation-staging/`

### Seed
Directory:
`seed/generation-000001/`

- Status: `PREPARED_NOT_ACTIVATED`
- New identity SHA-256: `79f670c09e00b9e0b6ac002a2b84c49e89061161db58ba672ce055c94effe52c`
- New public-key SHA-256 fingerprint: `79127023af983df1930607d77d76d6e7cd91b91f836a371a35cd063931c235f9`
- New protected-key SHA-256: `b141db0900876132a1bfb9b3e71a4689ff08f49d2546ac3ff277d9aee732e838`
- Rotation manifest SHA-256: `eadce784c458b3ce82fbc6f6d6e5a98da489936741e6599aa090ec9e412a815f`
- Prepared Seed config SHA-256: `50e3c3138566baf6db5c588f7b9dcea8cc82b9fa7ec26eb13e73775ade3a60cb`

### Joining
Directory:
`joining/generation-000001/`

- Status: `PREPARED_NOT_ACTIVATED`
- New identity SHA-256: `e6956c58df5c64fa1e9320644b96fed03e5ec484165b0c2185eebfa926141c14`
- New public-key SHA-256 fingerprint: `ecacad84ef6e14a32e3301c0e83a5b6c15043bfd703f4345b221e8e4fc1a6f80`
- New protected-key SHA-256: `8595a0bee92ffcde56a85706454cf22d200e58ce42716e8867e571c982642df1`
- Rotation manifest SHA-256: `5efff62735b0aedd9f287dfabc1de1e9ee480c15fb74449df8bc2b0693a24f73`
- Runtime config status: `BLOCKED_MISSING_STABLE_SEED_ENDPOINT_AND_OUT_OF_BAND_VERIFICATION`
- No Joining runtime config was created.

## Staged bundle integrity recheck — PASS
For both real generation-1 bundles, independent read-only checks confirmed:
- New identity file SHA-256 equals its manifest pin.
- `previous-identity.json` SHA-256 equals the previous-identity manifest pin.
- New protected-key SHA-256 equals the manifest pin.
- SHA-256 recomputed from the new public key equals the manifest public fingerprint.
- Activation is disabled.
- Node/listener startup is false.
- Previous identity and protected key are retained.

For Seed:
- Prepared config file hash equals its manifest hash.
- New Seed identity `seed_config_sha256` equals that exact prepared config hash.
- Prepared config references the staged versioned protected key.

For Joining:
- The endpoint placeholder `NOT_EMBEDDED_REQUIRES_CURRENT_OUT_OF_BAND_ENDPOINT` is preserved.
- The explicit missing-endpoint/out-of-band-verification blocker remains in the manifest.
- No Joining runtime config is present.

## Active-source identity/key preservation
The active source files retained their recorded hashes:
- Seed identity: `28178575dc5cf5947245308e78d90e1d0ee33704b7714f522c202f1b9738c3d5`
- Joining identity: `120f3d89d07febe29670ed82319f63348db5ef1e7c64c99754f9565c7ee05b1a`
- IPv6 Seed config: `dab3e9df70125888710b3a60b22981f62efcb65f1b60a3b38fcd7bbe501f5747`
- Existing Seed protected-key file (path resolved dynamically from the pinned Seed config): `a7743aa6c17b7cfeb008d8ef568a4a813fe218bd80f529c327b65284c1a5b584`
- Existing Joining protected-key file: `2d4023202541ba8534768aa23386b1229f96e387e8197d92068c3d98ddc23c6c`

No active key was replaced.

## Joining readiness — still blocked
At the read-only network check, Wi-Fi had preferred non-link-local IPv6 address(es) and a default IPv6 route, but the router-advertised preferred lifetime was only about 58 minutes. This is transient network evidence, not a stable Seed endpoint suitable for embedding into a Joining peer set.

The Joining identity still contains:
`NOT_EMBEDDED_REQUIRES_CURRENT_OUT_OF_BAND_ENDPOINT`

Outstanding requirements:
1. A stable, owner-approved Seed public endpoint.
2. Independent out-of-band verification of the Seed Noise fingerprint through a separate trusted channel.
3. Inbound TCP 30333 reachability verified from an independent external network/operator.
4. Independent Joining host/operator and isolated Noise XX, history sync, restart/catch-up and rollover testing.

No final Joining config was generated. No public node started.

## Public website / PR #195 — not ready to ask the owner to visit
Repository: `hamidnikkhah660-arch/ai-native-l1`
PR: https://github.com/hamidnikkhah660-arch/ai-native-l1/pull/195

Observed on 2026-11-16:
- PR #195 remains OPEN and not merged.
- PR head remains `f397b1ca2156708a304e915802b67db15e9c2396`.
- Submitted reviews: 0; requested reviewers: none.
- Exact-head GitHub Actions run `43763061469`: completed successfully.
- Three check runs completed successfully: Format/check/test; EVM contract/wallet/dependency audit; Windows PMT4/TXN4 two-node loopback.

However, the live site `https://hamidnikkhah660-arch.github.io/ai-native-l1/` still serves older content:
- Live homepage reports the old 10-billion economics content.
- The updated 7B candidate economics and capability-register changes are not present on the live homepage.
- Live and PR-branch hashes differ for index.html, technology.html, status.html and economics.html.
- Latest GitHub Pages deployment visible in the deployment API is ID `7634195479`, ref `main`, SHA `7160f5364d610152c16626c187f03f9f870fd0bb`, created 2026-11-08; it predates the PR head.

Therefore CI is green for the PR head, but publication and independent review are not complete. Do not tell the owner the public site is ready to inspect until the PR is independently reviewed, merged, the Pages deployment corresponds to the approved new content, and the live files are verified to contain the updated economics/capability language.

## Final safety and Git state
- `git diff --check`: exit code 0; existing LF/CRLF normalization notices only.
- HEAD remains `5aba5f69d24fce03af742fd1bebf13ad00e5d9c3`.
- Worktree status entry count after this work and the final test-tool hardening: 131.
- qrun_v06_node process count: 0.
- TCP 30333 listeners: 0; TCP 30334 listeners: 0.
- No firewall/router/NAT/VPN/DNS/adapter changes.
- No reset, clean, stash, commit, push, merge or rebase.
- Preserve all pre-existing dirty and untracked project files.

## Next step
Keep the prepared rotation bundles inactive. Continue Joining endpoint and external operator qualification. Keep tracking PR #195 and only notify the owner to inspect the public site after independent review, merge, updated deployment, and live-content verification are all confirmed.
