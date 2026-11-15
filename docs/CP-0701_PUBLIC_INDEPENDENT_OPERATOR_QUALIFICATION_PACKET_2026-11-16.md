# CP-0701 — Public Independent-Operator Qualification Packet — 2026-11-16

## Scope

Publish a current, reviewable operator recruitment brief and staged acceptance matrix without publishing unrelated uncommitted engineering work or activating any network service.

## Published artefacts

The following files were added on the isolated documentation branch:

- `docs/AI_NATIVE_L1_INDEPENDENT_ZERO_VALUE_SEED_OPERATOR_BRIEF_2026-11-16.md`
  - Commit: `b637de60ea5ba7b52a821d05cbf4779a8eaba6e3`
  - Defines the future zero-value Public Testnet operator role, the three-independent-operator requirement, host-local Linux key custody, no-value boundaries, and non-sensitive initial intake.
- `docs/AI_NATIVE_L1_INDEPENDENT_OPERATOR_INTAKE_AND_ACCEPTANCE_MATRIX_2026-11-16.md`
  - Commit: `b7f60671ac41cd17504fce8900fb136f32040be4`
  - Defines staged interest, independence, host capability, cryptographic, and multi-operator acceptance gates; stop conditions; and private evidence handling.
- `README.md`
  - Commit: `ceabb576e7aeb7cbb2b6e54b55b3ea81e1fd44d4`
  - Adds direct links to both new public documents under the ecosystem/operator onboarding section.

Branch: `docs/cp0700-independent-operator-refresh-20261116`

The publication branch was created from `main`. The active Windows engineering worktree was not committed, pushed, reset, cleaned, stashed, rebased, or merged. Its existing dirty and untracked files were left intact.

## Technical accuracy notes

- The Linux key-custody implementation invokes `systemd-creds encrypt --with-key=host+tpm2 --tpm2-pcrs=7`, then expects systemd `LoadCredentialEncrypted` delivery. Local test evidence does not establish that any prospective public host supports the same behavior.
- systemd documents `--with-key=` and `--tpm2-pcrs=` as available since v250. The current upstream manual states that systemd v262 and later additionally pin encrypted credentials to the TPM2 SRK, making credentials produced by that newer behavior incompatible with earlier systemd versions. Host qualification must therefore record the exact systemd version and test upgrade/rollback/recovery behavior; do not assume encrypted credentials are portable between host versions.
- Reference: https://www.freedesktop.org/software/systemd/man/latest/systemd-creds.html
- The Seed private key must be generated on the qualified host. Windows DPAPI-protected key files must never be copied to Linux.

## Public issue synchronization

GitHub Issue #72 was reviewed before publication. Its prior body still referred to an obsolete candidate commit and historical gate descriptions. The issue is intended to be updated only after the new public brief and matrix are available. No operator has been qualified by this publication.

## Honest status after this checkpoint

- Public operator brief and qualification matrix: published on the documentation branch.
- README links: added on that branch.
- Issue #72 body refresh: pending verification of branch links and then update.
- Three independent operators: not yet obtained or verified.
- Qualified independent Seed host / stable public endpoint: none.
- Genuine Public Testnet: not launched.
- Mainnet, value-bearing transfers, rewards, market activity and QZXB allocation: not authorized by this work.

## Safety boundary

No external email or hosting application was sent. No account, VPS, payment, server, key, node process, listener, firewall/router/DNS/VPN/adapter configuration, or Joining configuration was created or changed. No funds or QZXB were spent or allocated.
