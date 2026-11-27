# CP-0700 — Operator Qualification Workflow and Hosting Route Reassessment — 2026-11-16

## Scope
Continue the zero-cost AI-NATIVE L1 infrastructure path after the owner confirmed there is no qualifying FreeVPS forum account. Convert the operator brief into a staged, evidence-based intake/acceptance process; reassess institutional hosting and grant routes against current primary-source rules. No public outreach or provisioning was performed.

## Verified repository and public issue context
- Active worktree: D:\Temp\ASUS\QRUN_QFP6_CP0596_20261111
- Branch: feat/cp0600-bootstrap-sync-startup.
- HEAD before this checkpoint: 5aba5f69d24fce03af742fd1bebf13ad00e5d9c3.
- Existing dirty/untracked changes preserved. No reset, clean, stash, commit, push, merge or rebase.
- Root LICENSE is Apache License 2.0.
- CONTRIBUTING.md describes the project as a research prototype and requires reproducible, reviewable contributions; it also states that no public production readiness or value-bearing transaction should be claimed.
- GitHub Issue #72 is open and seeks at least three genuinely independent operators. Its current body is still based on older candidate source commit 06d2f7802111cdd7b1f93ca2fb53c46a57911635 and historical gates. Existing comments also show zero operator responses at the latest recorded update on 2026-11-09. No new comment was posted.
- Existing operator packet QZXB_ZERO_VALUE_DEVNET_OPERATOR_ONBOARDING_V01 says three independently administered operators are required. The new recruitment brief now explicitly says that one Seed host is only the first infrastructure priority and does not satisfy the three-operator gate.

## Work completed
1. Updated docs/AI_NATIVE_L1_INDEPENDENT_ZERO_VALUE_SEED_OPERATOR_BRIEF_2026-11-16.md:
   - Clarifies that three independent operators remain required overall.
   - Distinguishes first Seed host from full multi-operator qualification.
   - Requires separate human administrators, hosts and network/provider paths.
   - Preserves no-value/no-token/no-Mainnet scope and Linux host-local key custody.
2. Added docs/AI_NATIVE_L1_INDEPENDENT_OPERATOR_INTAKE_AND_ACCEPTANCE_MATRIX_2026-11-16.md:
   - Staged progression from interest-only to independence review, host capability, cryptographic gates and multi-operator acceptance.
   - Defines non-secret intake data, evidence required, decision states and stop conditions.
   - Explicitly prevents CI runners, multiple VMs or multiple processes under one administrator from counting as independent operators.
3. Added docs/OSU_OPEN_SOURCE_LAB_PRELIMINARY_HOSTING_INQUIRY_DRAFT_2026-11-16.md:
   - Draft only; not sent.
   - Requests eligibility clarification before any formal hosting application.
   - Asks whether OSL could support stable inbound TCP and TPM2/vTPM host-bound credentials, without assuming those capabilities.
4. README.md now links the public operator brief and qualification matrix.

## Hosting route reassessment — primary sources
### OSU Open Source Lab
- Official hosting policy requires an OSI-approved license; repository root LICENSE is Apache-2.0.
- OSL supports managed/unmanaged hosting ranging from websites to VMs and dedicated hardware.
- OSL explicitly says it generally avoids hosting smaller projects that can use free hosting such as GitHub; it prioritizes projects with significant positive impact and an active development community.
- OSL reserves the right to disconnect systems or discontinue hosting at any time.
- No official evidence found that OSL provides TPM2/vTPM or supports systemd-creds host+tpm2 with PCR 7.
- Decision: a low-cost preliminary eligibility inquiry is reasonable, but OSL is not yet a qualified or guaranteed Seed host and cannot be treated as the sole durable infrastructure. The inquiry remains unsent.

### NLnet Restack
- Current call deadline: 2027-01-03 12:00 CET.
- Restack excludes GenAI-related projects unless they already have more than one million active human users and are directly relevant to the stack.
- Current project identity is AI-NATIVE L1, with substantial GenAI-assisted development/documentation in its existing work. NLnet's GenAI policy v2.0 (effective 2026-10-20) prohibits GenAI in proposal writing and prohibits GenAI-produced project artefacts; read-only use is allowed. The owner would have to write any application unaided and the project's past/current GenAI usage and planned work would require accurate disclosure.
- Restack also requires a strong European dimension; outside-region proposals are only potentially considered in exceptional cases.
- Decision: do not pursue or draft an NLnet Restack application under the current project workflow. This is a policy/fit no-go, not a claim that the owner is categorically legally ineligible for all NLnet programmes. Do not conceal AI use, relabel the project, or use a proxy applicant to bypass the policy.

## Safety and execution boundary
- No email or form was sent; no external application or contact was initiated.
- No server, cloud account, card, payment or registration was created.
- No node process/listener, firewall/router/DNS/VPN/adapter change, or Joining config was created.
- No key was generated or copied; no QZXB allocated or spent.
- Q6GA v2 remains zero-value Public Testnet only; no Mainnet, market, rewards or real-value activity authorized.
- No Git commit/push or destructive operation.

## Next gates
1. Review the OSL preliminary inquiry draft; send only after owner review and confirmation of contact details.
2. Refresh Issue #72 content to remove stale candidate commit/gate language and link the current operator brief/matrix, after a deliberate public update decision.
3. Recruit at least three independent operators; evaluate each through the staged matrix.
4. For the first Seed host, verify lawful provider terms, stable endpoint, inbound reachability, Linux host-local TPM-backed custody, durable Anchor Vault and backup.
5. Only after independent operator attestation and owner-signed authorization pass, prepare Seed runtime config; Joining remains blocked until Seed endpoint/fingerprint verification passes.
6. Keep the network unlaunched until multi-operator sync/soak, security review, observability, wallet/faucet and rollback gates are independently evidenced.

## Honest status
The project now has a clear public recruitment brief and a staged qualification workflow. The institutional hosting inquiry is only drafted. There are still zero newly verified independent operators, no qualified Seed host, no stable public endpoint and no genuine Public Testnet launch.

[executed on device: heymed (79d5a0fa-d9fd-427e-a5b5-d22f382f1128)]
