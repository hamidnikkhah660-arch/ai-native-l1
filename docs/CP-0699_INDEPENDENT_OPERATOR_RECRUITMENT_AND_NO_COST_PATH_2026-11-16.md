# CP-0699 — Independent Operator Recruitment Package and No-Cost Path — 2026-11-16

## Scope
Respond to the owner's confirmation that they do not hold a qualifying LowEndTalk/LowEndSpirit account. Pivot from FreeVPS eligibility to recruiting an independently administered volunteer or institutional host. Prepare public-safe recruitment material only; no deployment or account activity.

## Verified starting state
- Project: AI-NATIVE L1.
- Active worktree: D:\Temp\ASUS\QRUN_QFP6_CP0596_20261111
- Branch: feat/cp0600-bootstrap-sync-startup.
- HEAD observed before this checkpoint: 5aba5f69d24fce03af742fd1bebf13ad00e5d9c3.
- Existing dirty and untracked work was preserved.
- The repository has an existing public operator onboarding issue #72 and already invites independent operators in README.md.
- CONTINUE_HERE.md and PROJECT_STATE.md were not present at the active worktree root; this checkpoint and prior dated checkpoints remain the available state records.
- No qualifying FreeVPS community account is available, so no FreeVPS application was attempted.

## Work completed
- Added docs/AI_NATIVE_L1_INDEPENDENT_ZERO_VALUE_SEED_OPERATOR_BRIEF_2026-11-16.md.
- The brief is public-safe and explicitly distinguishes recruitment from deployment authorization.
- It requests existing infrastructure in-kind; it does not ask a volunteer to purchase a server.
- It specifies independent host administration, stable public endpoint, external inbound TCP test, durable storage/Anchor Vault, Linux host-local key custody, TPM2/vTPM qualification, out-of-band Noise fingerprint attestation, and owner-signed authorization.
- It excludes private keys, Windows DPAPI material, owner signing secrets, and unredacted local paths/manifests.
- It states no Mainnet, value-bearing transfer, market, token reward, mining payout, or QZXB incentive is authorized or promised.
- It does not invent a minimum CPU/RAM/disk profile; the brief says resource sizing must be measured and published before capacity is requested.

## External support research (not an application)
- NLnet currently describes grants of EUR 5,000–50,000 for qualifying free/libre/open-source projects and its Restack fund supports resilient open-internet infrastructure; the current Restack call deadline is 2027-01-03 12:00 CET. Eligibility and fit must be assessed before applying; funding is not guaranteed.
- Open Source Lab advertises hosting for open-source projects; eligibility and capacity need direct confirmation.
- Open Source Collective offers fiscal hosting and project administration; it is not itself a guaranteed free Seed-hosting provider.
- GitHub Sponsors is a sponsorship mechanism, not a direct hosting grant, and payout eligibility depends on supported regions and required tax/banking details.
- No applications, registrations, donations, or payment arrangements were initiated.

## Safety and release boundary
- No QRun node launched; no listener, firewall, router, DNS, VPN, adapter, or port-forwarding change.
- No public endpoint was assigned or published.
- No Linux key was generated; no Windows DPAPI key was copied.
- No Joining config was created.
- No QZXB was allocated or spent.
- Q6GA v2 remains zero-value Public Testnet only; Mainnet and real-value activity remain unauthorized.
- No reset, clean, stash, commit, push, merge, or rebase.

## Next executable gates
1. Publish/review the operator brief through the existing public issue #72 or a linked project discussion, after confirming the text is suitable for public release.
2. Contact potential open-source infrastructure hosts and university/research groups using the same scope and no-token/no-investment framing.
3. Separately evaluate NLnet Restack fit and Open Source Lab hosting eligibility; neither is assumed to accept or host the project.
4. Before any candidate host is selected, obtain provider/jurisdiction, resource, stable endpoint, inbound transport, TPM2/vTPM, storage and operator-independence evidence.
5. Only after the host passes qualification, perform host-local Linux key provisioning, independent fingerprint attestation, signed owner authorization preflight, and then prepare Joining configuration. Do not skip or reorder these gates.

## Current honest status
Recruitment materials are prepared, but no volunteer, institutional sponsor, stable endpoint, or public Seed exists yet. This is real preparatory progress, not a Public Testnet launch.

[executed on device: heymed (79d5a0fa-d9fd-427e-a5b5-d22f382f1128)]


## External program references checked on 2026-11-16
- NLnet funding overview: https://nlnet.nl/funding.html — describes EUR 5,000–50,000 grants for eligible open-source/public-interest projects and notes fund-specific eligibility conditions.
- NLnet Restack: https://nlnet.nl/restack/ — current call opened 2026-11-03; published deadline 2027-01-03 at 12:00 CET. This is a grant route, not immediate free hosting; project fit and eligibility remain unassessed.
- OSU Open Source Lab: https://osuosl.org/ — advertises hosting/infrastructure for open-source projects and invites project inquiries. It has hosted projects on VMs and other infrastructure, but acceptance, capacity, legal eligibility and whether it can provide the specific Seed/TPM/storage setup are unknown.
- OSU OSL hosted-project/service list: https://osuosl.org/projects/ — confirms that some hosted projects receive VMs, but does not guarantee an allocation to this project.
- No application or outreach was submitted during this checkpoint.


### NLnet eligibility caution
The general NLnet page says eligibility is fund-specific, and the Restack page notes that AI-related projects are generally out of scope except for a specified exception. Because this project is named AI-NATIVE L1, no fit is assumed: any proposal would need to focus truthfully on qualifying open-internet infrastructure work, review the current Restack guide/exception, and confirm applicant, country, sanctions, contracting and payout eligibility directly with NLnet. No workaround or proxy-based eligibility approach is appropriate.
