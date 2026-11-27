# CP-0698 — No-Card Independent Hosting Options
Date: 2026-11-16
Project: AI-NATIVE L1
Purpose: assess no-card hosting alternatives for a stable, independently operated zero-value Public Testnet Seed.

## Repository / safety state
- Active worktree: D:\Temp\ASUS\QRUN_QFP6_CP0596_20261111
- HEAD unchanged: 5aba5f69d24fce03af742fd1bebf13ad00e5d9c3
- Existing dirty/untracked work preserved. No reset/clean/stash/commit/push/merge/rebase.
- No account registration, payment, provisioning, node launch, DNS/firewall change, or QZXB allocation occurred.
- Q6GA v2 scope remains zero-value Public Testnet only. Existing staged identities remain inactive. No Joining config created.

## Oracle Cloud
- Official OCI Free Tier requires a credit/debit card for account identity/payment verification, plus accurate contact/billing information. A passport does not replace the card requirement.
- No attempt to circumvent country/payment eligibility with false details, borrowed cards, proxies, or duplicate accounts.
- Not a practical route with the currently stated Iranian bank card and phone constraints unless Oracle itself confirms an officially supported lawful verification path.

## No-card services reviewed
### FreeVPS.org
- Official site advertises sponsor-donated NAT KVM instances, $0/no card.
- Eligibility: active LowEndTalk or LowEndSpirit account at least 3 months old, 50+ substantive posts, 25+ received thanks.
- Standard resource: 1 fair-share core, 1 GB RAM (up to 2 GB justified), 20 GB disk, 250 GB bandwidth, 20 forwarded NAT IPv4 ports, dedicated IPv6 /64 or /80.
- No SLA; best-effort; instances can be reclaimed; no private support. Suitable only as a temporary staging/test candidate, not the sole stable public Seed. Verify UDP inbound/forwarding and exact endpoint behaviour before considering it.
- Source: https://www.freevps.org/

### Openworld
- FAQ advertises no-card free hosting, public IPv6, root access, systemd and seven-day renewable containers.
- Terms describe containerized instances and disclaim uninterrupted availability; free instances need frequent manual renewal.
- Too ephemeral and insufficiently dependable for the only Seed. At most an experimental connectivity sandbox if its terms and technical details are independently confirmed.
- Sources: https://openworld.eu.org/faq and https://openworld.eu.org/tos

### VPSFree.io
- Registration page claims no-card/email-only signup and advertises a free server.
- Terms page contains unresolved template placeholders for legal entity, registered address, age threshold, deletion grace period, governing jurisdiction and liability; it also describes Linux containers despite marketing copy claiming KVM.
- Terms prohibit free servers in some countries and explicitly prohibit claiming/accessing them via VPN/proxy/masking tools. AUP prohibits using VPN/proxy to bypass country restrictions. No attempt should be made to evade this.
- Free servers are 10-day renewable, no support, no uptime guarantee; live inventory showed only a 192 MB NAT IPv4-only Amsterdam free node, inadequate for the intended Seed.
- Decision: do not use for Seed; do not register until operator/legal identity and eligibility are credible and the exact service fits.
- Sources: https://vpsfree.io/terms ; https://vpsfree.io/acceptable-use ; https://vpsfree.io/linux-vps

### FreeMach
- Community VPS currently reports both EU and US VM allocations full; eligibility requires established community participation and application approval.
- Not presently available.
- Source: https://freemach.rowe.sh/

## Recommended path
1. Primary no-payment route: recruit one genuinely independent volunteer Seed operator or an academic/open-source infrastructure sponsor who already controls a lawful, stable public host. Operator must be independent from the user's laptop, VPN and admin account.
2. Secondary route: if the owner already meets FreeVPS community eligibility, evaluate a temporary staging instance only. Do not promote it to sole production-like Seed unless inbound TCP/UDP, stability, resource headroom, key custody and external reachability pass.
3. Prepare a public-safe operator package containing only architecture overview, zero-value scope, resource estimates, operator responsibilities, threat model and verification procedure. Never include private keys, DPAPI material, local paths, internal manifests or unredacted endpoint secrets.
4. Any future infrastructure support or QZXB benefit remains a proposal only; no tokens, mining rewards, allocation, or payment are promised or transferred. Any future incentive needs legal review, governance approval and explicit Mainnet authorization.

## Gate before any Seed deployment
- Host ownership/control and operator identity independently established.
- Host is in a jurisdiction/provider that accepts the operator and workload under applicable law and provider terms.
- Stable public endpoint and required inbound transport verified from a truly independent network.
- New Linux host key generated locally on host; do not copy Windows DPAPI-protected NPK.
- Linux key custody/recovery tested; Seed Noise fingerprint independently attested out-of-band.
- Owner authority pin and versioned signed authorization verified.
- Separate durable Anchor Vault path and backup/recovery plan proven.
- Only then generate final Joining configuration. Until all gates pass, do not launch or create Joining config.

## One owner-specific eligibility question
Does the owner already have a LowEndTalk or LowEndSpirit account that is at least 3 months old, with 50+ substantive posts and 25+ received thanks? If not, FreeVPS is not currently an actionable path and effort should focus on an independent volunteer/sponsor operator.
