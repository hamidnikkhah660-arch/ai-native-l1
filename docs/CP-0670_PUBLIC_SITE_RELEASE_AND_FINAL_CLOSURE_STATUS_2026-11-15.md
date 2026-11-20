# CP-0670 — Public Site Release and Final Closure Status

Date: 2026-11-15  
Project: AI-NATIVE L1 / QRun-QFP6  
Candidate source branch: feat/cp0600-bootstrap-sync-startup  
Candidate worktree HEAD at inspection: 5aba5f69d24fce03af742fd1bebf13ad00e5d9c3  
Status: **site update prepared and PR opened; public network / Genesis / wallet transfer remain NOT COMPLETE**

## 1. Public website correction

The live GitHub Pages site returned HTTP 200, but its homepage and economics page still contained the superseded CP-0437 10B owner-only policy. The Pages source is main at repository root. The last recorded Pages deployment before this change was 2026-11-08 from main commit 7160f5364d610152c16626c187f03f9f870fd0bb.

A dedicated site-only worktree was created from origin/main:
D:\Temp\ASUS\QRUN_SITE_PUBLICATION_20261115

Commit pushed:
3168c04 docs(site): publish CP-0651 economics and November status

Pull request:
https://github.com/hamidnikkhah660-arch/ai-native-l1/pull/195

PR branch:
site/cp0651-public-status-20261115

The PR changes only README / static site pages / supporting evidence documents / candidate manifest. It does not merge candidate Rust runtime code, authorize Testnet or Mainnet, or claim a token transfer.

Files in the PR:
- README.md
- index.html
- economics.html
- status.html
- CP-0647, CP-0648, CP-0649
- CP-0651, CP-0652, CP-0655, CP-0656, CP-0659
- release/qfp6-candidate/manifest.json

All current page links to these CP docs and the manifest point to main.

## 2. Website validation

The isolated publication tree passed:
- HTML parsing for index.html, economics.html, status.html.
- JSON-LD parsing for all three pages.
- Duplicate-ID check.
- CP-0651 manifest checks: 7B maximum accounting ceiling; 1B owner Genesis allocation; 6B across six non-circulating accounting labels; zero block subsidy; canonical transaction-fee-only producer compensation.
- Release guard checks: production_authorized=false, mainnet_status=NOT_AUTHORIZED, final Genesis/Q6GD/Q6CP/Q6PN/bootstrap peers missing, owner Genesis signature absent.
- Evidence-document link checks and no stale feature-branch links in the three pages.
- git diff --check.

## 3. GitHub PR / public deployment gate

PR #195 was created against main and remains OPEN, not merged.
At last check:
- EVM contract, wallet console and dependency audit: PASS.
- Format, check and test: PASS (completed 2026-11-14 21:15:17Z).
- Windows PMT4/TXN4 two-node loopback: PASS (completed 2026-11-14 21:13:34Z).
- EVM contract, wallet console and dependency audit: PASS (completed 2026-11-14 21:10:12Z).
- All three required CI checks are now PASS. The PR remains REVIEW_REQUIRED / BLOCKED solely because one approving review is required.
- GitHub auto-merge is disabled at repository level; enabling it by force is unavailable and will not be bypassed.

Branch protection on main requires three named status checks and one approving review. enforce_admins=true. The authorized collaborator list currently contains only the repository owner. Do not disable branch protection or self-approve to force the site deployment.

Consequently, the public Pages site remains on the old main commit until PR #195 receives all required green checks, a genuine independent approval, and is merged. After merge, verify the Pages deployment and HTTP content before calling the website update complete.

## 4. Current monetary policy / Genesis facts

The candidate manifest records:
- policy_id=CP-0651
- max_gross_supply_qzxb=7000000000
- owner_genesis_qzxb=1000000000
- accounting_labels_total_qzxb=6000000000
- six accounting labels of 1B each, marked non-circulating accounting ceilings
- block subsidy atoms = 0
- producer compensation = canonical transaction fees only
- production_authorized=false
- mainnet_status=NOT_AUTHORIZED

The candidate owner public account ID is bound in the manifest, but genesis_signature_present=false. The Genesis execution snapshot, Q6GD descriptor, Q6CP consensus profile, Q6PN network profile and bootstrap peer set remain missing. Independent consensus, cryptography and economics reviews remain pending.

The six accounting labels are not minted balances, spendable coins, or permission to issue tokens.

## 5. Network evidence and external infrastructure

Do not repeat the existing CP-0566C NetBird two-host qualification. Preserve it as valid evidence for its private-overlay scope.

The prior NetBird branch evidence used the laptop as Node A and a temporary GitHub-hosted runner as Node B over private NetBird overlay addresses. That does not establish public Internet inbound reachability, permanent seed uptime, or two independently administered public seed hosts.

CP-0647/0648/0649 remain scoped correctly: the current end-to-end two-source agreement fixtures use loopback listeners. They do not prove public Internet seed reachability.

CP-0656 records that the laptop/hotspot path did not demonstrate unsolicited inbound TCP reachability. At this inspection, no active QRun node process was identified and no listener was present on TCP 30333.

Before a zero-value public Testnet, obtain and independently administer two public seed hosts, preferably at distinct providers/ASNs, each with:
- stable public endpoint;
- local protected Noise private key;
- independently verified public-key fingerprint;
- separate operator/trust-domain evidence;
- externally tested listener and full-history sync.

The single connected laptop cannot satisfy these independent public-host requirements by creating more local VMs or repeating the private-overlay test.

## 6. Wallet / transfer status

**No native QZXB wallet transfer has been executed or confirmed.**

There is currently no signed CP-0651 Genesis snapshot or authorized live native chain from which a real QZXB balance can be sent. The owner Genesis allocation is a candidate policy allocation, not an existing spendable wallet balance. The candidate owner account binding is not, by itself, proof that it matches the user's intended receiving address.

Do not fabricate a transaction hash or report success. Do not request or place a seed phrase, private key, recovery phrase or protected signing material in chat. Once Genesis bytes and profile files are frozen and independently checked, the owner must confirm the intended public account and sign the exact digest on an owner-controlled protected signer. Only then can a zero-value Testnet be operated and a real transfer test be attempted; value-bearing Mainnet transfer is a separate release decision.

## 7. Trading / listing

Local Q6MO market-ingress and execution tests are engineering evidence only. No live native QZXB pair, order book, AMM liquidity, exchange trade, CMC tracked listing, or TradingView public symbol is established by those tests. These require an authorized network/asset, real market data, functioning venue/liquidity and external platform acceptance.

## 8. Exact remaining closure order

1. Finish PR #195 CI; obtain one genuine independent approving review; merge; verify GitHub Pages deployment and live content.
2. Reconcile/land the stacked candidate engineering PRs in their dependency order. Do not merge the whole 121-commit-ahead branch blindly and do not disturb the existing dirty candidate worktree.
3. Provision two independently administered public seed hosts and import their real endpoint/fingerprint/operator evidence.
4. Freeze Genesis/Q6GD/Q6CP/Q6PN/bootstrap peer bytes, hash-pin them, and obtain the owner's signature using the protected signer after confirming the intended owner account.
5. Complete independent consensus, cryptography and economics review plus external multi-host listener/sync/restart/divergence/DoS qualification.
6. Only then authorize and launch a separately labelled zero-value Public Testnet. Mainnet, real-value wallet transfer, market liquidity, exchange listing and TradingView integration remain separate gates.

**Decision at CP-0670:** local website content is corrected and isolated publication PR #195 is open; the live website has not yet been updated. Candidate economics are recorded as CP-0651 but Genesis is unsigned and unreleased. No native QZXB transfer occurred. Public Testnet and Mainnet remain NO-GO. This is an evidence-based stopping point, not a false completion claim.

## 9. Follow-up update — CI completed

As of this update, all three PR #195 required GitHub checks have completed successfully: Format/check/test, Windows PMT4/TXN4 two-node loopback, and EVM contract/wallet/dependency audit. The PR remains unmerged because an independent approval is still required and the repository does not allow auto-merge. The public website is therefore still on the pre-CP-0651 deployment until the protected review/merge/Pages sequence completes.
