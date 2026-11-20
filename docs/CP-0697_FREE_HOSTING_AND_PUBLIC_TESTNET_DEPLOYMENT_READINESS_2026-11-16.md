# CP-0697 — Free Hosting and Public Testnet Deployment Readiness
Date: 2026-11-16
Project: AI-NATIVE L1
Scope: read-only infrastructure/code audit plus focused existing tests; no deployment.

## 1. Verified repository state
- Active worktree: D:\Temp\ASUS\QRUN_QFP6_CP0596_20261111
- Branch: feat/cp0600-bootstrap-sync-startup
- HEAD unchanged: 5aba5f69d24fce03af742fd1bebf13ad00e5d9c3
- Existing dirty/untracked work was preserved. No reset, clean, stash, commit, push, merge or rebase.
- CP-0696 remains the prior engineering checkpoint.
- Public Testnet package artifacts currently exist under:
  release/qfp6-local-single-operator-devnet-2026-11-15/
  including Q6GD, Q6CP, Q6PN, Genesis snapshot, Q6GA public-testnet authorization, public-only Seed identity JSON, and IPv4/IPv6 Seed candidate configs.
- The package README still labels the package LOCAL SINGLE-OPERATOR / LOOPBACK ONLY and explicitly says it is not a public Testnet release. The presence of candidate public configs is not launch authorization.

## 2. Existing public runtime path and tests
- qrun_v06_node has a separate --public-testnet-run path; the ordinary --run path remains private-candidate.
- Public mode requires the exact public-testnet-zero-value-candidate mode, candidate/public-listener opt-ins, exact zero-value/no-Mainnet/no-market acknowledgement, and the explicit anonymous inbound Noise XX acknowledgement.
- Topology validation requires a public/wildcard listener. A Seed starts from Genesis with an empty pinned bootstrap set; a Joining node requires at least one independently pinned public bootstrap peer.
- The runtime verifies Q6PN/Q6GD/Q6CP/Genesis hashes and Q6GA v2 public-testnet owner/economics bindings before opening the listener. It binds the socket only after key, trust, durable state and mempool checks.
- Focused existing tests run in this session:
  cargo test --bin qrun_v06_node public_testnet_ -- --nocapture
  Result: 2 passed, 0 failed; 43 filtered out. The 9 pre-existing library warnings remain unrelated.
- These unit tests do not prove external reachability, multi-host sync, public soak, adversarial DoS resistance or independent operation.

## 3. Existing candidate configs are not portable to a Linux VPS
- Both public Seed candidate configs use wildcard binding (one IPv4, one IPv6) and role=seed, with no bootstrap peers.
- Their node_noise_private_key_path points to the Windows DPAPI-protected NPK file. Their trusted_manifest_anchor_vault_path points to the local Windows C: Anchor Vault.
- Do not copy the Windows DPAPI NPK file to Linux. It is bound to the Windows CurrentUser DPAPI context.
- The existing Linux custody implementation in noise_key_provisioning.rs uses systemd-creds with --with-key=host+tpm2 and --tpm2-pcrs=7, delivered through a systemd LoadCredentialEncrypted service credential. A Linux VPS requires a new host-local key provisioned and tested under that Linux custody path.
- The current Anchor Vault path must be replaced with a host-appropriate absolute path. Runtime path validation is lexical/non-overlap only; it does not prove separate physical storage. If separate storage is required, provision and verify it explicitly.
- The new host Noise public key/fingerprint must be independently attested out-of-band. The owner authority pin and signed versioned rotation authorization gate from CP-0696 remain separate requirements.

## 4. Public-network security and remaining launch gates
- Public Seed ingress intentionally allows anonymous Joining clients; the Seed does not authenticate every inbound client identity through this path.
- Joining clients authenticate the Seed by pinning its exact Noise responder public key through Noise XX. The public identity JSON is not self-authenticating; its fingerprint must be verified with the owner over a separate trusted channel.
- Automatic peer discovery is not implemented. Bootstrap peers are explicit, numeric public IP:port entries with pinned Noise keys and a SHA-256-pinned peer file.
- The laptop's earlier inbound IPv6 diagnostic succeeded at that time, but the Wi-Fi IPv6 address had a short preferred lifetime. It is not a stable Seed endpoint and must not be promoted to one.
- No stable owner-controlled public Seed endpoint or independent external operator attestation is currently available.
- No Joining config is to be created until the final Seed endpoint and fingerprint are independently verified and the owner-signed authorization gate passes.
- No node was started in this session. Final read-only check: qrun_v06_node processes=0; TCP 30333 listeners=0; TCP 30334 listeners=0.

## 5. Zero-cost hosting options assessed
### Oracle Cloud Always Free
- Official Oracle documentation currently lists up to two VM.Standard.E2.1.Micro instances (1 GB RAM each) and an Ampere A1 allowance equivalent to 2 OCPUs / 12 GB RAM, in the tenancy home region.
- Oracle requires most signups to provide a mobile phone and a credit/debit card for identity verification. Oracle states it may place a temporary authorization hold; it says the hold is removed and is not an actual charge. Do not upgrade to Pay As You Go or create resources outside Always Free.
- Always Free capacity is region-dependent. Oracle can reclaim an Always Free VM after a 7-day period if the published CPU/network/memory idle thresholds are met. The service has no SLA; Always Free-only accounts do not receive Oracle Support tickets.
- Oracle documents TPM/Measured Boot for supported shielded VMs. The actual selected shape/image must expose and enable vTPM before relying on systemd-creds host+tpm2. OCI documents that TPM state/PCR values are not retained when a shielded VM is migrated; migration/recreation therefore requires a planned key recovery/rotation path.
- Conclusion: best first candidate only if the owner can complete legitimate signup verification and the exact Always Free shape, public IPv6/IPv4 route, vTPM and storage requirements are verified in the account console. It is not a guaranteed production-grade sole Seed.

### FreeVPS.org community allocation
- The provider advertises no card/payment, but requires an active LowEndTalk or LowEndSpirit account at least 3 months old, 50+ substantive posts and 25+ received thanks.
- Published regular allocation: 1 fair-share core, 1 GB RAM, 20 GB storage, 250 GB bandwidth on a 150 Mbps port, 20 forwarded NAT IPv4 ports and a dedicated IPv6 /64 or /80, subject to capacity.
- Provider states no SLA, best-effort uptime and that instances may be reclaimed when physical nodes are reorganized. UDP forwarding and TPM/vTPM availability are not established by the reviewed page.
- Conclusion: possible temporary/community test host only if the owner already meets eligibility and all technical/custody checks pass. Not acceptable as the only permanent Seed or as proof of independent operator diversity.

## 6. Economic and operational boundary
- QZXB allocation: 0 spent; no QZXB or mining allocation is assigned to hosting.
- No payment, account signup, card entry, VPS provisioning, firewall change, DNS change or router change occurred.
- Q6GA v2 remains ZERO_VALUE_PUBLIC_TESTNET_ONLY. Mainnet, real-value transfers, rewards, market activity and exchange/listing claims remain unauthorized.
- Do not launch a node or create a real Joining config as part of this checkpoint.

## 7. Next decision
Before any account creation, the owner must confirm whether a valid credit/debit card and mobile number can be used for Oracle's identity verification without an actual payment. If not, assess whether the owner already meets the FreeVPS.org forum eligibility; otherwise seek a genuinely independent volunteer/operator host rather than relying on an anonymous low-quality free VPS.
