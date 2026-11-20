# AI-NATIVE L1 — Independent Operator Intake and Acceptance Matrix

Date: 2026-11-16  
Status: Internal qualification procedure; interest collection only. No node deployment is authorized.

## 1. Operator-count rule

The current public onboarding request seeks at least three genuinely independent operators. For a future public test, independence must be demonstrated by separate human administrators and independently controlled infrastructure/network paths. Three nodes, VMs, containers, cloud projects or GitHub runners controlled by one person or one organization do not satisfy this requirement.

The first infrastructure priority is a qualified Seed host. The Seed host is only one role in the multi-operator qualification; it does not by itself satisfy the three-operator gate.

## 2. Stage A — non-sensitive expression of interest

Collect only:
- Preferred operator/team name (public alias acceptable for initial interest).
- Country and provider/region.
- Platform family and Linux distribution.
- Approximate CPU, RAM and persistent storage available.
- Stable public IPv4/IPv6 availability (yes/no; do not request the actual address publicly).
- Ability to test inbound TCP from an unrelated network (yes/no/unknown).
- TPM2/vTPM availability and whether systemd-creds host+tpm2 is supported (yes/no/unknown).
- Whether administrator, provider account and network path are independent of other operators.
- Availability window and preferred private contact method.

Never collect public issue comments containing public IPs, hostnames, credentials, passwords, private keys, recovery phrases, identity documents, payment data or local secrets.

## 3. Stage B — independence review

For each candidate, record evidence privately:
- Named responsible administrator and their control boundary.
- Hosting provider, account ownership/control and region.
- Whether the candidate shares a physical host, provider account, admin team, NAT gateway or network path with another candidate.
- Whether any candidate is controlled by the project owner or runs on the owner's laptop/home network/VPN.
- Conflict-of-interest and operational responsibility disclosure.

Reject duplicate administrators or infrastructure presented as separate operators. Do not publish sensitive network topology.

## 4. Stage C — host capability review (still no deployment)

- Linux distribution, kernel and systemd version supported by the project.
- Public route stability and provider terms allowing experimental P2P service.
- Inbound TCP transport tested from an unrelated network on a temporary, approved test endpoint; do not start QRun for this test.
- TPM2/vTPM presence, PCR behavior, and actual support for systemd-creds --with-key=host+tpm2 --tpm2-pcrs=7.
- Durable storage and an Anchor Vault location with verified non-overlap and separate backup/recovery.
- Resource sizing from a measured, reproducible QRun workload. No minimum CPU/RAM/disk value is approved yet.
- Operator incident contact, maintenance window, backup and shutdown plan.

A hosting provider's marketing claim is not evidence of TPM, public inbound transport, durable storage or stable addressing.

## 5. Stage D — cryptographic and release gates

Before any public Seed start:
1. Provision a fresh Noise key locally on the selected Linux host using the approved Linux custody path. Never copy a Windows DPAPI key.
2. Verify the public Noise fingerprint through an independent out-of-band channel.
3. Verify stable endpoint reachability from a separate network and preserve timestamped evidence.
4. Establish the owner Ed25519 authority public-key fingerprint through an independent channel.
5. Produce the exact version-bound owner-signed authorization and pass the existing preflight verifier.
6. Verify Q6GD, Q6CP, Q6PN, Genesis, Q6GA, peer list and all relevant artifact hashes.
7. Confirm durable Anchor Vault isolation, backup and tested recovery.
8. Only then prepare the Seed runtime config and separately review listener activation.
9. Do not prepare Joining runtime config until the Seed endpoint and fingerprint are independently verified and authorization passes.

## 6. Multi-operator test acceptance

The three-operator requirement is not met until:
- Three distinct administrators and hosts are independently verified.
- Each node uses the exact same reviewed zero-value profile and source/binary hashes.
- External peer connectivity, authentication, sync, restart/replay and canonical-tip/state-root convergence are demonstrated.
- Abuse controls, monitoring, backups, incident response and rollback are exercised.
- Independent security review scope/findings and launch decision are recorded.

A candidate response, account registration, hosting allocation, unit test, local loopback run or CI runner does not close this gate.

## 7. Stop conditions

Stop and do not launch if:
- Provider terms or jurisdiction are unclear or disallow the intended use.
- Independence cannot be substantiated.
- Stable endpoint or inbound transport cannot be independently verified.
- TPM/custody requirements cannot be demonstrated.
- Anchor Vault storage overlaps or recovery is untested.
- Owner trust pin, signature, manifest binding or fingerprint attestation fails.
- The public profile is not explicitly zero-value-only.
- Any secret would need to be copied to an untrusted party or committed to the repository.

## 8. Decision record

For each candidate use one of:
- INTEREST_ONLY
- TECHNICAL_SCREEN_PENDING
- INDEPENDENCE_VERIFIED
- HOST_CAPABILITY_VERIFIED
- CRYPTOGRAPHIC_GATES_PENDING
- APPROVED_FOR_SCOPED_TEST (requires separate written authorization)
- REJECTED / WITHDRAWN

No candidate may skip stages. Keep private evidence out of public Git history.
