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

- Linux distribution, kernel, firmware/Secure Boot mode, TPM vendor/model or vTPM implementation, and exact systemd version.
- Record the systemd version used to create each encrypted credential as well as the version that decrypts it. The local CP-0669 qualification covers one disposable Ubuntu 24.04.5 / systemd 255 / Hyper-V vTPM2 environment only; it is not blanket qualification for other distributions, providers, firmware or TPM implementations.
- Treat systemd credential-format compatibility as version-sensitive: upstream documents that systemd v262 and later additionally bind encrypted credentials to the TPM2 SRK and that credentials produced with this newer behavior are incompatible with earlier systemd versions. Provision and test credentials on the actual target host/version; do not assume cross-version portability. Before an upgrade or rollback, test the intended credential recovery/re-provisioning procedure in a disposable environment and document the supported upgrade path.
- For PCR 7, record the Secure Boot state and relevant enrolled firmware certificates, verify the expected PCR bank/value on the actual host, and test reboot plus the approved Secure Boot/certificate-change recovery path. PCR 7 represents Secure Boot policy; do not describe it as a complete measurement of every boot component or as proof of runtime integrity.
- Public route stability and provider terms allowing experimental P2P service.
- Inbound TCP transport tested from an unrelated network on a temporary, approved test endpoint; do not start QRun for this test.
- TPM2/vTPM presence, PCR behavior, and actual support for systemd-creds --with-key=host+tpm2 --tpm2-pcrs=7.
- Durable storage and an Anchor Vault location with verified non-overlap and separate backup/recovery.
- Resource sizing from a measured, reproducible QRun workload. No minimum CPU/RAM/disk value is approved yet.
- Operator incident contact, maintenance window, backup and shutdown plan.

A hosting provider's marketing claim is not evidence of TPM, public inbound transport, durable storage or stable addressing.

## 4A. TPM and host-loss recovery qualification

Before a Seed host can be approved, document and test the recovery behavior for TPM clear/reset, TPM or motherboard replacement, loss of the host installation or `/var/lib/systemd/credential.secret`, and loss or corruption of the encrypted credential file. The `host+tpm2` credential must not be assumed portable to a replacement host or TPM.

- Run the recovery exercise on a disposable host or snapshot; do not experiment against the only copy of an operational key.
- Choose and document an approved recovery path: restore from a separately protected recovery source, or rotate the Noise identity through the project's reviewed authorization and peer-trust update process.
- If identity rotation is required, verify the new public fingerprint out-of-band, bind the change to the applicable owner-authorized version, update peer trust only through the reviewed process, and prove that the retired identity is no longer accepted.
- Keep recovery material encrypted and access-controlled outside the host failure domain. Never place plaintext private keys, recovery material, or credentials in Git, public issues, or operator intake.
- Record the tested failure mode, recovery steps, responsible authority, and evidence. If no safe recovery path is demonstrated, the host is not qualified for Seed duty.
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
