# AI-NATIVE L1 — Independent Zero-Value Public Testnet Operator Brief

**Status:** Recruitment brief only; no deployment is authorized by this document.  
**Project:** AI-NATIVE L1 (QRun / QZXB)  
**Scope:** Recruit independently administered operators for a future zero-value Public Testnet.

## Why independent operators are needed

The project is not yet operating a genuine public Testnet. The current candidate package is explicitly local/single-operator only. A stable host administered by a separate volunteer, research group, university lab, nonprofit, or open-source infrastructure sponsor is needed before external deployment can be qualified.

The initial infrastructure priority is one independently administered Seed host. That does **not** complete the network-operator requirement: the existing project onboarding gate calls for at least **three genuinely independent operators**, on separate hosts and networks/providers. Three processes, containers, VMs or cloud accounts under one administrator do not count as three operators.

This is a request for infrastructure collaboration, not an investment offer, token sale, or promise of compensation.

## What an operator would provide

- A lawful, stable Linux server or VM under the operator's own account and control.
- A stable public endpoint and permission to run a small experimental Rust node, only after a reviewed configuration is issued.
- A way to test the required inbound transport from an independent network.
- Persistent storage, with a separately managed durable Anchor Vault location and documented backup/recovery.
- Administrative access sufficient to install a systemd service and use the host's supported TPM2/vTPM-backed credential mechanism.
- A named technical contact who can independently attest the endpoint and node's public Noise identity fingerprint.
- Agreement to coordinate maintenance, incident response and orderly shutdown if the experiment is unsafe or no longer supported.

The operator retains control of their infrastructure and can withdraw with reasonable notice. No access to unrelated systems or personal data is requested.

## What the project team provides

- Public source repository and technical documentation for review.
- A narrowly scoped, zero-value test configuration after all release gates are satisfied.
- A documented installation, validation, monitoring and rollback procedure.
- A public record of test scope, known limitations and incident/maintenance notices.

## Security and deployment boundaries

- **Zero-value only.** No Mainnet, real-value transfers, market activity, token rewards, mining payouts or investment claims are authorized.
- Operators must be genuinely independent of the project owner's laptop, VPN, home network and personal hosting account, and independent of one another.
- Never send private keys, Windows DPAPI-protected files, owner signing keys or unredacted local manifests to a prospective operator.
- The Seed private key must be generated and protected locally on the qualified Linux host. The existing Windows DPAPI key is not portable and must not be copied.
- The Linux host's TPM2/vTPM and systemd credential path must be verified before it is relied upon. If required custody properties are unavailable, the host is not qualified.
- The Seed public Noise fingerprint must be verified out-of-band by the operator and independently confirmed by the owner.
- The owner-authority trust pin and exact versioned signed authorization must pass the existing preflight verifier.
- Do not open the public listener, start the Seed, or create a Joining configuration until endpoint, identity, custody, storage and authorization gates have all passed.
- Operator interest, a hosting inquiry, a grant application or a green CI run is not deployment authorization and does not close the independent-operator gate.

## Initial technical qualification (no deployment)

A prospective operator can begin with a short written response confirming:

1. Country/jurisdiction and hosting provider (provider name and region; no account credentials).
2. Whether the host is dedicated or virtual, Linux distribution/kernel, CPU/RAM/storage allocation.
3. Whether public IPv4 and/or IPv6 is stable and under the operator's control.
4. Whether inbound TCP on the eventual configured port can be tested from an unrelated network.
5. Whether TPM2/vTPM is exposed and whether systemd-creds with host+tpm2 and PCR 7 is supported.
6. Whether durable storage and a separately managed Anchor Vault/backup location can be provided.
7. Whether the operator is independently administered from the other participants, including distinct administrator, provider/account and network path.
8. Availability, maintenance window and preferred contact method.

These details are for qualification only. Do not expose public IPs, hostnames, credentials, private keys or sensitive infrastructure details in a public issue; exchange endpoint details privately after initial screening.

## Resource sizing

A final minimum CPU/RAM/disk specification has not been certified for an independently operated Seed. We will measure and publish a reproducible resource profile before asking an operator to commit capacity. Please state available resources rather than provisioning a new server for this request.

## No-cost collaboration model

The preferred contribution is already-available infrastructure donated in-kind by an independent operator or institution. No payment, QZXB allocation, mining reward or future token benefit is promised. Any later funding or incentive proposal would require separate legal review, governance approval and explicit authorization; it is not part of this request.

## How to respond

- Public operator onboarding issue: https://github.com/hamidnikkhah660-arch/ai-native-l1/issues/72
- Repository: https://github.com/hamidnikkhah660-arch/ai-native-l1
- General collaboration contact: hamidnikkhah660@gmail.com

Please mention **“AI-NATIVE L1 independent zero-value operator”** and include only the non-sensitive qualification details above.

## Current limitations

This brief does not claim that the Public Testnet is live, that a Seed endpoint exists, that multi-host synchronization or soak testing has passed, or that any operator has been approved. The project remains experimental. The operator role is conditional on independent technical and security review.
