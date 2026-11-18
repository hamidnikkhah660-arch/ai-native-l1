# CP-0655 — External Public Testnet Provisioning Requirements

Date: 2026-11-14  
Project: AI-NATIVE L1 / QRUN-QFP6  
Depends on: CP-0651 through CP-0654  
Status: **owner provisioning required; no external seed hosts currently connected**

## 1. Current verified environment

The connected Desktop Commander device inventory currently contains only:

- `heymed` — the user's Windows development workstation.

No independent public seed host, joining VPS, public P2P endpoint, or externally provisioned node Noise key is currently connected/available in the authorized device inventory.

## 2. Minimum external infrastructure to begin the zero-value Public Testnet

Provide **two independently administered seed hosts** so bootstrap can use two operator-assigned trust domains and the CP-0648/0649 multi-source agreement gate.

Recommended candidate host profile for each seed:

- Ubuntu 24.04 LTS, x86_64.
- 4 vCPU, 8 GiB RAM, 60–80 GiB SSD.
- Stable public IPv4 or globally routable IPv6 address.
- Ability to permit one explicitly approved inbound TCP P2P port after preflight passes.
- Prefer different hosting providers and network/ASN ownership for the two seeds; two VM names or two IPs under one operator are not proof of independent control.

A separate joining node is useful for the first external sync/restart/transaction test. The current Windows workstation may serve as a joining client only if the user chooses that topology and its network constraints permit the required outbound connectivity; otherwise provide a third VPS.

### Secure access path

Add the seed hosts as separate online Desktop Commander devices through the account's device-management page:

`https://mcp.desktopcommander.app/`

Do not paste SSH passwords, root passwords, recovery codes or private keys into chat. Once the hosts are connected, inspect each host and provision its keys locally. Share only public endpoints and public-key fingerprints.

## 3. Owner Genesis signing authority

The final CP-0651 Genesis must credit exactly 1B QZXB to the intended owner account and must be signed by the authorized owner identity.

- The current candidate release manifest already contains a public owner identity/account binding.
- The owner must confirm that the existing public owner account in the manifest is the intended recipient of the 1B Genesis allocation.
- The private signing key must remain on an owner-controlled offline/protected signer. Do not upload or paste private signing material.
- Once Q6GD/Q6CP/Q6PN and Genesis bytes are frozen, produce a signable digest package; the owner signs that digest through the protected signer and supplies only the resulting public signature/artifact.

If the existing owner signing key is not available, do not create a different owner identity silently. Resolve the key/account custody and recovery path first.

## 4. Node identity and bootstrap trust

Each seed node needs its own locally generated protected Noise static private key. The private key stays on that host. Only the corresponding public static key, fingerprint, and public endpoint are published into the separately reviewed bootstrap configuration.

The two seed nodes must receive distinct operator-assigned trust-domain identifiers. Those assignments must reflect genuinely independent administration; different keys alone do not establish independent ownership or eliminate collusion.

## 5. Security acknowledgement required for public inbound

The current Public Testnet candidate path uses anonymous inbound Noise XX over classical X25519. This encrypts records but does not authenticate the remote operator's real-world identity; an active MITM can terminate/re-encrypt an unpinned inbound session. It is not post-quantum transport.

Before using the existing public inbound mode, the owner must explicitly accept this limitation for a **zero-value candidate Testnet only**. Otherwise the launch remains blocked while an authenticated peer-identity handshake/profile is designed and qualified. Neither option authorizes Mainnet or value-bearing use.

## 6. Independent qualification

Before the release manifest can mark external readiness true, arrange independent reviewers/operators for:

- Consensus and difficulty/retarget parameters.
- Cryptographic protocol, identity/key custody and Noise transport.
- CP-0651 tokenomics, Genesis allocation, zero block subsidy and fee-only producer incentives.
- External two-/multi-host full-history sync, divergence rejection, restart/replay, peer loss and listener/slow-handshake resilience.

Internal unit tests and loopback Noise tests cannot self-certify these reviews.

## 7. No premature exposure

Do not open firewall/router ports, publish seed endpoints, or start a public listener until:

1. Both seed hosts are connected and inspected.
2. Protected local keys and public identity fingerprints are generated.
3. Q6GD/Q6CP/Q6PN and CP-0651 Genesis are produced and independently pinned.
4. The owner signs the Genesis digest.
5. The exact config and bootstrap files are hash-pinned and preflight-tested.
6. The security acknowledgement and external-test plan are recorded.

At the time of this checkpoint, these external prerequisites are still outstanding. Public Testnet and Mainnet remain NO-GO.
