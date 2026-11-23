# QFP6 Public Alpha Operator Package — CP-0834

**Scope:** ZERO_VALUE_PUBLIC_TESTNET_CANDIDATE_ONLY  
**Package type:** experimental Windows x64 operator candidate, not a production release  
**Current bootstrap:** one pinned public Seed identity; the first independent external peer has not yet been verified.

## What this package does

This package prepares a new joining/relay node using the CP-0834 QFP6 runtime:

- bootstraps to `heymed.tail2a756d.ts.net:443` with the exact pinned Noise static key;
- enables signed Q6PD discovery, periodic peer-record pull, and a signed self-announcement;
- creates a new local Noise XX identity protected by Windows CurrentUser DPAPI;
- creates/reuses a non-exportable TPM 2.0 Device Root on the operator's own Windows machine;
- binds that local TPM root to the local Noise identity;
- creates a separate Ed25519 Q6PD peer-node identity and TPM binding;
- publishes the self-record only for the explicitly supplied numeric public endpoint;
- refuses to auto-trust advertised peers. A discovered peer is dialed only after its signed record passes network/profile/signature/expiry/sequence checks and the live Noise static key matches the record.

This is the intended first-independent-node path: outbound pinned bootstrap to the Seed, signed local announcement, Seed acceptance/persistence, then relay inventory and automatic dialing by eligible peers. It has **not yet been demonstrated between independent hosts**.

## Important security warning — read before starting

The current inbound P2P transport is Noise XX over classical X25519. A peer can reach the listener and complete the unauthenticated Noise XX handshake before application-layer Q6PD identity binding is checked. Therefore inbound Noise XX is **anonymous and not mutual authentication**. This package does not claim a production security audit or post-quantum transport.

The node binds its listener to `0.0.0.0:<ListenPort>`. That is an exposed network service on all local interfaces. Do not run it on a computer/network you do not administer, do not use it on a sensitive daily-use device without an appropriate isolation decision, and do not expose it until you understand the inbound security boundary. The scripts never create firewall exceptions, router/NAT port mappings, tunnels, Windows services, or scheduled tasks.

**Do not start the node merely to test installation.** Setup and validation do not start the listener. The actual start command requires two explicit acknowledgement switches.

## Requirements

- Windows 10/11 x64 and Windows PowerShell 5.1 or later.
- TPM 2.0 available through the Microsoft Platform Crypto Provider.
- At least 2 GB free RAM and 1 GB free disk space before setup.
- Outbound TCP to the pinned Seed on port 443.
- A globally routable inbound endpoint that you administer and have verified from a separate network. The setup tool accepts numeric IPv4:port or bracketed IPv6:port.
- If behind NAT, you must already have a suitable inbound mapping from the public endpoint to the local listen port. This package does not configure it.
- For a TLS-terminating TCP relay, supply a lowercase public DNS SNI name and use public endpoint port 443.

A machine without a supported TPM cannot use this public-self-announcement package. A machine without a verified reachable endpoint must not advertise itself as a relay.

## Install and verify

Extract the ZIP to a new folder. Open PowerShell in that folder:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\verify-package.ps1
# Optional exhaustive rehash of every file in the large package:
.\verify-package.ps1 -FullIntegrity
.\preflight-host.ps1 -ListenPort 31000
```

Choose the public address that remote peers can actually reach. For a numeric public IPv4:

```powershell
.\setup-node.ps1 -ListenPort 31000 -PublicEndpoint "YOUR_PUBLIC_IPV4:31000" -AcknowledgePubliclyReachableEndpoint
```

For global IPv6, use brackets:

```powershell
.\setup-node.ps1 -ListenPort 31000 -PublicEndpoint "[YOUR_GLOBAL_IPV6]:31000" -AcknowledgePubliclyReachableEndpoint
```

For a TLS-terminating TCP relay on port 443, include the public SNI name:

```powershell
.\setup-node.ps1 -ListenPort 31000 -PublicEndpoint "YOUR_PUBLIC_IPV4:443" -TlsServerName "your-public-name.example" -AcknowledgePubliclyReachableEndpoint
```

Replace placeholders with an endpoint you administer and have tested from another network. Do not post the address in the public GitHub issue. DNS names alone do not establish identity; the Seed's exact Noise key remains pinned.

Setup creates local-only credentials and configuration. It does not start the node. Private Noise and Ed25519 seeds are never printed or included in this ZIP. The Device Root private key is non-exportable through the TPM CNG provider. DPAPI-protected files are bound to the Windows user/machine and are not portable backups. A TPM clear or motherboard replacement requires explicit reenrollment; never silently replace an identity.

## Validate and start

First validate the generated configuration without starting a node:

```powershell
.\start-node.ps1 -ListenPort 31000 -ValidateOnly
```

Only after you have reviewed the listener exposure warning and independently confirmed that the public endpoint is reachable, start the zero-value candidate explicitly:

```powershell
.\start-node.ps1 -ListenPort 31000 -Start -AcknowledgeZeroValuePublicTestnet -AcknowledgeAnonymousInboundNoiseXX
```

Stop the foreground process with Ctrl+C. This is not a Windows service and does not auto-start at login. No firewall/router/NAT/tunnel changes are performed by the package.

## What gets shared — and what never does

Included: public Genesis/profile/authorization/checkpoint files, a hash-checked bootstrap anchor baseline, the public Seed endpoint, and its public Noise key pin.

Generated locally and never packaged: Noise private key, TPM Device Root private key, Q6PD Ed25519 private seed, local TPM binding files, local node data, and node runtime state. The bootstrap Anchor Vault directory is a hash-chained checkpoint baseline only; it is **not** the owner's live Vault, not a private-key store, and not an independent remote monotonic trust service.

The Seed identity is:
- Endpoint: `heymed.tail2a756d.ts.net:443`
- Noise static public key: `9899d6d17d1659df8befcca2bf3ebe19ebe106a8c3d9bd0a4f06d141db3af508`
- Bootstrap peer-file SHA-256: `2305ca15acda495960f1e84f4f3f2a7d5b20e279a58953bbc6328e9b16b15e07`
- Network ID: `633b5dfc16fb2ec1825baf924ae7f7f16bf2006f8b64441a57692a3531722712`
- Profile ID: `a0a057d72c11253386bfe90d428bccbc44ebc86fc84e04e3682193a99d8805c4`

## What success looks like

After an external operator has completed setup and starts the node, the first verification event is a Q6PD self-announcement signed by that operator's local Ed25519 identity and bound to their Noise key/TPM root. The Seed should validate and persist the signed record. The Seed's bounded scheduler can then dial the advertised endpoint under the signed record's exact Noise-key pin. Other nodes subsequently obtain the record through Q6PD inventory/pull and may dial it under the same checks.

A setup success message is **not** a network join. An independent peer only counts after logs demonstrate a successful pinned Noise session, accepted signed Q6PD record, history/state convergence, and restart/reconnect from a separately administered host. Until then, the live multi-host mesh remains unverified.

## Release boundaries and limitations

- ZERO_VALUE_PUBLIC_TESTNET_CANDIDATE_ONLY.
- No Mainnet, real-value transfers, issuance/rewards, exchange listing, or market activity is authorized.
- The current P2P transport is classical X25519; it is not post-quantum.
- Inbound Noise XX is anonymous/unauthenticated before Q6PD application checks.
- This is not a code-signed Windows installer, auto-updater, Windows service, audited release, or Bitcoin-equivalent network.
- The source worktree used for the current candidate build contains additional uncommitted changes; the package is hash-pinned, but is not claimed reproducible from the public branch head alone. See PACKAGE-METADATA.md.

Independent operator intake: https://github.com/hamidnikkhah660-arch/ai-native-l1/issues/204