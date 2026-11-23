# QFP6 Public Alpha Operator Package Ã¢â‚¬â€ CP-0848

**Scope:** ZERO_VALUE_PUBLIC_TESTNET_CANDIDATE_ONLY
**Package type:** experimental Windows x64 operator candidate; not a production release.
**Bootstrap:** one pinned public QFP6 Seed; additional peers are learned through signed Q6PD record gossip.

## Choose your node role

### 1. Outbound-only client Ã¢â‚¬â€ normal/default role

This is the ordinary way to join QFP6 from a home, school or office connection, including behind NAT.

- Connects outward to heymed.tail2a756d.ts.net:443.
- Verifies the Seed using its exact pinned Noise static public key.
- Pulls signed Q6PD peer records, stores them locally and periodically refreshes them.
- Relays third-party signed Q6PD records learned over its Noise session.
- Automatically dials eligible public QFP6 relay candidates only after verifying the record signature, Network ID, Profile ID, TTL, sequence and live Noise key pin.
- Binds only to 127.0.0.1:<ListenPort>; it does not accept Internet inbound connections and does not announce an unreachable private address.
- Requires no public IP, port-forward, firewall/router change, tunnel, TPM or public endpoint. The local Noise key is protected by Windows CurrentUser DPAPI.

This mode lets a participant join without becoming an inbound relay. Discovery does not grant operator, validator, consensus or market authority; auto-trust remains disabled.

### 2. Public relay Ã¢â‚¬â€ optional, for operators with a reachable endpoint

A public relay helps the network grow its set of dialable peers. Use it only when you control an endpoint independently verified from another network.

- Binds to 0.0.0.0:<ListenPort>.
- Announces a signed Q6PD record containing the public numeric endpoint and exact Noise key.
- Requires a local TPM 2.0 Device Root, a TPM-bound Ed25519 Q6PD identity and a Noise-key binding.
- Can receive inbound peers, retain verified signed records and relay those records to later peers.

A public relay requires a globally routable IPv4 or bracketed IPv6 endpoint. If behind NAT, the inbound mapping must already exist. This package does not create it.

## Install and verify

Extract the ZIP to a new folder and open Windows PowerShell 5.1 in that folder. Run:

    Set-ExecutionPolicy -Scope Process Bypass
    .\verify-package.ps1
    .\verify-package.ps1 -FullIntegrity
    .\preflight-host.ps1 -ListenPort 31000

### Join as an ordinary outbound-only client (recommended)

    .\setup-node.ps1 -ListenPort 31000
    .\start-node.ps1 -ListenPort 31000 -ValidateOnly

To start the zero-value public-testnet node after reviewing validation:

    .\start-node.ps1 -ListenPort 31000 -Start -AcknowledgeZeroValuePublicTestnet

No TPM, public listener, public IP, port-forward or firewall exception is needed for this role.

### Optional: join as a public relay

For a numeric public IPv4:

    .\setup-node.ps1 -ListenPort 31000 -PublicEndpoint "YOUR_PUBLIC_IPV4:31000" -AcknowledgePubliclyReachableEndpoint

For global IPv6:

    .\setup-node.ps1 -ListenPort 31000 -PublicEndpoint "[YOUR_GLOBAL_IPV6]:31000" -AcknowledgePubliclyReachableEndpoint

For a TLS-terminating TCP relay on port 443, also provide a lowercase public DNS SNI name:

    .\setup-node.ps1 -ListenPort 31000 -PublicEndpoint "YOUR_PUBLIC_IPV4:443" -TlsServerName "your-public-name.example" -AcknowledgePubliclyReachableEndpoint

Validate, then start only after reviewing inbound exposure:

    .\start-node.ps1 -ListenPort 31000 -ValidateOnly
    .\start-node.ps1 -ListenPort 31000 -Start -AcknowledgeZeroValuePublicTestnet -AcknowledgeAnonymousInboundNoiseXX

Never advertise a private or unverified endpoint. The scripts do not configure firewall, router, NAT mapping, tunnels, Windows services or scheduled tasks.

## Identity and security

Each node generates its own local Noise XX static key protected by CurrentUser DPAPI. An outbound-only client does not publish a Q6PD self-record and does not need a TPM-bound public identity. A public relay additionally provisions a non-exportable TPM Device Root and a separate Ed25519 Q6PD identity bound to that exact local Noise key.

Private keys, DPAPI files, TPM private material, local runtime databases and owner credentials are never copied from the Seed or included in the package. DPAPI-protected keys are local to the Windows user/machine and are not portable backups.

The current inbound P2P transport is Noise XX over classical X25519. On a public relay, inbound Noise XX is anonymous before application-layer Q6PD identity checks; it is not mutual transport authentication. The transport is not post-quantum and no independent production security audit is claimed.

## Seed identity and network pins

- Seed endpoint: heymed.tail2a756d.ts.net:443
- Noise static public key: 9899d6d17d1659df8befcca2bf3ebe19ebe106a8c3d9bd0a4f06d141db3af508
- Bootstrap peer-file SHA-256: 2305ca15acda495960f1e84f4f3f2a7d5b20e279a58953bbc6328e9b16b15e07
- Network ID: 633b5dfc16fb2ec1825baf924ae7f7f16bf2006f8b64441a57692a3531722712
- Profile ID: a0a057d72c11253386bfe90d428bccbc44ebc86fc84e04e3682193a99d8805c4

DNS A/AAAA routes are paths to the same Seed identity, not independent peers. The network does not scan the entire Internet: a node starts from a pinned Seed and learns addresses from QFP6 participants that are actually running and advertising reachable relay endpoints. Outbound-only clients can join behind NAT and exchange relay records, but they do not claim to be publicly dialable.

A live multi-host mesh is only confirmed when an independently administered external host completes a pinned Noise session, exchanges valid signed peer records, converges chain state, and reconnects after restart. A successful setup or same-host test is not that proof.

## Resource bounds and release scope

Peer and session tables are deliberately bounded per node to protect resource usage. That does not impose a fixed global network node count; the network can grow as additional independent QFP6 operators join, subject to physical network and node capacity.

This package is for ZERO_VALUE_PUBLIC_TESTNET_CANDIDATE_ONLY. It does not authorize Mainnet, real-value transfer, issuance/rewards, exchange listing or market activity. It is not a code-signed Windows installer, auto-updater, audited production release or Bitcoin Wire Protocol implementation.

Independent operator intake: https://github.com/hamidnikkhah660-arch/ai-native-l1/issues/204