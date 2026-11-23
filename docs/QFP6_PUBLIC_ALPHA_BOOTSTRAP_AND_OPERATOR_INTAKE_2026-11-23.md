# QFP6 Zero-Value Public Alpha — Bootstrap and Independent Operator Intake

**Date:** 2026-11-23  
**Scope:** ZERO_VALUE_PUBLIC_TESTNET_CANDIDATE_ONLY  
**Status:** one configured public Seed; no independently operated external QFP6 node has yet been verified.

## Canonical bootstrap

- Peer file: [qfp6-public-testnet-bootstrap-peers-v1.json](../assets/qfp6-public-testnet-bootstrap-peers-v1.json)
- Manifest: [qfp6-public-testnet-bootstrap-v1.json](../assets/qfp6-public-testnet-bootstrap-v1.json)
- Peer-file SHA-256: `2305ca15acda495960f1e84f4f3f2a7d5b20e279a58953bbc6328e9b16b15e07`
- Seed endpoint: `heymed.tail2a756d.ts.net:443`
- TLS SNI: `heymed.tail2a756d.ts.net`
- Seed Noise static public-key pin: `9899d6d17d1659df8befcca2bf3ebe19ebe106a8c3d9bd0a4f06d141db3af508`
- Network ID: `633b5dfc16fb2ec1825baf924ae7f7f16bf2006f8b64441a57692a3531722712`
- Profile ID: `a0a057d72c11253386bfe90d428bccbc44ebc86fc84e04e3682193a99d8805c4`

DNS is transport discovery only and does not establish identity. Joining software must pin the exact peer-file digest and authenticate the Seed with the exact Noise key. The manifest is metadata plus digests, **not a digital signature**.

## Current candidate behaviour

The locally built CP-0834 candidate resolves the configured DNS Seed to public TCP/443 routes, preserves TLS SNI and the operator-pinned Noise key while attempting routes, and implements signed Q6PD peer-record gossip. Record admission is bound to network/profile and cryptographic signature, expiry, and sequence checks. A discovered record is not automatically trusted: the Noise identity must match the record's pinned key before a dial is accepted.

The local Root Seed can serve signed peer records and can auto-dial eligible signed records. The current root record store contains only the Seed's own record. A first external signed identity and a live multi-host mesh have **not** been demonstrated. The local Root and Joiner processes on the same physical host do not count as independent operators.

## How an independent operator must join

A joining operator must provision a fresh local node identity and Noise key on their own host. Never copy the Seed's private key, TPM metadata, local Vault, node data directory, or another operator's credentials.

An operator behind NAT may initiate an outbound connection to the Seed. They must not advertise a private, loopback, link-local, or otherwise unreachable address. A node becomes a useful dialable relay only after it has an independently reachable public endpoint and its signed record and Noise-key binding have been verified.

## Installer and release warning

This publication makes the canonical Seed pin and protocol scope reviewable. It is **not a complete self-service installer or a general-purpose signed binary release**. The older controlled-QA Joiner folder is not a public installer for this CP-0834 topology: its old setup script disables the Q6PD relay/self-publication path and its docs explicitly label it internal QA. Do not use it as a public install path. A new operator bundle must be built from the exact CP-0834 source/config, exclude owner secrets and TPM material, generate a fresh local key on the joining host, and include verified binary and package hashes before broad distribution.

Do not expose a listener or change firewall/router rules based only on this bootstrap file.

## Operator independence and requested evidence

The project is seeking independent zero-value QFP6 operators on separately administered hosts and networks. Initial interest can be posted to [operator-intake issue #204](https://github.com/hamidnikkhah660-arch/ai-native-l1/issues/204). Do not post private keys, credentials, wallet recovery data, public IP addresses, or sensitive host details. Initial reproduction/interest does not itself qualify an operator. Actual qualification requires evidence of a fresh identity, successful pinned Noise handshake, valid Q6PD record acceptance, independent history/state convergence, restart/reconnect, and a reachable endpoint before that operator is advertised as a relay.

## Release boundary

This is an experimental zero-value candidate. It does not authorize Mainnet, real-value transfers, token issuance/rewards, or market activity. A public bootstrap file is not proof of a public multi-host network, decentralization, an audit, or Bitcoin-equivalent operation.
