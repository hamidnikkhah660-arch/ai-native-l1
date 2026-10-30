# QRun v0.5 wallet-bound Genesis setup - 2026-10-28

## Current status

Current state (2026-10-29): the node is running in `public-alpha` candidate mode. The prior `--mainnet` startup was found to report `mainnet=true` even when no remote peer or startup sync was configured; that behavior contradicted the launch criteria and is now blocked in source. The fixed wallet-bound Genesis and 10B supply remain intact; current read-only RPC confirms the owner's 10B balance while correctly reporting `mainnet=false`.

This is a one-node experimental public-alpha candidate: canonical height is 0 and no independent peer is configured. The TCP P2P listener is bound to 0.0.0.0:49341, but inbound Internet reachability has not been verified; Windows Firewall is enabled and no matching inbound rule was found, and no local Windows NAT mapping was detected. Router/NAT forwarding may also be required. RPC (49339) and transaction ingress (49340) remain loopback-only. Do not treat a mode flag, listener bind, or successful local balance query as proof of public Mainnet connectivity.

A candidate node can initialize the deterministic Genesis without an existing peer, but this project must not call that state Mainnet. The `--mainnet` mode now requires `--sync-on-start true`, at least one non-loopback seed, and a static Noise-key pin for every configured seed. Startup must authenticate and successfully sync with that seed before the process sets its RPC `mainnet` status to true. Genesis/profile identity and the height-zero state root/single-owner allocation are checked, and the total supply must remain at the fixed cap.

## Local wallet identity

- Wallet file: `C:\QRun\owner.qzkw`
- Format: `QZKW1_Windows_CurrentUser_DPAPI` (bound to this Windows user context)
- Account ID: `a14d67bd195c6a0044bedac8532e742811f92501630764d73a98b2f0cc335fdd`
- Public key: `fca65e26f596fa60674f5ec35808ec80b317a701e97feee343d85007713bd93f`
- Recovery phrase is not recorded in this repository or chat; it is displayed in the local wallet-creation console. Write it down offline and do not share it.

## Wallet-bound chain identity

To avoid reusing the prior proposed Genesis identity with a different owner, the wallet-specific network ID is derived as:

`SHA256("QUANTUMZXB-QRUN-PUBLIC-ALPHA-WALLET-GENESIS-V1\0" || proposed_network_id_bytes || wallet_account_id_bytes)`

- Proposed base network ID: `70fdcdbe6f0afa1edb0c4fb4a85252831376f7b9ecf2a13a86dcf61979cdcad7`
- Wallet-bound network ID: `8b5d169205ac49cb9866a9d27ff1a6c3c2571fca65f634854c41c112e506aebb`
- Original proposed Genesis ID (different owner): `613bb4f36c8e57e73dd04308809b9decdd1b4411e0838f948ee2aa7eaacbab97`

Because the owner/network values differ, this wallet-bound network has a different Genesis and consensus profile ID. It must not be presented as the original frozen identity. All peers joining this alpha chain must use the exact same network ID, Genesis owner account/public key, Genesis and profile.

## Monetary state

The QRun v0.5 Genesis runtime credits the fixed total supply of 1,000,000,000,000,000,000 atoms (10 billion QZXB at 8 decimals) to the configured Genesis owner. There is no subsequent issuance and the block subsidy is zero. This is an owner pre-allocation model, not Bitcoin's miner-reward issuance schedule. The local node currently runs in `public-alpha` candidate mode (`mainnet=false`); external reachability and independent peer replication are not yet verified.

## Local verification completed

1. A rebuilt public-alpha node was launched with the wallet-derived account/public key, this wallet-bound network ID, a matching DPAPI-protected Noise key, and fresh data directory `C:\QRun\wallet-bound-genesis-data-v3`.
2. Verified from the node startup output: Genesis owner equals the wallet account, owner balance and total supply are `1000000000000000000` atoms, and height is zero. The `qzxb_wallet balance` command against `127.0.0.1:49339` returned the same balance, account ID, and state root.
3. Observed listeners: RPC `127.0.0.1:49339`, transaction ingress `127.0.0.1:49340`, and P2P `0.0.0.0:49341`. No independent peer is connected (`block_peer_count=0`); inbound Internet reachability remains unverified. Keep RPC and transaction ingress loopback-only.

## Historical one-node Mainnet-flag launch (superseded; not proof of public Mainnet)

This section records an earlier flag-only/Genesis-bootstrap run for traceability. It had no configured peers, so the observed `mainnet=true` response did not establish a public Mainnet. The current source and verified Release build reject the same no-peer/no-sync configuration.

- Release node supports --mainnet, locked to the wallet-bound network ID, owner account ID, and owner public key recorded above.
- Mainnet-mode startup banners: QRUN_V05_MAINNET_GENESIS_BOOTSTRAP followed by QRUN_V05_MAINNET_NODE_READY after listener binding.
- mainnet=true; network_class=qzxb_mainnet.
- Genesis ID: 91229b7d21b23cee83f00cec53a566ef1b30db70c644c1e9d05a431c1acf4dbc.
- Profile ID: 75596fa188dc308088efc6b138e9fcd50be6de82ec2bc117c13e81d7eebfdb09.
- State root at height zero: a44e545c2cd8fa4e56e228f4f242cbf5445b1cc983c7b1f8fe89c5b42aef88d7.
- Node startup reports owner_balance_atoms=1000000000000000000 and total_supply_atoms=1000000000000000000.
- The rebuilt qzxb_wallet.exe rpc-status and qzxb_wallet.exe balance both succeed. Wallet RPC reports network_class=qzxb_mainnet and balance 1000000000000000000 atoms for the owner account.
- Listeners: RPC 127.0.0.1:49339, transaction ingress 127.0.0.1:49340, P2P 0.0.0.0:49341. RPC and transaction ingress remain loopback-only.
- No independent peer is currently connected (configured_peer_count=0) and public Internet reachability has not been verified. The PowerShell process is not elevated, so it cannot install the inbound firewall rule. pinned_peer_sync_verified=true is intentionally not reported because no peer sync was requested.
- Supply policy remains a one-time 10B Genesis preallocation to the owner with zero subsequent issuance and zero block subsidy. This is not Bitcoin's miner-reward issuance schedule.


## Public P2P firewall step

Run PowerShell as Administrator on the node host to open only the P2P listener. Keep RPC and transaction ingress restricted to loopback. Use the correct executable path for the firewall program filter; the latest verified Release build is C:\QRun\qrun-mainnet-verified-target-20261029a\release\qrun_v05_pow_local_node.exe.

New-NetFirewallRule -DisplayName "QZXB P2P 49341" -Direction Inbound -Action Allow -Enabled True -Profile Any -Program "C:\QRun\qrun-mainnet-verified-target-20261029a\release\qrun_v05_pow_local_node.exe" -Protocol TCP -LocalPort 49341 -EdgeTraversalPolicy Block

If this machine is behind NAT, forward TCP 49341 on the router to the host LAN IPv4 address. No Internet peer has yet been observed, so external reachability must not be claimed until an outside peer can connect.
## Current engineering verification — 2026-10-29

- The currently running node was relaunched using the latest isolated Release build in `public-alpha` mode against the existing `C:\QRun\wallet-bound-genesis-data-v3` directory. No wallet, Noise-key, or chain data files were deleted or reset.
- Current RPC `/v1/status`: `mainnet=false`, `network_class=public_alpha_experimental_not_mainnet`, `height=0`. Network ID, Genesis ID and Profile ID match the wallet-bound identity above. State root remains `a44e545c2cd8fa4e56e228f4f242cbf5445b1cc983c7b1f8fe89c5b42aef88d7`.
- Current RPC balance for the owner account is `1000000000000000000` atoms (`10000000000.00000000` QZXB); total supply is the same amount. This verifies the persistent local Genesis state, not public replication.
- Current listeners: RPC `127.0.0.1:49339`, transaction ingress `127.0.0.1:49340`, P2P `0.0.0.0:49341`. `configured_peer_count=0`.
- Source now refuses `--mainnet` unless `--sync-on-start true`, at least one non-loopback seed, one static-key pin for each seed, and a non-loopback P2P listener are configured. After the authenticated seed sync succeeds and listeners bind, the frozen Genesis/Profile and the fixed 10B supply are checked before Mainnet status can be enabled.
- Integration gate check: invoking the latest Release binary with the correct wallet/network identity but no `--peer` or startup-sync option returned `QRUN_V05_LOCAL_NODE_ERROR: --mainnet requires --sync-on-start true` (exit code 2). The designated smoke-test data directory was not created.
- Validation passed: `cargo fmt --all -- --check`; node binary tests `14 passed, 0 failed`; wallet binary tests `6 passed, 0 failed`; wallet-bound Genesis regression `1 passed, 0 failed`; Release build of `qrun_v05_pow_local_node` and `qzxb_wallet` succeeded in `C:\QRun\qrun-mainnet-verified-target-20261029a`. Existing unrelated warnings about unused imports/helpers and `unused_mut` remain.
- Windows Firewall profiles are enabled; no inbound rule for TCP 49341 was found, and no local Windows NAT mapping was found. Outbound public-IPv4 detection worked, but inbound Internet reachability remains unverified. RPC/transaction ingress remain loopback-only. No remote peer address or Noise static-key pin is presently configured, so this remains a candidate and must not be advertised as public Mainnet.

The earlier one-node process that reported `mainnet=true` without a seed was stopped after verification, because that status contradicted the launch criteria. Its data directory was retained and the same persistent store was reopened in candidate mode. The legacy executable that repeatedly launched this unpinned mode was preserved, not deleted, under `C:\QRun\qrun-verification-target\release\qrun_v05_pow_local_node.legacy-unverified-mainnet-disabled` (renamed away from the `.exe` extension to prevent accidental relaunch). The running candidate uses the latest verified binary at `C:\QRun\qrun-mainnet-verified-target-20261029a\release\qrun_v05_pow_local_node.exe`.
