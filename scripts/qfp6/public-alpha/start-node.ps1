[CmdletBinding()]
param(
    [ValidateRange(1024,65535)]
    [int]$ListenPort = 31000,
    [switch]$ValidateOnly,
    [switch]$Start,
    [switch]$AcknowledgeZeroValuePublicTestnet,
    [switch]$AcknowledgeAnonymousInboundNoiseXX
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$NodeRoot = Join-Path $env:LOCALAPPDATA ("AI_NATIVE_L1\QFP6\public-node-" + $ListenPort)
$Binary = Join-Path $Root 'qrun_v06_node.exe'
$ConfigPath = Join-Path $NodeRoot 'node-config.json'
$HashPath = $ConfigPath + '.sha256'

if ($Start -and $ValidateOnly) { throw 'Choose either -ValidateOnly or -Start, not both.' }
if (-not $Start -and -not $ValidateOnly) { throw 'Use -ValidateOnly for a non-starting check, or -Start with both explicit acknowledgement switches.' }
if ($Start -and (-not $AcknowledgeZeroValuePublicTestnet -or -not $AcknowledgeAnonymousInboundNoiseXX)) {
    throw 'Starting requires -AcknowledgeZeroValuePublicTestnet and -AcknowledgeAnonymousInboundNoiseXX.'
}
& (Join-Path $Root 'verify-package.ps1')
if (-not $?) { throw 'Static package verification failed.' }
if (!(Test-Path $Binary -PathType Leaf) -or !(Test-Path $ConfigPath -PathType Leaf) -or !(Test-Path $HashPath -PathType Leaf)) {
    throw 'Node binary/config/hash sidecar missing. Run setup-node.ps1 first.'
}
$binaryHash = (Get-FileHash $Binary -Algorithm SHA256).Hash.ToLowerInvariant()
if ($binaryHash -ne 'c457ce91773d5b6e5fe5b4f392556f05d4f5a647314ffcb35541cb7c5fcc5e14') {
    throw 'CP-0834 node binary SHA-256 mismatch.'
}
$expectedHash = (Get-Content $HashPath -Raw).Trim().ToLowerInvariant()
if ($expectedHash -notmatch '^[0-9a-f]{64}$') { throw 'Generated config hash sidecar is malformed.' }
$actualHash = (Get-FileHash $ConfigPath -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actualHash -ne $expectedHash) { throw 'Generated config changed after setup; refusing to launch.' }

$config = Get-Content $ConfigPath -Raw -Encoding UTF8 | ConvertFrom-Json
$r = $config.permissionless_runtime
if ($r.mode -cne 'public-testnet-zero-value-candidate' -or
    $r.node_role -cne 'joining' -or
    $r.enable_q6pd_peer_discovery -ne $true -or
    $r.enable_q6pd_peer_pull -ne $true -or
    $r.enable_q6pd_self_announcement -ne $true -or
    $r.require_device_root_binding -ne $true) {
    throw 'Generated config does not match the reviewed Q6PD public-operator policy.'
}
if ($r.enable_q6ar_candidate_address_book -ne $false -or
    $r.enable_q6ar_candidate_pull -ne $false -or
    $r.enable_approved_peer_outbound_sync -ne $false) {
    throw 'Legacy Q6AR/approved-peer path must remain disabled in this package.'
}
if ($r.public_testnet_acknowledgement -cne 'ZERO_VALUE_PUBLIC_TESTNET_NO_MAINNET_NO_MARKET' -or
    $r.public_inbound_security_acknowledgement -cne 'ANONYMOUS_NOISE_XX_UNAUTHENTICATED') {
    throw 'Explicit zero-value/inbound-security acknowledgements are missing from config.'
}
$peerPath = Join-Path $Root $r.bootstrap_peers_path
if (!(Test-Path $peerPath -PathType Leaf)) { throw 'Pinned bootstrap peer file is missing.' }
$peerHash = (Get-FileHash $peerPath -Algorithm SHA256).Hash.ToLowerInvariant()
if ($peerHash -cne $r.bootstrap_peers_sha256) { throw 'Pinned bootstrap peer digest differs from generated config.' }
if ($ValidateOnly) {
    Write-Host 'QFP6_PUBLIC_ALPHA_NODE_CONFIG_VALIDATION=PASS'
    Write-Host 'Q6PD_DISCOVERY_PULL_SELF_ANNOUNCEMENT=ENABLED'
    Write-Host 'TPM_NOISE_AND_Q6PD_IDENTITY_BINDINGS=REQUIRED'
    Write-Host 'NODE_START=NOT_PERFORMED'
    return
}

Write-Warning 'This node accepts inbound Noise XX before Q6PD identity verification. Noise XX inbound is anonymous and is not mutual peer authentication.'
Write-Warning 'No Windows Firewall, router, NAT, port-forward, tunnel, or service rule is created by this script.'
Write-Host 'Starting ZERO-VALUE PUBLIC TESTNET candidate only. Mainnet/market activity is not authorized.'
& $Binary --public-testnet-run --config $ConfigPath --config-sha256 $expectedHash
exit $LASTEXITCODE