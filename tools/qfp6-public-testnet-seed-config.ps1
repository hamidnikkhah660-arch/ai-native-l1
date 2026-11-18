[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$PackageDirectory,

    [Parameter(Mandatory = $true)]
    [string]$ListenAddress,

    [Parameter(Mandatory = $true)]
    [string]$NoisePrivateKeyPath,

    [Parameter(Mandatory = $true)]
    [string]$OutputConfigPath,

    [switch]$ConfirmPublicExposure
)

$ErrorActionPreference = 'Stop'

function Assert-AbsolutePath([string]$Value, [string]$Label) {
    if ([string]::IsNullOrWhiteSpace($Value) -or -not [IO.Path]::IsPathRooted($Value)) {
        throw "$Label must be an absolute path."
    }
}

function Assert-RealFile([string]$Path, [string]$Label) {
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if ($item.PSIsContainer -or (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
        throw "$Label must be a regular non-reparse file."
    }
}

function Set-JsonProperty($Object, [string]$Name, $Value) {
    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property) {
        $Object | Add-Member -MemberType NoteProperty -Name $Name -Value $Value
    }
    else {
        $property.Value = $Value
    }
}

Assert-AbsolutePath $PackageDirectory 'PackageDirectory'
Assert-AbsolutePath $NoisePrivateKeyPath 'NoisePrivateKeyPath'
Assert-AbsolutePath $OutputConfigPath 'OutputConfigPath'

if (-not $ConfirmPublicExposure) {
    throw 'Refusing to prepare a public-listener config without -ConfirmPublicExposure. This script does not open the firewall or start the node.'
}
if ([string]::IsNullOrWhiteSpace($ListenAddress)) {
    throw 'ListenAddress is required; no default public bind address is assumed.'
}

$package = (Resolve-Path -LiteralPath $PackageDirectory).Path
$packageItem = Get-Item -LiteralPath $package -Force
if (-not $packageItem.PSIsContainer -or (($packageItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
    throw 'PackageDirectory must be a real, non-reparse directory.'
}

$outputFull = [IO.Path]::GetFullPath($OutputConfigPath)
$outputDirectory = [IO.Path]::GetFullPath([IO.Path]::GetDirectoryName($outputFull))
if ($outputDirectory -ine [IO.Path]::GetFullPath($package)) {
    throw 'OutputConfigPath must be inside PackageDirectory so package-relative paths remain stable.'
}
if (Test-Path -LiteralPath $outputFull) {
    throw "Refusing to overwrite existing config: $outputFull"
}

$manifestPath = Join-Path $package 'local-devnet-manifest.json'
$configPath = Join-Path $package 'permissionless-config.json'
$authorizationPath = Join-Path $package 'public-testnet-authorization.q6ga'
$bootstrapPath = Join-Path $package 'bootstrap-peers.json'
foreach ($required in @($manifestPath, $configPath, $authorizationPath, $bootstrapPath,
    (Join-Path $package 'genesis-descriptor.q6gd'),
    (Join-Path $package 'consensus-profile.q6cp'),
    (Join-Path $package 'q6pn-profile.q6pn'),
    (Join-Path $package 'genesis-snapshot.q6sn'))) {
    if (-not (Test-Path -LiteralPath $required -PathType Leaf)) {
        throw "Required package artifact is missing: $required"
    }
}
Assert-RealFile $authorizationPath 'Public Testnet authorization'
Assert-RealFile $bootstrapPath 'Bootstrap peer file'
Assert-RealFile $NoisePrivateKeyPath 'Protected Noise private-key file'

$authorization = [IO.File]::ReadAllBytes($authorizationPath)
$scopeOffset = 8 + (9 * 32) + (8 * 3) + 1
if ($authorization.Length -le ($scopeOffset + 6) -or
    [Text.Encoding]::ASCII.GetString($authorization, 0, 4) -ne 'Q6GA' -or
    $authorization[4] -ne 0 -or $authorization[5] -ne 2 -or
    $authorization[$scopeOffset] -ne 2) {
    throw 'Authorization is not a Q6GA v2 zero-value Public Testnet envelope. The node performs full dual-signature and artifact verification at startup.'
}
for ($i = $scopeOffset + 1; $i -lt $scopeOffset + 7; $i++) {
    if ($authorization[$i] -ne 0) { throw 'Q6GA v2 reserved bytes are not canonical.' }
}
$authorizationHash = (Get-FileHash -LiteralPath $authorizationPath -Algorithm SHA256).Hash.ToLowerInvariant()

$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
if ($manifest.schema -ne 'qfp6-local-only-devnet/v1' -or
    $manifest.scope -ne 'LOCAL_SINGLE_OPERATOR_LOOPBACK_ONLY' -or
    $manifest.public_testnet_authorized -ne $false -or
    $manifest.mainnet_authorized -ne $false -or
    $manifest.genesis_owner_signature_present -ne $true) {
    throw 'Source package must remain the owner-signed local-only candidate; this script will not mutate its manifest.'
}
if ($manifest.genesis_owner_allocation_qzxb -ne '1000000000' -or
    $manifest.gross_supply_ceiling_qzxb -ne '7000000000' -or
    $manifest.block_subsidy_qzxb -ne '0' -or
    $manifest.six_accounting_labels_are_spendable -ne $false) {
    throw 'Source package does not match the fixed CP-0651 zero-subsidy economics.'
}

$bootstrapRaw = Get-Content -LiteralPath $bootstrapPath -Raw
$null = $bootstrapRaw | ConvertFrom-Json
if ($bootstrapRaw.Trim() -notmatch '^\[\s*\]$') {
    throw 'This seed-config builder requires an empty bootstrap peer list. Joining-node configuration is intentionally separate.'
}

$config = Get-Content -LiteralPath $configPath -Raw | ConvertFrom-Json
$runtime = $config.permissionless_runtime
if ($null -eq $runtime -or
    $runtime.mode -ne 'permissionless-full-history-candidate' -or
    $runtime.allow_public_listener -ne $false -or
    [string]::IsNullOrWhiteSpace([string]$runtime.trusted_manifest_anchor)) {
    throw 'Source runtime config is not the expected pinned local candidate profile.'
}

$dataDirectory = Join-Path $package ([string]$runtime.data_directory)
$manifestDirectory = Join-Path $dataDirectory 'manifests'
$segmentDirectory = $dataDirectory + '.checkpoint-segments'
if (-not (Test-Path -LiteralPath $manifestDirectory -PathType Container) -or
    -not (Test-Path -LiteralPath $segmentDirectory -PathType Container)) {
    throw 'Expected canonical Genesis-rooted history plus checkpoint-segment history is not present; refusing to create a fresh public seed config.'
}

if (Get-Process -Name 'qrun_v06_node' -ErrorAction SilentlyContinue) {
    throw 'A QRun node process is already active; refusing to prepare a second writer against the same history.'
}
if (Get-NetTCPConnection -LocalPort 30333 -ErrorAction SilentlyContinue) {
    throw 'TCP 30333 is already bound; refusing to prepare a seed config while the standard P2P port is occupied.'
}

$vaultDirectory = Join-Path $env:LOCALAPPDATA 'AI_NATIVE_L1\QFP6\anchor-vault'
if (-not (Test-Path -LiteralPath (Join-Path $vaultDirectory 'records') -PathType Container)) {
    throw 'The existing independent local anchor Vault is unavailable. This builder will not initialize or replace it.'
}
$vaultVerifier = Join-Path $PSScriptRoot 'qfp6_anchor_vault.py'
if (-not (Test-Path -LiteralPath $vaultVerifier -PathType Leaf)) {
    throw 'qfp6_anchor_vault.py verifier is missing beside this script.'
}
$verifyOutput = & python $vaultVerifier --package-dir $package --vault-dir $vaultDirectory verify 2>&1
if ($LASTEXITCODE -ne 0) {
    $verifyOutput | ForEach-Object { Write-Output $_ }
    throw 'Canonical package / anchor Vault verification failed; no public config was written.'
}
$verifyOutput | ForEach-Object { Write-Output $_ }

Set-JsonProperty $runtime 'mode' 'public-testnet-zero-value-candidate'
Set-JsonProperty $runtime 'allow_candidate_runtime' $true
Set-JsonProperty $runtime 'allow_public_listener' $true
Set-JsonProperty $runtime 'listen_address' $ListenAddress
Set-JsonProperty $runtime 'node_role' 'seed'
Set-JsonProperty $runtime 'public_testnet_acknowledgement' 'ZERO_VALUE_PUBLIC_TESTNET_NO_MAINNET_NO_MARKET'
Set-JsonProperty $runtime 'public_inbound_security_acknowledgement' 'ANONYMOUS_NOISE_XX_UNAUTHENTICATED'
Set-JsonProperty $runtime 'public_testnet_authorization_path' 'public-testnet-authorization.q6ga'
Set-JsonProperty $runtime 'public_testnet_authorization_sha256' $authorizationHash
Set-JsonProperty $runtime 'node_noise_private_key_path' $NoisePrivateKeyPath
Set-JsonProperty $runtime 'trusted_manifest_anchor_vault_path' $vaultDirectory
Set-JsonProperty $runtime 'enable_approved_peer_outbound_sync' $false
Set-JsonProperty $runtime 'enable_q6ar_candidate_address_book' $false
$runtime.PSObject.Properties.Remove('owner_genesis_approval_path')
$runtime.PSObject.Properties.Remove('owner_genesis_approval_sha256')
$config.PSObject.Properties.Remove('local_only_notice')
$config | Add-Member -MemberType NoteProperty -Name 'public_testnet_notice' -Value 'ZERO_VALUE_PUBLIC_TESTNET_CANDIDATE_ONLY_NOT_MAINNET' -Force

$json = $config | ConvertTo-Json -Depth 40
$bytes = [Text.UTF8Encoding]::new($false).GetBytes($json + [Environment]::NewLine)
$stream = [IO.File]::Open($outputFull, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
try {
    $stream.Write($bytes, 0, $bytes.Length)
    $stream.Flush($true)
}
finally {
    $stream.Dispose()
}
$configHash = (Get-FileHash -LiteralPath $outputFull -Algorithm SHA256).Hash.ToLowerInvariant()

Write-Output 'PUBLIC_TESTNET_SEED_CONFIG=CREATED'
Write-Output "config_path=$outputFull"
Write-Output "config_sha256=$configHash"
Write-Output "listen_address=$ListenAddress"
Write-Output 'node_role=seed'
Write-Output 'bootstrap_peer_count=0'
Write-Output 'history_source=existing canonical local Genesis-rooted history and witnessed checkpoint segment'
Write-Output 'mainnet_authorization=NOT_GRANTED'
Write-Output 'market_authorization=NOT_GRANTED'
Write-Output 'firewall_or_router_changes=NONE'
Write-Output 'node_started=FALSE'
Write-Output 'next_command=qrun_v06_node --public-testnet-run --config <config_path> --config-sha256 <config_sha256>'
