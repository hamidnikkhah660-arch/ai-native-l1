[CmdletBinding()]
param([switch]$FullIntegrity)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path

$expected = [ordered]@{
    'qrun_v06_node.exe' = '519e695aed1a0b68195f841c167c06e4fe23176eb50cd96476a34113233c0470'
    'qrun_v05_noise_key_provision.exe' = '379b85301a607e0894d57b617d1bfaec156142adc44371ba5f411f6cc2fd57b1'
    'qfp6_device_root_binding.exe' = '739fefa8870f3667062aa24b0ee52540bbc2606ab1b1f56683399cfa8e46ce3b'
    'qfp6_q6pd_identity_provision.exe' = '36d9a709247a5bc64a06c1ea861716c45cc969fb1c6587f2c3401b97f776d58a'
    'Initialize-QFP6-DeviceRoot.ps1' = '197e75bc75ea45f38dcc76a6d4f38a422d31d2b0295eca98d00d450103eef9ea'
    'assets\qfp6-public-testnet-bootstrap-peers-v1.json' = '2305ca15acda495960f1e84f4f3f2a7d5b20e279a58953bbc6328e9b16b15e07'
    'assets\genesis-snapshot.q6sn' = '6961e7517adcb66c04a3c566ec8c5cba398940eb273eabd082b706bb32a4f757'
    'assets\consensus-profile.q6cp' = '0ff4786c2b62228883699c687b34d57a85f3bcddde9a545c95f5515a388c516f'
    'assets\genesis-descriptor.q6gd' = 'e5bbd024511f907d1e9bf3c1d4004d05851cd96c79eebd0f1ce446aee15a1888'
    'assets\q6pn-profile.q6pn' = 'bb3d1e5710827afd8248292f9c19ab250dcdc8e508711597dd049c77a6ec8233'
    'assets\public-testnet-authorization.q6ga' = '72d58ef455d9b6f6ab9a5514f5f0fb40f333d347af288363b3897b5584c2f169'
}
foreach ($relative in $expected.Keys) {
    $path = Join-Path $Root $relative
    if (!(Test-Path -LiteralPath $path -PathType Leaf)) { throw "Required file missing: $relative" }
    $actual = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -ne $expected[$relative]) { throw "SHA-256 mismatch: $relative" }
    Write-Host "PASS $relative"
}

$peersPath = Join-Path $Root 'assets\qfp6-public-testnet-bootstrap-peers-v1.json'
$peers = ConvertFrom-Json -InputObject (Get-Content -LiteralPath $peersPath -Raw -Encoding UTF8)
if (@($peers).Count -ne 1) { throw 'Bootstrap peer list must contain exactly one reviewed Seed.' }
$peer = $peers[0]
$peerAddress = $peer | Select-Object -ExpandProperty address
$peerNoiseKey = $peer | Select-Object -ExpandProperty noise_static_public_key
if ($peerAddress -cne 'heymed.tail2a756d.ts.net:443' -or
    $peerNoiseKey -cne '9899d6d17d1659df8befcca2bf3ebe19ebe106a8c3d9bd0a4f06d141db3af508') {
    throw 'Bootstrap peer identity does not match the reviewed Seed pin.'
}

$manifest = ConvertFrom-Json -InputObject (Get-Content (Join-Path $Root 'assets\qfp6-public-testnet-bootstrap-v1.json') -Raw -Encoding UTF8)
if ($manifest.bootstrap_peers_sha256 -cne $expected['assets\qfp6-public-testnet-bootstrap-peers-v1.json'] -or
    $manifest.noise_static_public_key -cne $peerNoiseKey -or
    $manifest.network_id -cne '633b5dfc16fb2ec1825baf924ae7f7f16bf2006f8b64441a57692a3531722712' -or
    $manifest.profile_id -cne 'a0a057d72c11253386bfe90d428bccbc44ebc86fc84e04e3682193a99d8805c4' -or
    $manifest.dns_seed -cne 'heymed.tail2a756d.ts.net' -or
    $manifest.tls_sni -cne 'heymed.tail2a756d.ts.net' -or
    $manifest.tcp_port -ne 443 -or
    $manifest.seed_count -ne 1 -or
    $manifest.dns_is_transport_only -ne $true -or
    $manifest.noise_key_pin_is_identity_anchor -ne $true) {
    throw 'Bootstrap manifest does not bind the expected Seed/network/profile/transport policy.'
}
if ($manifest.auto_trust -ne $false -or $manifest.mainnet_authorized -ne $false -or $manifest.market_authorized -ne $false) {
    throw 'Bootstrap manifest contains an unsafe authorization flag.'
}

$vaultRecords = Join-Path $Root 'bootstrap\anchor-vault\records'
if (!(Test-Path $vaultRecords -PathType Container)) { throw 'Bootstrap Anchor Vault records directory missing.' }
$count = (Get-ChildItem $vaultRecords -File | Measure-Object).Count
if ($count -ne 20501) { throw "Bootstrap Anchor Vault record count mismatch: $count" }

$checkpointBase = Join-Path $Root 'runtime\data.checkpoint-segments\segment-00000000000000000020\qfp6-base.checkpoint'
if (!(Test-Path $checkpointBase -PathType Leaf)) { throw 'Checkpoint base is missing.' }
$checkpointHash = (Get-FileHash $checkpointBase -Algorithm SHA256).Hash.ToLowerInvariant()
if ($checkpointHash -ne '53440ca17dea342ef5af1adf73539452162fe4c3a452b203b1e4f5eed51ba296') {
    throw 'Checkpoint base hash mismatch.'
}

$privateFiles = @(Get-ChildItem $Root -Recurse -File -ErrorAction Stop | Where-Object {
    $_.Extension -in @('.npk','.dpapi','.pfx','.p12') -or
    $_.Name -in @('device-root.json') -or
    $_.Name -like 'node-config.generated-*.json'
})
if ($privateFiles.Count -gt 0) {
    throw ('Package contains local key/config material: ' + ($privateFiles.Name -join ', '))
}

$sumsPath = Join-Path $Root 'SHA256SUMS.txt'
if (!(Test-Path $sumsPath -PathType Leaf)) { throw 'Package SHA256SUMS.txt is missing.' }
$checksumMap = @{}
foreach ($line in Get-Content -LiteralPath $sumsPath -Encoding UTF8) {
    if ([string]::IsNullOrWhiteSpace($line)) { continue }
    if ($line -notmatch '^(?<hash>[0-9a-f]{64})  (?<relative>.+)$') { throw 'Malformed line in SHA256SUMS.txt.' }
    $relative = $Matches.relative
    if ([IO.Path]::IsPathRooted($relative) -or $relative -match '(^|[\/])\.\.([\/]|$)' -or $relative -eq 'SHA256SUMS.txt') {
        throw "Unsafe or recursive path in SHA256SUMS.txt: $relative"
    }
    if ($checksumMap.ContainsKey($relative)) { throw "Duplicate checksum entry: $relative" }
    $filePath = Join-Path $Root $relative
    if (!(Test-Path -LiteralPath $filePath -PathType Leaf)) { throw "Checksum-listed file is missing: $relative" }
    if ($FullIntegrity) {
        $actualHash = (Get-FileHash -LiteralPath $filePath -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($actualHash -ne $Matches.hash) { throw "Package file SHA-256 mismatch: $relative" }
    }
    $checksumMap[$relative] = $Matches.hash
}
$actualFiles = @(Get-ChildItem -LiteralPath $Root -Recurse -File | Where-Object { $_.FullName -ne $sumsPath })
if ($checksumMap.Count -ne $actualFiles.Count) { throw 'SHA256SUMS.txt does not enumerate every package file exactly once.' }
foreach ($file in $actualFiles) {
    $relative = $file.FullName.Substring($Root.Length + 1)
    if (!$checksumMap.ContainsKey($relative)) { throw "File is not covered by SHA256SUMS.txt: $relative" }
}

Write-Host "PASS Anchor Vault records=$count"
Write-Host 'PASS checkpoint base'
Write-Host 'PASS no node-local key, TPM metadata, generated config or private credential'
Write-Host ("PASS package file coverage=" + $checksumMap.Count)
Write-Host ("FULL_FILE_REHASH=" + $(if ($FullIntegrity) { 'PASS' } else { 'NOT_REQUESTED' }))
Write-Host 'QFP6_PUBLIC_ALPHA_PACKAGE_VERIFY=PASS'
