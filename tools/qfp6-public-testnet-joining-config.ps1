[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$PackageDirectory,
    [Parameter(Mandatory=$true)][string]$SeedEndpoint,
    [Parameter(Mandatory=$true)][string]$VerifiedSeedFingerprint,
    [Parameter(Mandatory=$true)][string]$ListenAddress,
    [string]$JoiningNoisePrivateKeyPath,
    [string]$AnchorVaultDirectory,
    [string]$OutputConfigPath,
    [string]$OutputBootstrapPeersPath,
    [string]$OutputDeploymentRecordPath,
    [switch]$ConfirmSeedFingerprintOutOfBand,
    [switch]$ConfirmPublicExposure,
    [switch]$AllowPublicTcpRelay
)
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot 'qfp6-public-seed-endpoint.psm1') -Force -ErrorAction Stop

function Assert-Absolute([string]$Value,[string]$Label){
    if([string]::IsNullOrWhiteSpace($Value) -or -not [IO.Path]::IsPathRooted($Value)){throw "$Label must be an absolute path."}
}
function Assert-File([string]$Path,[string]$Label){
    $i=Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if($i.PSIsContainer -or (($i.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)){throw "$Label must be a regular non-reparse file."}
}
function Assert-NoReparse([string]$Path,[string]$Label){
    $p=[IO.Path]::GetFullPath($Path)
    while(-not [string]::IsNullOrWhiteSpace($p) -and (Test-Path -LiteralPath $p)){
        $i=Get-Item -LiteralPath $p -Force -ErrorAction Stop
        if(($i.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw "$Label traverses a reparse point: $p"}
        $parent=[IO.Path]::GetDirectoryName($p)
        if([string]::IsNullOrWhiteSpace($parent) -or $parent -ieq $p){break}
        $p=$parent
    }
}
function Test-Overlap([string]$A,[string]$B){
    $a=[IO.Path]::GetFullPath($A).TrimEnd('\')
    $b=[IO.Path]::GetFullPath($B).TrimEnd('\')
    return ($a -ieq $b) -or $a.StartsWith(($b+'\'),[StringComparison]::OrdinalIgnoreCase) -or $b.StartsWith(($a+'\'),[StringComparison]::OrdinalIgnoreCase)
}
function Test-PublicIP([Net.IPAddress]$IP){
    if([Net.IPAddress]::IsLoopback($IP) -or $IP.IsIPv6LinkLocal -or $IP.IsIPv6SiteLocal -or $IP.IsIPv6Multicast -or $IP.IsIPv4MappedToIPv6){return $false}
    if($IP.Equals([Net.IPAddress]::Any) -or $IP.Equals([Net.IPAddress]::IPv6Any)){return $false}
    $b=$IP.GetAddressBytes()
    if($IP.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork){
        if($b[0] -eq 0 -or $b[0] -eq 10 -or $b[0] -eq 127 -or $b[0] -ge 224){return $false}
        if($b[0] -eq 100 -and $b[1] -ge 64 -and $b[1] -le 127){return $false}
        if($b[0] -eq 169 -and $b[1] -eq 254){return $false}
        if($b[0] -eq 172 -and $b[1] -ge 16 -and $b[1] -le 31){return $false}
        if($b[0] -eq 192 -and ($b[1] -eq 168 -or $b[1] -eq 0)){return $false}
        if($b[0] -eq 192 -and $b[1] -eq 88 -and $b[2] -eq 99){return $false}
        if($b[0] -eq 192 -and $b[1] -eq 88 -and $b[2] -eq 99){return $false}
        if($b[0] -eq 198 -and ($b[1] -eq 18 -or $b[1] -eq 19 -or $b[1] -eq 51)){return $false}
        if($b[0] -eq 203 -and $b[1] -eq 0 -and $b[2] -eq 113){return $false}
        if($b[0] -ge 240){return $false}
    }else{
        if(($b[0] -band 0xfe) -eq 0xfc -or $b[0] -eq 0xff){return $false}
        if($b[0] -eq 0x00 -and $b[1] -eq 0x64 -and $b[2] -eq 0xff -and $b[3] -eq 0x9b -and $b[4] -eq 0x00 -and $b[5] -eq 0x01){return $false}
        if($b[0] -eq 0x01 -and $b[1] -eq 0x00 -and $b[2] -eq 0 -and $b[3] -eq 0 -and $b[4] -eq 0 -and $b[5] -eq 0 -and $b[6] -eq 0 -and $b[7] -eq 0){return $false}
        if($b[0] -eq 0x20 -and $b[1] -eq 0x01 -and $b[2] -le 1){return $false}
        if($b[0] -eq 0x20 -and $b[1] -eq 0x01 -and $b[2] -eq 0x0d -and $b[3] -eq 0xb8){return $false}
        if($b[0] -eq 0x20 -and $b[1] -eq 0x02){return $false}
        if($b[0] -eq 0x3f -and $b[1] -eq 0xff -and ($b[2] -band 0xf0) -eq 0){return $false}
    }
    return $true
}
function Parse-Endpoint([string]$Value,[string]$Label,[bool]$AllowWildcard){
    $ipText=$null;$portText=$null
    if($Value -match '^\[(?<ip>[0-9A-Fa-f:]+)\]:(?<port>[0-9]{1,5})$'){$ipText=$Matches.ip;$portText=$Matches.port}
    elseif($Value -match '^(?<ip>(?:[0-9]{1,3}\.){3}[0-9]{1,3}):(?<port>[0-9]{1,5})$'){$ipText=$Matches.ip;$portText=$Matches.port}
    else{throw "$Label must be a numeric IPv4:30333 or [IPv6]:30333 SocketAddr; hostnames and placeholders are forbidden."}
    $port=0
    if(-not [int]::TryParse($portText,[ref]$port) -or $port -ne 30333){throw "$Label must use port 30333."}
    $addr=$null
    if(-not [Net.IPAddress]::TryParse($ipText,[ref]$addr)){throw "$Label contains an invalid IP address."}
    $wild=$addr.Equals([Net.IPAddress]::Any) -or $addr.Equals([Net.IPAddress]::IPv6Any)
    if($wild -and -not $AllowWildcard){throw "$Label must identify a specific public Seed IP."}
    if(-not $wild -and -not (Test-PublicIP $addr)){throw "$Label must be globally routable unicast; private, reserved, documentation and special-use ranges are rejected."}
    $ipOut=$addr.ToString().ToLowerInvariant()
    if($addr.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetworkV6){$normal='[{0}]:{1}' -f $ipOut,$port}
    else{$normal='{0}:{1}' -f $ipOut,$port}
    return [pscustomobject]@{Address=$addr;Port=$port;Wildcard=$wild;Normalized=$normal}
}
function Hex32([string]$Hex,[string]$Label){
    if($Hex -notmatch '^[0-9A-Fa-f]{64}$'){throw "$Label must be exactly 32 bytes of hex."}
    $bytes=New-Object byte[] 32
    for($i=0;$i -lt 32;$i++){$bytes[$i]=[Convert]::ToByte($Hex.Substring($i*2,2),16)}
    return ,$bytes
}
function HashBytes([byte[]]$Bytes){
    $s=[Security.Cryptography.SHA256]::Create()
    try{$h=$s.ComputeHash($Bytes)}finally{$s.Dispose()}
    return ([BitConverter]::ToString($h)).Replace('-','').ToLowerInvariant()
}
function HashFile([string]$Path){return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()}
function Set-Prop($Object,[string]$Name,$Value){
    $p=$Object.PSObject.Properties[$Name]
    if($null -eq $p){$Object | Add-Member -MemberType NoteProperty -Name $Name -Value $Value}else{$p.Value=$Value}
}
function DiskNumber([string]$Path,[string]$Label){
    $r=[IO.Path]::GetPathRoot([IO.Path]::GetFullPath($Path))
    if($r.Length -lt 2 -or $r[1] -ne ':'){throw "$Label must be on a local drive-letter volume."}
    $parts=@(Get-Partition -DriveLetter $r.Substring(0,1) -ErrorAction Stop)
    if($parts.Count -ne 1){throw "Unable to resolve one disk for $Label."}
    return [int]$parts[0].DiskNumber
}
function Write-New([string]$Path,[byte[]]$Bytes){
    $f=[IO.File]::Open($Path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try{$f.Write($Bytes,0,$Bytes.Length);$f.Flush($true)}finally{$f.Dispose()}
}

Assert-Absolute $PackageDirectory 'PackageDirectory'
if(-not $ConfirmSeedFingerprintOutOfBand){throw 'Use -ConfirmSeedFingerprintOutOfBand only after separately verifying the Seed fingerprint through a trusted channel.'}
if(-not $ConfirmPublicExposure){throw 'Use -ConfirmPublicExposure only after approving a public Joining listener config. This tool never opens a firewall or starts a node.'}
if($VerifiedSeedFingerprint -notmatch '^[0-9A-Fa-f]{64}$'){throw 'VerifiedSeedFingerprint must be 64 hex characters.'}

$package=(Resolve-Path -LiteralPath $PackageDirectory).Path
$pkg=Get-Item -LiteralPath $package -Force
if(-not $pkg.PSIsContainer -or (($pkg.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)){throw 'PackageDirectory must be a real non-reparse directory.'}
if([string]::IsNullOrWhiteSpace($JoiningNoisePrivateKeyPath)){$JoiningNoisePrivateKeyPath=Join-Path $package 'protected\joining-node-noise-static-key.npk'}
if([string]::IsNullOrWhiteSpace($AnchorVaultDirectory)){
    if([string]::IsNullOrWhiteSpace($env:LOCALAPPDATA)){throw 'LOCALAPPDATA unavailable; supply AnchorVaultDirectory.'}
    $AnchorVaultDirectory=Join-Path $env:LOCALAPPDATA 'AI_NATIVE_L1\QFP6\joining-anchor-vault'
}
if([string]::IsNullOrWhiteSpace($OutputConfigPath)){$OutputConfigPath=Join-Path $package 'permissionless-public-testnet-joining.json'}
if([string]::IsNullOrWhiteSpace($OutputBootstrapPeersPath)){$OutputBootstrapPeersPath=Join-Path $package 'joining-bootstrap-peers.json'}
if([string]::IsNullOrWhiteSpace($OutputDeploymentRecordPath)){$OutputDeploymentRecordPath=Join-Path $package 'joining-deployment-record.json'}
foreach($pair in @(@($JoiningNoisePrivateKeyPath,'JoiningNoisePrivateKeyPath'),@($AnchorVaultDirectory,'AnchorVaultDirectory'),@($OutputConfigPath,'OutputConfigPath'),@($OutputBootstrapPeersPath,'OutputBootstrapPeersPath'),@($OutputDeploymentRecordPath,'OutputDeploymentRecordPath'))){Assert-Absolute ([string]$pair[0]) ([string]$pair[1])}

$seedEp=Resolve-Qfp6PublicSeedEndpoint -Value $SeedEndpoint -AllowPublicTcpRelay:$AllowPublicTcpRelay
$listenEp=Parse-Endpoint $ListenAddress 'ListenAddress' $true
if(-not $listenEp.Wildcard){foreach($seedAddress in $seedEp.ResolvedAddresses){if($listenEp.Address.Equals($seedAddress)){throw 'Joining listen endpoint must not alias the Seed endpoint.'}}}
$seedEndpointMode=if($seedEp.Relay){'PUBLIC_TCP_RELAY_443'}else{'DIRECT_TCP_30333'}

$seedPath=Join-Path $package 'seed-noise-identity.json'
$joinPath=Join-Path $package 'joining-noise-identity.json'
$seedCfgPath=Join-Path $package 'public-testnet-seed-config-ipv6.json'
$q6gaPath=Join-Path $package 'public-testnet-authorization.q6ga'
foreach($p in @($seedPath,$joinPath,$seedCfgPath,$q6gaPath)){if(-not (Test-Path -LiteralPath $p -PathType Leaf)){throw "Required identity/config/auth artifact missing: $p"};Assert-File $p 'Seed/Joining artifact'}

$seed=Get-Content -LiteralPath $seedPath -Raw | ConvertFrom-Json
$joining=Get-Content -LiteralPath $joinPath -Raw | ConvertFrom-Json
$seedCfg=Get-Content -LiteralPath $seedCfgPath -Raw | ConvertFrom-Json
$src=$seedCfg.permissionless_runtime
if($seed.role -ne 'seed' -or $joining.role -ne 'joining'){throw 'Seed/Joining role metadata mismatch.'}
if($seed.transport -ne 'Noise_XX_25519_ChaChaPoly_SHA256' -or $joining.transport -ne $seed.transport){throw 'Unsupported or mismatched Noise XX transport.'}
if($seed.network_id_hex -ne $joining.network_id -or $seed.profile_id_hex -ne $joining.profile_id){throw 'Seed and Joining network/profile identifiers differ.'}
if($src.node_role -ne 'seed' -or $src.mode -ne 'public-testnet-zero-value-candidate' -or $src.allow_public_listener -ne $true){throw 'Source config is not the expected public-testnet Seed config.'}

$seedPub=Hex32 $seed.noise_static_public_key_hex 'Seed public key'
$seedFp=HashBytes $seedPub
if($seedFp -ne $seed.noise_static_public_key_sha256 -or $seedFp -ne $joining.seed_public_key_fingerprint -or $seedFp -ne $VerifiedSeedFingerprint.ToLowerInvariant()){throw 'Out-of-band Seed fingerprint, Seed identity and Joining pin do not match.'}
$joinPub=Hex32 $joining.public_static_key 'Joining public key'
$joinFp=HashBytes $joinPub
if($joinFp -ne $joining.public_static_key_sha256_fingerprint){throw 'Joining public-key fingerprint mismatch.'}
if($joining.protection -ne 'Windows_CurrentUser_DPAPI_NPK1' -or $joining.private_key_material -ne 'NEVER_EXPORT_OR_PRINT'){throw 'Joining DPAPI custody metadata mismatch.'}
if((HashFile $seedCfgPath) -ne $seed.seed_config_sha256){throw 'Seed identity does not pin the current Seed config bytes.'}

$artifacts=@(
    @($src.q6gd_descriptor_path,$src.q6gd_descriptor_sha256,'Q6GD'),
    @($src.q6cp_profile_path,$src.q6cp_profile_sha256,'Q6CP'),
    @($src.q6pn_profile_pin_path,$src.q6pn_profile_pin_sha256,'Q6PN'),
    @($src.genesis_snapshot_path,$src.genesis_snapshot_sha256,'Genesis'),
    @($src.bootstrap_peers_path,$src.bootstrap_peers_sha256,'Seed bootstrap')
)
foreach($a in $artifacts){
    $p=Join-Path $package ([string]$a[0])
    if(-not (Test-Path -LiteralPath $p -PathType Leaf)){throw "$($a[2]) artifact missing."}
    Assert-File $p "$($a[2]) artifact"
    if((HashFile $p) -ne ([string]$a[1]).ToLowerInvariant()){throw "$($a[2]) artifact hash differs from Seed config pin."}
}

Assert-File $q6gaPath 'Q6GA v2 authorization'
$auth=[IO.File]::ReadAllBytes($q6gaPath)
$scopeOffset=8+(9*32)+(8*3)+1
if($auth.Length -le ($scopeOffset+6) -or [Text.Encoding]::ASCII.GetString($auth,0,4) -ne 'Q6GA' -or $auth[4] -ne 0 -or $auth[5] -ne 2 -or $auth[$scopeOffset] -ne 2){throw 'Public authorization is not Q6GA v2 / scope 2.'}
for($i=$scopeOffset+1;$i -lt $scopeOffset+7;$i++){if($auth[$i] -ne 0){throw 'Q6GA v2 reserved bytes are not canonical.'}}
$authHash=HashFile $q6gaPath
if($authHash -ne $src.public_testnet_authorization_sha256){throw 'Q6GA v2 hash differs from Seed config pin.'}
if($src.trusted_manifest_anchor -notmatch '^[0-9A-Fa-f]{64}$'){throw 'Seed config lacks a valid immutable Genesis root anchor.'}

Assert-File $JoiningNoisePrivateKeyPath 'Joining protected DPAPI key'
if((HashFile $JoiningNoisePrivateKeyPath) -ne $joining.protected_private_key_file_sha256){throw 'Joining protected key hash differs from identity pin.'}

$pkgFull=[IO.Path]::GetFullPath($package)
$bootFull=[IO.Path]::GetFullPath($OutputBootstrapPeersPath)
$cfgFull=[IO.Path]::GetFullPath($OutputConfigPath)
$recordFull=[IO.Path]::GetFullPath($OutputDeploymentRecordPath)
foreach($p in @($bootFull,$cfgFull,$recordFull)){
    if(-not $p.StartsWith(($pkgFull.TrimEnd('\')+'\'),[StringComparison]::OrdinalIgnoreCase)){throw "Output must be inside the package: $p"}
    if([IO.Path]::GetDirectoryName($p) -ine $pkgFull){throw "Output files must be directly in PackageDirectory so all package-relative config paths remain unambiguous: $p"}
    if(Test-Path -LiteralPath $p){throw "Refusing to overwrite output: $p"}
    if(-not (Test-Path -LiteralPath ([IO.Path]::GetDirectoryName($p)) -PathType Container)){throw "Output parent directory missing: $p"}
}
if((Test-Overlap $bootFull $cfgFull) -or (Test-Overlap $bootFull $recordFull) -or (Test-Overlap $cfgFull $recordFull)){throw 'Output paths must be pairwise separate.'}

$vaultFull=[IO.Path]::GetFullPath($AnchorVaultDirectory)
if(Test-Path -LiteralPath $vaultFull){throw 'Joining Anchor Vault path already exists; refusing to adopt or overwrite.'}
$vaultParent=[IO.Path]::GetDirectoryName($vaultFull)
if(-not (Test-Path -LiteralPath $vaultParent -PathType Container)){throw 'Joining Anchor Vault parent directory must already exist.'}

$dataRel='runtime/joining/data'
$mempoolRel='runtime/joining/mempool'
$dataFull=[IO.Path]::GetFullPath((Join-Path $package $dataRel))
$mempoolFull=[IO.Path]::GetFullPath((Join-Path $package $mempoolRel))
if((Test-Path $dataFull) -or (Test-Path $mempoolFull)){throw 'Joining data/mempool paths already exist; refusing reuse.'}
if((Test-Overlap $dataFull $mempoolFull) -or (Test-Overlap $vaultFull $dataFull) -or (Test-Overlap $vaultFull $mempoolFull)){throw 'Joining data, mempool and Vault paths must be pairwise separate and non-nested.'}
foreach($pair in @(@($dataFull,'Joining data'),@($mempoolFull,'Joining mempool'),@($vaultFull,'Joining Vault'),@($package,'Package'),@($JoiningNoisePrivateKeyPath,'Protected key'))){Assert-NoReparse ([string]$pair[0]) ([string]$pair[1])}

$dataDisk=DiskNumber $dataFull 'Joining data'
$vaultDisk=DiskNumber $vaultFull 'Joining Anchor Vault'
if($dataDisk -eq $vaultDisk){throw 'Joining data and Anchor Vault must be on different physical disks.'}
if(Get-Process -Name qrun_v06_node -ErrorAction SilentlyContinue){throw 'A QRun node process is active.'}
if(Get-NetTCPConnection -LocalPort 30333 -ErrorAction SilentlyContinue){throw 'TCP 30333 is occupied.'}

$peer=[ordered]@{address=$seedEp.Normalized;noise_static_public_key=$seed.noise_static_public_key_hex.ToLowerInvariant()}
$utf8=New-Object System.Text.UTF8Encoding($false)
$peerJson=ConvertTo-Json -InputObject @($peer) -Depth 8
$peerBytes=$utf8.GetBytes($peerJson+[Environment]::NewLine)
$peerHash=HashBytes $peerBytes

$runtime=$seedCfg.permissionless_runtime
Set-Prop $runtime 'mode' 'public-testnet-zero-value-candidate'
Set-Prop $runtime 'allow_candidate_runtime' $true
Set-Prop $runtime 'allow_public_listener' $true
Set-Prop $runtime 'listen_address' $listenEp.Normalized
Set-Prop $runtime 'node_role' 'joining'
Set-Prop $runtime 'bootstrap_peers_path' ([IO.Path]::GetFileName($bootFull))
Set-Prop $runtime 'bootstrap_peers_sha256' $peerHash
Set-Prop $runtime 'node_noise_private_key_path' ([IO.Path]::GetFullPath($JoiningNoisePrivateKeyPath))
Set-Prop $runtime 'data_directory' $dataRel
Set-Prop $runtime 'mempool_directory' $mempoolRel
Set-Prop $runtime 'trusted_manifest_anchor_vault_path' $vaultFull
Set-Prop $runtime 'public_testnet_acknowledgement' 'ZERO_VALUE_PUBLIC_TESTNET_NO_MAINNET_NO_MARKET'
Set-Prop $runtime 'public_inbound_security_acknowledgement' 'ANONYMOUS_NOISE_XX_UNAUTHENTICATED'
Set-Prop $runtime 'public_testnet_authorization_path' 'public-testnet-authorization.q6ga'
Set-Prop $runtime 'public_testnet_authorization_sha256' $authHash
Set-Prop $runtime 'enable_approved_peer_outbound_sync' $false
Set-Prop $runtime 'enable_q6ar_candidate_address_book' $false
$runtime.PSObject.Properties.Remove('owner_genesis_approval_path')
$runtime.PSObject.Properties.Remove('owner_genesis_approval_sha256')
$config=($seedCfg | ConvertTo-Json -Depth 40 | ConvertFrom-Json)
Set-Prop $config 'public_testnet_notice' 'ZERO_VALUE_PUBLIC_TESTNET_CANDIDATE_ONLY_NOT_MAINNET'
$config.PSObject.Properties.Remove('local_only_notice')
$configJson=ConvertTo-Json -InputObject $config -Depth 40
$configBytes=$utf8.GetBytes($configJson+[Environment]::NewLine)
$configHash=HashBytes $configBytes

$record=[ordered]@{
    schema='qfp6-public-testnet-joining-deployment/v1'
    role='joining'
    network_id=$joining.network_id
    profile_id=$joining.profile_id
    seed_endpoint=$seedEp.Normalized
    seed_endpoint_mode=$seedEndpointMode
    seed_public_key_sha256_fingerprint=$seedFp
    seed_fingerprint_confirmed_out_of_band=$true
    joining_public_key_sha256_fingerprint=$joinFp
    joining_protected_key_sha256=$joining.protected_private_key_file_sha256
    config_path=[IO.Path]::GetFileName($cfgFull)
    config_sha256=$configHash
    bootstrap_peers_path=[IO.Path]::GetFileName($bootFull)
    bootstrap_peers_sha256=$peerHash
    data_directory=$dataRel
    mempool_directory=$mempoolRel
    anchor_vault_path=$vaultFull
    data_disk_number=$dataDisk
    anchor_vault_disk_number=$vaultDisk
    trusted_genesis_root_anchor=$src.trusted_manifest_anchor
    mainnet_authorization='NOT_GRANTED'
    market_authorization='NOT_GRANTED'
    node_started=$false
}
$recordJson=ConvertTo-Json -InputObject $record -Depth 12
$recordBytes=$utf8.GetBytes($recordJson+[Environment]::NewLine)

$created=New-Object System.Collections.Generic.List[string]
try{
    Write-New $bootFull $peerBytes;$created.Add($bootFull)
    Write-New $cfgFull $configBytes;$created.Add($cfgFull)
    Write-New $recordFull $recordBytes;$created.Add($recordFull)
}catch{
    foreach($p in $created){if(Test-Path -LiteralPath $p -PathType Leaf){Remove-Item -LiteralPath $p -Force}}
    throw
}
Write-Output 'PUBLIC_TESTNET_JOINING_CONFIG=CREATED'
Write-Output "config_path=$cfgFull"
Write-Output "config_sha256=$configHash"
Write-Output "bootstrap_peers_path=$bootFull"
Write-Output "bootstrap_peers_sha256=$peerHash"
Write-Output "deployment_record_path=$recordFull"
Write-Output "seed_endpoint=$($seedEp.Normalized)"
Write-Output "seed_endpoint_mode=$seedEndpointMode"
Write-Output "seed_public_key_sha256_fingerprint=$seedFp"
Write-Output "joining_public_key_sha256_fingerprint=$joinFp"
Write-Output "data_disk_number=$dataDisk"
Write-Output "anchor_vault_disk_number=$vaultDisk"
Write-Output 'node_role=joining'
Write-Output 'bootstrap_peer_count=1'
Write-Output 'mainnet_authorization=NOT_GRANTED'
Write-Output 'market_authorization=NOT_GRANTED'
Write-Output 'firewall_or_router_changes=NONE'
Write-Output 'node_started=FALSE'
Write-Output 'joining-noise-identity.json=UNCHANGED'
Write-Output 'next_step=independent operator validates generated config and performs isolated Noise XX, history-sync, restart, rollover and recovery tests; this script never starts a node.'
