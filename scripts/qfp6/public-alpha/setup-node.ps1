[CmdletBinding()]
param(
 [ValidateRange(1024,65535)][int]$ListenPort=31000,
 [string]$PublicEndpoint,
 [string]$TlsServerName,
 [switch]$AcknowledgePubliclyReachableEndpoint,
 [switch]$Resume
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$Root=Split-Path -Parent $MyInvocation.MyCommand.Path
$NetworkId='633b5dfc16fb2ec1825baf924ae7f7f16bf2006f8b64441a57692a3531722712'
$ProfileId='a0a057d72c11253386bfe90d428bccbc44ebc86fc84e04e3682193a99d8805c4'
$NodeRoot=Join-Path $env:LOCALAPPDATA ("AI_NATIVE_L1\QFP6\public-node-"+$ListenPort)
$DeviceRootDir=Join-Path $env:LOCALAPPDATA 'AI_NATIVE_L1\QFP6\device-identity'
$DeviceRootMetadata=Join-Path $DeviceRootDir 'device-root.json'
$NoiseKey=Join-Path (Join-Path $NodeRoot 'keys') ("noise-"+$ListenPort+".npk")
$NoiseBinding=Join-Path (Join-Path $NodeRoot 'bindings') ("noise-binding-"+$ListenPort+".json")
$Q6pdIdentityKey=Join-Path (Join-Path $NodeRoot 'keys') ("q6pd-peer-node-"+$ListenPort+".dpapi")
$Q6pdIdentityBinding=Join-Path (Join-Path $NodeRoot 'bindings') ("q6pd-peer-binding-"+$ListenPort+".json")
$AnchorVault=Join-Path $NodeRoot 'anchor-vault'
$DataDir=Join-Path $NodeRoot 'data'
$CheckpointDir=$DataDir+'.checkpoint-segments'
$MempoolDir=Join-Path $NodeRoot 'mempool'
$Q6pdDir=Join-Path $NodeRoot 'q6pd'
$ConfigPath=Join-Path $NodeRoot 'node-config.json'
$ConfigHashPath=$ConfigPath+'.sha256'
$IsPublicRelay=-not [string]::IsNullOrWhiteSpace($PublicEndpoint)

function Remove-JsonProperty {
 param([object]$Object,[string]$Name)
 if($Object.PSObject.Properties[$Name]){$Object.PSObject.Properties.Remove($Name)}
}
function Get-PublicEndpoint {
 param([string]$Value)
 $ipText=$null;$portText=$null
 if($Value -match '^\[(?<ip>[^\]]+)\]:(?<port>[0-9]{1,5})$'){$ipText=$Matches.ip;$portText=$Matches.port}
 elseif($Value -match '^(?<ip>(?:[0-9]{1,3}\.){3}[0-9]{1,3}):(?<port>[0-9]{1,5})$'){$ipText=$Matches.ip;$portText=$Matches.port}
 else{throw 'PublicEndpoint must be numeric IPv4:port or [IPv6]:port.'}
 $ip=$null
 if(-not [System.Net.IPAddress]::TryParse($ipText,[ref]$ip)){throw 'PublicEndpoint contains an invalid IP address.'}
 $port=[int]$portText
 if($port -lt 1 -or $port -gt 65535){throw 'PublicEndpoint port is outside TCP range.'}
 $bytes=$ip.GetAddressBytes()
 if($ip.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork){
  $a=$bytes[0];$b=$bytes[1];$c=$bytes[2]
  if($ip.Equals([System.Net.IPAddress]::Any) -or [System.Net.IPAddress]::IsLoopback($ip) -or
   $a -eq 0 -or $a -ge 224 -or $a -eq 10 -or ($a -eq 100 -and $b -ge 64 -and $b -le 127) -or
   ($a -eq 169 -and $b -eq 254) -or ($a -eq 172 -and $b -ge 16 -and $b -le 31) -or
   ($a -eq 192 -and $b -eq 168) -or ($a -eq 192 -and $b -eq 0 -and $c -eq 0) -or
   ($a -eq 192 -and $b -eq 0 -and $c -eq 2) -or ($a -eq 192 -and $b -eq 88 -and $c -eq 99) -or
   ($a -eq 198 -and ($b -eq 18 -or $b -eq 19 -or ($b -eq 51 -and $c -eq 100))) -or
   ($a -eq 203 -and $b -eq 0 -and $c -eq 113) -or $ip.Equals([System.Net.IPAddress]::Broadcast)){
   throw 'PublicEndpoint is private, reserved, shared-CGNAT, documentation-only, or non-routable.'
  }
  return [pscustomobject]@{Address=($ip.ToString()+':'+$port);Port=$port}
 }
 if($ip.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6){
  if($ip.IsIPv4MappedToIPv6 -or $ip.IsIPv6LinkLocal -or $ip.IsIPv6SiteLocal -or $ip.IsIPv6Multicast -or
   (($bytes[0] -band 0xE0) -ne 0x20) -or
   ($bytes[0] -eq 0x20 -and $bytes[1] -eq 0x01 -and $bytes[2] -eq 0x0d -and $bytes[3] -eq 0xb8)){
   throw 'PublicEndpoint IPv6 must be globally routable unicast (2000::/3).'
  }
  return [pscustomobject]@{Address=('['+$ip.ToString()+']:'+$port);Port=$port}
 }
 throw 'Unsupported public endpoint address family.'
}
if(-not $env:LOCALAPPDATA){throw 'LOCALAPPDATA is unavailable.'}
if($IsPublicRelay -and -not $AcknowledgePubliclyReachableEndpoint){throw 'Public relay requires -AcknowledgePubliclyReachableEndpoint after external verification.'}
if(-not $IsPublicRelay -and $AcknowledgePubliclyReachableEndpoint){throw 'Do not acknowledge a public endpoint when none was supplied.'}
if(-not $IsPublicRelay -and -not [string]::IsNullOrWhiteSpace($TlsServerName)){throw 'TlsServerName is only valid for a public relay.'}
$endpoint=$null
if($IsPublicRelay){$endpoint=Get-PublicEndpoint -Value $PublicEndpoint}
if($TlsServerName -and ($endpoint.Port -ne 443 -or $TlsServerName -cnotmatch '^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$')){
 throw 'TlsServerName must be a lowercase DNS name and requires public endpoint port 443.'
}
& (Join-Path $Root 'verify-package.ps1')
if(-not $?){throw 'Static package verification failed.'}
& (Join-Path $Root 'preflight-host.ps1') -ListenPort $ListenPort
if(-not $?){throw 'Host preflight failed.'}
if(Test-Path $NodeRoot){if(-not $Resume){throw "Node data folder already exists: $NodeRoot. Use -Resume only to continue an interrupted setup."}}
elseif($Resume){throw '-Resume was supplied but this node data folder does not exist.'}
if(Test-Path $ConfigPath){throw "Node config already exists at $ConfigPath. Refusing to overwrite it."}

New-Item -ItemType Directory -Path $NodeRoot -Force|Out-Null
$requiredDirs=@((Join-Path $NodeRoot 'keys'),$DataDir,$MempoolDir,$Q6pdDir)
if($IsPublicRelay){$requiredDirs+=@((Join-Path $NodeRoot 'bindings'),(Split-Path $DeviceRootMetadata -Parent))}
foreach($dir in $requiredDirs){New-Item -ItemType Directory -Path $dir -Force|Out-Null}
if(-not (Test-Path $AnchorVault)){
 $copy=robocopy (Join-Path $Root 'bootstrap\anchor-vault') $AnchorVault /E /COPY:DAT /DCOPY:T /R:1 /W:1 /NP /NFL /NDL
 if($LASTEXITCODE -ge 8){throw "Bootstrap Anchor Vault copy failed (robocopy=$LASTEXITCODE)."}
}
if(-not (Test-Path $CheckpointDir)){
 $copy=robocopy (Join-Path $Root 'runtime\data.checkpoint-segments') $CheckpointDir /E /COPY:DAT /DCOPY:T /R:1 /W:1 /NP /NFL /NDL
 if($LASTEXITCODE -ge 8){throw "Checkpoint segment copy failed (robocopy=$LASTEXITCODE)."}
}

# Every node has its own local Noise identity. Only publicly reachable relays need a TPM-bound advertised identity.
$NoiseTool=Join-Path $Root 'qrun_v05_noise_key_provision.exe'
if(-not (Test-Path $NoiseKey)){
 & $NoiseTool --network-id-hex $NetworkId --output $NoiseKey
 if($LASTEXITCODE -ne 0){throw 'Local CurrentUser DPAPI Noise-key provisioning failed.'}
}
if($IsPublicRelay){
 & (Join-Path $Root 'Initialize-QFP6-DeviceRoot.ps1')
 if(-not $?){throw 'Local TPM Device Root provisioning/verification failed.'}
 $DeviceBindingTool=Join-Path $Root 'qfp6_device_root_binding.exe'
 if(Test-Path $NoiseBinding){
  & $DeviceBindingTool --mode verify --metadata $DeviceRootMetadata --noise-key $NoiseKey --network-id-hex $NetworkId --profile-id-hex $ProfileId --binding $NoiseBinding
 }else{
  & $DeviceBindingTool --mode create --metadata $DeviceRootMetadata --noise-key $NoiseKey --network-id-hex $NetworkId --profile-id-hex $ProfileId --output $NoiseBinding
 }
 if($LASTEXITCODE -ne 0){throw 'TPM-to-Noise binding failed.'}
 $IdentityTool=Join-Path $Root 'qfp6_q6pd_identity_provision.exe'
 $hasKey=Test-Path $Q6pdIdentityKey;$hasBinding=Test-Path $Q6pdIdentityBinding
 if($hasKey -xor $hasBinding){throw 'Partial Q6PD identity files detected. Refusing silent identity replacement.'}
 if($hasKey){
  & $IdentityTool --mode verify --metadata $DeviceRootMetadata --noise-key $NoiseKey --identity-key $Q6pdIdentityKey --binding $Q6pdIdentityBinding --network-id-hex $NetworkId --profile-id-hex $ProfileId
 }else{
  & $IdentityTool --mode provision --metadata $DeviceRootMetadata --noise-key $NoiseKey --identity-key $Q6pdIdentityKey --binding $Q6pdIdentityBinding --network-id-hex $NetworkId --profile-id-hex $ProfileId
 }
 if($LASTEXITCODE -ne 0){throw 'TPM-bound Q6PD Ed25519 identity provisioning/verification failed.'}
}

$rng=[System.Security.Cryptography.RandomNumberGenerator]::Create()
try{$accountBytes=New-Object byte[] 32;$rng.GetBytes($accountBytes);$account=([BitConverter]::ToString($accountBytes)).Replace('-','').ToLowerInvariant();[Array]::Clear($accountBytes,0,$accountBytes.Length)}
finally{$rng.Dispose()}

$config=Get-Content (Join-Path $Root 'node-config.template.json') -Raw -Encoding UTF8|ConvertFrom-Json
$r=$config.permissionless_runtime
$r.listen_address=if($IsPublicRelay){'0.0.0.0:'+$ListenPort}else{'127.0.0.1:'+$ListenPort}
$r.data_directory=$DataDir
$r.mempool_directory=$MempoolDir
$r.bootstrap_peers_path='assets\qfp6-public-testnet-bootstrap-peers-v1.json'
$r.node_noise_private_key_path=$NoiseKey
$r.producer_account=$account
$r.trusted_manifest_anchor_vault_path=$AnchorVault
$r.q6pd_peer_record_store_path=Join-Path $Q6pdDir 'peer-record-store.json'
$r.enable_q6pd_peer_discovery=$true
$r.enable_q6pd_peer_pull=$true
$r.enable_q6pd_self_announcement=[bool]$IsPublicRelay
$r.require_device_root_binding=[bool]$IsPublicRelay
$r.enable_q6ar_candidate_address_book=$false
$r.enable_q6ar_candidate_pull=$false
$r.enable_approved_peer_outbound_sync=$false
$r.node_role='joining'
if($IsPublicRelay){
 $r.device_root_metadata_path=$DeviceRootMetadata
 $r.device_root_binding_path=$NoiseBinding
 $r.q6pd_identity_key_path=$Q6pdIdentityKey
 $r.q6pd_identity_binding_path=$Q6pdIdentityBinding
 $r.q6pd_self_advertise_endpoint=$endpoint.Address
 if($TlsServerName){$r|Add-Member -NotePropertyName 'q6pd_self_advertise_tls_server_name' -NotePropertyValue $TlsServerName}
 else{Remove-JsonProperty $r 'q6pd_self_advertise_tls_server_name'}
}else{
 foreach($name in @('device_root_metadata_path','device_root_binding_path','q6pd_identity_key_path','q6pd_identity_binding_path','q6pd_self_advertise_endpoint','q6pd_self_advertise_tls_server_name')){Remove-JsonProperty $r $name}
}
$json=$config|ConvertTo-Json -Depth 16
[IO.File]::WriteAllText($ConfigPath,$json,[Text.UTF8Encoding]::new($false))
$configHash=(Get-FileHash $ConfigPath -Algorithm SHA256).Hash.ToLowerInvariant()
[IO.File]::WriteAllText($ConfigHashPath,$configHash+[Environment]::NewLine,[Text.UTF8Encoding]::new($false))
Write-Host 'QFP6_PUBLIC_ALPHA_NODE_SETUP=READY'
Write-Host "Local node data: $NodeRoot"
Write-Host "Node role: $(if($IsPublicRelay){'PUBLIC_RELAY'}else{'OUTBOUND_ONLY_CLIENT'})"
Write-Host "Listen address: $(if($IsPublicRelay){'0.0.0.0'}else{'127.0.0.1'}):$ListenPort"
Write-Host 'Q6PD signed peer discovery and pull: ENABLED.'
if($IsPublicRelay){
 Write-Host "Signed Q6PD public endpoint: $($endpoint.Address)"
 Write-Host "TLS SNI: $(if($TlsServerName){$TlsServerName}else{'none'})"
 Write-Host 'TPM Device Root + TPM-bound Ed25519 Q6PD identity: ENABLED.'
}else{
 Write-Host 'Signed Q6PD self-announcement: DISABLED.'
 Write-Host 'TPM requirement: NONE for outbound-only client; local Noise key uses CurrentUser DPAPI.'
}
Write-Host "Config SHA-256: $configHash"
Write-Host 'Auto-trust remains DISABLED; every dial uses the verified record Noise-key pin.'
Write-Host 'No firewall, router, NAT, tunnel, service or scheduled task was changed.'
Write-Host 'Node is NOT started. Review README.md before using start-node.ps1.'