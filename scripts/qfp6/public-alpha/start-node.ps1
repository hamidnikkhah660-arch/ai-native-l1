[CmdletBinding()]
param(
 [ValidateRange(1024,65535)][int]$ListenPort=31000,
 [switch]$ValidateOnly,
 [switch]$Start,
 [switch]$AcknowledgeZeroValuePublicTestnet,
 [switch]$AcknowledgeAnonymousInboundNoiseXX
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$Root=Split-Path -Parent $MyInvocation.MyCommand.Path
$NodeRoot=Join-Path $env:LOCALAPPDATA ("AI_NATIVE_L1\QFP6\public-node-"+$ListenPort)
$Binary=Join-Path $Root 'qrun_v06_node.exe'
$ConfigPath=Join-Path $NodeRoot 'node-config.json'
$HashPath=$ConfigPath+'.sha256'

function Has-NonEmptyConfigValue {
 param([object]$Object,[string]$Name)
 $property=$Object.PSObject.Properties[$Name]
 return ($null -ne $property -and -not [string]::IsNullOrWhiteSpace([string]$property.Value))
}
function Has-ConfigProperty {
 param([object]$Object,[string]$Name)
 return ($null -ne $Object.PSObject.Properties[$Name])
}
if($Start -and $ValidateOnly){throw 'Choose either -ValidateOnly or -Start, not both.'}
if(-not $Start -and -not $ValidateOnly){throw 'Use -ValidateOnly for a non-starting check, or -Start with the required acknowledgement switches.'}
if($Start -and -not $AcknowledgeZeroValuePublicTestnet){throw 'Starting requires -AcknowledgeZeroValuePublicTestnet.'}
& (Join-Path $Root 'verify-package.ps1')
if(-not $?){throw 'Static package verification failed.'}
if(!(Test-Path $Binary -PathType Leaf) -or !(Test-Path $ConfigPath -PathType Leaf) -or !(Test-Path $HashPath -PathType Leaf)){
 throw 'Node binary/config/hash sidecar missing. Run setup-node.ps1 first.'
}
$binaryHash=(Get-FileHash $Binary -Algorithm SHA256).Hash.ToLowerInvariant()
if($binaryHash -ne '519e695aed1a0b68195f841c167c06e4fe23176eb50cd96476a34113233c0470'){
 throw 'CP-0843 node binary SHA-256 mismatch.'
}
$expectedHash=(Get-Content $HashPath -Raw).Trim().ToLowerInvariant()
if($expectedHash -notmatch '^[0-9a-f]{64}$'){throw 'Generated config hash sidecar is malformed.'}
$actualHash=(Get-FileHash $ConfigPath -Algorithm SHA256).Hash.ToLowerInvariant()
if($actualHash -ne $expectedHash){throw 'Generated config changed after setup; refusing to launch.'}

$config=Get-Content $ConfigPath -Raw -Encoding UTF8|ConvertFrom-Json
$r=$config.permissionless_runtime
if($r.mode -cne 'public-testnet-zero-value-candidate' -or $r.node_role -cne 'joining' -or
 $r.enable_q6pd_peer_discovery -ne $true -or $r.enable_q6pd_peer_pull -ne $true){
 throw 'Generated config does not match the reviewed Q6PD joining-node policy.'
}
if($r.enable_q6ar_candidate_address_book -ne $false -or $r.enable_q6ar_candidate_pull -ne $false -or $r.enable_approved_peer_outbound_sync -ne $false){
 throw 'Legacy Q6AR/approved-peer path must remain disabled in this package.'
}
if($r.public_testnet_acknowledgement -cne 'ZERO_VALUE_PUBLIC_TESTNET_NO_MAINNET_NO_MARKET' -or
 $r.public_inbound_security_acknowledgement -cne 'ANONYMOUS_NOISE_XX_UNAUTHENTICATED'){
 throw 'Explicit zero-value/inbound-security acknowledgements are missing from config.'
}
if(-not (Has-NonEmptyConfigValue $r 'node_noise_private_key_path') -or
 -not (Test-Path ([string]$r.node_noise_private_key_path) -PathType Leaf)){
 throw 'The local protected Noise key is missing.'
}
$peerPath=Join-Path $Root $r.bootstrap_peers_path
if(!(Test-Path $peerPath -PathType Leaf)){throw 'Pinned bootstrap peer file is missing.'}
$peerHash=(Get-FileHash $peerPath -Algorithm SHA256).Hash.ToLowerInvariant()
if($peerHash -cne $r.bootstrap_peers_sha256){throw 'Pinned bootstrap peer digest differs from generated config.'}

$isPublicRelay=$r.enable_q6pd_self_announcement -eq $true
if($isPublicRelay){
 if($r.require_device_root_binding -ne $true -or $r.listen_address -cne "0.0.0.0:$ListenPort"){
  throw 'Public relay must use a wildcard listener and require TPM Device Root binding.'
 }
 foreach($name in @('device_root_metadata_path','device_root_binding_path','q6pd_identity_key_path','q6pd_identity_binding_path','q6pd_self_advertise_endpoint')){
  if(-not (Has-NonEmptyConfigValue $r $name)){throw "Public relay config is missing $name."}
  if($name -ne 'q6pd_self_advertise_endpoint' -and
   -not (Test-Path ([string]$r.PSObject.Properties[$name].Value) -PathType Leaf)){
   throw "Public relay identity file is missing: $name."
  }
 }
 if($Start -and -not $AcknowledgeAnonymousInboundNoiseXX){
  throw 'Public relay start requires -AcknowledgeAnonymousInboundNoiseXX because inbound Noise XX is anonymous before Q6PD checks.'
 }
}else{
 if($r.enable_q6pd_self_announcement -ne $false -or $r.require_device_root_binding -ne $false -or
  $r.listen_address -cne "127.0.0.1:$ListenPort"){
  throw 'Outbound-only client must use a loopback-only listener, disable self-announcement and not require TPM binding.'
 }
 foreach($name in @('device_root_metadata_path','device_root_binding_path','q6pd_identity_key_path','q6pd_identity_binding_path','q6pd_self_advertise_endpoint','q6pd_self_advertise_tls_server_name')){
  if(Has-ConfigProperty $r $name){throw "Outbound-only client must not configure $name."}
 }
}

if($ValidateOnly){
 Write-Host 'QFP6_PUBLIC_ALPHA_NODE_CONFIG_VALIDATION=PASS'
 if($isPublicRelay){
  Write-Host 'NODE_ROLE=PUBLIC_RELAY'
  Write-Host 'Q6PD_DISCOVERY_PULL_SELF_ANNOUNCEMENT=ENABLED'
  Write-Host 'LISTENER_SCOPE=PUBLIC_WILDCARD'
  Write-Host 'TPM_DEVICE_ROOT_AND_Q6PD_IDENTITY=REQUIRED'
 }else{
  Write-Host 'NODE_ROLE=OUTBOUND_ONLY_CLIENT'
  Write-Host 'Q6PD_DISCOVERY_PULL=ENABLED'
  Write-Host 'Q6PD_SELF_ANNOUNCEMENT=DISABLED'
  Write-Host 'LISTENER_SCOPE=LOOPBACK_ONLY'
  Write-Host 'TPM_REQUIREMENT=NONE'
 }
 Write-Host 'AUTO_TRUST=DISABLED'
 Write-Host 'NODE_START=NOT_PERFORMED'
 return
}
if($isPublicRelay){
 Write-Warning 'This public relay accepts inbound Noise XX before Q6PD identity verification. Noise XX inbound is anonymous and is not mutual authentication.'
}else{
 Write-Host 'OUTBOUND_ONLY_CLIENT: listener is bound to loopback; no inbound Internet listener or public self-announcement is enabled.'
}
Write-Warning 'No Windows Firewall, router, NAT, port-forward, tunnel, or service rule is created by this script.'
Write-Host 'Starting ZERO-VALUE PUBLIC TESTNET candidate only. Mainnet/market activity is not authorized.'
& $Binary --public-testnet-run --config $ConfigPath --config-sha256 $expectedHash
exit $LASTEXITCODE