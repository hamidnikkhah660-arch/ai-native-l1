[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$Root=Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)

# Parse all shipping PowerShell scripts plus this test.
$scriptFiles=@(Get-ChildItem $Root -Recurse -File -Filter '*.ps1')
foreach($file in $scriptFiles){
 $tokens=$null;$errors=$null
 [void][System.Management.Automation.Language.Parser]::ParseFile($file.FullName,[ref]$tokens,[ref]$errors)
 if($errors.Count -gt 0){throw ("PowerShell parse failure in {0}: {1}" -f $file.FullName,($errors -join '; '))}
}

# Launcher and package verifier must pin the exact same node executable.
$startText=Get-Content (Join-Path $Root 'start-node.ps1') -Raw
$verifyText=Get-Content (Join-Path $Root 'verify-package.ps1') -Raw
$setupText=Get-Content (Join-Path $Root 'setup-node.ps1') -Raw
$binaryVerify=[regex]::Match($verifyText,"'qrun_v06_node\.exe'\s*=\s*'(?<hash>[0-9a-f]{64})'").Groups['hash'].Value
if(!$binaryVerify -or -not $startText.Contains($binaryVerify)){throw "Launcher/package binary hash mismatch."}
if($setupText -match '\[Parameter\(Mandatory\s*=\s*\$true\)\]\s*\[string\]\$PublicEndpoint'){
 throw 'PublicEndpoint must remain optional for outbound-only participants.'
}

# Template default must be a NAT-friendly outbound-only peer.
$template=Get-Content (Join-Path $Root 'node-config.template.json') -Raw|ConvertFrom-Json
$r=$template.permissionless_runtime
if($r.enable_q6pd_peer_discovery -ne $true -or $r.enable_q6pd_peer_pull -ne $true -or
 $r.enable_q6pd_self_announcement -ne $false -or $r.require_device_root_binding -ne $false){
 throw 'Template default is not outbound-only, Q6PD-enabled and TPM-optional.'
}

# Run the actual non-starting launcher validator twice using isolated temporary profile data.
$oldLocalAppData=$env:LOCALAPPDATA
$tempRoot=Join-Path $env:TEMP ('QFP6-CP0848-validation-'+[guid]::NewGuid().ToString('N'))
try{
 $nodeRoot=Join-Path $tempRoot 'AI_NATIVE_L1\QFP6\public-node-31000'
 New-Item -ItemType Directory -Path (Join-Path $nodeRoot 'keys') -Force|Out-Null
 $noisePath=Join-Path $nodeRoot 'keys\test-noise-key.npk'
 [IO.File]::WriteAllBytes($noisePath,[byte[]]@())
 $env:LOCALAPPDATA=$tempRoot
 $config=Get-Content (Join-Path $Root 'node-config.template.json') -Raw|ConvertFrom-Json
 $c=$config.permissionless_runtime
 $c.mode='public-testnet-zero-value-candidate'
 $c.node_role='joining'
 $c.listen_address='127.0.0.1:31000'
 $c.node_noise_private_key_path=$noisePath
 $c.bootstrap_peers_path='assets\qfp6-public-testnet-bootstrap-peers-v1.json'
 $c.bootstrap_peers_sha256='2305ca15acda495960f1e84f4f3f2a7d5b20e279a58953bbc6328e9b16b15e07'
 $c.enable_q6pd_peer_discovery=$true
 $c.enable_q6pd_peer_pull=$true
 $c.enable_q6pd_self_announcement=$false
 $c.require_device_root_binding=$false
 $c.enable_q6ar_candidate_address_book=$false
 $c.enable_q6ar_candidate_pull=$false
 $c.enable_approved_peer_outbound_sync=$false
 foreach($name in @('device_root_metadata_path','device_root_binding_path','q6pd_identity_key_path','q6pd_identity_binding_path','q6pd_self_advertise_endpoint','q6pd_self_advertise_tls_server_name')){
  if($c.PSObject.Properties[$name]){$c.PSObject.Properties.Remove($name)}
 }
 $nodeConfigPath=Join-Path $nodeRoot 'node-config.json'
 $json=$config|ConvertTo-Json -Depth 16
 [IO.File]::WriteAllText($nodeConfigPath,$json,[Text.UTF8Encoding]::new($false))
 $hash=(Get-FileHash $nodeConfigPath -Algorithm SHA256).Hash.ToLowerInvariant()
 [IO.File]::WriteAllText(($nodeConfigPath+'.sha256'),$hash+[Environment]::NewLine,[Text.UTF8Encoding]::new($false))
 & (Join-Path $Root 'start-node.ps1') -ListenPort 31000 -ValidateOnly

 # Structural relay validation: local placeholder identity files only; no network listener is started.
 foreach($fileName in @('device-root.json','noise-binding.json','q6pd-identity.dpapi','q6pd-identity-binding.json')){
  $filePath=Join-Path $nodeRoot $fileName
  [IO.File]::WriteAllBytes($filePath,[byte[]]@())
 }
 $c.listen_address='0.0.0.0:31000'
 $c.enable_q6pd_self_announcement=$true
 $c.require_device_root_binding=$true
 $c|Add-Member -NotePropertyName 'device_root_metadata_path' -NotePropertyValue (Join-Path $nodeRoot 'device-root.json')
 $c|Add-Member -NotePropertyName 'device_root_binding_path' -NotePropertyValue (Join-Path $nodeRoot 'noise-binding.json')
 $c|Add-Member -NotePropertyName 'q6pd_identity_key_path' -NotePropertyValue (Join-Path $nodeRoot 'q6pd-identity.dpapi')
 $c|Add-Member -NotePropertyName 'q6pd_identity_binding_path' -NotePropertyValue (Join-Path $nodeRoot 'q6pd-identity-binding.json')
 $c|Add-Member -NotePropertyName 'q6pd_self_advertise_endpoint' -NotePropertyValue '8.8.8.8:31000'
 $json=$config|ConvertTo-Json -Depth 16
 [IO.File]::WriteAllText($nodeConfigPath,$json,[Text.UTF8Encoding]::new($false))
 $hash=(Get-FileHash $nodeConfigPath -Algorithm SHA256).Hash.ToLowerInvariant()
 [IO.File]::WriteAllText(($nodeConfigPath+'.sha256'),$hash+[Environment]::NewLine,[Text.UTF8Encoding]::new($false))
 & (Join-Path $Root 'start-node.ps1') -ListenPort 31000 -ValidateOnly
}finally{
 $env:LOCALAPPDATA=$oldLocalAppData
 if(Test-Path $tempRoot){Remove-Item $tempRoot -Recurse -Force}
}
Write-Host 'QFP6_PUBLIC_ALPHA_SCRIPT_PARSE=PASS'
Write-Host 'QFP6_PUBLIC_ALPHA_OUTBOUND_CLIENT_VALIDATION=PASS'
Write-Host 'QFP6_PUBLIC_ALPHA_PUBLIC_RELAY_POLICY_VALIDATION=PASS'
Write-Host 'QFP6_PUBLIC_ALPHA_BINARY_PIN_PARITY=PASS'
