[CmdletBinding()]
param(
 [Parameter(Mandatory=$true)][string]$ManifestPath,
 [Parameter(Mandatory=$true)][string]$AuthorizationPath,
 [Parameter(Mandatory=$true)][string]$SignaturePath,
 [Parameter(Mandatory=$true)][string]$AuthorityPublicKeyPath,
 [Parameter(Mandatory=$true)][string]$AuthorityFingerprintSha256,
 [Parameter(Mandatory=$true)][string]$SeedEndpoint,
 [Parameter(Mandatory=$true)][string]$SeedFingerprintSha256,
 [string]$VerifierExecutablePath
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
function Assert-True([bool]$ok,[string]$message){if(-not $ok){throw "ASSERTION FAILED: $message"}}
function Hash([string]$path){(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()}
function Assert-RegularNoReparse([string]$path,[string]$label,[string]$root){
 $full=[IO.Path]::GetFullPath($path)
 $rootFull=[IO.Path]::GetFullPath($root).TrimEnd('\')+'\'
 Assert-True ($full.StartsWith($rootFull,[StringComparison]::OrdinalIgnoreCase)) "$label escapes the package root."
 $item=Get-Item -LiteralPath $full -Force -ErrorAction Stop
 Assert-True (-not $item.PSIsContainer) "$label is not a regular file."
 $cursor=$full
 while($cursor.StartsWith($rootFull,[StringComparison]::OrdinalIgnoreCase)){
  $ancestor=Get-Item -LiteralPath $cursor -Force -ErrorAction Stop
  Assert-True (($ancestor.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) "$label traverses a reparse point."
  $cursor=Split-Path -Parent $cursor
 }
 return $full
}
function Assert-ExternalRegularNoReparse([string]$path,[string]$label){
 $full=[IO.Path]::GetFullPath($path)
 $item=Get-Item -LiteralPath $full -Force -ErrorAction Stop
 Assert-True (-not $item.PSIsContainer) "$label is not a regular file."
 $cursor=$full
 while(-not [string]::IsNullOrWhiteSpace($cursor)){
  if(Test-Path -LiteralPath $cursor){$ancestor=Get-Item -LiteralPath $cursor -Force -ErrorAction Stop;Assert-True (($ancestor.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) "$label traverses a reparse point."}
  $parent=Split-Path -Parent $cursor
  if([string]::IsNullOrWhiteSpace($parent) -or $parent -eq $cursor){break}
  $cursor=$parent
 }
 return $full
}
function Fingerprint([string]$publicHex){
 Assert-True ($publicHex -match '^[0-9a-f]{64}$') 'Public key must be 32-byte lowercase hex.'
 $bytes=New-Object byte[] 32
 for($i=0;$i -lt 32;$i++){$bytes[$i]=[Convert]::ToByte($publicHex.Substring($i*2,2),16)}
 $sha=[Security.Cryptography.SHA256]::Create()
 try{([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-','').ToLowerInvariant()}finally{$sha.Dispose()}
}
$ManifestPath=(Resolve-Path -LiteralPath $ManifestPath).Path
$generationDir=Split-Path -Parent $ManifestPath
$packageRoot=Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $generationDir))
$manifest=Get-Content -LiteralPath $ManifestPath -Raw|ConvertFrom-Json
Assert-True ($manifest.status -eq 'PREPARED_NOT_ACTIVATED') 'Manifest is not inactive/prepared.'
Assert-True ($manifest.activation_authorized -eq $false -and $manifest.active_identity_modified -eq $false -and $manifest.active_protected_key_modified -eq $false -and $manifest.node_started -eq $false -and $manifest.listener_opened -eq $false) 'Manifest contains unsafe activation/runtime flags.'
$identityPath=Assert-RegularNoReparse (Join-Path $generationDir ([string]$manifest.new_identity_path)) 'Staged identity' $packageRoot
$previousPath=Assert-RegularNoReparse (Join-Path $generationDir ([string]$manifest.previous_identity_path)) 'Previous identity' $packageRoot
$keyPath=Assert-RegularNoReparse (Join-Path $packageRoot ([string]$manifest.new_protected_key_path_package_relative)) 'Staged protected key' $packageRoot
Assert-True ((Hash $identityPath) -eq $manifest.new_identity_sha256) 'Staged identity SHA-256 mismatch.'
Assert-True ((Hash $previousPath) -eq $manifest.previous_identity_sha256) 'Previous identity SHA-256 mismatch.'
Assert-True ((Hash $keyPath) -eq $manifest.new_protected_key_sha256) 'Staged protected-key SHA-256 mismatch.'
$identity=Get-Content -LiteralPath $identityPath -Raw|ConvertFrom-Json
Assert-True ($identity.role -eq $manifest.role) 'Staged identity role mismatch.'
$network=if($manifest.role -eq 'seed'){[string]$identity.network_id_hex}else{[string]$identity.network_id}
$profile=if($identity.profile_id_hex){[string]$identity.profile_id_hex}else{[string]$identity.profile_id}
Assert-True ($network -eq $manifest.network_id_hex -and $profile -eq $manifest.profile_id_hex) 'Staged identity network/profile mismatch.'
$publicHex=if($manifest.role -eq 'seed'){[string]$identity.noise_static_public_key_hex}else{[string]$identity.public_static_key}
Assert-True ((Fingerprint $publicHex) -eq $manifest.new_public_key_sha256_fingerprint) 'Staged identity public fingerprint mismatch.'
if($manifest.role -eq 'seed'){
 $configPath=Assert-RegularNoReparse (Join-Path $generationDir ([string]$manifest.prepared_config_path)) 'Prepared Seed config' $packageRoot
 Assert-True ((Hash $configPath) -eq $manifest.prepared_config_sha256) 'Prepared Seed config hash mismatch.'
 Assert-True ($identity.seed_config_sha256 -eq $manifest.prepared_config_sha256) 'Seed identity does not bind prepared config.'
 $config=Get-Content -LiteralPath $configPath -Raw|ConvertFrom-Json
 Assert-True ([IO.Path]::GetFullPath([string]$config.permissionless_runtime.node_noise_private_key_path) -eq $keyPath) 'Prepared Seed config points to a different protected key.'
}else{
 Assert-True ($manifest.joining_runtime_config_status -eq 'BLOCKED_MISSING_STABLE_SEED_ENDPOINT_AND_OUT_OF_BAND_VERIFICATION' -or $manifest.joining_runtime_config_status -eq 'NOT_PRODUCED_EXPLICIT_NETWORK_CONFIG_BUILDER_REQUIRED') 'Joining status is invalid.'
 Assert-True (-not $manifest.prepared_config_path) 'Joining rotation bundle must not carry a runtime config.'
}
$AuthorizationPath=(Resolve-Path -LiteralPath $AuthorizationPath).Path
$SignaturePath=(Resolve-Path -LiteralPath $SignaturePath).Path
$AuthorityPublicKeyPath=(Resolve-Path -LiteralPath $AuthorityPublicKeyPath).Path
$AuthorizationPath=Assert-ExternalRegularNoReparse $AuthorizationPath 'Signed authorization'
$SignaturePath=Assert-ExternalRegularNoReparse $SignaturePath 'Detached signature'
$AuthorityPublicKeyPath=Assert-ExternalRegularNoReparse $AuthorityPublicKeyPath 'Owner authority public key'
Assert-True ((Get-Item $SignaturePath).Length -eq 64) 'Detached Ed25519 signature must be 64 raw bytes.'
Assert-True ((Get-Item $AuthorityPublicKeyPath).Length -eq 32) 'Owner authority public key must be 32 raw bytes.'
Assert-True ((Hash $AuthorityPublicKeyPath) -eq $AuthorityFingerprintSha256.ToLowerInvariant()) 'Owner authority public-key fingerprint differs from supplied out-of-band pin.'
if([string]::IsNullOrWhiteSpace($VerifierExecutablePath)){
 $repo=Split-Path -Parent $PSScriptRoot
 $VerifierExecutablePath=Join-Path $repo 'src\native\pow_bench\target\release\noise_identity_rotation_authorization_verify.exe'
}
$VerifierExecutablePath=(Resolve-Path -LiteralPath $VerifierExecutablePath).Path
$psi=New-Object Diagnostics.ProcessStartInfo
$psi.FileName=$VerifierExecutablePath
$psi.Arguments='"'+$ManifestPath+'" "'+$AuthorizationPath+'" "'+$SignaturePath+'" "'+$AuthorityPublicKeyPath+'" '+$AuthorityFingerprintSha256+' "'+$SeedEndpoint+'" '+$SeedFingerprintSha256
$psi.UseShellExecute=$false;$psi.CreateNoWindow=$true;$psi.RedirectStandardOutput=$true;$psi.RedirectStandardError=$true
$p=New-Object Diagnostics.Process;$p.StartInfo=$psi
if(-not $p.Start()){throw 'Could not start signed rotation authorization verifier.'}
$outTask=$p.StandardOutput.ReadToEndAsync();$errTask=$p.StandardError.ReadToEndAsync()
if(-not $p.WaitForExit(30000)){try{$p.Kill()}catch{};throw 'Signed rotation authorization verifier timed out.'}
$out=$outTask.Result;$err=$errTask.Result
if($out){$out.TrimEnd()|Write-Output}
if($err){$err.TrimEnd()|Write-Output}
Assert-True ($p.ExitCode -eq 0) 'Signed rotation authorization was rejected.'
Write-Output 'ROTATION_ACTIVATION_PREFLIGHT=PASS'
Write-Output 'ACTIVATION_PERFORMED=FALSE'
