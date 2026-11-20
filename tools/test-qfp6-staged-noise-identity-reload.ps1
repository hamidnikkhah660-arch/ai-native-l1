[CmdletBinding()]
param([string]$PackageDirectory,[string]$VerifierExecutablePath)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
if([string]::IsNullOrWhiteSpace($PackageDirectory)){
 $PackageDirectory=Join-Path (Split-Path -Parent $PSScriptRoot) 'release\qfp6-local-single-operator-devnet-2026-11-15'
}
$PackageDirectory=(Resolve-Path -LiteralPath $PackageDirectory).Path
if([string]::IsNullOrWhiteSpace($VerifierExecutablePath)){
 $VerifierExecutablePath=Join-Path (Split-Path -Parent $PSScriptRoot) 'src\native\pow_bench\target\release\noise_identity_reload_verify.exe'
}
$VerifierExecutablePath=(Resolve-Path -LiteralPath $VerifierExecutablePath).Path
function Assert-True([bool]$ok,[string]$message){if(-not $ok){throw "ASSERTION FAILED: $message"}}
function Hash([string]$path){(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()}
function Run-Child([string]$path,[string]$network,[string]$fingerprint){
 $psi=New-Object Diagnostics.ProcessStartInfo
 $psi.FileName=$VerifierExecutablePath
 $psi.Arguments='"'+$path+'" '+$network+' '+$fingerprint
 $psi.UseShellExecute=$false;$psi.CreateNoWindow=$true
 $psi.RedirectStandardOutput=$true;$psi.RedirectStandardError=$true
 $p=New-Object Diagnostics.Process;$p.StartInfo=$psi
 if(-not $p.Start()){throw 'Could not start child verifier'}
 $outTask=$p.StandardOutput.ReadToEndAsync();$errTask=$p.StandardError.ReadToEndAsync()
 if(-not $p.WaitForExit(30000)){try{$p.Kill()}catch{};throw 'Child verifier timeout'}
 [pscustomobject]@{Code=$p.ExitCode;Text=$outTask.Result+$errTask.Result}
}
$stage=Join-Path $PackageDirectory 'identity-rotation-staging'
$seed=Get-Content (Join-Path $stage 'seed\generation-000001\rotation-manifest.json') -Raw|ConvertFrom-Json
$network=[string]$seed.network_id_hex
$temp=Join-Path $env:TEMP ('ain1-reload-'+[guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($temp)
$passed=0
try{
 foreach($role in @('seed','joining')){
  $dir=Join-Path (Join-Path $stage $role) 'generation-000001'
  $m=Get-Content (Join-Path $dir 'rotation-manifest.json') -Raw|ConvertFrom-Json
  $identity=Join-Path $dir $(if($role -eq 'seed'){'seed-noise-identity.json'}else{'joining-noise-identity.json'})
  $key=Join-Path $dir 'protected\noise-static-key.npk'
  Assert-True ($m.status -eq 'PREPARED_NOT_ACTIVATED' -and -not $m.activation_authorized -and -not $m.active_identity_modified -and -not $m.active_protected_key_modified -and -not $m.node_started -and -not $m.listener_opened) "$role activation flags"
  Assert-True ((Hash $identity) -eq $m.new_identity_sha256) "$role identity hash"
  Assert-True ((Hash $key) -eq $m.new_protected_key_sha256) "$role protected key hash"
  Assert-True ((Hash (Join-Path $dir 'previous-identity.json')) -eq $m.previous_identity_sha256) "$role previous identity hash"
  $good=Run-Child $key $network $m.new_public_key_sha256_fingerprint
  Assert-True ($good.Code -eq 0 -and $good.Text -match 'PUBLIC_FINGERPRINT_MATCH=TRUE') "$role fresh process reload: $($good.Text)"
  $passed++;Write-Output "$($role.ToUpperInvariant())_FRESH_PROCESS_RELOAD=PASS"
  $wrongNetwork=('f'+$network.Substring(1))
  $bad=Run-Child $key $wrongNetwork $m.new_public_key_sha256_fingerprint
  Assert-True ($bad.Code -ne 0 -and $bad.Text -match 'NetworkMismatch') "$role wrong network rejection"
  $passed++;Write-Output "$($role.ToUpperInvariant())_WRONG_NETWORK_REJECTION=PASS"
  $wrongPin=('f'+$m.new_public_key_sha256_fingerprint.Substring(1))
  $badPin=Run-Child $key $network $wrongPin
  Assert-True ($badPin.Code -ne 0 -and $badPin.Text -match 'does not match the expected public fingerprint') "$role wrong fingerprint rejection"
  $passed++;Write-Output "$($role.ToUpperInvariant())_WRONG_FINGERPRINT_REJECTION=PASS"
  $corrupt=Join-Path $temp ($role+'.npk')
  [IO.File]::Copy($key,$corrupt,$false)
  $bytes=[IO.File]::ReadAllBytes($corrupt);$bytes[$bytes.Length-1]=$bytes[$bytes.Length-1] -bxor 0x80;[IO.File]::WriteAllBytes($corrupt,$bytes)
  $badBlob=Run-Child $corrupt $network $m.new_public_key_sha256_fingerprint
  Assert-True ($badBlob.Code -ne 0) "$role corrupted envelope rejection"
  $passed++;Write-Output "$($role.ToUpperInvariant())_CORRUPTED_ENVELOPE_REJECTION=PASS"
 }
 Write-Output 'STAGED_IDENTITY_RELOAD_REGRESSION=PASS'
 Write-Output "PASSED_CASES=$passed"
}finally{if(Test-Path $temp){Remove-Item $temp -Recurse -Force}}
