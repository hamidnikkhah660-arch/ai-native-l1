[CmdletBinding()]
param(
    [string]$ProvisionerExecutablePath
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repoRoot = Split-Path -Parent $PSScriptRoot
$script:LastPrepareError = ''
$prepareTool = Join-Path $PSScriptRoot 'qfp6-prepare-noise-identity-rotation.ps1'
if (-not (Test-Path -LiteralPath $prepareTool -PathType Leaf)) {
    throw 'Prepare-only rotation tool is missing.'
}
if ([string]::IsNullOrWhiteSpace($ProvisionerExecutablePath)) {
    $release = Join-Path $repoRoot 'src\native\pow_bench\target\release\noise_key_provisioner.exe'
    $debug = Join-Path $repoRoot 'src\native\pow_bench\target\debug\noise_key_provisioner.exe'
    if (Test-Path -LiteralPath $release -PathType Leaf) { $ProvisionerExecutablePath = $release }
    elseif (Test-Path -LiteralPath $debug -PathType Leaf) { $ProvisionerExecutablePath = $debug }
    else { throw 'noise_key_provisioner.exe not found; build it with the repository Cargo.lock first.' }
}
$ProvisionerExecutablePath = (Resolve-Path -LiteralPath $ProvisionerExecutablePath).Path

function Assert-True([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw "ASSERTION FAILED: $Message" }
}
function Write-Utf8NoBom([string]$Path, [string]$Text) {
    $encoding = New-Object System.Text.UTF8Encoding($false)
    [IO.File]::WriteAllText($Path, $Text, $encoding)
}
function Get-HashBytes([byte[]]$Bytes) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash($Bytes))).Replace('-','').ToLowerInvariant() }
    finally { $sha.Dispose() }
}
function Convert-HexToBytes([string]$Hex) {
    Assert-True ($Hex -match '^[0-9a-fA-F]{64}$') 'Expected a 32-byte hex value.'
    $bytes = New-Object byte[] 32
    for ($i=0; $i -lt 32; $i++) { $bytes[$i] = [Convert]::ToByte($Hex.Substring($i*2,2),16) }
    return ,$bytes
}
function Get-KeyFingerprint([string]$PublicHex) {
    return Get-HashBytes (Convert-HexToBytes $PublicHex)
}
function New-FixtureProtectedKey([string]$Path, [string]$NetworkHex) {
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $ProvisionerExecutablePath
    $psi.Arguments = '--output "' + $Path + '" --network-id-hex ' + $NetworkHex
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $psi
    if (-not $process.Start()) { throw 'Could not start fixture key provisioner.' }
    $stdout = $process.StandardOutput.ReadToEnd()
    $stderr = $process.StandardError.ReadToEnd()
    $process.WaitForExit()
    if ($process.ExitCode -ne 0) { throw "Fixture key provisioning failed: $stderr" }
    $publicMatch = [regex]::Match($stdout, '(?m)^noise_static_public_key_hex=([0-9a-f]{64})\s*$')
    $protectionMatch = [regex]::Match($stdout, '(?m)^protection=(\S+)\s*$')
    Assert-True $publicMatch.Success 'Provisioner did not return one public key.'
    Assert-True ($protectionMatch.Groups[1].Value -eq 'Windows_CurrentUser_DPAPI_NPK1') 'Fixture key did not use CurrentUser DPAPI.'
    return [pscustomobject]@{
        PublicHex = $publicMatch.Groups[1].Value
        Fingerprint = Get-KeyFingerprint $publicMatch.Groups[1].Value
        Protection = $protectionMatch.Groups[1].Value
        FileHash = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
    }
}
function Invoke-Prepare([string]$Package, [string]$Role) {
    try {
        $null = & $prepareTool -PackageDirectory $Package -Role $Role -ProvisionerExecutablePath $ProvisionerExecutablePath
        return $true
    }
    catch {
        $script:LastPrepareError = $_.Exception.Message
        return $false
    }
}
function Read-Json([string]$Path) {
    return (Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json)
}
function Test-Bundle([string]$Package, [string]$Role, [int]$Generation) {
    $generationName = 'generation-{0:D6}' -f $Generation
    $directory = Join-Path (Join-Path (Join-Path $Package 'identity-rotation-staging') $Role) $generationName
    $identityName = if ($Role -eq 'seed') { 'seed-noise-identity.json' } else { 'joining-noise-identity.json' }
    $manifest = Read-Json (Join-Path $directory 'rotation-manifest.json')
    $identity = Read-Json (Join-Path $directory $identityName)
    $identityHash = (Get-FileHash (Join-Path $directory $identityName) -Algorithm SHA256).Hash.ToLowerInvariant()
    $previousHash = (Get-FileHash (Join-Path $directory 'previous-identity.json') -Algorithm SHA256).Hash.ToLowerInvariant()
    $keyPath = Join-Path $Package ([string]$manifest.new_protected_key_path_package_relative)
    $keyHash = (Get-FileHash $keyPath -Algorithm SHA256).Hash.ToLowerInvariant()
    Assert-True ($manifest.status -eq 'PREPARED_NOT_ACTIVATED') "$Role status must remain prepare-only."
    Assert-True ($manifest.generation -eq $Generation) "$Role generation counter mismatch."
    Assert-True ($manifest.activation_authorized -eq $false) "$Role activation must remain disabled."
    Assert-True ($manifest.active_identity_modified -eq $false) "$Role active identity must not be modified."
    Assert-True ($manifest.active_protected_key_modified -eq $false) "$Role active key must not be modified."
    Assert-True ($manifest.node_started -eq $false -and $manifest.listener_opened -eq $false) "$Role must not start a node or listener."
    Assert-True ($identityHash -eq $manifest.new_identity_sha256) "$Role new identity hash mismatch."
    Assert-True ($previousHash -eq $manifest.previous_identity_sha256) "$Role previous identity hash mismatch."
    Assert-True ($keyHash -eq $manifest.new_protected_key_sha256) "$Role new protected-key hash mismatch."
    Assert-True ((Get-KeyFingerprint ([string]$manifest.new_public_key_hex)) -eq $manifest.new_public_key_sha256_fingerprint) "$Role public fingerprint mismatch."
    if ($Role -eq 'seed') {
        $configPath = Join-Path $directory 'prepared-seed-config.json'
        $configHash = (Get-FileHash $configPath -Algorithm SHA256).Hash.ToLowerInvariant()
        $config = Read-Json $configPath
        Assert-True ($configHash -eq $manifest.prepared_config_sha256) 'Prepared Seed config hash mismatch.'
        Assert-True ($identity.seed_config_sha256 -eq $configHash) 'Prepared Seed identity does not bind the prepared config.'
        Assert-True ($config.permissionless_runtime.node_noise_private_key_path -eq $keyPath) 'Prepared Seed config points to another key path.'
    }
    else {
        Assert-True ($manifest.joining_runtime_config_status -eq 'BLOCKED_MISSING_STABLE_SEED_ENDPOINT_AND_OUT_OF_BAND_VERIFICATION') 'Joining endpoint blocker was not preserved.'
        Assert-True ($identity.seed_endpoint -eq 'NOT_EMBEDDED_REQUIRES_CURRENT_OUT_OF_BAND_ENDPOINT') 'Joining Seed endpoint placeholder was unexpectedly changed.'
        Assert-True (-not (Test-Path (Join-Path $directory 'prepared-joining-config.json'))) 'Joining runtime config must not be created without a stable endpoint and out-of-band fingerprint verification.'
    }
    return $true
}

$testRoot = Join-Path $env:TEMP ('ain1-rotation-prepare-test-' + [guid]::NewGuid().ToString('N'))
$seedPackage = Join-Path $testRoot 'seed'
$joiningPackage = Join-Path $testRoot 'joining'
$passed = New-Object System.Collections.Generic.List[string]
try {
    [void][IO.Directory]::CreateDirectory((Join-Path $seedPackage 'protected'))
    [void][IO.Directory]::CreateDirectory((Join-Path $joiningPackage 'protected'))

    $networkHex = '11' * 32
    $profileHex = '22' * 32

    # Build a disposable Seed source identity/config whose protected key is test-only.
    $seedOldKeyPath = Join-Path $seedPackage 'protected\old-seed.npk'
    $seedOld = New-FixtureProtectedKey $seedOldKeyPath $networkHex
    $seedConfig = [ordered]@{
        permissionless_runtime = [ordered]@{
            mode = 'public-testnet-zero-value-candidate'
            node_role = 'seed'
            node_noise_private_key_path = $seedOldKeyPath
            listen_address = '[::]:30333'
            allow_public_listener = $true
            bootstrap_peers_path = 'bootstrap-peers.json'
            bootstrap_peers_sha256 = '00' * 32
        }
        public_testnet_notice = 'ZERO_VALUE_PUBLIC_TESTNET_CANDIDATE_ONLY_NOT_MAINNET'
    }
    $seedConfigPath = Join-Path $seedPackage 'public-testnet-seed-config-ipv6.json'
    Write-Utf8NoBom $seedConfigPath (ConvertTo-Json -InputObject $seedConfig -Depth 20)
    $seedIdentity = [ordered]@{
        schema = 'qfp6-public-testnet-seed-noise-identity/v1'
        network_id_hex = $networkHex
        profile_id_hex = $profileHex
        role = 'seed'
        transport = 'Noise_XX_25519_ChaChaPoly_SHA256'
        listen_socket = '[::]:30333'
        noise_static_public_key_hex = $seedOld.PublicHex
        noise_static_public_key_sha256 = $seedOld.Fingerprint
        q6ga_authorization_sha256 = '33' * 32
        seed_config_sha256 = (Get-FileHash $seedConfigPath -Algorithm SHA256).Hash.ToLowerInvariant()
        identity_authentication = 'OUT_OF_BAND_PIN_REQUIRED'
        self_authenticating = $false
        private_key_material = 'NOT_INCLUDED'
    }
    $seedIdentityPath = Join-Path $seedPackage 'seed-noise-identity.json'
    Write-Utf8NoBom $seedIdentityPath (ConvertTo-Json -InputObject $seedIdentity -Depth 20)
    $seedIdentityBefore = (Get-FileHash $seedIdentityPath -Algorithm SHA256).Hash
    $seedKeyBefore = (Get-FileHash $seedOldKeyPath -Algorithm SHA256).Hash

    Assert-True (Invoke-Prepare $seedPackage 'seed') "Seed generation 1 failed: $script:LastPrepareError"
    Assert-True (Test-Bundle $seedPackage 'seed' 1) 'Seed generation 1 bundle validation failed.'
    Assert-True (Invoke-Prepare $seedPackage 'seed') "Seed generation 2 failed: $script:LastPrepareError"
    Assert-True (Test-Bundle $seedPackage 'seed' 2) 'Seed generation 2 bundle validation failed.'
    Assert-True ((Get-FileHash $seedIdentityPath -Algorithm SHA256).Hash -eq $seedIdentityBefore) 'Seed source identity changed.'
    Assert-True ((Get-FileHash $seedOldKeyPath -Algorithm SHA256).Hash -eq $seedKeyBefore) 'Seed active protected key changed.'
    $passed.Add('Seed prepare-only generations 1 and 2; active identity/key unchanged')

    # Build a separate disposable Joining identity with no Seed endpoint.
    $joiningOldKeyPath = Join-Path $joiningPackage 'protected\old-joining.npk'
    $joiningOld = New-FixtureProtectedKey $joiningOldKeyPath $networkHex
    $joiningIdentity = [ordered]@{
        schema = 'qfp6-public-testnet-node-noise-identity/v1'
        network_id = $networkHex
        profile_id = $profileHex
        role = 'joining'
        transport = 'Noise_XX_25519_ChaChaPoly_SHA256'
        public_static_key = $joiningOld.PublicHex
        public_static_key_sha256_fingerprint = $joiningOld.Fingerprint
        protected_private_key_file = 'protected/old-joining.npk'
        protected_private_key_file_sha256 = $joiningOld.FileHash
        protection = $joiningOld.Protection
        identity_authentication = 'OUT_OF_BAND_PIN_REQUIRED'
        self_authenticating = $false
        seed_identity_file = 'seed-noise-identity.json'
        seed_public_key_fingerprint = $seedOld.Fingerprint
        seed_endpoint = 'NOT_EMBEDDED_REQUIRES_CURRENT_OUT_OF_BAND_ENDPOINT'
        private_key_material = 'NEVER_EXPORT_OR_PRINT'
    }
    $joiningIdentityPath = Join-Path $joiningPackage 'joining-noise-identity.json'
    Write-Utf8NoBom $joiningIdentityPath (ConvertTo-Json -InputObject $joiningIdentity -Depth 20)
    $joiningIdentityBefore = (Get-FileHash $joiningIdentityPath -Algorithm SHA256).Hash
    $joiningKeyBefore = (Get-FileHash $joiningOldKeyPath -Algorithm SHA256).Hash

    Assert-True (Invoke-Prepare $joiningPackage 'joining') "Joining generation 1 failed: $script:LastPrepareError"
    Assert-True (Test-Bundle $joiningPackage 'joining' 1) 'Joining generation 1 bundle validation failed.'
    Assert-True (Invoke-Prepare $joiningPackage 'joining') "Joining generation 2 failed: $script:LastPrepareError"
    Assert-True (Test-Bundle $joiningPackage 'joining' 2) 'Joining generation 2 bundle validation failed.'
    Assert-True ((Get-FileHash $joiningIdentityPath -Algorithm SHA256).Hash -eq $joiningIdentityBefore) 'Joining source identity changed.'
    Assert-True ((Get-FileHash $joiningOldKeyPath -Algorithm SHA256).Hash -eq $joiningKeyBefore) 'Joining active protected key changed.'
    $passed.Add('Joining prepare-only generations 1 and 2; endpoint blocker retained; no runtime config')

    # Negative test: mismatched active-key hash must fail before a third generation is created.
    $joiningIdentity.protected_private_key_file_sha256 = 'ff' * 32
    Write-Utf8NoBom $joiningIdentityPath (ConvertTo-Json -InputObject $joiningIdentity -Depth 20)
    $script:LastPrepareError = ''
    $negativeRejected = -not (Invoke-Prepare $joiningPackage 'joining')
    Assert-True $negativeRejected 'Mismatched Joining key hash was not rejected.'
    $generation3 = Join-Path (Join-Path (Join-Path $joiningPackage 'identity-rotation-staging') 'joining') 'generation-000003'
    Assert-True (-not (Test-Path $generation3)) 'Negative test left a partial generation directory.'
    $passed.Add('Negative mismatched-key-hash rejection; no partial generation')

    Write-Output 'IDENTITY_ROTATION_PREPARATION_TESTS=PASS'
    Write-Output "PASSED_CASES=$($passed.Count)"
    $passed | ForEach-Object { Write-Output "PASS: $_" }
}
finally {
    if (Test-Path -LiteralPath $testRoot) {
        Remove-Item -LiteralPath $testRoot -Recurse -Force
    }
}
