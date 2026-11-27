[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$PackageDirectory,
    [Parameter(Mandatory=$true)][ValidateSet('seed','joining')][string]$Role,
    [string]$RotationRootDirectory,
    [string]$ProvisionerExecutablePath,
    [string]$CargoManifestPath
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Get-Sha256Bytes([byte[]]$Bytes) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash($Bytes))).Replace('-','').ToLowerInvariant() }
    finally { $sha.Dispose() }
}
function Get-Sha256File([string]$Path) {
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}
function Convert-HexToBytes([string]$Hex, [string]$Label) {
    if ([string]::IsNullOrWhiteSpace($Hex) -or $Hex -notmatch '^[0-9a-fA-F]{64}$') {
        throw "$Label must be exactly 32 bytes of hexadecimal."
    }
    $bytes = New-Object byte[] 32
    for ($i=0; $i -lt 32; $i++) { $bytes[$i] = [Convert]::ToByte($Hex.Substring($i * 2, 2), 16) }
    return ,$bytes
}
function ConvertTo-Utf8JsonBytes($Object) {
    $json = ConvertTo-Json -InputObject $Object -Depth 40
    $encoding = New-Object System.Text.UTF8Encoding($false)
    return $encoding.GetBytes($json + [Environment]::NewLine)
}
function Write-NewFile([string]$Path, [byte[]]$Bytes) {
    $stream = [IO.File]::Open($Path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try { $stream.Write($Bytes, 0, $Bytes.Length); $stream.Flush($true) }
    finally { $stream.Dispose() }
}
function Set-JsonProperty($Object, [string]$Name, $Value) {
    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property) { $Object | Add-Member -MemberType NoteProperty -Name $Name -Value $Value }
    else { $property.Value = $Value }
}
function Get-JsonProperty($Object, [string]$Name, $Default = $null) {
    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property) { return $Default }
    return $property.Value
}
function Assert-NoReparseInExistingAncestors([string]$Path, [string]$Label) {
    $full = [IO.Path]::GetFullPath($Path)
    $cursor = $full
    while (-not [string]::IsNullOrWhiteSpace($cursor)) {
        if (Test-Path -LiteralPath $cursor) {
            $item = Get-Item -LiteralPath $cursor -Force -ErrorAction Stop
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "$Label traverses a reparse point: $cursor"
            }
        }
        $parent = [IO.Path]::GetDirectoryName($cursor)
        if ([string]::IsNullOrWhiteSpace($parent) -or $parent -ieq $cursor) { break }
        $cursor = $parent
    }
}
function Assert-RegularFile([string]$Path, [string]$Label) {
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if ($item.PSIsContainer -or (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
        throw "$Label must be a regular non-reparse file."
    }
}
function Read-Json([string]$Path, [string]$Label) {
    Assert-RegularFile $Path $Label
    try { return (Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json) }
    catch { throw "$Label is not valid JSON: $($_.Exception.Message)" }
}
function Invoke-NoiseKeyProvisioner([string]$Executable, [string]$OutputPath, [string]$NetworkIdHex) {
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $Executable
    $psi.Arguments = '--output "' + $OutputPath + '" --network-id-hex ' + $NetworkIdHex
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $psi
    if (-not $process.Start()) { throw 'Noise key provisioner could not be started.' }
    $stdout = $process.StandardOutput.ReadToEnd()
    $stderr = $process.StandardError.ReadToEnd()
    $process.WaitForExit()
    if ($process.ExitCode -ne 0) {
        throw "Noise key provisioner failed with exit code $($process.ExitCode): $stderr"
    }
    if ($stderr -match '(?i)error|panic') { throw "Noise key provisioner emitted an error: $stderr" }

    $publicMatches = [regex]::Matches($stdout, '(?m)^noise_static_public_key_hex=([0-9a-fA-F]{64})\s*$')
    $networkMatches = [regex]::Matches($stdout, '(?m)^network_id_hex=([0-9a-fA-F]{64})\s*$')
    $protectionMatches = [regex]::Matches($stdout, '(?m)^protection=(\S+)\s*$')
    if ($publicMatches.Count -ne 1 -or $networkMatches.Count -ne 1 -or $protectionMatches.Count -ne 1) {
        throw 'Provisioner output did not contain exactly one public key, network ID, and protection provider.'
    }
    if ($networkMatches[0].Groups[1].Value.ToLowerInvariant() -ne $NetworkIdHex.ToLowerInvariant()) {
        throw 'Provisioner output network ID differs from the requested network.'
    }
    if ($protectionMatches[0].Groups[1].Value -ne 'Windows_CurrentUser_DPAPI_NPK1') {
        throw 'This prepare-only tool currently requires Windows CurrentUser DPAPI NPK1 custody.'
    }
    Assert-RegularFile $OutputPath 'New protected Noise key'
    return [pscustomobject]@{
        PublicKeyHex = $publicMatches[0].Groups[1].Value.ToLowerInvariant()
        Protection = $protectionMatches[0].Groups[1].Value
        ProtectedFileSha256 = Get-Sha256File $OutputPath
    }
}
function Get-NextGeneration([string]$RoleRoot) {
    $max = 0
    if (Test-Path -LiteralPath $RoleRoot -PathType Container) {
        foreach ($directory in Get-ChildItem -LiteralPath $RoleRoot -Directory -Force) {
            if ($directory.Name -match '^generation-(\d{6})$') {
                $value = [int]$Matches[1]
                if ($value -gt $max) { $max = $value }
            }
            elseif ($directory.Name -like 'generation-*') {
                throw "Unrecognized generation directory blocks safe sequence selection: $($directory.FullName)"
            }
        }
    }
    if ($max -ge 999999) { throw 'Identity rotation generation limit reached.' }
    return ($max + 1)
}

if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
    throw 'This version prepares Windows CurrentUser DPAPI identities only.'
}
if ([string]::IsNullOrWhiteSpace($PackageDirectory) -or -not [IO.Path]::IsPathRooted($PackageDirectory)) {
    throw 'PackageDirectory must be an absolute path.'
}
$package = (Resolve-Path -LiteralPath $PackageDirectory -ErrorAction Stop).Path
$packageItem = Get-Item -LiteralPath $package -Force
if (-not $packageItem.PSIsContainer -or (($packageItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
    throw 'PackageDirectory must be a real non-reparse directory.'
}
Assert-NoReparseInExistingAncestors $package 'PackageDirectory'

if ([string]::IsNullOrWhiteSpace($RotationRootDirectory)) {
    $RotationRootDirectory = Join-Path $package 'identity-rotation-staging'
}
if (-not [IO.Path]::IsPathRooted($RotationRootDirectory)) { throw 'RotationRootDirectory must be absolute.' }
$rotationRoot = [IO.Path]::GetFullPath($RotationRootDirectory)
$packagePrefix = $package.TrimEnd('\') + '\'
if (-not $rotationRoot.StartsWith($packagePrefix, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'RotationRootDirectory must be a child of PackageDirectory to preserve package-relative paths.'
}
Assert-NoReparseInExistingAncestors $rotationRoot 'RotationRootDirectory'

$identityName = if ($Role -eq 'seed') { 'seed-noise-identity.json' } else { 'joining-noise-identity.json' }
$identityPath = Join-Path $package $identityName
$identity = Read-Json $identityPath 'Active public identity'
$identityBytes = [IO.File]::ReadAllBytes($identityPath)
$previousIdentityHash = Get-Sha256Bytes $identityBytes
$expectedSchema = if ($Role -eq 'seed') { 'qfp6-public-testnet-seed-noise-identity/v1' } else { 'qfp6-public-testnet-node-noise-identity/v1' }
if ($identity.schema -ne $expectedSchema -or $identity.role -ne $Role) {
    throw "Active identity schema/role mismatch; expected $expectedSchema."
}
$networkField = if ($Role -eq 'seed') { [string]$identity.network_id_hex } else { [string]$identity.network_id }
$profileField = [string](Get-JsonProperty $identity 'profile_id_hex' '')
if ([string]::IsNullOrWhiteSpace($profileField) -and $Role -eq 'joining') { $profileField = [string](Get-JsonProperty $identity 'profile_id' '') }
$networkBytes = Convert-HexToBytes $networkField 'Active network ID'
$null = Convert-HexToBytes $profileField 'Active profile ID'
$networkHex = $networkField.ToLowerInvariant()

$oldPublicHex = if ($Role -eq 'seed') { [string]$identity.noise_static_public_key_hex } else { [string]$identity.public_static_key }
$oldPublicBytes = Convert-HexToBytes $oldPublicHex 'Active public Noise key'
$oldFingerprint = Get-Sha256Bytes $oldPublicBytes
$storedFingerprint = if ($Role -eq 'seed') { [string]$identity.noise_static_public_key_sha256 } else { [string]$identity.public_static_key_sha256_fingerprint }
if ($oldFingerprint -ne $storedFingerprint.ToLowerInvariant()) { throw 'Active identity public-key fingerprint is inconsistent.' }

$sourceKeyPath = $null
$sourceKeyHash = $null
$sourceConfigPath = $null
$sourceConfig = $null
if ($Role -eq 'seed') {
    $pinnedConfigHash = ([string]$identity.seed_config_sha256).ToLowerInvariant()
    if ($pinnedConfigHash -notmatch '^[0-9a-f]{64}$') { throw 'Seed identity does not contain a valid pinned config SHA-256.' }
    $matches = @()
    foreach ($candidateName in @('public-testnet-seed-config-ipv6.json','public-testnet-seed-config.json')) {
        $candidate = Join-Path $package $candidateName
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            if ((Get-Sha256File $candidate) -eq $pinnedConfigHash) { $matches += $candidate }
        }
    }
    if ($matches.Count -ne 1) { throw 'Exactly one Seed config must match the active identity config hash.' }
    $sourceConfigPath = $matches[0]
    $sourceConfig = Read-Json $sourceConfigPath 'Pinned Seed runtime config'
    $runtime = $sourceConfig.permissionless_runtime
    if ($null -eq $runtime -or $runtime.node_role -ne 'seed' -or $runtime.mode -ne 'public-testnet-zero-value-candidate') {
        throw 'Pinned Seed runtime config does not have the expected zero-value Seed role.'
    }
    $sourceKeyPath = [string]$runtime.node_noise_private_key_path
    if ([string]::IsNullOrWhiteSpace($sourceKeyPath) -or -not [IO.Path]::IsPathRooted($sourceKeyPath)) {
        throw 'Pinned Seed config must reference an absolute protected-key path.'
    }
}
else {
    $relativeOldKey = [string]$identity.protected_private_key_file
    if ([string]::IsNullOrWhiteSpace($relativeOldKey) -or [IO.Path]::IsPathRooted($relativeOldKey)) {
        throw 'Joining identity must reference its active protected key with a package-relative path.'
    }
    $sourceKeyPath = [IO.Path]::GetFullPath((Join-Path $package $relativeOldKey))
    if (-not $sourceKeyPath.StartsWith($packagePrefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Joining protected-key path escapes PackageDirectory.'
    }
    if ((Get-Sha256File $sourceKeyPath) -ne ([string]$identity.protected_private_key_file_sha256).ToLowerInvariant()) {
        throw 'Joining protected-key file hash differs from the active identity pin.'
    }
    if ($identity.protection -ne 'Windows_CurrentUser_DPAPI_NPK1') {
        throw 'Joining active key is not protected with the expected Windows CurrentUser DPAPI format.'
    }
}
Assert-RegularFile $sourceKeyPath 'Active protected Noise key'
Assert-NoReparseInExistingAncestors $sourceKeyPath 'Active protected Noise key'
$sourceKeyHash = Get-Sha256File $sourceKeyPath

if ([string]::IsNullOrWhiteSpace($ProvisionerExecutablePath)) {
    $releaseCandidate = Join-Path (Split-Path -Parent $PSScriptRoot) 'src\native\pow_bench\target\release\noise_key_provisioner.exe'
    $debugCandidate = Join-Path (Split-Path -Parent $PSScriptRoot) 'src\native\pow_bench\target\debug\noise_key_provisioner.exe'
    if (Test-Path -LiteralPath $releaseCandidate -PathType Leaf) { $ProvisionerExecutablePath = $releaseCandidate }
    elseif (Test-Path -LiteralPath $debugCandidate -PathType Leaf) { $ProvisionerExecutablePath = $debugCandidate }
    else { throw 'noise_key_provisioner.exe is missing; build it with the repository Cargo.lock before preparing a rotation.' }
}
if (-not [IO.Path]::IsPathRooted($ProvisionerExecutablePath)) { throw 'ProvisionerExecutablePath must be absolute.' }
$ProvisionerExecutablePath = (Resolve-Path -LiteralPath $ProvisionerExecutablePath -ErrorAction Stop).Path
Assert-RegularFile $ProvisionerExecutablePath 'Noise key provisioner'

$roleRoot = Join-Path $rotationRoot $Role
if (Test-Path -LiteralPath $roleRoot) { Assert-NoReparseInExistingAncestors $roleRoot 'Role rotation root' }
$generation = Get-NextGeneration $roleRoot
$generationName = 'generation-{0:D6}' -f $generation
$generationDirectory = Join-Path $roleRoot $generationName
if (Test-Path -LiteralPath $generationDirectory) { throw 'Selected rotation generation already exists; refusing overwrite.' }
[void][IO.Directory]::CreateDirectory($generationDirectory)
$createdBundle = $true
$success = $false
try {
    $protectedDirectory = Join-Path $generationDirectory 'protected'
    [void][IO.Directory]::CreateDirectory($protectedDirectory)
    $newKeyPath = Join-Path $protectedDirectory 'noise-static-key.npk'
    $provisioned = Invoke-NoiseKeyProvisioner $ProvisionerExecutablePath $newKeyPath $networkHex
    $newPublicBytes = Convert-HexToBytes $provisioned.PublicKeyHex 'Provisioned public Noise key'
    $newFingerprint = Get-Sha256Bytes $newPublicBytes
    if ($newFingerprint -eq $oldFingerprint) { throw 'Newly generated Noise identity unexpectedly equals the active identity.' }

    $generationRelativePath = $generationDirectory.Substring($packagePrefix.Length)
    $relativeKeyPath = (Join-Path $generationRelativePath 'protected\noise-static-key.npk').Replace('\','/')
    $newIdentity = ConvertFrom-Json (ConvertTo-Json -InputObject $identity -Depth 40)
    $preparedConfigPath = $null
    $preparedConfigHash = $null
    $joiningConfigStatus = 'NOT_PRODUCED_ROLE_PREPARATION_ONLY'

    if ($Role -eq 'seed') {
        Set-JsonProperty $newIdentity 'noise_static_public_key_hex' $provisioned.PublicKeyHex
        Set-JsonProperty $newIdentity 'noise_static_public_key_sha256' $newFingerprint

        $newConfig = ConvertFrom-Json (ConvertTo-Json -InputObject $sourceConfig -Depth 40)
        Set-JsonProperty $newConfig.permissionless_runtime 'node_noise_private_key_path' $newKeyPath
        $configBytes = ConvertTo-Utf8JsonBytes $newConfig
        $preparedConfigHash = Get-Sha256Bytes $configBytes
        Set-JsonProperty $newIdentity 'seed_config_sha256' $preparedConfigHash
        $preparedConfigPath = Join-Path $generationDirectory 'prepared-seed-config.json'
        Write-NewFile $preparedConfigPath $configBytes
        $joiningConfigStatus = 'NOT_APPLICABLE_SEED_ROLE'
    }
    else {
        Set-JsonProperty $newIdentity 'public_static_key' $provisioned.PublicKeyHex
        Set-JsonProperty $newIdentity 'public_static_key_sha256_fingerprint' $newFingerprint
        Set-JsonProperty $newIdentity 'protected_private_key_file' $relativeKeyPath
        Set-JsonProperty $newIdentity 'protected_private_key_file_sha256' $provisioned.ProtectedFileSha256
        Set-JsonProperty $newIdentity 'protection' $provisioned.Protection
        if ($identity.seed_endpoint -eq 'NOT_EMBEDDED_REQUIRES_CURRENT_OUT_OF_BAND_ENDPOINT' -or
            [string]::IsNullOrWhiteSpace([string]$identity.seed_endpoint)) {
            $joiningConfigStatus = 'BLOCKED_MISSING_STABLE_SEED_ENDPOINT_AND_OUT_OF_BAND_VERIFICATION'
        }
        else {
            $joiningConfigStatus = 'NOT_PRODUCED_EXPLICIT_NETWORK_CONFIG_BUILDER_REQUIRED'
        }
    }

    $identityBytesOut = ConvertTo-Utf8JsonBytes $newIdentity
    $identityOutPath = Join-Path $generationDirectory $identityName
    Write-NewFile $identityOutPath $identityBytesOut
    $identityHashOut = Get-Sha256Bytes $identityBytesOut

    $previousIdentityPath = Join-Path $generationDirectory 'previous-identity.json'
    Write-NewFile $previousIdentityPath $identityBytes

    $manifest = [ordered]@{
        schema = 'qfp6-noise-identity-rotation-preparation/v1'
        status = 'PREPARED_NOT_ACTIVATED'
        role = $Role
        generation = $generation
        generation_name = $generationName
        network_id_hex = $networkHex
        profile_id_hex = $profileField.ToLowerInvariant()
        transport = 'Noise_XX_25519_ChaChaPoly_SHA256'
        previous_identity_path = 'previous-identity.json'
        previous_identity_sha256 = $previousIdentityHash
        previous_public_key_sha256_fingerprint = $oldFingerprint
        previous_protected_key_sha256 = $sourceKeyHash
        new_identity_path = $identityName
        new_identity_sha256 = $identityHashOut
        new_public_key_hex = $provisioned.PublicKeyHex
        new_public_key_sha256_fingerprint = $newFingerprint
        new_protected_key_path_package_relative = $relativeKeyPath
        new_protected_key_sha256 = $provisioned.ProtectedFileSha256
        protection = $provisioned.Protection
        prepared_config_path = if ($null -ne $preparedConfigPath) { 'prepared-seed-config.json' } else { $null }
        prepared_config_sha256 = $preparedConfigHash
        source_config_path = if ($null -ne $sourceConfigPath) { [IO.Path]::GetFileName($sourceConfigPath) } else { $null }
        source_config_sha256 = if ($null -ne $sourceConfigPath) { $pinnedConfigHash } else { $null }
        joining_runtime_config_status = $joiningConfigStatus
        seed_endpoint = if ($Role -eq 'joining') { [string]$identity.seed_endpoint } else { $null }
        seed_listen_socket = if ($Role -eq 'seed') { [string]$identity.listen_socket } else { $null }
        new_identity_fingerprint_independently_verified = $false
        activation_authorized = $false
        old_key_retained = $true
        active_identity_modified = $false
        active_protected_key_modified = $false
        bootstrap_peer_file_modified = $false
        node_started = $false
        listener_opened = $false
        mainnet_authorization = 'NOT_GRANTED'
        market_authorization = 'NOT_GRANTED'
        required_before_activation = @(
            'Independent review of the complete versioned bundle and all hashes',
            'Owner authorization for the exact new public-key fingerprint',
            'Out-of-band peer trust-pin update and documented overlap/rollback window',
            'Process restart/reload test using the prepared protected key',
            'Rejection tests for stale pins, wrong network/profile, partial writes, and rollback'
        )
    }
    $manifestBytes = ConvertTo-Utf8JsonBytes $manifest
    Write-NewFile (Join-Path $generationDirectory 'rotation-manifest.json') $manifestBytes

    $manifestHash = Get-Sha256Bytes $manifestBytes
    $success = $true
    Write-Output 'NOISE_IDENTITY_ROTATION=PREPARED_NOT_ACTIVATED'
    Write-Output "role=$Role"
    Write-Output "generation=$generation"
    Write-Output "bundle_directory=$generationDirectory"
    Write-Output "new_identity_sha256=$identityHashOut"
    Write-Output "new_public_key_sha256_fingerprint=$newFingerprint"
    Write-Output "new_protected_key_sha256=$($provisioned.ProtectedFileSha256)"
    Write-Output "rotation_manifest_sha256=$manifestHash"
    if ($null -ne $preparedConfigPath) { Write-Output "prepared_config_sha256=$preparedConfigHash" }
    Write-Output "joining_runtime_config_status=$joiningConfigStatus"
    Write-Output 'active_identity_modified=FALSE'
    Write-Output 'active_protected_key_modified=FALSE'
    Write-Output 'activation_authorized=FALSE'
    Write-Output 'node_started=FALSE'
    Write-Output 'listener_opened=FALSE'
    Write-Output 'mainnet_authorization=NOT_GRANTED'
    Write-Output 'market_authorization=NOT_GRANTED'
}
catch {
    throw
}
finally {
    if (-not $success -and $createdBundle -and (Test-Path -LiteralPath $generationDirectory)) {
        Remove-Item -LiteralPath $generationDirectory -Recurse -Force -ErrorAction SilentlyContinue
    }
}
