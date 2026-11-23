param([switch]$VerifyOnly)

Set-StrictMode -Version 2
$ErrorActionPreference = 'Stop'

$networkIdHex = '633b5dfc16fb2ec1825baf924ae7f7f16bf2006f8b64441a57692a3531722712'
$profileIdHex = 'a0a057d72c11253386bfe90d428bccbc44ebc86fc84e04e3682193a99d8805c4'
$keyName = 'QFP6_DEVICE_ROOT_V1'
$provider = [System.Security.Cryptography.CngProvider]::new('Microsoft Platform Crypto Provider')
$rootDir = Join-Path $env:LOCALAPPDATA 'AI_NATIVE_L1\QFP6\device-identity'
$metadataPath = Join-Path $rootDir 'device-root.json'

function Convert-HexToBytes([string]$Hex) {
    if (($Hex.Length % 2) -ne 0 -or $Hex -notmatch '^[0-9a-fA-F]+$') { throw 'Invalid hexadecimal value.' }
    $bytes = New-Object byte[] ($Hex.Length / 2)
    for ($i = 0; $i -lt $bytes.Length; $i++) {
        $bytes[$i] = [Convert]::ToByte($Hex.Substring($i * 2, 2), 16)
    }
    return ,$bytes
}

function Convert-BytesToHex([byte[]]$Bytes) {
    return ([BitConverter]::ToString($Bytes)).Replace('-', '').ToLowerInvariant()
}

if (!$env:LOCALAPPDATA) { throw 'LOCALAPPDATA is unavailable; refusing to create a key in an unknown location.' }

$metadataExists = Test-Path -LiteralPath $metadataPath -PathType Leaf
$keyExists = [System.Security.Cryptography.CngKey]::Exists($keyName, $provider)

if ($metadataExists -and !$keyExists) {
    throw 'Device-root metadata exists but the TPM key is missing. Refusing to create a replacement identity silently.'
}
if (!$keyExists -and $VerifyOnly) {
    throw 'The persistent TPM device-root key has not been provisioned.'
}

New-Item -ItemType Directory -Path $rootDir -Force | Out-Null

$key = $null
$signer = $null
$verifier = $null
$createdNewKey = $false

try {
    if ($keyExists) {
        $key = [System.Security.Cryptography.CngKey]::Open($keyName, $provider)
    }
    else {
        $creation = [System.Security.Cryptography.CngKeyCreationParameters]::new()
        $creation.Provider = $provider
        $creation.ExportPolicy = [System.Security.Cryptography.CngExportPolicies]::None
        $creation.KeyUsage = [System.Security.Cryptography.CngKeyUsages]::Signing
        $key = [System.Security.Cryptography.CngKey]::Create(
            [System.Security.Cryptography.CngAlgorithm]::ECDsaP256,
            $keyName,
            $creation
        )
        $createdNewKey = $true
    }

    if ($key.Provider.Provider -ne 'Microsoft Platform Crypto Provider') {
        throw 'The persistent key is not stored by the Microsoft Platform Crypto Provider.'
    }

    $signer = [System.Security.Cryptography.ECDsaCng]::new($key)
    $public = $signer.ExportParameters($false)
    $x = [byte[]]$public.Q.X
    $y = [byte[]]$public.Q.Y
    if ($x.Length -ne 32 -or $y.Length -ne 32) {
        throw 'Unexpected P-256 public-key coordinate length.'
    }

    $networkBytes = Convert-HexToBytes $networkIdHex
    $profileBytes = Convert-HexToBytes $profileIdHex
    $payload = New-Object 'System.Collections.Generic.List[byte]'
    $payload.AddRange([Text.Encoding]::ASCII.GetBytes('QFP6-DEVICE-ROOT-V1'))
    $payload.Add([byte]0)
    $payload.AddRange($networkBytes)
    $payload.AddRange($profileBytes)
    $payload.AddRange($x)
    $payload.AddRange($y)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { $deviceId = Convert-BytesToHex ($sha.ComputeHash($payload.ToArray())) } finally { $sha.Dispose() }

    try {
        $privateBlob = $key.Export([System.Security.Cryptography.CngKeyBlobFormat]::EccPrivateBlob)
        [Array]::Clear($privateBlob, 0, $privateBlob.Length)
        throw 'The TPM private key unexpectedly allowed export. Refusing this identity.'
    }
    catch {
        if ($_.Exception.Message -like 'The TPM private key unexpectedly allowed export.*') { throw }
        $privateExportBlocked = $true
    }

    if ($metadataExists) {
        $old = Get-Content -LiteralPath $metadataPath -Raw | ConvertFrom-Json
        if ($old.device_id -ne $deviceId -or $old.public_key_x_base64 -ne [Convert]::ToBase64String($x) -or $old.public_key_y_base64 -ne [Convert]::ToBase64String($y)) {
            throw 'The saved public identity does not match the TPM key. Refusing to overwrite metadata.'
        }
    }
    else {
        $record = [ordered]@{
            schema = 'QFP6_DEVICE_ROOT_V1'
            key_name = $keyName
            provider = 'Microsoft Platform Crypto Provider'
            algorithm = 'ECDSA_P256'
            export_policy = 'NONE'
            private_key_exportable = $false
            network_id = $networkIdHex
            profile_id = $profileIdHex
            device_id = $deviceId
            public_key_x_base64 = [Convert]::ToBase64String($x)
            public_key_y_base64 = [Convert]::ToBase64String($y)
            scope = 'LOCAL_ONLY_NOT_PUBLISHED'
            key_scope = 'CURRENT_USER_CNG'
            created_at_utc = [DateTime]::UtcNow.ToString('o')
        }
        $json = $record | ConvertTo-Json -Depth 5
        $tempPath = $metadataPath + '.tmp'
        $utf8 = New-Object System.Text.UTF8Encoding($true)
        [System.IO.File]::WriteAllText($tempPath, $json, $utf8)
        Move-Item -LiteralPath $tempPath -Destination $metadataPath
    }
}
finally {
    if ($verifier) { $verifier.Dispose() }
    if ($signer) { $signer.Dispose() }
    if ($key) { $key.Dispose() }
}

# Re-open the persistent TPM key and prove it is usable without reading any private-key bytes.
$reopened = $null
$signer2 = $null
$verifier2 = $null
try {
    $reopened = [System.Security.Cryptography.CngKey]::Open($keyName, $provider)
    $signer2 = [System.Security.Cryptography.ECDsaCng]::new($reopened)
    $challenge = New-Object byte[] 32
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($challenge) } finally { $rng.Dispose() }
    $signature = $signer2.SignData($challenge, [System.Security.Cryptography.HashAlgorithmName]::SHA256)
    $pubParams = $signer2.ExportParameters($false)
    $verifier2 = [System.Security.Cryptography.ECDsa]::Create()
    $verifier2.ImportParameters($pubParams)
    if (!$verifier2.VerifyData($challenge, $signature, [System.Security.Cryptography.HashAlgorithmName]::SHA256)) {
        throw 'Persistent TPM device-root signature verification failed.'
    }
}
finally {
    if ($verifier2) { $verifier2.Dispose() }
    if ($signer2) { $signer2.Dispose() }
    if ($reopened) { $reopened.Dispose() }
}

Write-Output 'DEVICE_ROOT_PROVIDER=Microsoft Platform Crypto Provider'
Write-Output 'DEVICE_ROOT_ALGORITHM=ECDSA_P256'
Write-Output 'DEVICE_ROOT_PRIVATE_EXPORT=BLOCKED'
Write-Output 'DEVICE_ROOT_PERSISTENT_REOPEN=PASS'
Write-Output ('DEVICE_ROOT_CREATED_THIS_RUN=' + $createdNewKey)
Write-Output ('DEVICE_ROOT_ID=' + $deviceId)
Write-Output ('DEVICE_ROOT_METADATA=' + $metadataPath)
Write-Output 'DEVICE_ROOT_SCOPE=LOCAL_ONLY_NOT_PUBLISHED'
Write-Output 'NETWORK_ACCESS=NOT_USED'
Write-Output 'NODE_RUNTIME_INTEGRATION=NOT_YET_WIRED'
Write-Output 'RECOVERY_WARNING=TPM_CLEAR_OR_MOTHERBOARD_REPLACEMENT_REQUIRES_EXPLICIT_REENROLLMENT'
