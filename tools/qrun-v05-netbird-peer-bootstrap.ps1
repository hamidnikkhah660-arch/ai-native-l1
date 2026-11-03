[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet("Generate", "Serve", "Enroll", "SelfTest", "RemoveProtectedToken")]
    [string]$Mode,
    [string]$TokenFile,
    [string]$OutputFile,
    [string]$AckFile,
    [string]$BindIp,
    [string]$NodeAIp,
    [string]$NodeBIp,
    [string]$NetworkIdHex,
    [string]$NodeBNoisePublicKeyHex,
    [int]$TimeoutSeconds = 600,
    [switch]$PublishGitHubSecret
)
$ErrorActionPreference = "Stop"
Add-Type -AssemblyName System.Security
$script:Utf8Strict = [System.Text.UTF8Encoding]::new($false, $true)
$script:Entropy = [System.Text.Encoding]::UTF8.GetBytes("QRun-NetBird-Peer-Bootstrap-v1")

function Assert-OverlayIPv4([string]$Name, [string]$Value) {
    $parsed = [System.Net.IPAddress]::Parse($Value)
    if ($parsed.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) {
        throw "$Name must be an IPv4 address."
    }
    $octets = $parsed.GetAddressBytes()
    if ($octets[0] -ne 100 -or $octets[1] -lt 64 -or $octets[1] -gt 127) {
        throw "$Name is outside the NetBird overlay CGNAT range."
    }
    return $parsed
}

function Assert-Hex32([string]$Name, [string]$Value) {
    if ($Value -notmatch '^[0-9a-fA-F]{64}$' -or $Value -match '^0{64}$') {
        throw "$Name must be a nonzero 32-byte hexadecimal value."
    }
}

function Convert-HexToBytes([string]$Value) {
    $bytes = New-Object byte[] ($Value.Length / 2)
    for ($i = 0; $i -lt $bytes.Length; $i++) {
        $bytes[$i] = [Convert]::ToByte($Value.Substring($i * 2, 2), 16)
    }
    return ,$bytes
}

function Test-FixedTimeEqual([byte[]]$Left, [byte[]]$Right) {
    if ($null -eq $Left -or $null -eq $Right -or $Left.Length -ne $Right.Length) {
        return $false
    }
    $diff = 0
    for ($i = 0; $i -lt $Left.Length; $i++) {
        $diff = $diff -bor ($Left[$i] -bxor $Right[$i])
    }
    return ($diff -eq 0)
}

function Get-BootstrapCanonicalBytes(
    [string]$Network,
    [string]$NodeA,
    [string]$NodeB,
    [string]$PublicKey,
    [string]$Nonce,
    [long]$IssuedAt
) {
    $parts = @(
        "QRUN-NETBIRD-PEER-BOOTSTRAP-V1",
        $Network.ToLowerInvariant(),
        $NodeA,
        $NodeB,
        $PublicKey.ToLowerInvariant(),
        $Nonce.ToLowerInvariant(),
        [string]$IssuedAt
    )
    return $script:Utf8Strict.GetBytes(($parts -join [char]10))
}

function Get-HmacHex([byte[]]$Key, [byte[]]$Message) {
    $hmac = [System.Security.Cryptography.HMACSHA256]::new($Key)
    try {
        return ([BitConverter]::ToString($hmac.ComputeHash($Message))).Replace("-", "").ToLowerInvariant()
    }
    finally {
        $hmac.Dispose()
    }
}

function Read-BoundedJsonLine(
    [System.Net.Sockets.NetworkStream]$Stream,
    [int]$MaximumBytes = 4096
) {
    $buffer = New-Object System.Collections.Generic.List[byte]
    $one = New-Object byte[] 1
    while ($buffer.Count -lt $MaximumBytes) {
        $read = $Stream.Read($one, 0, 1)
        if ($read -ne 1) { throw "Peer closed the bootstrap connection before completing its message." }
        if ($one[0] -eq 10) {
            $bytes = $buffer.ToArray()
            if ($bytes.Length -gt 0 -and $bytes[$bytes.Length - 1] -eq 13) {
                $bytes = $bytes[0..($bytes.Length - 2)]
            }
            return $script:Utf8Strict.GetString($bytes)
        }
        $buffer.Add($one[0])
    }
    throw "Bootstrap message exceeded the $MaximumBytes-byte limit."
}

function Write-JsonLine([System.Net.Sockets.NetworkStream]$Stream, $Value) {
    $json = $Value | ConvertTo-Json -Depth 4 -Compress
    $bytes = $script:Utf8Strict.GetBytes($json + [char]10)
    $Stream.Write($bytes, 0, $bytes.Length)
    $Stream.Flush()
}

function Get-TokenBytesFromBase64([string]$Value) {
    if ([string]::IsNullOrWhiteSpace($Value)) { throw "Bootstrap token is missing." }
    try { $bytes = [Convert]::FromBase64String($Value.Trim()) }
    catch { throw "Bootstrap token is not valid Base64." }
    if ($bytes.Length -ne 32) { throw "Bootstrap token must contain exactly 32 random bytes." }
    return ,$bytes
}

function Protect-TokenForCurrentUser([byte[]]$Token, [string]$Path) {
    $protected = [System.Security.Cryptography.ProtectedData]::Protect(
        $Token,
        $script:Entropy,
        [System.Security.Cryptography.DataProtectionScope]::CurrentUser
    )
    $parent = Split-Path -Parent $Path
    if (-not (Test-Path -LiteralPath $parent)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }
    [System.IO.File]::WriteAllBytes($Path, $protected)
}

function Unprotect-TokenForCurrentUser([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Protected bootstrap token file is missing."
    }
    $protected = [System.IO.File]::ReadAllBytes($Path)
    $token = [System.Security.Cryptography.ProtectedData]::Unprotect(
        $protected,
        $script:Entropy,
        [System.Security.Cryptography.DataProtectionScope]::CurrentUser
    )
    if ($token.Length -ne 32) { throw "Protected bootstrap token has an unexpected length." }
    return ,$token
}

function Publish-GitHubSecretFromMemory([string]$Name, [string]$Value) {
    if ($Name -notmatch '^[A-Z][A-Z0-9_]{2,99}$') { throw "GitHub secret name is invalid." }
    $gh = Get-Command gh -ErrorAction Stop
    $start = [System.Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $gh.Source
    $start.Arguments = "secret set $Name"
    $start.UseShellExecute = $false
    $start.RedirectStandardInput = $true
    $start.CreateNoWindow = $true
    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $start
    if (-not $process.Start()) { throw "Could not start GitHub CLI to publish the bootstrap secret." }
    try {
        $process.StandardInput.WriteLine($Value)
        $process.StandardInput.Close()
        if (-not $process.WaitForExit(30000)) {
            try { $process.Kill() } catch {}
            throw "GitHub CLI did not finish publishing the bootstrap secret within 30 seconds."
        }
        if ($process.ExitCode -ne 0) {
            throw "GitHub CLI failed to publish the bootstrap secret. Check repository permissions and authentication."
        }
    }
    finally {
        $process.Dispose()
    }
}

function Invoke-Generate {
    if ([string]::IsNullOrWhiteSpace($TokenFile)) { throw "-TokenFile is required for Generate." }
    if (Test-Path -LiteralPath $TokenFile) { throw "Refusing to overwrite an existing protected bootstrap token." }
    $random = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $token = New-Object byte[] 32
    try { $random.GetBytes($token) } finally { $random.Dispose() }
    try {
        Protect-TokenForCurrentUser -Token $token -Path $TokenFile
        if ($PublishGitHubSecret) {
            $tokenBase64 = [Convert]::ToBase64String($token)
            Publish-GitHubSecretFromMemory -Name "QRUN_PEER_BOOTSTRAP_TOKEN" -Value $tokenBase64
        }
        Write-Output "BOOTSTRAP_TOKEN_PROTECTED_BY_CURRENTUSER_DPAPI=PASS"
        if ($PublishGitHubSecret) { Write-Output "GITHUB_BOOTSTRAP_SECRET_PUBLISHED=PASS" }
        Write-Output "BOOTSTRAP_TOKEN_VALUE=NEVER_EXPORTED"
    }
    catch {
        Remove-Item -LiteralPath $TokenFile -Force -ErrorAction SilentlyContinue
        throw
    }
    finally {
        [Array]::Clear($token, 0, $token.Length)
    }
}

function Invoke-Serve {
    if ([string]::IsNullOrWhiteSpace($TokenFile) -or
        [string]::IsNullOrWhiteSpace($OutputFile) -or
        [string]::IsNullOrWhiteSpace($BindIp) -or
        [string]::IsNullOrWhiteSpace($NetworkIdHex)) {
        throw "Serve requires -TokenFile, -OutputFile, -BindIp and -NetworkIdHex."
    }
    Assert-Hex32 "NetworkIdHex" $NetworkIdHex
    $bind = Assert-OverlayIPv4 "BindIp" $BindIp
    if (Test-Path -LiteralPath $OutputFile) {
        throw "Refusing to overwrite an existing peer enrollment record."
    }
    if ($TimeoutSeconds -lt 10 -or $TimeoutSeconds -gt 900) {
        throw "TimeoutSeconds must be between 10 and 900."
    }
    $token = Unprotect-TokenForCurrentUser -Path $TokenFile
    $listener = [System.Net.Sockets.TcpListener]::new($bind, 49342)
    $client = $null
    try {
        $listener.Start(1)
        Write-Output "PEER_BOOTSTRAP_LISTENER_READY=$($bind.ToString()):49342"
        $acceptTask = $listener.AcceptTcpClientAsync()
        if (-not $acceptTask.Wait($TimeoutSeconds * 1000)) {
            throw "Timed out waiting for the one permitted peer bootstrap connection."
        }
        $client = $acceptTask.GetAwaiter().GetResult()
        $client.ReceiveTimeout = 5000
        $client.SendTimeout = 5000
        $remote = ([System.Net.IPAddress]$client.Client.RemoteEndPoint.Address).MapToIPv4().ToString()
        [void](Assert-OverlayIPv4 "Bootstrap source address" $remote)
        $stream = $client.GetStream()
        $nonceBytes = New-Object byte[] 32
        $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
        try { $rng.GetBytes($nonceBytes) } finally { $rng.Dispose() }
        $nonce = ([BitConverter]::ToString($nonceBytes)).Replace("-", "").ToLowerInvariant()
        [Array]::Clear($nonceBytes, 0, $nonceBytes.Length)
        $issuedAt = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
        Write-JsonLine $stream ([ordered]@{
            version = 1
            network_id_hex = $NetworkIdHex.ToLowerInvariant()
            node_a_overlay_ip = $bind.ToString()
            nonce_hex = $nonce
            issued_at_unix_secs = $issuedAt
        })
        $requestText = Read-BoundedJsonLine $stream
        $request = $requestText | ConvertFrom-Json
        $allowedProperties = @("version", "network_id_hex", "node_b_overlay_ip", "node_b_noise_public_key_hex", "nonce_hex", "issued_at_unix_secs", "mac_hex")
        foreach ($property in $request.PSObject.Properties) {
            if ($property.Name -notin $allowedProperties) { throw "Bootstrap request contains an unsupported field." }
        }
        foreach ($required in $allowedProperties) {
            if (-not $request.PSObject.Properties[$required]) { throw "Bootstrap request is missing a required field." }
        }
        if ([int]$request.version -ne 1) { throw "Bootstrap protocol version mismatch." }
        if ([string]$request.network_id_hex -ne $NetworkIdHex.ToLowerInvariant()) {
            throw "Bootstrap Network ID mismatch."
        }
        if ([string]$request.nonce_hex -ne $nonce -or [long]$request.issued_at_unix_secs -ne $issuedAt) {
            throw "Bootstrap challenge mismatch or replay detected."
        }
        $now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
        if (($now - $issuedAt) -lt 0 -or ($now - $issuedAt) -gt 60) {
            throw "Bootstrap challenge expired."
        }
        $advertisedIp = [string]$request.node_b_overlay_ip
        if ($advertisedIp -ne $remote) {
            throw "Advertised Node B overlay address does not match the authenticated TCP source address."
        }
        [void](Assert-OverlayIPv4 "Node B overlay address" $advertisedIp)
        if ($advertisedIp -eq $bind.ToString()) {
            throw "Node A and Node B must be distinct NetBird overlay hosts."
        }
        $publicKey = [string]$request.node_b_noise_public_key_hex
        Assert-Hex32 "Node B Noise public key" $publicKey
        $providedMac = [string]$request.mac_hex
        if ($providedMac -notmatch '^[0-9a-fA-F]{64}$') { throw "Bootstrap authentication tag is malformed." }
        $canonical = Get-BootstrapCanonicalBytes -Network $NetworkIdHex -NodeA $bind.ToString() -NodeB $advertisedIp -PublicKey $publicKey -Nonce $nonce -IssuedAt $issuedAt
        $expectedMac = Convert-HexToBytes (Get-HmacHex -Key $token -Message $canonical)
        $actualMac = Convert-HexToBytes $providedMac
        if (-not (Test-FixedTimeEqual -Left $expectedMac -Right $actualMac)) {
            throw "Bootstrap HMAC authentication failed."
        }
        $parent = Split-Path -Parent $OutputFile
        if (-not (Test-Path -LiteralPath $parent)) {
            New-Item -ItemType Directory -Path $parent -Force | Out-Null
        }
        $record = [ordered]@{
            protocol_version = 1
            network_id_hex = $NetworkIdHex.ToLowerInvariant()
            node_a_overlay_ip = $bind.ToString()
            node_b_overlay_ip = $advertisedIp
            node_b_noise_public_key_hex = $publicKey.ToLowerInvariant()
            enrolled_at_utc = [DateTimeOffset]::UtcNow.ToString("o")
            source_ip_verified = $true
        }
        $temporary = $OutputFile + "." + [guid]::NewGuid().ToString("N") + ".tmp"
        try {
            $json = $record | ConvertTo-Json -Depth 4
            [System.IO.File]::WriteAllText($temporary, $json, $script:Utf8Strict)
            [System.IO.File]::Move($temporary, $OutputFile)
        }
        finally {
            Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue
        }

        $enrollmentAccepted = $true
        if (-not [string]::IsNullOrWhiteSpace($AckFile)) {
            $ackDeadline = [DateTimeOffset]::UtcNow.AddSeconds($TimeoutSeconds)
            $ackValue = $null
            while ([DateTimeOffset]::UtcNow -lt $ackDeadline) {
                if (Test-Path -LiteralPath $AckFile -PathType Leaf) {
                    $ackValue = (Get-Content -LiteralPath $AckFile -Raw).Trim()
                    break
                }
                Start-Sleep -Milliseconds 250
            }
            if ($ackValue -ne "PASS") {
                $enrollmentAccepted = $false
            }
        }
        Write-JsonLine $stream ([ordered]@{ accepted = $enrollmentAccepted; protocol_version = 1 })
        if (-not $enrollmentAccepted) {
            throw "Node A did not complete its reverse pinned startup sync."
        }
        Write-Output "PEER_BOOTSTRAP_HMAC_VERIFIED=PASS"
        Write-Output "PEER_BOOTSTRAP_SOURCE_IP_PINNED=PASS"
        Write-Output "PEER_BOOTSTRAP_PUBLIC_KEY_RECEIVED=PASS"
        Write-Output "PEER_BOOTSTRAP_ONE_SHOT_COMPLETE=PASS"
    }
    finally {
        if ($client) { $client.Dispose() }
        $listener.Stop()
        [Array]::Clear($token, 0, $token.Length)
    }
}

function Invoke-Enroll {
    if ([string]::IsNullOrWhiteSpace($NodeAIp) -or
        [string]::IsNullOrWhiteSpace($NodeBIp) -or
        [string]::IsNullOrWhiteSpace($NetworkIdHex) -or
        [string]::IsNullOrWhiteSpace($NodeBNoisePublicKeyHex)) {
        throw "Enroll requires Node A IP, Node B IP, Network ID and Node B Noise public key."
    }
    $nodeA = Assert-OverlayIPv4 "NodeAIp" $NodeAIp
    $nodeB = Assert-OverlayIPv4 "NodeBIp" $NodeBIp
    if ($nodeA -eq $nodeB) { throw "Node A and Node B must be distinct NetBird overlay hosts." }
    if ($TimeoutSeconds -lt 10 -or $TimeoutSeconds -gt 900) { throw "TimeoutSeconds must be between 10 and 900." }
    Assert-Hex32 "NetworkIdHex" $NetworkIdHex
    Assert-Hex32 "NodeBNoisePublicKeyHex" $NodeBNoisePublicKeyHex
    $token = Get-TokenBytesFromBase64 $env:QRUN_PEER_BOOTSTRAP_TOKEN
    $client = [System.Net.Sockets.TcpClient]::new([System.Net.Sockets.AddressFamily]::InterNetwork)
    try {
        $connect = $client.ConnectAsync($nodeA, 49342)
        if (-not $connect.Wait(10000)) { throw "Timed out connecting to Node A peer bootstrap listener." }
        $connect.GetAwaiter().GetResult()
        $ackTimeoutMilliseconds = [Math]::Min($TimeoutSeconds, 900) * 1000
        $client.ReceiveTimeout = $ackTimeoutMilliseconds
        $client.SendTimeout = 10000
        $stream = $client.GetStream()
        $challenge = (Read-BoundedJsonLine $stream) | ConvertFrom-Json
        if ([int]$challenge.version -ne 1 -or
            [string]$challenge.network_id_hex -ne $NetworkIdHex.ToLowerInvariant() -or
            [string]$challenge.node_a_overlay_ip -ne $nodeA.ToString()) {
            throw "Node A bootstrap challenge identity does not match the expected network and address."
        }
        $nonce = [string]$challenge.nonce_hex
        if ($nonce -notmatch '^[0-9a-fA-F]{64}$') { throw "Node A bootstrap nonce is malformed." }
        $issuedAt = [long]$challenge.issued_at_unix_secs
        $now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
        if (($now - $issuedAt) -lt 0 -or ($now - $issuedAt) -gt 60) {
            throw "Node A bootstrap challenge is expired or has an invalid clock."
        }
        $canonical = Get-BootstrapCanonicalBytes -Network $NetworkIdHex -NodeA $nodeA.ToString() -NodeB $nodeB.ToString() -PublicKey $NodeBNoisePublicKeyHex -Nonce $nonce -IssuedAt $issuedAt
        $mac = Get-HmacHex -Key $token -Message $canonical
        Write-JsonLine $stream ([ordered]@{
            version = 1
            network_id_hex = $NetworkIdHex.ToLowerInvariant()
            node_b_overlay_ip = $nodeB.ToString()
            node_b_noise_public_key_hex = $NodeBNoisePublicKeyHex.ToLowerInvariant()
            nonce_hex = $nonce.ToLowerInvariant()
            issued_at_unix_secs = $issuedAt
            mac_hex = $mac
        })
        $ack = (Read-BoundedJsonLine $stream) | ConvertFrom-Json
        if ($ack.accepted -ne $true -or [int]$ack.protocol_version -ne 1) {
            throw "Node A did not acknowledge the one-shot peer enrollment."
        }
        Write-Output "PEER_BOOTSTRAP_CLIENT_AUTHENTICATED=PASS"
        Write-Output "NODE_B_PRIVATE_KEY_EXPORTED=NO"
    }
    finally {
        $client.Dispose()
        [Array]::Clear($token, 0, $token.Length)
    }
}

function Invoke-SelfTest {
    $vectorKey = New-Object byte[] 20
    for ($i = 0; $i -lt $vectorKey.Length; $i++) { $vectorKey[$i] = 0x0b }
    $vectorMessage = [System.Text.Encoding]::ASCII.GetBytes("Hi There")
    $vectorMac = Get-HmacHex -Key $vectorKey -Message $vectorMessage
    if ($vectorMac -ne "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7") {
        throw "RFC 4231 HMAC-SHA256 test vector failed."
    }

    $key = New-Object byte[] 32
    for ($i = 0; $i -lt $key.Length; $i++) { $key[$i] = 0x11 }
    $message = Get-BootstrapCanonicalBytes -Network ("22" * 32) -NodeA "100.100.1.1" -NodeB "100.100.1.2" -PublicKey ("33" * 32) -Nonce ("44" * 32) -IssuedAt 1793670000
    $mac1 = Convert-HexToBytes (Get-HmacHex -Key $key -Message $message)
    $mac2 = Convert-HexToBytes (Get-HmacHex -Key $key -Message $message)
    if (-not (Test-FixedTimeEqual -Left $mac1 -Right $mac2)) { throw "HMAC determinism self-test failed." }
    $tampered = [byte[]]$message.Clone()
    $tampered[$tampered.Length - 1] = $tampered[$tampered.Length - 1] -bxor 1
    $mac3 = Convert-HexToBytes (Get-HmacHex -Key $key -Message $tampered)
    if (Test-FixedTimeEqual -Left $mac1 -Right $mac3) { throw "HMAC tamper detection self-test failed." }
    if (Test-FixedTimeEqual -Left $mac1 -Right (New-Object byte[] 31)) { throw "Fixed-time length validation self-test failed." }

    $dpapiPath = Join-Path $env:TEMP ("qrun-bootstrap-dpapi-" + [guid]::NewGuid().ToString("N") + ".bin")
    try {
        Protect-TokenForCurrentUser -Token $key -Path $dpapiPath
        $roundTrip = Unprotect-TokenForCurrentUser -Path $dpapiPath
        if (-not (Test-FixedTimeEqual -Left $key -Right $roundTrip)) {
            throw "DPAPI current-user protection round-trip failed."
        }
        [Array]::Clear($roundTrip, 0, $roundTrip.Length)
    }
    finally {
        Remove-Item -LiteralPath $dpapiPath -Force -ErrorAction SilentlyContinue
    }

    [Array]::Clear($vectorKey, 0, $vectorKey.Length)
    [Array]::Clear($key, 0, $key.Length)
    Write-Output "BOOTSTRAP_RFC4231_HMAC_SHA256_VECTOR=PASS"
    Write-Output "BOOTSTRAP_HMAC_DETERMINISM=PASS"
    Write-Output "BOOTSTRAP_HMAC_TAMPER_REJECTION=PASS"
    Write-Output "BOOTSTRAP_FIXED_LENGTH_COMPARE=PASS"
    Write-Output "BOOTSTRAP_DPAPI_CURRENTUSER_ROUNDTRIP=PASS"
    Write-Output "BOOTSTRAP_PROTOCOL_SELF_TEST=PASS"
}

switch ($Mode) {
    "Generate" { Invoke-Generate }
    "Serve" { Invoke-Serve }
    "Enroll" { Invoke-Enroll }
    "SelfTest" { Invoke-SelfTest }
    "RemoveProtectedToken" {
        if ([string]::IsNullOrWhiteSpace($TokenFile)) { throw "-TokenFile is required for RemoveProtectedToken." }
        Remove-Item -LiteralPath $TokenFile -Force -ErrorAction Stop
        Write-Output "PROTECTED_BOOTSTRAP_TOKEN_REMOVED=PASS"
    }
}