[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$NodeAOverlayIp,
    [Parameter(Mandatory)][string]$NetworkIdHex,
    [Parameter(Mandatory)][string]$OwnerAccountIdHex,
    [Parameter(Mandatory)][string]$OwnerPublicKeyHex,
    [Parameter(Mandatory)][string]$GenesisTimeUnixSecs,
    [Parameter(Mandatory)][string]$NodeANoisePublicKeyHex,
    [Parameter(Mandatory)][string]$ReferenceTimeAdminPublicKeyHex,
    [Parameter(Mandatory)][string]$ReferenceTimePolicyBase64
)

$ErrorActionPreference = "Stop"
$netbirdExe = "C:\Program Files\NetBird\netbird.exe"
$nodeProcess = $null
$tempRoot = Join-Path $env:TEMP ("qrun-v05-cross-host-" + [guid]::NewGuid().ToString("N"))
$netbirdConnected = $false

function Assert-Hex32([string]$Name, [string]$Value) {
    if ($Value -notmatch '^[0-9a-fA-F]{64}$' -or $Value -match '^0{64}$') {
        throw "$Name must be a nonzero 32-byte hexadecimal value."
    }
}

function Test-TcpEndpoint([string]$Address, [int]$Port, [int]$TimeoutMs = 2500) {
    $client = [System.Net.Sockets.TcpClient]::new()
    try {
        $task = $client.ConnectAsync($Address, $Port)
        if (-not $task.Wait($TimeoutMs)) { return $false }
        $task.GetAwaiter().GetResult()
        return $client.Connected
    } catch {
        return $false
    } finally {
        $client.Dispose()
    }
}

function Get-NetBirdStatus {
    $text = (& $netbirdExe status 2>&1 | Out-String)
    if ($LASTEXITCODE -ne 0) { throw "NetBird status command failed." }
    return $text
}

function ConvertTo-QuotedArgument([string]$Value) {
    return '"' + $Value.Replace('"', '\"') + '"'
}

try {
    Assert-Hex32 "NetworkIdHex" $NetworkIdHex
    Assert-Hex32 "OwnerAccountIdHex" $OwnerAccountIdHex
    Assert-Hex32 "OwnerPublicKeyHex" $OwnerPublicKeyHex
    Assert-Hex32 "NodeANoisePublicKeyHex" $NodeANoisePublicKeyHex
    Assert-Hex32 "ReferenceTimeAdminPublicKeyHex" $ReferenceTimeAdminPublicKeyHex
    if ($GenesisTimeUnixSecs -notmatch '^[1-9][0-9]{8,11}$') {
        throw "GenesisTimeUnixSecs is malformed."
    }
    $nodeAIp = [System.Net.IPAddress]::Parse($NodeAOverlayIp)
    if ($nodeAIp.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) {
        throw "Node A address must be IPv4."
    }
    $ipBytes = $nodeAIp.GetAddressBytes()
    if ($ipBytes[0] -ne 100 -or $ipBytes[1] -lt 64 -or $ipBytes[1] -gt 127) {
        throw "Node A address is not in the NetBird CGNAT overlay range."
    }
    if ([string]::IsNullOrWhiteSpace($env:NETBIRD_SETUP_KEY)) {
        throw "Required GitHub Actions secret NETBIRD_SETUP_KEY is missing."
    }

    New-Item -ItemType Directory -Path $tempRoot | Out-Null
    $msiPath = Join-Path $tempRoot "netbird_installer_0.82.0_windows_amd64.msi"

    if (-not (Test-Path $netbirdExe)) {
        $msiUrl = "https://github.com/netbirdio/netbird/releases/download/v0.82.0/netbird_installer_0.82.0_windows_amd64.msi"
        Invoke-WebRequest -Uri $msiUrl -OutFile $msiPath
        $expectedHash = "8155544c557676069c49d43ccf2c62a5ccb2fefec9d92ec58fa6920db8bc43e9"
        $actualHash = (Get-FileHash -Path $msiPath -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($actualHash -ne $expectedHash) { throw "NetBird MSI SHA-256 verification failed." }
        $signature = Get-AuthenticodeSignature -FilePath $msiPath
        if ($signature.Status -ne "Valid" -or $signature.SignerCertificate.Subject -notmatch "NetBird GmbH") {
            throw "NetBird MSI Authenticode verification failed."
        }
        $install = Start-Process -FilePath "msiexec.exe" -ArgumentList @("/i", $msiPath, "/qn", "/norestart") -Wait -PassThru
        if ($install.ExitCode -notin @(0, 3010)) { throw "NetBird MSI installation failed." }
    }
    if (-not (Test-Path $netbirdExe)) { throw "NetBird CLI was not installed." }

    $service = Get-Service -Name NetBird -ErrorAction Stop
    if ($service.Status -ne "Running") { Start-Service -Name NetBird }
    $env:NB_SETUP_KEY = $env:NETBIRD_SETUP_KEY
    Remove-Item Env:NETBIRD_SETUP_KEY -ErrorAction SilentlyContinue
    & $netbirdExe up
    $upExit = $LASTEXITCODE
    Remove-Item Env:NB_SETUP_KEY -ErrorAction SilentlyContinue
    if ($upExit -ne 0) { throw "NetBird peer enrollment failed." }
    $netbirdConnected = $true

    $status = ""
    $nodeBIp = $null
    for ($attempt = 0; $attempt -lt 60; $attempt++) {
        $status = Get-NetBirdStatus
        if ($status -match "Management:\s+Connected" -and $status -match "Signal:\s+Connected") {
            $match = [regex]::Match($status, "NetBird IP:\s+([0-9]{1,3}(?:\.[0-9]{1,3}){3})")
            if ($match.Success) { $nodeBIp = $match.Groups[1].Value; break }
        }
        Start-Sleep -Seconds 1
    }
    if (-not $nodeBIp) { throw "Temporary runner did not obtain a connected NetBird overlay address." }

    if (-not (Test-TcpEndpoint $NodeAOverlayIp 49341)) {
        throw "Node A QRun P2P TCP 49341 is not reachable over NetBird."
    }
    if (-not (Test-TcpEndpoint $NodeAOverlayIp 49550)) {
        throw "Node A authenticated reference-time TCP 49550 is not reachable over NetBird."
    }
    if (Test-TcpEndpoint $NodeAOverlayIp 49339) { throw "Security boundary failed: Node A RPC 49339 is reachable remotely." }
    if (Test-TcpEndpoint $NodeAOverlayIp 49340) { throw "Security boundary failed: Node A transaction ingress 49340 is reachable remotely." }

    $repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
    $manifest = Join-Path $repoRoot "src/native/pow_bench/Cargo.toml"
    Write-Host "=== Build isolated QRun v0.5 Node B ==="
    cargo build --release --locked --manifest-path $manifest --bin qrun_v05_pow_local_node --bin qrun_v05_noise_key_provision
    if ($LASTEXITCODE -ne 0) { throw "QRun Node B build failed." }

    $target = Join-Path $repoRoot "src/native/pow_bench/target/release"
    $nodeExe = Join-Path $target "qrun_v05_pow_local_node.exe"
    $noiseExe = Join-Path $target "qrun_v05_noise_key_provision.exe"
    $policyPath = Join-Path $tempRoot "public-alpha.rtp1"
    $policyBytes = [Convert]::FromBase64String($ReferenceTimePolicyBase64)
    if ($policyBytes.Length -lt 64 -or $policyBytes.Length -gt 8192) { throw "Signed RTP1 policy length is outside the expected bounds." }
    [System.IO.File]::WriteAllBytes($policyPath, $policyBytes)

    $noisePath = Join-Path $tempRoot "node-b.npk1"
    $noiseOutput = & $noiseExe --network-id-hex $NetworkIdHex --output $noisePath 2>&1
    if ($LASTEXITCODE -ne 0) { throw "Node B Noise key provisioning failed." }
    $publicLine = $noiseOutput | Where-Object { "$_" -match "^public_key_hex=" } | Select-Object -First 1
    if (-not $publicLine) { throw "Node B Noise public key was not returned." }
    $nodeBNoisePublic = ("$publicLine" -replace "^public_key_hex=", "").Trim()
    Assert-Hex32 "Node B Noise public key" $nodeBNoisePublic
    Write-Host "NODE_B_NOISE_KEY_PROTECTED_BY_CURRENTUSER_DPAPI=PASS"
    Write-Host "NODE_B_PRIVATE_KEY_EXPORTED=NO"

    $dataDir = Join-Path $tempRoot "node-b-data"
    $statePath = Join-Path $tempRoot "node-b-reference-time.rts1"
    $stdoutPath = Join-Path $tempRoot "node-b.stdout.log"
    $stderrPath = Join-Path $tempRoot "node-b.stderr.log"
    $peerAddress = "$($NodeAOverlayIp):49341"
    $timeAddress = "$($NodeAOverlayIp):49550"
    $nodeArgs = @(
        "--public-alpha",
        "--network-id-hex", $NetworkIdHex,
        "--owner-account-id-hex", $OwnerAccountIdHex,
        "--owner-public-key-hex", $OwnerPublicKeyHex,
        "--genesis-time-unix-secs", $GenesisTimeUnixSecs,
        "--data-dir", $dataDir,
        "--rpc-listen", "127.0.0.1:49339",
        "--tx-listen", "127.0.0.1:49340",
        "--block-listen", "$($nodeBIp):49341",
        "--noise-private-key-file", $noisePath,
        "--reference-time-policy-file", $policyPath,
        "--reference-time-admin-public-key-hex", $ReferenceTimeAdminPublicKeyHex,
        "--reference-time-address", $timeAddress,
        "--reference-time-state-file", $statePath,
        "--peer", $peerAddress,
        "--peer-static-public-key-hex", $NodeANoisePublicKeyHex,
        "--sync-on-start", "true"
    )
    $quotedArgs = $nodeArgs | ForEach-Object { ConvertTo-QuotedArgument "$_" }
    $nodeProcess = Start-Process -FilePath $nodeExe -ArgumentList $quotedArgs -PassThru -WindowStyle Hidden -RedirectStandardOutput $stdoutPath -RedirectStandardError $stderrPath

    $syncVerified = $false
    $stdout = ""
    $statusJson = $null
    for ($attempt = 0; $attempt -lt 240; $attempt++) {
        $nodeProcess.Refresh()
        if ($nodeProcess.HasExited) {
            $errorText = Get-Content -LiteralPath $stderrPath -Raw -ErrorAction SilentlyContinue
            $outputText = Get-Content -LiteralPath $stdoutPath -Raw -ErrorAction SilentlyContinue
            throw "Node B exited during startup. STDERR=$errorText STDOUT=$outputText"
        }
        $stdout = Get-Content -LiteralPath $stdoutPath -Raw -ErrorAction SilentlyContinue
        # Public Alpha reports authenticated sync completion; pinned_peer_sync_verified is Mainnet-only.
        if ($stdout -match "qrun_pow_authenticated_startup_sync_complete peer=" -and
            $stdout -match "qrun_reference_time_ready source=ed25519-attested-time-v1 provenance=ConfiguredProvider" -and
            $stdout -match "network_class=public_alpha_experimental_not_mainnet" -and
            $stdout -match "mainnet=false") {
            $syncVerified = $true
            try { $statusJson = Invoke-RestMethod -Method Get -Uri "http://127.0.0.1:49339/v1/status" -TimeoutSec 5 } catch {}
            if ($statusJson) { break }
        }
        Start-Sleep -Seconds 1
    }
    if (-not $syncVerified -or -not $statusJson) {
        $errorText = Get-Content -LiteralPath $stderrPath -Raw -ErrorAction SilentlyContinue
        throw "Node B did not prove authenticated startup sync and RPC readiness. STDERR=$errorText STDOUT=$stdout"
    }
    if ($statusJson.network_id -ne $NetworkIdHex.ToLowerInvariant()) {
        throw "Node B status network ID differs from the supplied Public Alpha network."
    }
    if ([string]::IsNullOrWhiteSpace([string]$statusJson.profile_id) -or
        [string]::IsNullOrWhiteSpace([string]$statusJson.tip) -or
        [string]::IsNullOrWhiteSpace([string]$statusJson.state_root)) {
        throw "Node B status did not expose a complete profile/tip/state-root tuple."
    }

    Write-Host "NETBIRD_CROSS_HOST_TCP_P2P_49341=PASS"
    Write-Host "NETBIRD_CROSS_HOST_AUTH_TIME_49550=PASS"
    Write-Host "REMOTE_RPC_49339_BLOCKED=PASS"
    Write-Host "REMOTE_TX_49340_BLOCKED=PASS"
    Write-Host "NOISE_XX_PINNED_STARTUP_SYNC=PASS"
    Write-Host "NODE_B_PUBLIC_ALPHA_NOT_MAINNET=PASS"
    Write-Host "node_b_height=$($statusJson.height)"
    Write-Host "node_b_profile_id=$($statusJson.profile_id)"
    Write-Host "node_b_tip=$($statusJson.tip)"
    Write-Host "node_b_state_root=$($statusJson.state_root)"
    Write-Host "mainnet=false"
}
finally {
    if ($nodeProcess -and -not $nodeProcess.HasExited) {
        Stop-Process -Id $nodeProcess.Id -Force -ErrorAction SilentlyContinue
        Wait-Process -Id $nodeProcess.Id -Timeout 10 -ErrorAction SilentlyContinue
    }
    if ($netbirdConnected -and (Test-Path $netbirdExe)) {
        & $netbirdExe down 2>&1 | Out-Null
    }
    Remove-Item Env:NB_SETUP_KEY -ErrorAction SilentlyContinue
    Remove-Item Env:NETBIRD_SETUP_KEY -ErrorAction SilentlyContinue
    if (Test-Path $tempRoot) {
        Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}
