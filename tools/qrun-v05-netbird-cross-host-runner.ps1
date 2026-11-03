[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$NodeAOverlayIp,
    [Parameter(Mandatory)][string]$NetworkIdHex,
    [Parameter(Mandatory)][string]$OwnerAccountIdHex,
    [Parameter(Mandatory)][string]$OwnerPublicKeyHex,
    [Parameter(Mandatory)][string]$GenesisTimeUnixSecs,
    [Parameter(Mandatory)][string]$NodeANoisePublicKeyHex,
    [Parameter(Mandatory)][string]$ReferenceTimeAdminPublicKeyHex,
    [Parameter(Mandatory)][string]$ReferenceTimePolicyBase64,
    [switch]$StagePartitionReconnectReorg,
    [switch]$StageFullDuplex
)

$ErrorActionPreference = "Stop"
$netbirdExe = "C:\Program Files\NetBird\netbird.exe"
$nodeProcess = $null
$tempRoot = Join-Path $env:TEMP ("qrun-v05-cross-host-" + [guid]::NewGuid().ToString("N"))
$netbirdConnected = $false
$partitionRuleName = $null

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
    if ($StagePartitionReconnectReorg -and $StageFullDuplex) {
        throw "Stage C2 and Stage D1 cannot be combined in one runner invocation."
    }
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
    # NetBird parses cloud Setup Keys as canonical UUIDs. Validate the exact secret
    # before installing/starting the runner client so pasted labels or extra text fail early.
    $setupKey = $env:NETBIRD_SETUP_KEY.Trim()
    if ($setupKey -notmatch '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$') {
        throw "NETBIRD_SETUP_KEY is not a canonical 36-character UUID Setup Key. Recreate it in NetBird and copy the actual key value."
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
    if ($StagePartitionReconnectReorg) {
        # Build before enrollment so the Node A controller's 120-second delay
        # starts only after compilation is complete.
        $preRepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
        $preManifest = Join-Path $preRepoRoot "src/native/pow_bench/Cargo.toml"
        Write-Host "=== Pre-build QRun binaries before NetBird enrollment for Stage C2 ==="
        cargo build --release --locked --manifest-path $preManifest --bin qrun_v05_pow_local_node --bin qrun_v05_noise_key_provision --bin qrun_v05_public_alpha_process_smoke
        if ($LASTEXITCODE -ne 0) { throw "Pre-enrollment QRun build failed." }
        Write-Host "CROSS_HOST_PARTITION_RUNNER_PREBUILD=PASS"
    }
    $env:NB_SETUP_KEY = $setupKey
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

    # Management/signalling can become Connected before the peer-to-peer WireGuard
    # path finishes establishing. Wait for both allowed TCP endpoints instead of
    # failing on the first probe immediately after enrollment.
    $overlayReady = $false
    $lastP2pReachable = $false
    $lastTimeReachable = $false
    for ($attempt = 0; $attempt -lt 90; $attempt++) {
        $status = Get-NetBirdStatus
        if ($status -match "Management:\s+Connected" -and $status -match "Signal:\s+Connected") {
            $lastP2pReachable = Test-TcpEndpoint $NodeAOverlayIp 49341 1000
            $lastTimeReachable = Test-TcpEndpoint $NodeAOverlayIp 49550 1000
            if ($lastP2pReachable -and $lastTimeReachable) {
                $overlayReady = $true
                break
            }
        }
        if (($attempt + 1) % 15 -eq 0) {
            Write-Host "NETBIRD_OVERLAY_WAIT attempt=$($attempt + 1) p2p=$lastP2pReachable time=$lastTimeReachable"
        }
        Start-Sleep -Seconds 1
    }
    if (-not $overlayReady) {
        throw "NetBird peer tunnel was not ready within 90 seconds (P2P 49341=$lastP2pReachable, reference-time 49550=$lastTimeReachable)."
    }
    Write-Host "NETBIRD_PEER_TUNNEL_READY=PASS"
    if (Test-TcpEndpoint $NodeAOverlayIp 49339) { throw "Security boundary failed: Node A RPC 49339 is reachable remotely." }
    if (Test-TcpEndpoint $NodeAOverlayIp 49340) { throw "Security boundary failed: Node A transaction ingress 49340 is reachable remotely." }

    $repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
    $manifest = Join-Path $repoRoot "src/native/pow_bench/Cargo.toml"
    Write-Host "=== Build isolated QRun v0.5 Node B ==="
    cargo build --release --locked --manifest-path $manifest --bin qrun_v05_pow_local_node --bin qrun_v05_noise_key_provision --bin qrun_v05_public_alpha_process_smoke
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

    $startupProfileId = [string]$statusJson.profile_id
    if ($StageFullDuplex) {
        if ([string]::IsNullOrWhiteSpace($env:QRUN_PEER_BOOTSTRAP_TOKEN)) {
            throw "Stage D1 requires the dedicated GitHub Actions secret QRUN_PEER_BOOTSTRAP_TOKEN."
        }
        $bootstrapScript = Join-Path $PSScriptRoot "qrun-v05-netbird-peer-bootstrap.ps1"
        if (-not (Test-Path -LiteralPath $bootstrapScript)) { throw "The D1 peer bootstrap client script is missing." }
        Write-Host "=== Stage D1: authenticate Node B metadata and await Node A reverse pinned startup sync ==="
        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $bootstrapScript -Mode Enroll -NodeAIp $NodeAOverlayIp -NodeBIp $nodeBIp -NetworkIdHex $NetworkIdHex -NodeBNoisePublicKeyHex $nodeBNoisePublic
        if ($LASTEXITCODE -ne 0) {
            throw "Stage D1 peer bootstrap or Node A reverse pinned startup sync failed."
        }
        Write-Host "D1_NODE_B_ENROLLED_AND_NODE_A_REVERSE_SYNC_ACKNOWLEDGED=PASS"
    }
    # Stage C1: have Node B originate a signed test-only transaction on this disposable Public Alpha network.
    # This helper embeds the documented TEST_ONLY_SEED and is permitted only on this
    # freshly generated Public Alpha network; it is never a wallet or Mainnet key.
    if ([uint64]$statusJson.height -ne 0) {
        throw "Cross-host gossip stage requires a fresh height-zero Genesis on Node B."
    }
    $smokeExe = Join-Path $repoRoot "src/native/pow_bench/target/release/qrun_v05_public_alpha_process_smoke.exe"
    if (-not (Test-Path $smokeExe)) { throw "Public Alpha test-only signed transaction helper was not built." }
    $testIdentity = & $smokeExe identity 2>&1
    if ($LASTEXITCODE -ne 0) { throw "Could not derive the documented disposable Public Alpha test identity." }
    $testAccountLine = $testIdentity | Where-Object { "$_" -match "^owner_account_id_hex=" } | Select-Object -First 1
    $testPublicLine = $testIdentity | Where-Object { "$_" -match "^owner_public_key_hex=" } | Select-Object -First 1
    $testAccount = ("$testAccountLine" -replace "^owner_account_id_hex=", "").Trim()
    $testPublic = ("$testPublicLine" -replace "^owner_public_key_hex=", "").Trim()
    if ($testAccount -ne $OwnerAccountIdHex.ToLowerInvariant() -or
        $testPublic -ne $OwnerPublicKeyHex.ToLowerInvariant()) {
        throw "Node B's test-only signer does not match the freshly generated Genesis owner identity."
    }
    Write-Host "CROSS_HOST_TEST_SIGNER_MATCHES_GENESIS=PASS"
    Write-Host "CROSS_HOST_TEST_SIGNER_PRIVATE_SEED_EXPORTED=NO"

    if ($StagePartitionReconnectReorg) {
        Write-Host "=== Stage C2: isolate only Node B -> Node A QRun P2P while retaining authenticated time ==="
        if ([uint64]$statusJson.height -ne 0) {
            throw "Stage C2 requires both hosts at the shared Genesis before the partition."
        }
        if (-not (Test-TcpEndpoint $NodeAOverlayIp 49341 3000)) {
            throw "Node B could not reach Node A P2P TCP 49341 immediately before the controlled partition."
        }
        Write-Host "CROSS_HOST_PARTITION_PREBLOCK_P2P_49341_REACHABLE=PASS"
        $partitionRuleName = "QRun-CrossHost-StageC2-" + [guid]::NewGuid().ToString("N")
        $existingRule = Get-NetFirewallRule -DisplayName $partitionRuleName -ErrorAction SilentlyContinue
        if ($existingRule) { throw "Unexpected Stage C2 firewall rule name collision." }
        New-NetFirewallRule -DisplayName $partitionRuleName -Direction Outbound -Action Block -Protocol TCP -RemoteAddress $NodeAOverlayIp -RemotePort 49341 -Profile Any -Enabled True | Out-Null
        $activeRule = Get-NetFirewallRule -DisplayName $partitionRuleName -ErrorAction Stop
        $activePortFilter = $activeRule | Get-NetFirewallPortFilter
        $activeAddressFilter = $activeRule | Get-NetFirewallAddressFilter
        $remoteAddressScope = @($activeAddressFilter.RemoteAddress) -join ","
        if ($activeRule.Direction -ne "Outbound" -or $activeRule.Action -ne "Block" -or
            $activePortFilter.Protocol -ne "TCP" -or "$($activePortFilter.RemotePort)" -notmatch "49341" -or
            $remoteAddressScope -notmatch [regex]::Escape($NodeAOverlayIp)) {
            throw "Stage C2 outbound firewall partition rule did not match the exact Node A overlay IP and TCP 49341 scope."
        }
        if (Test-TcpEndpoint $NodeAOverlayIp 49341 1500) {
            throw "Stage C2 partition failed: Node B can still establish TCP to Node A P2P 49341."
        }
        if (-not (Test-TcpEndpoint $NodeAOverlayIp 49550 3000)) {
            throw "Stage C2 partition is not selective: authenticated reference-time TCP 49550 must remain reachable."
        }
        Write-Host "CROSS_HOST_PARTITION_P2P_49341_BLOCKED=PASS"
        $partitionNetBirdStatus = (& $netbirdExe status 2>&1 | Out-String)
        if ($LASTEXITCODE -ne 0 -or
            $partitionNetBirdStatus -notmatch "Management:\s+Connected" -or
            $partitionNetBirdStatus -notmatch "Signal:\s+Connected") {
            throw "NetBird overlay must remain connected while only TCP 49341 is partitioned."
        }
        Write-Host "CROSS_HOST_PARTITION_AUTH_TIME_49550_RETAINED=PASS"
        Write-Host "NETBIRD_OVERLAY_REMAINS_CONNECTED=PASS"

        Write-Host "=== Submit the competing nonce-1 branch on isolated Node B ==="
        $conflictOutput = & $smokeExe submit-conflict --network-id-hex $NetworkIdHex --address "127.0.0.1:49340" 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw "Node B partitioned conflict transaction failed: $($conflictOutput -join ' ')"
        }
        $conflictIdLine = $conflictOutput | Where-Object { "$_" -match "^transaction_id=" } | Select-Object -First 1
        $conflictStatusLine = $conflictOutput | Where-Object { "$_" -match "^qzts_status=" } | Select-Object -First 1
        $partitionTxid = ("$conflictIdLine" -replace "^transaction_id=", "").Trim()
        $partitionAck = ("$conflictStatusLine" -replace "^qzts_status=", "").Trim()
        if ($partitionTxid -notmatch "^[0-9a-fA-F]{64}$" -or $partitionAck -ne "Accepted") {
            throw "Node B did not accept its signed conflicting nonce-1 transaction."
        }

        $partitionStatus = $null
        $partitionReceipt = $null
        $partitionOwner = $null
        $partitionRecipient = $null
        for ($attempt = 0; $attempt -lt 180; $attempt++) {
            try {
                $partitionStatus = Invoke-RestMethod -Method Get -Uri "http://127.0.0.1:49339/v1/status" -TimeoutSec 5
                $partitionReceipt = Invoke-RestMethod -Method Get -Uri "http://127.0.0.1:49339/v1/transaction/$partitionTxid" -TimeoutSec 5
                $partitionOwner = Invoke-RestMethod -Method Get -Uri "http://127.0.0.1:49339/v1/balance/$OwnerAccountIdHex" -TimeoutSec 5
                $partitionRecipient = Invoke-RestMethod -Method Get -Uri ("http://127.0.0.1:49339/v1/balance/" + ("79" * 32)) -TimeoutSec 5
                if ([uint64]$partitionStatus.height -eq 1 -and
                    $partitionReceipt.status -eq "confirmed" -and
                    [uint64]$partitionOwner.nonce -eq 1 -and
                    [uint64]$partitionRecipient.balance_atoms -eq 2000) { break }
            } catch {}
            Start-Sleep -Seconds 1
        }
        if ([uint64]$partitionStatus.height -ne 1 -or
            $partitionStatus.network_id -ne $NetworkIdHex.ToLowerInvariant() -or
            $partitionStatus.profile_id -ne $startupProfileId -or
            $partitionStatus.mainnet -ne $false -or
            $partitionReceipt.status -ne "confirmed" -or
            [uint64]$partitionOwner.nonce -ne 1 -or
            [uint64]$partitionRecipient.balance_atoms -ne 2000) {
            throw "Node B did not reach its isolated canonical height-1 conflicting branch."
        }
        $partitionNodeBStdout = Get-Content -LiteralPath $stdoutPath -Raw -ErrorAction SilentlyContinue
        $partitionNodeBStderr = Get-Content -LiteralPath $stderrPath -Raw -ErrorAction SilentlyContinue
        $expectedFailedBroadcast = "qrun_pow_local_block_broadcast_failed peer=" + $NodeAOverlayIp + ":49341"
        $unexpectedSuccessBroadcast = "qrun_pow_local_block_broadcast peer=" + $NodeAOverlayIp + ":49341"
        if (-not $partitionNodeBStderr.Contains($expectedFailedBroadcast)) {
            throw "Node B did not record the failed P2P broadcast on stderr caused by the Stage C2 partition."
        }
        if ($partitionNodeBStdout.Contains($unexpectedSuccessBroadcast)) {
            throw "Node B unexpectedly broadcast its competing branch to Node A while partitioned."
        }
        Write-Host "CROSS_HOST_PARTITION_NODE_B_BRANCH_HEIGHT1=PASS"
        Write-Host "CROSS_HOST_PARTITION_NODE_B_CANONICAL_RECEIPT=PASS"
        Write-Host "CROSS_HOST_PARTITION_NODE_B_RECIPIENT_BALANCE=PASS"
        Write-Host "partition_node_b_txid=$partitionTxid"
        Write-Host "partition_node_b_height=$($partitionStatus.height)"
        Write-Host "partition_node_b_tip=$($partitionStatus.tip)"
        Write-Host "mainnet=false"

        # Node A's local controller waits 120 seconds after the Node B peer becomes
        # directly connected, then creates its nonce-1/nonce-2 branch. The P2P block
        # above is already active. Hold it closed long enough for Node A's two PoW blocks.
        Write-Host "CROSS_HOST_PARTITION_HOLD_SECONDS=600"
        Start-Sleep -Seconds 600

        Write-Host "=== Heal only the P2P partition and verify both allowed paths ==="
        Remove-NetFirewallRule -DisplayName $partitionRuleName -ErrorAction Stop
        $partitionRuleName = $null
        $healed = $false
        for ($attempt = 0; $attempt -lt 90; $attempt++) {
            $p2pReady = Test-TcpEndpoint $NodeAOverlayIp 49341 1000
            $timeReady = Test-TcpEndpoint $NodeAOverlayIp 49550 1000
            if ($p2pReady -and $timeReady) { $healed = $true; break }
            Start-Sleep -Seconds 1
        }
        if (-not $healed) { throw "Stage C2 P2P and authenticated-time paths did not recover after removing the firewall rule." }
        Write-Host "CROSS_HOST_PARTITION_RECONNECTED=PASS"

        Write-Host "=== Restart Node B with pinned authenticated sync to the higher-work Node A branch ==="
        if ($nodeProcess -and -not $nodeProcess.HasExited) {
            Stop-Process -Id $nodeProcess.Id -Force -ErrorAction SilentlyContinue
            Wait-Process -Id $nodeProcess.Id -Timeout 10 -ErrorAction SilentlyContinue
        }
        $nodeProcess = $null
        $reorgOut = Join-Path $tempRoot "node-b-reorg-sync.stdout.log"
        $reorgErr = Join-Path $tempRoot "node-b-reorg-sync.stderr.log"
        $quotedReorgArgs = $nodeArgs | ForEach-Object { ConvertTo-QuotedArgument "$_" }
        $nodeProcess = Start-Process -FilePath $nodeExe -ArgumentList $quotedReorgArgs -PassThru -WindowStyle Hidden -RedirectStandardOutput $reorgOut -RedirectStandardError $reorgErr
        $reorgStatus = $null
        $reorgSyncComplete = $false
        for ($attempt = 0; $attempt -lt 600; $attempt++) {
            $nodeProcess.Refresh()
            if ($nodeProcess.HasExited) {
                throw "Node B exited during cross-host reorg sync. STDERR=$(Get-Content -LiteralPath $reorgErr -Raw -ErrorAction SilentlyContinue)"
            }
            $reorgText = Get-Content -LiteralPath $reorgOut -Raw -ErrorAction SilentlyContinue
            if ($reorgText -match "qrun_pow_authenticated_startup_sync_complete peer=" -and
                $reorgText -match "qrun_pow_local_rpc_ready") {
                try { $reorgStatus = Invoke-RestMethod -Method Get -Uri "http://127.0.0.1:49339/v1/status" -TimeoutSec 5 } catch {}
                if ($reorgStatus) { $reorgSyncComplete = $true; break }
            }
            Start-Sleep -Seconds 1
        }
        if (-not $reorgSyncComplete) {
            throw "Node B did not complete authenticated restart sync. STDERR=$(Get-Content -LiteralPath $reorgErr -Raw -ErrorAction SilentlyContinue)"
        }
        if ([uint64]$reorgStatus.height -ne 2 -or
            $reorgStatus.network_id -ne $NetworkIdHex.ToLowerInvariant() -or
            $reorgStatus.profile_id -ne $startupProfileId -or
            $reorgStatus.mainnet -ne $false) {
            throw "Node B did not adopt the expected height-2 Node A branch under the same Network/Profile identity."
        }
        $orphanReceipt = Invoke-RestMethod -Method Get -Uri "http://127.0.0.1:49339/v1/transaction/$partitionTxid" -TimeoutSec 5
        $reorgOwner = Invoke-RestMethod -Method Get -Uri "http://127.0.0.1:49339/v1/balance/$OwnerAccountIdHex" -TimeoutSec 5
        $reorgA1 = Invoke-RestMethod -Method Get -Uri ("http://127.0.0.1:49339/v1/balance/" + ("78" * 32)) -TimeoutSec 5
        $reorgA2 = Invoke-RestMethod -Method Get -Uri ("http://127.0.0.1:49339/v1/balance/" + ("7a" * 32)) -TimeoutSec 5
        $reorgB = Invoke-RestMethod -Method Get -Uri ("http://127.0.0.1:49339/v1/balance/" + ("79" * 32)) -TimeoutSec 5
        if ($orphanReceipt.status -ne "not_found_in_canonical_chain" -or
            [uint64]$reorgOwner.nonce -ne 2 -or
            [uint64]$reorgOwner.balance_atoms -ne 999999999999996000 -or
            [uint64]$reorgA1.balance_atoms -ne 1000 -or
            [uint64]$reorgA2.balance_atoms -ne 3000 -or
            [uint64]$reorgB.balance_atoms -ne 0) {
            throw "Node B failed to orphan its losing receipt and rebuild the winning branch's canonical ledger."
        }
        Write-Host "CROSS_HOST_AUTHENTICATED_RECONNECT_REORG=PASS"
        Write-Host "CROSS_HOST_ORPHAN_RECEIPT_REMOVED=PASS"
        Write-Host "CROSS_HOST_CANONICAL_RECEIPTS_AND_BALANCES=PASS"
        Write-Host "node_b_reorg_height=$($reorgStatus.height)"
        Write-Host "node_b_reorg_tip=$($reorgStatus.tip)"
        Write-Host "node_b_reorg_state_root=$($reorgStatus.state_root)"
        Write-Host "node_b_owner_nonce=$($reorgOwner.nonce)"
        Write-Host "node_b_owner_balance_atoms=$($reorgOwner.balance_atoms)"

        Write-Host "=== Durable restart Node B without startup sync ==="
        Stop-Process -Id $nodeProcess.Id -Force -ErrorAction SilentlyContinue
        Wait-Process -Id $nodeProcess.Id -Timeout 10 -ErrorAction SilentlyContinue
        $nodeProcess = $null
        $durableArgs = New-Object System.Collections.Generic.List[string]
        for ($i = 0; $i -lt $nodeArgs.Count; $i++) {
            if ($nodeArgs[$i] -eq "--sync-on-start") { $i++; continue }
            [void]$durableArgs.Add([string]$nodeArgs[$i])
        }
        $durableOut = Join-Path $tempRoot "node-b-durable-reopen.stdout.log"
        $durableErr = Join-Path $tempRoot "node-b-durable-reopen.stderr.log"
        $quotedDurableArgs = $durableArgs.ToArray() | ForEach-Object { ConvertTo-QuotedArgument "$_" }
        $nodeProcess = Start-Process -FilePath $nodeExe -ArgumentList $quotedDurableArgs -PassThru -WindowStyle Hidden -RedirectStandardOutput $durableOut -RedirectStandardError $durableErr
        $durableStatus = $null
        for ($attempt = 0; $attempt -lt 180; $attempt++) {
            $nodeProcess.Refresh()
            if ($nodeProcess.HasExited) {
                throw "Node B exited during durable reopen. STDERR=$(Get-Content -LiteralPath $durableErr -Raw -ErrorAction SilentlyContinue)"
            }
            $durableText = Get-Content -LiteralPath $durableOut -Raw -ErrorAction SilentlyContinue
            if ($durableText -match "qrun_pow_local_rpc_ready" -and
                $durableText -match "qrun_reference_time_ready source=ed25519-attested-time-v1 provenance=ConfiguredProvider") {
                try { $durableStatus = Invoke-RestMethod -Method Get -Uri "http://127.0.0.1:49339/v1/status" -TimeoutSec 5 } catch {}
                if ($durableStatus) { break }
            }
            Start-Sleep -Seconds 1
        }
        if (-not $durableStatus -or
            [uint64]$durableStatus.height -ne 2 -or
            $durableStatus.mainnet -ne $false -or
            $durableStatus.network_id -ne $NetworkIdHex.ToLowerInvariant() -or
            $durableStatus.profile_id -ne $startupProfileId -or
            $durableStatus.tip -ne $reorgStatus.tip -or
            $durableStatus.state_root -ne $reorgStatus.state_root) {
            throw "Node B durable reopen did not preserve the post-reorg canonical tip and state root."
        }
        $durableOrphan = Invoke-RestMethod -Method Get -Uri "http://127.0.0.1:49339/v1/transaction/$partitionTxid" -TimeoutSec 5
        $durableOwner = Invoke-RestMethod -Method Get -Uri "http://127.0.0.1:49339/v1/balance/$OwnerAccountIdHex" -TimeoutSec 5
        $durableA1 = Invoke-RestMethod -Method Get -Uri ("http://127.0.0.1:49339/v1/balance/" + ("78" * 32)) -TimeoutSec 5
        $durableA2 = Invoke-RestMethod -Method Get -Uri ("http://127.0.0.1:49339/v1/balance/" + ("7a" * 32)) -TimeoutSec 5
        $durableB = Invoke-RestMethod -Method Get -Uri ("http://127.0.0.1:49339/v1/balance/" + ("79" * 32)) -TimeoutSec 5
        if ($durableOrphan.status -ne "not_found_in_canonical_chain" -or
            [uint64]$durableOwner.nonce -ne 2 -or
            [uint64]$durableOwner.balance_atoms -ne 999999999999996000 -or
            [uint64]$durableA1.balance_atoms -ne 1000 -or
            [uint64]$durableA2.balance_atoms -ne 3000 -or
            [uint64]$durableB.balance_atoms -ne 0) {
            throw "Node B durable reopen restored a stale receipt or incorrect canonical ledger."
        }

        Write-Host "CROSS_HOST_DURABLE_REOPEN_AFTER_REORG=PASS"
        Write-Host "CROSS_HOST_PARTITION_RECONNECT_REORG=PASS"
        Write-Host "node_b_final_height=$($durableStatus.height)"
        Write-Host "node_b_final_tip=$($durableStatus.tip)"
        Write-Host "node_b_final_state_root=$($durableStatus.state_root)"
        Write-Host "partition_orphaned_tx=$partitionTxid"
        Write-Host "mainnet=false"
        return
    }

    Write-Host "=== Submit one signed QZTS/1 test transaction to Node B loopback ingress ==="
    $submitOutput = & $smokeExe submit --network-id-hex $NetworkIdHex --address "127.0.0.1:49340" 2>&1
    $submitExit = $LASTEXITCODE
    if ($submitExit -ne 0) {
        throw "Node B signed QZTS/1 submission/PoW failed (exit=$submitExit): $($submitOutput -join ' ')"
    }
    $txidLine = $submitOutput | Where-Object { "$_" -match "^transaction_id=" } | Select-Object -First 1
    $statusLine = $submitOutput | Where-Object { "$_" -match "^qzts_status=" } | Select-Object -First 1
    $crossHostTxid = ("$txidLine" -replace "^transaction_id=", "").Trim()
    $qztsStatus = ("$statusLine" -replace "^qzts_status=", "").Trim()
    if ($crossHostTxid -notmatch '^[0-9a-fA-F]{64}$' -or $qztsStatus -ne "Accepted") {
        throw "Node B did not return an Accepted QZTA/1 acknowledgement for the signed cross-host transaction."
    }

    $ownerBalance = $null
    $recipientBalance = $null
    $txReceipt = $null
    for ($attempt = 0; $attempt -lt 90; $attempt++) {
        try {
            $statusJson = Invoke-RestMethod -Method Get -Uri "http://127.0.0.1:49339/v1/status" -TimeoutSec 5
            $txReceipt = Invoke-RestMethod -Method Get -Uri "http://127.0.0.1:49339/v1/transaction/$crossHostTxid" -TimeoutSec 5
            $ownerBalance = Invoke-RestMethod -Method Get -Uri "http://127.0.0.1:49339/v1/balance/$OwnerAccountIdHex" -TimeoutSec 5
            $testRecipient = ("78" * 32)
            $recipientBalance = Invoke-RestMethod -Method Get -Uri "http://127.0.0.1:49339/v1/balance/$testRecipient" -TimeoutSec 5
            if ([uint64]$statusJson.height -ge 1 -and
                $txReceipt.status -eq "confirmed" -and
                [uint64]$ownerBalance.nonce -eq 1 -and
                [uint64]$recipientBalance.balance_atoms -eq 1000) {
                break
            }
        } catch {}
        Start-Sleep -Seconds 1
    }
    if ([uint64]$statusJson.height -ne 1 -or
        $txReceipt.status -ne "confirmed" -or
        [uint64]$ownerBalance.nonce -ne 1 -or
        [uint64]$recipientBalance.balance_atoms -ne 1000) {
        throw "Node B did not reach canonical height 1 with the signed transaction receipt and expected owner/recipient balances."
    }
    if ($statusJson.network_id -ne $NetworkIdHex.ToLowerInvariant() -or $statusJson.profile_id -ne $startupProfileId) {
        throw "Node B network/profile identity changed during cross-host block gossip."
    }

    # A successful broadcast marker is written only after Node A's authenticated QRA5
    # response passed its block-height/hash/status checks. The receiver returns a reject
    # status for invalid blocks, so this is evidence of independent remote validation.
    $nodeBLog = Get-Content -LiteralPath $stdoutPath -Raw -ErrorAction SilentlyContinue
    $expectedBroadcast = "qrun_pow_local_block_broadcast peer=$($NodeAOverlayIp):49341"
    if (-not $nodeBLog.Contains($expectedBroadcast)) {
        throw "Node B did not record a successful authenticated block ACK from Node A."
    }
    if ($nodeBLog -match [regex]::Escape("qrun_pow_local_block_broadcast_failed peer=$($NodeAOverlayIp):49341")) {
        throw "Node B recorded a failed authenticated block broadcast to Node A."
    }
    $expectedIngress = "qrun_pow_local_tx_ingress accepted_pow_candidate txid=$crossHostTxid height=1 canonical_height=1"
    if (-not $nodeBLog.Contains($expectedIngress)) {
        throw "Node B did not log the signed transaction as canonically included in its height-1 candidate."
    }

    if ($StageFullDuplex) {
        Write-Host "=== Stage D1: wait for Node A-originated reciprocal QFP5 block ==="
        $reverseDeadline = [DateTimeOffset]::UtcNow.AddSeconds(900)
        $reverseReceived = $false
        while ([DateTimeOffset]::UtcNow -lt $reverseDeadline) {
            try {
                $reverseStatus = Invoke-RestMethod -Method Get -Uri "http://127.0.0.1:49339/v1/status" -TimeoutSec 5
                $reverseOwner = Invoke-RestMethod -Method Get -Uri "http://127.0.0.1:49339/v1/balance/$OwnerAccountIdHex" -TimeoutSec 5
                $reverseB = Invoke-RestMethod -Method Get -Uri ("http://127.0.0.1:49339/v1/balance/" + ("78" * 32)) -TimeoutSec 5
                $reverseA = Invoke-RestMethod -Method Get -Uri ("http://127.0.0.1:49339/v1/balance/" + ("7a" * 32)) -TimeoutSec 5
                if ([uint64]$reverseStatus.height -ge 2 -and
                    [uint64]$reverseOwner.nonce -eq 2 -and
                    [uint64]$reverseB.balance_atoms -eq 1000 -and
                    [uint64]$reverseA.balance_atoms -eq 3000) {
                    $reverseReceived = $true
                    break
                }
            } catch {}
            Start-Sleep -Milliseconds 500
        }
        if (-not $reverseReceived) {
            throw "Node B did not receive Node A's reciprocal block and canonical ledger update within 900 seconds."
        }
        if ($reverseStatus.network_id -ne $NetworkIdHex.ToLowerInvariant() -or
            $reverseStatus.profile_id -ne $startupProfileId -or
            $reverseStatus.mainnet -ne $false) {
            throw "Node B network/profile identity changed during reciprocal full-duplex gossip."
        }
        Write-Host "D1_NODE_A_TO_NODE_B_RECIPROCAL_BLOCK=PASS"
        Write-Host "D1_BOTH_DIRECTIONS_CANONICAL_LEDGER=PASS"
        Write-Host "D1_NODE_B_FINAL_HEIGHT=$($reverseStatus.height)"
        Write-Host "D1_NODE_B_FINAL_TIP=$($reverseStatus.tip)"
        Write-Host "D1_NODE_B_FINAL_STATE_ROOT=$($reverseStatus.state_root)"
    }

    Write-Host "CROSS_HOST_SIGNED_QZTS_TX_ACCEPTED=PASS"
    Write-Host "CROSS_HOST_NODE_B_CANONICAL_RECEIPT=PASS"
    Write-Host "CROSS_HOST_NODE_B_RECIPIENT_BALANCE=PASS"
    Write-Host "CROSS_HOST_NOISE_QFP5_BLOCK_GOSSIP_NODE_A_ACK=PASS"
    Write-Host "cross_host_transaction_id=$crossHostTxid"
    Write-Host "cross_host_canonical_height=$($statusJson.height)"
    Write-Host "cross_host_canonical_tip=$($statusJson.tip)"
    Write-Host "cross_host_state_root=$($statusJson.state_root)"
    Write-Host "mainnet=false"
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
    if ($partitionRuleName) {
        Remove-NetFirewallRule -DisplayName $partitionRuleName -ErrorAction SilentlyContinue
    }
    if ($nodeProcess -and -not $nodeProcess.HasExited) {
        Stop-Process -Id $nodeProcess.Id -Force -ErrorAction SilentlyContinue
        Wait-Process -Id $nodeProcess.Id -Timeout 10 -ErrorAction SilentlyContinue
    }
    if ($netbirdConnected -and (Test-Path $netbirdExe)) {
        & $netbirdExe down 2>&1 | Out-Null
    }
    Remove-Item Env:NB_SETUP_KEY -ErrorAction SilentlyContinue
    Remove-Item Env:NETBIRD_SETUP_KEY -ErrorAction SilentlyContinue
    Remove-Item Env:QRUN_PEER_BOOTSTRAP_TOKEN -ErrorAction SilentlyContinue
    if (Test-Path $tempRoot) {
        Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}
