[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$PublicConfigPath,
    [switch]$ConfirmBootstrapAclRestricted,
    [switch]$PublishBootstrapSecret,
    [int]$BootstrapTimeoutSeconds = 900,
    [int]$TransactionTimeoutSeconds = 900
)

$ErrorActionPreference = "Stop"
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$bootstrapScript = Join-Path $PSScriptRoot "qrun-v05-netbird-peer-bootstrap.ps1"
$smokeExe = Join-Path $repoRoot "src/native/pow_bench/target/release/qrun_v05_public_alpha_process_smoke.exe"
$nodeExe = Join-Path $repoRoot "src/native/pow_bench/target/release/qrun_v05_pow_local_node.exe"
$netbirdExe = "C:\Program Files\NetBird\netbird.exe"
$serverProcess = $null
$newNodeProcess = $null
$firewallRuleName = $null
$oldNodeStopped = $false
$bootstrapComplete = $false
$tokenFile = $null
$recordFile = $null
$ackFile = $null
$root = $null
$cfg = $null
$baseNodeArgs = @()

function ConvertTo-QuotedArgument([string]$Value) {
    return '"' + $Value.Replace('"', '\"') + '"'
}

function Assert-OverlayIPv4([string]$Name, [string]$Value) {
    $ip = [System.Net.IPAddress]::Parse($Value)
    if ($ip.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) {
        throw "$Name must be IPv4."
    }
    $bytes = $ip.GetAddressBytes()
    if ($bytes[0] -ne 100 -or $bytes[1] -lt 64 -or $bytes[1] -gt 127) {
        throw "$Name is outside the NetBird overlay range."
    }
    return $ip.ToString()
}

function Assert-Hex32([string]$Name, [string]$Value) {
    if ($Value -notmatch '^[0-9a-fA-F]{64}$' -or $Value -match '^0{64}$') {
        throw "$Name must be a nonzero 32-byte hexadecimal value."
    }
}

function Start-QRunNode([string[]]$Arguments, [string]$StdoutPath, [string]$StderrPath) {
    $quoted = $Arguments | ForEach-Object { ConvertTo-QuotedArgument $_ }
    return Start-Process -FilePath $nodeExe -ArgumentList $quoted -PassThru -WindowStyle Hidden -RedirectStandardOutput $StdoutPath -RedirectStandardError $StderrPath
}

function Get-NodeStatus {
    return Invoke-RestMethod -Method Get -Uri "http://127.0.0.1:49339/v1/status" -TimeoutSec 5
}

function Get-Balance([string]$Account) {
    return Invoke-RestMethod -Method Get -Uri "http://127.0.0.1:49339/v1/balance/$Account" -TimeoutSec 5
}

function Restore-NodeAWithoutPeer {
    if (-not $oldNodeStopped -or -not $cfg) { return }
    if ($newNodeProcess) {
        try {
            $newNodeProcess.Refresh()
            if (-not $newNodeProcess.HasExited) {
                Stop-Process -Id $newNodeProcess.Id -Force -ErrorAction SilentlyContinue
                Wait-Process -Id $newNodeProcess.Id -Timeout 10 -ErrorAction SilentlyContinue
            }
        } catch {}
    }
    $out = Join-Path $root "node-a-bootstrap-rollback.stdout.log"
    $err = Join-Path $root "node-a-bootstrap-rollback.stderr.log"
    $rollback = Start-QRunNode -Arguments $baseNodeArgs -StdoutPath $out -StderrPath $err
    Set-Content -LiteralPath (Join-Path $root "node-a.pid") -Value $rollback.Id -Encoding ASCII
    Write-Output "NODE_A_BASELINE_ROLLBACK_STARTED_PID=$($rollback.Id)"
}

try {
    if (-not $ConfirmBootstrapAclRestricted) {
        throw "Refusing D1 enrollment until the NetBird policy has been independently verified to allow port 49342 only from the dedicated temporary Node B group."
    }
    if (-not (Test-Path -LiteralPath $PublicConfigPath -PathType Leaf)) {
        throw "Public Node A configuration file is missing."
    }
    foreach ($path in @($bootstrapScript, $smokeExe, $nodeExe, $netbirdExe)) {
        if (-not (Test-Path -LiteralPath $path)) { throw "Required QRun/NetBird file is missing: $path" }
    }

    $configPath = (Resolve-Path -LiteralPath $PublicConfigPath).Path
    $cfg = Get-Content -LiteralPath $configPath -Raw | ConvertFrom-Json
    $root = [IO.Path]::GetFullPath([string]$cfg.local_secure_root)
    $allowedRoot = [IO.Path]::GetFullPath((Join-Path $env:LOCALAPPDATA "QRun")) + [IO.Path]::DirectorySeparatorChar
    if (-not $root.StartsWith($allowedRoot, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing to operate outside the dedicated QRun secure root."
    }
    $nodeAIp = Assert-OverlayIPv4 "Node A overlay IP" ([string]$cfg.node_a_overlay_ip)
    Assert-Hex32 "Network ID" ([string]$cfg.network_id_hex)
    Assert-Hex32 "Owner account" ([string]$cfg.owner_account_id_hex)
    Assert-Hex32 "Owner public key" ([string]$cfg.owner_public_key_hex)
    Assert-Hex32 "Node A Noise public key" ([string]$cfg.node_a_noise_public_key_hex)
    Assert-Hex32 "Reference-time admin public key" ([string]$cfg.reference_time_admin_public_key_hex)
    if ($cfg.mainnet -ne $false) { throw "D1 controller accepts Public Alpha only; mainnet must be false." }

    $nodeData = [IO.Path]::GetFullPath([string]$cfg.node_a_data_dir)
    if (-not $nodeData.StartsWith($root + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Node A data directory is outside the dedicated secure root."
    }
    $noiseKey = Join-Path $root "node-a.npk1"
    $policyFile = Join-Path $root "public-alpha.rtp1"
    $referenceState = Join-Path $root "node-a-reference-time.rts1"
    foreach ($path in @($noiseKey, $policyFile, $referenceState, $nodeData)) {
        if (-not (Test-Path -LiteralPath $path)) { throw "Required persistent Node A path is missing: $path" }
    }

    $tokenFile = Join-Path $root "peer-bootstrap-token.dpapi"
    if (-not (Test-Path -LiteralPath $tokenFile)) {
        if (-not $PublishBootstrapSecret) {
            throw "Bootstrap token is absent. Run with -PublishBootstrapSecret to create a DPAPI token and publish the matching Actions secret."
        }
        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $bootstrapScript -Mode Generate -TokenFile $tokenFile -PublishGitHubSecret
        if ($LASTEXITCODE -ne 0) { throw "Bootstrap token generation or GitHub secret publication failed." }
    }
    elseif ($PublishBootstrapSecret) {
        throw "A protected bootstrap token already exists. Refusing to silently rotate it while GitHub may hold a different value."
    }

    $recordFile = Join-Path $root "peer-enrollment.json"
    $ackFile = Join-Path $root "peer-enrollment.ack"
    $serverOut = Join-Path $root "peer-bootstrap-server.stdout.log"
    $serverErr = Join-Path $root "peer-bootstrap-server.stderr.log"
    foreach ($path in @($recordFile, $ackFile)) {
        if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path -Force }
    }

    $firewallRuleName = "QRun-D1-PeerBootstrap-" + [guid]::NewGuid().ToString("N")
    New-NetFirewallRule -DisplayName $firewallRuleName -Direction Inbound -Action Allow -Protocol TCP -LocalAddress $nodeAIp -LocalPort 49342 -RemoteAddress "100.64.0.0/10" -Profile Any -Enabled True | Out-Null
    Write-Output "D1_BOOTSTRAP_FIREWALL_TEMPORARY_SCOPE=PASS"

    $serverArgs = @(
        "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $bootstrapScript,
        "-Mode", "Serve",
        "-TokenFile", $tokenFile,
        "-OutputFile", $recordFile,
        "-AckFile", $ackFile,
        "-BindIp", $nodeAIp,
        "-NetworkIdHex", ([string]$cfg.network_id_hex),
        "-TimeoutSeconds", ([string]$BootstrapTimeoutSeconds)
    )
    $serverQuoted = $serverArgs | ForEach-Object { ConvertTo-QuotedArgument $_ }
    $serverProcess = Start-Process -FilePath (Join-Path $PSHOME "powershell.exe") -ArgumentList $serverQuoted -PassThru -WindowStyle Hidden -RedirectStandardOutput $serverOut -RedirectStandardError $serverErr

    $listenerReady = $false
    $listenerDeadline = [DateTimeOffset]::UtcNow.AddSeconds(30)
    while ([DateTimeOffset]::UtcNow -lt $listenerDeadline) {
        $serverProcess.Refresh()
        if ($serverProcess.HasExited) {
            throw "Bootstrap listener process exited early. STDERR=$(Get-Content $serverErr -Raw -ErrorAction SilentlyContinue)"
        }
        $serverText = Get-Content -LiteralPath $serverOut -Raw -ErrorAction SilentlyContinue
        if ($serverText -match "PEER_BOOTSTRAP_LISTENER_READY=") {
            $listenerReady = $true
            break
        }
        Start-Sleep -Milliseconds 200
    }
    if (-not $listenerReady) { throw "Node A bootstrap listener did not become ready." }
    Write-Output "D1_BOOTSTRAP_LISTENER_READY=PASS"

    $enrollmentDeadline = [DateTimeOffset]::UtcNow.AddSeconds($BootstrapTimeoutSeconds)
    while ([DateTimeOffset]::UtcNow -lt $enrollmentDeadline) {
        $serverProcess.Refresh()
        if ($serverProcess.HasExited) {
            throw "Bootstrap server exited before peer enrollment was received. STDERR=$(Get-Content $serverErr -Raw -ErrorAction SilentlyContinue)"
        }
        if (Test-Path -LiteralPath $recordFile -PathType Leaf) { break }
        Start-Sleep -Milliseconds 250
    }
    if (-not (Test-Path -LiteralPath $recordFile -PathType Leaf)) {
        throw "Timed out waiting for authenticated Node B peer metadata."
    }

    $peer = Get-Content -LiteralPath $recordFile -Raw | ConvertFrom-Json
    if ([int]$peer.protocol_version -ne 1 -or
        $peer.network_id_hex -ne ([string]$cfg.network_id_hex).ToLowerInvariant() -or
        $peer.node_a_overlay_ip -ne $nodeAIp -or
        $peer.source_ip_verified -ne $true) {
        throw "Received peer metadata failed Node A's local identity checks."
    }
    $nodeBIp = Assert-OverlayIPv4 "Node B overlay IP" ([string]$peer.node_b_overlay_ip)
    Assert-Hex32 "Node B Noise public key" ([string]$peer.node_b_noise_public_key_hex)
    Write-Output "D1_NODE_B_PUBLIC_METADATA_VALIDATED=PASS"

    $pidPath = Join-Path $root "node-a.pid"
    if (-not (Test-Path -LiteralPath $pidPath -PathType Leaf)) { throw "Node A process PID marker is missing." }
    $oldPid = [int](Get-Content -LiteralPath $pidPath -Raw).Trim()
    $oldProcess = Get-CimInstance Win32_Process -Filter "ProcessId = $oldPid" -ErrorAction Stop
    if (-not $oldProcess -or
        $oldProcess.ExecutablePath -ne $nodeExe -or
        $oldProcess.CommandLine -notlike "*$nodeData*") {
        throw "Refusing to stop a process that does not match the recorded Node A executable and data directory."
    }

    $baseNodeArgs = @(
        "--public-alpha",
        "--network-id-hex", ([string]$cfg.network_id_hex),
        "--owner-account-id-hex", ([string]$cfg.owner_account_id_hex),
        "--owner-public-key-hex", ([string]$cfg.owner_public_key_hex),
        "--genesis-time-unix-secs", ([string]$cfg.genesis_time_unix_secs),
        "--data-dir", $nodeData,
        "--rpc-listen", "127.0.0.1:49339",
        "--tx-listen", "127.0.0.1:49340",
        "--block-listen", ($nodeAIp + ":49341"),
        "--noise-private-key-file", $noiseKey,
        "--reference-time-policy-file", $policyFile,
        "--reference-time-admin-public-key-hex", ([string]$cfg.reference_time_admin_public_key_hex),
        "--reference-time-address", ($nodeAIp + ":49550"),
        "--reference-time-state-file", $referenceState
    )

    Stop-Process -Id $oldPid -Force -ErrorAction Stop
    Wait-Process -Id $oldPid -Timeout 15 -ErrorAction SilentlyContinue
    if (Get-Process -Id $oldPid -ErrorAction SilentlyContinue) {
        throw "Node A's original process did not exit; refusing to start a second process against the same durable data directory."
    }
    $oldNodeStopped = $true
    Write-Output "D1_NODE_A_CONTROLLED_RESTART=PASS"

    $duplexArgs = @($baseNodeArgs) + @(
        "--peer", ($nodeBIp + ":49341"),
        "--peer-static-public-key-hex", ([string]$peer.node_b_noise_public_key_hex),
        "--sync-on-start", "true"
    )
    $nodeOut = Join-Path $root "node-a-duplex.stdout.log"
    $nodeErr = Join-Path $root "node-a-duplex.stderr.log"
    $newNodeProcess = Start-QRunNode -Arguments $duplexArgs -StdoutPath $nodeOut -StderrPath $nodeErr
    Set-Content -LiteralPath $pidPath -Value $newNodeProcess.Id -Encoding ASCII

    $syncVerified = $false
    $status = $null
    $startupDeadline = [DateTimeOffset]::UtcNow.AddSeconds(240)
    while ([DateTimeOffset]::UtcNow -lt $startupDeadline) {
        $newNodeProcess.Refresh()
        if ($newNodeProcess.HasExited) {
            throw "Restarted Node A exited. STDERR=$(Get-Content $nodeErr -Raw -ErrorAction SilentlyContinue)"
        }
        $stdout = Get-Content -LiteralPath $nodeOut -Raw -ErrorAction SilentlyContinue
        if ($stdout -match [regex]::Escape("qrun_pow_authenticated_startup_sync_complete peer=$($nodeBIp):49341") -and
            $stdout -match "qrun_reference_time_ready source=ed25519-attested-time-v1 provenance=ConfiguredProvider" -and
            $stdout -match "network_class=public_alpha_experimental_not_mainnet" -and
            $stdout -match "mainnet=false") {
            try { $status = Get-NodeStatus } catch {}
            if ($status) { $syncVerified = $true; break }
        }
        Start-Sleep -Seconds 1
    }
    if (-not $syncVerified) {
        throw "Node A did not prove authenticated startup sync from the exact Node B peer. STDERR=$(Get-Content $nodeErr -Raw -ErrorAction SilentlyContinue)"
    }
    if ($status.network_id -ne ([string]$cfg.network_id_hex).ToLowerInvariant() -or
        $status.profile_id -ne [string]$cfg.qrun_profile_id -or
        $status.mainnet -ne $false) {
        throw "Restarted Node A identity/profile does not match the original Public Alpha configuration."
    }
    Write-Output "D1_NODE_A_REVERSE_STATIC_PIN=PASS"
    Write-Output "D1_NODE_A_AUTHENTICATED_SYNC_FROM_NODE_B=PASS"
    Write-Output "D1_NODE_A_PROFILE_AND_NETWORK_ID_PRESERVED=PASS"
    Set-Content -LiteralPath $ackFile -Value "PASS" -Encoding ASCII

    if (-not $serverProcess.WaitForExit(15000)) {
        throw "Bootstrap server did not close after the Node A reverse-sync acknowledgement."
    }
    $serverText = Get-Content -LiteralPath $serverOut -Raw -ErrorAction SilentlyContinue
    if ($serverText -notmatch "PEER_BOOTSTRAP_ONE_SHOT_COMPLETE=PASS") {
        throw "Bootstrap server did not report one-shot completion."
    }
    $bootstrapComplete = $true
    Remove-Item -LiteralPath $tokenFile -Force -ErrorAction SilentlyContinue
    Write-Output "D1_BOOTSTRAP_TOKEN_REMOVED_FROM_NODE_A=PASS"

    Write-Output "=== Waiting for Node B's first canonical block ==="
    $transactionDeadline = [DateTimeOffset]::UtcNow.AddSeconds($TransactionTimeoutSeconds)
    $heightOne = $false
    while ([DateTimeOffset]::UtcNow -lt $transactionDeadline) {
        $status = Get-NodeStatus
        $owner = Get-Balance ([string]$cfg.owner_account_id_hex)
        $recipientB = Get-Balance ("78" * 32)
        if ([uint64]$status.height -ge 1 -and
            [uint64]$owner.nonce -ge 1 -and
            [uint64]$recipientB.balance_atoms -ge 1000) {
            $heightOne = $true
            break
        }
        Start-Sleep -Milliseconds 500
    }
    if (-not $heightOne) { throw "Node A did not receive and canonically accept Node B's first signed transaction." }
    Write-Output "D1_NODE_B_TO_NODE_A_BLOCK_AND_RECEIPT=PASS"

    $submitNext = & $smokeExe submit-next --network-id-hex ([string]$cfg.network_id_hex) --address "127.0.0.1:49340" 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "Node A's reciprocal signed transaction submission failed: $($submitNext -join ' ')"
    }
    $idLine = $submitNext | Where-Object { "$_" -match "^transaction_id=" } | Select-Object -First 1
    $ackLine = $submitNext | Where-Object { "$_" -match "^qzts_status=" } | Select-Object -First 1
    $nodeATxid = ("$idLine" -replace "^transaction_id=", "").Trim()
    $nodeAAck = ("$ackLine" -replace "^qzts_status=", "").Trim()
    if ($nodeATxid -notmatch '^[0-9a-fA-F]{64}$' -or $nodeAAck -ne "Accepted") {
        throw "Node A did not receive an Accepted acknowledgement for its reciprocal transaction."
    }

    $heightTwo = $false
    $transactionDeadline = [DateTimeOffset]::UtcNow.AddSeconds($TransactionTimeoutSeconds)
    $expectedReverseAck = "qrun_pow_local_block_broadcast peer=$($nodeBIp):49341"
    while ([DateTimeOffset]::UtcNow -lt $transactionDeadline) {
        $status = Get-NodeStatus
        $receipt = Invoke-RestMethod -Method Get -Uri "http://127.0.0.1:49339/v1/transaction/$nodeATxid" -TimeoutSec 5
        $owner = Get-Balance ([string]$cfg.owner_account_id_hex)
        $recipientB = Get-Balance ("78" * 32)
        $recipientA = Get-Balance ("7a" * 32)
        $nodeLog = Get-Content -LiteralPath $nodeOut -Raw -ErrorAction SilentlyContinue
        if ([uint64]$status.height -ge 2 -and
            $receipt.status -eq "confirmed" -and
            [uint64]$owner.nonce -eq 2 -and
            [uint64]$recipientB.balance_atoms -eq 1000 -and
            [uint64]$recipientA.balance_atoms -eq 3000 -and
            $nodeLog.Contains($expectedReverseAck)) {
            $heightTwo = $true
            break
        }
        Start-Sleep -Milliseconds 500
    }
    if (-not $heightTwo) { throw "Node A failed to canonically include its reciprocal transaction and receive Node B's authenticated QFP5 acknowledgement." }

    Write-Output "D1_NODE_A_TO_NODE_B_SIGNED_BLOCK_ORIGIN=PASS"
    Write-Output "D1_NODE_A_RECIPROCAL_RECEIPT=PASS"
    Write-Output "D1_NODE_A_CANONICAL_HEIGHT=$($status.height)"
    Write-Output "D1_NODE_A_CANONICAL_TIP=$($status.tip)"
    Write-Output "D1_NODE_A_STATE_ROOT=$($status.state_root)"
    Write-Output "D1_NODE_A_RECIPROCAL_TXID=$nodeATxid"
    Write-Output "D1_NODE_A_RECEIVED_NODE_B_QFP5_ACK=PASS"
    Write-Output "mainnet=false"
    Write-Output "D1_NODE_A_FULL_DUPLEX_CONTROLLER=PASS"
}
catch {
    if ($ackFile -and (Test-Path -LiteralPath $ackFile)) {
        Set-Content -LiteralPath $ackFile -Value "FAIL" -Encoding ASCII -ErrorAction SilentlyContinue
    }
    if (-not $bootstrapComplete) {
        try { Restore-NodeAWithoutPeer } catch {
            Write-Warning "Node A automatic rollback failed; inspect the dedicated secure root and restart Node A using the original no-peer arguments."
        }
    }
    throw
}
finally {
    if ($serverProcess) {
        try {
            $serverProcess.Refresh()
            if (-not $serverProcess.HasExited) {
                Stop-Process -Id $serverProcess.Id -Force -ErrorAction SilentlyContinue
            }
        } catch {}
    }
    if ($firewallRuleName) {
        Remove-NetFirewallRule -DisplayName $firewallRuleName -ErrorAction SilentlyContinue
    }
    if ($bootstrapComplete) {
        if (Test-Path -LiteralPath $tokenFile) {
            Remove-Item -LiteralPath $tokenFile -Force -ErrorAction SilentlyContinue
        }
        $gh = Get-Command gh -ErrorAction SilentlyContinue
        if ($gh) {
            & $gh.Source secret delete QRUN_PEER_BOOTSTRAP_TOKEN 2>&1 | Out-Null
            if ($LASTEXITCODE -eq 0) {
                Write-Output "D1_GITHUB_BOOTSTRAP_SECRET_DELETED=PASS"
            }
            else {
                Write-Warning "The one-shot GitHub bootstrap secret was not deleted. Remove or rotate QRUN_PEER_BOOTSTRAP_TOKEN manually before another run."
            }
        }
    }
}
