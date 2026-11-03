[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$PublicConfigPath,
    [int]$PeerWaitSeconds = 1200,
    [int]$PeerStabilitySeconds = 15,
    [int]$AfterPeerConnectedSeconds = 120
)

$ErrorActionPreference = "Stop"
$netbirdExe = "C:\Program Files\NetBird\netbird.exe"
$configPath = (Resolve-Path -LiteralPath $PublicConfigPath).Path
$cfg = Get-Content -LiteralPath $configPath -Raw | ConvertFrom-Json
$root = [IO.Path]::GetFullPath([string]$cfg.local_secure_root)
$allowed = [IO.Path]::GetFullPath((Join-Path $env:LOCALAPPDATA "QRun")) + [IO.Path]::DirectorySeparatorChar
if (-not $root.StartsWith($allowed, [StringComparison]::OrdinalIgnoreCase)) {
    throw "Refusing to operate outside the dedicated QRun cross-host temp root."
}
if (-not (Test-Path $netbirdExe)) { throw "NetBird CLI is not installed." }

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$smokeExe = Join-Path $repoRoot "src/native/pow_bench/target/release/qrun_v05_public_alpha_process_smoke.exe"
if (-not (Test-Path $smokeExe)) { throw "Release Public Alpha signer helper is missing: $smokeExe" }

$logPath = Join-Path $root "partition-controller.log"
function Write-Log([string]$Message) {
    $line = "{0} {1}" -f [DateTimeOffset]::UtcNow.ToString("o"), $Message
    Add-Content -LiteralPath $logPath -Value $line -Encoding UTF8
    Write-Host $Message
}
function Get-PeerCounts {
    $text = (& $netbirdExe status 2>&1 | Out-String)
    if ($LASTEXITCODE -ne 0) { throw "NetBird status command failed." }
    $match = [regex]::Match($text, "Peers count:\s+([0-9]+)/([0-9]+)\s+Connected")
    if (-not $match.Success) { throw "Could not parse NetBird peer counts." }
    return [pscustomobject]@{
        Connected = [int]$match.Groups[1].Value
        Total = [int]$match.Groups[2].Value
        Text = $text
    }
}
function Get-NodeStatus {
    return Invoke-RestMethod -Method Get -Uri "http://127.0.0.1:49339/v1/status" -TimeoutSec 5
}
function Get-Tx([string]$Id) {
    return Invoke-RestMethod -Method Get -Uri "http://127.0.0.1:49339/v1/transaction/$Id" -TimeoutSec 5
}
function Get-Balance([string]$Account) {
    return Invoke-RestMethod -Method Get -Uri "http://127.0.0.1:49339/v1/balance/$Account" -TimeoutSec 5
}
function Wait-Height([uint64]$Height, [int]$Seconds) {
    $deadline = [DateTimeOffset]::UtcNow.AddSeconds($Seconds)
    do {
        $status = Get-NodeStatus
        if ([uint64]$status.height -ge $Height) { return $status }
        Start-Sleep -Milliseconds 250
    } while ([DateTimeOffset]::UtcNow -lt $deadline)
    throw "Node A did not reach canonical height $Height."
}
function Submit-Tx([string]$Mode, [string]$Label) {
    $output = & $smokeExe $Mode --network-id-hex ([string]$cfg.network_id_hex) --address "127.0.0.1:49340" 2>&1
    if ($LASTEXITCODE -ne 0) { throw "$Label QZTS submission failed: $($output -join ' ')" }
    $idLine = $output | Where-Object { "$_" -match "^transaction_id=" } | Select-Object -First 1
    $statusLine = $output | Where-Object { "$_" -match "^qzts_status=" } | Select-Object -First 1
    $id = ("$idLine" -replace "^transaction_id=", "").Trim()
    $ack = ("$statusLine" -replace "^qzts_status=", "").Trim()
    if ($id -notmatch "^[0-9a-fA-F]{64}$" -or $ack -ne "Accepted") {
        throw "$Label did not receive an Accepted QZTA/1 acknowledgement."
    }
    Write-Log ($Label + "_TXID=" + $id)
    Write-Log ($Label + "_ACCEPTED=PASS")
    return $id
}

try {
    $initial = Get-NodeStatus
    if ($initial.network_id -ne ([string]$cfg.network_id_hex).ToLowerInvariant() -or
        $initial.profile_id -ne [string]$cfg.qrun_profile_id -or
        [uint64]$initial.height -ne 0 -or $initial.mainnet -ne $false) {
        throw "Node A is not at the expected fresh height-zero Public Alpha identity."
    }

    Write-Log "NODE_A_CONTROLLER_READY=PASS"
    $deadline = [DateTimeOffset]::UtcNow.AddSeconds($PeerWaitSeconds)
    $counts = Get-PeerCounts
    while ($counts.Total -ne 0 -and [DateTimeOffset]::UtcNow -lt $deadline) {
        Start-Sleep -Seconds 5
        $counts = Get-PeerCounts
    }
    if ($counts.Total -ne 0) {
        throw "A previous NetBird peer is still present; wait for its ephemeral cleanup before Stage C2."
    }
    Write-Log "NETBIRD_PRETEST_PEERS_CLEAR=PASS"
    $deadline = [DateTimeOffset]::UtcNow.AddSeconds($PeerWaitSeconds)

    $connected = $false
    while ([DateTimeOffset]::UtcNow -lt $deadline) {
        $counts = Get-PeerCounts
        if ($counts.Total -gt 1) { throw "Unexpected additional NetBird peer appeared during qualification." }
        if ($counts.Total -eq 1 -and $counts.Connected -eq 1) {
            $detail = (& $netbirdExe status -d 2>&1 | Out-String)
            if ($LASTEXITCODE -ne 0 -or $detail -notmatch "Connection type:\s+P2P" -or
                $detail -match "Last WireGuard handshake:\s+-") {
                throw "The single Node B peer is not on a verified direct P2P WireGuard path."
            }
            $connected = $true
            break
        }
        Start-Sleep -Seconds 2
    }
    if (-not $connected) { throw "The single temporary Node B peer did not establish a direct P2P tunnel." }
    for ($stable = 0; $stable -lt $PeerStabilitySeconds; $stable++) {
        $stableCounts = Get-PeerCounts
        if ($stableCounts.Total -ne 1 -or $stableCounts.Connected -ne 1) {
            throw "The Node B peer did not remain connected for the required stability window."
        }
        Start-Sleep -Seconds 1
    }
    Write-Log "NODE_B_NETBIRD_P2P_CONNECTED=PASS"
    Write-Log ("NODE_A_PARTITION_CONTROLLER_DELAY_SECONDS=" + $AfterPeerConnectedSeconds)
    Start-Sleep -Seconds $AfterPeerConnectedSeconds
    $afterDelayCounts = Get-PeerCounts
    if ($afterDelayCounts.Total -ne 1 -or $afterDelayCounts.Connected -ne 1) {
        throw "Node B disconnected before Node A could create its partitioned branch."
    }
    $afterDelayDetail = (& $netbirdExe status -d 2>&1 | Out-String)
    if ($LASTEXITCODE -ne 0 -or $afterDelayDetail -notmatch "Connection type:\s+P2P") {
        throw "NetBird direct P2P connectivity was lost before Node A branch creation."
    }

    $before = Get-NodeStatus
    if ([uint64]$before.height -ne 0 -or
        $before.network_id -ne ([string]$cfg.network_id_hex).ToLowerInvariant() -or
        $before.profile_id -ne [string]$cfg.qrun_profile_id -or
        $before.mainnet -ne $false) {
        throw "Node A changed identity or left the expected fresh Public Alpha Genesis before its partitioned branch was created."
    }

    $identity = & $smokeExe identity 2>&1
    if ($LASTEXITCODE -ne 0) { throw "Could not derive the disposable Public Alpha test identity." }
    $accountLine = $identity | Where-Object { "$_" -match "^owner_account_id_hex=" } | Select-Object -First 1
    $publicLine = $identity | Where-Object { "$_" -match "^owner_public_key_hex=" } | Select-Object -First 1
    $account = ("$accountLine" -replace "^owner_account_id_hex=", "").Trim()
    $public = ("$publicLine" -replace "^owner_public_key_hex=", "").Trim()
    if ($account -ne ([string]$cfg.owner_account_id_hex).ToLowerInvariant() -or
        $public -ne ([string]$cfg.owner_public_key_hex).ToLowerInvariant()) {
        throw "Node A's local test signer does not match the fresh Genesis owner identity."
    }
    Write-Log "NODE_A_TEST_SIGNER_MATCHES_GENESIS=PASS"

    $txA1 = Submit-Tx "submit" "NODE_A_BRANCH_NONCE1"
    $statusA1 = Wait-Height 1 240
    if ((Get-Tx $txA1).status -ne "confirmed") { throw "Node A nonce-1 branch receipt is not canonical." }
    $txA2 = Submit-Tx "submit-next" "NODE_A_BRANCH_NONCE2"
    $statusA2 = Wait-Height 2 300
    if ((Get-Tx $txA2).status -ne "confirmed") { throw "Node A nonce-2 branch receipt is not canonical." }

    $owner = Get-Balance ([string]$cfg.owner_account_id_hex)
    $recipientA1 = Get-Balance ("78" * 32)
    $recipientA2 = Get-Balance ("7a" * 32)
    $recipientB = Get-Balance ("79" * 32)
    if ($statusA2.network_id -ne ([string]$cfg.network_id_hex).ToLowerInvariant() -or
        $statusA2.profile_id -ne [string]$cfg.qrun_profile_id -or
        $statusA2.mainnet -ne $false -or
        [uint64]$owner.nonce -ne 2 -or
        [uint64]$owner.balance_atoms -ne 999999999999996000 -or
        [uint64]$recipientA1.balance_atoms -ne 1000 -or
        [uint64]$recipientA2.balance_atoms -ne 3000 -or
        [uint64]$recipientB.balance_atoms -ne 0) {
        throw "Node A branch ledger invariants failed while the Node B P2P path was scheduled as partitioned."
    }

    Write-Log "CROSS_HOST_PARTITION_NODE_A_BRANCH_HEIGHT2=PASS"
    Write-Log ("NODE_A_CANONICAL_HEIGHT=" + $statusA2.height)
    Write-Log ("NODE_A_CANONICAL_TIP=" + $statusA2.tip)
    Write-Log ("NODE_A_CANONICAL_STATE_ROOT=" + $statusA2.state_root)
    Write-Log ("NODE_A_OWNER_NONCE=" + $owner.nonce)
    Write-Log ("NODE_A_OWNER_BALANCE_ATOMS=" + $owner.balance_atoms)
    Write-Log ("NODE_A_RECIPIENT_78_BALANCE_ATOMS=" + $recipientA1.balance_atoms)
    Write-Log ("NODE_A_RECIPIENT_7A_BALANCE_ATOMS=" + $recipientA2.balance_atoms)
    Write-Log "mainnet=false"
    Write-Log "NODE_A_PARTITION_CONTROLLER=PASS"
}
catch {
    Write-Log "NODE_A_PARTITION_CONTROLLER=FAIL"
    Write-Log ("ERROR=" + $_.Exception.Message)
    throw
}
