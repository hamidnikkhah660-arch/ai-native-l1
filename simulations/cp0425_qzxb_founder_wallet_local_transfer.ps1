$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repo = Split-Path -Parent $PSScriptRoot
Set-Location $repo
$manifest = '.\src\native\pow_bench\Cargo.toml'
$null = cargo +stable build --release --manifest-path $manifest --bin devnet_node --bin noise_key_provisioner --bin qzxb_wallet --quiet
if ($LASTEXITCODE -ne 0) { throw 'CP-0425 QZBE continuous-mining release build failed' }
$null = cargo +stable test --manifest-path $manifest --bin qzxb_wallet --locked --quiet
if ($LASTEXITCODE -ne 0) { throw 'CP-0425 native wallet unit tests failed' }
Write-Host 'CP-0425 WALLET_UNIT_TESTS_PASS'

$nodeExe = (Resolve-Path '.\src\native\pow_bench\target\release\devnet_node.exe').Path
$keyExe = (Resolve-Path '.\src\native\pow_bench\target\release\noise_key_provisioner.exe').Path
$walletExe = (Resolve-Path '.\src\native\pow_bench\target\release\qzxb_wallet.exe').Path
$root = Join-Path $env:TEMP ("ain1_cp0425_qzbe_continuous_" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $root | Out-Null

function Get-FreePort {
    $listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
    $listener.Start()
    $port = [int]$listener.LocalEndpoint.Port
    $listener.Stop()
    return $port
}
function Get-Text([string]$Path) {
    if (Test-Path -LiteralPath $Path) { return Get-Content -LiteralPath $Path -Raw -ErrorAction SilentlyContinue }
    return ''
}
function Wait-Pattern([string]$Path, [string]$Pattern, [int]$Millis = 20000) {
    $watch = [Diagnostics.Stopwatch]::StartNew()
    while ($watch.ElapsedMilliseconds -lt $Millis) {
        if ((Get-Text $Path) -match $Pattern) { return $true }
        Start-Sleep -Milliseconds 50
    }
    return $false
}
function Provision-Key([string]$Path, [string]$Network) {
    $out = @(& $keyExe --output $Path --network-id-hex $Network 2>&1)
    if ($LASTEXITCODE -ne 0) { throw ("CP-0425 Noise key provisioning failed: " + ($out -join [Environment]::NewLine)) }
    $match = [regex]::Match(($out -join [Environment]::NewLine), 'noise_static_public_key_hex=([0-9a-f]{64})')
    if (-not $match.Success) { throw ("CP-0425 Noise public key missing: " + ($out -join [Environment]::NewLine)) }
    return $match.Groups[1].Value
}

$network = 'd4' * 32
$recipient = '44' * 32
$walletPath = Join-Path $root 'founder-test.qzw1'
$walletCreate = @(& $walletExe create --output $walletPath 2>&1)
if ($LASTEXITCODE -ne 0) { throw ("CP-0425 temporary wallet creation failed: " + ($walletCreate -join [Environment]::NewLine)) }
$walletOutput = @(& $walletExe address --wallet $walletPath 2>&1)
if ($LASTEXITCODE -ne 0) { throw ("CP-0425 temporary wallet could not be reopened: " + ($walletOutput -join [Environment]::NewLine)) }
$walletText = $walletOutput -join [Environment]::NewLine
$pubMatch = [regex]::Match($walletText, 'public_key_hex=([0-9a-f]{64})')
$ownerMatch = [regex]::Match($walletText, 'account_id_hex=([0-9a-f]{64})')
if (-not ($pubMatch.Success -and $ownerMatch.Success)) { throw ("CP-0425 wallet public identity fields missing: " + $walletText) }
$txPublicKey = $pubMatch.Groups[1].Value
$owner = $ownerMatch.Groups[1].Value
$txAmountAtoms = '10000000000000000'
$txFeeAtoms = '1'
$txExpiresAt = '4102444800'
$txOutput = @(& $walletExe sign-transfer --wallet $walletPath --network-id-hex $network --recipient-id-hex $recipient --nonce 1 --amount-atoms $txAmountAtoms --fee-atoms $txFeeAtoms --expires-at $txExpiresAt 2>&1)
if ($LASTEXITCODE -ne 0) { throw ("CP-0425 founder transfer signing failed: " + ($txOutput -join [Environment]::NewLine)) }
$txText = $txOutput -join [Environment]::NewLine
$sigMatch = [regex]::Match($txText, 'tx_signature_hex=([0-9a-f]{128})')
if (-not $sigMatch.Success) { throw ("CP-0425 transaction signature missing: " + $txText) }
$txSignature = $sigMatch.Groups[1].Value

$miner = '33' * 32
$observe = '44' * 32
$subsidy = '35673515981'
$halving = '4204800'
$keyA = Join-Path $root 'node-a.npk1'
$keyB = Join-Path $root 'node-b.npk1'
$pubA = Provision-Key $keyA $network
$pubB = Provision-Key $keyB $network
$dataA = Join-Path $root 'node-a-data'
$dataB = Join-Path $root 'node-b-data'
$logA = Join-Path $root 'node-a.err.log'
$stdA = Join-Path $root 'node-a.out.log'
$logB = Join-Path $root 'node-b.err.log'
$stdB = Join-Path $root 'node-b.out.log'
$portA = Get-FreePort
$portB = Get-FreePort
while ($portB -eq $portA) { $portB = Get-FreePort }
$addrA = "127.0.0.1:$portA"
$addrB = "127.0.0.1:$portB"
$nodeA = $null
$nodeB = $null

try {
    $argsA = @(
        '--qzbe-v04-peer-smoke',
        '--network-id', $network, '--owner-id', $owner, '--miner-id', $miner,
        '--tx-public-key-hex', $txPublicKey, '--observe-account-id', $observe,
        '--tx-recipient-id', $recipient, '--tx-nonce', '1',
        '--tx-amount-atoms', $txAmountAtoms, '--tx-fee-atoms', $txFeeAtoms,
        '--tx-expires-at', $txExpiresAt, '--tx-signature-hex', $txSignature,
        '--initial-subsidy-atoms', $subsidy, '--blocks-per-halving', $halving,
        '--data-dir', $dataA, '--listen', $addrA,
        '--trusted-peer-key-hex', $pubB,
        '--noise-static-private-key-dpapi-file', $keyA,
        '--mine-blocks', '0', '--run-seconds', '3600', '--stop-after-height', '2'
    )
    $nodeA = Start-Process -FilePath $nodeExe -ArgumentList $argsA -RedirectStandardOutput $stdA -RedirectStandardError $logA -PassThru
    if (-not (Wait-Pattern $logA 'event=qzbe_v04_peer_smoke_ready .*mining_mode=bounded .*local_only=true public_launch_approved=false' 20000)) {
        throw ("CP-0425 receiver did not become ready: " + (Get-Text $stdA) + (Get-Text $logA))
    }

    $argsB = @(
        '--qzbe-v04-peer-smoke',
        '--network-id', $network, '--owner-id', $owner, '--miner-id', $miner,
        '--tx-public-key-hex', $txPublicKey, '--observe-account-id', $observe,
        '--tx-recipient-id', $recipient, '--tx-nonce', '1',
        '--tx-amount-atoms', $txAmountAtoms, '--tx-fee-atoms', $txFeeAtoms,
        '--tx-expires-at', $txExpiresAt, '--tx-signature-hex', $txSignature,
        '--initial-subsidy-atoms', $subsidy, '--blocks-per-halving', $halving,
        '--data-dir', $dataB, '--listen', $addrB,
        '--peer', $addrA, '--trusted-peer-key-hex', $pubA,
        '--noise-static-private-key-dpapi-file', $keyB,
        '--mine-forever', '--stop-after-height', '2'
    )
    $nodeB = Start-Process -FilePath $nodeExe -ArgumentList $argsB -RedirectStandardOutput $stdB -RedirectStandardError $logB -PassThru
    if (-not (Wait-Pattern $logB 'event=qzbe_v04_peer_smoke_stopped .*height=2 .*replay=matched' 3600000)) {
        throw ("CP-0425 continuous miner did not stop cleanly at height 2: " + (Get-Text $stdB) + (Get-Text $logB))
    }
    if (-not (Wait-Pattern $logA 'event=qzbe_v04_peer_smoke_stopped .*height=2 .*replay=matched' 3600000)) {
        throw ("CP-0425 receiver did not converge/replay at height 2: " + (Get-Text $stdA) + (Get-Text $logA))
    }
    Wait-Process -Id $nodeA.Id -Timeout 15 -ErrorAction SilentlyContinue
    Wait-Process -Id $nodeB.Id -Timeout 15 -ErrorAction SilentlyContinue
    $activeA = Get-Process -Id $nodeA.Id -ErrorAction SilentlyContinue
    $activeB = Get-Process -Id $nodeB.Id -ErrorAction SilentlyContinue
    if ($null -ne $activeA) {
        throw ("CP-0425 receiver stayed alive after its stop event (pid=$($nodeA.Id)): " + (Get-Text $logA))
    }
    if ($null -ne $activeB) {
        throw ("CP-0425 miner stayed alive after its stop event (pid=$($nodeB.Id)): " + (Get-Text $logB))
    }
    if ((Get-Text $logA) -match 'event=devnet_qzbe_v04_dispatch_failed|panicked at' -or
        (Get-Text $logB) -match 'event=devnet_qzbe_v04_dispatch_failed|panicked at') {
        throw ("CP-0425 node failure marker found: " + (Get-Text $logA) + (Get-Text $logB))
    }

    $finalA = [regex]::Match((Get-Text $logA), 'event=qzbe_v04_peer_smoke_stopped .*height=2 state_root=([0-9a-f]{64}) tip=([0-9a-f]{64}).*replay=matched')
    $finalB = [regex]::Match((Get-Text $logB), 'event=qzbe_v04_peer_smoke_stopped .*height=2 state_root=([0-9a-f]{64}) tip=([0-9a-f]{64}).*replay=matched')
    if (-not ($finalA.Success -and $finalB.Success)) { throw 'CP-0425 final snapshots are missing canonical height/root/tip.' }
    if ($finalA.Groups[1].Value -ne $finalB.Groups[1].Value -or $finalA.Groups[2].Value -ne $finalB.Groups[2].Value) {
        throw 'CP-0425 receiver/miner canonical state did not converge.'
    }
    if ((Get-Text $logA) -notmatch ("observed_balance_atoms=" + $txAmountAtoms)) { throw ("CP-0425 recipient balance mismatch at receiver: " + (Get-Text $logA)) }
    if ((Get-Text $logB) -notmatch ("observed_balance_atoms=" + $txAmountAtoms)) { throw ("CP-0425 recipient balance mismatch at miner: " + (Get-Text $logB)) }
    Write-Host 'CP-0425 FOUNDER_GENESIS_ALLOCATION_AND_LOCAL_TRANSFER_PASS'
    Write-Host 'CP-0425 TRANSFERRED_TEST_QZXB_COINS=100000000'
    Write-Host ("CP-0425 FOUNDER_ACCOUNT_ID=" + $owner)
    Write-Host ("CP-0425 RECIPIENT_BALANCE_ATOMS=" + $txAmountAtoms)
    Write-Host 'CP-0425 CONTINUOUS_MINING_HEIGHT_2_PASS'
    Write-Host 'CP-0425 TWO_NODE_RESTART_REPLAY_CONVERGENCE_PASS'
}
finally {
    foreach ($proc in @($nodeA, $nodeB)) {
        if ($null -ne $proc) {
            $proc.Refresh()
            if (-not $proc.HasExited) { Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue }
        }
    }
    Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
}
