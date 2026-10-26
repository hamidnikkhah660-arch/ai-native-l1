$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repo = Split-Path -Parent $PSScriptRoot
Set-Location $repo
$manifest = '.\src\native\pow_bench\Cargo.toml'
$null = cargo +stable build --release --manifest-path $manifest --bin devnet_node --bin noise_key_provisioner --bin qzbe_v04_test_tx_signer --quiet
if ($LASTEXITCODE -ne 0) { throw 'CP-0424 QZBE continuous-mining release build failed' }

$nodeExe = (Resolve-Path '.\src\native\pow_bench\target\release\devnet_node.exe').Path
$keyExe = (Resolve-Path '.\src\native\pow_bench\target\release\noise_key_provisioner.exe').Path
$txSignerExe = (Resolve-Path '.\src\native\pow_bench\target\release\qzbe_v04_test_tx_signer.exe').Path
$root = Join-Path $env:TEMP ("ain1_cp0424_qzbe_continuous_" + [guid]::NewGuid().ToString('N'))
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
    if ($LASTEXITCODE -ne 0) { throw ("CP-0424 Noise key provisioning failed: " + ($out -join [Environment]::NewLine)) }
    $match = [regex]::Match(($out -join [Environment]::NewLine), 'noise_static_public_key_hex=([0-9a-f]{64})')
    if (-not $match.Success) { throw ("CP-0424 Noise public key missing: " + ($out -join [Environment]::NewLine)) }
    return $match.Groups[1].Value
}

$network = 'd4' * 32
$recipient = '44' * 32
$txSeedFile = Join-Path $env:TEMP ("ain1_cp0424_tx_seed_" + [guid]::NewGuid().ToString('N') + '.bin')
$txSeed = New-Object byte[] 32
$rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
try { $rng.GetBytes($txSeed); [IO.File]::WriteAllBytes($txSeedFile, $txSeed) }
finally { $rng.Dispose(); [Array]::Clear($txSeed, 0, $txSeed.Length) }
try {
    $txOutput = @(& $txSignerExe --seed-file $txSeedFile --network-id-hex $network --recipient-id-hex $recipient --nonce 1 --amount-atoms 1 --fee-atoms 1 --expires-at 4102444800 2>&1)
    if ($LASTEXITCODE -ne 0) { throw ("CP-0424 owner-key fixture failed: " + ($txOutput -join [Environment]::NewLine)) }
    $txText = $txOutput -join [Environment]::NewLine
    $pubMatch = [regex]::Match($txText, 'tx_public_key_hex=([0-9a-f]{64})')
    $ownerMatch = [regex]::Match($txText, 'tx_sender_account_id_hex=([0-9a-f]{64})')
    if (-not ($pubMatch.Success -and $ownerMatch.Success)) { throw ("CP-0424 owner fixture fields missing: " + $txText) }
    $txPublicKey = $pubMatch.Groups[1].Value
    $owner = $ownerMatch.Groups[1].Value
}
finally { Remove-Item -LiteralPath $txSeedFile -Force -ErrorAction SilentlyContinue }

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
        '--qzbe-v04-peer-smoke', '--test-easy-pow',
        '--network-id', $network, '--owner-id', $owner, '--miner-id', $miner,
        '--tx-public-key-hex', $txPublicKey, '--observe-account-id', $observe,
        '--initial-subsidy-atoms', $subsidy, '--blocks-per-halving', $halving,
        '--data-dir', $dataA, '--listen', $addrA,
        '--trusted-peer-key-hex', $pubB,
        '--noise-static-private-key-dpapi-file', $keyA,
        '--mine-blocks', '0', '--run-seconds', '30', '--stop-after-height', '2'
    )
    $nodeA = Start-Process -FilePath $nodeExe -ArgumentList $argsA -RedirectStandardOutput $stdA -RedirectStandardError $logA -PassThru
    if (-not (Wait-Pattern $logA 'event=qzbe_v04_peer_smoke_ready .*mining_mode=bounded .*local_only=true public_launch_approved=false' 20000)) {
        throw ("CP-0424 receiver did not become ready: " + (Get-Text $stdA) + (Get-Text $logA))
    }

    $argsB = @(
        '--qzbe-v04-peer-smoke', '--test-easy-pow',
        '--network-id', $network, '--owner-id', $owner, '--miner-id', $miner,
        '--tx-public-key-hex', $txPublicKey, '--observe-account-id', $observe,
        '--initial-subsidy-atoms', $subsidy, '--blocks-per-halving', $halving,
        '--data-dir', $dataB, '--listen', $addrB,
        '--peer', $addrA, '--trusted-peer-key-hex', $pubA,
        '--noise-static-private-key-dpapi-file', $keyB,
        '--mine-forever', '--stop-after-height', '2'
    )
    $nodeB = Start-Process -FilePath $nodeExe -ArgumentList $argsB -RedirectStandardOutput $stdB -RedirectStandardError $logB -PassThru
    if (-not (Wait-Pattern $logB 'event=qzbe_v04_peer_smoke_stopped .*height=2 .*replay=matched' 60000)) {
        throw ("CP-0424 continuous miner did not stop cleanly at height 2: " + (Get-Text $stdB) + (Get-Text $logB))
    }
    if (-not (Wait-Pattern $logA 'event=qzbe_v04_peer_smoke_stopped .*height=2 .*replay=matched' 60000)) {
        throw ("CP-0424 receiver did not converge/replay at height 2: " + (Get-Text $stdA) + (Get-Text $logA))
    }
    Wait-Process -Id $nodeA.Id -Timeout 15 -ErrorAction SilentlyContinue
    Wait-Process -Id $nodeB.Id -Timeout 15 -ErrorAction SilentlyContinue
    $activeA = Get-Process -Id $nodeA.Id -ErrorAction SilentlyContinue
    $activeB = Get-Process -Id $nodeB.Id -ErrorAction SilentlyContinue
    if ($null -ne $activeA) {
        throw ("CP-0424 receiver stayed alive after its stop event (pid=$($nodeA.Id)): " + (Get-Text $logA))
    }
    if ($null -ne $activeB) {
        throw ("CP-0424 miner stayed alive after its stop event (pid=$($nodeB.Id)): " + (Get-Text $logB))
    }
    if ((Get-Text $logA) -match 'event=devnet_qzbe_v04_dispatch_failed|panicked at' -or
        (Get-Text $logB) -match 'event=devnet_qzbe_v04_dispatch_failed|panicked at') {
        throw ("CP-0424 node failure marker found: " + (Get-Text $logA) + (Get-Text $logB))
    }

    $finalA = [regex]::Match((Get-Text $logA), 'event=qzbe_v04_peer_smoke_stopped .*height=2 state_root=([0-9a-f]{64}) tip=([0-9a-f]{64}).*replay=matched')
    $finalB = [regex]::Match((Get-Text $logB), 'event=qzbe_v04_peer_smoke_stopped .*height=2 state_root=([0-9a-f]{64}) tip=([0-9a-f]{64}).*replay=matched')
    if (-not ($finalA.Success -and $finalB.Success)) { throw 'CP-0424 final snapshots are missing canonical height/root/tip.' }
    if ($finalA.Groups[1].Value -ne $finalB.Groups[1].Value -or $finalA.Groups[2].Value -ne $finalB.Groups[2].Value) {
        throw 'CP-0424 receiver/miner canonical state did not converge.'
    }
    Write-Host 'CP-0424 CONTINUOUS_MINING_HEIGHT_2_PASS'
    Write-Host 'CP-0424 TWO_NODE_RESTART_REPLAY_CONVERGENCE_PASS'
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
