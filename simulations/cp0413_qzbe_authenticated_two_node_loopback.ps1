$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repo = Split-Path -Parent $PSScriptRoot
Set-Location $repo
$manifest = '.\src\native\pow_bench\Cargo.toml'
$null = cargo +stable build --release --manifest-path $manifest --bin qzbe_v04_peer_node --bin noise_key_provisioner --quiet
if ($LASTEXITCODE -ne 0) { throw 'CP-0413 QZBE runtime candidate release build failed' }

$nodeExe = (Resolve-Path '.\src\native\pow_bench\target\release\qzbe_v04_peer_node.exe').Path
$keyExe = (Resolve-Path '.\src\native\pow_bench\target\release\noise_key_provisioner.exe').Path
$root = Join-Path $env:TEMP ("ain1_cp0413_qzbe_runtime_" + [guid]::NewGuid().ToString('N'))
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
function Wait-Pattern([string]$Path, [string]$Pattern, [int]$Millis = 15000) {
    $watch = [Diagnostics.Stopwatch]::StartNew()
    while ($watch.ElapsedMilliseconds -lt $Millis) {
        if ((Get-Text $Path) -match $Pattern) { return $true }
        Start-Sleep -Milliseconds 50
    }
    return $false
}
function Provision-Key([string]$Path, [string]$Network) {
    $out = & $keyExe --output $Path --network-id-hex $Network
    if ($LASTEXITCODE -ne 0) { throw ("CP-0413 Noise key provisioning failed: " + $Path) }
    $match = [regex]::Match(($out -join [Environment]::NewLine), 'noise_static_public_key_hex=([0-9a-f]{64})')
    if (-not $match.Success) { throw ("CP-0413 Noise public key missing: " + $Path) }
    return $match.Groups[1].Value
}

$network = 'c5' * 32
$owner = '22' * 32
$miner = '33' * 32
$subsidy = '1000000'
$halving = '1000'
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
while ($portA -eq $portB) { $portB = Get-FreePort }
$nodeA = $null
$nodeB = $null
try {
    # Verify the candidate node rejects public binds before any profile or store is initialized.
    $savedErrorPreference = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    $bindOutput = @(& $nodeExe --data-dir (Join-Path $root 'invalid-bind') --listen '0.0.0.0:49331' 2>&1)
    $bindExitCode = $LASTEXITCODE
    $ErrorActionPreference = $savedErrorPreference
    if ($bindExitCode -ne 2 -or (($bindOutput -join [Environment]::NewLine) -notmatch 'refuses all non-loopback listen addresses')) {
        throw ("CP-0413 public-bind guard did not fail closed (exit=$bindExitCode): " + ($bindOutput -join [Environment]::NewLine))
    }
    Write-Host 'CP-0413 PUBLIC_BIND_GUARD_PASS'

    $argsB = @(
        '--network-id', $network,
        '--owner-id', $owner,
        '--miner-id', $miner,
        '--initial-subsidy-atoms', $subsidy,
        '--blocks-per-halving', $halving,
        '--data-dir', $dataB,
        '--listen', "127.0.0.1:$portB",
        '--noise-static-private-key-dpapi-file', $keyB,
        '--trusted-peer-key-hex', $pubA,
        '--mine-blocks', '0',
        '--run-seconds', '30',
        '--stop-after-height', '2'
    )
    $nodeB = Start-Process -FilePath $nodeExe -ArgumentList $argsB -RedirectStandardOutput $stdB -RedirectStandardError $logB -PassThru
    if (-not (Wait-Pattern $logB 'event=qzbe_v04_peer_smoke_ready .*height=0 .*local_only=true public_launch_approved=false' 20000)) {
        throw ("CP-0413 receiver node B did not become ready: " + (Get-Text $stdB) + (Get-Text $logB))
    }

    $argsA = @(
        '--network-id', $network,
        '--owner-id', $owner,
        '--miner-id', $miner,
        '--initial-subsidy-atoms', $subsidy,
        '--blocks-per-halving', $halving,
        '--data-dir', $dataA,
        '--listen', "127.0.0.1:$portA",
        '--peer', "127.0.0.1:$portB",
        '--noise-static-private-key-dpapi-file', $keyA,
        '--trusted-peer-key-hex', $pubB,
        '--mine-blocks', '2',
        '--run-seconds', '30',
        '--exit-after-mining'
    )
    $nodeA = Start-Process -FilePath $nodeExe -ArgumentList $argsA -RedirectStandardOutput $stdA -RedirectStandardError $logA -PassThru

    if (-not (Wait-Pattern $logA 'event=qzbe_v04_peer_broadcast_ack height=2 .*sent_count=2' 30000)) {
        throw ("CP-0413 sending node A did not receive both peer ACKs: " + (Get-Text $stdA) + (Get-Text $logA) + (Get-Text $stdB) + (Get-Text $logB))
    }
    if (-not (Wait-Pattern $logB 'event=qzbe_v04_peer_block_accepted .*height=2 .*accepted_count=2' 15000)) {
        throw ("CP-0413 receiver B did not accept both QZBE blocks: " + (Get-Text $logB))
    }
    if (-not $nodeA.WaitForExit(30000)) { throw 'CP-0413 sending node A did not stop after its bounded mining run' }
    if (-not $nodeB.WaitForExit(35000)) { throw 'CP-0413 receiver node B did not stop after reaching height 2' }
    $textA = Get-Text $logA
    $textB = Get-Text $logB
    if ($textA -match 'event=qzbe_v04_peer_smoke_failed') { throw ("CP-0413 node A reported runtime failure: " + $textA) }
    if ($textB -match 'event=qzbe_v04_peer_smoke_failed') { throw ("CP-0413 node B reported runtime failure: " + $textB) }

    $pattern = 'event=qzbe_v04_peer_smoke_stopped .*height=2 state_root=([0-9a-f]{64}) tip=([0-9a-f]{64}) generation=2 accepted_peer_blocks=\d+ sent_peer_blocks=\d+ replay=matched local_only=true public_launch_approved=false'
    $finalA = [regex]::Match((Get-Text $logA), $pattern)
    $finalB = [regex]::Match((Get-Text $logB), $pattern)
    if (-not ($finalA.Success -and $finalB.Success)) {
        throw ("CP-0413 restart/replay summaries missing: " + (Get-Text $logA) + (Get-Text $logB))
    }
    if ($finalA.Groups[1].Value -ne $finalB.Groups[1].Value -or $finalA.Groups[2].Value -ne $finalB.Groups[2].Value) {
        throw ("CP-0413 independent QZBE stores diverged: A=$($finalA.Groups[1].Value)/$($finalA.Groups[2].Value) B=$($finalB.Groups[1].Value)/$($finalB.Groups[2].Value)")
    }
    if ((Get-Text $logA) -match 'event=qzbe_v04_peer_connection_rejected' -or (Get-Text $logB) -match 'event=qzbe_v04_peer_connection_rejected') {
        throw 'CP-0413 observed an unexpected peer protocol or Noise error'
    }
    Write-Host ("CP-0413 QZBE_AUTHENTICATED_TWO_NODE_LOOPBACK_PASS height=2 state_root=" + $finalA.Groups[1].Value + " tip=" + $finalA.Groups[2].Value + ' replay=matched public_bind=denied')
}
finally {
    foreach ($node in @($nodeA, $nodeB)) {
        if ($null -ne $node) {
            try { if (-not $node.HasExited) { Stop-Process -Id $node.Id -Force -ErrorAction SilentlyContinue } } catch { }
        }
    }
    Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
}
