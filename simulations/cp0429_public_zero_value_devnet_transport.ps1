$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repo = Split-Path -Parent $PSScriptRoot
Set-Location $repo
$manifest = '.\src\native\pow_bench\Cargo.toml'
$null = cargo +stable build --release --manifest-path $manifest --bin devnet_node --bin noise_key_provisioner --quiet
if ($LASTEXITCODE -ne 0) { throw 'CP-0429 public zero-value Devnet release build failed' }

$nodeExe = (Resolve-Path '.\src\native\pow_bench\target\release\devnet_node.exe').Path
$keyExe = (Resolve-Path '.\src\native\pow_bench\target\release\noise_key_provisioner.exe').Path
$root = Join-Path $env:TEMP ("ain1_cp0429_public_devnet_" + [guid]::NewGuid().ToString('N'))
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
function Wait-Pattern([string]$Path, [string]$Pattern, [int]$Millis = 30000) {
    $watch = [Diagnostics.Stopwatch]::StartNew()
    while ($watch.ElapsedMilliseconds -lt $Millis) {
        if ((Get-Text $Path) -match $Pattern) { return $true }
        Start-Sleep -Milliseconds 50
    }
    return $false
}
function Provision-Key([string]$Path, [string]$Network) {
    $out = & $keyExe --output $Path --network-id-hex $Network
    if ($LASTEXITCODE -ne 0) { throw ("CP-0429 Noise key provisioning failed: " + $Path) }
    $match = [regex]::Match(($out -join [Environment]::NewLine), 'noise_static_public_key_hex=([0-9a-f]{64})')
    if (-not $match.Success) { throw ("CP-0429 Noise public key missing: " + $Path) }
    return $match.Groups[1].Value
}

$network = 'd9' * 32
$keyA = Join-Path $root 'public-listener.npk1'
$keyB = Join-Path $root 'loopback-peer.npk1'
$pubA = Provision-Key $keyA $network
$pubB = Provision-Key $keyB $network
$dataA = Join-Path $root 'public-listener-data'
$dataB = Join-Path $root 'loopback-peer-data'
$logA = Join-Path $root 'public-listener.err.log'
$stdA = Join-Path $root 'public-listener.out.log'
$logB = Join-Path $root 'loopback-peer.err.log'
$stdB = Join-Path $root 'loopback-peer.out.log'
$portA = Get-FreePort
$portB = Get-FreePort
while ($portA -eq $portB) { $portB = Get-FreePort }
$nodeA = $null
$nodeB = $null
try {
    # A is deliberately bound to the wildcard IPv4 interface, but accepts only its pinned Noise peer.
    $argsA = @(
        '--public-devnet', '--network-id', $network, '--data-dir', $dataA,
        '--listen', "0.0.0.0:$portA", '--peer', "127.0.0.1:$portB",
        '--noise-static-private-key-dpapi-file', $keyA, '--trusted-peer-key-hex', $pubB,
        '--run-seconds', '60', '--stop-after-height', '1'
    )
    $nodeA = Start-Process -FilePath $nodeExe -ArgumentList $argsA -RedirectStandardOutput $stdA -RedirectStandardError $logA -PassThru
    if (-not (Wait-Pattern $logA 'event=devnet_node_ready .*network_surface=external_bind_allowed_with_authenticated_peers public_devnet_mode=true .*mainnet=false public_launch_approved=false' 30000)) {
        throw ("CP-0429 public listener failed closed or did not become ready: " + (Get-Text $stdA) + (Get-Text $logA))
    }
    Write-Host 'CP-0429 EXPLICIT_PUBLIC_ZERO_VALUE_BIND_READY_PASS'

    # B uses the same zero-balance Genesis, dials A through a pinned Noise identity, and mines one
    # empty candidate block. A exits only after accepting that block; no monetary mode is enabled.
    $argsB = @(
        '--network-id', $network, '--data-dir', $dataB, '--listen', "127.0.0.1:$portB",
        '--peer', "127.0.0.1:$portA",
        '--noise-static-private-key-dpapi-file', $keyB, '--trusted-peer-key-hex', $pubA,
        '--mine-blocks', '1', '--run-seconds', '12'
    )
    $nodeB = Start-Process -FilePath $nodeExe -ArgumentList $argsB -RedirectStandardOutput $stdB -RedirectStandardError $logB -PassThru
    if (-not (Wait-Pattern $logB 'event=devnet_node_ready .*network_surface=loopback_only public_devnet_mode=false' 30000)) {
        throw ("CP-0429 loopback peer did not become ready: " + (Get-Text $stdB) + (Get-Text $logB))
    }
    if (-not (Wait-Pattern $logB 'event=private_testnet_broadcast height=1 peers=1 accepted=1' 60000)) {
        throw ("CP-0429 pinned-peer block broadcast was not acknowledged: " + (Get-Text $logB))
    }
    if (-not (Wait-Pattern $logA 'event=devnet_node_stopped .*height=1' 30000)) {
        throw ("CP-0429 public node did not stop at the imported height: " + (Get-Text $logA))
    }
    if (-not (Wait-Pattern $logB 'event=devnet_node_stopped .*height=1' 30000)) {
        throw ("CP-0429 peer did not stop after broadcast: " + (Get-Text $logB))
    }

    $stoppedPatternA = 'event=devnet_node_stopped listen=0\.0\.0\.0:' + $portA + ' height=(\d+) state_root=([0-9a-f]{64}) consensus_tip=([0-9a-f]{64})'
    $stoppedPatternB = 'event=devnet_node_stopped listen=127\.0\.0\.1:' + $portB + ' height=(\d+) state_root=([0-9a-f]{64}) consensus_tip=([0-9a-f]{64})'
    $stoppedA = [regex]::Match((Get-Text $logA), $stoppedPatternA)
    $stoppedB = [regex]::Match((Get-Text $logB), $stoppedPatternB)
    if (-not ($stoppedA.Success -and $stoppedB.Success)) {
        throw ("CP-0429 final canonical-state markers missing: A=" + (Get-Text $logA) + " B=" + (Get-Text $logB))
    }
    if ($stoppedA.Groups[1].Value -ne '1' -or $stoppedB.Groups[1].Value -ne '1' -or
        $stoppedA.Groups[2].Value -ne $stoppedB.Groups[2].Value -or
        $stoppedA.Groups[3].Value -ne $stoppedB.Groups[3].Value) {
        throw ("CP-0429 state convergence failed: A=" + $stoppedA.Value + " B=" + $stoppedB.Value)
    }
    Write-Host 'CP-0429 AUTHENTICATED_NOISE_BLOCK_BROADCAST_ACK_PASS'
    Write-Host 'CP-0429 ZERO_VALUE_EXTERNAL_BIND_STATE_ROOT_TIP_CONVERGENCE_PASS'
}
finally {
    foreach ($process in @($nodeA, $nodeB)) {
        if ($null -ne $process) {
            try {
                $process.Refresh()
                if (-not $process.HasExited) { Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue }
            } catch {}
        }
    }
    Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
}
