$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$repo = Split-Path -Parent $PSScriptRoot
Set-Location $repo
$manifest = '.\src\native\pow_bench\Cargo.toml'
$null = cargo +stable build --release --manifest-path $manifest --bin devnet_node --bin noise_key_provisioner --bin qzxb_wallet --quiet
if ($LASTEXITCODE -ne 0) { throw 'CP-0437 QZBE archive-sync release build failed' }

$nodeExe = (Resolve-Path '.\src\native\pow_bench\target\release\devnet_node.exe').Path
$keyExe = (Resolve-Path '.\src\native\pow_bench\target\release\noise_key_provisioner.exe').Path
$walletExe = (Resolve-Path '.\src\native\pow_bench\target\release\qzxb_wallet.exe').Path
$root = Join-Path $env:TEMP ("ain1_cp0437_qzbe_archive_sync_" + [guid]::NewGuid().ToString('N'))
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
    $out = @(& $keyExe --output $Path --network-id-hex $Network 2>&1)
    if ($LASTEXITCODE -ne 0) { throw ("CP-0437 Noise key provisioning failed: " + ($out -join [Environment]::NewLine)) }
    $match = [regex]::Match(($out -join [Environment]::NewLine), 'noise_static_public_key_hex=([0-9a-f]{64})')
    if (-not $match.Success) { throw ("CP-0437 Noise public key missing: " + ($out -join [Environment]::NewLine)) }
    return $match.Groups[1].Value
}
function Get-RpcStatus([string]$Address) {
    $parts = $Address.Split(':')
    $client = [Net.Sockets.TcpClient]::new()
    try {
        $client.ReceiveTimeout = 3000
        $client.SendTimeout = 3000
        $client.Connect([Net.IPAddress]::Loopback, [int]$parts[1])
        $stream = $client.GetStream()
        $stream.ReadTimeout = 3000
        $stream.WriteTimeout = 3000
        $crlf = [char]13 + [char]10
        $request = [Text.Encoding]::ASCII.GetBytes(("GET /v1/status HTTP/1.1" + $crlf + "Host: localhost" + $crlf + "Connection: close" + $crlf + $crlf))
        $stream.Write($request, 0, $request.Length)
        $memory = [IO.MemoryStream]::new()
        $buffer = [byte[]]::new(4096)
        while (($read = $stream.Read($buffer, 0, $buffer.Length)) -gt 0) {
            $memory.Write($buffer, 0, $read)
            if ($memory.Length -gt 8192) { throw 'CP-0437 RPC status response exceeded the small status cap' }
        }
        $response = [Text.Encoding]::ASCII.GetString($memory.ToArray())
        $separator = $response.IndexOf($crlf + $crlf)
        if ($separator -lt 0) { throw ("CP-0437 malformed read-only RPC response: " + $response) }
        $statusLineEnd = $response.IndexOf($crlf)
        $statusLine = $response.Substring(0, $statusLineEnd)
        if ($statusLine -notmatch 'HTTP/1\.[01] 200 ') { throw ("CP-0437 unexpected RPC status: " + $statusLine) }
        return ($response.Substring($separator + 4) | ConvertFrom-Json)
    }
    finally { $client.Dispose() }
}
function Wait-RpcHeight([string]$Address, [int]$MinimumHeight, [int]$Millis = 30000) {
    $watch = [Diagnostics.Stopwatch]::StartNew()
    while ($watch.ElapsedMilliseconds -lt $Millis) {
        try {
            $status = Get-RpcStatus $Address
            if ($status.ok -and [int]$status.height -ge $MinimumHeight) { return $status }
        } catch {}
        Start-Sleep -Milliseconds 100
    }
    throw "CP-0437 RPC at $Address did not reach height $MinimumHeight"
}

$network = 'd4' * 32
$recipient = '44' * 32
$miner = '33' * 32
$walletPath = Join-Path $root 'owner-test.qzw1'
$walletCreate = @(& $walletExe create --output $walletPath 2>&1)
if ($LASTEXITCODE -ne 0) { throw ("CP-0437 temporary wallet creation failed: " + ($walletCreate -join [Environment]::NewLine)) }
$walletOutput = @(& $walletExe address --wallet $walletPath 2>&1)
if ($LASTEXITCODE -ne 0) { throw ("CP-0437 temporary wallet could not be reopened: " + ($walletOutput -join [Environment]::NewLine)) }
$walletText = $walletOutput -join [Environment]::NewLine
$pubMatch = [regex]::Match($walletText, 'public_key_hex=([0-9a-f]{64})')
$ownerMatch = [regex]::Match($walletText, 'account_id_hex=([0-9a-f]{64})')
if (-not ($pubMatch.Success -and $ownerMatch.Success)) { throw ("CP-0437 wallet identity fields missing: " + $walletText) }
$txPublicKey = $pubMatch.Groups[1].Value
$owner = $ownerMatch.Groups[1].Value

$keyA = Join-Path $root 'node-a.npk1'
$keyB = Join-Path $root 'node-b.npk1'
$keyC = Join-Path $root 'node-c.npk1'
$pubA = Provision-Key $keyA $network
$pubB = Provision-Key $keyB $network
$pubC = Provision-Key $keyC $network
$dataA = Join-Path $root 'node-a-data'
$dataB = Join-Path $root 'node-b-data'
$dataC = Join-Path $root 'node-c-data'
$logA = Join-Path $root 'node-a.err.log'
$stdA = Join-Path $root 'node-a.out.log'
$logB = Join-Path $root 'node-b.err.log'
$stdB = Join-Path $root 'node-b.out.log'
$logC = Join-Path $root 'node-c.err.log'
$stdC = Join-Path $root 'node-c.out.log'
$portA = Get-FreePort
$portB = Get-FreePort
$portC = Get-FreePort
$rpcPortA = Get-FreePort
$rpcPortC = Get-FreePort
$ports = @($portA, $portB, $portC, $rpcPortA, $rpcPortC)
while (($ports | Select-Object -Unique).Count -ne $ports.Count) {
    $portB = Get-FreePort; $portC = Get-FreePort; $rpcPortA = Get-FreePort; $rpcPortC = Get-FreePort
    $ports = @($portA, $portB, $portC, $rpcPortA, $rpcPortC)
}
$addrA = "127.0.0.1:$portA"
$addrB = "127.0.0.1:$portB"
$addrC = "127.0.0.1:$portC"
$rpcA = "127.0.0.1:$rpcPortA"
$rpcC = "127.0.0.1:$rpcPortC"
$subsidy = '35673515981'
$halving = '4204800'
$nodeA = $null
$nodeB = $null
$nodeC = $null

try {
    # Node A is a loopback-only RPC/archive source and pins keys for both clients.
    $argsA = @(
        '--qzbe-v04-peer-smoke', '--test-easy-pow', '--public-testnet-p2p',
        '--network-id', $network, '--owner-id', $owner, '--miner-id', $miner,
        '--tx-public-key-hex', $txPublicKey, '--observe-account-id', $recipient,
        '--initial-subsidy-atoms', $subsidy, '--blocks-per-halving', $halving,
        '--data-dir', $dataA, '--listen', $addrA, '--rpc-listen', $rpcA,
        '--trusted-peer-key-hex', $pubB, '--trusted-peer-key-hex', $pubC,
        '--noise-static-private-key-dpapi-file', $keyA,
        '--mine-blocks', '0', '--run-seconds', '240'
    )
    $nodeA = Start-Process -FilePath $nodeExe -ArgumentList $argsA -RedirectStandardOutput $stdA -RedirectStandardError $logA -PassThru
    if (-not (Wait-Pattern $logA 'event=qzbe_v04_peer_smoke_ready .*mainnet=false .*public_launch_approved=false' 30000)) {
        throw ("CP-0437 archive source node did not become ready: " + (Get-Text $stdA) + (Get-Text $logA))
    }

    # Node B mines a short candidate chain and broadcasts the three blocks to A.
    $argsB = @(
        '--qzbe-v04-peer-smoke', '--test-easy-pow', '--public-testnet-p2p',
        '--network-id', $network, '--owner-id', $owner, '--miner-id', $miner,
        '--tx-public-key-hex', $txPublicKey, '--observe-account-id', $recipient,
        '--initial-subsidy-atoms', $subsidy, '--blocks-per-halving', $halving,
        '--data-dir', $dataB, '--listen', $addrB, '--peer', $addrA,
        '--trusted-peer-key-hex', $pubA, '--noise-static-private-key-dpapi-file', $keyB,
        '--mine-forever', '--stop-after-height', '3'
    )
    $nodeB = Start-Process -FilePath $nodeExe -ArgumentList $argsB -RedirectStandardOutput $stdB -RedirectStandardError $logB -PassThru
    if (-not (Wait-Pattern $logB 'event=qzbe_v04_peer_smoke_stopped .*height=3 .*replay=matched' 60000)) {
        throw ("CP-0437 mining peer failed to reach three blocks: " + (Get-Text $stdB) + (Get-Text $logB))
    }
    $null = Wait-RpcHeight $rpcA 3 30000
    $sourceStatus = Get-RpcStatus $rpcA
    if ([int]$sourceStatus.height -ne 3 -or $sourceStatus.mainnet -ne $false -or $sourceStatus.read_only -ne $true) {
        throw ("CP-0437 source did not report test-only height 3: " + ($sourceStatus | ConvertTo-Json -Compress))
    }

    # Node C starts from a fresh Genesis store and imports A's authenticated, bounded history.
    $argsC = @(
        '--qzbe-v04-peer-smoke', '--test-easy-pow', '--public-testnet-p2p', '--sync-from-peers',
        '--network-id', $network, '--owner-id', $owner, '--miner-id', $miner,
        '--tx-public-key-hex', $txPublicKey, '--observe-account-id', $recipient,
        '--initial-subsidy-atoms', $subsidy, '--blocks-per-halving', $halving,
        '--data-dir', $dataC, '--listen', $addrC, '--rpc-listen', $rpcC,
        '--peer', $addrA, '--trusted-peer-key-hex', $pubA,
        '--noise-static-private-key-dpapi-file', $keyC,
        '--mine-blocks', '0', '--run-seconds', '60'
    )
    $nodeC = Start-Process -FilePath $nodeExe -ArgumentList $argsC -RedirectStandardOutput $stdC -RedirectStandardError $logC -PassThru
    if (-not (Wait-Pattern $logC 'event=qzbe_v04_archive_sync_complete .*height=3 .*work=' 30000)) {
        throw ("CP-0437 fresh node did not complete archive sync: " + (Get-Text $stdC) + (Get-Text $logC))
    }
    if (-not (Wait-Pattern $logC 'event=qzbe_v04_peer_smoke_ready .*mainnet=false .*public_launch_approved=false' 30000)) {
        throw ("CP-0437 fresh node failed to become test-ready after sync: " + (Get-Text $stdC) + (Get-Text $logC))
    }

    $freshStatus = Get-RpcStatus $rpcC
    if ([int]$freshStatus.height -ne 3 -or $freshStatus.genesis_id -ne $sourceStatus.genesis_id -or $freshStatus.profile_id -ne $sourceStatus.profile_id -or $freshStatus.tip -ne $sourceStatus.tip -or $freshStatus.state_root -ne $sourceStatus.state_root -or $freshStatus.mainnet -ne $false -or $freshStatus.read_only -ne $true) {
        throw ("CP-0437 source/fresh-node status mismatch: source=" + ($sourceStatus | ConvertTo-Json -Compress) + " fresh=" + ($freshStatus | ConvertTo-Json -Compress))
    }

    Write-Host 'CP-0437 FRESH_NODE_ARCHIVE_SYNC_TIP_ROOT_WORK_CONVERGENCE_PASS'
    Write-Host ("CP-0437 source_height=" + $sourceStatus.height + " fresh_height=" + $freshStatus.height + " tip=" + $freshStatus.tip + " root=" + $freshStatus.state_root)
    Write-Host 'CP-0437 zero-value, loopback-local exercise only; not Mainnet readiness evidence.'
}
finally {
    foreach ($proc in @($nodeB, $nodeC, $nodeA)) {
        if ($null -ne $proc) {
            try { if (-not $proc.HasExited) { Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue } } catch {}
        }
    }
    Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
}
