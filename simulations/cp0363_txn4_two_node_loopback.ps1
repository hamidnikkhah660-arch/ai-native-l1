$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repo = Split-Path -Parent $PSScriptRoot
Set-Location $repo
$manifest = '.\src\native\pow_bench\Cargo.toml'
$null = cargo build --release --manifest-path $manifest --bin devnet_node --bin noise_key_provisioner --example txn4_loopback_fixture --quiet
if ($LASTEXITCODE -ne 0) { throw 'CP-0363 release build failed' }

$nodeExe = (Resolve-Path '.\src\native\pow_bench\target\release\devnet_node.exe').Path
$keyExe = (Resolve-Path '.\src\native\pow_bench\target\release\noise_key_provisioner.exe').Path
$fixtureExe = (Resolve-Path '.\src\native\pow_bench\target\release\examples\txn4_loopback_fixture.exe').Path
$root = Join-Path $env:TEMP ("ain1_cp0363_txn4_two_node_" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $root | Out-Null
$fixtureDir = Join-Path $root 'fixture'
New-Item -ItemType Directory -Path $fixtureDir | Out-Null

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
function Wait-Pattern([string]$Path, [string]$Pattern, [int]$Millis = 12000) {
    $watch = [Diagnostics.Stopwatch]::StartNew()
    while ($watch.ElapsedMilliseconds -lt $Millis) {
        if ((Get-Text $Path) -match $Pattern) { return $true }
        Start-Sleep -Milliseconds 50
    }
    return $false
}
function Provision-Key([string]$Path, [string]$Network) {
    $out = & $keyExe --output $Path --network-id-hex $Network
    if ($LASTEXITCODE -ne 0) { throw ("CP-0363 Noise key provisioning failed: " + $Path) }
    $match = [regex]::Match(($out -join [Environment]::NewLine), 'noise_static_public_key_hex=([0-9a-f]{64})')
    if (-not $match.Success) { throw ("CP-0363 Noise public key missing: " + $Path) }
    return $match.Groups[1].Value
}
function Submit-Txn4([int]$Port, [byte[]]$Bytes) {
    $client = [Net.Sockets.TcpClient]::new()
    $client.ReceiveTimeout = 4000
    $client.SendTimeout = 4000
    $client.Connect('127.0.0.1', $Port)
    $stream = $client.GetStream()
    try {
        $crlf = [string][char]13 + [char]10
        $headerText = 'POST /tx/submit HTTP/1.1' + $crlf +
            'Host: 127.0.0.1' + $crlf +
            'Content-Type: application/octet-stream' + $crlf +
            "Content-Length: $($Bytes.Length)" + $crlf +
            'Connection: close' + $crlf + $crlf
        $header = [System.Text.Encoding]::ASCII.GetBytes($headerText)
        $stream.Write($header, 0, $header.Length)
        $stream.Write($Bytes, 0, $Bytes.Length)
        $stream.Flush()
        $memory = [System.IO.MemoryStream]::new()
        $buffer = New-Object byte[] 4096
        while (($read = $stream.Read($buffer, 0, $buffer.Length)) -gt 0) {
            $memory.Write($buffer, 0, $read)
        }
        return [System.Text.Encoding]::UTF8.GetString($memory.ToArray())
    }
    finally {
        $stream.Dispose()
        $client.Dispose()
    }
}

$network = 'c4' * 32
$fixtureOutput = & $fixtureExe --network-id $network --out-dir $fixtureDir
if ($LASTEXITCODE -ne 0) { throw ("CP-0363 TXN4 fixture generation failed: " + ($fixtureOutput -join [Environment]::NewLine)) }
$fixtureText = $fixtureOutput -join [Environment]::NewLine
$edMatch = [regex]::Match($fixtureText, 'founder_ed25519_public_key_hex=([0-9a-f]{64})')
$pqMatch = [regex]::Match($fixtureText, 'founder_mldsa65_public_key_file=(.+)')
$txidMatch = [regex]::Match($fixtureText, 'txid=([0-9a-f]{64})')
$txPathMatch = [regex]::Match($fixtureText, 'transaction_file=(.+)')
$fixtureManifestMatch = [regex]::Match($fixtureText, 'manifest_id=([0-9a-f]{64})')
if (-not ($edMatch.Success -and $pqMatch.Success -and $txidMatch.Success -and $txPathMatch.Success -and $fixtureManifestMatch.Success)) {
    throw ("CP-0363 fixture output missing required fields: " + $fixtureText)
}
$founderEd = $edMatch.Groups[1].Value
$founderPqPath = $pqMatch.Groups[1].Value.Trim()
$expectedTxid = $txidMatch.Groups[1].Value
$txPath = $txPathMatch.Groups[1].Value.Trim()
$fixtureManifest = $fixtureManifestMatch.Groups[1].Value
$txBytes = [System.IO.File]::ReadAllBytes($txPath)
if ($txBytes.Length -lt 100) { throw "CP-0363 TXN4 fixture looks truncated ($($txBytes.Length) bytes)" }

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
$statusA = Get-FreePort
$statusB = Get-FreePort
$txPort = Get-FreePort
$ports = @($portA, $portB, $statusA, $statusB, $txPort)
while (($ports | Select-Object -Unique).Count -ne 5) {
    $portA = Get-FreePort; $portB = Get-FreePort; $statusA = Get-FreePort; $statusB = Get-FreePort; $txPort = Get-FreePort
    $ports = @($portA, $portB, $statusA, $statusB, $txPort)
}
$nodeA = $null
$nodeB = $null
try {
    $argsB = @(
        '--network-id', $network,
        '--data-dir', $dataB,
        '--listen', "127.0.0.1:$portB",
        '--status-listen', "127.0.0.1:$statusB",
        '--noise-static-private-key-dpapi-file', $keyB,
        '--trusted-peer-key-hex', $pubA,
        '--peer', "127.0.0.1:$portA",
        '--v4-founder-ed25519-public-key-hex', $founderEd,
        '--v4-founder-mldsa65-public-key-file', $founderPqPath,
        '--monetary-v4-hybrid-peer-smoke',
        '--mine-blocks', '0',
        '--run-seconds', '40'
    )
    $nodeB = Start-Process -FilePath $nodeExe -ArgumentList $argsB -RedirectStandardOutput $stdB -RedirectStandardError $logB -PassThru
    if (-not (Wait-Pattern $logB 'event=monetary_v4_peer_smoke_ready.*height=0.*profile_scope=loopback_diagnostic.*wire=PMT4' 20000)) {
        throw ("CP-0363 receiving node B did not become ready: " + (Get-Text $stdB) + (Get-Text $logB))
    }

    $argsA = @(
        '--network-id', $network,
        '--data-dir', $dataA,
        '--listen', "127.0.0.1:$portA",
        '--status-listen', "127.0.0.1:$statusA",
        '--transaction-listen', "127.0.0.1:$txPort",
        '--noise-static-private-key-dpapi-file', $keyA,
        '--trusted-peer-key-hex', $pubB,
        '--peer', "127.0.0.1:$portB",
        '--v4-founder-ed25519-public-key-hex', $founderEd,
        '--v4-founder-mldsa65-public-key-file', $founderPqPath,
        '--monetary-v4-hybrid-peer-smoke',
        '--mine-blocks', '1',
        '--exit-after-mining', 'true',
        '--run-seconds', '35'
    )
    $nodeA = Start-Process -FilePath $nodeExe -ArgumentList $argsA -RedirectStandardOutput $stdA -RedirectStandardError $logA -PassThru
    if (-not (Wait-Pattern $logA 'event=monetary_v4_peer_smoke_ready.*height=0.*profile_scope=loopback_diagnostic.*tx_submit_listen=127\.0\.0\.1:' 20000)) {
        throw ("CP-0363 submitting node A did not become ready: " + (Get-Text $stdA) + (Get-Text $logA))
    }

    $readyA = [regex]::Match((Get-Text $logA), 'event=monetary_v4_peer_smoke_ready .*manifest=([0-9a-f]{64})')
    $readyB = [regex]::Match((Get-Text $logB), 'event=monetary_v4_peer_smoke_ready .*manifest=([0-9a-f]{64})')
    if (-not ($readyA.Success -and $readyB.Success)) { throw 'CP-0363 did not find both PMT4 manifest IDs in node logs' }
    if ($readyA.Groups[1].Value -ne $fixtureManifest -or $readyB.Groups[1].Value -ne $fixtureManifest) {
        throw ("CP-0363 manifest mismatch: fixture=$fixtureManifest nodeA=$($readyA.Groups[1].Value) nodeB=$($readyB.Groups[1].Value)")
    }

    $response = Submit-Txn4 -Port $txPort -Bytes $txBytes
    if ($response -notmatch '^HTTP/1\.1 202 Accepted') { throw ("CP-0363 TXN4 submission was not HTTP 202: " + $response) }
    if ($response -notmatch '"status":"accepted"') { throw ("CP-0363 response did not report accepted: " + $response) }
    $responseId = [regex]::Match($response, '"transaction_id":"([0-9a-f]{64})"')
    if (-not $responseId.Success -or $responseId.Groups[1].Value -ne $expectedTxid) {
        throw ("CP-0363 mempool TXID mismatch: expected=$expectedTxid response=$response")
    }
    Write-Host "CP-0363 TXN4_SUBMIT_PASS txid=$expectedTxid http=202"

    if (-not (Wait-Pattern $logA 'event=monetary_v4_peer_broadcast_complete height=1 .*transactions=1' 16000)) {
        throw ("CP-0363 node A did not mine and broadcast a one-transaction block: " + (Get-Text $logA))
    }
    if (-not (Wait-Pattern $logB 'event=monetary_v4_peer_ack_sent .*ack=MTA4 status=0 candidate_height=1' 16000)) {
        throw ("CP-0363 node B did not accept the propagated PMT4 block: " + (Get-Text $logB))
    }

    $broadcast = [regex]::Match((Get-Text $logA), 'event=monetary_v4_peer_broadcast_complete height=1 digest=[0-9a-f]{64} state_root=([0-9a-f]{64}) tip=([0-9a-f]{64}) peers=1 transactions=1')
    if (-not $broadcast.Success) { throw 'CP-0363 node A broadcast did not contain a height-1 state root and tip' }
    $expectedRoot = $broadcast.Groups[1].Value
    $expectedTip = $broadcast.Groups[2].Value
    $matched = $false
    $watch = [Diagnostics.Stopwatch]::StartNew()
    while ($watch.ElapsedMilliseconds -lt 12000) {
        try {
            $stateB = Invoke-RestMethod -Uri ("http://127.0.0.1:" + $statusB + "/status") -TimeoutSec 2
            if ([int]$stateB.height -eq 1) {
                if ($stateB.state_root -ne $expectedRoot -or $stateB.consensus_tip -ne $expectedTip) {
                    throw ("CP-0363 node state disagreement: A root/tip=$expectedRoot/$expectedTip B=$($stateB.state_root)/$($stateB.consensus_tip)")
                }
                $matched = $true
                break
            }
        }
        catch {
            if ($_.Exception.Message -like 'CP-0363 node state disagreement*') { throw }
        }
        Start-Sleep -Milliseconds 150
    }
    if (-not $matched) { throw 'CP-0363 receiver node B did not converge to the broadcast height-1 state root and tip' }
    Write-Host ("CP-0363 TWO_NODE_CONSENSUS_PASS height=1 state_root=" + $expectedRoot + " tip=" + $expectedTip)

    if (-not $nodeA.WaitForExit(45000)) { throw 'CP-0363 node A did not exit after its bounded run' }
    if (-not $nodeB.WaitForExit(45000)) { throw 'CP-0363 node B did not exit after its bounded run' }
    if ((Get-Text $logA) -notmatch 'event=monetary_v4_peer_smoke_stopped height=1 .*replay=matched') { throw 'CP-0363 node A replay result missing' }
    if ((Get-Text $logB) -notmatch 'event=monetary_v4_peer_smoke_stopped height=1 .*replay=matched') { throw 'CP-0363 node B replay result missing' }
    $acceptedPattern = 'event=txn4_submission_accepted txid=' + [regex]::Escape($expectedTxid)
    if ((Get-Text $logA) -notmatch $acceptedPattern) { throw 'CP-0363 node A log did not record the accepted fixture TXN4 identifier' }
    Write-Host 'CP-0363 TXN4_TWO_NODE_REPLAY_PASS nodeA_height=1 nodeB_height=1 replay=matched'
    Write-Host ("CP-0363 ARTIFACTS " + $root)
}
finally {
    foreach ($process in @($nodeA, $nodeB)) {
        if ($process) {
            $process.Refresh()
            if (-not $process.HasExited) {
                $process.Kill()
                [void]$process.WaitForExit(5000)
            }
        }
    }
}
