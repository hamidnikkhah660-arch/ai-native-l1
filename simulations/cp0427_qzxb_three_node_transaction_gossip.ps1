$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repo = Split-Path -Parent $PSScriptRoot
Set-Location $repo
$manifest = '.\src\native\pow_bench\Cargo.toml'
$null = cargo +stable build --release --manifest-path $manifest --bin devnet_node --bin noise_key_provisioner --bin qzxb_wallet --quiet
if ($LASTEXITCODE -ne 0) { throw 'CP-0427 QZBE live TXN2 ingress release build failed' }
$null = cargo +stable test --manifest-path $manifest --bin qzxb_wallet --locked --quiet
if ($LASTEXITCODE -ne 0) { throw 'CP-0427 native wallet unit tests failed' }
$null = cargo +stable test --manifest-path $manifest --lib qzbe_tx_ingress_candidate::tests --locked --quiet
if ($LASTEXITCODE -ne 0) { throw 'CP-0427 QZTS/1 ingress framing tests failed' }
$null = cargo +stable test --manifest-path $manifest --bin devnet_node --locked --quiet
if ($LASTEXITCODE -ne 0) { throw 'CP-0427 QZBE runtime/parser/authentication tests failed' }
Write-Host 'CP-0427 WALLET_INGRESS_AND_QZBE_UNIT_TESTS_PASS'

$nodeExe = (Resolve-Path '.\src\native\pow_bench\target\release\devnet_node.exe').Path
$keyExe = (Resolve-Path '.\src\native\pow_bench\target\release\noise_key_provisioner.exe').Path
$walletExe = (Resolve-Path '.\src\native\pow_bench\target\release\qzxb_wallet.exe').Path
$root = Join-Path $env:TEMP ("ain1_cp0427_qzxb_three_node_gossip_" + [guid]::NewGuid().ToString('N'))
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
    if ($LASTEXITCODE -ne 0) { throw ("CP-0427 Noise key provisioning failed: " + ($out -join [Environment]::NewLine)) }
    $match = [regex]::Match(($out -join [Environment]::NewLine), 'noise_static_public_key_hex=([0-9a-f]{64})')
    if (-not $match.Success) { throw ("CP-0427 Noise public key missing: " + ($out -join [Environment]::NewLine)) }
    return $match.Groups[1].Value
}
function Convert-HexStringToBytes([string]$Hex) {
    if (($Hex.Length % 2) -ne 0) { throw 'CP-0427 hexadecimal byte string has odd length' }
    $bytes = [byte[]]::new([int]($Hex.Length / 2))
    for ($i = 0; $i -lt $bytes.Length; $i++) {
        $bytes[$i] = [Convert]::ToByte($Hex.Substring($i * 2, 2), 16)
    }
    return ,$bytes
}
function Submit-RawQztsTransaction([string]$Address, [string]$TransactionHex) {
    $parts = $Address.Split(':')
    $payload = Convert-HexStringToBytes $TransactionHex
    if ($payload.Length -lt 137 -or $payload.Length -gt 136 + 4096) { throw "CP-0427 transaction payload length outside TXN2 bounds: $($payload.Length)" }
    $header = [byte[]]::new(10)
    [Array]::Copy([Text.Encoding]::ASCII.GetBytes('QZTS'), 0, $header, 0, 4)
    $header[4] = 0; $header[5] = 1
    $lengthBytes = [BitConverter]::GetBytes([uint32]$payload.Length)
    [Array]::Reverse($lengthBytes)
    [Array]::Copy($lengthBytes, 0, $header, 6, 4)
    $client = [Net.Sockets.TcpClient]::new()
    try {
        $client.ReceiveTimeout = 180000
        $client.SendTimeout = 10000
        $client.Connect([Net.IPAddress]::Parse($parts[0]), [int]$parts[1])
        $stream = $client.GetStream()
        $stream.ReadTimeout = 180000
        $stream.WriteTimeout = 10000
        $stream.Write($header, 0, $header.Length)
        $stream.Write($payload, 0, $payload.Length)
        $response = [byte[]]::new(43)
        $readTotal = 0
        while ($readTotal -lt $response.Length) {
            $read = $stream.Read($response, $readTotal, $response.Length - $readTotal)
            if ($read -le 0) { throw 'CP-0427 peer closed before a complete QZTA acknowledgement' }
            $readTotal += $read
        }
        if ([Text.Encoding]::ASCII.GetString($response, 0, 4) -ne 'QZTA' -or $response[4] -ne 0 -or $response[5] -ne 1) {
            throw 'CP-0427 malformed QZTA/1 acknowledgement'
        }
        $countBytes = [byte[]]@($response[7], $response[8], $response[9], $response[10])
        [Array]::Reverse($countBytes)
        return [pscustomobject]@{ Status = [int]$response[6]; MempoolCount = [BitConverter]::ToUInt32($countBytes, 0) }
    }
    finally { $client.Dispose() }
}

$network = 'd4' * 32
$recipient = '44' * 32
$miner = '33' * 32
$walletPath = Join-Path $root 'founder-live-test.qzw1'
$walletCreate = @(& $walletExe create --output $walletPath 2>&1)
if ($LASTEXITCODE -ne 0) { throw ("CP-0427 temporary DPAPI wallet creation failed: " + ($walletCreate -join [Environment]::NewLine)) }
$walletOutput = @(& $walletExe address --wallet $walletPath 2>&1)
if ($LASTEXITCODE -ne 0) { throw ("CP-0427 temporary wallet could not be reopened: " + ($walletOutput -join [Environment]::NewLine)) }
$walletText = $walletOutput -join [Environment]::NewLine
$pubMatch = [regex]::Match($walletText, 'public_key_hex=([0-9a-f]{64})')
$ownerMatch = [regex]::Match($walletText, 'account_id_hex=([0-9a-f]{64})')
if (-not ($pubMatch.Success -and $ownerMatch.Success)) { throw ("CP-0427 wallet identity fields missing: " + $walletText) }
$txPublicKey = $pubMatch.Groups[1].Value
$owner = $ownerMatch.Groups[1].Value
$txAmountAtoms = '10000000000000000'
$txFeeAtoms = '1'
$txExpiresAt = '4102444800'
$signArgs = @('sign-transfer', '--wallet', $walletPath, '--network-id-hex', $network,
    '--recipient-id-hex', $recipient, '--nonce', '1', '--amount-atoms', $txAmountAtoms,
    '--fee-atoms', $txFeeAtoms, '--expires-at', $txExpiresAt)
$signedOutput = @(& $walletExe @signArgs 2>&1)
if ($LASTEXITCODE -ne 0) { throw ("CP-0427 self-contained TXN2 signing failed: " + ($signedOutput -join [Environment]::NewLine)) }
$signedText = $signedOutput -join [Environment]::NewLine
$wireMatch = [regex]::Match($signedText, 'tx_wire_hex=([0-9a-f]+)')
if (-not $wireMatch.Success -or $signedText -notmatch 'tx_signature_mode=self-contained-ed25519-v1') {
    throw ("CP-0427 self-contained TXN2 payload missing: " + $signedText)
}
$txWireHex = $wireMatch.Groups[1].Value
$mutatedNibble = if ($txWireHex.EndsWith('0')) { '1' } else { '0' }
$invalidWireHex = $txWireHex.Substring(0, $txWireHex.Length - 1) + $mutatedNibble

$subsidy = '35673515981'
$halving = '4204800'
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
$txPortB = Get-FreePort
$ports = @($portA, $portB, $portC, $txPortB)
while (($ports | Select-Object -Unique).Count -ne $ports.Count) {
    $portB = Get-FreePort; $portC = Get-FreePort; $txPortB = Get-FreePort
    $ports = @($portA, $portB, $portC, $txPortB)
}
$addrA = "127.0.0.1:$portA"
$addrB = "127.0.0.1:$portB"
$addrC = "127.0.0.1:$portC"
$txAddrB = "127.0.0.1:$txPortB"
$nodeA = $null
$nodeB = $null
$nodeC = $null

try {
    $argsA = @(
        '--qzbe-v04-peer-smoke', '--network-id', $network, '--owner-id', $owner,
        '--miner-id', $miner, '--tx-public-key-hex', $txPublicKey,
        '--observe-account-id', $recipient, '--initial-subsidy-atoms', $subsidy,
        '--blocks-per-halving', $halving, '--data-dir', $dataA, '--listen', $addrA,
        '--trusted-peer-key-hex', $pubB, '--noise-static-private-key-dpapi-file', $keyA,
        '--mine-blocks', '0', '--run-seconds', '3600', '--stop-after-height', '3'
    )
    $nodeA = Start-Process -FilePath $nodeExe -ArgumentList $argsA -RedirectStandardOutput $stdA -RedirectStandardError $logA -PassThru
    if (-not (Wait-Pattern $logA 'event=qzbe_v04_peer_smoke_ready .*tx_ingress=QZTS/1 .*local_only=true public_launch_approved=false' 20000)) {
        throw ("CP-0427 receiver did not become ready: " + (Get-Text $stdA) + (Get-Text $logA))
    }

    $argsC = @(
        '--qzbe-v04-peer-smoke', '--network-id', $network, '--owner-id', $owner,
        '--miner-id', $miner, '--tx-public-key-hex', $txPublicKey,
        '--observe-account-id', $recipient, '--initial-subsidy-atoms', $subsidy,
        '--blocks-per-halving', $halving, '--data-dir', $dataC, '--listen', $addrC,
        '--trusted-peer-key-hex', $pubB, '--noise-static-private-key-dpapi-file', $keyC,
        '--mine-blocks', '0', '--run-seconds', '3600', '--stop-after-height', '3'
    )
    $nodeC = Start-Process -FilePath $nodeExe -ArgumentList $argsC -RedirectStandardOutput $stdC -RedirectStandardError $logC -PassThru
    if (-not (Wait-Pattern $logC 'event=qzbe_v04_peer_smoke_ready .*tx_ingress=QZTS/1 .*local_only=true public_launch_approved=false' 20000)) {
        throw ("CP-0427 third peer did not become ready: " + (Get-Text $stdC) + (Get-Text $logC))
    }

    $argsB = @(
        '--qzbe-v04-peer-smoke', '--network-id', $network, '--owner-id', $owner,
        '--miner-id', $miner, '--tx-public-key-hex', $txPublicKey,
        '--observe-account-id', $recipient, '--initial-subsidy-atoms', $subsidy,
        '--blocks-per-halving', $halving, '--data-dir', $dataB, '--listen', $addrB,
        '--peer', $addrA, '--trusted-peer-key-hex', $pubA,
        '--peer', $addrC, '--trusted-peer-key-hex', $pubC,
        '--noise-static-private-key-dpapi-file', $keyB, '--tx-listen', $txAddrB,
        '--mine-forever', '--stop-after-height', '3'
    )
    $nodeB = Start-Process -FilePath $nodeExe -ArgumentList $argsB -RedirectStandardOutput $stdB -RedirectStandardError $logB -PassThru
    if (-not (Wait-Pattern $logB 'event=qzbe_v04_peer_smoke_ready .*tx_ingress=QZTS/1 .*local_only=true public_launch_approved=false' 20000)) {
        throw ("CP-0427 mining/ingress node did not become ready: " + (Get-Text $stdB) + (Get-Text $logB))
    }

    $badAck = Submit-RawQztsTransaction $txAddrB $invalidWireHex
    if ($badAck.Status -ne 2 -or $badAck.MempoolCount -ne 0) {
        throw "CP-0427 invalid-signature TXN2 was not atomically rejected: status=$($badAck.Status) mempool_count=$($badAck.MempoolCount)"
    }
    Write-Host 'CP-0427 INVALID_SIGNATURE_REJECTED_ATOMICALLY_PASS'

    $submitOutput = @(& $walletExe @signArgs '--submit-to' $txAddrB 2>&1)
    if ($LASTEXITCODE -ne 0) { throw ("CP-0427 wallet TXN2 live submission failed: " + ($submitOutput -join [Environment]::NewLine)) }
    $submitText = $submitOutput -join [Environment]::NewLine
    if ($submitText -notmatch 'tx_submit_status=accepted' -or $submitText -notmatch 'tx_submit_mempool_count=1') {
        throw ("CP-0427 node did not acknowledge valid TXN2 admission: " + $submitText)
    }
    Write-Host 'CP-0427 WALLET_TO_NODE_QZTS_TRANSACTION_ADMISSION_PASS'

    if (-not (Wait-Pattern $logB 'event=qzbe_v04_peer_smoke_stopped .*height=3 .*replay=matched' 3600000)) {
        throw ("CP-0427 miner did not stop at height 3: " + (Get-Text $stdB) + (Get-Text $logB))
    }
    if (-not (Wait-Pattern $logA 'event=qzbe_v04_peer_smoke_stopped .*height=3 .*replay=matched' 3600000)) {
        throw ("CP-0427 node A did not converge/replay at height 3: " + (Get-Text $stdA) + (Get-Text $logA))
    }
    if (-not (Wait-Pattern $logC 'event=qzbe_v04_peer_smoke_stopped .*height=3 .*replay=matched' 3600000)) {
        throw ("CP-0427 node C did not converge/replay at height 3: " + (Get-Text $stdC) + (Get-Text $logC))
    }
    Wait-Process -Id $nodeA.Id -Timeout 15 -ErrorAction SilentlyContinue
    Wait-Process -Id $nodeB.Id -Timeout 15 -ErrorAction SilentlyContinue
    Wait-Process -Id $nodeC.Id -Timeout 15 -ErrorAction SilentlyContinue
    foreach ($proc in @($nodeA, $nodeB, $nodeC)) {
        if ($null -ne $proc -and $null -ne (Get-Process -Id $proc.Id -ErrorAction SilentlyContinue)) {
            throw "CP-0427 node stayed alive after stop event (pid=$($proc.Id))"
        }
    }
    foreach ($log in @($logA, $logB, $logC)) {
        if ((Get-Text $log) -match 'event=devnet_qzbe_v04_dispatch_failed|panicked at') {
            throw ("CP-0427 node failure marker found in ${log}: " + (Get-Text $log))
        }
    }
    if ((Get-Text $logB) -notmatch 'event=qzbe_v04_tx_admitted .*mempool_count=1' -or
        (Get-Text $logB) -notmatch 'event=qzbe_v04_tx_rejected .*rejected_atomically=true') {
        throw ("CP-0427 missing live TXN2 ingress admission/rejection events: " + (Get-Text $logB))
    }
    if ((Get-Text $logA) -notmatch 'event=qzbe_v04_tx_gossip_admitted .*mempool_count=1' -or
        (Get-Text $logC) -notmatch 'event=qzbe_v04_tx_gossip_admitted .*mempool_count=1') {
        throw ("CP-0427 valid transaction did not reach both pinned peers over QZTG/1. A=" + (Get-Text $logA) + " C=" + (Get-Text $logC))
    }
    if ((Get-Text $logB) -notmatch ('event=qzbe_v04_tx_gossip_sent origin=wallet .*peer=' + [regex]::Escape($addrA)) -or
        (Get-Text $logB) -notmatch ('event=qzbe_v04_tx_gossip_sent origin=wallet .*peer=' + [regex]::Escape($addrC))) {
        throw ("CP-0427 sender did not ACK QZTG/1 from both configured peers: " + (Get-Text $logB))
    }

    $finalPattern = 'event=qzbe_v04_peer_smoke_stopped .*height=3 state_root=([0-9a-f]{64}) tip=([0-9a-f]{64}).*observed_balance_atoms=' + $txAmountAtoms + '.*replay=matched'
    $finalA = [regex]::Match((Get-Text $logA), $finalPattern)
    $finalB = [regex]::Match((Get-Text $logB), $finalPattern)
    $finalC = [regex]::Match((Get-Text $logC), $finalPattern)
    if (-not ($finalA.Success -and $finalB.Success -and $finalC.Success)) {
        throw 'CP-0427 final snapshots, recipient balance, and replay are missing from one or more nodes.'
    }
    foreach ($final in @($finalB, $finalC)) {
        if ($final.Groups[1].Value -ne $finalA.Groups[1].Value -or $final.Groups[2].Value -ne $finalA.Groups[2].Value) {
            throw 'CP-0427 three canonical state roots/tips did not converge.'
        }
    }
    Write-Host 'CP-0427 INVALID_SIGNATURE_REJECTED_ATOMICALLY_PASS'
    Write-Host 'CP-0427 WALLET_TO_NODE_QZTS_TRANSACTION_ADMISSION_PASS'
    Write-Host 'CP-0427 TRANSACTION_GOSSIP_REACHED_BOTH_PINNED_PEERS_PASS'
    Write-Host 'CP-0427 THREE_NODE_BLOCK_STATE_ROOT_TIP_REPLAY_CONVERGENCE_PASS'
    Write-Host ("CP-0427 TRANSACTION_ID=" + ([regex]::Match($submitText, 'tx_submit_transaction_id_hex=([0-9a-f]{64})')).Groups[1].Value)
    Write-Host ("CP-0427 RECIPIENT_BALANCE_ATOMS=" + $txAmountAtoms)
}
finally {
    foreach ($proc in @($nodeA, $nodeB, $nodeC)) {
        if ($null -ne $proc) {
            $proc.Refresh()
            if (-not $proc.HasExited) { Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue }
        }
    }
    Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
}
