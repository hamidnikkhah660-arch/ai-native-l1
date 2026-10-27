$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repo = Split-Path -Parent $PSScriptRoot
Set-Location $repo
$manifest = '.\src\native\pow_bench\Cargo.toml'
$null = cargo +stable build --release --manifest-path $manifest --bin devnet_node --bin noise_key_provisioner --bin qzxb_wallet --quiet
if ($LASTEXITCODE -ne 0) { throw 'CP-0426 QZBE live TXN2 ingress release build failed' }
$null = cargo +stable test --manifest-path $manifest --bin qzxb_wallet --locked --quiet
if ($LASTEXITCODE -ne 0) { throw 'CP-0426 native wallet unit tests failed' }
$null = cargo +stable test --manifest-path $manifest --lib qzbe_tx_ingress_candidate::tests --locked --quiet
if ($LASTEXITCODE -ne 0) { throw 'CP-0426 QZTS/1 ingress framing tests failed' }
$null = cargo +stable test --manifest-path $manifest --bin devnet_node --locked --quiet
if ($LASTEXITCODE -ne 0) { throw 'CP-0426 QZBE runtime/parser/authentication tests failed' }
Write-Host 'CP-0426 WALLET_INGRESS_AND_QZBE_UNIT_TESTS_PASS'

$nodeExe = (Resolve-Path '.\src\native\pow_bench\target\release\devnet_node.exe').Path
$keyExe = (Resolve-Path '.\src\native\pow_bench\target\release\noise_key_provisioner.exe').Path
$walletExe = (Resolve-Path '.\src\native\pow_bench\target\release\qzxb_wallet.exe').Path
$root = Join-Path $env:TEMP ("ain1_cp0426_qzxb_live_ingress_" + [guid]::NewGuid().ToString('N'))
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
    if ($LASTEXITCODE -ne 0) { throw ("CP-0426 Noise key provisioning failed: " + ($out -join [Environment]::NewLine)) }
    $match = [regex]::Match(($out -join [Environment]::NewLine), 'noise_static_public_key_hex=([0-9a-f]{64})')
    if (-not $match.Success) { throw ("CP-0426 Noise public key missing: " + ($out -join [Environment]::NewLine)) }
    return $match.Groups[1].Value
}
function Convert-HexStringToBytes([string]$Hex) {
    if (($Hex.Length % 2) -ne 0) { throw 'CP-0426 hexadecimal byte string has odd length' }
    $bytes = [byte[]]::new([int]($Hex.Length / 2))
    for ($i = 0; $i -lt $bytes.Length; $i++) {
        $bytes[$i] = [Convert]::ToByte($Hex.Substring($i * 2, 2), 16)
    }
    return ,$bytes
}
function Submit-RawQztsTransaction([string]$Address, [string]$TransactionHex) {
    $parts = $Address.Split(':')
    $payload = Convert-HexStringToBytes $TransactionHex
    if ($payload.Length -lt 137 -or $payload.Length -gt 136 + 4096) { throw "CP-0426 transaction payload length outside TXN2 bounds: $($payload.Length)" }
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
            if ($read -le 0) { throw 'CP-0426 peer closed before a complete QZTA acknowledgement' }
            $readTotal += $read
        }
        if ([Text.Encoding]::ASCII.GetString($response, 0, 4) -ne 'QZTA' -or $response[4] -ne 0 -or $response[5] -ne 1) {
            throw 'CP-0426 malformed QZTA/1 acknowledgement'
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
if ($LASTEXITCODE -ne 0) { throw ("CP-0426 temporary DPAPI wallet creation failed: " + ($walletCreate -join [Environment]::NewLine)) }
$walletOutput = @(& $walletExe address --wallet $walletPath 2>&1)
if ($LASTEXITCODE -ne 0) { throw ("CP-0426 temporary wallet could not be reopened: " + ($walletOutput -join [Environment]::NewLine)) }
$walletText = $walletOutput -join [Environment]::NewLine
$pubMatch = [regex]::Match($walletText, 'public_key_hex=([0-9a-f]{64})')
$ownerMatch = [regex]::Match($walletText, 'account_id_hex=([0-9a-f]{64})')
if (-not ($pubMatch.Success -and $ownerMatch.Success)) { throw ("CP-0426 wallet identity fields missing: " + $walletText) }
$txPublicKey = $pubMatch.Groups[1].Value
$owner = $ownerMatch.Groups[1].Value
$txAmountAtoms = '10000000000000000'
$txFeeAtoms = '1'
$txExpiresAt = '4102444800'
$signArgs = @('sign-transfer', '--wallet', $walletPath, '--network-id-hex', $network,
    '--recipient-id-hex', $recipient, '--nonce', '1', '--amount-atoms', $txAmountAtoms,
    '--fee-atoms', $txFeeAtoms, '--expires-at', $txExpiresAt)
$signedOutput = @(& $walletExe @signArgs 2>&1)
if ($LASTEXITCODE -ne 0) { throw ("CP-0426 self-contained TXN2 signing failed: " + ($signedOutput -join [Environment]::NewLine)) }
$signedText = $signedOutput -join [Environment]::NewLine
$wireMatch = [regex]::Match($signedText, 'tx_wire_hex=([0-9a-f]+)')
if (-not $wireMatch.Success -or $signedText -notmatch 'tx_signature_mode=self-contained-ed25519-v1') {
    throw ("CP-0426 self-contained TXN2 payload missing: " + $signedText)
}
$txWireHex = $wireMatch.Groups[1].Value
$mutatedNibble = if ($txWireHex.EndsWith('0')) { '1' } else { '0' }
$invalidWireHex = $txWireHex.Substring(0, $txWireHex.Length - 1) + $mutatedNibble

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
$txPortB = Get-FreePort
while ($portB -eq $portA -or $txPortB -eq $portA -or $txPortB -eq $portB) { $portB = Get-FreePort; $txPortB = Get-FreePort }
$addrA = "127.0.0.1:$portA"
$addrB = "127.0.0.1:$portB"
$txAddrB = "127.0.0.1:$txPortB"
$nodeA = $null
$nodeB = $null

try {
    $argsA = @(
        '--qzbe-v04-peer-smoke', '--test-easy-pow', '--network-id', $network, '--owner-id', $owner,
        '--miner-id', $miner, '--tx-public-key-hex', $txPublicKey,
        '--observe-account-id', $recipient, '--initial-subsidy-atoms', $subsidy,
        '--blocks-per-halving', $halving, '--data-dir', $dataA, '--listen', $addrA,
        '--trusted-peer-key-hex', $pubB, '--noise-static-private-key-dpapi-file', $keyA,
        '--mine-blocks', '0', '--run-seconds', '3600', '--stop-after-height', '3'
    )
    $nodeA = Start-Process -FilePath $nodeExe -ArgumentList $argsA -RedirectStandardOutput $stdA -RedirectStandardError $logA -PassThru
    if (-not (Wait-Pattern $logA 'event=qzbe_v04_peer_smoke_ready .*tx_ingress=QZTS/1 .*local_only=true public_launch_approved=false' 20000)) {
        throw ("CP-0426 receiver did not become ready: " + (Get-Text $stdA) + (Get-Text $logA))
    }

    $argsB = @(
        '--qzbe-v04-peer-smoke', '--test-easy-pow', '--network-id', $network, '--owner-id', $owner,
        '--miner-id', $miner, '--tx-public-key-hex', $txPublicKey,
        '--observe-account-id', $recipient, '--initial-subsidy-atoms', $subsidy,
        '--blocks-per-halving', $halving, '--data-dir', $dataB, '--listen', $addrB,
        '--peer', $addrA, '--trusted-peer-key-hex', $pubA,
        '--noise-static-private-key-dpapi-file', $keyB, '--tx-listen', $txAddrB,
        '--mine-forever', '--stop-after-height', '3'
    )
    $nodeB = Start-Process -FilePath $nodeExe -ArgumentList $argsB -RedirectStandardOutput $stdB -RedirectStandardError $logB -PassThru
    if (-not (Wait-Pattern $logB 'event=qzbe_v04_peer_smoke_ready .*tx_ingress=QZTS/1 .*local_only=true public_launch_approved=false' 20000)) {
        throw ("CP-0426 mining/ingress node did not become ready: " + (Get-Text $stdB) + (Get-Text $logB))
    }

    $badAck = Submit-RawQztsTransaction $txAddrB $invalidWireHex
    if ($badAck.Status -ne 2 -or $badAck.MempoolCount -ne 0) {
        throw "CP-0426 invalid-signature TXN2 was not atomically rejected: status=$($badAck.Status) mempool_count=$($badAck.MempoolCount)"
    }
    Write-Host 'CP-0426 INVALID_SIGNATURE_REJECTED_ATOMICALLY_PASS'

    $submitOutput = @(& $walletExe @signArgs '--submit-to' $txAddrB 2>&1)
    if ($LASTEXITCODE -ne 0) { throw ("CP-0426 wallet TXN2 live submission failed: " + ($submitOutput -join [Environment]::NewLine)) }
    $submitText = $submitOutput -join [Environment]::NewLine
    if ($submitText -notmatch 'tx_submit_status=accepted' -or $submitText -notmatch 'tx_submit_mempool_count=1') {
        throw ("CP-0426 node did not acknowledge valid TXN2 admission: " + $submitText)
    }
    Write-Host 'CP-0426 WALLET_TO_NODE_QZTS_TRANSACTION_ADMISSION_PASS'

    if (-not (Wait-Pattern $logB 'event=qzbe_v04_peer_smoke_stopped .*height=3 .*replay=matched' 3600000)) {
        throw ("CP-0426 continuous miner did not stop at height 3: " + (Get-Text $stdB) + (Get-Text $logB))
    }
    if (-not (Wait-Pattern $logA 'event=qzbe_v04_peer_smoke_stopped .*height=3 .*replay=matched' 3600000)) {
        throw ("CP-0426 receiver did not converge/replay at height 3: " + (Get-Text $stdA) + (Get-Text $logA))
    }
    Wait-Process -Id $nodeA.Id -Timeout 15 -ErrorAction SilentlyContinue
    Wait-Process -Id $nodeB.Id -Timeout 15 -ErrorAction SilentlyContinue
    if ($null -ne (Get-Process -Id $nodeA.Id -ErrorAction SilentlyContinue)) { throw "CP-0426 receiver stayed alive after stop event (pid=$($nodeA.Id))" }
    if ($null -ne (Get-Process -Id $nodeB.Id -ErrorAction SilentlyContinue)) { throw "CP-0426 miner stayed alive after stop event (pid=$($nodeB.Id))" }
    if ((Get-Text $logA) -match 'event=devnet_qzbe_v04_dispatch_failed|panicked at' -or (Get-Text $logB) -match 'event=devnet_qzbe_v04_dispatch_failed|panicked at') {
        throw ("CP-0426 node failure marker found: " + (Get-Text $logA) + (Get-Text $logB))
    }
    if ((Get-Text $logB) -notmatch 'event=qzbe_v04_tx_admitted .*mempool_count=1' -or
        (Get-Text $logB) -notmatch 'event=qzbe_v04_tx_rejected .*rejected_atomically=true') {
        throw ("CP-0426 missing live TXN2 ingress admission/rejection audit events: " + (Get-Text $logB))
    }

    $finalA = [regex]::Match((Get-Text $logA), 'event=qzbe_v04_peer_smoke_stopped .*height=3 state_root=([0-9a-f]{64}) tip=([0-9a-f]{64}).*observed_balance_atoms=' + $txAmountAtoms + '.*replay=matched')
    $finalB = [regex]::Match((Get-Text $logB), 'event=qzbe_v04_peer_smoke_stopped .*height=3 state_root=([0-9a-f]{64}) tip=([0-9a-f]{64}).*observed_balance_atoms=' + $txAmountAtoms + '.*replay=matched')
    if (-not ($finalA.Success -and $finalB.Success)) { throw 'CP-0426 final canonical snapshots/recipient balance/replay are missing.' }
    if ($finalA.Groups[1].Value -ne $finalB.Groups[1].Value -or $finalA.Groups[2].Value -ne $finalB.Groups[2].Value) {
        throw 'CP-0426 receiver and miner canonical state did not converge.'
    }
    Write-Host 'CP-0426 SELF_CONTAINED_TXN2_MINED_IN_CANONICAL_BLOCK_PASS'
    Write-Host ("CP-0426 TRANSACTION_ID=" + ([regex]::Match($submitText, 'tx_submit_transaction_id_hex=([0-9a-f]{64})')).Groups[1].Value)
    Write-Host ("CP-0426 RECIPIENT_BALANCE_ATOMS=" + $txAmountAtoms)
    Write-Host 'CP-0426 TWO_NODE_STATE_ROOT_TIP_REPLAY_CONVERGENCE_PASS'
}
catch {
    Write-Host 'CP-0426 FAILURE_NODE_A_STDOUT_BEGIN'
    Write-Host (Get-Text $stdA)
    Write-Host 'CP-0426 FAILURE_NODE_A_STDERR_BEGIN'
    Write-Host (Get-Text $logA)
    Write-Host 'CP-0426 FAILURE_NODE_B_STDOUT_BEGIN'
    Write-Host (Get-Text $stdB)
    Write-Host 'CP-0426 FAILURE_NODE_B_STDERR_BEGIN'
    Write-Host (Get-Text $logB)
    throw
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
