$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repo = Split-Path -Parent $PSScriptRoot
Set-Location $repo
$manifest = '.\src\native\pow_bench\Cargo.toml'
$null = cargo +stable build --release --manifest-path $manifest --bin devnet_node --bin noise_key_provisioner --bin qzxb_amm_client --quiet
if ($LASTEXITCODE -ne 0) { throw 'CP-0441 release build failed' }
cargo +stable test --manifest-path $manifest --lib qzxb_amm_candidate::tests::test_quote_faucet_is_testnet_only_and_supply_capped --locked --quiet
if ($LASTEXITCODE -ne 0) { throw 'CP-0441 test-quote faucet safety tests failed' }
cargo +stable test --manifest-path $manifest --bin qzxb_amm_client --locked --quiet
if ($LASTEXITCODE -ne 0) { throw 'CP-0441 AMM wallet/client unit tests failed' }

$nodeExe = (Resolve-Path '.\src\native\pow_bench\target\release\devnet_node.exe').Path
$keyExe = (Resolve-Path '.\src\native\pow_bench\target\release\noise_key_provisioner.exe').Path
$ammExe = (Resolve-Path '.\src\native\pow_bench\target\release\qzxb_amm_client.exe').Path
$root = Join-Path $env:TEMP ("ain1_cp0441_native_amm_" + [guid]::NewGuid().ToString('N'))
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
function Convert-HexStringToBytes([string]$Hex) {
    if (($Hex.Length % 2) -ne 0) { throw 'CP-0441 hexadecimal value has odd length' }
    $bytes = [byte[]]::new([int]($Hex.Length / 2))
    for ($i = 0; $i -lt $bytes.Length; $i++) {
        $bytes[$i] = [Convert]::ToByte($Hex.Substring($i * 2, 2), 16)
    }
    return ,$bytes
}
function Join-Bytes([byte[]]$Left, [byte[]]$Right) {
    $joined = [byte[]]::new($Left.Length + $Right.Length)
    [Array]::Copy($Left, 0, $joined, 0, $Left.Length)
    [Array]::Copy($Right, 0, $joined, $Left.Length, $Right.Length)
    return ,$joined
}
function Get-Sha256Hex([byte[]]$Bytes) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash($Bytes))).Replace('-', '').ToLowerInvariant() }
    finally { $sha.Dispose() }
}
function Get-DomainHash([string]$Domain, [string]$SuffixHex) {
    $prefix = [Text.Encoding]::UTF8.GetBytes($Domain + [char]0)
    return Get-Sha256Hex (Join-Bytes $prefix (Convert-HexStringToBytes $SuffixHex))
}
function Provision-Key([string]$Path, [string]$Network) {
    $out = @(& $keyExe --output $Path --network-id-hex $Network 2>&1)
    if ($LASTEXITCODE -ne 0) { throw ("CP-0441 Noise-key provisioning failed: " + ($out -join [Environment]::NewLine)) }
    $match = [regex]::Match(($out -join [Environment]::NewLine), 'noise_static_public_key_hex=([0-9a-f]{64})')
    if (-not $match.Success) { throw ("CP-0441 Noise public key missing: " + ($out -join [Environment]::NewLine)) }
    return $match.Groups[1].Value
}
function Submit-Amm([int]$Nonce, [string[]]$OperationArguments) {
    $cmd = @('--seed-file', $seedPath, '--network-id', $network, '--nonce', [string]$Nonce,
        '--expires-at', $expiresAt, '--endpoint', $ammAddress, '--operation')
    $cmd += $OperationArguments
    $cmd += '--submit'
    $out = @(& $ammExe @cmd 2>&1)
    if ($LASTEXITCODE -ne 0) { throw ("CP-0441 AMM operation failed at nonce " + $Nonce + ": " + ($out -join [Environment]::NewLine)) }
    $joined = $out -join [Environment]::NewLine
    if ($joined -notmatch 'ACK status=Accepted') {
        throw ("CP-0441 AMM operation was not accepted at nonce " + $Nonce + ": " + $joined)
    }
    Write-Host ("CP-0441 AMM_ADMITTED nonce=" + $Nonce + " operation=" + $OperationArguments[0])
}

$network = 'd4' * 32
$expiresAt = '4102444800'
$seedPath = Join-Path $root 'testnet-only-seed.hex'
[IO.File]::WriteAllText($seedPath, ('4e' * 32), [Text.Encoding]::ASCII)
$identity = @(& $ammExe --seed-file $seedPath --show-account 2>&1)
if ($LASTEXITCODE -ne 0) { throw ("CP-0441 test key identity failed: " + ($identity -join [Environment]::NewLine)) }
$identityText = $identity -join [Environment]::NewLine
$ownerMatch = [regex]::Match($identityText, 'account_id=([0-9a-f]{64})')
$pubMatch = [regex]::Match($identityText, 'public_key=([0-9a-f]{64})')
if (-not ($ownerMatch.Success -and $pubMatch.Success)) { throw ("CP-0441 test account fields missing: " + $identityText) }
$owner = $ownerMatch.Groups[1].Value
$txPublicKey = $pubMatch.Groups[1].Value
$miner = '33' * 32

$nativeAsset = Get-DomainHash 'QZXB-NATIVE-ASSET-ID-V1' $network
$quoteAsset = Get-DomainHash 'QZXB-TESTNET-QUSDT-ASSET-ID-V1' $network
if ([string]::CompareOrdinal($nativeAsset, $quoteAsset) -lt 0) {
    $token0 = $nativeAsset; $token1 = $quoteAsset
} else {
    $token0 = $quoteAsset; $token1 = $nativeAsset
}
$pairPrefix = [Text.Encoding]::UTF8.GetBytes('QZXB-NATIVE-AMM-PAIR-V1' + [char]0)
$pairSuffix = Join-Bytes (Convert-HexStringToBytes $token0) (Convert-HexStringToBytes $token1)
$pairId = Get-Sha256Hex (Join-Bytes $pairPrefix $pairSuffix)
Write-Host ("CP-0441 NATIVE_QZXB_ASSET_ID=" + $nativeAsset)
Write-Host ("CP-0441 TEST_QUOTE_ASSET_ID=" + $quoteAsset + " ticker=QUSDT_TESTNET_UNBACKED")
Write-Host ("CP-0441 PAIR_ID=" + $pairId)

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
$ammPortB = Get-FreePort
$rpcPortA = Get-FreePort
while (@($portA, $portB, $ammPortB, $rpcPortA | Select-Object -Unique).Count -lt 4) {
    $portB = Get-FreePort; $ammPortB = Get-FreePort; $rpcPortA = Get-FreePort
}
$addrA = "127.0.0.1:$portA"
$addrB = "127.0.0.1:$portB"
$ammAddress = "127.0.0.1:$ammPortB"
$rpcAddress = "http://127.0.0.1:$rpcPortA"
$nodeA = $null
$nodeB = $null

try {
    $argsA = @(
        '--qzbe-v04-peer-smoke', '--test-easy-pow', '--network-id', $network, '--owner-id', $owner,
        '--miner-id', $miner, '--tx-public-key-hex', $txPublicKey,
        '--observe-account-id', $owner, '--initial-subsidy-atoms', '35673515981',
        '--blocks-per-halving', '4204800', '--data-dir', $dataA, '--listen', $addrA,
        '--trusted-peer-key-hex', $pubB, '--noise-static-private-key-dpapi-file', $keyA,
        '--rpc-listen', ("127.0.0.1:" + $rpcPortA), '--mine-blocks', '0', '--run-seconds', '3600'
    )
    $nodeA = Start-Process -FilePath $nodeExe -ArgumentList $argsA -RedirectStandardOutput $stdA -RedirectStandardError $logA -PassThru
    if (-not (Wait-Pattern $logA ('event=qzbe_v04_peer_smoke_ready .*rpc_listen=127.0.0.1:' + $rpcPortA + ' .*local_only=true public_launch_approved=false') 20000)) {
        throw ("CP-0441 observer node failed to start: " + (Get-Text $stdA) + (Get-Text $logA))
    }

    $argsB = @(
        '--qzbe-v04-peer-smoke', '--test-easy-pow', '--network-id', $network, '--owner-id', $owner,
        '--miner-id', $miner, '--tx-public-key-hex', $txPublicKey,
        '--observe-account-id', $owner, '--initial-subsidy-atoms', '35673515981',
        '--blocks-per-halving', '4204800', '--data-dir', $dataB, '--listen', $addrB,
        '--peer', $addrA, '--trusted-peer-key-hex', $pubA,
        '--noise-static-private-key-dpapi-file', $keyB, '--amm-listen', $ammAddress,
        '--mine-forever', '--stop-after-height', '48'
    )
    $nodeB = Start-Process -FilePath $nodeExe -ArgumentList $argsB -RedirectStandardOutput $stdB -RedirectStandardError $logB -PassThru
    if (-not (Wait-Pattern $logB 'event=qzbe_v04_peer_smoke_ready .*amm_listen=127.0.0.1:[0-9]+ .*tx_ingress=QZTS/1 .*local_only=true public_launch_approved=false' 20000)) {
        throw ("CP-0441 AMM/miner node failed to start: " + (Get-Text $stdB) + (Get-Text $logB))
    }

    Submit-Amm 1 @('mint-test-quote', '--amount', '1000000000000000')
    Submit-Amm 2 @('create-pair', '--token-a', $nativeAsset, '--token-b', $quoteAsset)
    Submit-Amm 3 @('add-liquidity', '--pair-id', $pairId, '--amount0', '1000000000000', '--amount1', '1000000000000', '--min-lp', '1')
    Submit-Amm 4 @('swap-exact-in', '--token-in', $quoteAsset, '--token-out', $nativeAsset, '--amount-in', '1000000000', '--min-amount-out', '1')
    Write-Host 'CP-0441 LIVE_QZAS_MINT_CREATE_PAIR_ADD_LIQUIDITY_SWAP_ADMISSION_PASS'

    if (-not (Wait-Pattern $logB 'event=qzbe_v04_peer_smoke_stopped .*height=48 .*replay=matched' 3600000)) {
        throw ("CP-0441 miner failed to complete bounded testnet run: " + (Get-Text $stdB) + (Get-Text $logB))
    }
    $finalB = [regex]::Match((Get-Text $logB), 'event=qzbe_v04_peer_smoke_stopped .*height=48 state_root=([0-9a-f]{64}) tip=([0-9a-f]{64}).*amm_submissions=([0-9]+).*replay=matched')
    if (-not $finalB.Success) { throw ("CP-0441 final miner summary missing AMM/replay data: " + (Get-Text $logB)) }
    if (-not (Wait-Pattern $logA 'event=qzbe_v04_peer_block_accepted .*height=48 ' 30000)) {
        throw ("CP-0441 observer did not receive final canonical block: " + (Get-Text $logA))
    }
    $finalA = [regex]::Match((Get-Text $logA), 'event=qzbe_v04_peer_block_accepted .*height=48 digest=([0-9a-f]{64}) tip=([0-9a-f]{64}) state_root=([0-9a-f]{64})')
    if (-not $finalA.Success -or $finalA.Groups[2].Value -ne $finalB.Groups[2].Value -or $finalA.Groups[3].Value -ne $finalB.Groups[1].Value) {
        throw ("CP-0441 peer canonical state did not converge. NodeA=" + $finalA.Value + " NodeB=" + $finalB.Value)
    }
    Write-Host 'CP-0441 TWO_NODE_CANONICAL_STATE_ROOT_TIP_CONVERGENCE_PASS'

    $rpcResult = Invoke-RestMethod -Method Get -Uri ($rpcAddress + '/v1/amm/swaps?min_confirmations=1&limit_blocks=8') -TimeoutSec 3
    if ($rpcResult.mainnet -ne $false -or $rpcResult.public_launch_approved -ne $false -or $rpcResult.read_only -ne $true) {
        throw 'CP-0441 test fixture unexpectedly mislabels candidate RPC launch status'
    }
    if ($rpcResult.height -ne 48 -or $rpcResult.tip -ne $finalB.Groups[2].Value) {
        throw ("CP-0441 RPC canonical height/tip does not match completed miner: " + ($rpcResult | ConvertTo-Json -Depth 5 -Compress))
    }
    Write-Host 'CP-0441 READ_ONLY_RPC_CANONICAL_IDENTITY_PASS'

    $candleStd = Join-Path $root 'candle-check.out.log'
    $candleErr = Join-Path $root 'candle-check.err.log'
    $nodePath = (Get-Command node).Source
    $candleArgs = @('.\simulations\cp0441_native_candle_check.mjs', $rpcAddress, $pairId, $nativeAsset, $quoteAsset)
    $candleProcess = Start-Process -FilePath $nodePath -ArgumentList $candleArgs -RedirectStandardOutput $candleStd -RedirectStandardError $candleErr -Wait -PassThru -NoNewWindow
    $candleText = (Get-Text $candleStd) + [Environment]::NewLine + (Get-Text $candleErr)
    if ($candleProcess.ExitCode -ne 0) { throw ("CP-0441 confirmed-swap candle check failed (exit=" + $candleProcess.ExitCode + "): " + $candleText) }
    if ($candleText -notmatch 'CP-0441_HOURLY_DAILY_WEEKLY_MONTHLY_CANDLES_PASS') {
        throw ("CP-0441 timeframe candle pass markers are missing: " + $candleText)
    }
    ($candleText -split [Environment]::NewLine) | ForEach-Object { if (-not [string]::IsNullOrWhiteSpace($_)) { Write-Host $_ } }
    Write-Host 'CP-0441 NATIVE_AMM_LIVE_SWAP_AND_ALL_TIMEFRAME_CANDLES_PASS'
}
finally {
    if ($null -ne $nodeB -and $null -ne (Get-Process -Id $nodeB.Id -ErrorAction SilentlyContinue)) {
        Stop-Process -Id $nodeB.Id -Force -ErrorAction SilentlyContinue
    }
    if ($null -ne $nodeA -and $null -ne (Get-Process -Id $nodeA.Id -ErrorAction SilentlyContinue)) {
        Stop-Process -Id $nodeA.Id -Force -ErrorAction SilentlyContinue
    }
}
