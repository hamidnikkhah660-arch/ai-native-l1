param([switch]$SkipBuild)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repo = Split-Path -Parent $PSScriptRoot
Set-Location $repo
$manifest = '.\src\native\pow_bench\Cargo.toml'
$crateDir = Join-Path $repo 'src\native\pow_bench'
$targetDir = if ($env:CARGO_TARGET_DIR) { [IO.Path]::GetFullPath($env:CARGO_TARGET_DIR) } else { Join-Path $crateDir 'target' }
$profileDir = 'debug'

if (-not $SkipBuild) {
    $previousErrorPreference = $ErrorActionPreference
    try {
        # Cargo emits compiler warnings on stderr; do not let PowerShell's native-stderr
        # adapter turn an ordinary warning into a terminating PowerShell error.
        $ErrorActionPreference = 'Continue'
        $buildOutput = @(& cargo +stable build --manifest-path $manifest --locked --bin qrun_v05_pow_local_node --bin qrun_v05_noise_keygen --quiet 2>&1)
        $buildExit = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $previousErrorPreference
    }
    if ($buildExit -ne 0) {
        $buildOutput | ForEach-Object { Write-Host $_ }
        throw "CP-0449 QRun startup-sync candidate build failed (exit=$buildExit)"
    }
}

$nodeExe = Join-Path $targetDir "$profileDir\qrun_v05_pow_local_node.exe"
$keyExe = Join-Path $targetDir "$profileDir\qrun_v05_noise_keygen.exe"
foreach ($pathToCheck in @($nodeExe, $keyExe)) {
    if (-not (Test-Path -LiteralPath $pathToCheck)) { throw "CP-0449 required executable missing: $pathToCheck" }
}

function Get-FreeLoopbackPort {
    $listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
    try {
        $listener.Start()
        return [int]$listener.LocalEndpoint.Port
    }
    finally { $listener.Stop() }
}

function Wait-Pattern([string]$Path, [string]$Pattern, [int]$Millis = 20000) {
    $watch = [Diagnostics.Stopwatch]::StartNew()
    while ($watch.ElapsedMilliseconds -lt $Millis) {
        if ((Test-Path -LiteralPath $Path) -and ((Get-Content -LiteralPath $Path -Raw -ErrorAction SilentlyContinue) -match $Pattern)) {
            return $true
        }
        Start-Sleep -Milliseconds 50
    }
    return $false
}

function Get-Log([string]$Path) {
    if (Test-Path -LiteralPath $Path) { return Get-Content -LiteralPath $Path -Raw -ErrorAction SilentlyContinue }
    return ''
}

function New-NoiseKey([string]$Network, [string]$Path) {
    $output = @(& $keyExe --network-id-hex $Network --output-key-file $Path 2>&1)
    $exitCode = $LASTEXITCODE
    $text = $output -join [Environment]::NewLine
    if ($exitCode -ne 0) { throw "CP-0449 Noise key provisioning failed (exit=$exitCode): $text" }
    $match = [regex]::Match($text, 'static_public_key_hex=([0-9a-f]{64})')
    if (-not $match.Success -or $text -notmatch 'private_key_output=none') {
        throw "CP-0449 key provisioner did not return only the public-key contract: $text"
    }
    return $match.Groups[1].Value
}

function Start-QRunNode([string[]]$Arguments, [string]$Stdout, [string]$Stderr) {
    return Start-Process -FilePath $nodeExe -ArgumentList $Arguments -PassThru -RedirectStandardOutput $Stdout -RedirectStandardError $Stderr
}

$root = Join-Path $env:TEMP ("qrun_cp0449_startup_sync_" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $root | Out-Null
$networkBytes = [byte[]]::new(32)
$networkHex = ([Guid]::NewGuid().ToString('N') + [Guid]::NewGuid().ToString('N')).ToLowerInvariant()
$owner = 'eee2e72882d770ab6fd7815c905b49e39650c74e8f121b26cbd49e333a3715c8'
$ownerPublicKey = '42a45fd22f7483fc75f6c30fc25f156ab958e6eaec7eb683b5badcc90f4f5131'

$rpcA = Get-FreeLoopbackPort
$txA = Get-FreeLoopbackPort
$blockA = Get-FreeLoopbackPort
$rpcB = Get-FreeLoopbackPort
$txB = Get-FreeLoopbackPort
$blockB = Get-FreeLoopbackPort
$rpcC = Get-FreeLoopbackPort
$txC = Get-FreeLoopbackPort
$blockC = Get-FreeLoopbackPort
$deadPeerPort = Get-FreeLoopbackPort
$allPorts = @($rpcA,$txA,$blockA,$rpcB,$txB,$blockB,$rpcC,$txC,$blockC,$deadPeerPort)
while (@($allPorts | Select-Object -Unique).Count -ne $allPorts.Count) {
    $rpcC = Get-FreeLoopbackPort; $txC = Get-FreeLoopbackPort; $blockC = Get-FreeLoopbackPort; $deadPeerPort = Get-FreeLoopbackPort
    $allPorts = @($rpcA,$txA,$blockA,$rpcB,$txB,$blockB,$rpcC,$txC,$blockC,$deadPeerPort)
}

$sourceProcess = $null
$receiverProcess = $null
$failClosedProcess = $null
try {
    $keyA = Join-Path $root 'source.npk1'
    $keyB = Join-Path $root 'receiver.npk1'
    $keyC = Join-Path $root 'fail-closed.npk1'
    $pubA = New-NoiseKey $networkHex $keyA
    $pubB = New-NoiseKey $networkHex $keyB
    $null = New-NoiseKey $networkHex $keyC

    $argsA = @(
        '--local-testnet', '--network-id-hex', $networkHex,
        '--owner-account-id-hex', $owner, '--owner-public-key-hex', $ownerPublicKey,
        '--data-dir', (Join-Path $root 'source-data'),
        '--rpc-listen', "127.0.0.1:$rpcA", '--tx-listen', "127.0.0.1:$txA",
        '--block-listen', "127.0.0.1:$blockA",
        '--noise-private-key-file', $keyA,
        '--peer', "127.0.0.1:$blockB", '--peer-static-public-key-hex', $pubB
    )
    $sourceProcess = Start-QRunNode $argsA (Join-Path $root 'source.out.log') (Join-Path $root 'source.err.log')
    if (-not (Wait-Pattern (Join-Path $root 'source.out.log') 'QRUN_V05_LOCAL_POW_LOOPBACK_TESTNET_READY')) {
        throw "CP-0449 source node did not become ready: $(Get-Log (Join-Path $root 'source.out.log')) $(Get-Log (Join-Path $root 'source.err.log'))"
    }
    $sourceProcess.Refresh()
    if ($sourceProcess.HasExited) { throw 'CP-0449 source node exited before receiver startup.' }

    $argsB = @(
        '--local-testnet', '--network-id-hex', $networkHex,
        '--owner-account-id-hex', $owner, '--owner-public-key-hex', $ownerPublicKey,
        '--data-dir', (Join-Path $root 'receiver-data'),
        '--rpc-listen', "127.0.0.1:$rpcB", '--tx-listen', "127.0.0.1:$txB",
        '--block-listen', "127.0.0.1:$blockB",
        '--noise-private-key-file', $keyB,
        '--peer', "127.0.0.1:$blockA", '--peer-static-public-key-hex', $pubA,
        '--sync-on-start', 'true'
    )
    $receiverProcess = Start-QRunNode $argsB (Join-Path $root 'receiver.out.log') (Join-Path $root 'receiver.err.log')
    if (-not (Wait-Pattern (Join-Path $root 'receiver.out.log') 'qrun_pow_authenticated_startup_sync_complete .*height=0')) {
        throw "CP-0449 receiver startup sync did not complete: $(Get-Log (Join-Path $root 'receiver.out.log')) $(Get-Log (Join-Path $root 'receiver.err.log'))"
    }
    if (-not (Wait-Pattern (Join-Path $root 'receiver.out.log') 'qrun_pow_local_block_ready address=127\.0\.0\.1:\d+ protocol=QRB5/2 loopback_only=true')) {
        throw "CP-0449 receiver listeners did not bind after startup sync: $(Get-Log (Join-Path $root 'receiver.out.log')) $(Get-Log (Join-Path $root 'receiver.err.log'))"
    }
    $receiverText = Get-Log (Join-Path $root 'receiver.out.log')
    if ($receiverText.IndexOf('qrun_pow_authenticated_startup_sync_complete') -gt $receiverText.IndexOf('qrun_pow_local_rpc_ready')) {
        throw 'CP-0449 receiver RPC listener was reported before startup sync completed.'
    }
    $status = $null
    for ($attempt = 0; $attempt -lt 5; $attempt++) {
        try {
            $status = Invoke-RestMethod -Uri "http://127.0.0.1:$rpcB/v1/status" -TimeoutSec 3
            break
        }
        catch { Start-Sleep -Milliseconds 200 }
    }
    if ($null -eq $status -or $status.ok -ne $true -or $status.mainnet -ne $false -or $status.height -ne 0) {
        throw "CP-0449 receiver read-only RPC did not confirm the local-only genesis state."
    }
    if ($status.genesis_id -ne (Get-Content (Join-Path $root 'source.out.log') | Select-String '^genesis_id_hex=' | Select-Object -First 1 | ForEach-Object { $_.Line.Substring('genesis_id_hex='.Length) })) {
        throw 'CP-0449 source and receiver Genesis commitments differed.'
    }
    Write-Host 'CP-0449 AUTHENTICATED_STARTUP_SYNC_BEFORE_LISTENER_BIND_PASS'
    Write-Host 'CP-0449 LOOPBACK_ONLY_MAINNET_FALSE_PASS'

    # A missing/unreachable pinned peer must fail startup; RPC/TX/block listeners must never bind.
    $argsC = @(
        '--local-testnet', '--network-id-hex', $networkHex,
        '--owner-account-id-hex', $owner, '--owner-public-key-hex', $ownerPublicKey,
        '--data-dir', (Join-Path $root 'fail-closed-data'),
        '--rpc-listen', "127.0.0.1:$rpcC", '--tx-listen', "127.0.0.1:$txC",
        '--block-listen', "127.0.0.1:$blockC",
        '--noise-private-key-file', $keyC,
        '--peer', "127.0.0.1:$deadPeerPort", '--peer-static-public-key-hex', $pubA,
        '--sync-on-start', 'true'
    )
    $failClosedProcess = Start-QRunNode $argsC (Join-Path $root 'fail-closed.out.log') (Join-Path $root 'fail-closed.err.log')
    Wait-Process -Id $failClosedProcess.Id -Timeout 15 -ErrorAction SilentlyContinue
    $failClosedProcess.Refresh()
    if (-not $failClosedProcess.HasExited) { throw 'CP-0449 fail-closed node stayed alive after all pinned peers failed.' }
    $failureText = (Get-Log (Join-Path $root 'fail-closed.out.log')) + (Get-Log (Join-Path $root 'fail-closed.err.log'))
    if ($failureText -notmatch 'authenticated startup sync requested but every pinned peer failed') {
        throw "CP-0449 fail-closed startup error not found: $failureText"
    }
    $bound = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Where-Object { $_.LocalPort -in @($rpcC,$txC,$blockC) }
    if ($bound) { throw "CP-0449 failed sync node unexpectedly bound a listener: $($bound | Out-String)" }
    Write-Host 'CP-0449 FAILED_AUTHENTICATED_SYNC_DOES_NOT_BIND_LISTENERS_PASS'
}
catch {
    Write-Host 'CP-0449 FAILURE SOURCE LOG'
    Write-Host (Get-Log (Join-Path $root 'source.out.log'))
    Write-Host (Get-Log (Join-Path $root 'source.err.log'))
    Write-Host 'CP-0449 FAILURE RECEIVER LOG'
    Write-Host (Get-Log (Join-Path $root 'receiver.out.log'))
    Write-Host (Get-Log (Join-Path $root 'receiver.err.log'))
    Write-Host 'CP-0449 FAILURE FAIL-CLOSED LOG'
    Write-Host (Get-Log (Join-Path $root 'fail-closed.out.log'))
    Write-Host (Get-Log (Join-Path $root 'fail-closed.err.log'))
    throw
}
finally {
    foreach ($process in @($sourceProcess, $receiverProcess, $failClosedProcess)) {
        if ($null -ne $process) {
            $process.Refresh()
            if (-not $process.HasExited) { Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue }
        }
    }
    Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
}
