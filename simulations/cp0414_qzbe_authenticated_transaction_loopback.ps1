$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repo = Split-Path -Parent $PSScriptRoot
Set-Location $repo
$manifest = '.\src\native\pow_bench\Cargo.toml'
$null = cargo +stable build --release --manifest-path $manifest --bin qzbe_v04_peer_node --bin noise_key_provisioner --bin qzbe_v04_test_tx_signer --bin qzxb_wallet --quiet
if ($LASTEXITCODE -ne 0) { throw 'CP-0414 QZBE authenticated transaction runtime release build failed' }

$nodeExe = (Resolve-Path '.\src\native\pow_bench\target\release\qzbe_v04_peer_node.exe').Path
$keyExe = (Resolve-Path '.\src\native\pow_bench\target\release\noise_key_provisioner.exe').Path
$txSignerExe = (Resolve-Path '.\src\native\pow_bench\target\release\qzbe_v04_test_tx_signer.exe').Path
$walletExe = (Resolve-Path '.\src\native\pow_bench\target\release\qzxb_wallet.exe').Path
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
function Get-QzbeRpc([int]$Port, [string]$Path) {
    return Invoke-RestMethod -Uri ("http://127.0.0.1:{0}{1}" -f $Port, $Path) -Method Get -TimeoutSec 5
}
function Make-Signed-TestTransaction([string]$SeedPath, [string]$Network, [string]$Recipient) {
    $seed = New-Object byte[] 32
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($seed) } finally { $rng.Dispose() }
    [IO.File]::WriteAllBytes($SeedPath, $seed)
    [Array]::Clear($seed, 0, $seed.Length)
    try {
        $out = @(& $txSignerExe --seed-file $SeedPath --network-id-hex $Network --recipient-id-hex $Recipient --nonce 1 --amount-atoms 2500 --fee-atoms 7 --expires-at 4102444800 2>&1)
        $signerExit = $LASTEXITCODE
        if ($signerExit -ne 0) { throw ("CP-0414 transaction signing helper failed: " + ($out -join [Environment]::NewLine)) }
        $all = $out -join [Environment]::NewLine
        $pub = [regex]::Match($all, 'tx_public_key_hex=([0-9a-f]{64})')
        $account = [regex]::Match($all, 'tx_sender_account_id_hex=([0-9a-f]{64})')
        $signature = [regex]::Match($all, 'tx_signature_hex=([0-9a-f]{128})')
        $txid = [regex]::Match($all, 'tx_id_hex=([0-9a-f]{64})')
        if (-not ($pub.Success -and $account.Success -and $signature.Success -and $txid.Success)) { throw ("CP-0414 signed transaction material / TXID missing: " + $all) }
        return @{ PublicKey = $pub.Groups[1].Value; Sender = $account.Groups[1].Value; Signature = $signature.Groups[1].Value; TransactionId = $txid.Groups[1].Value }
    }
    finally {
        Remove-Item -LiteralPath $SeedPath -Force -ErrorAction SilentlyContinue
    }
}
function Provision-Key([string]$Path, [string]$Network) {
    $out = & $keyExe --output $Path --network-id-hex $Network
    if ($LASTEXITCODE -ne 0) { throw ("CP-0414 Noise key provisioning failed: " + $Path) }
    $match = [regex]::Match(($out -join [Environment]::NewLine), 'noise_static_public_key_hex=([0-9a-f]{64})')
    if (-not $match.Success) { throw ("CP-0414 Noise public key missing: " + $Path) }
    return $match.Groups[1].Value
}

$network = 'c5' * 32
$recipient = '44' * 32
$txSeedFile = Join-Path $env:TEMP ("ain1_cp0414_tx_seed_" + [guid]::NewGuid().ToString('N') + '.bin')
$tx = Make-Signed-TestTransaction $txSeedFile $network $recipient
$owner = $tx.Sender
$txPublicKey = $tx.PublicKey
$txSignature = $tx.Signature
$miner = '33' * 32
$subsidy = '35673515981' # v0.4 candidate: 356.73515981 QZXB in atoms
$halving = '4204800' # v0.4 candidate halving interval
$expectedMinedAtoms = '71347031962' # two height-1/2 rewards before the first halving
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
$rpcPort = Get-FreePort
while ($portA -eq $portB) { $portB = Get-FreePort }
while ($rpcPort -eq $portA -or $rpcPort -eq $portB) { $rpcPort = Get-FreePort }
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
        throw ("CP-0414 public-bind guard did not fail closed (exit=$bindExitCode): " + ($bindOutput -join [Environment]::NewLine))
    }
    Write-Host 'CP-0414 PUBLIC_BIND_GUARD_PASS'

    $argsB = @(
        '--test-easy-pow',
        '--network-id', $network,
        '--owner-id', $owner,
        '--miner-id', $miner,
        '--tx-public-key-hex', $txPublicKey,
        '--observe-account-id', $recipient,
        '--initial-subsidy-atoms', $subsidy,
        '--blocks-per-halving', $halving,
        '--data-dir', $dataB,
        '--listen', "127.0.0.1:$portB",
        '--rpc-listen', "127.0.0.1:$rpcPort",
        '--noise-static-private-key-dpapi-file', $keyB,
        '--trusted-peer-key-hex', $pubA,
        '--mine-blocks', '0',
        '--run-seconds', '5'
    )
    $nodeB = Start-Process -FilePath $nodeExe -ArgumentList $argsB -RedirectStandardOutput $stdB -RedirectStandardError $logB -PassThru
    if (-not (Wait-Pattern $logB 'event=qzbe_v04_peer_smoke_ready .*height=0 .*local_only=true public_launch_approved=false' 20000)) {
        throw ("CP-0414 receiver node B did not become ready: " + (Get-Text $stdB) + (Get-Text $logB))
    }
    $rpcGenesisStatus = Get-QzbeRpc $rpcPort '/v1/status'
    $rpcGenesisBalance = Get-QzbeRpc $rpcPort ("/v1/balance/{0}" -f $recipient)
    if ($rpcGenesisStatus.height -ne 0 -or $rpcGenesisStatus.mainnet -ne $false -or
        $rpcGenesisStatus.read_only -ne $true -or $rpcGenesisBalance.balance_atoms -ne 0) {
        throw ("CP-0414 read-only RPC Genesis response mismatch: status=" + ($rpcGenesisStatus | ConvertTo-Json -Compress) +
            " balance=" + ($rpcGenesisBalance | ConvertTo-Json -Compress))
    }
    Write-Host 'CP-0414 READ_ONLY_RPC_GENESIS_PASS'

    $argsA = @(
        '--test-easy-pow',
        '--network-id', $network,
        '--owner-id', $owner,
        '--miner-id', $miner,
        '--tx-public-key-hex', $txPublicKey,
        '--observe-account-id', $recipient,
        '--initial-subsidy-atoms', $subsidy,
        '--blocks-per-halving', $halving,
        '--data-dir', $dataA,
        '--listen', "127.0.0.1:$portA",
        '--peer', "127.0.0.1:$portB",
        '--noise-static-private-key-dpapi-file', $keyA,
        '--trusted-peer-key-hex', $pubB,
        '--tx-recipient-id', $recipient,
        '--tx-nonce', '1',
        '--tx-amount-atoms', '2500',
        '--tx-fee-atoms', '7',
        '--tx-expires-at', '4102444800',
        '--tx-signature-hex', $txSignature,
        '--probe-invalid-signature-first',
        '--mine-blocks', '2',
        '--run-seconds', '30',
        '--exit-after-mining'
    )
    $nodeA = Start-Process -FilePath $nodeExe -ArgumentList $argsA -RedirectStandardOutput $stdA -RedirectStandardError $logA -PassThru

    if (-not (Wait-Pattern $logA 'event=qzbe_v04_invalid_signature_probe_rejected height=0 .*rejected_atomically=true' 20000)) {
        throw ("CP-0414 sender did not verify atomic rejection of tampered signature: " + (Get-Text $logA) + (Get-Text $logB))
    }
    if (-not (Wait-Pattern $logB 'event=qzbe_v04_peer_candidate_rejected .*Transition' 15000)) {
        throw ("CP-0414 receiver did not reject the invalid-signature QZBE candidate: " + (Get-Text $logB))
    }
    if (-not (Wait-Pattern $logA 'event=qzbe_v04_peer_broadcast_ack height=2 .*sent_count=2' 30000)) {
        throw ("CP-0414 sender A did not receive both peer ACKs: " + (Get-Text $stdA) + (Get-Text $logA) + (Get-Text $stdB) + (Get-Text $logB))
    }
    if (-not (Wait-Pattern $logB 'event=qzbe_v04_peer_block_accepted .*height=2 .*accepted_count=2' 15000)) {
        throw ("CP-0414 receiver B did not accept both QZBE blocks: " + (Get-Text $logB))
    }
    $rpcFinalStatus = Get-QzbeRpc $rpcPort '/v1/status'
    $rpcFinalBalance = Get-QzbeRpc $rpcPort ("/v1/balance/{0}" -f $recipient)
    if ($rpcFinalStatus.height -ne 2 -or $rpcFinalBalance.height -ne 2 -or
        $rpcFinalStatus.tip -ne $rpcFinalBalance.tip -or
        $rpcFinalStatus.state_root -ne $rpcFinalBalance.state_root -or
        $rpcFinalStatus.mainnet -ne $false -or $rpcFinalBalance.read_only -ne $true -or
        $rpcFinalBalance.balance_atoms -ne 2500) {
        throw ("CP-0414 read-only RPC settled-state mismatch: status=" + ($rpcFinalStatus | ConvertTo-Json -Compress) +
            " balance=" + ($rpcFinalBalance | ConvertTo-Json -Compress))
    }
    Write-Host ("CP-0414 READ_ONLY_RPC_SETTLED_STATE_PASS height=2 balance_atoms=" + $rpcFinalBalance.balance_atoms)
    $rpcReceipt = Get-QzbeRpc $rpcPort ("/v1/transaction/{0}" -f $tx.TransactionId)
    if ($rpcReceipt.txid -ne $tx.TransactionId -or $rpcReceipt.status -ne 'confirmed' -or
        $rpcReceipt.block_height -lt 1 -or $rpcReceipt.block_height -gt $rpcFinalStatus.height -or
        $rpcReceipt.confirmations -ne ($rpcFinalStatus.height - $rpcReceipt.block_height + 1) -or
        $rpcReceipt.tip -ne $rpcFinalStatus.tip -or $rpcReceipt.state_root -ne $rpcFinalStatus.state_root -or
        $rpcReceipt.mainnet -ne $false -or $rpcReceipt.read_only -ne $true) {
        throw ("CP-0414 read-only transaction receipt mismatch: " + ($rpcReceipt | ConvertTo-Json -Compress))
    }
    Write-Host ("CP-0414 READ_ONLY_RPC_CANONICAL_TXID_RECEIPT_PASS txid=" + $rpcReceipt.txid +
        " block_height=" + $rpcReceipt.block_height + " confirmations=" + $rpcReceipt.confirmations)

    $walletStatus = @(& $walletExe rpc-status --rpc "127.0.0.1:$rpcPort" 2>&1)
    $walletStatusExit = $LASTEXITCODE
    $walletStatusText = $walletStatus -join [Environment]::NewLine
    if ($walletStatusExit -ne 0 -or $walletStatusText -notmatch 'height=2' -or
        $walletStatusText -notmatch 'network_class=candidate_not_mainnet' -or
        $walletStatusText -notmatch 'state_root_hex=' -or $walletStatusText -notmatch 'wallet_rpc_status=ok') {
        throw ("CP-0414 native wallet rpc-status query failed: " + $walletStatusText)
    }
    $walletBalance = @(& $walletExe balance --rpc "127.0.0.1:$rpcPort" --account-id-hex $recipient 2>&1)
    $walletBalanceExit = $LASTEXITCODE
    $walletBalanceText = $walletBalance -join [Environment]::NewLine
    if ($walletBalanceExit -ne 0 -or $walletBalanceText -notmatch 'wallet_rpc_balance_status=ok' -or
        $walletBalanceText -notmatch 'balance_atoms=2500' -or $walletBalanceText -notmatch 'height=2') {
        throw ("CP-0414 native wallet balance query failed: " + $walletBalanceText)
    }
    $walletTxStatus = @(& $walletExe tx-status --rpc "127.0.0.1:$rpcPort" --txid-hex $tx.TransactionId 2>&1)
    $walletTxStatusExit = $LASTEXITCODE
    $walletTxStatusText = $walletTxStatus -join [Environment]::NewLine
    if ($walletTxStatusExit -ne 0 -or $walletTxStatusText -notmatch 'wallet_tx_status=confirmed' -or
        $walletTxStatusText -notmatch ('txid_hex=' + $tx.TransactionId) -or
        $walletTxStatusText -notmatch ('confirmations=' + $rpcReceipt.confirmations) -or
        $walletTxStatusText -notmatch 'finality=probabilistic_candidate_chain_reorg_possible' -or
        $walletTxStatusText -notmatch 'network_class=candidate_not_mainnet') {
        throw ("CP-0414 native wallet TXID query failed: " + $walletTxStatusText)
    }
    Write-Host ("CP-0432 NATIVE_WALLET_READ_ONLY_RPC_PASS height=2 balance_atoms=2500 txid=" +
        $tx.TransactionId + " confirmations=" + $rpcReceipt.confirmations + " mainnet=false")
    if (-not $nodeA.WaitForExit(30000)) { throw 'CP-0414 sending node A did not stop after its bounded mining run' }
    if (-not $nodeB.WaitForExit(10000)) { throw 'CP-0414 receiver node B did not stop after its bounded observer run' }
    $textA = Get-Text $logA
    $textB = Get-Text $logB
    if ($textA -match 'event=qzbe_v04_peer_smoke_failed') { throw ("CP-0414 node A reported runtime failure: " + $textA) }
    if ($textB -match 'event=qzbe_v04_peer_smoke_failed') { throw ("CP-0414 node B reported runtime failure: " + $textB) }

    $pattern = 'event=qzbe_v04_peer_smoke_stopped .*height=2 state_root=([0-9a-f]{64}) tip=([0-9a-f]{64}) generation=2 total_mined_atoms=' + $expectedMinedAtoms + ' observed_account=' + $recipient + ' observed_balance_atoms=2500 accepted_peer_blocks=\d+ sent_peer_blocks=\d+(?: tx_submissions=\d+ mempool_count=\d+)? replay=matched local_only=true public_launch_approved=false'
    $finalA = [regex]::Match((Get-Text $logA), $pattern)
    $finalB = [regex]::Match((Get-Text $logB), $pattern)
    if (-not ($finalA.Success -and $finalB.Success)) {
        throw ("CP-0414 restart/replay summaries missing: " + (Get-Text $logA) + (Get-Text $logB))
    }
    if ((Get-Text $logA) -notmatch 'accepted_peer_blocks=0 sent_peer_blocks=2' -or (Get-Text $logB) -notmatch 'accepted_peer_blocks=2 sent_peer_blocks=0') {
        throw ("CP-0414 peer direction counters do not match expectations: A=" + (Get-Text $logA) + " B=" + (Get-Text $logB))
    }
    if ($finalA.Groups[1].Value -ne $finalB.Groups[1].Value -or $finalA.Groups[2].Value -ne $finalB.Groups[2].Value) {
        throw ("CP-0414 independent QZBE stores diverged: A=$($finalA.Groups[1].Value)/$($finalA.Groups[2].Value) B=$($finalB.Groups[1].Value)/$($finalB.Groups[2].Value)")
    }
    if ((Get-Text $logA) -match 'event=qzbe_v04_peer_connection_rejected' -or (Get-Text $logB) -match 'event=qzbe_v04_peer_connection_rejected') {
        throw 'CP-0414 observed an unexpected peer protocol or Noise error'
    }
    $rejectedSignatureCount = [regex]::Matches((Get-Text $logB), 'event=qzbe_v04_peer_candidate_rejected').Count
    if ($rejectedSignatureCount -ne 1) { throw "CP-0414 expected exactly one invalid-signature candidate rejection, saw $rejectedSignatureCount" }
    Write-Host ("CP-0414 QZBE_AUTHENTICATED_TXN_TWO_NODE_PASS height=2 state_root=" + $finalA.Groups[1].Value + " tip=" + $finalA.Groups[2].Value + " recipient=" + $recipient + ' balance_atoms=2500 invalid_signature=atomically_rejected replay=matched public_bind=denied')
}
finally {
    foreach ($node in @($nodeA, $nodeB)) {
        if ($null -ne $node) {
            try { if (-not $node.HasExited) { Stop-Process -Id $node.Id -Force -ErrorAction SilentlyContinue } } catch { }
        }
    }
    Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
}

# GitHub Actions appends `exit $LASTEXITCODE` for PowerShell steps. The negative bind
# probe intentionally invokes a process with exit code 2, so normalize success explicitly
# only after every positive assertion and cleanup have completed. Exceptions still fail the step.
exit 0
