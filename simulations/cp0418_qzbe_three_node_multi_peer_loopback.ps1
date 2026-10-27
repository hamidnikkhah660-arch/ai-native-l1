$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repo = Split-Path -Parent $PSScriptRoot
Set-Location $repo
$manifest = '.\src\native\pow_bench\Cargo.toml'
$null = cargo +stable build --release --manifest-path $manifest --bin devnet_node --bin noise_key_provisioner --bin qzbe_v04_test_tx_signer --quiet
if ($LASTEXITCODE -ne 0) { throw 'CP-0418 QZBE three-node release build failed' }

$nodeExe = (Resolve-Path '.\src\native\pow_bench\target\release\devnet_node.exe').Path
$keyExe = (Resolve-Path '.\src\native\pow_bench\target\release\noise_key_provisioner.exe').Path
$txSignerExe = (Resolve-Path '.\src\native\pow_bench\target\release\qzbe_v04_test_tx_signer.exe').Path
$root = Join-Path $env:TEMP ("ain1_cp0418_qzbe_three_node_" + [guid]::NewGuid().ToString('N'))
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
function Make-Signed-TestTransaction([string]$SeedPath, [string]$Network, [string]$Recipient) {
    $seed = New-Object byte[] 32
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($seed) } finally { $rng.Dispose() }
    [IO.File]::WriteAllBytes($SeedPath, $seed)
    [Array]::Clear($seed, 0, $seed.Length)
    try {
        $out = @(& $txSignerExe --seed-file $SeedPath --network-id-hex $Network --recipient-id-hex $Recipient --nonce 1 --amount-atoms 2500 --fee-atoms 7 --expires-at 4102444800 2>&1)
        $signerExit = $LASTEXITCODE
        if ($signerExit -ne 0) { throw ("CP-0418 transaction signing failed: " + ($out -join [Environment]::NewLine)) }
        $all = $out -join [Environment]::NewLine
        $pub = [regex]::Match($all, 'tx_public_key_hex=([0-9a-f]{64})')
        $account = [regex]::Match($all, 'tx_sender_account_id_hex=([0-9a-f]{64})')
        $signature = [regex]::Match($all, 'tx_signature_hex=([0-9a-f]{128})')
        if (-not ($pub.Success -and $account.Success -and $signature.Success)) { throw ("CP-0418 signed transaction material missing: " + $all) }
        return @{ PublicKey = $pub.Groups[1].Value; Sender = $account.Groups[1].Value; Signature = $signature.Groups[1].Value }
    }
    finally {
        Remove-Item -LiteralPath $SeedPath -Force -ErrorAction SilentlyContinue
    }
}
function Provision-Key([string]$Path, [string]$Network) {
    $out = & $keyExe --output $Path --network-id-hex $Network
    if ($LASTEXITCODE -ne 0) { throw ("CP-0418 Noise key provisioning failed: " + $Path) }
    $match = [regex]::Match(($out -join [Environment]::NewLine), 'noise_static_public_key_hex=([0-9a-f]{64})')
    if (-not $match.Success) { throw ("CP-0418 Noise public key missing: " + $Path) }
    return $match.Groups[1].Value
}

$network = 'c5' * 32
$recipient = '44' * 32
$txSeedFile = Join-Path $env:TEMP ("ain1_cp0418_tx_seed_" + [guid]::NewGuid().ToString('N') + '.bin')
$tx = Make-Signed-TestTransaction $txSeedFile $network $recipient
$owner = $tx.Sender
$txPublicKey = $tx.PublicKey
$txSignature = $tx.Signature
$miner = '33' * 32
$subsidy = '35673515981'
$halving = '4204800'
$expectedMinedAtoms = '71347031962'

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
while (($portB -eq $portA) -or ($portC -eq $portA) -or ($portC -eq $portB)) { $portC = Get-FreePort }
$addrA = "127.0.0.1:$portA"
$addrB = "127.0.0.1:$portB"
$addrC = "127.0.0.1:$portC"
$nodeA = $null
$nodeB = $null
$nodeC = $null

try {
    $savedErrorPreference = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    $bindOutput = @(& $nodeExe --qzbe-v04-peer-smoke --data-dir (Join-Path $root 'invalid-bind') --listen '0.0.0.0:49331' 2>&1)
    $bindExitCode = $LASTEXITCODE
    $ErrorActionPreference = $savedErrorPreference
    if ($bindExitCode -ne 1 -or (($bindOutput -join [Environment]::NewLine) -notmatch 'non-loopback QZBE P2P bind requires both --test-easy-pow and --public-testnet-p2p')) {
        throw ("CP-0418 public-bind guard failed (exit=$bindExitCode): " + ($bindOutput -join [Environment]::NewLine))
    }
    Write-Host 'CP-0418 PUBLIC_BIND_GUARD_PASS'

    # Nodes B and C are independently persisted receivers with a full static trust set.
    $argsC = @(
        '--qzbe-v04-peer-smoke', '--test-easy-pow',
        '--network-id', $network, '--owner-id', $owner, '--miner-id', $miner,
        '--tx-public-key-hex', $txPublicKey, '--observe-account-id', $recipient,
        '--initial-subsidy-atoms', $subsidy, '--blocks-per-halving', $halving,
        '--data-dir', $dataC, '--listen', $addrC,
        '--peer', $addrA, '--trusted-peer-key-hex', $pubA,
        '--peer', $addrB, '--trusted-peer-key-hex', $pubB,
        '--noise-static-private-key-dpapi-file', $keyC,
        '--mine-blocks', '0', '--run-seconds', '30', '--stop-after-height', '2'
    )
    $nodeC = Start-Process -FilePath $nodeExe -ArgumentList $argsC -RedirectStandardOutput $stdC -RedirectStandardError $logC -PassThru
    if (-not (Wait-Pattern $logC 'event=qzbe_v04_peer_smoke_ready .*local_only=true public_launch_approved=false' 20000)) {
        throw ("CP-0418 node C did not become ready: " + (Get-Text $stdC) + (Get-Text $logC))
    }

    $argsB = @(
        '--qzbe-v04-peer-smoke', '--test-easy-pow',
        '--network-id', $network, '--owner-id', $owner, '--miner-id', $miner,
        '--tx-public-key-hex', $txPublicKey, '--observe-account-id', $recipient,
        '--initial-subsidy-atoms', $subsidy, '--blocks-per-halving', $halving,
        '--data-dir', $dataB, '--listen', $addrB,
        '--peer', $addrA, '--trusted-peer-key-hex', $pubA,
        '--peer', $addrC, '--trusted-peer-key-hex', $pubC,
        '--noise-static-private-key-dpapi-file', $keyB,
        '--mine-blocks', '0', '--run-seconds', '30', '--stop-after-height', '2'
    )
    $nodeB = Start-Process -FilePath $nodeExe -ArgumentList $argsB -RedirectStandardOutput $stdB -RedirectStandardError $logB -PassThru
    if (-not (Wait-Pattern $logB 'event=qzbe_v04_peer_smoke_ready .*local_only=true public_launch_approved=false' 20000)) {
        throw ("CP-0418 node B did not become ready: " + (Get-Text $stdB) + (Get-Text $logB))
    }

    # Node A mines two real-schedule QZBE candidates on the explicit test PoW profile
    # and sends each to both independent peers using its two correspondingly pinned keys.
    $argsA = @(
        '--qzbe-v04-peer-smoke', '--test-easy-pow',
        '--network-id', $network, '--owner-id', $owner, '--miner-id', $miner,
        '--tx-public-key-hex', $txPublicKey, '--observe-account-id', $recipient,
        '--initial-subsidy-atoms', $subsidy, '--blocks-per-halving', $halving,
        '--data-dir', $dataA, '--listen', $addrA,
        '--peer', $addrB, '--trusted-peer-key-hex', $pubB,
        '--peer', $addrC, '--trusted-peer-key-hex', $pubC,
        '--noise-static-private-key-dpapi-file', $keyA,
        '--tx-recipient-id', $recipient, '--tx-nonce', '1',
        '--tx-amount-atoms', '2500', '--tx-fee-atoms', '7',
        '--tx-expires-at', '4102444800', '--tx-signature-hex', $txSignature,
        '--probe-invalid-signature-first',
        '--mine-blocks', '2', '--run-seconds', '30', '--exit-after-mining'
    )
    $nodeA = Start-Process -FilePath $nodeExe -ArgumentList $argsA -RedirectStandardOutput $stdA -RedirectStandardError $logA -PassThru

    if (-not (Wait-Pattern $logA ("event=qzbe_v04_invalid_signature_probe_rejected height=0 .*rejected_atomically=true") 20000)) {
        throw ("CP-0418 invalid-signature probe did not prove atomic rejection: " + (Get-Text $logA) + (Get-Text $logB))
    }
    if (-not (Wait-Pattern $logB 'event=qzbe_v04_peer_candidate_rejected .*Transition' 15000)) {
        throw ("CP-0418 node B did not reject the tampered signature: " + (Get-Text $logB))
    }
    foreach ($addr in @($addrB, $addrC)) {
        if (-not (Wait-Pattern $logA ("event=qzbe_v04_peer_broadcast_ack height=1 .*peer=" + [regex]::Escape($addr)) 20000)) {
            throw ("CP-0418 node A did not receive height-1 ACK from " + $addr + ": " + (Get-Text $logA))
        }
        if (-not (Wait-Pattern $logA ("event=qzbe_v04_peer_broadcast_ack height=2 .*peer=" + [regex]::Escape($addr)) 30000)) {
            throw ("CP-0418 node A did not receive height-2 ACK from " + $addr + ": " + (Get-Text $logA))
        }
    }
    if (-not (Wait-Pattern $logB 'event=qzbe_v04_peer_block_accepted .*height=2 .*accepted_count=2' 20000)) {
        throw ("CP-0418 node B did not accept two blocks: " + (Get-Text $logB))
    }
    if (-not (Wait-Pattern $logC 'event=qzbe_v04_peer_block_accepted .*height=2 .*accepted_count=2' 20000)) {
        throw ("CP-0418 node C did not accept two blocks: " + (Get-Text $logC))
    }
    if (-not $nodeA.WaitForExit(30000)) { throw 'CP-0418 node A did not exit after its bounded mining run' }
    if (-not $nodeB.WaitForExit(35000)) { throw 'CP-0418 node B did not reach height 2 and exit' }
    if (-not $nodeC.WaitForExit(35000)) { throw 'CP-0418 node C did not reach height 2 and exit' }

    $textA = Get-Text $logA
    $textB = Get-Text $logB
    $textC = Get-Text $logC
    foreach ($text in @($textA, $textB, $textC)) {
        if ($text -match 'event=qzbe_v04_peer_smoke_failed') { throw ("CP-0418 node runtime failed: " + $text) }
        if ($text -match 'event=qzbe_v04_peer_connection_rejected') { throw ("CP-0418 unexpected Noise/peer rejection: " + $text) }
    }
    $pattern = 'event=qzbe_v04_peer_smoke_stopped .*height=2 state_root=([0-9a-f]{64}) tip=([0-9a-f]{64}) generation=2 total_mined_atoms=' + $expectedMinedAtoms + ' observed_account=' + $recipient + ' observed_balance_atoms=2500 accepted_peer_blocks=\d+ sent_peer_blocks=\d+(?: tx_submissions=\d+ mempool_count=\d+)? replay=matched tx_rpc_loopback_only=true mainnet=false network_surface=loopback_only local_only=true public_launch_approved=false'
    $finalA = [regex]::Match($textA, $pattern)
    $finalB = [regex]::Match($textB, $pattern)
    $finalC = [regex]::Match($textC, $pattern)
    if (-not ($finalA.Success -and $finalB.Success -and $finalC.Success)) {
        throw ("CP-0418 replay summaries missing/malformed: A=" + $textA + " B=" + $textB + " C=" + $textC)
    }
    foreach ($final in @($finalB, $finalC)) {
        if ($final.Groups[1].Value -ne $finalA.Groups[1].Value -or $final.Groups[2].Value -ne $finalA.Groups[2].Value) {
            throw 'CP-0418 three independent QZBE stores did not converge on identical height-2 state root/tip'
        }
    }
    if ($textA -notmatch 'accepted_peer_blocks=0 sent_peer_blocks=4' -or
        $textB -notmatch 'accepted_peer_blocks=2 sent_peer_blocks=0' -or
        $textC -notmatch 'accepted_peer_blocks=2 sent_peer_blocks=0') {
        throw ("CP-0418 peer direction counters mismatched: A=" + $textA + " B=" + $textB + " C=" + $textC)
    }
    $rejectedSignatureCount = [regex]::Matches($textB, 'event=qzbe_v04_peer_candidate_rejected').Count
    if ($rejectedSignatureCount -ne 1) { throw "CP-0418 expected one tampered-signature rejection at B, saw $rejectedSignatureCount" }
    Write-Host ("CP-0418 QZBE_THREE_NODE_MULTI_PEER_PASS height=2 state_root=" + $finalA.Groups[1].Value + " tip=" + $finalA.Groups[2].Value + " nodes=3 sent_peer_blocks=4 accepted_each=2 balance_atoms=2500 invalid_signature=atomically_rejected replay=matched public_bind=denied")
}
finally {
    foreach ($node in @($nodeA, $nodeB, $nodeC)) {
        if ($null -ne $node) {
            try { if (-not $node.HasExited) { Stop-Process -Id $node.Id -Force -ErrorAction SilentlyContinue } } catch { }
        }
    }
    Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
}
exit 0
