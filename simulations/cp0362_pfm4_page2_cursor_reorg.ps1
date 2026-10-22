$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$repo = Split-Path -Parent $PSScriptRoot
Set-Location $repo
$manifest = '.\src\native\pow_bench\Cargo.toml'
cargo build --release --manifest-path $manifest --bin devnet_node --bin noise_key_provisioner --quiet
if ($LASTEXITCODE -ne 0) { throw 'CP-0362 Release build failed' }
$nodeExe = (Resolve-Path '.\src\native\pow_bench\target\release\devnet_node.exe').Path
$keyExe = (Resolve-Path '.\src\native\pow_bench\target\release\noise_key_provisioner.exe').Path
$root = Join-Path $env:TEMP ("ain1_cp0362_pfm4_page2_cursor_reorg_" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $root | Out-Null

function Get-FreePort {
    $listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
    $listener.Start(); $port = [int]$listener.LocalEndpoint.Port; $listener.Stop()
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
        Start-Sleep -Milliseconds 40
    }
    return $false
}
function Assert-Log([string]$Path, [string]$Pattern, [string]$Name) {
    if ((Get-Text $Path) -notmatch $Pattern) { throw ("CP-0362 expected " + $Name + ": " + (Get-Text $Path)) }
}
function Wait-IfRunning($Process) {
    if ($Process) {
        $Process.Refresh()
        if (-not $Process.HasExited) {
            [void]$Process.WaitForExit(40000)
            $Process.Refresh()
            if (-not $Process.HasExited) { Write-Warning ("CP-0362 bounded child still running PID " + $Process.Id) }
        }
    }
}
function Provision-Key([string]$Path, [string]$Network) {
    $out = & $keyExe --output $Path --network-id-hex $Network
    if ($LASTEXITCODE -ne 0) { throw ("CP-0362 key provisioning failed: " + $Path) }
    $match = [regex]::Match(($out -join [Environment]::NewLine), 'noise_static_public_key_hex=([0-9a-f]{64})')
    if (-not $match.Success) { throw ("CP-0362 public key missing from provisioner: " + $Path) }
    return $match.Groups[1].Value
}
function Run-Seed([string[]]$Arguments, [string]$Prefix, [string]$ExpectedHeight) {
    $stdout = Join-Path $root ($Prefix + '.out.log')
    $stderr = Join-Path $root ($Prefix + '.err.log')
    $proc = Start-Process -FilePath $nodeExe -ArgumentList $Arguments -RedirectStandardOutput $stdout -RedirectStandardError $stderr -PassThru -Wait
    $proc.Refresh()
    $log = (Get-Text $stdout) + (Get-Text $stderr)
    if ($proc.ExitCode -ne 0) { throw ("CP-0362 seed failed " + $Prefix + ": " + $log) }
    $m = [regex]::Match($log, 'event=monetary_v4_hybrid_local_smoke_stopped wire=PMT4 store=PFM4 height=(\d+) state_root=([0-9a-f]{64}) tip=([0-9a-f]{64}) archive_branches=(\d+) replay=matched')
    if (-not $m.Success -or $m.Groups[1].Value -ne $ExpectedHeight) { throw ("CP-0362 bad seed output " + $Prefix + ": " + $log) }
    return @{Height=[int]$m.Groups[1].Value; Root=$m.Groups[2].Value; Tip=$m.Groups[3].Value; ArchiveBranches=$m.Groups[4].Value}
}

$network = 'c4' * 32
$keyB = Join-Path $root 'node-b.npk1'
$keyC = Join-Path $root 'node-c.npk1'
$pubB = Provision-Key $keyB $network
$pubC = Provision-Key $keyC $network
$dataA = Join-Path $root 'baseline-a-data'
$dataB = Join-Path $root 'reorg-source-b-data'
$dataC = Join-Path $root 'cursor-client-c-data'

Write-Host 'CP-0362 STEP_1 seed baseline PFM4 branch A at height 3'
$seedArgs = @('--network-id',$network,'--data-dir',$dataA,'--monetary-v4-hybrid-local-smoke',
    '--mine-blocks','3','--exit-after-mining','true','--run-seconds','120')
$seed = Run-Seed $seedArgs 'baseline-a-seed' '3'
New-Item -ItemType Directory -Path $dataB | Out-Null
Get-ChildItem -LiteralPath $dataA -Force | Copy-Item -Destination $dataB -Recurse -Force

$portB = Get-FreePort; $portC = Get-FreePort
$statusB = Get-FreePort; $statusC = Get-FreePort
$ports = @($portB,$portC,$statusB,$statusC)
while (($ports | Select-Object -Unique).Count -ne 4) {
    $portB = Get-FreePort; $portC = Get-FreePort; $statusB = Get-FreePort; $statusC = Get-FreePort
    $ports = @($portB,$portC,$statusB,$statusC)
}
$logB = Join-Path $root 'node-b.err.log'; $stdB = Join-Path $root 'node-b.out.log'
$logC = Join-Path $root 'node-c.err.log'; $stdC = Join-Path $root 'node-c.out.log'
$nodeB = $null; $nodeC = $null
try {
    # Start B before C so B's only outbound range attempt fails against the not-yet-listening C.
    # C then opens a cursor against B. B serves page 2 and synchronously reorgs before the
    # main loop can accept the same C sync worker's page 3 continuation.
    $argsB = @('--network-id',$network,'--data-dir',$dataB,'--listen',"127.0.0.1:$portB",
        '--status-listen',"127.0.0.1:$statusB",'--noise-static-private-key-dpapi-file',$keyB,
        '--trusted-peer-key-hex',$pubC,'--peer',"127.0.0.1:$portC",
        '--monetary-v4-hybrid-peer-smoke','--monetary-v4-hybrid-archive-range-sync',
        '--archive-range-max-page-items','1','--test-reorg-after-second-archive-range-page',
        '--mine-blocks','0','--run-seconds','22')
    $nodeB = Start-Process -FilePath $nodeExe -ArgumentList $argsB -RedirectStandardOutput $stdB -RedirectStandardError $logB -PassThru
    if (-not (Wait-Pattern $logB 'event=monetary_v4_peer_smoke_ready.*height=3.*wire=PMT4 ack=MTA4 noise=required' 15000)) {
        throw ("CP-0362 reorg source B readiness failed: " + (Get-Text $stdB) + (Get-Text $logB))
    }
    # Source B serves one item per page. It must send pages 1 and 2, then reorg before accepting C's page-3 cursor.

    $argsC = @('--network-id',$network,'--data-dir',$dataC,'--listen',"127.0.0.1:$portC",
        '--status-listen',"127.0.0.1:$statusC",'--noise-static-private-key-dpapi-file',$keyC,
        '--trusted-peer-key-hex',$pubB,'--peer',"127.0.0.1:$portB",
        '--monetary-v4-hybrid-peer-smoke','--monetary-v4-hybrid-archive-range-sync',
        '--archive-range-max-page-items','1','--mine-blocks','0','--run-seconds','60')
    $nodeC = Start-Process -FilePath $nodeExe -ArgumentList $argsC -RedirectStandardOutput $stdC -RedirectStandardError $logC -PassThru
    if (-not (Wait-Pattern $logC 'event=monetary_v4_peer_smoke_ready.*height=0.*wire=PMT4 ack=MTA4 noise=required' 15000)) {
        throw ("CP-0362 cursor client C readiness failed: " + (Get-Text $stdC) + (Get-Text $logC))
    }

    if (-not (Wait-Pattern $logC 'event=monetary_v4_archive_range_item_imported.*status=ACCEPTED height=1 ' 12000)) {
        throw ("CP-0362 client did not accept the first baseline page: " + (Get-Text $logC) + (Get-Text $logB))
    }
    Assert-Log $logB 'event=devnet_archive_range_page_served.*page=1 .*items=1' 'first range page sent from the old snapshot'
    if (-not (Wait-Pattern $logC 'event=monetary_v4_archive_range_item_imported.*status=ACCEPTED height=2 ' 12000)) {
        throw ("CP-0362 client did not accept the second page before the reorg: " + (Get-Text $logC) + (Get-Text $logB))
    }
    Assert-Log $logB 'event=devnet_archive_range_page_served.*page=2 .*items=1' 'second range page sent from the old snapshot'
    if (-not (Wait-Pattern $logB 'event=test_fault_reorg_after_pfm4_archive_page old_tip=[0-9a-f]{64} new_tip=[0-9a-f]{64} canonical_height=4 trigger_page=2' 12000)) {
        throw ("CP-0362 source did not reorg after sending page 2: " + (Get-Text $logB))
    }
    if (-not (Wait-Pattern $logB 'event=monetary_v4_archive_range_request_rejected.*reason=stale_snapshot manifest_anchor_changed=true' 12000)) {
        throw ("CP-0362 same cursor continuation was not rejected after the inter-page reorg: " + (Get-Text $logB) + (Get-Text $logC))
    }
    Write-Host 'CP-0362 INFLIGHT_CURSOR_REORG_PASS first_page_sent=true second_page_sent=true accepted_prefix=2 source_reorged=true stale_page3_rejected=true'

    if (-not (Wait-Pattern $logC 'event=monetary_v4_archive_range_sync_failed peer=.*' 10000)) {
        throw ("CP-0362 client did not observe rejection on continuation: " + (Get-Text $logC))
    }
    $clientLog = Get-Text $logC
    if ($clientLog -match 'event=monetary_v4_archive_range_item_imported.*status=ACCEPTED height=(3|4) ') {
        throw 'CP-0362 client imported height 3 or 4 from the stale cursor after the source reorg'
    }
    $statusBNow = Invoke-RestMethod -Uri ("http://127.0.0.1:" + $statusB + "/status") -TimeoutSec 2
    $statusCNow = Invoke-RestMethod -Uri ("http://127.0.0.1:" + $statusC + "/status") -TimeoutSec 2
    if ([int]$statusBNow.height -ne 4 -or [int]$statusCNow.height -ne 2) {
        throw ("CP-0362 unexpected final heights: source=" + $statusBNow.height + " client=" + $statusCNow.height)
    }
    if ((Get-Text $logB) -match 'event=devnet_archive_range_page_served.*page=3') {
        throw 'CP-0362 source served page 3 from its stale startup snapshot'
    }
    Write-Host ("CP-0362 HEIGHTS_PASS source_after_reorg=" + $statusBNow.height + " client_stopped_at=" + $statusCNow.height)

    if (-not $nodeC.WaitForExit(65000)) { throw 'CP-0362 cursor client did not gracefully stop in its bounded run' }
    if (-not $nodeB.WaitForExit(30000)) { throw 'CP-0362 reorg source did not gracefully stop in its bounded run' }
    $nodeB.Refresh()
    if (-not $nodeB.HasExited) { throw 'CP-0362 source still running after WaitForExit' }
    Assert-Log $logB 'event=monetary_v4_peer_smoke_stopped.*height=4.*replay=matched' 'source PFM4 replay after in-flight reorg'
    Assert-Log $logC 'event=monetary_v4_peer_smoke_stopped.*height=2.*replay=matched' 'client PFM4 replay after two accepted pages'
    Write-Host 'CP-0362 REORG_REPLAY_PASS source_height=4 client_height=2 replay=matched'
    Write-Host ("CP-0362 ARTIFACTS " + $root)
}
finally {
    Wait-IfRunning $nodeC
    Wait-IfRunning $nodeB
}
