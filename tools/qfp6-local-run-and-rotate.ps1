[CmdletBinding()]
param(
    [string]$RepositoryRoot = "",
    [switch]$VerifyOnly
)

$ErrorActionPreference = "Stop"

function Stop-Safely([string]$Message, [int]$Code = 2) {
    [Console]::Error.WriteLine($Message)
    exit $Code
}

try {
    if ([string]::IsNullOrWhiteSpace($RepositoryRoot)) {
        $toolsDirectory = Split-Path -Parent $MyInvocation.MyCommand.Path
        $RepositoryRoot = Split-Path -Parent $toolsDirectory
    }
    $repo = (Resolve-Path -LiteralPath $RepositoryRoot).Path
    $package = Join-Path $repo "release\qfp6-local-single-operator-devnet-2026-11-15"
    $config = Join-Path $package "permissionless-config.json"
    $vaultTool = Join-Path $repo "tools\qfp6_anchor_vault.py"
    $binary = Join-Path $repo "src\native\pow_bench\target\release\qrun_v06_node.exe"

    foreach ($required in @($package, $config, $vaultTool)) {
        if (-not (Test-Path -LiteralPath $required)) {
            Stop-Safely "Required local QFP6 path is missing: $required"
        }
    }

    if ($VerifyOnly) {
        & python $vaultTool --package-dir $package verify
        if ($LASTEXITCODE -ne 0) {
            Stop-Safely "Local QFP6 anchor vault verification failed." $LASTEXITCODE
        }
        exit 0
    }

    if (-not (Test-Path -LiteralPath $binary -PathType Leaf)) {
        Stop-Safely "Release node binary is missing. Build it first: cargo build --release --bin qrun_v06_node --locked --offline -j 1"
    }

    # Re-check the exact package mode before launching anything.
    $cfgObject = Get-Content -LiteralPath $config -Raw | ConvertFrom-Json
    $runtime = $cfgObject.permissionless_runtime
    if ($runtime.listen_address -ne "127.0.0.1:30333" -or
        $runtime.allow_public_listener -ne $false -or
        $runtime.enable_approved_peer_outbound_sync -ne $false) {
        Stop-Safely "Refusing to run: package is not the exact local loopback-only profile."
    }

    & python $vaultTool --package-dir $package verify
    if ($LASTEXITCODE -ne 0) {
        Stop-Safely "Anchor vault verification failed before node startup." $LASTEXITCODE
    }

    $configHash = (Get-FileHash -LiteralPath $config -Algorithm SHA256).Hash.ToLowerInvariant()
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $log = Join-Path $package "permissionless-run-$timestamp.log"
    Write-Host "QFP6 local-only runner"
    Write-Host "Listener: 127.0.0.1:30333"
    Write-Host "Public listener: disabled"
    Write-Host "Output log: $log"
    Write-Host "Press Ctrl+C in this same console for the node's controlled shutdown."
    Write-Host "Every successful local manifest commit is anchored on C: before success is returned."
    Write-Host "A crash may leave one D: generation pending; restart reconciles only after full replay."

    # Run synchronously in this console. Tee captures the node's own final shutdown evidence.
    & $binary --permissionless-run --config $config --config-sha256 $configHash 2>&1 |
        Tee-Object -FilePath $log

    $nodeExitCode = $LASTEXITCODE
    if ($nodeExitCode -ne 0) {
        Stop-Safely "Node exited with code $nodeExitCode. Preserve the log; do not edit the local anchor vault manually." $nodeExitCode
    }

    $output = Get-Content -LiteralPath $log -Raw
    $generationMatch = [regex]::Match($output, '(?m)^final_manifest_generation=(\d+)\s*$')
    $anchorMatch = [regex]::Match($output, '(?m)^final_manifest_anchor=([0-9a-f]{64})\s*$')
    if (-not $generationMatch.Success -or -not $anchorMatch.Success) {
        Stop-Safely "Node exited zero but final generation/anchor evidence is missing. No final success verification was recorded."
    }
    $evidencePatterns = @(
        '(?m)^QFP6 PERMISSIONLESS BASE RUNTIME: STARTING \(candidate qualification only\)\s*$',
        '(?m)^owner_genesis_approval=Q6GA_ED25519_MLDSA65_VERIFIED\s*$',
        '(?m)^final_manifest_generation=\d+\s*$',
        '(?m)^final_manifest_anchor=[0-9a-f]{64}\s*$',
        '(?m)^anchor_persistence_status=LOCAL_C_VAULT_PER_COMMIT_PERSISTED\s*$',
        '(?m)^runtime_status=STOPPED\s*$'
    )
    $evidenceLines = @()
    foreach ($pattern in $evidencePatterns) {
        $match = [regex]::Match($output, $pattern)
        if (-not $match.Success) {
            Stop-Safely "Required successful-stop/Q6GA/per-commit-vault evidence is missing."
        }
        $evidenceLines += $match.Value
    }

    $generation = [UInt64]::Parse($generationMatch.Groups[1].Value)
    $anchor = $anchorMatch.Groups[1].Value
    $statusFile = Join-Path $package "permissionless-stop-evidence-$timestamp.txt"
    [System.IO.File]::WriteAllLines($statusFile, $evidenceLines, [System.Text.UTF8Encoding]::new($false))

    & python $vaultTool --package-dir $package advance --final-generation $generation --final-anchor $anchor --final-status-file $statusFile --confirm-clean-shutdown
    if ($LASTEXITCODE -ne 0) {
        Stop-Safely "Final per-commit anchor verification failed. Keep the node stopped and preserve the log; do not edit the vault/config manually." $LASTEXITCODE
    }

    & python $vaultTool --package-dir $package verify
    if ($LASTEXITCODE -ne 0) {
        Stop-Safely "Post-rotation verification failed. Keep the node stopped and preserve the log." $LASTEXITCODE
    }

    Write-Host "QFP6 local run and per-commit Anchor Persistence verification completed successfully."
    Write-Host "The node is stopped. It was NOT restarted automatically."
    exit 0
}
catch {
    Stop-Safely ("QFP6 local runner failed safely: " + $_.Exception.Message)
}
