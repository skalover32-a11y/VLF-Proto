<#
Run proto_bench matrix with fixed parameter combinations and collect reports.

Examples:
  .\scripts\run-bench-matrix.ps1
  .\scripts\run-bench-matrix.ps1 -Duration 20s
  .\scripts\run-bench-matrix.ps1 -ReportsDir .\reports -ExtraBenchArgs @("--prefer-quic")
#>

[CmdletBinding()]
param(
  [string]$Duration = "10s",
  [string]$ReportsDir = "",
  [string[]]$ExtraBenchArgs = @()
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ScriptDir = $PSScriptRoot
if (-not $ScriptDir) {
  $ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
}
$Root = (Resolve-Path (Join-Path $ScriptDir "..")).Path
if (-not $ReportsDir) {
  $ReportsDir = Join-Path $Root "reports"
}

$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$runRoot = Join-Path $ReportsDir $timestamp
New-Item -ItemType Directory -Path $runRoot -Force | Out-Null

$runBenchScript = Join-Path $ScriptDir "run-bench.ps1"
if (-not (Test-Path -LiteralPath $runBenchScript)) {
  throw "run-bench.ps1 not found at $runBenchScript"
}

$clients = @(1, 2)
$udpPps = @(300, 600, 900, 1200)
$udpPayload = @(256, 1200)

$results = New-Object System.Collections.Generic.List[object]
$firstFailure = $null

foreach ($c in $clients) {
  foreach ($pps in $udpPps) {
    foreach ($payload in $udpPayload) {
      $runId = "c${c}_pps${pps}_pl${payload}"
      $runDir = Join-Path $runRoot $runId
      New-Item -ItemType Directory -Path $runDir -Force | Out-Null

      $jsonPath = Join-Path $runDir "proto_bench_report.json"
      $mdPath = Join-Path $runDir "proto_bench_report.md"
      $logPath = Join-Path $runDir "console.log"

      $benchArgs = @(
        "--clients", "$c",
        "--duration", "$Duration",
        "--tcp-flows", "1",
        "--tcp-total-mb", "8",
        "--udp-pps", "$pps",
        "--udp-payload-bytes", "$payload",
        "--udp-burst", "10",
        "--udp-max-loss", "0.05",
        "--udp-max-jitter-ms", "50",
        "--tcp-min-mbps", "1",
        "--report-json", $jsonPath,
        "--report-md", $mdPath
      )
      if ($ExtraBenchArgs -and $ExtraBenchArgs.Count -gt 0) {
        $benchArgs += $ExtraBenchArgs
      }

      Write-Host ""
      Write-Host ">>> RUN $runId (duration=$Duration)"

      $exitCode = 1
      try {
        & $runBenchScript -- @benchArgs 2>&1 | Tee-Object -FilePath $logPath | Out-Host
        $exitCode = if ($LASTEXITCODE -ne $null) { [int]$LASTEXITCODE } else { 0 }
      } catch {
        $_ | Out-String | Tee-Object -FilePath $logPath -Append | Out-Host
        $exitCode = 1
      }

      $status = if ($exitCode -eq 0) { "PASS" } else { "FAIL" }
      if ($status -eq "FAIL" -and -not $firstFailure) {
        $firstFailure = "$runId (exit=$exitCode)"
      }

      $results.Add([pscustomobject]@{
        run_id = $runId
        status = $status
        exit_code = $exitCode
        report_dir = $runDir
      }) | Out-Null
    }
  }
}

Write-Host ""
Write-Host "Bench matrix reports: $runRoot"
Write-Host "Summary:"
$results | Format-Table -AutoSize run_id, status, exit_code, report_dir | Out-Host

$failed = @($results | Where-Object { $_.status -eq "FAIL" }).Count
Write-Host ("Total runs: {0}" -f $results.Count)
Write-Host ("Failed: {0}" -f $failed)
if ($firstFailure) {
  Write-Host ("First failure: {0}" -f $firstFailure)
} else {
  Write-Host "All matrix runs passed."
}

if ($failed -gt 0) {
  exit 1
}
