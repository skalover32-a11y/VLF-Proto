<#
Run proto_bench from Windows with native Go or Dockerized Go fallback.
#>

[CmdletBinding()]
param(
  [string]$Network = "",
  [string]$EnvFile = "",
  [Parameter(ValueFromRemainingArguments = $true)]
  [string[]]$BenchArgs
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ScriptDir = $PSScriptRoot
if (-not $ScriptDir) {
  $ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
}
$Root = (Resolve-Path (Join-Path $ScriptDir "..")).Path
if (-not $EnvFile) {
  $EnvFile = Join-Path $ScriptDir ".env"
}

function Test-Cmd([string]$Name) {
  try {
    Get-Command $Name -ErrorAction Stop | Out-Null
    return $true
  } catch {
    return $false
  }
}

function Import-DotEnv([string]$Path) {
  if (-not (Test-Path -LiteralPath $Path)) {
    return
  }
  $lines = Get-Content -LiteralPath $Path
  foreach ($lineRaw in $lines) {
    $line = $lineRaw.Trim()
    if (-not $line) { continue }
    if ($line.StartsWith("#")) { continue }
    if ($line.StartsWith("export ")) { $line = $line.Substring(7).Trim() }
    $idx = $line.IndexOf("=")
    if ($idx -lt 1) { continue }
    $key = $line.Substring(0, $idx).Trim()
    $val = $line.Substring($idx + 1).Trim()
    if (($val.StartsWith('"') -and $val.EndsWith('"')) -or ($val.StartsWith("'") -and $val.EndsWith("'"))) {
      $val = $val.Substring(1, $val.Length - 2)
    }
    if (-not [Environment]::GetEnvironmentVariable($key, "Process")) {
      [Environment]::SetEnvironmentVariable($key, $val, "Process")
    }
  }
}

Import-DotEnv $EnvFile

if (Test-Cmd "go") {
  Push-Location $Root
  try {
    & go run ./cmd/proto_bench @BenchArgs
    exit $LASTEXITCODE
  } finally {
    Pop-Location
  }
}

if (-not (Test-Cmd "docker")) {
  throw "Neither 'go' nor 'docker' is available."
}

if (-not $Network) {
  try {
    $Network = (docker network ls --format '{{.Name}}' | Select-String -Pattern 'vlf-proto|vlf' | Select-Object -First 1).ToString().Trim()
  } catch {
    $Network = ""
  }
}

$dockerArgs = @("run", "--rm", "-v", "${Root}:/src", "-w", "/src")
if ($Network) {
  $dockerArgs += @("--network", $Network)
}

$envKeys = @(
  "GATEWAY_HOST", "GATEWAY_PORT", "GATEWAY_PORT_UDP", "GATEWAY_PORT_TCP",
  "RELAY_BASE", "VLF_CLIENT", "VLF_CLIENT_ID", "VLF_SECRET", "VLF_PIN_SPKI",
  "VLF_PREFER_QUIC", "VLF_DISABLE_QUIC", "VLF_DISABLE_TCP_SESSION", "VLF_DISABLE_RELAY_FALLBACK",
  "BENCH_TARGET_TCP_HOST", "BENCH_TARGET_TCP_PORT", "BENCH_TARGET_UDP_HOST", "BENCH_TARGET_UDP_PORT"
)
foreach ($k in $envKeys) {
  $v = [Environment]::GetEnvironmentVariable($k, "Process")
  if ($v) {
    $dockerArgs += @("-e", "$k=$v")
  }
}

$joinedArgs = ($BenchArgs -join " ")
$dockerArgs += @(
  "golang:1.24-alpine",
  "sh",
  "-lc",
  "apk add --no-cache git ca-certificates >/dev/null && go run ./cmd/proto_bench $joinedArgs"
)

& docker @dockerArgs
exit $LASTEXITCODE
