<#
Windows smoke launcher for dockerized execution.
- Detects docker network used by compose
- Runs relay + session smoke inside that network
- Optional: builds Windows smoke binaries with dockerized Go
#>

[CmdletBinding()]
param(
  [string]$Network = "",
  [switch]$BuildBinaries,

  [string]$RelayBase = "",
  [string]$RelayDialHost = "",
  [int]$RelayDialPort = 0,

  [string]$GatewayHost = "",
  [int]$GatewayPortUdp = 0,
  [int]$GatewayPortTcp = 0,

  [string]$Client = "",
  [string]$Secret = "",
  [string]$PinSpki = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ScriptDir = $PSScriptRoot
if (-not $ScriptDir) {
  $ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
}
$RepoRoot = (Resolve-Path (Join-Path $ScriptDir "..")).Path

function Write-Log([string]$Message) {
  $ts = (Get-Date).ToString("HH:mm:ss")
  Write-Host "[$ts] $Message"
}

function Require-Docker {
  try {
    & docker version | Out-Null
    if ($LASTEXITCODE -ne 0) {
      throw "docker command returned non-zero exit code"
    }
  } catch {
    throw "Docker is required"
  }
}

function Resolve-Default([string]$Current, [string]$EnvName, [string]$Fallback) {
  if ($Current) { return $Current }
  $envValue = [Environment]::GetEnvironmentVariable($EnvName, "Process")
  if ($envValue) { return $envValue }
  return $Fallback
}

function Resolve-DefaultInt([int]$Current, [string]$EnvName, [int]$Fallback) {
  if ($Current -gt 0) { return $Current }
  $envValue = [Environment]::GetEnvironmentVariable($EnvName, "Process")
  if ($envValue) {
    try {
      $n = [int]$envValue
      if ($n -gt 0) { return $n }
    } catch {}
  }
  return $Fallback
}

function Detect-Network([string]$Current) {
  if ($Current) { return $Current }

  $lines = & docker network ls --format '{{.Name}}'
  if ($LASTEXITCODE -ne 0) {
    throw "failed to list docker networks"
  }

  foreach ($line in $lines) {
    if ($line -match 'vlf-proto|vlf') {
      return $line.Trim()
    }
  }

  throw "could not auto-detect docker network. Pass -Network explicitly"
}

function Invoke-DockerSmoke([string]$Name, [string]$NetworkName, [hashtable]$Env, [string]$GoFile) {
  Write-Log "Running $Name on network '$NetworkName'"

  $args = @("run", "--rm", "--network", $NetworkName, "-v", "${RepoRoot}:/src", "-w", "/src")
  foreach ($key in $Env.Keys) {
    $args += @("-e", "$key=$($Env[$key])")
  }
  $args += @("golang:1.24-alpine", "sh", "-lc", "apk add --no-cache git ca-certificates >/dev/null && go run $GoFile")

  & docker @args
  if ($LASTEXITCODE -ne 0) {
    throw "$Name failed"
  }
}

function Invoke-DockerBuild {
  Write-Log "Building Windows smoke binaries via dockerized Go"
  $cmd = @"
apk add --no-cache git ca-certificates >/dev/null && \
GOOS=windows GOARCH=amd64 go build -o scripts/out/session_smoke.exe ./scripts/session_smoke.go && \
GOOS=windows GOARCH=amd64 go build -o scripts/out/relay_smoke.exe ./scripts/relay_smoke.go
"@
  & docker run --rm -v "${RepoRoot}:/src" -w /src golang:1.24-alpine sh -lc $cmd
  if ($LASTEXITCODE -ne 0) {
    throw "dockerized build failed"
  }
}

try {
  Require-Docker

  $Network = Detect-Network $Network
  $RelayBase = Resolve-Default $RelayBase "RELAY_BASE" "http://gateway:8080"
  $RelayDialHost = Resolve-Default $RelayDialHost "RELAY_DIAL_HOST" "tcp-echo"
  $RelayDialPort = Resolve-DefaultInt $RelayDialPort "RELAY_DIAL_PORT" 9000

  $GatewayHost = Resolve-Default $GatewayHost "GATEWAY_HOST" "gateway"
  $GatewayPortUdp = Resolve-DefaultInt $GatewayPortUdp "GATEWAY_PORT_UDP" 443
  $GatewayPortTcp = Resolve-DefaultInt $GatewayPortTcp "GATEWAY_PORT_TCP" 443

  $Client = Resolve-Default $Client "VLF_CLIENT" "smoke-client"
  $Secret = Resolve-Default $Secret "VLF_SECRET" "smoke-secret"
  $PinSpki = Resolve-Default $PinSpki "VLF_PIN_SPKI" ""

  Write-Log "Network=$Network"
  Write-Log "RelayBase=$RelayBase"
  Write-Log "Gateway=$GatewayHost udp=$GatewayPortUdp tcp=$GatewayPortTcp"

  if ($BuildBinaries.IsPresent) {
    Invoke-DockerBuild
  }

  $relayEnv = @{
    RELAY_BASE = $RelayBase
    RELAY_DIAL_HOST = $RelayDialHost
    RELAY_DIAL_PORT = "$RelayDialPort"
    VLF_CLIENT = $Client
    VLF_SECRET = $Secret
  }
  Invoke-DockerSmoke -Name "relay_smoke" -NetworkName $Network -Env $relayEnv -GoFile "./scripts/relay_smoke.go"

  $sessionEnv = @{
    GATEWAY_HOST = $GatewayHost
    GATEWAY_PORT_UDP = "$GatewayPortUdp"
    GATEWAY_PORT_TCP = "$GatewayPortTcp"
    SESSION_ADDR = "$GatewayHost`:$GatewayPortUdp"
    RELAY_BASE = $RelayBase
    VLF_CLIENT_ID = $Client
    VLF_SECRET = $Secret
    VLF_PIN_SPKI = $PinSpki
    VLF_PROTO_ID = "vlf-runtime/0.1"
    DST_TCP_HOST = "tcp-echo"
    DST_TCP_PORT = "9000"
    DST_UDP_HOST = "udp-echo"
    DST_UDP_PORT = "9001"
    MAX_DGRAM_PAYLOAD = "1200"
  }
  Invoke-DockerSmoke -Name "session_smoke" -NetworkName $Network -Env $sessionEnv -GoFile "./scripts/session_smoke.go"

  Write-Host "PASS windows docker smoke"
} catch {
  Write-Error $_.Exception.Message
  exit 1
}
