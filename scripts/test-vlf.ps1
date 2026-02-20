param(
  [string]$ProjectDir = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path,
  [string]$Network = "",
  [string]$GatewayContainer = "vlf-gateway",
  [switch]$BuildBinaries
)

$ErrorActionPreference = "Stop"

function Fail([string]$Message) {
  Write-Error $Message
  exit 1
}

function Ensure-Command([string]$Name) {
  if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
    Fail "Required command not found: $Name"
  }
}

function Resolve-NetworkName([string]$Requested, [string]$GatewayName) {
  if ($Requested) {
    return $Requested
  }

  $inspect = @()
  try {
    $inspect = & docker inspect --format '{{range $k, $v := .NetworkSettings.Networks}}{{println $k}}{{end}}' $GatewayName 2>$null
  } catch {
    $inspect = @()
  }
  $inspect = $inspect | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "" }
  if ($inspect.Count -gt 0) {
    return $inspect[0]
  }

  $candidates = & docker network ls --format '{{.Name}}'
  $picked = $candidates | Where-Object { $_ -match 'vlf|VLF|proto' } | Select-Object -First 1
  if (-not $picked) {
    Fail "Could not detect docker network. Set -Network explicitly."
  }
  return $picked
}

function Invoke-DockerGo([string[]]$EnvPairs, [string]$ScriptBody, [string]$VolumeSpec, [string]$NetworkName) {
  $args = @("run", "--rm", "--network", $NetworkName, "-v", $VolumeSpec, "-w", "/src")
  foreach ($pair in $EnvPairs) {
    $args += @("--env", $pair)
  }
  $args += @("golang:1.24-alpine", "sh", "-lc", $ScriptBody)

  & docker @args
  if ($LASTEXITCODE -ne 0) {
    Fail "dockerized go command failed"
  }
}

Ensure-Command "docker"

$null = & docker compose version 2>$null
if ($LASTEXITCODE -ne 0) {
  Fail "docker compose v2 plugin is required"
}

$projectPath = (Resolve-Path $ProjectDir).Path
$mountPath = ($projectPath -replace "\\", "/") + ":/src"
$netName = Resolve-NetworkName -Requested $Network -GatewayName $GatewayContainer

Write-Host "ProjectDir: $projectPath"
Write-Host "Network: $netName"

$relayBase = if ($env:RELAY_BASE) { $env:RELAY_BASE } else { "http://gateway:8080" }
$relayDialHost = if ($env:RELAY_DIAL_HOST) { $env:RELAY_DIAL_HOST } else { "tcp-echo" }
$relayDialPort = if ($env:RELAY_DIAL_PORT) { $env:RELAY_DIAL_PORT } else { "9000" }
$client = if ($env:VLF_CLIENT) { $env:VLF_CLIENT } elseif ($env:VLF_CLIENT_ID) { $env:VLF_CLIENT_ID } else { "smoke-client" }
$secret = if ($env:VLF_SECRET) { $env:VLF_SECRET } else { "smoke-secret" }
$sessionAddr = if ($env:SESSION_ADDR) { $env:SESSION_ADDR } else { "gateway:443" }
$protoId = if ($env:VLF_PROTO_ID) { $env:VLF_PROTO_ID } else { "vlf-runtime/0.1" }
$dstTcpHost = if ($env:DST_TCP_HOST) { $env:DST_TCP_HOST } else { "tcp-echo" }
$dstTcpPort = if ($env:DST_TCP_PORT) { $env:DST_TCP_PORT } else { "9000" }
$dstUdpHost = if ($env:DST_UDP_HOST) { $env:DST_UDP_HOST } else { "udp-echo" }
$dstUdpPort = if ($env:DST_UDP_PORT) { $env:DST_UDP_PORT } else { "9001" }
$maxDgram = if ($env:MAX_DGRAM_PAYLOAD) { $env:MAX_DGRAM_PAYLOAD } else { "1200" }
$pin = if ($env:VLF_PIN_SPKI) { $env:VLF_PIN_SPKI } else { "" }

if ($BuildBinaries) {
  Write-Host "[1/3] Building Windows smoke binaries in dockerized Go toolchain..."
  Invoke-DockerGo -VolumeSpec $mountPath -NetworkName $netName -EnvPairs @() -ScriptBody @'
apk add --no-cache git ca-certificates &&
mkdir -p out &&
GOOS=windows GOARCH=amd64 go build -o out/relay_smoke.exe ./scripts/relay_smoke.go &&
GOOS=windows GOARCH=amd64 go build -o out/session_smoke.exe ./scripts/session_smoke.go
'@
}

Write-Host "[2/3] Running relay smoke in docker network..."
Invoke-DockerGo -VolumeSpec $mountPath -NetworkName $netName -EnvPairs @(
  "RELAY_BASE=$relayBase",
  "RELAY_DIAL_HOST=$relayDialHost",
  "RELAY_DIAL_PORT=$relayDialPort",
  "VLF_CLIENT=$client",
  "VLF_CLIENT_ID=$client",
  "VLF_SECRET=$secret"
) -ScriptBody "apk add --no-cache git ca-certificates && go run ./scripts/relay_smoke.go"

Write-Host "[3/3] Running session smoke in docker network..."
$sessionEnv = @(
  "SESSION_ADDR=$sessionAddr",
  "VLF_CLIENT_ID=$client",
  "VLF_CLIENT=$client",
  "VLF_SECRET=$secret",
  "VLF_PROTO_ID=$protoId",
  "DST_TCP_HOST=$dstTcpHost",
  "DST_TCP_PORT=$dstTcpPort",
  "DST_UDP_HOST=$dstUdpHost",
  "DST_UDP_PORT=$dstUdpPort",
  "MAX_DGRAM_PAYLOAD=$maxDgram"
)
if ($pin) {
  $sessionEnv += "VLF_PIN_SPKI=$pin"
}
Invoke-DockerGo -VolumeSpec $mountPath -NetworkName $netName -EnvPairs $sessionEnv -ScriptBody "apk add --no-cache git ca-certificates && go run ./scripts/session_smoke.go"

Write-Host "PASS: relay + session smoke"
