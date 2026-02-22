<#
VLF Runtime Windows test runner.
- Loads configuration from .env (BOM/quotes/comments safe)
- Builds smoke binaries with native Go or dockerized Go toolchain
- Runs session + relay smoke + negative checks
- Always writes report.json and report.md
#>

[CmdletBinding()]
param(
  [string]$EnvFile = "",

  [ValidateSet("External","Docker","Both")]
  [string]$Mode = "",

  [string]$GatewayHost = "",
  [int]$GatewayPort = 0,
  [int]$GatewayPortUdp = 0,
  [int]$GatewayPortTcp = 0,
  [string]$RelayBase = "",

  [string]$Client = "",
  [string]$ClientId = "",
  [string]$Secret = "",
  [string]$PinSpki = "",

  [string]$WorkDir = "",
  [string]$OutDir = "",
  [string]$SessionExe = "",
  [string]$RelayExe = "",
  [string]$SessionGo = "",
  [string]$RelayGo = "",

  [switch]$Build,
  [int]$MaxDgramPayload = 0,
  [switch]$NoPause
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ScriptDir = $PSScriptRoot
if (-not $ScriptDir) {
  $ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
}
if (-not $ScriptDir) {
  $ScriptDir = (Get-Location).Path
}
if (-not $EnvFile) {
  $EnvFile = Join-Path $ScriptDir ".env"
}

$RepoRoot = (Resolve-Path (Join-Path $ScriptDir "..")).Path

function New-RunId {
  (Get-Date).ToString("yyyyMMdd_HHmmss")
}

function Ensure-Dir([string]$Path) {
  if (-not (Test-Path -LiteralPath $Path)) {
    New-Item -ItemType Directory -Path $Path | Out-Null
  }
}

function Write-Log([string]$Message) {
  $ts = (Get-Date).ToString("HH:mm:ss")
  Write-Host "[$ts] $Message"
}

function Import-DotEnv([string]$Path) {
  if (-not (Test-Path -LiteralPath $Path)) {
    return @{}
  }

  $resolved = (Resolve-Path -LiteralPath $Path).Path
  $raw = [System.IO.File]::ReadAllText($resolved)
  if ($raw.Length -gt 0 -and [int][char]$raw[0] -eq 0xFEFF) {
    $raw = $raw.Substring(1)
  }

  $map = @{}
  $lines = $raw -split "`r?`n"
  foreach ($lineRaw in $lines) {
    $line = $lineRaw.Trim()
    if (-not $line) { continue }
    if ($line.StartsWith("#")) { continue }
    if ($line.StartsWith("export ")) {
      $line = $line.Substring(7).Trim()
    }

    $idx = $line.IndexOf('=')
    if ($idx -lt 1) { continue }

    $key = $line.Substring(0, $idx).Trim()
    $val = $line.Substring($idx + 1).Trim()

    if (($val.StartsWith('"') -and $val.EndsWith('"')) -or ($val.StartsWith("'") -and $val.EndsWith("'"))) {
      $val = $val.Substring(1, $val.Length - 2)
    } else {
      $commentIdx = $val.IndexOf(" #")
      if ($commentIdx -gt 0) {
        $val = $val.Substring(0, $commentIdx).Trim()
      }
    }

    if ($key.Length -gt 0) {
      $map[$key] = $val
    }
  }

  return $map
}

function Pick-Value([string]$CliValue, [hashtable]$DotEnv, [string[]]$Keys, [string]$Fallback = "") {
  if ($CliValue) { return $CliValue }

  foreach ($key in $Keys) {
    $processValue = [Environment]::GetEnvironmentVariable($key, "Process")
    if ($processValue) { return [string]$processValue }

    $userValue = [Environment]::GetEnvironmentVariable($key, "User")
    if ($userValue) { return [string]$userValue }

    if ($DotEnv.ContainsKey($key) -and $DotEnv[$key]) {
      return [string]$DotEnv[$key]
    }
  }

  return $Fallback
}

function Pick-Int([int]$CliValue, [hashtable]$DotEnv, [string[]]$Keys, [int]$Fallback) {
  if ($CliValue -gt 0) { return $CliValue }

  foreach ($key in $Keys) {
    $raw = Pick-Value "" $DotEnv @($key) ""
    if (-not $raw) { continue }
    try {
      $parsed = [int]$raw
      if ($parsed -gt 0) { return $parsed }
    } catch {}
  }

  return $Fallback
}

function Pick-Bool([bool]$CliTrue, [hashtable]$DotEnv, [string[]]$Keys, [bool]$Fallback = $false) {
  if ($CliTrue) {
    return $true
  }

  foreach ($key in $Keys) {
    $raw = Pick-Value "" $DotEnv @($key) ""
    if (-not $raw) { continue }
    switch ($raw.Trim().ToLowerInvariant()) {
      "1" { return $true }
      "true" { return $true }
      "yes" { return $true }
      "on" { return $true }
      "0" { return $false }
      "false" { return $false }
      "no" { return $false }
      "off" { return $false }
    }
  }

  return $Fallback
}

function Require-Value([string]$Name, [string]$Value) {
  if (-not $Value) {
    throw "Missing required config: $Name"
  }
}

function Get-DockerAvailable {
  try {
    $p = Start-Process -FilePath "docker" -ArgumentList @("version") -NoNewWindow -PassThru -Wait -RedirectStandardOutput "$env:TEMP\vlf_docker_stdout.txt" -RedirectStandardError "$env:TEMP\vlf_docker_stderr.txt"
    return ($p.ExitCode -eq 0)
  } catch {
    return $false
  }
}

function Get-GoAvailable {
  try {
    $p = Start-Process -FilePath "go" -ArgumentList @("version") -NoNewWindow -PassThru -Wait -RedirectStandardOutput "$env:TEMP\vlf_go_stdout.txt" -RedirectStandardError "$env:TEMP\vlf_go_stderr.txt"
    return ($p.ExitCode -eq 0)
  } catch {
    return $false
  }
}

function To-UnixPath([string]$Path) {
  return $Path.Replace("\\", "/")
}

function Build-GoBinary {
  param(
    [Parameter(Mandatory = $true)][string]$GoFile,
    [Parameter(Mandatory = $true)][string]$OutExe,
    [Parameter(Mandatory = $true)][string]$WorkingDirectory
  )

  if (-not (Test-Path -LiteralPath $GoFile)) {
    throw "Go source not found: $GoFile"
  }

  Ensure-Dir (Split-Path -Parent $OutExe)
  $goAbs = (Resolve-Path -LiteralPath $GoFile).Path
  $wdAbs = (Resolve-Path -LiteralPath $WorkingDirectory).Path
  $outAbs = [System.IO.Path]::GetFullPath($OutExe)

  Write-Log "Building $goAbs -> $outAbs"

  if (Get-GoAvailable) {
    & go build -o $outAbs $goAbs
    if ($LASTEXITCODE -ne 0) {
      throw "go build failed for $goAbs"
    }
    return
  }

  if (-not (Get-DockerAvailable)) {
    throw "Neither native Go nor Docker is available to build $goAbs"
  }

  $goRel = To-UnixPath([System.IO.Path]::GetRelativePath($wdAbs, $goAbs))
  $outRel = To-UnixPath([System.IO.Path]::GetRelativePath($wdAbs, $outAbs))
  $wdForDocker = $wdAbs

  $cmd = "apk add --no-cache git ca-certificates >/dev/null && go build -o '$outRel' '$goRel'"
  & docker run --rm -v "${wdForDocker}:/src" -w /src golang:1.24-alpine sh -lc $cmd
  if ($LASTEXITCODE -ne 0) {
    throw "dockerized go build failed for $goRel"
  }
}

function Resolve-ExePath([string]$Provided, [string]$Fallback) {
  if ($Provided -and (Test-Path -LiteralPath $Provided)) {
    return (Resolve-Path -LiteralPath $Provided).Path
  }
  if ($Fallback -and (Test-Path -LiteralPath $Fallback)) {
    return (Resolve-Path -LiteralPath $Fallback).Path
  }
  return ""
}

function Set-ProcessEnv([hashtable]$Vars) {
  foreach ($key in $Vars.Keys) {
    $val = $Vars[$key]
    if ($null -eq $val) { continue }
    [Environment]::SetEnvironmentVariable($key, [string]$val, "Process")
  }
}

function Run-Process {
  param(
    [Parameter(Mandatory = $true)][string]$FilePath,
    [string[]]$Arguments = @(),
    [hashtable]$Env = @{},
    [string]$WorkingDirectory,
    [int]$TimeoutSec = 120
  )

  $start = Get-Date
  $psi = New-Object System.Diagnostics.ProcessStartInfo
  $psi.FileName = $FilePath
  $psi.WorkingDirectory = $WorkingDirectory
  $psi.UseShellExecute = $false
  $psi.RedirectStandardOutput = $true
  $psi.RedirectStandardError = $true
  $psi.CreateNoWindow = $true

  foreach ($a in $Arguments) {
    [void]$psi.ArgumentList.Add($a)
  }

  foreach ($k in $Env.Keys) {
    if ($null -ne $Env[$k]) {
      $psi.Environment[$k] = [string]$Env[$k]
    }
  }

  $p = New-Object System.Diagnostics.Process
  $p.StartInfo = $psi

  $null = $p.Start()
  if (-not $p.WaitForExit($TimeoutSec * 1000)) {
    try { $p.Kill($true) } catch {}
    return [pscustomobject]@{
      exitCode = 124
      durationMs = [int]((Get-Date) - $start).TotalMilliseconds
      stdout = ""
      stderr = "TIMEOUT after ${TimeoutSec}s"
    }
  }

  return [pscustomobject]@{
    exitCode = $p.ExitCode
    durationMs = [int]((Get-Date) - $start).TotalMilliseconds
    stdout = $p.StandardOutput.ReadToEnd()
    stderr = $p.StandardError.ReadToEnd()
  }
}

function Get-ResultReason([pscustomobject]$ProcResult) {
  if ($ProcResult.exitCode -eq 124) {
    return "timeout"
  }

  $stderr = [string]$ProcResult.stderr
  if ($stderr) {
    $lines = $stderr -split "`r?`n"
    foreach ($line in $lines) {
      $trimmed = $line.Trim()
      if ($trimmed) { return $trimmed }
    }
  }

  $stdout = [string]$ProcResult.stdout
  if ($stdout) {
    $lines = $stdout -split "`r?`n"
    foreach ($line in $lines) {
      $trimmed = $line.Trim()
      if ($trimmed) { return $trimmed }
    }
  }

  return "exit=$($ProcResult.exitCode)"
}

function New-ValidWrongPin([string]$Pin) {
  $rawPin = $Pin.Trim()
  if ($rawPin.StartsWith("sha256/")) {
    $rawPin = $rawPin.Substring(7)
  }
  if (-not $rawPin) {
    throw "empty pin"
  }

  $bytes = [Convert]::FromBase64String($rawPin)
  if ($bytes.Length -ne 32) {
    throw "pin length must be 32 bytes, got $($bytes.Length)"
  }

  $bytes[0] = [byte]($bytes[0] -bxor 0x01)
  return [Convert]::ToBase64String($bytes)
}

function New-BadSecret([string]$SecretValue) {
  if (-not $SecretValue) {
    return "bad-secret"
  }

  if ($SecretValue.StartsWith("b64:")) {
    $raw = $SecretValue.Substring(4)
    try {
      $bytes = [Convert]::FromBase64String($raw)
      if ($bytes.Length -eq 0) {
        return "b64:AQ"
      }
      $bytes[0] = [byte]($bytes[0] -bxor 0x01)
      return "b64:" + [Convert]::ToBase64String($bytes)
    } catch {
      return "bad-secret"
    }
  }

  return "$SecretValue-bad"
}

function Test-IsAdmin {
  $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
  $principal = New-Object Security.Principal.WindowsPrincipal($identity)
  return $principal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

function Add-UdpBlockRule([string]$Name, [int]$RemotePort) {
  & netsh advfirewall firewall add rule name="$Name" dir=out action=block protocol=UDP remoteport=$RemotePort | Out-Null
  if ($LASTEXITCODE -ne 0) {
    throw "failed to add firewall rule $Name"
  }
}

function Remove-FirewallRuleSafe([string]$Name) {
  try {
    & netsh advfirewall firewall delete rule name="$Name" | Out-Null
  } catch {}
}

function Get-MetaValue([object]$Meta, [string]$Key) {
  if ($null -eq $Meta) {
    return ""
  }
  if ($Meta -is [hashtable]) {
    if ($Meta.ContainsKey($Key)) {
      return [string]$Meta[$Key]
    }
    return ""
  }

  $prop = $Meta.PSObject.Properties[$Key]
  if ($null -eq $prop -or $null -eq $prop.Value) {
    return ""
  }
  return [string]$prop.Value
}

function Resolve-WithBase([string]$BaseDir, [string]$PathValue) {
  if (-not $PathValue) {
    return $PathValue
  }
  if ([System.IO.Path]::IsPathRooted($PathValue)) {
    return [System.IO.Path]::GetFullPath($PathValue)
  }
  return [System.IO.Path]::GetFullPath((Join-Path $BaseDir $PathValue))
}

$DotEnv = Import-DotEnv $EnvFile
$EnvBaseDir = $ScriptDir
if (Test-Path -LiteralPath $EnvFile) {
  $EnvBaseDir = Split-Path -Parent (Resolve-Path -LiteralPath $EnvFile).Path
}

if (-not $Mode) { $Mode = Pick-Value "" $DotEnv @("MODE") "External" }
$GatewayHost = Pick-Value $GatewayHost $DotEnv @("GATEWAY_HOST") ""
$legacyPort = Pick-Int $GatewayPort $DotEnv @("GATEWAY_PORT") 443
$GatewayPortUdp = Pick-Int $GatewayPortUdp $DotEnv @("GATEWAY_PORT_UDP") $legacyPort
$GatewayPortTcp = Pick-Int $GatewayPortTcp $DotEnv @("GATEWAY_PORT_TCP") $legacyPort
$RelayBase = Pick-Value $RelayBase $DotEnv @("RELAY_BASE") ""

$Client = Pick-Value $Client $DotEnv @("VLF_CLIENT") "smoke-client"
$ClientId = Pick-Value $ClientId $DotEnv @("VLF_CLIENT_ID","VLF_CLIENT") ""
$Secret = Pick-Value $Secret $DotEnv @("VLF_SECRET") ""
$PinSpki = Pick-Value $PinSpki $DotEnv @("VLF_PIN_SPKI") ""

if (-not $WorkDir) {
  $WorkDir = Pick-Value "" $DotEnv @("WORK_DIR") $RepoRoot
}
if ($WorkDir) {
  $WorkDir = Resolve-WithBase $EnvBaseDir $WorkDir
}
if (-not $OutDir) {
  $OutDir = Pick-Value "" $DotEnv @("OUT_DIR") "out"
}
if ($OutDir) {
  $OutDir = Resolve-WithBase $WorkDir $OutDir
}
if (-not $SessionGo) {
  $SessionGo = Pick-Value "" $DotEnv @("SESSION_GO") "session_smoke.go"
}
if ($SessionGo) {
  $SessionGo = Resolve-WithBase $WorkDir $SessionGo
}
if (-not $RelayGo) {
  $RelayGo = Pick-Value "" $DotEnv @("RELAY_GO") "relay_smoke/main.go"
}
if ($RelayGo) {
  $RelayGo = Resolve-WithBase $WorkDir $RelayGo
}
if (-not $SessionExe) {
  $SessionExe = Pick-Value "" $DotEnv @("SESSION_EXE") "out/session_smoke.exe"
}
if ($SessionExe) {
  $SessionExe = Resolve-WithBase $WorkDir $SessionExe
}
if (-not $RelayExe) {
  $RelayExe = Pick-Value "" $DotEnv @("RELAY_EXE") "out/relay_smoke.exe"
}
if ($RelayExe) {
  $RelayExe = Resolve-WithBase $WorkDir $RelayExe
}

if ($MaxDgramPayload -le 0) {
  $MaxDgramPayload = Pick-Int 0 $DotEnv @("MAX_DGRAM_PAYLOAD") 1200
}
$debugEnabled = Pick-Bool $false $DotEnv @("VLF_DEBUG") $false
$buildFromDotEnv = Pick-Bool $false $DotEnv @("BUILD") $false
if (-not $Build.IsPresent -and $buildFromDotEnv) {
  $Build = $true
}
$noPauseFromDotEnv = Pick-Bool $false $DotEnv @("NO_PAUSE") $false
if (-not $NoPause.IsPresent -and $noPauseFromDotEnv) {
  $NoPause = $true
}

Require-Value "GATEWAY_HOST" $GatewayHost
Require-Value "VLF_CLIENT_ID" $ClientId
Require-Value "VLF_SECRET" $Secret
if (-not $RelayBase) {
  $RelayBase = "http://$GatewayHost:8080"
}

Ensure-Dir $OutDir
$runId = New-RunId
$runRoot = Join-Path $OutDir "run_$runId"
Ensure-Dir $runRoot

$logFile = Join-Path $runRoot "runner.log.txt"
$reportJson = Join-Path $runRoot "report.json"
$reportMd = Join-Path $runRoot "report.md"

Start-Transcript -Path $logFile -Append | Out-Null

$scriptExitCode = 0

try {
  Write-Log "VLF Windows runner started"
  Write-Log "Mode=$Mode"
  Write-Log "Gateway=$GatewayHost udp=$GatewayPortUdp tcp=$GatewayPortTcp"
  Write-Log "Relay=$RelayBase"
  Write-Log "WorkDir=$WorkDir"

  if ($Build) {
    Build-GoBinary -GoFile $SessionGo -OutExe $SessionExe -WorkingDirectory $WorkDir
    Build-GoBinary -GoFile $RelayGo -OutExe $RelayExe -WorkingDirectory $WorkDir
  }

  $sessionExePath = Resolve-ExePath $SessionExe (Join-Path $OutDir "session_smoke.exe")
  $relayExePath = Resolve-ExePath $RelayExe (Join-Path $OutDir "relay_smoke.exe")

  if (-not $sessionExePath) {
    throw "session smoke binary not found. Use BUILD=1 or set SESSION_EXE."
  }
  if (-not $relayExePath) {
    throw "relay smoke binary not found. Use BUILD=1 or set RELAY_EXE."
  }

  Write-Log "SessionExe=$sessionExePath"
  Write-Log "RelayExe=$relayExePath"

  $results = New-Object System.Collections.Generic.List[object]

  function Add-Result {
    param(
      [string]$Name,
      [string]$Scope,
      [string]$Expected,
      [pscustomobject]$ProcResult,
      [hashtable]$Meta = @{}
    )

    $ok = $false
    switch ($Expected) {
      "Exit0" { $ok = ($ProcResult.exitCode -eq 0) }
      "ExitNon0" { $ok = ($ProcResult.exitCode -ne 0) }
      "Skip" { $ok = $true }
      default { $ok = ($ProcResult.exitCode -eq 0) }
    }

    $item = [pscustomobject]@{
      name = $Name
      scope = $Scope
      expected = $Expected
      ok = $ok
      exitCode = $ProcResult.exitCode
      durationMs = $ProcResult.durationMs
      reason = Get-ResultReason $ProcResult
      stdout = $ProcResult.stdout
      stderr = $ProcResult.stderr
      meta = $Meta
    }

    $results.Add($item) | Out-Null
    $status = if ($ok) { "PASS" } else { "FAIL" }
    Write-Log "$status :: $Name :: exit=$($ProcResult.exitCode) reason=$($item.reason)"
  }

  function New-BaseEnv([string]$secretOverride = $null, [string]$pinOverride = $null, [bool]$disableRelayFallback = $false) {
    $map = @{
      VLF_CLIENT = $Client
      VLF_CLIENT_ID = $ClientId
      VLF_SECRET = $(if ($null -ne $secretOverride) { $secretOverride } else { $Secret })
      VLF_PIN_SPKI = $(if ($null -ne $pinOverride) { $pinOverride } else { $PinSpki })
      VLF_DISABLE_RELAY_FALLBACK = $(if ($disableRelayFallback) { "1" } else { "0" })
      VLF_DEBUG = $(if ($debugEnabled) { "1" } else { "0" })
      MAX_DGRAM_PAYLOAD = "$MaxDgramPayload"

      GATEWAY_HOST = $GatewayHost
      GATEWAY_PORT = "$legacyPort"
      GATEWAY_PORT_UDP = "$GatewayPortUdp"
      GATEWAY_PORT_TCP = "$GatewayPortTcp"
      SESSION_ADDR = "$GatewayHost`:$GatewayPortUdp"

      RELAY_BASE = $RelayBase
    }

    $relayDialHost = Pick-Value "" $DotEnv @("RELAY_DIAL_HOST") ""
    $relayDialPort = Pick-Value "" $DotEnv @("RELAY_DIAL_PORT") ""
    if ($relayDialHost) { $map["RELAY_DIAL_HOST"] = $relayDialHost }
    if ($relayDialPort) { $map["RELAY_DIAL_PORT"] = $relayDialPort }

    return $map
  }

  if ($Mode -in @("External","Both")) {
    Write-Log "Running External tests"

    $envSession = New-BaseEnv
    Set-ProcessEnv $envSession
    $res = Run-Process -FilePath $sessionExePath -Env $envSession -WorkingDirectory $WorkDir -TimeoutSec 120
    Add-Result -Name "session_smoke: primary path (QUIC->TCP->relay fallback)" -Scope "external" -Expected "Exit0" -ProcResult $res -Meta @{ transport="auto" }

    $envRelay = New-BaseEnv
    Set-ProcessEnv $envRelay
    $res = Run-Process -FilePath $relayExePath -Env $envRelay -WorkingDirectory $WorkDir -TimeoutSec 90
    Add-Result -Name "relay_smoke: relay lane" -Scope "external" -Expected "Exit0" -ProcResult $res -Meta @{ lane="relay" }

    if ($PinSpki) {
      $wrongPin = New-ValidWrongPin $PinSpki
      $envBadPin = New-BaseEnv -pinOverride $wrongPin -disableRelayFallback $true
      Set-ProcessEnv $envBadPin
      $res = Run-Process -FilePath $sessionExePath -Env $envBadPin -WorkingDirectory $WorkDir -TimeoutSec 60
      Add-Result -Name "session_smoke: wrong pin should fail" -Scope "external" -Expected "ExitNon0" -ProcResult $res -Meta @{ note="valid-length SPKI pin mismatch" }
    } else {
      Add-Result -Name "session_smoke: wrong pin should fail" -Scope "external" -Expected "Skip" -ProcResult ([pscustomobject]@{exitCode=0;durationMs=0;stdout="";stderr=""}) -Meta @{ note="skipped: VLF_PIN_SPKI is empty" }
    }

    $badSecret = New-BadSecret $Secret
    $envBadSecret = New-BaseEnv -secretOverride $badSecret -disableRelayFallback $true
    Set-ProcessEnv $envBadSecret
    $res = Run-Process -FilePath $sessionExePath -Env $envBadSecret -WorkingDirectory $WorkDir -TimeoutSec 60
    Add-Result -Name "session_smoke: wrong secret should fail" -Scope "external" -Expected "ExitNon0" -ProcResult $res -Meta @{ note="HMAC reject expected" }

    if (Test-IsAdmin) {
      $ruleName = "VLF_BlockUDP_${GatewayPortUdp}_$runId"
      try {
        Add-UdpBlockRule -Name $ruleName -RemotePort $GatewayPortUdp
        $envUdpBlocked = New-BaseEnv
        Set-ProcessEnv $envUdpBlocked
        $res = Run-Process -FilePath $sessionExePath -Env $envUdpBlocked -WorkingDirectory $WorkDir -TimeoutSec 90
        Add-Result -Name "session_smoke: UDP blocked fallback" -Scope "external" -Expected "Exit0" -ProcResult $res -Meta @{ note="fallback must keep test green" }
      } finally {
        Remove-FirewallRuleSafe -Name $ruleName
      }
    } else {
      Add-Result -Name "session_smoke: UDP blocked fallback" -Scope "external" -Expected "Skip" -ProcResult ([pscustomobject]@{exitCode=0;durationMs=0;stdout="";stderr=""}) -Meta @{ note="skipped: run PowerShell as Administrator to apply firewall rule" }
    }
  }

  if ($Mode -in @("Docker","Both")) {
    $dockerOk = Get-DockerAvailable
    if ($dockerOk) {
      Add-Result -Name "docker mode note" -Scope "docker" -Expected "Skip" -ProcResult ([pscustomobject]@{exitCode=0;durationMs=0;stdout="";stderr=""}) -Meta @{ note="windows .exe execution in linux container is not supported" }
    } else {
      Add-Result -Name "docker mode note" -Scope "docker" -Expected "Skip" -ProcResult ([pscustomobject]@{exitCode=0;durationMs=0;stdout="";stderr=""}) -Meta @{ note="skipped: docker is unavailable" }
    }
  }

  $passCount = @($results | Where-Object { $_.ok }).Count
  $failCount = @($results | Where-Object { -not $_.ok }).Count

  $summary = [pscustomobject]@{
    runId = $runId
    startedAt = (Get-Date).ToString("o")
    mode = $Mode
    targets = [pscustomobject]@{
      gateway_host = $GatewayHost
      gateway_port_udp = $GatewayPortUdp
      gateway_port_tcp = $GatewayPortTcp
      relay_base = $RelayBase
    }
    totals = [pscustomobject]@{
      pass = $passCount
      fail = $failCount
      total = $results.Count
    }
    results = $results
  }

  $summary | ConvertTo-Json -Depth 10 | Out-File -LiteralPath $reportJson -Encoding utf8

  $md = New-Object System.Collections.Generic.List[string]
  $null = $md.Add("# VLF Windows Smoke Report")
  $null = $md.Add("")
  $null = $md.Add("- Run ID: **$runId**")
  $null = $md.Add("- Mode: **$Mode**")
  $null = $md.Add("- Gateway host: **$GatewayHost**")
  $null = $md.Add("- Gateway UDP port: **$GatewayPortUdp**")
  $null = $md.Add("- Gateway TCP port: **$GatewayPortTcp**")
  $null = $md.Add("- Relay base: **$RelayBase**")
  $null = $md.Add("")
  $null = $md.Add("## Summary")
  $null = $md.Add("")
  $null = $md.Add("- PASS: **$passCount**")
  $null = $md.Add("- FAIL: **$failCount**")
  $null = $md.Add("- TOTAL: **$($results.Count)**")
  $null = $md.Add("")
  $null = $md.Add("## Results")
  $null = $md.Add("")
  $null = $md.Add("| Status | Test | Scope | Expected | Exit | Duration (ms) | Reason | Notes |")
  $null = $md.Add("|---|---|---|---|---:|---:|---|---|")

  foreach ($r in $results) {
    $status = if ($r.ok) { "PASS" } else { "FAIL" }
    $note = Get-MetaValue $r.meta "note"
    $reason = [string]$r.reason
    $reason = $reason.Replace("|", "\\|")
    $note = $note.Replace("|", "\\|")
    $null = $md.Add("| $status | $($r.name) | $($r.scope) | $($r.expected) | $($r.exitCode) | $($r.durationMs) | $reason | $note |")
  }

  $null = $md.Add("")
  $null = $md.Add("## Details")
  $null = $md.Add("")
  foreach ($r in $results) {
    $status = if ($r.ok) { "PASS" } else { "FAIL" }
    $null = $md.Add("### $status - $($r.name)")
    $null = $md.Add("")
    $null = $md.Add("- Exit: **$($r.exitCode)**")
    $null = $md.Add("- Duration: **$($r.durationMs) ms**")
    $null = $md.Add(('- Reason: `{0}`' -f $r.reason))
    $null = $md.Add("")

    $stdout = [string]$r.stdout
    if ($stdout.Length -gt 0) {
      if ($stdout.Length -gt 4000) { $stdout = $stdout.Substring(0, 4000) }
      $null = $md.Add("stdout:")
      $null = $md.Add('```')
      $null = $md.Add($stdout)
      $null = $md.Add('```')
    }

    $stderr = [string]$r.stderr
    if ($stderr.Length -gt 0) {
      if ($stderr.Length -gt 4000) { $stderr = $stderr.Substring(0, 4000) }
      $null = $md.Add("stderr:")
      $null = $md.Add('```')
      $null = $md.Add($stderr)
      $null = $md.Add('```')
    }
    $null = $md.Add("")
  }

  $md -join "`r`n" | Out-File -LiteralPath $reportMd -Encoding utf8

  Write-Host ""
  Write-Host "Result table:" -ForegroundColor Cyan
  $results | Select-Object @{Name='Status';Expression={ if ($_.ok) { 'PASS' } else { 'FAIL' } }}, name, scope, expected, exitCode, durationMs, reason | Format-Table -AutoSize
  Write-Host ""
  Write-Log "Report files:"
  Write-Host "  $reportJson"
  Write-Host "  $reportMd"
  Write-Host "  $logFile"

  if ($failCount -gt 0) {
    Write-Log "Overall FAIL"
    $scriptExitCode = 1
  } else {
    Write-Log "Overall PASS"
  }
} catch {
  $scriptExitCode = 2
  Write-Host ""
  Write-Host "Runner crashed: $($_.Exception.Message)" -ForegroundColor Red
  Write-Host "Stack: $($_.ScriptStackTrace)"
} finally {
  try { Stop-Transcript | Out-Null } catch {}
  if (-not $NoPause.IsPresent) {
    Write-Host ""
    Read-Host "Press Enter to close"
  }
}

exit $scriptExitCode
