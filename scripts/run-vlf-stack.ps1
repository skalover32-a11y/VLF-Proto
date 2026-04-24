<#
Run VLF socks_client + sing-box in one PowerShell window with merged logs.

Examples:
  .\scripts\run-vlf-stack.ps1 -GatewayHost example.com -GatewayIP 203.0.113.10 -SingBoxConfig .\config.json
  .\scripts\run-vlf-stack.ps1 -Build -Debug -DisableTcpSession -DisableRelayFallback
#>

[CmdletBinding()]
param(
  [string]$EnvFile = "",
  [string]$SocksExe = ".\socks_client.exe",
  [string]$SingBoxExe = ".\sing-box.exe",
  [string]$SingBoxConfig = ".\config.json",
  [string]$LogsRoot = ".\scripts\out\stack",

  [string]$Listen = "127.0.0.1:1080",
  [string]$GatewayHost = "",
  [string]$GatewayIP = "",
  [string]$TlsServerName = "",
  [int]$GatewayPortUdp = 0,
  [int]$GatewayPortTcp = 0,

  [string]$Mode = "auto",
  [string]$StatsFormat = "text",

  [string]$ClientID = "",
  [string]$Secret = "",
  [string]$PinSPKI = "",
  [switch]$NoPin,
  [string]$Auth = "none",
  [string]$Username = "",
  [string]$Password = "",

  [switch]$ResolveOnce = $true,
  [switch]$DisableQuic,
  [switch]$DisableTcpSession,
  [switch]$DisableRelayFallback,
  [switch]$ForceIPv4,
  [switch]$SessionDebug,
  [switch]$Build,
  [switch]$NoSingBox,

  [int]$StartupTimeoutSec = 20,
  [int]$PollIntervalMs = 250,
  [int]$RunSeconds = 0,

  [string[]]$SocksExtraArgs = @(),
  [string[]]$SingBoxExtraArgs = @()
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

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

function Resolve-AbsPath([string]$Path, [string]$Label) {
  if (-not (Test-Path -LiteralPath $Path)) {
    throw "$Label not found: $Path"
  }
  return (Resolve-Path -LiteralPath $Path).Path
}

function Resolve-IPv4([string]$TargetHost) {
  $TargetHost = $TargetHost.Trim()
  if (-not $TargetHost) {
    throw "empty host"
  }
  $parsed = $null
  if ([System.Net.IPAddress]::TryParse($TargetHost, [ref]$parsed)) {
    $ip = $parsed
    if ($ip.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) {
      return $ip.ToString()
    }
    throw "host '$TargetHost' is not IPv4"
  }
  $addrs = [System.Net.Dns]::GetHostAddresses($TargetHost)
  foreach ($a in $addrs) {
    if ($a.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) {
      return $a.ToString()
    }
  }
  throw "no IPv4 address for '$TargetHost'"
}

function Wait-TcpPort([string]$TargetHost, [int]$Port, [int]$TimeoutSec) {
  $deadline = (Get-Date).AddSeconds($TimeoutSec)
  while ((Get-Date) -lt $deadline) {
    try {
      $client = New-Object System.Net.Sockets.TcpClient
      try {
        $iar = $client.BeginConnect($TargetHost, $Port, $null, $null)
        if ($iar.AsyncWaitHandle.WaitOne(700)) {
          $client.EndConnect($iar)
          return $true
        }
      } finally {
        $client.Close()
      }
    } catch {
      # ignore and retry
    }
    Start-Sleep -Milliseconds 200
  }
  return $false
}

function New-LogState([string]$Name, [string]$Path) {
  return @{
    Name = $Name
    Path = $Path
    Offset = 0L
    Pending = ""
  }
}

function Read-NewLogLines([hashtable]$State) {
  if (-not (Test-Path -LiteralPath $State.Path)) {
    return @()
  }

  $stream = $null
  $reader = $null
  $chunk = ""
  try {
    $stream = [System.IO.File]::Open($State.Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
    [void]$stream.Seek([long]$State.Offset, [System.IO.SeekOrigin]::Begin)
    $reader = New-Object System.IO.StreamReader($stream)
    $chunk = $reader.ReadToEnd()
    $State.Offset = [long]$stream.Position
  } catch {
    return @()
  } finally {
    if ($reader) {
      $reader.Dispose()
    } elseif ($stream) {
      $stream.Dispose()
    }
  }

  if ([string]::IsNullOrEmpty($chunk)) {
    return @()
  }

  $data = [string]$State.Pending + $chunk
  $parts = $data -split "\r?\n"
  if ($data -match "\r?\n$") {
    $State.Pending = ""
    if ($parts.Length -gt 0 -and $parts[-1] -eq "") {
      $parts = $parts[0..($parts.Length - 2)]
    }
  } else {
    if ($parts.Length -gt 0) {
      $State.Pending = $parts[-1]
      if ($parts.Length -gt 1) {
        $parts = $parts[0..($parts.Length - 2)]
      } else {
        $parts = @()
      }
    }
  }
  return $parts
}

function Emit-LogLines([hashtable]$State, [string[]]$Lines, [string]$CombinedLog) {
  foreach ($line in $Lines) {
    if ($line -eq "") { continue }
    $stamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss.fff")
    $out = "$stamp [$($State.Name)] $line"
    Write-Host $out
    Add-Content -LiteralPath $CombinedLog -Value $out
  }
}

function Stop-ProcessSafe($Process, [string]$Name) {
  if ($null -eq $Process) { return }
  try {
    if (-not $Process.HasExited) {
      Stop-Process -Id $Process.Id -Force -ErrorAction SilentlyContinue
      Start-Sleep -Milliseconds 150
    }
  } catch {
    Write-Warning "failed to stop ${Name}: $($_.Exception.Message)"
  }
}

function Parse-Listen([string]$ListenAddr) {
  $listenHost = "127.0.0.1"
  $port = 1080
  if ($ListenAddr.Contains(":")) {
    $parts = $ListenAddr.Split(":")
    $listenHost = ($parts[0]).Trim()
    $port = [int]($parts[-1])
  } else {
    $port = [int]$ListenAddr
  }
  return @{ Host = $listenHost; Port = $port }
}

$ScriptDir = $PSScriptRoot
if (-not $ScriptDir) {
  $ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
}
$Root = (Resolve-Path (Join-Path $ScriptDir "..")).Path
Push-Location $Root
$socksProc = $null
$singProc = $null
try {
  if (-not $EnvFile) {
    $EnvFile = Join-Path $ScriptDir ".env"
  }
  Import-DotEnv -Path $EnvFile

  if (-not $GatewayHost) {
    $GatewayHost = [Environment]::GetEnvironmentVariable("GATEWAY_HOST", "Process")
  }
  if (-not $GatewayHost) {
    throw "GatewayHost is required. Pass -GatewayHost or set GATEWAY_HOST."
  }
  if (-not $GatewayIP) {
    $GatewayIP = [Environment]::GetEnvironmentVariable("GATEWAY_IP", "Process")
  }
  if (-not $GatewayIP) {
    try {
      $GatewayIP = Resolve-IPv4 -TargetHost $GatewayHost
    } catch {
      Write-Warning "failed to resolve GatewayIP from '$GatewayHost': $($_.Exception.Message)"
    }
  }
  if (-not $TlsServerName) {
    $TlsServerName = [Environment]::GetEnvironmentVariable("VLF_TLS_SERVER_NAME", "Process")
  }
  if (-not $TlsServerName) {
    $TlsServerName = $GatewayHost
  }

  if ($GatewayPortUdp -le 0) {
    $val = [Environment]::GetEnvironmentVariable("GATEWAY_PORT_UDP", "Process")
    if (-not $val) { $val = [Environment]::GetEnvironmentVariable("GATEWAY_PORT", "Process") }
    if ($val) {
      $GatewayPortUdp = [int]$val
    } else {
      $GatewayPortUdp = 8443
    }
  }
  if ($GatewayPortTcp -le 0) {
    $val = [Environment]::GetEnvironmentVariable("GATEWAY_PORT_TCP", "Process")
    if (-not $val) { $val = [Environment]::GetEnvironmentVariable("GATEWAY_PORT", "Process") }
    if ($val) {
      $GatewayPortTcp = [int]$val
    } else {
      $GatewayPortTcp = 443
    }
  }

  if (-not $ClientID) {
    $ClientID = [Environment]::GetEnvironmentVariable("VLF_CLIENT", "Process")
    if (-not $ClientID) {
      $ClientID = [Environment]::GetEnvironmentVariable("VLF_CLIENT_ID", "Process")
    }
  }
  if (-not $ClientID) {
    $ClientID = "smoke-client"
  }
  if (-not $Secret) {
    $Secret = [Environment]::GetEnvironmentVariable("VLF_SECRET", "Process")
  }
  if (-not $Secret) {
    $Secret = "smoke-secret"
  }

  $envPin = [Environment]::GetEnvironmentVariable("VLF_PIN_SPKI", "Process")
  $effectivePin = $envPin
  if ($NoPin) {
    $effectivePin = ""
  } elseif ($PinSPKI -ne "") {
    $effectivePin = $PinSPKI.Trim()
  }
  [Environment]::SetEnvironmentVariable("VLF_PIN_SPKI", $effectivePin, "Process")
  if ($NoPin) {
    Write-Host "TLS pinning disabled for this run (-NoPin)."
  } elseif ($effectivePin) {
    Write-Host "TLS pinning enabled (VLF_PIN_SPKI set)."
    if ($effectivePin -eq "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=") {
      Write-Warning "VLF_PIN_SPKI is SHA256(empty) placeholder; it will fail unless server SPKI really matches it."
    }
  } else {
    Write-Host "TLS pinning disabled (empty VLF_PIN_SPKI)."
  }

  $socksExePath = Resolve-AbsPath -Path $SocksExe -Label "socks_client"
  $singBoxExePath = ""
  if (-not $NoSingBox) {
    $singBoxExePath = Resolve-AbsPath -Path $SingBoxExe -Label "sing-box"
    [void](Resolve-AbsPath -Path $SingBoxConfig -Label "sing-box config")
  }

  if ($Build) {
    if (-not (Get-Command go -ErrorAction SilentlyContinue)) {
      throw "go not found in PATH, cannot use -Build"
    }
    Write-Host "Building socks_client..."
    & go build -o $socksExePath .\cmd\socks_client
    if ($LASTEXITCODE -ne 0) {
      throw "go build socks_client failed with exit code $LASTEXITCODE"
    }
  }

  $runId = Get-Date -Format "yyyyMMdd_HHmmss"
  $runDir = Join-Path $LogsRoot $runId
  [void](New-Item -ItemType Directory -Path $runDir -Force)

  $socksStdOut = Join-Path $runDir "socks_client.stdout.log"
  $socksStdErr = Join-Path $runDir "socks_client.stderr.log"
  $singStdOut = Join-Path $runDir "sing_box.stdout.log"
  $singStdErr = Join-Path $runDir "sing_box.stderr.log"
  $combinedLog = Join-Path $runDir "combined.log"
  $metaPath = Join-Path $runDir "run.json"

  [void](New-Item -ItemType File -Path $socksStdOut -Force)
  [void](New-Item -ItemType File -Path $socksStdErr -Force)
  [void](New-Item -ItemType File -Path $combinedLog -Force)
  if (-not $NoSingBox) {
    [void](New-Item -ItemType File -Path $singStdOut -Force)
    [void](New-Item -ItemType File -Path $singStdErr -Force)
  }

  $socksArgs = @(
    "--listen", $Listen,
    "--server", $GatewayHost,
    "--port-udp", "$GatewayPortUdp",
    "--port-tcp", "$GatewayPortTcp",
    "--tls-server-name", $TlsServerName,
    "--mode", $Mode,
    "--stats-format", $StatsFormat,
    "--client-id", $ClientID,
    "--secret", $Secret,
    "--auth", $Auth
  )
  if ($GatewayIP) {
    $socksArgs += @("--server-ip", $GatewayIP)
  }
  if ($ResolveOnce) {
    $socksArgs += "--resolve-once=true"
  } else {
    $socksArgs += "--resolve-once=false"
  }
  if ($Auth -eq "userpass") {
    $socksArgs += @("--username", $Username, "--password", $Password)
  }
  if ($DisableQuic) { $socksArgs += "--disable-quic" }
  if ($DisableTcpSession) { $socksArgs += "--disable-tcp-session" }
  if ($DisableRelayFallback) { $socksArgs += "--allow-relay-fallback=false" }
  if ($ForceIPv4) { $socksArgs += "--force-ipv4=true" }
  if ($SessionDebug) { $socksArgs += "--debug" }
  if ($SocksExtraArgs) { $socksArgs += $SocksExtraArgs }

  $listenInfo = Parse-Listen -ListenAddr $Listen

  $meta = [ordered]@{
    started_at = (Get-Date).ToString("o")
    run_id = $runId
    run_dir = $runDir
    gateway = @{
      host = $GatewayHost
      ip = $GatewayIP
      tls_sni = $TlsServerName
      port_udp = $GatewayPortUdp
      port_tcp = $GatewayPortTcp
    }
    socks = @{
      exe = $socksExePath
      args = $socksArgs
      listen = $Listen
      stdout = $socksStdOut
      stderr = $socksStdErr
      pin_spki = if ($effectivePin) { $effectivePin } else { "" }
    }
    sing_box = @{
      enabled = (-not $NoSingBox)
      exe = $singBoxExePath
      config = $SingBoxConfig
      args = $SingBoxExtraArgs
      stdout = $singStdOut
      stderr = $singStdErr
    }
    combined_log = $combinedLog
  }

  Write-Host "Run dir: $runDir"
  Write-Host "Starting socks_client..."
  $socksProc = Start-Process -FilePath $socksExePath -ArgumentList $socksArgs -WorkingDirectory $Root -NoNewWindow -PassThru -RedirectStandardOutput $socksStdOut -RedirectStandardError $socksStdErr

  if (-not (Wait-TcpPort -TargetHost $listenInfo.Host -Port $listenInfo.Port -TimeoutSec $StartupTimeoutSec)) {
    Stop-ProcessSafe -Process $socksProc -Name "socks_client"
    throw "socks_client did not open $($listenInfo.Host):$($listenInfo.Port) within ${StartupTimeoutSec}s"
  }
  Write-Host "socks_client is listening on $($listenInfo.Host):$($listenInfo.Port)"

  if (-not $NoSingBox) {
    Write-Host "Starting sing-box..."
    $singArgs = @("run", "-c", $SingBoxConfig) + $SingBoxExtraArgs
    $singProc = Start-Process -FilePath $singBoxExePath -ArgumentList $singArgs -WorkingDirectory $Root -NoNewWindow -PassThru -RedirectStandardOutput $singStdOut -RedirectStandardError $singStdErr
    $meta.sing_box.args = $singArgs
  }

  $meta.socks.pid = $socksProc.Id
  if ($singProc) {
    $meta.sing_box.pid = $singProc.Id
  }
  $meta | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $metaPath

  $states = @(
    (New-LogState -Name "SOCKS-OUT" -Path $socksStdOut),
    (New-LogState -Name "SOCKS-ERR" -Path $socksStdErr)
  )
  if (-not $NoSingBox) {
    $states += (New-LogState -Name "SING-OUT" -Path $singStdOut)
    $states += (New-LogState -Name "SING-ERR" -Path $singStdErr)
  }

  $header = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff') [RUNNER] started. Press Ctrl+C to stop. Logs: $runDir"
  Write-Host $header
  Add-Content -LiteralPath $combinedLog -Value $header

  $exitReason = ""
  $loopStartedAt = Get-Date
  try {
    while ($true) {
      foreach ($state in $states) {
        $lines = Read-NewLogLines -State $state
        $arr = @($lines)
        if ($arr.Count -gt 0) {
          Emit-LogLines -State $state -Lines $arr -CombinedLog $combinedLog
        }
      }

      if ($socksProc.HasExited) {
        $exitReason = "socks_client exited (code=$($socksProc.ExitCode))"
        break
      }
      if ($singProc -and $singProc.HasExited) {
        $exitReason = "sing-box exited (code=$($singProc.ExitCode))"
        break
      }
      if ($RunSeconds -gt 0 -and ((Get-Date) - $loopStartedAt).TotalSeconds -ge $RunSeconds) {
        $exitReason = "run timeout reached (${RunSeconds}s)"
        break
      }
      Start-Sleep -Milliseconds $PollIntervalMs
    }
  } finally {
    foreach ($state in $states) {
      $tail = Read-NewLogLines -State $state
      $arr = @($tail)
      if ($arr.Count -gt 0) {
        Emit-LogLines -State $state -Lines $arr -CombinedLog $combinedLog
      }
      if ($state.Pending) {
        Emit-LogLines -State $state -Lines @($state.Pending) -CombinedLog $combinedLog
      }
    }
  }

  if (-not $exitReason) {
    $exitReason = "stopped"
  }

  $footer = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff') [RUNNER] stopping: $exitReason"
  Write-Host $footer
  Add-Content -LiteralPath $combinedLog -Value $footer

  Stop-ProcessSafe -Process $singProc -Name "sing-box"
  Stop-ProcessSafe -Process $socksProc -Name "socks_client"

  $meta.ended_at = (Get-Date).ToString("o")
  $meta.exit_reason = $exitReason
  $meta.socks.exit_code = if ($socksProc) { if ($socksProc.HasExited) { $socksProc.ExitCode } else { $null } } else { $null }
  $meta.sing_box.exit_code = if ($singProc) { if ($singProc.HasExited) { $singProc.ExitCode } else { $null } } else { $null }
  $meta | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $metaPath

  Write-Host "Done. Combined log: $combinedLog"
} catch {
  Write-Error $_
  exit 1
} finally {
  Stop-ProcessSafe -Process $singProc -Name "sing-box"
  Stop-ProcessSafe -Process $socksProc -Name "socks_client"
  Pop-Location
}
