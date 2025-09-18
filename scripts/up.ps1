param(
  [string]$PodName = "otel-poc",
  [switch]$Tail
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

# ------------------ helpers ------------------
function Run-Podman {
  param([Parameter(Mandatory=$true)][string[]]$Args)
  # Podman prints progress to STDERR; don't let PS treat it as fatal.
  $oldEap = $ErrorActionPreference
  try {
    $ErrorActionPreference = "Continue"
    $output = & podman @Args 2>&1
    $code = $LASTEXITCODE
  } finally {
    $ErrorActionPreference = $oldEap
  }
  if ($code -ne 0) { throw "podman $($Args -join ' ') failed ($code):`n$output" }
  return $output
}

function Test-PodmanWorks {
  $oldEap = $ErrorActionPreference
  try {
    $ErrorActionPreference = "Continue"
    & podman info 1>$null 2>$null
    return ($LASTEXITCODE -eq 0)
  } finally { $ErrorActionPreference = $oldEap }
}

function Machine-Exists {
  param([string]$Name)
  $txt = ((& podman machine list 2>$null) | Out-String)
  return ($txt -match [regex]::Escape($Name))
}

function Ensure-PodmanMachine {
  $name = "podman-machine-default"
  if (Test-PodmanWorks) { Write-Host "Podman is reachable." -ForegroundColor DarkGray; return }
  if (-not (Machine-Exists -Name $name)) {
    Write-Host "Initializing Podman machine ($name)..." -ForegroundColor Cyan
    Run-Podman @("machine","init",$name) | Out-Null
  }
  Write-Host "Starting Podman machine ($name)..." -ForegroundColor Cyan
  $null = (& podman machine start $name 2>&1)   # don't explode if already running
  if (-not (Test-PodmanWorks)) { throw "Podman still unreachable after machine start." }
}

function Get-Status {
  param([string]$Name)
  $oldEap = $ErrorActionPreference
  try {
    $ErrorActionPreference = "Continue"
    $out = & podman ps -a --filter "name=$Name" --format "{{.Status}}"
    if ($LASTEXITCODE -ne 0) { return "" }
    return ($out -join "`n").Trim()
  } finally { $ErrorActionPreference = $oldEap }
}

function Wait-Running {
  param([string]$Name,[int]$Tries=40)
  for ($i=0; $i -lt $Tries; $i++) {
    $st = Get-Status -Name $Name
    if ($st -match "^Up") { return $true }
    Start-Sleep -Milliseconds 250
  }
  return $false
}

# Robust, non-throwing volume check
function Ensure-Volume {
  param([string]$Name)
  $oldEap = $ErrorActionPreference
  try {
    $ErrorActionPreference = "Continue"
    $list = (& podman volume ls --format "{{.Name}}" 2>$null) -split "[\r\n]+" | Where-Object { $_ -ne "" }
  } finally { $ErrorActionPreference = $oldEap }
  if ($list -notcontains $Name) {
    Write-Host "Creating volume $Name ..." -ForegroundColor Cyan
    Run-Podman @("volume","create",$Name) | Out-Null
  }
}

# Pull images up-front; retry insecure if corp TLS MITM blocks Docker Hub (PoC only).
function Ensure-Image {
  param([Parameter(Mandatory=$true)][string]$Ref)
  $oldEap = $ErrorActionPreference
  try {
    $ErrorActionPreference = "Continue"
    & podman image exists $Ref
    if ($LASTEXITCODE -eq 0) {
      Write-Host "Image present: $Ref" -ForegroundColor DarkGray
      return
    }
  } finally { $ErrorActionPreference = $oldEap }

  Write-Host "Pulling image: $Ref" -ForegroundColor Cyan
  try {
    Run-Podman @("pull",$Ref) | Out-Null
  } catch {
    Write-Warning "Pull failed (likely corporate TLS). Retrying insecure (PoC only): $Ref"
    Run-Podman @("pull","--tls-verify=false",$Ref) | Out-Null
  }
}

function Preload-Volume-File {
  param(
    [string]$VolName,
    [string]$ContainerPath,  # e.g. /mnt/config.alloy or /mnt/app.log
    [string]$HostFile
  )
  & podman rm -f "dataprep-$VolName" 1>$null 2>$null
  Run-Podman @(
    "run","-d","--name","dataprep-$VolName",
    "--mount",("type=volume,source=$VolName,target=/mnt"),
    "docker.io/library/busybox:latest",
    "sleep","600"
  ) | Out-Null

  Run-Podman @("exec","dataprep-$VolName","sh","-lc","mkdir -p /mnt")
  # Safe "container:path" (avoid $var:scope parsing)
  Run-Podman @("cp", $HostFile, ("dataprep-$($VolName):$ContainerPath"))

  & podman stop "dataprep-$VolName" 1>$null 2>$null
  & podman rm   "dataprep-$VolName" 1>$null 2>$null
}

# Open a tail in a new window if possible; otherwise tail in the current terminal.
function Open-Tail {
  param([string]$Container="receiver")
  $tailCmd = "podman logs -f $Container"
  try {
    $pwsh = (Get-Command pwsh -ErrorAction SilentlyContinue).Path
    if ($pwsh) {
      Start-Process -FilePath $pwsh -ArgumentList @("-NoExit","-Command",$tailCmd) -WindowStyle Normal -ErrorAction Stop
      return
    }
    $classic = Join-Path $env:WINDIR "System32\WindowsPowerShell\v1.0\powershell.exe"
    Start-Process -FilePath $classic -ArgumentList @("-NoExit","-Command",$tailCmd) -WindowStyle Normal -ErrorAction Stop
    return
  } catch {
    Write-Warning "Couldn't open a new window for tail ($($_.Exception.Message)). Tailing here instead. Press Ctrl+C to stop."
    & podman logs -f $Container
  }
}
# ------------------------------------------------

Ensure-PodmanMachine

# --- Paths ---
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$root      = Split-Path -Parent $scriptDir

$senderCf  = Join-Path $root "alloy\sender.river"
$recvCf    = Join-Path $root "alloy\receiver.river"
$logsDir   = Join-Path $root "logs"
$sample    = Join-Path $logsDir "audit_sample.log"

# --- Sanity ---
if (-not (Test-Path $senderCf)) { throw "Missing config: $senderCf" }
if (-not (Test-Path $recvCf))   { throw "Missing config: $recvCf" }
if (-not (Test-Path $logsDir))  { New-Item -ItemType Directory -Path $logsDir | Out-Null }
if (-not (Test-Path $sample)) {
  "$(Get-Date -Format s) level=INFO msg='bootstrap line from up.ps1'" | Out-File -Encoding utf8 $sample
}

Write-Host "Using project root: $root" -ForegroundColor Cyan
Write-Host "Sender config:       $senderCf" -ForegroundColor Cyan
Write-Host "Receiver config:     $recvCf"   -ForegroundColor Cyan
Write-Host "Sample log:          $sample"   -ForegroundColor Cyan

# --- Reset pod ---
Write-Host "Resetting pod $PodName (if exists)..." -ForegroundColor Cyan
& podman pod rm -f $PodName 1>$null 2>$null
Write-Host "Creating pod $PodName (ports 4317/4318)..." -ForegroundColor Cyan
Run-Podman @("pod","create","--name",$PodName,"-p","4317:4317","-p","4318:4318","-p","12345:12345","-p","12346:12346") | Out-Null

# --- Images (pre-pull; tolerate corp TLS via insecure fallback for PoC) ---
Ensure-Image "docker.io/library/busybox:latest"
Ensure-Image "docker.io/grafana/alloy:latest"

# --- Named volumes (no Windows bind mounts) ---
$dataVol     = "otlp-data"
$cfgRecvVol  = "otlp-cfg-receiver"
$cfgSendVol  = "otlp-cfg-sender"

Ensure-Volume -Name $dataVol
Ensure-Volume -Name $cfgRecvVol
Ensure-Volume -Name $cfgSendVol

# Preload volumes with config + data (use .alloy for config file name)
Write-Host "Preloading config & data volumes..." -ForegroundColor Cyan
Preload-Volume-File -VolName $cfgRecvVol -ContainerPath "/mnt/config.alloy" -HostFile $recvCf
Preload-Volume-File -VolName $cfgSendVol -ContainerPath "/mnt/config.alloy" -HostFile $senderCf
Preload-Volume-File -VolName $dataVol    -ContainerPath "/mnt/app.log"      -HostFile $sample

# ---------------------------
# Receiver: mount cfg volume at /etc/alloy and run with path arg
# ---------------------------
Write-Host "Starting receiver..." -ForegroundColor Cyan
& podman rm -f receiver 1>$null 2>$null
Run-Podman @(
  "run","-d","--pod",$PodName,"--name","receiver",
  "--mount",("type=volume,source=$cfgRecvVol,target=/etc/alloy"),
  "docker.io/grafana/alloy:latest",
  "run","--stability.level=experimental",
  "--server.http.listen-addr=0.0.0.0:12345",
  "/etc/alloy/config.alloy"
) | Out-Null
if (-not (Wait-Running -Name "receiver")) {
  Write-Warning "Receiver did not reach 'Up' state. Recent logs:"
  & podman logs --since 2m receiver
  throw "Receiver failed to start."
}

# ---------------------------
# Sender: mount cfg volume at /etc/alloy AND data volume at /data
# ---------------------------
Write-Host "Starting sender..." -ForegroundColor Cyan
& podman rm -f sender 1>$null 2>$null
Run-Podman @(
  "run","-d","--pod",$PodName,"--name","sender",
  "--mount",("type=volume,source=$cfgSendVol,target=/etc/alloy"),
  "--mount",("type=volume,source=$dataVol,target=/data"),
  "docker.io/grafana/alloy:latest",
  "run","--stability.level=experimental",
  "--server.http.listen-addr=0.0.0.0:12346",
  "/etc/alloy/config.alloy"
) | Out-Null
if (-not (Wait-Running -Name "sender")) {
  Write-Warning "Sender did not reach 'Up' state. Recent logs:"
  & podman logs --since 2m sender
  throw "Sender failed to start."
}

# Optionally launch a tail window (resilient)
if ($Tail.IsPresent) {
  Write-Host "Opening live tail window (receiver)..." -ForegroundColor Cyan
  Open-Tail -Container "receiver"
}


# Final hints
Write-Host ""
Write-Host "All set." -ForegroundColor Green
Write-Host "Check containers:  podman ps --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}'" -ForegroundColor Yellow
Write-Host "Tail here (optional): podman logs -f receiver" -ForegroundColor Yellow
Write-Host ""
Write-Host 'If nothing shows, append & re-sync data volume:' -ForegroundColor DarkGray
Write-Host '  Add-Content .\logs\audit_sample.log "$(Get-Date -Format s) level=INFO msg=''ping''"' -ForegroundColor DarkGray
Write-Host "  podman run --rm --name vrefresh --mount type=volume,source=$dataVol,target=/mnt docker.io/library/busybox:latest sh -lc 'cp /mnt/app.log /mnt/app.log'" -ForegroundColor DarkGray
