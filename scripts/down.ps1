param(
  [string]$PodName = "otel-poc",
  [switch]$KillTails,   # also close any 'podman logs -f receiver' windows
  [switch]$Prune        # run 'podman system prune -f' after teardown
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

Write-Host "Tearing down '$PodName'..." -ForegroundColor Cyan

# Optionally kill tailing sessions (those separate PowerShell windows)
if ($KillTails.IsPresent) {
  Write-Host "Searching for tail sessions (podman logs -f receiver)..." -ForegroundColor Cyan
  try {
    $tails = Get-CimInstance Win32_Process | Where-Object {
      $_.CommandLine -match 'podman(\.exe)?\s+logs\s+-f\s+receiver'
    }
    if ($tails) {
      foreach ($p in $tails) {
        try {
          Stop-Process -Id $p.ProcessId -Force -ErrorAction Stop
          Write-Host "Killed tail PID $($p.ProcessId)." -ForegroundColor DarkYellow
        } catch {
          Write-Warning "Failed to kill tail PID $($p.ProcessId): $($_.Exception.Message)"
        }
      }
    } else {
      Write-Host "No tail sessions found." -ForegroundColor DarkGray
    }
  } catch {
    Write-Warning "Could not enumerate processes to kill tails: $($_.Exception.Message)"
  }
}

# Be extra-safe: stop/remove containers by name (in case pod removal fails)
foreach ($c in @("sender","receiver")) {
  try { podman stop $c | Out-Null } catch {}
  try { podman rm -f $c | Out-Null } catch {}
}

# Stop & remove the pod
try { podman pod stop $PodName | Out-Null } catch {}
try { podman pod rm   $PodName | Out-Null } catch {}

# Optional prune of unused resources
if ($Prune.IsPresent) {
  Write-Host "Pruning unused Podman resources..." -ForegroundColor Cyan
  try { podman system prune -f | Out-Null } catch {
    Write-Warning "Prune failed: $($_.Exception.Message)"
  }
}

Write-Host "Cleanup complete." -ForegroundColor Green

