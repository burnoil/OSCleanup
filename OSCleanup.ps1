<#
.SYNOPSIS
    Cleans up Windows OS junk and performs optional pre-flight checks
    to help prevent MSI / Click-to-Run install issues (e.g., 1603).

.DESCRIPTION
    - Must be run as Administrator.
    - Performs safe OS cleanup operations.
    - Optional pre-flight detection for:
        * Pending reboot
        * Installer busy (msiexec)
        * Office C2R busy (real installs, not background)
        * Installer service restart failures
    - Supports silent operation via -Silent
    - Logging to %ProgramData%\OSCleanup

.PARAMETER Aggressive
    Enables additional cleanup (WER queue, etc).

.PARAMETER SkipRecycleBin
    Skips clearing the Recycle Bin.

.PARAMETER SkipPreflight
    Runs cleanup only and bypasses all pre-flight checks.

.PARAMETER InstallerBusyMinutes
    How recent an msiexec must be (minutes) to count as busy. Default: 120.

.PARAMETER WhatIf
    Shows what would happen but makes no changes.

.PARAMETER Silent
    Suppresses all console output. Script still writes full logs.

.EXITCODES
    0  Success (or preflight skipped)
    1  General script error
    20 Pending reboot
    21 Installer busy
    22 Office C2R busy
    23 Installer service restart failure
#>

param(
    [switch]$Aggressive,
    [switch]$SkipRecycleBin,
    [switch]$SkipPreflight,
    [int]$InstallerBusyMinutes = 120,
    [switch]$WhatIf,
    [switch]$Silent
)

# ================================
# Logging Setup
# ================================
$script:LogRoot = Join-Path -Path $env:ProgramData -ChildPath "OSCleanup"
if (-not (Test-Path $script:LogRoot)) {
    New-Item -Path $script:LogRoot -ItemType Directory -Force | Out-Null
}
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$script:LogFile = Join-Path $script:LogRoot "OSCleanup_$timestamp.log"

function Write-Log {
    param(
        [Parameter(Mandatory)] [string]$Message,
        [ValidateSet("INFO","WARN","ERROR")] [string]$Level = "INFO"
    )

    $time = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = "[$time] [$Level] $Message"

    # No console output when -Silent is used
    if (-not $Silent) {
        Write-Host $line
    }

    Add-Content -Path $script:LogFile -Value $line
}

Write-Log "============================================================="
Write-Log "Starting OS Preflight Cleanup Script"
Write-Log "Parameters: Aggressive=$Aggressive SkipRecycleBin=$SkipRecycleBin SkipPreflight=$SkipPreflight InstallerBusyMinutes=$InstallerBusyMinutes WhatIf=$WhatIf Silent=$Silent"

# ================================
# Admin Check
# ================================
function Test-IsAdmin {
    $wid = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($wid)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-IsAdmin)) {
    if (-not $Silent) {
        Write-Host "ERROR: Script must be run as Administrator." -ForegroundColor Red
    }
    exit 1
}

# ================================
# Helpers
# ================================
function Format-Bytes {
    param([Int64]$Bytes)
    if ($Bytes -ge 1GB) { "{0:N2} GB" -f ($Bytes / 1GB) }
    elseif ($Bytes -ge 1MB) { "{0:N2} MB" -f ($Bytes / 1MB) }
    elseif ($Bytes -ge 1KB) { "{0:N2} KB" -f ($Bytes / 1KB) }
    else { "$Bytes B" }
}

function Get-SystemDriveFreeSpace {
    try {
        $root = $env:SystemDrive.TrimEnd('\')
        $driveLetter = $root.Substring(0,1)
        $drive = Get-PSDrive -Name $driveLetter -ErrorAction SilentlyContinue

        if ($drive) {
            return [int64]$drive.Free
        }

        $fallback = Get-WmiObject Win32_LogicalDisk -Filter "DeviceID='$root'" -ErrorAction SilentlyContinue
        if ($fallback) { return [int64]$fallback.FreeSpace }
    }
    catch {
        Write-Log "Get-SystemDriveFreeSpace failed: $_" "WARN"
    }
    return 0
}

$initialFree = Get-SystemDriveFreeSpace
Write-Log "Initial free space: $(Format-Bytes $initialFree)"

# ================================
# Safe Remove Wrapper
# ================================
function Remove-ItemSafe {
    param([Parameter(Mandatory)][string]$Path, [switch]$Recurse)

    if (-not (Test-Path $Path)) { Write-Log "Path not found: $Path" "INFO"; return }

    try {
        if ($WhatIf) {
            Write-Log "WhatIf: Would delete '$Path'"
        } else {
            Remove-Item -LiteralPath $Path -Recurse:$Recurse -Force -ErrorAction Stop
            Write-Log "Deleted: $Path"
        }
    }
    catch {
        Write-Log "Failed to delete '$Path': $_" "WARN"
    }
}

# ================================
# Pending Reboot Detection
# ================================
function Test-PendingReboot {
    $pending = $false

    if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending") {
        Write-Log "Pending reboot: CBS" "WARN"; $pending = $true
    }

    if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired") {
        Write-Log "Pending reboot: Windows Update" "WARN"; $pending = $true
    }

    # Log-only (Chrome updates)
    try {
        $value = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name PendingFileRenameOperations -ErrorAction SilentlyContinue
        if ($value) {
            Write-Log "PendingFileRenameOperations present (ignored)" "INFO"
        }
    } catch {}

    return $pending
}

# ================================
# Installer Busy Detection
# ================================
function Test-InstallerBusy {
    $busy = $false

    try {
        $procs = Get-CimInstance Win32_Process -Filter "Name='msiexec.exe'" -ErrorAction SilentlyContinue
        $now = Get-Date

        foreach ($p in $procs) {
            $cmd = $p.CommandLine
            $started = [Management.ManagementDateTimeConverter]::ToDateTime($p.CreationDate)
            $age = ($now - $started).TotalMinutes
            $recent = $age -le $InstallerBusyMinutes

            $installLike =
                ($cmd -match '/i' -or
                 $cmd -match '/x' -or
                 $cmd -match '/f' -or
                 $cmd -match '/update' -or
                 $cmd -match 'INSTALL' -or
                 $cmd -match 'UNINSTALL')

            if ($recent -and $installLike) {
                Write-Log "Installer busy: PID=$($p.ProcessId) Started=$started Cmd=$cmd" "WARN"
                $busy = $true
            } else {
                Write-Log "Ignoring msiexec PID $($p.ProcessId) (Recent=$recent InstallCmd=$installLike)" "INFO"
            }
        }
    } catch {
        Write-Log "Test-InstallerBusy failed: $_" "WARN"
    }

    # Installer\InProgress: log-only
    if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\InProgress") {
        Write-Log "Installer InProgress key present (ignored)" "INFO"
    }

    return $busy
}

# ================================
# Office C2R Busy Detection
# ================================
function Test-OfficeClickToRunBusy {
    $busy = $false

    try {
        $procs = Get-CimInstance Win32_Process -Filter "Name='setup.exe' OR Name='OfficeC2RClient.exe' OR Name='IntegratedOffice.exe'" -ErrorAction SilentlyContinue

        foreach ($p in $procs) {
            $cmd = $p.CommandLine
            if ($cmd -match "Office" -or $cmd -match "ClickToRun" -or $cmd -match "C2R") {
                Write-Log "Office C2R install/repair detected: PID=$($p.ProcessId) Cmd=$cmd" "WARN"
                $busy = $true
            } else {
                Write-Log "Ignoring process $($p.Name) PID $($p.ProcessId)" "INFO"
            }
        }
    } catch {
        Write-Log "Test-OfficeClickToRunBusy failed: $_" "WARN"
    }

    return $busy
}

# ================================
# Reset Services
# ================================
function Reset-InstallServices {
    Write-Log "Resetting installer-related services..."
    $error = $false

    foreach ($svcName in @("msiserver","ClickToRunSvc")) {
        try {
            $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
            if (-not $svc) { Write-Log "$svcName not present" "INFO"; continue }

            if ($svc.Status -eq "Running") {
                Write-Log "Restarting $svcName"
                if (-not $WhatIf) { Restart-Service $svcName -Force }
            } else {
                Write-Log "Starting $svcName"
                if (-not $WhatIf) { Start-Service $svcName }
            }
        }
        catch {
            Write-Log "Service reset failed for $svcName: $_" "WARN"
            $error = $true
        }
    }
    return $error
}

# ================================
# Cleanup Functions
# ================================
function Clear-TempFolders {
    Write-Log "Clearing temp folders..."
    $paths = @($env:TEMP, $env:TMP, "C:\Windows\Temp") | Where-Object { $_ -and (Test-Path $_) }
    foreach ($path in $paths) {
        Get-ChildItem $path -Force -ErrorAction SilentlyContinue | ForEach-Object {
            Remove-ItemSafe $_.FullName -Recurse
        }
    }
}

function Clear-UserProfileTempFolders {
    Write-Log "Clearing all user profile temp folders..."
    $profiles = Get-ChildItem "C:\Users" -Directory -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -notin "Public","Default","Default User","All Users" }

    foreach ($profile in $profiles) {
        $tempPath = Join-Path $profile.FullName "AppData\Local\Temp"
        if (Test-Path $tempPath) {
            Get-ChildItem $tempPath -Force -ErrorAction SilentlyContinue | ForEach-Object {
                Remove-ItemSafe $_.FullName -Recurse
            }
        }
    }
}

function Clear-WindowsUpdateCache {
    Write-Log "Clearing Windows Update cache..."
    $path = "C:\Windows\SoftwareDistribution\Download"

    $svcNames = @("wuauserv","bits")
    $stopped = @()

    foreach ($svc in $svcNames) {
        try {
            if ((Get-Service $svc -ErrorAction SilentlyContinue).Status -eq "Running") {
                Write-Log "Stopping $svc"
                if (-not $WhatIf) {
                    Stop-Service $svc -Force
                    $stopped += $svc
                }
            }
        } catch {}
    }

    if (Test-Path $path) {
        Get-ChildItem $path -Force -ErrorAction SilentlyContinue | ForEach-Object {
            Remove-ItemSafe $_.FullName -Recurse
        }
    }

    foreach ($svc in $stopped) {
        Write-Log "Restarting $svc"
        if (-not $WhatIf) { Start-Service $svc }
    }
}

function Clear-DeliveryOptimizationCache {
    Write-Log "Clearing Delivery Optimization cache..."
    $path = "C:\ProgramData\Microsoft\Windows\DeliveryOptimization\Cache"

    if (Test-Path $path) {
        Get-ChildItem $path -Force -ErrorAction SilentlyContinue | ForEach-Object {
            Remove-ItemSafe $_.FullName -Recurse
        }
    }
}

function Clear-OfficeClickToRunJunk {
    Write-Log "Clearing Office Click-to-Run logs and telemetry..."

    $paths = @(
        "C:\ProgramData\Microsoft\Office\ClickToRun\Log",
        "C:\ProgramData\Microsoft\Office\ClickToRun\Telemetry",
        "C:\ProgramData\Microsoft\ClickToRun\Log",
        "C:\ProgramData\Microsoft\ClickToRun\Telemetry",
        "C:\ProgramData\Microsoft\Office\ClickToRun\Logs",
        "C:\ProgramData\Microsoft\ClickToRun\Logs"
    )

    foreach ($path in $paths) {
        if (Test-Path $path) {
            Get-ChildItem $path -Force -ErrorAction SilentlyContinue | ForEach-Object {
                Remove-ItemSafe $_.FullName -Recurse
            }
        }
    }

    # Per-user Office cache
    $localBase = Join-Path $env:LOCALAPPDATA "Microsoft\Office\16.0"
    $subPaths = "OfficeFileCache","Wef","Telemetry","Lync\Tracing"

    foreach ($sub in $subPaths) {
        $full = Join-Path $localBase $sub
        if (Test-Path $full) {
            Get-ChildItem $full -Force -ErrorAction SilentlyContinue | ForEach-Object {
                Remove-ItemSafe $_.FullName -Recurse
            }
        }
    }
}

function Clear-OldSystemLogs {
    Write-Log "Clearing CBS/DISM/MoSetup logs..."
    $patterns = @(
        "C:\Windows\Logs\CBS\*.cab",
        "C:\Windows\Logs\CBS\CbsPersist_*.log",
        "C:\Windows\Logs\DISM\*.log.old",
        "C:\Windows\Logs\MoSetup\*.log"
    )
    foreach ($pattern in $patterns) {
        Get-ChildItem $pattern -Force -ErrorAction SilentlyContinue | ForEach-Object {
            Remove-ItemSafe $_.FullName
        }
    }
}

function Clear-WindowsInstallerLogs {
    Write-Log "Clearing Windows Installer logs/temp..."
    $root = "C:\Windows\Installer"
    if (Test-Path $root) {
        Get-ChildItem $root -Filter "*.log" -Force -ErrorAction SilentlyContinue | ForEach-Object {
            Remove-ItemSafe $_.FullName
        }
        Get-ChildItem $root -Filter "*.tmp" -Force -ErrorAction SilentlyContinue | ForEach-Object {
            Remove-ItemSafe $_.FullName
        }
    }
}

function Clear-RecycleBinSafe {
    if ($SkipRecycleBin) {
        Write-Log "Skipping Recycle Bin cleanup (SkipRecycleBin used)"
        return
    }

    Write-Log "Clearing Recycle Bin..."

    try {
        if ($WhatIf) {
            Write-Log "WhatIf: Would clear Recycle Bin"
        } else {
            Clear-RecycleBin -Force -ErrorAction SilentlyContinue
        }
    } catch {
        Write-Log "Recycle Bin cleanup failed: $_" "WARN"
    }
}

function Invoke-AggressiveCleanup {
    Write-Log "Running aggressive cleanup..."
    $wer = "C:\ProgramData\Microsoft\Windows\WER"
    if (Test-Path $wer) {
        Get-ChildItem $wer -Recurse -Force -ErrorAction SilentlyContinue | ForEach-Object {
            Remove-ItemSafe $_.FullName -Recurse
        }
    }
}

# ================================
# MAIN EXECUTION
# ================================
$exitCode = 0

if (-not $SkipPreflight) {

    if (Test-PendingReboot) {
        Write-Log "Pre-flight FAILED: Pending reboot" "WARN"
        $exitCode = 20
    }

    if (Test-InstallerBusy) {
        Write-Log "Pre-flight FAILED: Installer busy" "WARN"
        if ($exitCode -eq 0) { $exitCode = 21 }
    }

    if (Test-OfficeClickToRunBusy) {
        Write-Log "Pre-flight FAILED: Office C2R busy" "WARN"
        if ($exitCode -eq 0) { $exitCode = 22 }
    }

    if ($exitCode -eq 0) {
        $svcErrors = Reset-InstallServices
        if ($svcErrors) {
            Write-Log "Pre-flight FAILED: Service restart issue" "WARN"
            $exitCode = 23
        }
    }

    if ($exitCode -ne 0) {
        Write-Log "Pre-flight failed. ExitCode=$exitCode"
        Write-Log "============================================================="
        exit $exitCode
    }

    Write-Log "Pre-flight checks passed. Proceeding with cleanup..."
}
else {
    Write-Log "SkipPreflight used — performing cleanup only"
}

# ================================
# RUN CLEANUP
# ================================
try {
    Clear-TempFolders
    Clear-UserProfileTempFolders
    Clear-WindowsUpdateCache
    Clear-DeliveryOptimizationCache
    Clear-OfficeClickToRunJunk
    Clear-OldSystemLogs
    Clear-WindowsInstallerLogs
    Clear-RecycleBinSafe

    if ($Aggressive) {
        Invoke-AggressiveCleanup
    }
}
catch {
    Write-Log "Unexpected cleanup error: $_" "ERROR"
    if ($exitCode -eq 0) { $exitCode = 1 }
}

# ================================
# FINAL SPACE CALC
# ================================
$finalFree = Get-SystemDriveFreeSpace
$delta = $finalFree - $initialFree

if ($delta -lt 0) {
    Write-Log "SYSTEM CHURN: Free space decreased by $(Format-Bytes ([math]::Abs($delta))) during run. Reporting 0 B reclaimed." "INFO"
    $deltaShown = 0
}
else {
    $deltaShown = $delta
}

Write-Log "Final free space: $(Format-Bytes $finalFree)"
Write-Log "Space reclaimed: $(Format-Bytes $deltaShown)"
Write-Log "ExitCode: $exitCode"
Write-Log "Log file: $script:LogFile"
Write-Log "============================================================="

if (-not $Silent) {
    Write-Host ""
    Write-Host "Cleanup complete." -ForegroundColor Cyan
    Write-Host "Reclaimed: $(Format-Bytes $deltaShown)" -ForegroundColor Cyan
    Write-Host "Log file: $script:LogFile" -ForegroundColor DarkGray
}

exit $exitCode
