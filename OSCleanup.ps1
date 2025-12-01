<#
.SYNOPSIS
    Cleans up common Windows OS junk and checks system state to help prevent MSI / Click-to-Run install issues (e.g., 1603).

.DESCRIPTION
    - Must be run as Administrator.
    - Does NOT attempt to fix corruption; focuses on state sanity and safe junk cleanup.
    - Pre-flight checks (with exit codes):
        * Pending reboot detection (CBS / Windows Update only)
        * Windows Installer busy (msiexec / InProgress key)
        * Office Click-to-Run busy
        * Installer service restart issues
    - Cleanup:
        * User & system temp folders
        * All user profile temp folders (C:\Users\*\AppData\Local\Temp)
        * Windows Update download cache
        * Delivery Optimization cache
        * Office Click-to-Run logs/telemetry/cache (non-destructive; no binaries)
        * Old CBS/DISM/MoSetup logs & CAB files
        * Windows Installer logs/temp files (NOT the MSI/MSP cache)
        * Recycle Bin (optional)
        * Optional aggressive WER queue cleanup
    - Logs all actions to %ProgramData%\OSCleanup\OSCleanup_yyyyMMdd_HHmmss.log

.PARAMETER Aggressive
    Enables extra cleanup (currently Windows Error Reporting queue).

.PARAMETER SkipRecycleBin
    Skips clearing the Recycle Bin.

.PARAMETER WhatIf
    Shows what would be deleted / restarted without actually doing it.

.EXIT CODES
    0  = Success; pre-flight OK; cleanup completed.
    1  = General script error.
    20 = Pending reboot detected (CBS or Windows Update).
    21 = Windows Installer busy (msiexec or InProgress key).
    22 = Office Click-to-Run installation/maintenance busy.
    23 = Installer services failed to restart/start cleanly.

.EXAMPLE
    .\Invoke-OSPreflightCleanup.ps1 -Aggressive

.EXAMPLE
    .\Invoke-OSPreflightCleanup.ps1 -SkipRecycleBin

.EXAMPLE
    .\Invoke-OSPreflightCleanup.ps1 -WhatIf
#>

param(
    [switch]$Aggressive,
    [switch]$SkipRecycleBin,
    [switch]$WhatIf
)

# ================================
#  Logging Setup
# ================================
$script:LogRoot = Join-Path -Path $env:ProgramData -ChildPath "OSCleanup"
if (-not (Test-Path $script:LogRoot)) {
    New-Item -Path $script:LogRoot -ItemType Directory -Force | Out-Null
}
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$script:LogFile = Join-Path $script:LogRoot "OSCleanup_$timestamp.log"

function Write-Log {
    param(
        [Parameter(Mandatory)]
        [string]$Message,
        [ValidateSet("INFO","WARN","ERROR")]
        [string]$Level = "INFO"
    )
    $time = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = "[$time] [$Level] $Message"
    Write-Host $line
    Add-Content -Path $script:LogFile -Value $line
}

Write-Log "============================================================="
Write-Log "Starting OS pre-flight + cleanup script"
Write-Log "Parameters: Aggressive=$Aggressive; SkipRecycleBin=$SkipRecycleBin; WhatIf=$WhatIf"

# ================================
#  Admin Check
# ================================
function Test-IsAdmin {
    $currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentIdentity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-IsAdmin)) {
    Write-Host "This script must be run as Administrator." -ForegroundColor Red
    Write-Host "Right-click PowerShell and select 'Run as administrator', then run this script again."
    exit 1
}

# ================================
#  Helper: Size / Free Space
# ================================
function Format-Bytes {
    param(
        [Parameter(Mandatory)]
        [Int64]$Bytes
    )
    if ($Bytes -ge 1GB) {
        return ("{0:N2} GB" -f ($Bytes / 1GB))
    } elseif ($Bytes -ge 1MB) {
        return ("{0:N2} MB" -f ($Bytes / 1MB))
    } elseif ($Bytes -ge 1KB) {
        return ("{0:N2} KB" -f ($Bytes / 1KB))
    } else {
        return "$Bytes B"
    }
}

function Get-SystemDriveFreeSpace {
    try {
        $root = $env:SystemDrive  # e.g. 'C:'
        if (-not $root) {
            Write-Log "SystemDrive environment variable not found; defaulting to C:" "WARN"
            $root = "C:"
        }
        $root = $root.TrimEnd('\')

        $driveLetter = $root.Substring(0,1)  # 'C'
        $drive = Get-PSDrive -Name $driveLetter -ErrorAction SilentlyContinue

        if ($drive) {
            return [int64]$drive.Free
        } else {
            # Fallback via WMI
            $sys = Get-WmiObject Win32_LogicalDisk -Filter "DeviceID='$root'" -ErrorAction SilentlyContinue
            if ($sys) {
                return [int64]$sys.FreeSpace
            }
        }
    } catch {
        Write-Log "Failed to get system drive free space. $_" "WARN"
    }
    return 0
}

$initialFree = Get-SystemDriveFreeSpace
Write-Log "Initial free space on system drive ($env:SystemDrive): $(Format-Bytes $initialFree)"

# ================================
#  Helper: Safe Delete Wrapper
# ================================
function Remove-ItemSafe {
    param(
        [Parameter(Mandatory)]
        [string]$Path,
        [switch]$Recurse
    )

    if (-not (Test-Path $Path)) {
        Write-Log "Path not found: $Path" "WARN"
        return
    }

    try {
        if ($WhatIf) {
            Write-Log "WhatIf: Would delete '$Path' (Recurse=$Recurse)"
        } else {
            Remove-Item -LiteralPath $Path -Recurse:$Recurse -Force -ErrorAction Stop
            Write-Log "Deleted '$Path'"
        }
    } catch {
        Write-Log "Failed to delete '$Path'. $_" "WARN"
    }
}

# ================================
#  Check: Pending Reboot (CBS / WU only)
# ================================
function Test-PendingReboot {
    $pending = $false

    # CBS reboot pending
    if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending") {
        Write-Log "Pending reboot detected: Component Based Servicing" "WARN"
        $pending = $true
    }

    # Windows Update reboot pending
    if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired") {
        Write-Log "Pending reboot detected: Windows Update" "WARN"
        $pending = $true
    }

    # PendingFileRenameOperations is common (Chrome, etc.) -> LOG ONLY, DO NOT TRIP EXIT CODE
    try {
        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager"
        $value = Get-ItemProperty -Path $regPath -Name "PendingFileRenameOperations" -ErrorAction SilentlyContinue
        if ($value -and $value.PendingFileRenameOperations) {
            Write-Log "PendingFileRenameOperations present (common for app updates; not treated as a hard reboot block)." "INFO"
        }
    } catch {
        Write-Log "Error checking PendingFileRenameOperations. $_" "WARN"
    }

    return $pending
}

# ================================
#  Check: Installer Busy
# ================================
function Test-InstallerBusy {
    $busy = $false

    # Check for active msiexec.exe processes
    try {
        $msi = Get-Process -Name "msiexec" -ErrorAction SilentlyContinue
        if ($msi) {
            Write-Log "Windows Installer busy: msiexec.exe running (Count: $($msi.Count))" "WARN"
            $busy = $true
        }
    } catch {
        Write-Log "Error checking msiexec.exe. $_" "WARN"
    }

    # Check Installer\InProgress key
    try {
        $key = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\InProgress"
        if (Test-Path $key) {
            Write-Log "Installer 'InProgress' key exists — another installation is in progress or stuck." "WARN"
            $busy = $true
        }
    } catch {
        Write-Log "Error checking installer state. $_" "WARN"
    }

    return $busy
}

# ================================
#  Check: Office Click-to-Run Busy
# ================================
function Test-OfficeClickToRunBusy {
    $busy = $false

    $c2rProcesses = @(
        "OfficeClickToRun",
        "OfficeC2RClient",
        "IntegratedOffice",
        "setup"
    )

    foreach ($name in $c2rProcesses) {
        try {
            $p = Get-Process -Name $name -ErrorAction SilentlyContinue
            if ($p) {
                Write-Log "Office Click-to-Run activity detected: $name (Count: $($p.Count))" "WARN"
                $busy = $true
            }
        } catch {
            # ignore individual process lookup failures
        }
    }

    return $busy
}

# ================================
#  Reset: Installer-related Services
# ================================
function Reset-InstallServices {
    Write-Log "----- Resetting Installer-related services -----"
    $errorDuringRestart = $false

    $services = @(
        "msiserver",      # Windows Installer
        "ClickToRunSvc"   # Office C2R (if present)
    )

    foreach ($svcName in $services) {
        try {
            $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
            if (-not $svc) {
                Write-Log "Service '$svcName' not present (OK)" "INFO"
                continue
            }

            if ($svc.Status -eq "Running") {
                Write-Log "Restarting service '$svcName'"
                if (-not $WhatIf) {
                    Restart-Service -Name $svcName -Force -ErrorAction Stop
                } else {
                    Write-Log "WhatIf: Would restart service '$svcName'"
                }
            } else {
                Write-Log "Starting service '$svcName' (current state: $($svc.Status))"
                if (-not $WhatIf) {
                    Start-Service -Name $svcName -ErrorAction Stop
                } else {
                    Write-Log "WhatIf: Would start service '$svcName'"
                }
            }
        } catch {
            Write-Log "Failed to restart/start '$svcName'. $_" "WARN"
            $errorDuringRestart = $true
        }
    }

    return $errorDuringRestart
}

# ================================
#  Cleanup: Temp Folders (current user + system)
# ================================
function Clear-TempFolders {
    Write-Log "----- Clearing temp folders (current user + system) -----"

    $paths = @()

    # Current user temp
    if ($env:TEMP) { $paths += $env:TEMP }
    if ($env:TMP)  { $paths += $env:TMP }

    # System temp
    $paths += "C:\Windows\Temp"

    # Unique, existing paths only
    $paths = $paths | Where-Object { $_ -and (Test-Path $_) } | Select-Object -Unique

    foreach ($path in $paths) {
        Write-Log "Cleaning temp path: $path"
        try {
            $items = Get-ChildItem -Path $path -Force -ErrorAction SilentlyContinue
            foreach ($item in $items) {
                Remove-ItemSafe -Path $item.FullName -Recurse
            }
        } catch {
            Write-Log "Error while cleaning temp path '$path'. $_" "WARN"
        }
    }
}

# ================================
#  Cleanup: All User Profile Temp Folders
# ================================
function Clear-UserProfileTempFolders {
    Write-Log "----- Clearing temp folders for all user profiles -----"

    $profileRoot = "C:\Users"
    if (-not (Test-Path $profileRoot)) {
        Write-Log "Profile root '$profileRoot' not found; skipping user profile temp cleanup." "WARN"
        return
    }

    $excludeNames = @(
        "Public",
        "Default",
        "Default User",
        "All Users"
    )

    $profiles = Get-ChildItem -Path $profileRoot -Directory -ErrorAction SilentlyContinue |
        Where-Object { $excludeNames -notcontains $_.Name }

    foreach ($profile in $profiles) {
        $tempPath = Join-Path $profile.FullName "AppData\Local\Temp"
        if (Test-Path $tempPath) {
            Write-Log "Cleaning profile temp path: $tempPath"
            try {
                $items = Get-ChildItem -Path $tempPath -Force -ErrorAction SilentlyContinue
                foreach ($item in $items) {
                    Remove-ItemSafe -Path $item.FullName -Recurse
                }
            } catch {
                Write-Log "Error while cleaning '$tempPath'. $_" "WARN"
            }
        } else {
            Write-Log "Profile temp path not found: $tempPath" "INFO"
        }
    }
}

# ================================
#  Cleanup: Windows Update Cache
# ================================
function Clear-WindowsUpdateCache {
    Write-Log "----- Clearing Windows Update download cache -----"

    $wuDownload = "C:\Windows\SoftwareDistribution\Download"
    if (-not (Test-Path $wuDownload)) {
        Write-Log "Windows Update download folder not found at '$wuDownload'." "WARN"
        return
    }

    $serviceNames = @("wuauserv","bits")
    $stoppedServices = @()

    foreach ($svcName in $serviceNames) {
        $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
        if ($svc -and $svc.Status -eq 'Running') {
            if ($WhatIf) {
                Write-Log "WhatIf: Would stop service '$svcName'"
            } else {
                try {
                    Write-Log "Stopping service '$svcName'"
                    Stop-Service -Name $svcName -Force -ErrorAction Stop
                    $stoppedServices += $svcName
                } catch {
                    Write-Log "Failed to stop service '$svcName'. $_" "WARN"
                }
            }
        }
    }

    try {
        Write-Log "Cleaning '$wuDownload'"
        $items = Get-ChildItem -Path $wuDownload -Force -ErrorAction SilentlyContinue
        foreach ($item in $items) {
            Remove-ItemSafe -Path $item.FullName -Recurse
        }
    } catch {
        Write-Log "Error while cleaning Windows Update cache. $_" "WARN"
    }

    foreach ($svcName in $stoppedServices) {
        if ($WhatIf) {
            Write-Log "WhatIf: Would restart service '$svcName'"
        } else {
            try {
                Write-Log "Restarting service '$svcName'"
                Start-Service -Name $svcName -ErrorAction Stop
            } catch {
                Write-Log "Failed to restart service '$svcName'. $_" "WARN"
            }
        }
    }
}

# ================================
#  Cleanup: Delivery Optimization Cache
# ================================
function Clear-DeliveryOptimizationCache {
    Write-Log "----- Clearing Delivery Optimization cache -----"

    $doCache = "C:\ProgramData\Microsoft\Windows\DeliveryOptimization\Cache"
    if (-not (Test-Path $doCache)) {
        Write-Log "Delivery Optimization cache not found at '$doCache'." "INFO"
        return
    }

    $svcName = "DoSvc"
    $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
    $stopped = $false

    if ($svc -and $svc.Status -eq 'Running') {
        if ($WhatIf) {
            Write-Log "WhatIf: Would stop service '$svcName'"
        } else {
            try {
                Write-Log "Stopping service '$svcName'"
                Stop-Service -Name $svcName -Force -ErrorAction Stop
                $stopped = $true
            } catch {
                Write-Log "Failed to stop service '$svcName'. $_" "WARN"
            }
        }
    }

    try {
        Write-Log "Cleaning '$doCache'"
        $items = Get-ChildItem -Path $doCache -Force -ErrorAction SilentlyContinue
        foreach ($item in $items) {
            Remove-ItemSafe -Path $item.FullName -Recurse
        }
    } catch {
        Write-Log "Error while cleaning Delivery Optimization cache. $_" "WARN"
    }

    if ($stopped) {
        if ($WhatIf) {
            Write-Log "WhatIf: Would restart service '$svcName'"
        } else {
            try {
                Write-Log "Restarting service '$svcName'"
                Start-Service -Name $svcName -ErrorAction Stop
            } catch {
                Write-Log "Failed to restart service '$svcName'. $_" "WARN"
            }
        }
    }
}

# ================================
#  Cleanup: Office Click-to-Run Logs / Telemetry / Cache
# ================================
function Clear-OfficeClickToRunJunk {
    Write-Log "----- Clearing Office Click-to-Run logs/telemetry/cache (safe) -----"

    # ProgramData-level C2R logging/telemetry
    $programDataPaths = @(
        "C:\ProgramData\Microsoft\Office\ClickToRun\Log",
        "C:\ProgramData\Microsoft\Office\ClickToRun\Telemetry",
        "C:\ProgramData\Microsoft\ClickToRun\Log",
        "C:\ProgramData\Microsoft\ClickToRun\Telemetry",
        "C:\ProgramData\Microsoft\Office\ClickToRun\Logs",
        "C:\ProgramData\Microsoft\ClickToRun\Logs"
    )

    foreach ($path in $programDataPaths) {
        if (Test-Path $path) {
            Write-Log "Cleaning ClickToRun path: $path"
            try {
                $items = Get-ChildItem -Path $path -Force -ErrorAction SilentlyContinue
                foreach ($item in $items) {
                    Remove-ItemSafe -Path $item.FullName -Recurse
                }
            } catch {
                Write-Log "Error while cleaning '$path'. $_" "WARN"
            }
        } else {
            Write-Log "ClickToRun path not found: $path" "INFO"
        }
    }

    # Per-user Office cache/logging for Click-to-Run (16.0 covers Office 2016–2021 + M365)
    $localBase = Join-Path $env:LOCALAPPDATA "Microsoft\Office"
    if (Test-Path $localBase) {
        $localSubPaths = @(
            "16.0\OfficeFileCache",
            "16.0\Wef",
            "16.0\Telemetry",
            "16.0\Lync\Tracing"
        )

        foreach ($sub in $localSubPaths) {
            $full = Join-Path $localBase $sub
            if (Test-Path $full) {
                Write-Log "Cleaning per-user Office cache path: $full"
                try {
                    $items = Get-ChildItem -Path $full -Force -ErrorAction SilentlyContinue
                    foreach ($item in $items) {
                        Remove-ItemSafe -Path $item.FullName -Recurse
                    }
                } catch {
                    Write-Log "Error while cleaning '$full'. $_" "WARN"
                }
            } else {
                Write-Log "Per-user Office cache path not found: $full" "INFO"
            }
        }
    } else {
        Write-Log "Per-user Office base folder not found at '$localBase'." "INFO"
    }
}

# ================================
#  Cleanup: Old System Logs (CBS / DISM / MoSetup / Temp CAB)
# ================================
function Clear-OldSystemLogs {
    Write-Log "----- Clearing old CBS/DISM/MoSetup logs and CABs -----"

    $patterns = @(
        "C:\Windows\Logs\CBS\*.cab",
        "C:\Windows\Logs\CBS\CbsPersist_*.log",
        "C:\Windows\Logs\DISM\*.log.old",
        "C:\Windows\Logs\DISM\*.bak",
        "C:\Windows\Temp\*.log",
        "C:\Windows\Temp\*.cab",
        "C:\Windows\Logs\MoSetup\*.log"
    )

    foreach ($pattern in $patterns) {
        try {
            $files = Get-ChildItem -Path $pattern -Force -ErrorAction SilentlyContinue
            foreach ($file in $files) {
                Remove-ItemSafe -Path $file.FullName
            }
        } catch {
            Write-Log "Error while cleaning files matching '$pattern'. $_" "WARN"
        }
    }
}

# ================================
#  Cleanup: Windows Installer Logs / Temp (not MSI/MSP cache)
# ================================
function Clear-WindowsInstallerLogs {
    Write-Log "----- Clearing Windows Installer logs/temp files (not MSI/MSP cache) -----"

    $installerRoot = "C:\Windows\Installer"
    if (-not (Test-Path $installerRoot)) {
        Write-Log "Windows Installer folder not found at '$installerRoot'." "WARN"
        return
    }

    $patterns = @(
        "*.log",
        "*.tmp"
    )

    foreach ($pattern in $patterns) {
        try {
            $files = Get-ChildItem -Path $installerRoot -Filter $pattern -File -Force -ErrorAction SilentlyContinue
            foreach ($file in $files) {
                Remove-ItemSafe -Path $file.FullName
            }
        } catch {
            Write-Log "Error while cleaning Windows Installer files '$pattern'. $_" "WARN"
        }
    }
}

# ================================
#  Cleanup: Recycle Bin
# ================================
function Clear-RecycleBinSafe {
    Write-Log "----- Clearing Recycle Bin -----"

    if ($SkipRecycleBin) {
        Write-Log "SkipRecycleBin is set; skipping Recycle Bin cleanup."
        return
    }

    try {
        if ($WhatIf) {
            Write-Log "WhatIf: Would clear Recycle Bin."
        } else {
            Clear-RecycleBin -Force -ErrorAction SilentlyContinue
            Write-Log "Recycle Bin cleared."
        }
    } catch {
        Write-Log "Failed to clear Recycle Bin. $_" "WARN"
    }
}

# ================================
#  Aggressive Cleanup (Optional)
# ================================
function Invoke-AggressiveCleanup {
    Write-Log "----- Running Aggressive Cleanup -----"

    # Windows Error Reporting (WER) queue
    $werRoot = "C:\ProgramData\Microsoft\Windows\WER"
    if (Test-Path $werRoot) {
        Write-Log "Cleaning Windows Error Reporting queue at '$werRoot'"
        try {
            $items = Get-ChildItem -Path $werRoot -Recurse -Force -ErrorAction SilentlyContinue
            foreach ($item in $items) {
                Remove-ItemSafe -Path $item.FullName -Recurse
            }
        } catch {
            Write-Log "Error while cleaning Windows Error Reporting queue. $_" "WARN"
        }
    } else {
        Write-Log "WER root folder not found at '$werRoot'." "INFO"
    }

    # Add additional aggressive, known-safe cleanup targets here if desired.
}

# ================================
#  MAIN EXECUTION
# ================================
$exitCode = 0

# Pre-flight checks
if (Test-PendingReboot) {
    Write-Log "Pending reboot detected — installation should not proceed." "WARN"
    $exitCode = 20
} else {
    Write-Log "No reboot-pending indicators detected (CBS/Windows Update)."
}

if (Test-InstallerBusy) {
    Write-Log "Windows Installer is busy — installation should not proceed." "WARN"
    if ($exitCode -eq 0) { $exitCode = 21 }
} else {
    Write-Log "No active Windows Installer activity detected."
}

if (Test-OfficeClickToRunBusy) {
    Write-Log "Office Click-to-Run installer/maintenance activity detected." "WARN"
    if ($exitCode -eq 0) { $exitCode = 22 }
} else {
    Write-Log "No obvious Office Click-to-Run install activity detected."
}

$svcErrors = Reset-InstallServices
if ($svcErrors) {
    Write-Log "One or more installer services failed to restart/start cleanly." "WARN"
    if ($exitCode -eq 0) { $exitCode = 23 }
}

if ($exitCode -ne 0) {
    Write-Log "Pre-flight checks indicate system is NOT ready for installation. ExitCode=$exitCode"
    Write-Log "Cleanup will be skipped due to pre-flight failure."
    Write-Log "============================================================="
    exit $exitCode
}

Write-Log "System passes pre-flight checks. Proceeding with cleanup..."

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
} catch {
    Write-Log "Unexpected error during cleanup: $_" "ERROR"
    if ($exitCode -eq 0) { $exitCode = 1 }
}

$finalFree = Get-SystemDriveFreeSpace
$delta = $finalFree - $initialFree

Write-Log "Final free space on system drive ($env:SystemDrive): $(Format-Bytes $finalFree)"
Write-Log "Approximate space reclaimed: $(Format-Bytes $delta)"
Write-Log "Cleanup script finished with ExitCode=$exitCode."
Write-Log "Log file: $script:LogFile"
Write-Log "============================================================="

Write-Host ""
Write-Host "Cleanup complete. Approx. space reclaimed: $(Format-Bytes $delta)" -ForegroundColor Cyan
Write-Host "Pre-flight ExitCode: $exitCode" -ForegroundColor Cyan
Write-Host "Log file: $script:LogFile" -ForegroundColor Cyan

exit $exitCode
