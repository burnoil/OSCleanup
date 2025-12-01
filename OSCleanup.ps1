<#
.SYNOPSIS
    Cleans up common Windows OS junk to help prevent MSI / Click-to-Run errors (e.g., 1603).

.DESCRIPTION
    - Must be run as Administrator
    - Cleans:
        * User & system temp folders
        * All user profile temp folders (C:\Users\*\AppData\Local\Temp)
        * Windows Update download cache
        * Delivery Optimization cache
        * Office Click-to-Run logs/telemetry/cache (non-destructive, no binaries)
        * Old CBS/DISM logs & CAB files
        * Windows Installer logs/temp files (NOT the MSI/MSP cache)
        * Recycle Bin (optional)
    - Logs all actions to %ProgramData%\OSCleanup\OSCleanup_yyyyMMdd_HHmmss.log
    - Logs if a reboot is pending (common installer failure cause)

.PARAMETER Aggressive
    Enables extra cleanup (currently Windows Error Reporting queue).

.PARAMETER SkipRecycleBin
    Skips clearing the Recycle Bin.

.PARAMETER WhatIf
    Shows what would be deleted without actually deleting anything.

.EXAMPLE
    .\Invoke-OsCleanup.ps1 -Aggressive

.EXAMPLE
    .\Invoke-OsCleanup.ps1 -WhatIf
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
Write-Log "Starting OS cleanup script"
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
#  Check: Pending Reboot
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

    # Pending file rename operations
    try {
        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager"
        $value = Get-ItemProperty -Path $regPath -Name "PendingFileRenameOperations" -ErrorAction SilentlyContinue
        if ($value -and $value.PendingFileRenameOperations) {
            Write-Log "Pending reboot detected: PendingFileRenameOperations present" "WARN"
            $pending = $true
        }
    } catch {
        Write-Log "Error checking PendingFileRenameOperations. $_" "WARN"
    }

    return $pending
}

if (Test-PendingReboot) {
    Write-Log "One or more reboot-pending indicators found. A reboot before installation is strongly recommended." "WARN"
} else {
    Write-Log "No reboot-pending indicators detected."
}

# ================================
#  Cleanup: Temp Folders (Current user + system)
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
#  Cleanup: Old System Logs (CBS / DISM / Temp CAB)
# ================================
function Clear-OldSystemLogs {
    Write-Log "----- Clearing old CBS/DISM logs and CABs -----"

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
#  Cleanup: Windows Installer Logs / Temp (Not MSI/MSP cache)
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
    Write-Log "Unexpected error during main cleanup: $_" "ERROR"
}

$finalFree = Get-SystemDriveFreeSpace
$delta = $finalFree - $initialFree

Write-Log "Final free space on system drive ($env:SystemDrive): $(Format-Bytes $finalFree)"
Write-Log "Approximate space reclaimed: $(Format-Bytes $delta)"
Write-Log "Cleanup script finished."
Write-Log "Log file: $script:LogFile"
Write-Log "============================================================="

Write-Host ""
Write-Host "Cleanup complete. Approx. space reclaimed: $(Format-Bytes $delta)" -ForegroundColor Cyan
Write-Host "Log file: $script:LogFile" -ForegroundColor Cyan
