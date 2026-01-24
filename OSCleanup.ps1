<#
.SYNOPSIS
    GUI wrapper for OSCleanup.ps1 with real-time log monitoring and progress tracking.

.DESCRIPTION
    Enterprise-ready GUI for OS cleanup operations with:
    - Real-time log display with auto-scroll
    - Progress indication and space tracking
    - Parameter selection via checkboxes
    - Admin elevation handling
    - Exit code interpretation
    - BigFix deployment compatible

.NOTES
    Author: MIT Lincoln Laboratory
    Version: 1.0
    Requires: PowerShell 5.1+, .NET Framework 4.5+
#>

#Requires -Version 5.1

# ================================
# EMBEDDED CLEANUP SCRIPT
# ================================
$script:CleanupScriptContent = @'
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
        $root = $env:SystemDrive.TrimEnd(''\'')
        $driveLetter = $root.Substring(0,1)
        $drive = Get-PSDrive -Name $driveLetter -ErrorAction SilentlyContinue

        if ($drive) {
            return [int64]$drive.Free
        }

        $fallback = Get-WmiObject Win32_LogicalDisk -Filter "DeviceID=''$root''" -ErrorAction SilentlyContinue
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
            Write-Log "WhatIf: Would delete ''$Path''"
        } else {
            Remove-Item -LiteralPath $Path -Recurse:$Recurse -Force -ErrorAction Stop
            Write-Log "Deleted: $Path"
        }
    }
    catch {
        Write-Log "Failed to delete ''$Path'': $_" "WARN"
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
        $procs = Get-CimInstance Win32_Process -Filter "Name=''msiexec.exe''" -ErrorAction SilentlyContinue
        $now = Get-Date

        foreach ($p in $procs) {
            $cmd = $p.CommandLine
            $started = [Management.ManagementDateTimeConverter]::ToDateTime($p.CreationDate)
            $age = ($now - $started).TotalMinutes
            $recent = $age -le $InstallerBusyMinutes

            $installLike =
                ($cmd -match ''/i'' -or
                 $cmd -match ''/x'' -or
                 $cmd -match ''/f'' -or
                 $cmd -match ''/update'' -or
                 $cmd -match ''INSTALL'' -or
                 $cmd -match ''UNINSTALL'')

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
        $procs = Get-CimInstance Win32_Process -Filter "Name=''setup.exe'' OR Name=''OfficeC2RClient.exe'' OR Name=''IntegratedOffice.exe''" -ErrorAction SilentlyContinue

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

'@

# ================================
# INITIALIZATION
# ================================
Add-Type -AssemblyName PresentationFramework
Add-Type -AssemblyName System.Windows.Forms

$script:LogPath = $null
$script:RunspacePool = $null
$script:CleanupRunspace = $null
$script:StartTime = $null
$script:Timer = $null

# ================================
# ADMIN CHECK & ELEVATION
# ================================
function Test-IsAdmin {
    $wid = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($wid)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Start-ElevatedProcess {
    $scriptPath = $MyInvocation.ScriptName
    if (-not $scriptPath) { $scriptPath = $PSCommandPath }
    
    try {
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = "powershell.exe"
        $psi.Arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`""
        $psi.Verb = "runas"
        $psi.UseShellExecute = $true
        
        [System.Diagnostics.Process]::Start($psi) | Out-Null
        exit 0
    }
    catch {
        [System.Windows.MessageBox]::Show(
            "Failed to elevate to administrator.`n`nError: $_",
            "Elevation Failed",
            [System.Windows.MessageBoxButton]::OK,
            [System.Windows.MessageBoxImage]::Error
        )
        exit 1
    }
}

if (-not (Test-IsAdmin)) {
    Start-ElevatedProcess
}

# ================================
# XAML DEFINITION
# ================================
$xaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="OS Cleanup Utility" 
        Height="750" Width="900"
        WindowStartupLocation="CenterScreen"
        ResizeMode="CanResize"
        Background="#F5F5F5">
    
    <Window.Resources>
        <Style x:Key="ModernButton" TargetType="Button">
            <Setter Property="Background" Value="#0078D4"/>
            <Setter Property="Foreground" Value="White"/>
            <Setter Property="BorderThickness" Value="0"/>
            <Setter Property="Padding" Value="12,6"/>
            <Setter Property="FontSize" Value="13"/>
            <Setter Property="FontWeight" Value="SemiBold"/>
            <Setter Property="Cursor" Value="Hand"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="Button">
                        <Border Background="{TemplateBinding Background}" 
                                CornerRadius="3"
                                BorderThickness="0">
                            <ContentPresenter HorizontalAlignment="Center" 
                                            VerticalAlignment="Center"/>
                        </Border>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
            <Style.Triggers>
                <Trigger Property="IsMouseOver" Value="True">
                    <Setter Property="Background" Value="#005A9E"/>
                </Trigger>
                <Trigger Property="IsEnabled" Value="False">
                    <Setter Property="Background" Value="#CCCCCC"/>
                    <Setter Property="Foreground" Value="#666666"/>
                </Trigger>
            </Style.Triggers>
        </Style>

        <Style x:Key="SecondaryButton" TargetType="Button" BasedOn="{StaticResource ModernButton}">
            <Setter Property="Background" Value="#6C757D"/>
            <Style.Triggers>
                <Trigger Property="IsMouseOver" Value="True">
                    <Setter Property="Background" Value="#545B62"/>
                </Trigger>
            </Style.Triggers>
        </Style>

        <Style x:Key="SuccessButton" TargetType="Button" BasedOn="{StaticResource ModernButton}">
            <Setter Property="Background" Value="#28A745"/>
            <Style.Triggers>
                <Trigger Property="IsMouseOver" Value="True">
                    <Setter Property="Background" Value="#218838"/>
                </Trigger>
            </Style.Triggers>
        </Style>
    </Window.Resources>

    <Grid Margin="15">
        <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
        </Grid.RowDefinitions>

        <!-- Header -->
        <Border Grid.Row="0" Background="White" Padding="15" CornerRadius="5" Margin="0,0,0,10">
            <Grid>
                <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="*"/>
                    <ColumnDefinition Width="Auto"/>
                </Grid.ColumnDefinitions>
                
                <StackPanel Grid.Column="0">
                    <TextBlock Text="Windows OS Cleanup Utility" 
                               FontSize="20" 
                               FontWeight="Bold" 
                               Foreground="#2C3E50"/>
                    <TextBlock Text="Safely clean temporary files and perform system maintenance" 
                               FontSize="12" 
                               Foreground="#7F8C8D"
                               Margin="0,3,0,0"/>
                </StackPanel>

                <StackPanel Grid.Column="1" VerticalAlignment="Center">
                    <TextBlock Name="AdminBadge" 
                               Text="⚡ Administrator" 
                               FontSize="11" 
                               FontWeight="Bold"
                               Foreground="#E74C3C"
                               Background="#FFE6E6"
                               Padding="8,4"
                               HorizontalAlignment="Right"/>
                </StackPanel>
            </Grid>
        </Border>

        <!-- Options Panel -->
        <Border Grid.Row="1" Background="White" Padding="15" CornerRadius="5" Margin="0,0,0,10">
            <Grid>
                <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="*"/>
                    <ColumnDefinition Width="*"/>
                </Grid.ColumnDefinitions>

                <StackPanel Grid.Column="0" Margin="0,0,10,0">
                    <TextBlock Text="Cleanup Options" 
                               FontSize="13" 
                               FontWeight="SemiBold" 
                               Foreground="#34495E"
                               Margin="0,0,0,8"/>
                    
                    <CheckBox Name="chkAggressive" 
                              Content="Aggressive cleanup (includes WER data)" 
                              Margin="0,0,0,6"
                              ToolTip="Enables additional cleanup including Windows Error Reporting data"/>
                    
                    <CheckBox Name="chkSkipRecycleBin" 
                              Content="Skip Recycle Bin cleanup" 
                              Margin="0,0,0,6"
                              ToolTip="Preserve Recycle Bin contents"/>
                    
                    <CheckBox Name="chkSkipPreflight" 
                              Content="Skip preflight checks" 
                              Margin="0,0,0,6"
                              ToolTip="Bypass reboot and installer busy detection"/>
                    
                    <CheckBox Name="chkWhatIf" 
                              Content="WhatIf mode (dry run)" 
                              Margin="0,0,0,6"
                              ToolTip="Show what would be deleted without making changes"/>
                </StackPanel>

                <StackPanel Grid.Column="1" Margin="10,0,0,0">
                    <TextBlock Text="Advanced Settings" 
                               FontSize="13" 
                               FontWeight="SemiBold" 
                               Foreground="#34495E"
                               Margin="0,0,0,8"/>
                    
                    <TextBlock Text="Installer busy threshold (minutes):" 
                               FontSize="11" 
                               Foreground="#7F8C8D"
                               Margin="0,0,0,4"/>
                    
                    <Grid Margin="0,0,0,10">
                        <Grid.ColumnDefinitions>
                            <ColumnDefinition Width="*"/>
                            <ColumnDefinition Width="Auto"/>
                        </Grid.ColumnDefinitions>
                        <Slider Name="sliderInstallerMinutes" 
                                Grid.Column="0"
                                Minimum="30" 
                                Maximum="240" 
                                Value="120" 
                                TickFrequency="30"
                                IsSnapToTickEnabled="True"
                                VerticalAlignment="Center"/>
                        <TextBlock Name="txtInstallerMinutes" 
                                   Grid.Column="1"
                                   Text="120" 
                                   FontWeight="Bold"
                                   Foreground="#0078D4"
                                   Width="40"
                                   TextAlignment="Right"
                                   VerticalAlignment="Center"
                                   Margin="10,0,0,0"/>
                    </Grid>

                    <CheckBox Name="chkAutoScroll" 
                              Content="Auto-scroll log output" 
                              IsChecked="True"
                              Margin="0,0,0,6"
                              ToolTip="Automatically scroll to latest log entries"/>
                </StackPanel>
            </Grid>
        </Border>

        <!-- Log Display -->
        <Border Grid.Row="2" Background="White" Padding="0" CornerRadius="5" Margin="0,0,0,10">
            <Grid>
                <Grid.RowDefinitions>
                    <RowDefinition Height="Auto"/>
                    <RowDefinition Height="*"/>
                </Grid.RowDefinitions>

                <Border Grid.Row="0" 
                        Background="#34495E" 
                        Padding="10,8"
                        CornerRadius="5,5,0,0">
                    <Grid>
                        <Grid.ColumnDefinitions>
                            <ColumnDefinition Width="*"/>
                            <ColumnDefinition Width="Auto"/>
                        </Grid.ColumnDefinitions>
                        
                        <TextBlock Grid.Column="0"
                                   Text="Operation Log" 
                                   FontSize="12" 
                                   FontWeight="SemiBold" 
                                   Foreground="White"/>
                        
                        <Button Grid.Column="1"
                                Name="btnClearLog"
                                Content="Clear Log"
                                FontSize="10"
                                Padding="8,3"
                                Background="#546E7A"
                                Foreground="White"
                                BorderThickness="0"
                                Cursor="Hand"/>
                    </Grid>
                </Border>

                <TextBox Name="txtLog" 
                         Grid.Row="1"
                         IsReadOnly="True"
                         VerticalScrollBarVisibility="Auto"
                         HorizontalScrollBarVisibility="Auto"
                         FontFamily="Consolas"
                         FontSize="11"
                         Background="#1E1E1E"
                         Foreground="#D4D4D4"
                         Padding="10"
                         TextWrapping="NoWrap"
                         BorderThickness="0"/>
            </Grid>
        </Border>

        <!-- Status Bar -->
        <Border Grid.Row="3" Background="White" Padding="12" CornerRadius="5" Margin="0,0,0,10">
            <Grid>
                <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="Auto"/>
                    <ColumnDefinition Width="*"/>
                    <ColumnDefinition Width="Auto"/>
                </Grid.ColumnDefinitions>

                <StackPanel Grid.Column="0" Orientation="Horizontal" VerticalAlignment="Center">
                    <TextBlock Text="Status:" 
                               FontSize="11" 
                               Foreground="#7F8C8D" 
                               VerticalAlignment="Center"
                               Margin="0,0,8,0"/>
                    <TextBlock Name="txtStatus" 
                               Text="Ready" 
                               FontSize="11" 
                               FontWeight="SemiBold"
                               Foreground="#2ECC71"
                               VerticalAlignment="Center"/>
                </StackPanel>

                <ProgressBar Grid.Column="1" 
                             Name="progressBar" 
                             Height="6" 
                             Margin="15,0"
                             IsIndeterminate="False"
                             Visibility="Collapsed"/>

                <StackPanel Grid.Column="2" Orientation="Horizontal" VerticalAlignment="Center">
                    <TextBlock Name="txtSpaceReclaimed" 
                               Text="" 
                               FontSize="11"
                               FontWeight="Bold"
                               Foreground="#0078D4"
                               VerticalAlignment="Center"
                               Margin="0,0,10,0"/>
                    <TextBlock Name="txtElapsedTime" 
                               Text="" 
                               FontSize="10" 
                               Foreground="#95A5A6"
                               VerticalAlignment="Center"/>
                </StackPanel>
            </Grid>
        </Border>

        <!-- Action Buttons -->
        <Grid Grid.Row="4">
            <Grid.ColumnDefinitions>
                <ColumnDefinition Width="*"/>
                <ColumnDefinition Width="Auto"/>
                <ColumnDefinition Width="Auto"/>
                <ColumnDefinition Width="Auto"/>
            </Grid.ColumnDefinitions>

            <Button Grid.Column="1"
                    Name="btnRun"
                    Content="▶ Run Cleanup"
                    Style="{StaticResource SuccessButton}"
                    Width="140"
                    Height="35"
                    Margin="0,0,8,0"/>

            <Button Grid.Column="2"
                    Name="btnStop"
                    Content="⏹ Stop"
                    Style="{StaticResource SecondaryButton}"
                    Width="100"
                    Height="35"
                    IsEnabled="False"
                    Margin="0,0,8,0"/>

            <Button Grid.Column="3"
                    Name="btnOpenLog"
                    Content="📄 Open Log File"
                    Style="{StaticResource ModernButton}"
                    Width="130"
                    Height="35"/>
        </Grid>
    </Grid>
</Window>
"@

# ================================
# LOAD XAML
# ================================
try {
    $reader = [System.Xml.XmlReader]::Create([System.IO.StringReader]::new($xaml))
    $window = [Windows.Markup.XamlReader]::Load($reader)
}
catch {
    [System.Windows.MessageBox]::Show(
        "Failed to load GUI.`n`nError: $_",
        "Critical Error",
        [System.Windows.MessageBoxButton]::OK,
        [System.Windows.MessageBoxImage]::Error
    )
    exit 1
}

# ================================
# GET CONTROLS
# ================================
$controls = @{
    chkAggressive        = $window.FindName("chkAggressive")
    chkSkipRecycleBin    = $window.FindName("chkSkipRecycleBin")
    chkSkipPreflight     = $window.FindName("chkSkipPreflight")
    chkWhatIf            = $window.FindName("chkWhatIf")
    chkAutoScroll        = $window.FindName("chkAutoScroll")
    sliderInstallerMinutes = $window.FindName("sliderInstallerMinutes")
    txtInstallerMinutes  = $window.FindName("txtInstallerMinutes")
    txtLog               = $window.FindName("txtLog")
    txtStatus            = $window.FindName("txtStatus")
    txtSpaceReclaimed    = $window.FindName("txtSpaceReclaimed")
    txtElapsedTime       = $window.FindName("txtElapsedTime")
    progressBar          = $window.FindName("progressBar")
    btnRun               = $window.FindName("btnRun")
    btnStop              = $window.FindName("btnStop")
    btnOpenLog           = $window.FindName("btnOpenLog")
    btnClearLog          = $window.FindName("btnClearLog")
}

# ================================
# HELPER FUNCTIONS
# ================================
function Write-GuiLog {
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$Message,
        [string]$Color = "#D4D4D4"
    )
    
    $window.Dispatcher.Invoke([action]{
        $timestamp = Get-Date -Format "HH:mm:ss"
        $controls.txtLog.AppendText("[$timestamp] $Message`r`n")
        
        if ($controls.chkAutoScroll.IsChecked) {
            $controls.txtLog.ScrollToEnd()
        }
    })
}

function Update-Status {
    param(
        [Parameter(Mandatory)]
        [string]$Message,
        [string]$Color = "#2ECC71"
    )
    
    $window.Dispatcher.Invoke([action]{
        $controls.txtStatus.Text = $Message
        $controls.txtStatus.Foreground = $Color
    })
}

function Update-ElapsedTime {
    if ($script:StartTime) {
        $elapsed = (Get-Date) - $script:StartTime
        $timeStr = "{0:mm}:{0:ss}" -f $elapsed
        
        $window.Dispatcher.Invoke([action]{
            $controls.txtElapsedTime.Text = "⏱ $timeStr"
        })
    }
}

function Enable-Controls {
    param([bool]$Enabled)
    
    $window.Dispatcher.Invoke([action]{
        $controls.chkAggressive.IsEnabled = $Enabled
        $controls.chkSkipRecycleBin.IsEnabled = $Enabled
        $controls.chkSkipPreflight.IsEnabled = $Enabled
        $controls.chkWhatIf.IsEnabled = $Enabled
        $controls.sliderInstallerMinutes.IsEnabled = $Enabled
        $controls.btnRun.IsEnabled = $Enabled
        $controls.btnStop.IsEnabled = -not $Enabled
        
        if ($Enabled) {
            $controls.progressBar.Visibility = [System.Windows.Visibility]::Collapsed
            $controls.progressBar.IsIndeterminate = $false
        } else {
            $controls.progressBar.Visibility = [System.Windows.Visibility]::Visible
            $controls.progressBar.IsIndeterminate = $true
        }
    })
}

function Get-ExitCodeMessage {
    param([int]$ExitCode)
    
    switch ($ExitCode) {
        0  { return "Success" }
        1  { return "General error" }
        20 { return "Pending reboot detected" }
        21 { return "Installer is busy" }
        22 { return "Office Click-to-Run is busy" }
        23 { return "Service restart failure" }
        default { return "Unknown exit code: $ExitCode" }
    }
}

# ================================
# CLEANUP EXECUTION
# ================================
function Start-CleanupOperation {
    # Disable controls
    Enable-Controls -Enabled $false
    Update-Status "Running cleanup..." "#3498DB"
    
    $script:StartTime = Get-Date
    $controls.txtSpaceReclaimed.Text = ""
    
    # Start timer for elapsed time updates
    $script:Timer = New-Object System.Windows.Threading.DispatcherTimer
    $script:Timer.Interval = [TimeSpan]::FromSeconds(1)
    $script:Timer.Add_Tick({ Update-ElapsedTime })
    $script:Timer.Start()
    
    Write-GuiLog "=== OS CLEANUP OPERATION STARTED ==="
    Write-GuiLog "Aggressive: $($controls.chkAggressive.IsChecked)"
    Write-GuiLog "Skip Recycle Bin: $($controls.chkSkipRecycleBin.IsChecked)"
    Write-GuiLog "Skip Preflight: $($controls.chkSkipPreflight.IsChecked)"
    Write-GuiLog "WhatIf Mode: $($controls.chkWhatIf.IsChecked)"
    Write-GuiLog "Installer Busy Minutes: $($controls.sliderInstallerMinutes.Value)"
    Write-GuiLog ""
    
    # Create temporary script file
    $tempScript = [System.IO.Path]::GetTempFileName() + ".ps1"
    
    try {
        # Write cleanup script to temp file
        Set-Content -Path $tempScript -Value $script:CleanupScriptContent -ErrorAction Stop
        
        # Build arguments
        $arguments = @()
        if ($controls.chkAggressive.IsChecked) { $arguments += "-Aggressive" }
        if ($controls.chkSkipRecycleBin.IsChecked) { $arguments += "-SkipRecycleBin" }
        if ($controls.chkSkipPreflight.IsChecked) { $arguments += "-SkipPreflight" }
        if ($controls.chkWhatIf.IsChecked) { $arguments += "-WhatIf" }
        $arguments += "-InstallerBusyMinutes $([int]$controls.sliderInstallerMinutes.Value)"
        $arguments += "-Silent"
        
        # Create runspace
        $script:RunspacePool = [runspacefactory]::CreateRunspacePool(1, 1)
        $script:RunspacePool.Open()
        
        $script:CleanupRunspace = [powershell]::Create()
        $script:CleanupRunspace.RunspacePool = $script:RunspacePool
        
        # Add script
        [void]$script:CleanupRunspace.AddScript({
            param($ScriptPath, $Args)
            
            $output = @{
                ExitCode = 0
                LogFile = $null
                Output = @()
            }
            
            try {
                # Execute cleanup script
                $result = & $ScriptPath @Args 2>&1
                $output.ExitCode = $LASTEXITCODE
                $output.Output = $result
                
                # Find log file
                $logRoot = Join-Path $env:ProgramData "OSCleanup"
                if (Test-Path $logRoot) {
                    $latestLog = Get-ChildItem $logRoot -Filter "OSCleanup_*.log" -ErrorAction SilentlyContinue |
                        Sort-Object LastWriteTime -Descending |
                        Select-Object -First 1
                    
                    if ($latestLog) {
                        $output.LogFile = $latestLog.FullName
                    }
                }
            }
            catch {
                $output.ExitCode = 1
                $output.Output = @("ERROR: $_")
            }
            
            return $output
        })
        
        [void]$script:CleanupRunspace.AddArgument($tempScript)
        [void]$script:CleanupRunspace.AddArgument($arguments)
        
        # Start async
        $handle = $script:CleanupRunspace.BeginInvoke()
        
        # Monitor completion
        $monitorTimer = New-Object System.Windows.Threading.DispatcherTimer
        $monitorTimer.Interval = [TimeSpan]::FromMilliseconds(500)
        
        $monitorTimer.Add_Tick({
            if ($handle.IsCompleted) {
                $monitorTimer.Stop()
                
                try {
                    $result = $script:CleanupRunspace.EndInvoke($handle)
                    
                    # Stop elapsed timer
                    if ($script:Timer) {
                        $script:Timer.Stop()
                    }
                    
                    # Parse log file for results
                    if ($result.LogFile -and (Test-Path $result.LogFile)) {
                        $script:LogPath = $result.LogFile
                        
                        # Read and display log
                        $logContent = Get-Content $result.LogFile -Raw -ErrorAction SilentlyContinue
                        if ($logContent) {
                            Write-GuiLog ""
                            Write-GuiLog "=== CLEANUP LOG ==="
                            Write-GuiLog $logContent
                        }
                        
                        # Extract space reclaimed
                        if ($logContent -match "Space reclaimed:\s*(.+)") {
                            $spaceReclaimed = $matches[1].Trim()
                            $window.Dispatcher.Invoke([action]{
                                $controls.txtSpaceReclaimed.Text = "💾 Reclaimed: $spaceReclaimed"
                            })
                        }
                    }
                    
                    # Handle exit code
                    $exitCode = $result.ExitCode
                    $exitMessage = Get-ExitCodeMessage -ExitCode $exitCode
                    
                    if ($exitCode -eq 0) {
                        Write-GuiLog ""
                        Write-GuiLog "✓ CLEANUP COMPLETED SUCCESSFULLY" -Color "#2ECC71"
                        Update-Status "Completed: $exitMessage" "#2ECC71"
                        
                        [System.Windows.MessageBox]::Show(
                            "Cleanup completed successfully!`n`nExit Code: $exitCode`nStatus: $exitMessage",
                            "Success",
                            [System.Windows.MessageBoxButton]::OK,
                            [System.Windows.MessageBoxImage]::Information
                        )
                    }
                    elseif ($exitCode -ge 20 -and $exitCode -le 23) {
                        Write-GuiLog ""
                        Write-GuiLog "⚠ PREFLIGHT CHECK FAILED" -Color "#E67E22"
                        Write-GuiLog "Exit Code: $exitCode - $exitMessage" -Color "#E67E22"
                        Update-Status "Preflight failed: $exitMessage" "#E67E22"
                        
                        [System.Windows.MessageBox]::Show(
                            "Preflight check failed.`n`nExit Code: $exitCode`nReason: $exitMessage`n`nPlease address the issue and try again, or use 'Skip Preflight' to force cleanup.",
                            "Preflight Failed",
                            [System.Windows.MessageBoxButton]::OK,
                            [System.Windows.MessageBoxImage]::Warning
                        )
                    }
                    else {
                        Write-GuiLog ""
                        Write-GuiLog "✗ CLEANUP FAILED" -Color "#E74C3C"
                        Write-GuiLog "Exit Code: $exitCode - $exitMessage" -Color "#E74C3C"
                        Update-Status "Failed: $exitMessage" "#E74C3C"
                        
                        [System.Windows.MessageBox]::Show(
                            "Cleanup operation failed.`n`nExit Code: $exitCode`nStatus: $exitMessage`n`nCheck the log for details.",
                            "Operation Failed",
                            [System.Windows.MessageBoxButton]::OK,
                            [System.Windows.MessageBoxImage]::Error
                        )
                    }
                }
                catch {
                    Write-GuiLog ""
                    Write-GuiLog "✗ ERROR: $_" -Color "#E74C3C"
                    Update-Status "Error occurred" "#E74C3C"
                    
                    [System.Windows.MessageBox]::Show(
                        "An error occurred during cleanup.`n`nError: $_",
                        "Error",
                        [System.Windows.MessageBoxButton]::OK,
                        [System.Windows.MessageBoxImage]::Error
                    )
                }
                finally {
                    # Cleanup
                    if ($script:CleanupRunspace) {
                        $script:CleanupRunspace.Dispose()
                        $script:CleanupRunspace = $null
                    }
                    if ($script:RunspacePool) {
                        $script:RunspacePool.Close()
                        $script:RunspacePool.Dispose()
                        $script:RunspacePool = $null
                    }
                    
                    # Remove temp script
                    if (Test-Path $tempScript) {
                        Remove-Item $tempScript -Force -ErrorAction SilentlyContinue
                    }
                    
                    Enable-Controls -Enabled $true
                }
            }
        })
        
        $monitorTimer.Start()
    }
    catch {
        Write-GuiLog "✗ Failed to start cleanup: $_" -Color "#E74C3C"
        Update-Status "Failed to start" "#E74C3C"
        Enable-Controls -Enabled $true
        
        if ($script:Timer) {
            $script:Timer.Stop()
        }
        
        if (Test-Path $tempScript) {
            Remove-Item $tempScript -Force -ErrorAction SilentlyContinue
        }
    }
}

function Stop-CleanupOperation {
    Write-GuiLog "⏹ Stopping cleanup operation..."
    Update-Status "Stopping..." "#E67E22"
    
    try {
        if ($script:CleanupRunspace) {
            $script:CleanupRunspace.Stop()
        }
        if ($script:RunspacePool) {
            $script:RunspacePool.Close()
            $script:RunspacePool.Dispose()
        }
    }
    catch {
        Write-GuiLog "Error stopping operation: $_"
    }
    finally {
        $script:CleanupRunspace = $null
        $script:RunspacePool = $null
        
        if ($script:Timer) {
            $script:Timer.Stop()
        }
        
        Enable-Controls -Enabled $true
        Update-Status "Stopped" "#E67E22"
        Write-GuiLog "Operation stopped by user"
    }
}

# ================================
# EVENT HANDLERS
# ================================

# Slider value changed
$controls.sliderInstallerMinutes.Add_ValueChanged({
    $controls.txtInstallerMinutes.Text = [int]$controls.sliderInstallerMinutes.Value
})

# Clear log button
$controls.btnClearLog.Add_Click({
    $controls.txtLog.Clear()
    Write-GuiLog "Log cleared"
})

# Run button
$controls.btnRun.Add_Click({
    $result = [System.Windows.MessageBox]::Show(
        "Are you sure you want to run the cleanup operation?",
        "Confirm Cleanup",
        [System.Windows.MessageBoxButton]::YesNo,
        [System.Windows.MessageBoxImage]::Question
    )
    
    if ($result -eq [System.Windows.MessageBoxResult]::Yes) {
        Start-CleanupOperation
    }
})

# Stop button
$controls.btnStop.Add_Click({
    Stop-CleanupOperation
})

# Open log file button
$controls.btnOpenLog.Add_Click({
    if ($script:LogPath -and (Test-Path $script:LogPath)) {
        Start-Process notepad.exe -ArgumentList $script:LogPath
    }
    else {
        $logRoot = Join-Path $env:ProgramData "OSCleanup"
        if (Test-Path $logRoot) {
            Start-Process explorer.exe -ArgumentList $logRoot
        }
        else {
            [System.Windows.MessageBox]::Show(
                "No log file available yet.`n`nLogs will be created in:`n$logRoot",
                "No Log File",
                [System.Windows.MessageBoxButton]::OK,
                [System.Windows.MessageBoxImage]::Information
            )
        }
    }
})

# Window closing
$window.Add_Closing({
    if ($script:CleanupRunspace -or $script:RunspacePool) {
        $result = [System.Windows.MessageBox]::Show(
            "Cleanup operation is still running. Are you sure you want to exit?",
            "Confirm Exit",
            [System.Windows.MessageBoxButton]::YesNo,
            [System.Windows.MessageBoxImage]::Warning
        )
        
        if ($result -eq [System.Windows.MessageBoxResult]::No) {
            $_.Cancel = $true
            return
        }
        
        # Force stop
        Stop-CleanupOperation
    }
    
    if ($script:Timer) {
        $script:Timer.Stop()
    }
})

# ================================
# INITIALIZATION
# ================================
Write-GuiLog "OS Cleanup Utility initialized"
Write-GuiLog "Running as: $env:USERNAME"
Write-GuiLog "Computer: $env:COMPUTERNAME"
Write-GuiLog "Ready to begin cleanup operation"
Write-GuiLog ""

# ================================
# SHOW WINDOW
# ================================
[void]$window.ShowDialog()
