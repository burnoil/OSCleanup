# OSCleanup
## Disk/cache cleanup script for Windows OS. GUI or CLI.
## Cleans up Windows OS junk and performs optional pre-flight checks to help prevent MSI / Click-to-Run install issues (e.g., 1603).

## CLI

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

# Example - C:\OSCleanupCLI.ps1 -Silent

## GUI
### OSCleanupGUI.ps1

<img width="881" height="730" alt="image" src="https://github.com/user-attachments/assets/12c2857d-467f-460b-8701-f4be89f6b7b2" />
