#Requires -RunAsAdministrator

# Define parameters at the top
param (
    [switch]$Start
)

# Hide the PowerShell window using Win32 API
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public class Win32 {
    [DllImport("user32.dll")]
    public static extern IntPtr GetForegroundWindow();
    [DllImport("user32.dll")]
    public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
}
"@ -ErrorAction SilentlyContinue
try {
    $window = [Win32]::GetForegroundWindow()
    [Win32]::ShowWindow($window, 0) | Out-Null
}
catch {
    # Silent fail if window hiding doesn't work
}

# Initialize Event Log source
if (-not [System.Diagnostics.EventLog]::SourceExists("SecureWindows")) {
    New-EventLog -LogName "Application" -Source "SecureWindows"
}

# Log function
function Write-Log {
    param ([string]$Message, [string]$EntryType = "Information")
    Write-EventLog -LogName "Application" -Source "SecureWindows" -EventId 1000 -EntryType $EntryType -Message $Message
}

# Download YARA, Sigma, and IDS rules
function Get-SecurityRules {
    $tempDir = "$env:TEMP\security_rules"
    if (-not (Test-Path $tempDir)) { New-Item -ItemType Directory -Path $tempDir | Out-Null }

    try {
        # YARA rules
        $yaraZip = "$tempDir\yara_rules.zip"
        Invoke-WebRequest -Uri "https://github.com/Yara-Rules/rules/archive/refs/heads/master.zip" -OutFile $yaraZip -ErrorAction Stop
        Expand-Archive -Path $yaraZip -DestinationPath "$tempDir\yara" -Force
        $yaraRules = Get-ChildItem -Path "$tempDir\yara" -Recurse -Include "*.yar"

        # Sigma rules
        $sigmaZip = "$tempDir\sigma_rules.zip"
        Invoke-WebRequest -Uri "https://github.com/SigmaHQ/sigma/archive/refs/heads/master.zip" -OutFile $sigmaZip -ErrorAction Stop
        Expand-Archive -Path $sigmaZip -DestinationPath "$tempDir\sigma" -Force
        $sigmaRules = Get-ChildItem -Path "$tempDir\sigma" -Recurse -Include "*.yml"

        # IDS rules (Snort community)
        $snortRules = "$tempDir\snort.rules"
        Invoke-WebRequest -Uri "https://www.snort.org/downloads/community/community-rules" -OutFile $snortRules -ErrorAction Stop

        Write-Log "Successfully downloaded YARA, Sigma, and Snort rules."
        return @{ Yara = $yaraRules; Sigma = $sigmaRules; Snort = $snortRules }
    }
    catch {
        Write-Log "Error downloading rules: $_" -EntryType "Error"
        throw
    }
}

# Parse rules for actionable indicators
function Parse-Rules {
    param ($Rules)

    $indicators = @()

    # Parse YARA rules (simplified for hashes and filenames)
    foreach ($rule in $Rules.Yara) {
        $content = Get-Content $rule.FullName -ErrorAction SilentlyContinue
        if ($content -match 'meta:.*hash\s*=\s*"([a-f0-9]{32,64})"') {
            $indicators += @{ Type = "Hash"; Value = $matches[1]; Source = "YARA" }
        }
        if ($content -match 'meta:.*filename\s*=\s*"([^"]+)"') {
            $indicators += @{ Type = "FileName"; Value = $matches[1]; Source = "YARA" }
        }
    }

    # Parse Sigma rules (focus on process creation)
    foreach ($rule in $Rules.Sigma) {
        $content = Get-Content $rule.FullName -ErrorAction SilentlyContinue
        if ($content -match 'process_creation:.*image:.*\\([^\s]+.exe)') {
            $indicators += @{ Type = "FileName"; Value = $matches[1]; Source = "Sigma" }
        }
    }

    # Parse Snort rules (focus on C2 IPs)
    if (Test-Path $Rules.Snort) {
        foreach ($line in (Get-Content $Rules.Snort -ErrorAction SilentlyContinue)) {
            if ($line -match 'alert.*dst\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})') {
                $indicators += @{ Type = "IP"; Value = $matches[1]; Source = "Snort" }
            }
        }
    }

    Write-Log "Parsed $($indicators.Count) indicators from rules."
    return $indicators
}

# Apply rules to Windows Defender ASR and Firewall
function Apply-SecurityRules {
    param ($Indicators)

    # Apply Defender ASR rules
    $asrRules = @{}
    foreach ($indicator in $Indicators) {
        if ($indicator.Type -eq "FileName" -and $indicator.Source -in @("YARA", "Sigma")) {
            $asrRules[$indicator.Value] = $true
        }
    }
    foreach ($exe in $asrRules.Keys) {
        try {
            Add-MpPreference -AttackSurfaceReductionRules_Ids "e6db77e5-3df2-4cf1-b95a-636979351e5b" `
                            -AttackSurfaceReductionRules_Actions Enabled `
                            -AttackSurfaceReductionRules_ExecutablePaths $exe -ErrorAction Stop
            Write-Log "Blocked executable via ASR: $exe"
        }
        catch {
            Write-Log "Error applying ASR rule for ${exe}: $_" -EntryType "Warning"
        }
    }

    # Apply Firewall rules
    foreach ($indicator in $Indicators) {
        if ($indicator.Type -eq "IP") {
            try {
                New-NetFirewallRule -Name "Block_C2_$($indicator.Value)" -Direction Outbound -Action Block `
                                   -RemoteAddress $indicator.Value -ErrorAction Stop
                Write-Log "Blocked IP via Firewall: $($indicator.Value)"
            }
            catch {
                Write-Log "Error applying Firewall rule for $($indicator.Value): $_" -EntryType "Warning"
            }
        }
    }
}

# Monitor processes in real-time
function Start-ProcessMonitor {
    param ($Indicators)

    $fileNames = $Indicators | Where-Object { $_.Type -eq "FileName" } | Select-Object -ExpandProperty Value
    Register-WmiEvent -Query "SELECT * FROM __InstanceCreationEvent WITHIN 1 WHERE TargetInstance ISA 'Win32_Process'" -Action {
        $process = $event.SourceEventArgs.NewEvent.TargetInstance
        if ($fileNames -contains $process.Name) {
            try {
                Stop-Process -Id $process.ProcessId -Force -ErrorAction Stop
                Write-EventLog -LogName "Application" -Source "SecureWindows" -EventId 1000 -EntryType Warning `
                              -Message "Blocked malicious process: $($process.Name)"
            }
            catch {
                Write-EventLog -LogName "Application" -Source "SecureWindows" -EventId 1000 -EntryType Error `
                              -Message "Error blocking process $($process.Name): $_"
            }
        }
    }
    Write-Log "Process monitoring started."
}

# Schedule startup and daily update tasks
function Schedule-Tasks {
    $scriptPath = $PSCommandPath
    $exePath = $scriptPath -replace '\.ps1$', '.exe'

    # Startup task
    $taskName = "SecureWindowsStartup"
    $action = if (Test-Path $exePath) {
        New-ScheduledTaskAction -Execute $exePath -Argument "/Start"
    } else {
        New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -WindowStyle Hidden -File `"$scriptPath`" /Start"
    }
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal `
                          -Description "SecureWindows startup monitoring" -Force | Out-Null
    Write-Log "Scheduled startup task."

    # Daily update task
    $taskName = "SecureWindowsUpdate"
    $action = if (Test-Path $exePath) {
        New-ScheduledTaskAction -Execute $exePath
    } else {
        New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -WindowStyle Hidden -File `"$scriptPath`""
    }
    $trigger = New-ScheduledTaskTrigger -Daily -At "12:00"
    Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal `
                          -Description "Daily security rule update" -Force | Out-Null
    Write-Log "Scheduled daily rule updates."
}

# Main
try {
    Write-Log "Starting SecureWindows script (Mode: $(if ($Start) { 'Startup' } else { 'Initial/Update' }))."

    if ($Start) {
        # Startup mode: Load cached rules and start monitoring
        $tempDir = "$env:TEMP\security_rules"
        if (Test-Path $tempDir) {
            $rules = @{
                Yara = Get-ChildItem -Path "$tempDir\yara" -Recurse -Include "*.yar" -ErrorAction SilentlyContinue
                Sigma = Get-ChildItem -Path "$tempDir\sigma" -Recurse -Include "*.yml" -ErrorAction SilentlyContinue
                Snort = "$tempDir\snort.rules"
            }
            if ($rules.Yara -or $rules.Sigma -or (Test-Path $rules.Snort)) {
                $indicators = Parse-Rules -Rules $rules
                Start-ProcessMonitor -Indicators $indicators
                Write-Log "Startup mode: Monitoring active with cached rules."
                while ($true) { Start-Sleep -Seconds 3600 } # Keep script running
            } else {
                Write-Log "Startup mode: No valid cached rules found." -EntryType "Warning"
                exit 1
            }
        } else {
            Write-Log "Startup mode: Cached rules directory not found." -EntryType "Error"
            exit 1
        }
    } else {
        # Initial/Update mode: Download, apply, and schedule
        $rules = Get-SecurityRules
        $indicators = Parse-Rules -Rules $rules
        Apply-SecurityRules -Indicators $indicators
        Start-ProcessMonitor -Indicators $indicators
        Schedule-Tasks
        Write-Log "SecureWindows setup complete. Monitoring active."
        while ($true) { Start-Sleep -Seconds 3600 } # Keep script running
    }
}
catch {
    Write-Log "Fatal error: $_" -EntryType "Error"
    exit 1
}