# DevicesFiltering by Gorstak

# Define scheduled task parameters
$taskName = "DevicesFilteringStartup"
$taskDescription = "Runs the DevicesFiltering script at user logon with admin privileges."

# Define script path
$scriptDir = "C:\Windows\Setup\Scripts"
$scriptPath = "$scriptDir\DevicesFiltering.ps1"

# Check if task exists
$existingTask = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue

if (-not $existingTask) {
    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-WindowStyle Hidden -ExecutionPolicy Bypass -File `"$scriptPath`""
    $trigger = New-ScheduledTaskTrigger -AtLogOn
    $principal = New-ScheduledTaskPrincipal -UserId "$env:USERNAME" -LogonType Interactive -RunLevel Highest
    $task = New-ScheduledTask -Action $action -Trigger $trigger -Principal $principal -Description $taskDescription

    # Register the task
    Register-ScheduledTask -TaskName $taskName -InputObject $task
}

# Get current user's session ID
$currentSessionId = (Get-Process -PID $PID).SessionId

# List of critical device classes to exclude (add more as needed)
$criticalClasses = @(
    "DiskDrive",           # Storage devices
    "Volume",             # Disk volumes
    "Processor",          # CPU
    "System",             # Core system devices
    "Computer",           # Computer itself
    "USB",                # USB controllers (be cautious)
    "Net"                 # Network adapters
)

# Function to check if device is associated with current session (placeholder)
function Test-DeviceSession {
    param (
        [string]$DeviceInstanceId
    )
    # Placeholder logic - customize as needed
    return $true  # Default to keep enabled until better logic is implemented
}

# Get all PnP devices
$devices = Get-PnpDevice | Select-Object -Property Name, InstanceId, Status, Class

Write-Host "Found $($devices.Count) devices"

foreach ($device in $devices) {
    $deviceId = $device.InstanceId
    $deviceClass = $device.Class
    
    # Skip if already disabled
    if ($device.Status -eq "Error") {
        Write-Host "Device '$($device.Name)' already disabled"
        continue
    }
    
    # Skip critical device classes
    if ($criticalClasses -contains $deviceClass) {
        Write-Host "Skipping critical device: $($device.Name) (Class: $deviceClass)"
        continue
    }
    
    # Check if this device belongs to current session
    $isCurrentSessionDevice = Test-DeviceSession -DeviceInstanceId $deviceId
    
    if (-not $isCurrentSessionDevice) {
        try {
            # Disable the device
            Disable-PnpDevice -InstanceId $deviceId -Confirm:$false
            Write-Host "Disabled device: $($device.Name) (Class: $deviceClass)"
        }
        catch {
            Write-Host "Failed to disable $($device.Name): $_"
        }
    }
    else {
        Write-Host "Keeping device active: $($device.Name) (Class: $deviceClass)"
    }
}

# Optional: List all devices after changes
Get-PnpDevice | Format-Table -Property Name, Status, Class, InstanceId -AutoSize

Write-Host "Device restriction process completed"