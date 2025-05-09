@echo off

:: Configuration Variables
set "LOGPATH=%SystemDrive%\Logs"
set "LOGFILE=%COMPUTERNAME%_system_cleanup.log"
set "FORCE_CLOSE_PROCESSES=yes"
set "FORCE_CLOSE_PROCESSES_EXIT_CODE=1618"
set "LOG_MAX_SIZE=2097152"  :: 2MB

:: Process and GUID Lists
set "BROWSER_PROCESSES=battle chrome firefox flash iexplore iexplorer opera palemoon plugin-container skype steam yahoo"
set "VNC_PROCESSES=winvnc winvnc4 uvnc_service tvnserver"
set "FLASH_GUIDS_ACTIVE_X=cdf0cc64-4741-4e43-bf97-fef8fa1d6f1c ..."
set "FLASH_GUIDS_PLUGIN=F6E23569-A22A-4924-93A4-3F215BEF63D2 ..."

:: Initialize Environment
title %SCRIPT_NAME% v%SCRIPT_VERSION% (%SCRIPT_UPDATED%)
call :get_current_date
if not exist "%LOGPATH%" mkdir "%LOGPATH%" 2>NUL
pushd "%~dp0"
call :check_admin_rights
call :detect_os_version
call :handle_log_rotation

:: Main Execution
call :log "Starting system cleanup..."

:: Reset Windows Firewall to default (optional, comment out if not desired)
netsh advfirewall reset

:: Set default policies: block all inbound, allow specified outbound
netsh advfirewall set allprofiles state on
netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound

:: === SYSTEM Rules ===
:: NetBIOS Datagrams (UDP 137-138)
netsh advfirewall firewall add rule name="NetBIOS Datagrams Inbound" dir=in action=block protocol=UDP localport=137-138 remoteport=137-138 profile=any

:: Microsoft DS (TCP 445)
netsh advfirewall firewall add rule name="Microsoft DS Client Outbound" dir=out action=block protocol=TCP localport=1024-65535 remoteport=445 profile=any
netsh advfirewall firewall add rule name="Microsoft DS Server Inbound" dir=in action=block protocol=TCP localport=445 remoteport=1024-65535 profile=any

:: NetBIOS Sessions (TCP 139)
netsh advfirewall firewall add rule name="NetBIOS Sessions Client Outbound" dir=out action=block protocol=TCP localport=1024-65535 remoteport=139 profile=any
netsh advfirewall firewall add rule name="NetBIOS Sessions Server Inbound" dir=in action=block protocol=TCP localport=139 remoteport=1024-65535 profile=any

:: ICMP Incoming (specific types)
netsh advfirewall firewall add rule name="ICMP Incoming" dir=in action=block protocol=ICMPv4 type=8 profile=any
netsh advfirewall firewall add rule name="ICMP Outgoing" dir=out action=block protocol=ICMPv4 type=8 profile=any

:: ICMPv6 Error and Info Messages
netsh advfirewall firewall add rule name="ICMPv6 Error Messages" dir=in action=block protocol=ICMPv6 type=1,2,3,4 profile=any
netsh advfirewall firewall add rule name="ICMPv6 Info Messages" dir=in action=block protocol=ICMPv6 type=128,129,133,134,135,136,137 profile=any

:: 6to4 Tunnel (Protocol 41)
netme advfirewall firewall add rule name="6to4 Tunnel IPv6" dir=in action=block protocol=41 profile=any

:: Teredo Tunnel (UDP 3544-3545)
netsh advfirewall firewall add rule name="Teredo Tunnel Outbound" dir=out action=block protocol=UDP localport=0-65535 remoteport=3544-3545 profile=any

:: RDP (TCP 3389)
netsh advfirewall firewall add rule name="RDP Inbound" dir=in action=block protocol=TCP localport=3389 remoteport=1024-65535 profile=any

:: PPTP (TCP 1723, GRE)
netsh advfirewall firewall add rule name="PPTP Call Control Outbound" dir=out action=block protocol=TCP localport=1024-65535 remoteport=1723 profile=any
netsh advfirewall firewall add rule name="PPTP GRE" dir=in action=block protocol=47 profile=any

:: UPnP (UDP 1900)
netsh advfirewall firewall add rule name="UPnP Inbound" dir=in action=block protocol=UDP localport=1900 remoteport=1-65535 profile=any
netsh advfirewall firewall add rule name="UPnP Outbound" dir=out action=block protocol=UDP localport=1-65535 remoteport=1900 profile=any

:: IGMP (Protocol 2)
netsh advfirewall firewall add rule name="IGMP" dir=in action=block protocol=2 profile=any

:: === Application-Specific Rules ===

:: iexplore.exe
netsh advfirewall firewall add rule name="iexplore HTTP Outbound" dir=out action=block protocol=TCP localport=1024-65535 remoteport=80-88 program="C:\Program Files\Internet Explorer\iexplore.exe" profile=any
netsh advfirewall firewall add rule name="iexplore Alt HTTP1 Outbound" dir=out action=block protocol=TCP localport=1024-65535 remoteport=8000-8008 program="C:\Program Files\Internet Explorer\iexplore.exe" profile=any
netsh advfirewall firewall add rule name="iexplore Alt HTTP2 Outbound" dir=out action=block protocol=TCP localport=1024-65535 remoteport=8080-8088 program="C:\Program Files\Internet Explorer\iexplore.exe" profile=any
netsh advfirewall firewall add rule name="iexplore HTTPS Outbound" dir=out action=block protocol=TCP localport=1024-65535 remoteport=443 program="C:\Program Files\Internet Explorer\iexplore.exe" profile=any
netsh advfirewall firewall add rule name="iexplore Proxy Outbound" dir=out action=block protocol=TCP localport=1024-65535 remoteport=3128 program="C:\Program Files\Internet Explorer\iexplore.exe" profile=any
netsh advfirewall firewall add rule name="iexplore FTP Outbound" dir=out action=block protocol=TCP localport=1024-65535 remoteport=21 program="C:\Program Files\Internet Explorer\iexplore.exe" profile=any

:: SystemSettings.exe
netsh advfirewall firewall add rule name="SystemSettings HTTP Outbound" dir=out action=block protocol=TCP localport=1024-65535 remoteport=80 program="C:\Windows\ImmersiveControlPanel\SystemSettings.exe" profile=any
netsh advfirewall firewall add rule name="SystemSettings HTTPS Outbound" dir=out action=block protocol=TCP localport=1024-65535 remoteport=443 program="C:\Windows\ImmersiveControlPanel\SystemSettings.exe" profile=any

:: explorer.exe
netsh advfirewall firewall add rule name="explorer HTTP Outbound" dir=out action=block protocol=TCP localport=1024-65535 remoteport=80-88 program="C:\Windows\explorer.exe" profile=any
netsh advfirewall firewall add rule name="explorer Alt HTTP1 Outbound" dir=out action=block protocol=TCP localport=1024-65535 remoteport=8000-8008 program="C:\Windows\explorer.exe" profile=any
netsh advfirewall firewall add rule name="explorer Alt HTTP2 Outbound" dir=out action=block protocol=TCP localport=1024-65535 remoteport=8080-8088 program="C:\Windows\explorer.exe" profile=any
netsh advfirewall firewall add rule name="explorer HTTPS Outbound" dir=out action=block protocol=TCP localport=1024-65535 remoteport=443 program="C:\Windows\explorer.exe" profile=any
netsh advfirewall firewall add rule name="explorer Proxy Outbound" dir=out action=block protocol=TCP localport=1024-65535 remoteport=3128 program="C:\Windows\explorer.exe" profile=any

:: ftp.exe
netsh advfirewall firewall add rule name="ftp Command Outbound" dir=out action=block protocol=TCP localport=1024-65535 remoteport=21 program="C:\Windows\system32\ftp.exe" profile=any

:: lsass.exe
netsh advfirewall firewall add rule name="lsass DNS Outbound" dir=out action=block protocol=TCP localport=1024-65535 remoteport=53 program="C:\Windows\System32\lsass.exe" profile=any
netsh advfirewall firewall add rule name="lsass Kerberos UDP Out" dir=out action=block protocol=UDP localport=1024-65535 remoteport=88 program="C:\Windows\System32\lsass.exe" profile=any
netsh advfirewall firewall add rule name="lsass Kerberos UDP In" dir=in action=block protocol=UDP localport=88 remoteport=1024-65535 program="C:\Windows\System32\lsass.exe" profile=any
netsh advfirewall firewall add rule name="lsass Kerberos TCP Out" dir=out action=block protocol=TCP localport=1024-65535 remoteport=88 program="C:\Windows\System32\lsass.exe" profile=any
netsh advfirewall firewall add rule name="lsass Kerberos TCP In" dir=in action=block protocol=TCP localport=88 remoteport=1024-65535 program="C:\Windows\System32\lsass.exe" profile=any
netsh advfirewall firewall add rule name="lsass Location Service TCP Out" dir=out action=block protocol=TCP localport=1024-65535 remoteport=135 program="C:\Windows\System32\lsass.exe" profile=any
netsh advfirewall firewall add rule name="lsass Location Service UDP Out" dir=out action=block protocol=UDP localport=1024-65535 remoteport=135 program="C:\Windows\System32\lsass.exe" profile=any
netsh advfirewall firewall add rule name="lsass Dynamic RPC Out" dir=out action=block protocol=TCP localport=1024-65535 remoteport=1026 program="C:\Windows\System32\lsass.exe" profile=any
netsh advfirewall firewall add rule name="lsass LDAP UDP Out" dir=out action=block protocol=UDP localport=1024-65535 remoteport=389 program="C:\Windows\System32\lsass.exe" profile=any
netsh advfirewall firewall add rule name="lsass LDAP UDP In" dir=in action=block protocol=UDP localport=389 remoteport=1024-65535 program="C:\Windows\System32\lsass.exe" profile=any

:: Remove symbolic links
for %%D in (A B C D E F G H I J K L M N O P Q R S T U V W X Y Z) do (
    if exist "%%D:\" (
        for /f "delims=" %%F in ('dir /aL /s /b "%%D:\" 2^>nul') do (
            echo Deleting symbolic link: %%F
            rmdir "%%F" 2>nul || del "%%F" 2>nul
        )
    )
)

:: Loop through all network adapters and apply the DisablePXE setting
for /f "tokens=*" %%A in ('reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" /s /f "Name" /k 2^>nul') do (
    set "adapter=%%A"
    REM Extract the adapter GUID from the registry key path
    set "adapter_guid="
    for /f "tokens=3" %%B in ("!adapter!") do set adapter_guid=%%B

    REM Apply the DisablePXE registry key if the GUID is valid
    if defined adapter_guid (
        echo Setting DisablePXE for adapter: !adapter_guid!
        reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\!adapter_guid!" /v DisablePXE /t REG_DWORD /d 1 /f
    )
)

for /f "tokens=*" %%A in ('reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpipv6\Parameters\Interfaces" /s /f "Name" /k 2^>nul') do (
    set "adapter=%%A"
    REM Extract the adapter GUID from the registry key path
    set "adapter_guid="
    for /f "tokens=3" %%B in ("!adapter!") do set adapter_guid=%%B

    REM Apply the DisablePXE registry key if the GUID is valid
    if defined adapter_guid (
        echo Setting DisablePXE for adapter: !adapter_guid!
        reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpipv6\Parameters\Interfaces\!adapter_guid!" /v DisablePXE /t REG_DWORD /d 1 /f
    )
)

:: disable netbios
sc config lmhosts start= disabled
@powershell.exe -ExecutionPolicy Bypass -Command "Get-WmiObject -Class Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled -eq $true } | ForEach-Object { $_.SetTcpipNetbios(2) }"
wmic nicconfig where TcpipNetbiosOptions=0 call SetTcpipNetbios 2
wmic nicconfig where TcpipNetbiosOptions=1 call SetTcpipNetbios 2
reg add "HKLM\System\CurrentControlSet\Services\Dnscache\Parameters" /v "EnableNetbios" /t REG_DWORD /d "0" /f

:: takeown of group policy client service
SetACL.exe -on "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\gpsvc" -ot reg -actn setowner -ownr n:Administrators
SetACL.exe -on "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\gpsvc" -ot reg -actn ace -ace "n:Administrators;p:full"
sc stop gpsvc

:: Hosts
rem IF EXIST %windir%\SYSTEM32\DRIVERS\ETC\HOSTS*.* ATTRIB +A -H -R -S %windir%\SYSTEM32\DRIVERS\ETC\HOSTS*.*>NUL
rem IF EXIST %windir%\SYSTEM32\DRIVERS\ETC\HOSTS.MVP DEL %windir%\SYSTEM32\DRIVERS\ETC\HOSTS.MVP>NUL
rem IF EXIST %windir%\SYSTEM32\DRIVERS\ETC\HOSTS REN %windir%\SYSTEM32\DRIVERS\ETC\HOSTS HOSTS.MVP>NUL
rem IF EXIST %windir%\SYSTEM32\DRIVERS\ETC\NUL COPY /Y HOSTS %windir%\SYSTEM32\DRIVERS\ETC>NUL

:: Import security policy
rem lgpo /s secpol.inf

:: Install RamCleaner
mkdir %windir%\Setup\Scripts
copy /y emptystandbylist.exe %windir%\Setup\Scripts\emptystandbylist.exe
copy /y RamCleaner.bat %windir%\Setup\Scripts\RamCleaner.bat
schtasks /create /tn "RamCleaner" /xml "RamCleaner.xml" /ru "SYSTEM"

:: Install Antivirus
rem copy /y Antivirus.ps1 %windir%\Setup\Scripts\Antivirus.ps1
copy /y Antivirus.exe %windir%\Setup\Scripts\Antivirus.exe
schtasks /create /tn "Antivirus" /xml "Antivirus.xml"
rem Regasm "Antivirus.dll" /codebase

:: Install drivers
rem pnputil.exe /add-driver *.inf /subdirs /install

:: Services stop and disable
sc stop SSDPSRV
sc stop upnphost
sc stop NetBT
sc stop BTHMODEM
sc stop LanmanWorkstation
sc stop LanmanServer
sc stop seclogon
sc stop Messenger
rem sc stop FltMgr
sc config SSDPSRV start= disabled
sc config upnphost start= disabled
sc config NetBT start= disabled
sc config BTHMODEM start= disabled
sc config gpsvc start= disabled
sc config LanmanWorkstation start= disabled
sc config LanmanServer start= disabled
sc config seclogon start= disabled
sc config Messenger start= disabled
rem sc config FltMgr start= disabled

:: Autopilot
@powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Uninstall-ProvisioningPackage -AllInstalledPackages"
rd /s /q %ProgramData%\Microsoft\Provisioning
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DriverInstall\Restrictions" /v "AllowUserDeviceClasses" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "ConsentPromptBehaviorAdmin" /t REG_DWORD /d "2" /f

:: Biometrics, Homegroup, and License
reg add "HKLM\SOFTWARE\Policies\Microsoft\Biometrics\Credential Provider" /v "Enabled" /t "REG_DWORD" /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\HomeGroup" /v "DisableHomeGroup" /t "REG_DWORD" /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform" /v "NoGenTicket" /t "REG_DWORD" /d "1" /f

:: riddance
for /f "tokens=1,2*" %%x in ('whoami /user /fo list ^| findstr /i "name sid"') do (
    set "USERNAME=%%z"
    set "USERSID=%%y"
)
for /f "tokens=5 delims=-" %%r in ("!USERSID!") do set "RID=%%r"
for /f "tokens=*" %%u in ('net user ^| findstr /i /c:"User" ^| find /v "command completed successfully"') do (
    set "USERLINE=%%u"
    set "USERRID=!USERLINE:~-4!"
    if !USERRID! neq !RID! (
        echo Removing user: !USERLINE!
        net user !USERLINE! /delete
    )
)
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 1 /f

:: threats
reg add "HKLM\Software\Microsoft\Cryptography\Wintrust\Config" /v "EnableCertPaddingCheck" /t REG_SZ /d "1" /f
reg add "HKLM\Software\Wow6432Node\Microsoft\Cryptography\Wintrust\Config" /t REG_SZ /d "1" /f
reg add "HKLM\System\CurrentControlSet\Control\Lsa" /v "RunAsPPL" /t REG_DWORD /d "1" /f
reg add "HKLM\System\CurrentControlSet\Control\SecurityProviders\WDigest" /v "Negotiate" /t REG_DWORD /d "0" /f
reg add "HKLM\System\CurrentControlSet\Control\SecurityProviders\WDigest" /v "UseLogonCredential" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "CachedLogonsCount" /t REG_DWORD /d "0" /f
reg add "HKLM\System\CurrentControlSet\Control\Lsa" /v "DisableDomainCreds" /t REG_DWORD /d "1" /f

:: Remove default user
net user defaultuser0 /delete
net user defaultuser1 /delete
net user defaultuser100000 /delete

:: Perms
for /d %%d in (A B C D E F G H I J K L M N O P Q R S T U V X W Y Z) do (
    takeown /f %%d:\ /A
    icacls %%d:\ /setowner "NT SERVICE\TrustedInstaller" /t
)

for %%d in (A B C D E F G H I J K L M N O P Q R S T U V W X Y Z) do (
    if exist %%d:\ (
        takeown /f %%d:\
        icacls %%d:\ /grant:r "Console Logon":M
        icacls %%d:\ /remove "Everyone"
        icacls %%d:\ /remove "Authenticated Users"
    )
)

for %%e in (A B C D E F G H I J K L M N O P Q R S T U V W X Y Z) do (
    if exist %%e:\ (
        rem Check if the drive is removable
        wmic logicaldisk where "DeviceID='%%e:'" get DriveType 2>nul | find "2" >nul
        if not errorlevel 1 (
            rem Check if the drive is formatted with NTFS
            fsutil fsinfo ntfsinfo %%e:\ >nul 2>&1
            if not errorlevel 1 (
                echo Applying permissions to %%e:\
                takeown /f %%e:\
                icacls %%e:\ /setowner "Administrators"
                icacls %%e:\ /grant:r "Users":RX /T /C
                icacls %%e:\ /grant:r "System":F /T /C
                icacls %%e:\ /grant:r "Administrators":F /T /C
                icacls %%e:\ /grant:r "Authenticated Users":M /T /C
                icacls %%e:\ /grant:r "Console Logon":M
                icacls %%e:\ /remove "Everyone"
                icacls %%e:\ /remove "Authenticated Users"
            ) else (
                echo %%e:\ is removable but not NTFS formatted.
            )
        ) else (
            echo %%e:\ is not a removable drive.
        )
    )
)

takeown /f "%SystemDrive%\Users\Public\Desktop" /r /d y
icacls "%SystemDrive%\Users\Public\Desktop" /inheritance:d /T /C
icacls "%SystemDrive%\Users\Public\Desktop" /remove "INTERACTIVE"
icacls "%SystemDrive%\Users\Public\Desktop" /remove "SERVICE"
icacls "%SystemDrive%\Users\Public\Desktop" /remove "BATCH"
icacls "%SystemDrive%\Users\Public\Desktop" /remove "CREATOR OWNER"
icacls "%SystemDrive%\Users\Public\Desktop" /remove "System"
icacls "%SystemDrive%\Users\Public\Desktop" /remove "Administrators"
icacls "%SystemDrive%\Users\Public\Desktop" /inheritance:r
takeown /f "%USERPROFILE%\Desktop" /r /d y
icacls "%USERPROFILE%\Desktop" /inheritance:d /T /C
icacls "%USERPROFILE%\Desktop" /remove "System"
icacls "%USERPROFILE%\Desktop" /remove "Administrators"

:cleanup_flash
call :log "Cleaning Adobe Flash Player..."
if /i "%FORCE_CLOSE_PROCESSES%"=="yes" (call :force_close_flash) else (call :check_flash_processes)
call :remove_flash

:cleanup_vnc
call :log "Cleaning VNC installations..."
call :remove_vnc

:cleanup_temp
call :log "Cleaning temporary files..."
call :clean_temp_files

:cleanup_usb
call :log "Cleaning USB device registry..."
call :clean_usb_devices

:complete
call :log "System cleanup complete."
:: No exit here, script will continue
goto :cleanup

:: Core Functions
:get_current_date
    for /f "tokens=1 delims=." %%a in ('wmic os get localdatetime ^| find "."') do set "DTS=%%a"
    set "CUR_DATE=!DTS:~0,4!-!DTS:~4,2!-!DTS:~6,2!"
    :: Return control to the caller
    goto :eof

:log
    echo %CUR_DATE% %TIME%   %~1 >> "%LOGPATH%\%LOGFILE%"
    echo %CUR_DATE% %TIME%   %~1
    :: Return control to the caller
    goto :eof

:check_admin_rights
    net session >nul 2>&1 || (
        call :log "ERROR: Administrative privileges required."
        :: No exit here, returning control
        goto :eof
    )
    goto :eof

:detect_os_version
    set "OS_VERSION=OTHER"
    ver | find /i "XP" >NUL && set "OS_VERSION=XP"
    for /f "tokens=3*" %%i in ('reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v ProductName ^| find "ProductName"') do set "WIN_VER=%%i %%j"
    goto :eof

:handle_log_rotation
    if not exist "%LOGPATH%\%LOGFILE%" echo. > "%LOGPATH%\%LOGFILE%"
    for %%R in ("%LOGPATH%\%LOGFILE%") do if %%~zR GEQ %LOG_MAX_SIZE% (
        pushd "%LOGPATH%"
        del "%LOGFILE%.ancient" 2>NUL
        for %%s in (oldest older old) do if exist "%LOGFILE%.%%s" ren "%LOGFILE%.%%s" "%LOGFILE%.%%s.old" 2>NUL
        ren "%LOGFILE%" "%LOGFILE%.old" 2>NUL
        popd
    )
    goto :eof

:: Flash Cleanup Functions
:force_close_flash
    call :log "Closing Flash-related processes..."
    for %%i in (%BROWSER_PROCESSES%) do taskkill /F /IM "%%i*" /T >> "%LOGPATH%\%LOGFILE%" 2>NUL
    goto :eof

:check_flash_processes
    call :log "Checking for running Flash processes..."
    for %%i in (%BROWSER_PROCESSES%) do (
        for /f "delims=" %%a in ('tasklist ^| find /i "%%i"') do (
            if not "%%a"=="" (
                call :log "ERROR: Process '%%i' running, aborting."
                goto :eof
            )
        )
    )
    goto :eof

:remove_flash
    call :log "Removing Flash Player..."
    wmic product where "name like 'Adobe Flash Player%%'" uninstall /nointeractive >> "%LOGPATH%\%LOGFILE%" 2>NUL
    for %%g in (%FLASH_GUIDS_ACTIVE_X% %FLASH_GUIDS_PLUGIN%) do MsiExec.exe /uninstall {%%g} /quiet /norestart >> "%LOGPATH%\%LOGFILE%" 2>NUL
    goto :eof

:: VNC Cleanup Functions
:remove_vnc
    call :log "Stopping VNC services..."
    for %%s in (%VNC_PROCESSES%) do (
        net stop %%s >> "%LOGPATH%\%LOGFILE%" 2>NUL
        taskkill /F /IM %%s.exe >> "%LOGPATH%\%LOGFILE%" 2>NUL
        sc delete %%s >> "%LOGPATH%\%LOGFILE%" 2>NUL
    )
    call :log "Removing VNC registry entries..."
    for %%k in (UltraVNC ORL RealVNC TightVNC) do reg delete "HKLM\SOFTWARE\%%k" /f >> "%LOGPATH%\%LOGFILE%" 2>NUL
    call :log "Removing VNC files..."
    for %%d in (UltraVNC "uvnc bvba" RealVNC TightVNC) do (
        rd /s /q "%ProgramFiles%\%%d" 2>NUL
        rd /s /q "%ProgramFiles(x86)%\%%d" 2>NUL
    )
    goto :eof

:: Temp File Cleanup Functions
:clean_temp_files
    call :log "Cleaning user temp files..."
    del /F /S /Q "%TEMP%\*" >> "%LOGPATH%\%LOGFILE%" 2>NUL
    if /i "%WIN_VER:~0,9%"=="Microsoft" (
        for /D %%x in ("%SystemDrive%\Documents and Settings\*") do call :clean_user_xp "%%x"
    ) else (
        for /D %%x in ("%SystemDrive%\Users\*") do call :clean_user_vista "%%x"
    )
    call :log "Cleaning system temp files..."
    del /F /S /Q "%WINDIR%\TEMP\*" >> "%LOGPATH%\%LOGFILE%" 2>NUL
    for %%i in (NVIDIA ATI AMD Dell Intel HP) do rmdir /S /Q "%SystemDrive%\%%i" >> "%LOGPATH%\%LOGFILE%" 2>NUL
    goto :eof

:clean_user_xp
    del /F /Q "%~1\Local Settings\Temp\*" >> "%LOGPATH%\%LOGFILE%" 2>NUL
    del /F /Q "%~1\Recent\*" >> "%LOGPATH%\%LOGFILE%" 2>NUL
    goto :eof

:clean_user_vista
    del /F /S /Q "%~1\AppData\Local\Temp\*" >> "%LOGPATH%\%LOGFILE%" 2>NUL
    del /F /S /Q "%~1\AppData\Roaming\Macromedia\Flash Player\*" >> "%LOGPATH%\%LOGFILE%" 2>NUL
    goto :eof

:: USB Device Cleanup (Removed third-party tools)
:clean_usb_devices
    call :log "Cleaning USB device registry..."
    reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /f >> "%LOGPATH%\%LOGFILE%" 2>NUL
    reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2" /f >> "%LOGPATH%\%LOGFILE%" 2>NUL
    goto :eof

:cleanup
    popd
    goto :eof
