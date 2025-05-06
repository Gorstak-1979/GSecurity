@echo off

:: Step 1: Elevate
>nul 2>&1 fsutil dirty query %systemdrive% || echo CreateObject^("Shell.Application"^).ShellExecute "%~0", "ELEVATED", "", "runas", 1 > "%temp%\uac.vbs" && "%temp%\uac.vbs" && exit /b
DEL /F /Q "%temp%\uac.vbs"

:: Script Metadata
set "SCRIPT_NAME=GSecurity"
set "SCRIPT_VERSION=11.2.0"
set "SCRIPT_UPDATED=02-04-2025"
set "AUTHOR=Gorstak"
Title GSecurity && Color 0b

:: Step 2: Prep environment 
cd /d %~dp0
cd Bin
setlocal EnableExtensions EnableDelayedExpansion

:: Step 3: Execute PowerShell (.ps1) files alphabetically
for /f "tokens=*" %%P in ('dir /b /o:n *.ps1') do (
    start "" powershell -WindowStyle Hidden -ExecutionPolicy Bypass -File "%%P"
)

:: Step 4: Execute CMD (.cmd) files alphabetically
for /f "tokens=*" %%C in ('dir /b /o:n *.cmd') do (
    call "%%C"
)

:: Step 5: Execute Registry (.reg) files alphabetically
for /f "tokens=*" %%R in ('dir /b /o:n *.reg') do (
    reg import "%%R"
)

:: Step 6: Restart
shutdown /r /t 0