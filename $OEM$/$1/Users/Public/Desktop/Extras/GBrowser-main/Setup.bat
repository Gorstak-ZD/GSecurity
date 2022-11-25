<!-- : Begin batch script
@cls
@echo off
>nul chcp 437
setlocal enabledelayedexpansion
title GBrowser & color 0B
>nul 2>&1 where powershell || (
	echo.
	echo Missing Critical files [powershell.exe]
	echo.
	pause
	exit /b
)
fsutil dirty query %systemdrive% >nul
if %errorlevel% == 0 (
    goto:start
) else (
    call :IsAdmin
) 
:start
cls
call %~dp0\Bin\GBrowser.bat
exit
:IsAdmin
@powershell.exe Start-Process %~f0 -verb runas
exit