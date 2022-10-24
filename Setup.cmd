<!-- : Begin batch script
@cls
@echo off
>nul chcp 437
setlocal enabledelayedexpansion
title GSecurity & color 0b
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
call %~dp0\Bin\GSecurity.bat
Reg.exe import %~dp0\Bin\GSecurity.reg
exit
:IsAdmin
@powershell.exe Start-Process %~f0 -verb runas
exit