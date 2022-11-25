:: Title
Title GBrowser & color 0b

:: Active folder
pushd %~dp0

@echo off
:: Download Comodo Dragon
echo == Downloading and installing Comodo Dragon
curl -# https://cdn.download.comodo.com/browser/release/dragon/x86/dragonsetup.exe -o %userprofile%\Downloads\dragonsetup.exe
Start /wait "" %userprofile%\Downloads\dragonsetup.exe /S
del /f /q %userprofile%\Downloads\dragonsetup.exe
robocopy %~dp0 "%localappdata%\Comodo\Dragon\User Data\Default" Bookmarks /R:5 /ETA
Reg.exe import Extensions.reg