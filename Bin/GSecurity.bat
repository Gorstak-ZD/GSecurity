:: Title
Title GSecurity & color 0b
echo == Installing GSecurity

:: Active folder
pushd %~dp0

:: Take ownership of Desktop
takeown /f "%SystemDrive%\Users\Public\Desktop" /r /d y
icacls "%SystemDrive%\Users\Public\Desktop" /inheritance:r
icacls "%SystemDrive%\Users\Public\Desktop" /grant:r "%username%":(OI)(CI)F /t /l /q /c
takeown /f "%USERPROFILE%\Desktop" /r /d y
icacls "%USERPROFILE%\Desktop" /inheritance:r
icacls "%USERPROFILE%\Desktop" /grant:r "%username%":(OI)(CI)F /t /l /q /c

:: Firewall cleanup
netsh advfirewall firewall delete rule name=all

:: Registry
Reg.exe import Asc.reg
Reg.exe import Certs.reg
Reg.exe import Firewall.reg
Reg.exe import Immunity.reg
Reg.exe import Privacy.reg
Reg.exe import Routes.reg
Reg.exe import Safer.reg
Reg.exe import Services.reg
Reg.exe import Tuneup.reg

:: Exit
exit