:: Title
Title GSecurity & color 0b
echo == Installing GSecurity

:: Reset policies
rd /s /q %windir%\system32\grouppolicy
rd /s /q %windir%\system32\grouppolicyusers
rd /s /q %windir%\syswow64\grouppolicy
rd /s /q %windir%\syswow64\grouppolicyusers
reg delete HKLM\Software\Policies
reg delete HKCU\SOFTWARE\Policies

:: Import policies
lgpo /g %~dp0
netsh advfirewall import %~dp0GSecurity.wfw