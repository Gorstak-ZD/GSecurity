:: Title
Title GSecurity & color 0b
echo == Installing GSecurity

:: Reset policies
rd /s /q %windir%\system32\grouppolicy
rd /s /q %windir%\system32\grouppolicyusers
rd /s /q %windir%\syswow64\grouppolicy
rd /s /q %windir%\syswow64\grouppolicyusers
reg delete HKLM\Software\Policies /f
reg delete HKCU\SOFTWARE\Policies /f

:: Import policies
lgpo /g %~dp0
