:: Title
Title GSecurity & color 0b
echo == Installing GSecurity

:: Active folder
pushd %~dp0

:: Debloat
@powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0remove-default-apps.ps1"
@powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Get-ProvisionedAppxPackage -Online | Remove-ProvisionedAppxPackage -Online"
cleanmgr /sagerun:65535

:: Policies
Reg import HKCUPolicy.reg
Reg import HKLMPolicy.reg

:: Services
Reg import Services.reg

:: Performance
Reg import Performance.reg

:: Security
Reg import GSecurity.reg

:: Exit
exit