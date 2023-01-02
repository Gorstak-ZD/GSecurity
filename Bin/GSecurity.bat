:: Title
Title GSecurity & color 0b
echo == Installing GSecurity

:: Active folder
pushd %~dp0

:: Security policy
lgpo.exe /g %~dp0

:: Exit
exit