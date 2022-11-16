:: Title
Title GSecurity & color 0b
echo == Installing GSecurity

:: Active folder
pushd %~dp0

:: Install filters
pnputil.exe /add-driver *.inf /subdirs /install

:: Disallow certificates
Reg import GSecurity.reg

:: Exit
exit