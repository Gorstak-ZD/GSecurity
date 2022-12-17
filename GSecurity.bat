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
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Settings" /v "AllowRemoteRPC" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\WinRS" /v "AllowRemoteShellAccess" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "ForceActiveDesktopOn" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoActiveDesktop" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoActiveDesktopChanges" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoComponents" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoInstrumentation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Terminal Server" /v "AllowTSConnections" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Terminal Server" /v "DenyTSConnections" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Terminal Server" /v "fDenyTSConnections" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Remote Assistance" /v "AllowToGetHelp" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Remote Assistance" /v "fAllowToGetHelp" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\SecurePipeServers\winreg" /v "remoteregaccess" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall" /v "IPSecExempt" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall" /v "PolicyVersion" /t REG_DWORD /d "538" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" /v "AllowLocalIPsecPolicyMerge" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" /v "AllowLocalPolicyMerge" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" /v "DefaultInboundAction" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" /v "DefaultOutboundAction" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" /v "DisableNotifications" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" /v "DisableUnicastResponsesToMulticastBroadcast" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" /v "EnableFirewall" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\RemoteAdminSettings" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Services\FileAndPrint" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Services\RemoteDesktop" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "1" /t REG_SZ /d "v2.32|Action=Block|Active=TRUE|Dir=In|Name=1|Desc=Block all inbound except console logon|LUAuth=O:LSD:(D;;CC;;;S-1-2-1)|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "2" /t REG_SZ /d "v2.32|Action=Block|Active=TRUE|Dir=In|Protocol=6|LPort2_10=1-66|LPort2_10=69-55554|LPort2_10=55557-65535|Name=2|Desc=Block all inbound TCP except DHCP, and ports 55555-6 (if you need an open port)|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "3" /t REG_SZ /d "v2.32|Action=Block|Active=TRUE|Dir=In|Protocol=17|LPort2_10=1-66|LPort2_10=69-55554|LPort2_10=55557-65535|Name=3|Desc=Block all inbound UDP except DHCP, and ports 55555-6 (if you need an open port)|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "4" /t REG_SZ /d "v2.32|Action=Block|Active=TRUE|Dir=Out|Name=4|Desc=Block all outbound connections except console logon|LUAuth=O:LSD:(D;;CC;;;S-1-2-1)|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "5" /t REG_SZ /d "v2.32|Action=Allow|Active=TRUE|Dir=Out|Name=5|Desc=Allow all outgoing traffic to console logon|LUAuth=O:LSD:(A;;CC;;;S-1-2-1)|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "6" /t REG_SZ /d "v2.32|Action=Allow|Active=TRUE|Dir=Out|Protocol=6|LPort2_10=67-68|LPort2_10=55555-55556|Name=6|Desc=Allow traffic to DHCP and anything you binded to ports 55555-6|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "CoreNet-DHCP-In" /t REG_SZ /d "v2.31|Action=Allow|Active=TRUE|Dir=In|Protocol=17|LPort=68|RPort=67|App=%%SystemRoot%%\system32\svchost.exe|Svc=dhcp|Name=@FirewallAPI.dll,-25301|Desc=@FirewallAPI.dll,-25303|EmbedCtxt=@FirewallAPI.dll,-25000|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "RemoteDesktop-Shadow-In-TCP" /t REG_SZ /d "v2.28|Action=Block|Active=TRUE|Dir=In|Protocol=6|App=%%SystemRoot%%\system32\RdpSa.exe|Name=@FirewallAPI.dll,-28778|Desc=@FirewallAPI.dll,-28779|EmbedCtxt=@FirewallAPI.dll,-28752|Edge=TRUE|Defer=App|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "RemoteDesktop-UserMode-In-TCP" /t REG_SZ /d "v2.28|Action=Block|Active=TRUE|Dir=In|Protocol=6|LPort=3389|App=%%SystemRoot%%\system32\svchost.exe|Svc=termservice|Name=@FirewallAPI.dll,-28775|Desc=@FirewallAPI.dll,-28756|EmbedCtxt=@FirewallAPI.dll,-28752|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "RemoteDesktop-UserMode-In-UDP" /t REG_SZ /d "v2.28|Action=Block|Active=TRUE|Dir=In|Protocol=17|LPort=3389|App=%%SystemRoot%%\system32\svchost.exe|Svc=termservice|Name=@FirewallAPI.dll,-28776|Desc=@FirewallAPI.dll,-28777|EmbedCtxt=@FirewallAPI.dll,-28752|" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile" /v "AllowLocalIPsecPolicyMerge" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile" /v "AllowLocalPolicyMerge" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile" /v "DefaultInboundAction" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile" /v "DefaultOutboundAction" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile" /v "DisableNotifications" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile" /v "DisableUnicastResponsesToMulticastBroadcast" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile" /v "EnableFirewall" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\RemoteAdminSettings" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Services\FileAndPrint" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Services\RemoteDesktop" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" /v "AllowLocalIPsecPolicyMerge" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" /v "AllowLocalPolicyMerge" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" /v "DefaultInboundAction" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" /v "DefaultOutboundAction" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" /v "DisableNotifications" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" /v "DisableUnicastResponsesToMulticastBroadcast" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" /v "EnableFirewall" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\RemoteAdminSettings" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Services\FileAndPrint" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Services\RemoteDesktop" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile" /v "AllowLocalIPsecPolicyMerge" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile" /v "AllowLocalPolicyMerge" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile" /v "DefaultInboundAction" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile" /v "DefaultOutboundAction" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile" /v "DisableNotifications" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile" /v "DisableUnicastResponsesToMulticastBroadcast" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile" /v "EnableFirewall" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile\RemoteAdminSettings" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile\Services\FileAndPrint" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile\Services\RemoteDesktop" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile" /v "AllowLocalIPsecPolicyMerge" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile" /v "AllowLocalPolicyMerge" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile" /v "DefaultInboundAction" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile" /v "DefaultOutboundAction" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile" /v "DisableNotifications" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile" /v "DisableUnicastResponsesToMulticastBroadcast" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile" /v "EnableFirewall" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile\RemoteAdminSettings" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile\Services\FileAndPrint" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile\Services\RemoteDesktop" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules" /v "1" /t REG_SZ /d "v2.32|Action=Block|Active=TRUE|Dir=In|Name=1|Desc=Block all inbound except console logon|LUAuth=O:LSD:(D;;CC;;;S-1-2-1)|" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules" /v "2" /t REG_SZ /d "v2.32|Action=Block|Active=TRUE|Dir=In|Protocol=6|LPort2_10=1-66|LPort2_10=69-55554|LPort2_10=55557-65535|Name=2|Desc=Block all inbound TCP except DHCP, and ports 55555-6 (if you need an open port)|" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules" /v "3" /t REG_SZ /d "v2.32|Action=Block|Active=TRUE|Dir=In|Protocol=17|LPort2_10=1-66|LPort2_10=69-55554|LPort2_10=55557-65535|Name=3|Desc=Block all inbound UDP except DHCP, and ports 55555-6 (if you need an open port)|" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules" /v "4" /t REG_SZ /d "v2.32|Action=Block|Active=TRUE|Dir=Out|Name=4|Desc=Block all outbound connections except console logon|LUAuth=O:LSD:(D;;CC;;;S-1-2-1)|" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules" /v "5" /t REG_SZ /d "v2.32|Action=Allow|Active=TRUE|Dir=Out|Name=5|Desc=Allow all outgoing traffic to console logon|LUAuth=O:LSD:(A;;CC;;;S-1-2-1)|" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules" /v "6" /t REG_SZ /d "v2.32|Action=Allow|Active=TRUE|Dir=Out|Protocol=6|LPort2_10=67-68|LPort2_10=55555-55556|Name=6|Desc=Allow traffic to DHCP and anything you binded to ports 55555-6|" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules" /v "CoreNet-DHCP-In" /t REG_SZ /d "v2.31|Action=Allow|Active=TRUE|Dir=In|Protocol=17|LPort=68|RPort=67|App=%%SystemRoot%%\system32\svchost.exe|Svc=dhcp|Name=@FirewallAPI.dll,-25301|Desc=@FirewallAPI.dll,-25303|EmbedCtxt=@FirewallAPI.dll,-25000|" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules" /v "RemoteDesktop-Shadow-In-TCP" /t REG_SZ /d "v2.28|Action=Block|Active=TRUE|Dir=In|Protocol=6|App=%%SystemRoot%%\system32\RdpSa.exe|Name=@FirewallAPI.dll,-28778|Desc=@FirewallAPI.dll,-28779|EmbedCtxt=@FirewallAPI.dll,-28752|Edge=TRUE|Defer=App|" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules" /v "RemoteDesktop-UserMode-In-TCP" /t REG_SZ /d "v2.28|Action=Block|Active=TRUE|Dir=In|Protocol=6|LPort=3389|App=%%SystemRoot%%\system32\svchost.exe|Svc=termservice|Name=@FirewallAPI.dll,-28775|Desc=@FirewallAPI.dll,-28756|EmbedCtxt=@FirewallAPI.dll,-28752|" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules" /v "RemoteDesktop-UserMode-In-UDP" /t REG_SZ /d "v2.28|Action=Block|Active=TRUE|Dir=In|Protocol=17|LPort=3389|App=%%SystemRoot%%\system32\svchost.exe|Svc=termservice|Name=@FirewallAPI.dll,-28776|Desc=@FirewallAPI.dll,-28777|EmbedCtxt=@FirewallAPI.dll,-28752|" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\PrivateProfile" /v "AllowLocalIPsecPolicyMerge" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\PrivateProfile" /v "AllowLocalPolicyMerge" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\PrivateProfile" /v "DefaultInboundAction" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\PrivateProfile" /v "DefaultOutboundAction" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\PrivateProfile" /v "DisableNotifications" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\PrivateProfile" /v "DisableUnicastResponsesToMulticastBroadcast" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\PrivateProfile" /v "EnableFirewall" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\PrivateProfile\RemoteAdminSettings" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\PrivateProfile\Services\FileAndPrint" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\PrivateProfile\Services\RemoteDesktop" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile" /v "AllowLocalIPsecPolicyMerge" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile" /v "AllowLocalPolicyMerge" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile" /v "DefaultInboundAction" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile" /v "DefaultOutboundAction" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile" /v "DisableNotifications" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile" /v "DisableUnicastResponsesToMulticastBroadcast" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile" /v "EnableFirewall" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile\RemoteAdminSettings" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile\Services\FileAndPrint" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile\Services\RemoteDesktop" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile" /v "AllowLocalIPsecPolicyMerge" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile" /v "AllowLocalPolicyMerge" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile" /v "DefaultInboundAction" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile" /v "DefaultOutboundAction" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile" /v "DisableNotifications" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile" /v "DisableUnicastResponsesToMulticastBroadcast" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile" /v "EnableFirewall" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile\RemoteAdminSettings" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile\Services\FileAndPrint" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile\Services\RemoteDesktop" /v "Enabled" /t REG_DWORD /d "0" /f
rd /s /q %ProgramData%\Microsoft\Provisioning
@powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Uninstall-ProvisioningPackage -AllInstalledPackages"
c:
cd\
takeown /f a:
icacls a: /grant:r "CONSOLE LOGON":(OI)(CI)F
icacls a: /grant:r Administrators:(OI)(CI)F
icacls a: /grant:r System:(OI)(CI)F
icacls a: /remove "Users"
icacls a: /remove "Authenticated Users"
icacls a: /remove "Everyone"
takeown /f b:
icacls b: /grant:r "CONSOLE LOGON":(OI)(CI)F
icacls b: /grant:r Administrators:(OI)(CI)F
icacls b: /grant:r System:(OI)(CI)F
icacls b: /remove "Users"
icacls b: /remove "Authenticated Users"
icacls b: /remove "Everyone"
takeown /f c:
icacls c: /grant:r "%username%":(OI)(CI)F
icacls c: /grant:r "CONSOLE LOGON":(OI)(CI)F
icacls c: /remove "Authenticated Users"
icacls c: /remove "Users"
takeown /f d:
icacls d: /grant:r "CONSOLE LOGON":(OI)(CI)F
icacls d: /grant:r Administrators:(OI)(CI)F
icacls d: /grant:r System:(OI)(CI)F
icacls d: /remove "Users"
icacls d: /remove "Authenticated Users"
icacls d: /remove "Everyone"
takeown /f e:
icacls e: /grant:r "CONSOLE LOGON":(OI)(CI)F
icacls e: /grant:r Administrators:(OI)(CI)F
icacls e: /grant:r System:(OI)(CI)F
icacls e: /remove "Users"
icacls e: /remove "Authenticated Users"
icacls e: /remove "Everyone"
takeown /f f:
icacls f: /grant:r "CONSOLE LOGON":(OI)(CI)F
icacls f: /grant:r Administrators:(OI)(CI)F
icacls f: /grant:r System:(OI)(CI)F
icacls f: /remove "Users"
icacls f: /remove "Authenticated Users"
icacls f: /remove "Everyone"
takeown /f g:
icacls g: /grant:r "CONSOLE LOGON":(OI)(CI)F
icacls g: /grant:r Administrators:(OI)(CI)F
icacls g: /grant:r System:(OI)(CI)F
icacls g: /remove "Users"
icacls g: /remove "Authenticated Users"
icacls g: /remove "Everyone"
takeown /f h:
icacls h: /grant:r "CONSOLE LOGON":(OI)(CI)F
icacls h: /grant:r Administrators:(OI)(CI)F
icacls h: /grant:r System:(OI)(CI)F
icacls h: /remove "Users"
icacls h: /remove "Authenticated Users"
icacls h: /remove "Everyone"
takeown /f i:
icacls i: /grant:r "CONSOLE LOGON":(OI)(CI)F
icacls i: /grant:r Administrators:(OI)(CI)F
icacls i: /grant:r System:(OI)(CI)F
icacls i: /remove "Users"
icacls i: /remove "Authenticated Users"
icacls i: /remove "Everyone"
takeown /f j:
icacls j: /grant:r "CONSOLE LOGON":(OI)(CI)F
icacls j: /grant:r Administrators:(OI)(CI)F
icacls j: /grant:r System:(OI)(CI)F
icacls j: /remove "Users"
icacls j: /remove "Authenticated Users"
icacls j: /remove "Everyone"
takeown /f k:
icacls k: /grant:r "CONSOLE LOGON":(OI)(CI)F
icacls k: /grant:r Administrators:(OI)(CI)F
icacls k: /grant:r System:(OI)(CI)F
icacls k: /remove "Users"
icacls k: /remove "Authenticated Users"
icacls k: /remove "Everyone"
takeown /f l:
icacls l: /grant:r "CONSOLE LOGON":(OI)(CI)F
icacls l: /grant:r Administrators:(OI)(CI)F
icacls l: /grant:r System:(OI)(CI)F
icacls l: /remove "Users"
icacls l: /remove "Authenticated Users"
icacls l: /remove "Everyone"
takeown /f m:
icacls m: /grant:r "CONSOLE LOGON":(OI)(CI)F
icacls m: /grant:r Administrators:(OI)(CI)F
icacls m: /grant:r System:(OI)(CI)F
icacls m: /remove "Users"
icacls m: /remove "Authenticated Users"
icacls m: /remove "Everyone"
takeown /f n:
icacls n: /grant:r "CONSOLE LOGON":(OI)(CI)F
icacls n: /grant:r Administrators:(OI)(CI)F
icacls n: /grant:r System:(OI)(CI)F
icacls n: /remove "Users"
icacls n: /remove "Authenticated Users"
icacls n: /remove "Everyone"
takeown /f o:
icacls o: /grant:r "CONSOLE LOGON":(OI)(CI)F
icacls o: /grant:r Administrators:(OI)(CI)F
icacls o: /grant:r System:(OI)(CI)F
icacls o: /remove "Users"
icacls o: /remove "Authenticated Users"
icacls o: /remove "Everyone"
takeown /f p:
icacls p: /grant:r "CONSOLE LOGON":(OI)(CI)F
icacls p: /grant:r Administrators:(OI)(CI)F
icacls p: /grant:r System:(OI)(CI)F
icacls p: /remove "Users"
icacls p: /remove "Authenticated Users"
icacls p: /remove "Everyone"
takeown /f q:
icacls q: /grant:r "CONSOLE LOGON":(OI)(CI)F
icacls q: /grant:r Administrators:(OI)(CI)F
icacls q: /grant:r System:(OI)(CI)F
icacls q: /remove "Users"
icacls q: /remove "Authenticated Users"
icacls q: /remove "Everyone"
takeown /f r:
icacls r: /grant:r "CONSOLE LOGON":(OI)(CI)F
icacls r: /grant:r Administrators:(OI)(CI)F
icacls r: /grant:r System:(OI)(CI)F
icacls r: /remove "Users"
icacls r: /remove "Authenticated Users"
icacls r: /remove "Everyone"
takeown /f s:
icacls s: /grant:r "CONSOLE LOGON":(OI)(CI)F
icacls s: /grant:r Administrators:(OI)(CI)F
icacls s: /grant:r System:(OI)(CI)F
icacls s: /remove "Users"
icacls s: /remove "Authenticated Users"
icacls s: /remove "Everyone"
takeown /f t:
icacls t: /grant:r "CONSOLE LOGON":(OI)(CI)F
icacls t: /grant:r Administrators:(OI)(CI)F
icacls t: /grant:r System:(OI)(CI)F
icacls t: /remove "Users"
icacls t: /remove "Authenticated Users"
icacls t: /remove "Everyone"
takeown /f u:
icacls u: /grant:r "CONSOLE LOGON":(OI)(CI)F
icacls u: /grant:r Administrators:(OI)(CI)F
icacls u: /grant:r System:(OI)(CI)F
icacls u: /remove "Users"
icacls u: /remove "Authenticated Users"
icacls u: /remove "Everyone"
takeown /f v:
icacls v: /grant:r "CONSOLE LOGON":(OI)(CI)F
icacls v: /grant:r Administrators:(OI)(CI)F
icacls v: /grant:r System:(OI)(CI)F
icacls v: /remove "Users"
icacls v: /remove "Authenticated Users"
icacls v: /remove "Everyone"
takeown /f w:
icacls w: /grant:r "CONSOLE LOGON":(OI)(CI)F
icacls w: /grant:r Administrators:(OI)(CI)F
icacls w: /grant:r System:(OI)(CI)F
icacls w: /remove "Users"
icacls w: /remove "Authenticated Users"
icacls w: /remove "Everyone"
takeown /f x:
icacls x: /grant:r "CONSOLE LOGON":(OI)(CI)F
icacls x: /grant:r Administrators:(OI)(CI)F
icacls x: /grant:r System:(OI)(CI)F
icacls x: /remove "Users"
icacls x: /remove "Authenticated Users"
icacls x: /remove "Everyone"
takeown /f y:
icacls y: /grant:r "CONSOLE LOGON":(OI)(CI)F
icacls y: /grant:r Administrators:(OI)(CI)F
icacls y: /grant:r System:(OI)(CI)F
icacls y: /remove "Users"
icacls y: /remove "Authenticated Users"
icacls y: /remove "Everyone"
takeown /f z:
icacls z: /grant:r "CONSOLE LOGON":(OI)(CI)F
icacls z: /grant:r Administrators:(OI)(CI)F
icacls z: /grant:r System:(OI)(CI)F
icacls z: /remove "Users"
icacls z: /remove "Authenticated Users"
icacls z: /remove "Everyone"
takeown /f "%SystemDrive%\Users\Public\Desktop" /r /d y
icacls "%SystemDrive%\Users\Public\Desktop" /inheritance:r
icacls "%SystemDrive%\Users\Public\Desktop" /grant:r "%username%":(OI)(CI)F /t /l /q /c
takeown /f "%USERPROFILE%\Desktop" /r /d y
icacls "%USERPROFILE%\Desktop" /inheritance:r
icacls "%USERPROFILE%\Desktop" /grant:r "%username%":(OI)(CI)F /t /l /q /c
exit
:IsAdmin
@powershell.exe Start-Process %~f0 -verb runas
exit