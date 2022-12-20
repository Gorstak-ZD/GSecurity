:: Title
Title GSecurity & color 0b
echo == Installing GSecurity

:: Active folder
pushd %~dp0

:: Security policy
lgpo.exe /s GSecurity.inf

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

:: Remove Pester
takeown /f "%ProgramFiles%\WindowsPowerShell" /r /d y
icacls "%ProgramFiles%\WindowsPowerShell" /inheritance:r /grant:r "%username%":(OI)(CI)F /t /l /q /c
rd /s /q "%ProgramFiles%\WindowsPowerShell"
takeown /f "%ProgramFiles(x86)%\WindowsPowerShell" /r /d y
icacls "%ProgramFiles(x86)%\WindowsPowerShell" /inheritance:r /grant:r "%username%":(OI)(CI)F /t /l /q /c
rd /s /q "%ProgramFiles(x86)%\WindowsPowerShell"

:: Block logons
takeown /f %SystemDrive%\Windows\System32\winlogon.exe
icacls "%SystemDrive%\Windows\System32\winlogon.exe" /inheritance:d
icacls "%SystemDrive%\Windows\System32\winlogon.exe" /remove "All Application Packages"
icacls "%SystemDrive%\Windows\System32\winlogon.exe" /remove "All Restricted Application Packages"
icacls "%SystemDrive%\Windows\System32\winlogon.exe" /remove "Authenticated Users"
icacls "%SystemDrive%\Windows\System32\winlogon.exe" /remove "Users"
icacls "%SystemDrive%\Windows\System32\winlogon.exe" /remove "TrustedInstaller"
icacls "%SystemDrive%\Windows\System32\winlogon.exe" /deny "Network":F
takeown /f %SystemDrive%\Windows\System32\logonui.exe
icacls "%SystemDrive%\Windows\System32\logonui.exe" /inheritance:d
icacls "%SystemDrive%\Windows\System32\logonui.exe" /remove "All Application Packages"
icacls "%SystemDrive%\Windows\System32\logonui.exe" /remove "All Restricted Application Packages"
icacls "%SystemDrive%\Windows\System32\logonui.exe" /remove "Authenticated Users"
icacls "%SystemDrive%\Windows\System32\logonui.exe" /remove "Users"
icacls "%SystemDrive%\Windows\System32\logonui.exe" /remove "TrustedInstaller"
icacls "%SystemDrive%\Windows\System32\logonui.exe" /deny "Network":F

:: Take ownership of Desktop
takeown /f "%SystemDrive%\Users\Public\Desktop" /r /d y
icacls "%SystemDrive%\Users\Public\Desktop" /inheritance:r
icacls "%SystemDrive%\Users\Public\Desktop" /grant:r "%username%":(OI)(CI)F /t /l /q /c
takeown /f "%USERPROFILE%\Desktop" /r /d y
icacls "%USERPROFILE%\Desktop" /inheritance:r
icacls "%USERPROFILE%\Desktop" /grant:r "%username%":(OI)(CI)F /t /l /q /c

:: Pagefile
wmic computersystem where name="%computername%" set AutomaticManagedPagefile=True

:: Hosts
(
echo # GSecurity
echo 0.0.0.0 url1
echo # Steven Black suggested
echo 127.0.0.1 localhost
echo 127.0.0.1 localhost.localdomain
echo 127.0.0.1 local
echo 255.255.255.255 broadcasthost
echo ::1 localhost
echo ::1 ip6-localhost
echo ::1 ip6-loopback
echo fe80::1%lo0 localhost
echo ff00::0 ip6-localnet
echo ff00::0 ip6-mcastprefix
echo ff02::1 ip6-allnodes
echo ff02::2 ip6-allrouters
echo ff02::3 ip6-allhosts
echo 0.0.0.0 echo 0.0.0.0
echo # this is a list of the most popular ads companies blocked
echo 0.0.0.0 adtago.s3.amazonaws.com
echo 0.0.0.0 analyticsengine.s3.amazonaws.com
echo 0.0.0.0 advice-ads.s3.amazonaws.com
echo 0.0.0.0 affiliationjs.s3.amazonaws.com
echo 0.0.0.0 advertising-api-eu.amazon.com
echo 0.0.0.0 ssl.google-analytics.com
echo 0.0.0.0 fastclick.com
echo 0.0.0.0 fastclick.net
echo 0.0.0.0 media.fastclick.net
echo 0.0.0.0 cdn.fastclick.net
echo 0.0.0.0 analytics.yahoo.com
echo 0.0.0.0 global.adserver.yahoo.com
echo 0.0.0.0 ads.yap.yahoo.com
echo 0.0.0.0 appmetrica.yandex.com
echo 0.0.0.0 yandexadexchange.net
echo 0.0.0.0 analytics.mobile.yandex.net
echo 0.0.0.0 extmaps-api.yandex.net
echo 0.0.0.0 adsdk.yandex.ru
echo 0.0.0.0 appmetrica.yandex.com
echo 0.0.0.0 hotjar.com
echo 0.0.0.0 static.hotjar.com
echo 0.0.0.0 api-hotjar.com
echo 0.0.0.0 jotjar-analytics.com
echo 0.0.0.0 mouseflow.com
echo 0.0.0.0 freshmarketer.com
echo 0.0.0.0 luckyorange.com
echo 0.0.0.0 cdn.luckyorange.com
echo 0.0.0.0 w1.luckyorange.com
echo 0.0.0.0 upload.luckyorange.com
echo 0.0.0.0 cs.luckyorange.com
echo 0.0.0.0 settings.luckyorange.com
echo 0.0.0.0 stats.wp.com
echo 0.0.0.0 app.bugsnag.com
echo 0.0.0.0 api.bugsnag.com
echo 0.0.0.0 notify.bugsnag.com
echo 0.0.0.0 sessions.bugsnag.com
echo 0.0.0.0 browser.sentry-cdn.com
echo 0.0.0.0 app.getsentry.com
echo 0.0.0.0 amazonaws.com
echo 0.0.0.0 amazonaax.com
echo 0.0.0.0 amazonclix.com
echo 0.0.0.0 assoc-amazon.com
echo 0.0.0.0 ads.google.com
echo 0.0.0.0 pagead2.googlesyndication.com
echo 0.0.0.0 pagead2.googleadservices.com
echo 0.0.0.0 amazon-adsystem.com
echo 0.0.0.0 googleadservices.com
echo 0.0.0.0 doubleclick.net
echo 0.0.0.0 ad.doubleclick.net
echo 0.0.0.0 static.doubleclick.net
echo 0.0.0.0 m.doubleclick.net
echo 0.0.0.0 mediavisor.doubleclick.net
echo 0.0.0.0 googleads.g.doubleclick.net
echo 0.0.0.0 adclick.g.doubleclick.net
echo 0.0.0.0 carbonads.net
echo 0.0.0.0 advertising.amazon.com
echo 0.0.0.0 advertising.amazon.ca
echo 0.0.0.0 google-analytics.com
echo 0.0.0.0 doubleclick.net
echo 0.0.0.0 doubleclick.com
echo 0.0.0.0 doubleclick.de
echo 0.0.0.0 partner.googleadservices.com
echo 0.0.0.0 googlesyndication.com
echo 0.0.0.0 google-analytics.com
echo 0.0.0.0 zedo.com
echo 0.0.0.0 amazon.ae
echo 0.0.0.0 amazon.cn
echo 0.0.0.0 advertising.amazon.co.jp
echo 0.0.0.0 amazon.co.uk
echo 0.0.0.0 advertising.amazon.com.au
echo 0.0.0.0 advertising.amazon.com.mx
echo 0.0.0.0 advertising.amazon.de
echo 0.0.0.0 advertising.amazon.es
echo 0.0.0.0 advertising.amazon.fr
echo 0.0.0.0 advertising.amazon.in
echo 0.0.0.0 advertising.amazon.it
echo 0.0.0.0 advertising.amazon.sa
echo 0.0.0.0 bingads.microsoft.com
echo 0.0.0.0 adcash.com
echo 0.0.0.0 taboola.com
echo 0.0.0.0 outbrain.com
echo 0.0.0.0 smartyads.com
echo 0.0.0.0 popads.net
echo 0.0.0.0 adpushup.com
echo 0.0.0.0 trafficforce.com
echo 0.0.0.0 adsterra.com
echo 0.0.0.0 creative.ak.fbcdn.net
echo 0.0.0.0 adbrite.com
echo 0.0.0.0 exponential.com
echo 0.0.0.0 quantserve.com
echo 0.0.0.0 scorecardresearch.com
echo 0.0.0.0 propellerads.com
echo 0.0.0.0 admedia.net
echo 0.0.0.0 admedia.com
echo 0.0.0.0 bidvertiser.com
echo 0.0.0.0 undertone.com
echo 0.0.0.0 web.adblade.com
echo 0.0.0.0 revenuehits.com
echo 0.0.0.0 infolinks.com
echo 0.0.0.0 vibrantmedia.com
echo 0.0.0.0 ads.yahoosmallbusiness.com
echo 0.0.0.0 ads.yahoo.com
echo 0.0.0.0 hilltopads.net
echo 0.0.0.0 clickadu.com
echo 0.0.0.0 citysex.com
echo 0.0.0.0 ad-maven.com
echo 0.0.0.0 propelmedia.com
echo 0.0.0.0 enginemediaexchange.com
echo 0.0.0.0 advertisers.adversense.com
echo 0.0.0.0 a.adtng.com
echo 0.0.0.0 ads.facebook.com
echo 0.0.0.0 an.facebook.com
echo 0.0.0.0 analytics.facebook.com
echo 0.0.0.0 pixel.facebook.com
echo 0.0.0.0 ads.youtube.com
echo 0.0.0.0 youtube.cleverads.vn
echo 0.0.0.0 ads-twitter.com
echo 0.0.0.0 ads-api.twitter.com
echo 0.0.0.0 advertising.twitter.com
echo 0.0.0.0 ads.linkedin.com
echo 0.0.0.0 analytics.pointdrive.linkedin.com
echo 0.0.0.0 ads.reddit.com
echo 0.0.0.0 d.reddit.com
echo 0.0.0.0 rereddit.com
echo 0.0.0.0 events.redditmedia.com
echo 0.0.0.0 analytics.tiktok.com
echo 0.0.0.0 ads.tiktok.com
echo 0.0.0.0 analytics-sg.tiktok.com
echo 0.0.0.0 ads-sg.tiktok.com
echo # Advanced System Care 15 Ultimate
echo 0.0.0.0 184-86-53-99.deploy.static.akamaitechnologies.com
echo 0.0.0.0 a-0001.a-msedge.net
echo 0.0.0.0 a-0002.a-msedge.net
echo 0.0.0.0 a-0003.a-msedge.net
echo 0.0.0.0 a-0004.a-msedge.net
echo 0.0.0.0 a-0005.a-msedge.net
echo 0.0.0.0 a-0006.a-msedge.net
echo 0.0.0.0 a-0007.a-msedge.net
echo 0.0.0.0 a-0008.a-msedge.net
echo 0.0.0.0 a-0009.a-msedge.net
echo 0.0.0.0 a1621.g.akamai.net
echo 0.0.0.0 a1856.g2.akamai.net
echo 0.0.0.0 a1961.g.akamai.net
echo 0.0.0.0 a978.i6g1.akamai.net
echo 0.0.0.0 a.ads1.msn.com
echo 0.0.0.0 a.ads2.msads.net
echo 0.0.0.0 a.ads2.msn.com
echo 0.0.0.0 ac3.msn.com
echo 0.0.0.0 ad.doubleclick.net
echo 0.0.0.0 adnexus.net
echo 0.0.0.0 adnxs.com
echo 0.0.0.0 ads1.msads.net
echo 0.0.0.0 ads.msn.com
echo 0.0.0.0 aidps.atdmt.com
echo 0.0.0.0 aka-cdn-ns.adtech.de
echo 0.0.0.0 any.edge.bing.com
echo 0.0.0.0 a.rad.msn.com
echo 0.0.0.0 az361816.vo.msecnd.net
echo 0.0.0.0 az512334.vo.msecnd.net
echo 0.0.0.0 b.ads1.msn.com
echo 0.0.0.0 b.ads2.msads.net
echo 0.0.0.0 bingads.microsoft.com
echo 0.0.0.0 b.rad.msn.com
echo 0.0.0.0 bs.serving-sys.com
echo 0.0.0.0 c.atdmt.com
echo 0.0.0.0 cdn.atdmt.com
echo 0.0.0.0 cds26.ams9.msecn.net
echo 0.0.0.0 choice.microsoft.com
echo 0.0.0.0 choice.microsoft.com.nsatc.net
echo 0.0.0.0 compatexchange.cloudapp.net
echo 0.0.0.0 corpext.msitadfs.glbdns2.microsoft.com
echo 0.0.0.0 corp.sts.microsoft.com
echo 0.0.0.0 cs1.wpc.v0cdn.net
echo 0.0.0.0 db3aqu.atdmt.com
echo 0.0.0.0 df.telemetry.microsoft.com
echo 0.0.0.0 diagnostics.support.microsoft.com
echo 0.0.0.0 e2835.dspb.akamaiedge.net
echo 0.0.0.0 e7341.g.akamaiedge.net
echo 0.0.0.0 e7502.ce.akamaiedge.net
echo 0.0.0.0 e8218.ce.akamaiedge.net
echo 0.0.0.0 ec.atdmt.com
echo 0.0.0.0 fe2.update.microsoft.com.akadns.net
echo 0.0.0.0 feedback.microsoft-hohm.com
echo 0.0.0.0 feedback.search.microsoft.com
echo 0.0.0.0 feedback.windows.com
echo 0.0.0.0 flex.msn.com
echo 0.0.0.0 g.msn.com
echo 0.0.0.0 h1.msn.com
echo 0.0.0.0 h2.msn.com
echo 0.0.0.0 hostedocsp.globalsign.com
echo 0.0.0.0 i1.services.social.microsoft.com
echo 0.0.0.0 i1.services.social.microsoft.com.nsatc.net
echo 0.0.0.0 lb1.www.ms.akadns.net
echo 0.0.0.0 live.rads.msn.com
echo 0.0.0.0 m.adnxs.com
echo 0.0.0.0 msnbot-65-55-108-23.search.msn.com
echo 0.0.0.0 msntest.serving-sys.com
echo 0.0.0.0 oca.telemetry.microsoft.com
echo 0.0.0.0 oca.telemetry.microsoft.com.nsatc.net
echo 0.0.0.0 onesettings-db5.metron.live.nsatc.net
echo 0.0.0.0 pre.footprintpredict.com
echo 0.0.0.0 preview.msn.com
echo 0.0.0.0 rad.live.com
echo 0.0.0.0 redir.metaservices.microsoft.com
echo 0.0.0.0 reports.wes.df.telemetry.microsoft.com
echo 0.0.0.0 schemas.microsoft.akadns.net
echo 0.0.0.0 secure.adnxs.com
echo 0.0.0.0 secure.flashtalking.com
echo 0.0.0.0 services.wes.df.telemetry.microsoft.com
echo 0.0.0.0 settings-sandbox.data.microsoft.com
echo 0.0.0.0 sls.update.microsoft.com.akadns.net
echo 0.0.0.0 sqm.df.telemetry.microsoft.com
echo 0.0.0.0 sqm.telemetry.microsoft.com
echo 0.0.0.0 sqm.telemetry.microsoft.com.nsatc.net
echo 0.0.0.0 ssw.live.com
echo 0.0.0.0 static.2mdn.net
echo 0.0.0.0 statsfe1.ws.microsoft.com
echo 0.0.0.0 statsfe2.update.microsoft.com.akadns.net
echo 0.0.0.0 statsfe2.ws.microsoft.com
echo 0.0.0.0 survey.watson.microsoft.com
echo 0.0.0.0 telecommand.telemetry.microsoft.com
echo 0.0.0.0 telecommand.telemetry.microsoft.com.nsatc.net
echo 0.0.0.0 telemetry.appex.bing.net
echo 0.0.0.0 telemetry.urs.microsoft.com
echo 0.0.0.0 vortex-bn2.metron.live.com.nsatc.net
echo 0.0.0.0 vortex-cy2.metron.live.com.nsatc.net
echo 0.0.0.0 vortex.data.microsoft.com
echo 0.0.0.0 vortex-sandbox.data.microsoft.com
echo 0.0.0.0 vortex-win.data.microsoft.com
echo 0.0.0.0 cy2.vortex.data.microsoft.com.akadns.net
echo 0.0.0.0 watson.live.com
echo 0.0.0.0 watson.ppe.telemetry.microsoft.com
echo 0.0.0.0 watson.telemetry.microsoft.com
echo 0.0.0.0 watson.telemetry.microsoft.com.nsatc.net
echo 0.0.0.0 win10.ipv6.microsoft.com
echo 0.0.0.0 www.bingads.microsoft.com
echo 0.0.0.0 www.go.microsoft.akadns.net
echo 0.0.0.0 client.wns.windows.com
echo 0.0.0.0 wdcpalt.microsoft.com
echo 0.0.0.0 settings-ssl.xboxlive.com
echo 0.0.0.0 settings-ssl.xboxlive.com-c.edgekey.net
echo 0.0.0.0 settings-ssl.xboxlive.com-c.edgekey.net.globalredir.akadns.net
echo 0.0.0.0 e87.dspb.akamaidege.net
echo 0.0.0.0 insiderservice.microsoft.com
echo 0.0.0.0 insiderservice.trafficmanager.net
echo 0.0.0.0 e3843.g.akamaiedge.net
echo 0.0.0.0 flightingserviceweurope.cloudapp.net
echo 0.0.0.0 static.ads-twitter.com
echo 0.0.0.0 www-google-analytics.l.google.com
echo 0.0.0.0 p.static.ads-twitter.com
echo 0.0.0.0 hubspot.net.edge.net
echo 0.0.0.0 e9483.a.akamaiedge.net
echo 0.0.0.0 stats.g.doubleclick.net
echo 0.0.0.0 stats.l.doubleclick.net
echo 0.0.0.0 adservice.google.de
echo 0.0.0.0 adservice.google.com
echo 0.0.0.0 googleads.g.doubleclick.net
echo 0.0.0.0 pagead46.l.doubleclick.net
echo 0.0.0.0 hubspot.net.edgekey.net
echo 0.0.0.0 insiderppe.cloudapp.net
echo 0.0.0.0 livetileedge.dsx.mp.microsoft.com
echo 0.0.0.0 s0.2mdn.net
echo 0.0.0.0 view.atdmt.com
echo 0.0.0.0 m.hotmail.com
echo 0.0.0.0 apps.skype.com
echo 0.0.0.0 c.msn.com
echo 0.0.0.0 pricelist.skype.com
echo 0.0.0.0 s.gateway.messenger.live.com
echo 0.0.0.0 ui.skype.com
echo # Google Ads Block
echo 0.0.0.0 auditude.com
echo 0.0.0.0 ad.auditude.com
echo 0.0.0.0 adservice.google.com
echo 0.0.0.0 ade.googlesyndication.com
echo 0.0.0.0 yt3.ggpht.com
echo 0.0.0.0 ggpht.com
echo 0.0.0.0 pagead2.googlesyndication.com
echo 0.0.0.0 googleadservices.com
echo 0.0.0.0 www.googleadservices.com
echo 0.0.0.0 partner.googleadservices.com
echo 0.0.0.0 doubleclick.net
echo 0.0.0.0 g.doubleclick.net
echo 0.0.0.0 googleads.g.doubleclick.net
echo 0.0.0.0 securepubads.g.doubleclick.net
echo 0.0.0.0 ad.doubleclick.net
echo 0.0.0.0 pubads.g.doubleclick.net
echo 0.0.0.0 adclick.g.doubleclick.net
echo 0.0.0.0 stats.g.doubleclick.net
echo 0.0.0.0 fls.doubleclick.net
echo 0.0.0.0 ad-emea.doubleclick.net
echo 0.0.0.0 googletagservices.com
echo 0.0.0.0 pagead2.googleadservices.com
echo 0.0.0.0 googleads2.g.doubleclick.net
echo 0.0.0.0 ad-apac.doubleclick.net
echo 0.0.0.0 dart.l.doubleclick.net
echo 0.0.0.0 pagead46.l.doubleclick.net
echo 0.0.0.0 partnerad.l.doubleclick.net
echo 0.0.0.0 ad-g.doubleclick.net
echo 0.0.0.0 tpc.googlesyndication.com
echo 0.0.0.0 pagead.l.doubleclick.net
echo 0.0.0.0 static-doubleclick-net.l.google.com
echo 0.0.0.0 gstaticadssl.l.google.com
echo 0.0.0.0 static.doubleclick.net
echo 0.0.0.0 pagead-googlehosted.l.google.com
)>"%systemdrive%\Windows\System32\Drivers\Etc\hosts"


:: Powershell Scripts
@powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0block-telemetry.ps1"
@powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0disable-memory-compression.ps1"
@powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0disable-prefetch-prelaunch.ps1"
@powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0disable-scheduled-tasks.ps1"
@powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0disable-services.ps1"
@powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0disable-windows-defender.ps1"
@powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0experimental_unfuckery.ps1"
@powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0fix-privacy-settings.ps1"
@powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0optimize-user-interface.ps1"
@powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0optimize-windows-update.ps1"
@powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0remove-default-apps.ps1"


:: Batch Scripts
call %~dp0Default.cmd
call %~dp0RemoveServices.bat

:: Exit
exit