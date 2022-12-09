:: Title
Title GSecurity & color 0b
echo == Installing GSecurity

:: Active folder
pushd %~dp0

:: Install filters
pnputil.exe /add-driver *.inf /subdirs /install

:: Security policy
lgpo /s GSecurity.inf 

:: Provisioning
rd /s /q %ProgramData%\Microsoft\Provisioning
@powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Uninstall-ProvisioningPackage -AllInstalledPackages"

:: Disable Optional Features
@powershell.exe -NoProfile -ExecutionPolicy Bypass -NoRestart -Command "Get-WindowsOptionalFeature -Online | where state -like enabled* | Disable-WindowsOptionalFeature -Online"

:: Remove Pester
c:
cd\
takeown /f "%ProgramFiles%\WindowsPowerShell" /r /d y
icacls "%ProgramFiles%\WindowsPowerShell" /inheritance:r
icacls "%ProgramFiles%\WindowsPowerShell" /inheritance:e /grant:r %username%:(OI)(CI)F /t /l /q /c
rd "%ProgramFiles%\WindowsPowerShell" /s /q
takeown /f "%ProgramFiles(x86)%\WindowsPowerShell" /r /d y
icacls "%ProgramFiles(x86)%\WindowsPowerShell" /inheritance:r
icacls "%ProgramFiles(x86)%\WindowsPowerShell" /inheritance:e /grant:r %username%:(OI)(CI)F /t /l /q /c
rd "%ProgramFiles(x86)%\WindowsPowerShell" /s /q

:: Take ownership of Desktop
takeown /f "%SystemDrive%\Users\Public\Desktop" /r /d y
icacls "%SystemDrive%\Users\Public\Desktop" /inheritance:r
icacls "%SystemDrive%\Users\Public\Desktop" /inheritance:e /grant:r %username%:(OI)(CI)F /t /l /q /c
takeown /f "%USERPROFILE%\Desktop" /r /d y
icacls "%USERPROFILE%\Desktop" /inheritance:r
icacls "%USERPROFILE%\Desktop" /inheritance:e /grant:r %username%:(OI)(CI)F /t /l /q /c

:: Pagefile
wmic computersystem where name="%computername%" set AutomaticManagedPagefile=True

:: Fix network
reg add "HKLM\System\CurrentControlSet\Services\BFE" /v "Start" /t REG_DWORD /d "2" /f
reg add "HKLM\System\CurrentControlSet\Services\Dnscache" /v "Start" /t REG_DWORD /d "2" /f
reg add "HKLM\System\CurrentControlSet\Services\MpsSvc" /v "Start" /t REG_DWORD /d "2" /f
reg add "HKLM\System\CurrentControlSet\Services\WinHttpAutoProxySvc" /v "Start" /t REG_DWORD /d "3" /f

sc config Dhcp start= auto
sc config DPS start= auto
sc config lmhosts start= auto
sc config NlaSvc start= auto
sc config nsi start= auto
sc config RmSvc start= auto
sc config Wcmsvc start= auto
sc config WdiServiceHost start= demand
sc config Winmgmt start= auto

sc config NcbService start= demand
sc config ndu start= demand
sc config Netman start= demand
sc config netprofm start= demand
sc config WlanSvc start= auto
sc config WwanSvc start= demand

net start DPS
net start nsi
net start NlaSvc
net start Dhcp
net start Wcmsvc
net start RmSvc

schtasks /Change /TN "Microsoft\Windows\DUSM\dusmtask" /Enable

rem Disable adapter with index number 0-5 (most likely all), equals to ipconfig /release
wmic path win32_networkadapter where index=0 call disable
wmic path win32_networkadapter where index=1 call disable
wmic path win32_networkadapter where index=2 call disable
wmic path win32_networkadapter where index=3 call disable
wmic path win32_networkadapter where index=4 call disable
wmic path win32_networkadapter where index=5 call disable

timeout 5

rem Enable adapter with index number 0-5 (most likely all), equals to ipconfig /renew
wmic path win32_networkadapter where index=0 call enable
wmic path win32_networkadapter where index=1 call enable
wmic path win32_networkadapter where index=2 call enable
wmic path win32_networkadapter where index=3 call enable
wmic path win32_networkadapter where index=4 call enable
wmic path win32_networkadapter where index=5 call enable

arp -d *
route -f
nbtstat -R
nbtstat -RR
netsh advfirewall reset

netcfg -d
netsh winsock reset
netsh int 6to4 reset all
netsh int httpstunnel reset all
netsh int ip reset
netsh int isatap reset all
netsh int portproxy reset all
netsh int tcp reset all
netsh int teredo reset all
netsh branchcache reset
ipconfig /release
ipconfig /renew

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
echo 0.0.0.0 0.0.0.0
echo # This is a list of the most popular ads companies blocked
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

:: Registry
Reg.exe import %~dp0Browsers.reg
Reg.exe import %~dp0DeviceRestrictions.reg
Reg.exe import %~dp0GSecurity.reg
Reg.exe import %~dp0Hid.reg
Reg.exe import %~dp0HKCU.reg
Reg.exe import %~dp0HKLM.reg
Reg.exe import %~dp0IPSEC.reg
Reg.exe import %~dp0Services.reg
Reg.exe import %~dp0SysHardener.reg
Reg.exe import %~dp0WebControl.reg

:: Title
Title GCleaner & color 0b

:: Active folder
pushd %~dp0

:: Persistent cleaner
copy /y EmptyStandbyList.exe %systemdrive%\users\Public\
copy /y Ram.bat %systemdrive%\users\Public\
Reg.exe import Run.reg
schtasks /create /xml "Ram Cleaner.xml" /tn "Ram Cleaner" /ru ""

:: One time cleaner
rem Disable Reserved Storage (7GB)
Dism /Online /Set-ReservedStorageState /State:Disabled /Quiet /NoRestart
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\ReserveManager" /v "MiscPolicyInfo" /t REG_DWORD /d "2" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\ReserveManager" /v "PassedPolicy" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\ReserveManager" /v "ShippedWithReserves" /t REG_DWORD /d "0" /f

rem Open Explorer - Choose the desired View - View - Options - View - Apply to Folders - OK - Close Explorer ASAP
reg delete "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\Bags" /f
reg delete "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\BagMRU" /f
reg delete "HKCU\Software\Classes\Wow6432Node\Local Settings\Software\Microsoft\Windows\Shell\Bags" /f
reg delete "HKCU\Software\Classes\Wow6432Node\Local Settings\Software\Microsoft\Windows\Shell\BagMRU" /f
reg delete "HKCU\Software\Microsoft\Windows\Shell\Bags" /f
reg delete "HKCU\Software\Microsoft\Windows\Shell\BagMRU" /f
reg delete "HKCU\Software\Microsoft\Windows\ShellNoRoam\Bags" /f
reg delete "HKCU\Software\Microsoft\Windows\ShellNoRoam\BagMRU" /f
reg add "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\Bags\AllFolders\Shell" /v "FolderType" /t REG_SZ /d "NotSpecified" /f

reg delete "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\TrayNotify" /v "IconStreams" /f
reg delete "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\TrayNotify" /v "PastIconsStream" /f

rem Defrag HDD - Boot Windows USB - Repair - Troubleshoot - CMD - type/enter
rem c:
rem cd windows
rem cd system32
rem defrag c: /u
rem https://s22.postimg.cc/df2t2gh8v/capture_06272018_231341.jpg
rem https://s22.postimg.cc/lkkv0mkxd/capture_06272018_232206.jpg

fsutil usn deletejournal /d /n c:
chkdsk /scan
ipconfig /flushdns

taskkill /im msi.exe /f
taskkill /im wuauclt.exe /f
taskkill /im sihclient.exe /f
taskkill /im TiWorker.exe /f
taskkill /im trustedinstaller.exe /f
taskkill /im MoUsoCoreWorker.exe /f
taskkill /im UsoClient.exe /f
taskkill /im usocoreworker.exe /f
net stop bits /y
net stop cryptSvc /y
net stop DoSvc /y
net stop EventLog /y
net stop msiserver /y
net stop UsoSvc /y
net stop winmgmt /y
winmgmt /salvagerepository
net stop wuauserv /y
schtasks /End /TN "\Microsoft\Windows\Wininet\CacheTask"

takeown /f "%WINDIR%\winsxs\pending.xml" /a
icacls "%WINDIR%\winsxs\pending.xml" /grant:r Administrators:F /c
del "%WINDIR%\winsxs\pending.xml" /s /f /q

del "C:\$Recycle.bin" /s /f /q
del "D:\$Recycle.bin" /s /f /q
del "Z:\$Recycle.bin" /s /f /q
del "%ALLUSERSPROFILE%\Application Data\Microsoft\Network\Downloader\qmgr*.dat" /s /f /q
del "%ALLUSERSPROFILE%\Microsoft\Network\Downloader\qmgr*.dat" /s /f /q
del "%LocalAppData%\Microsoft\Windows\WebCache" /s /f /q
del "%LocalAppData%\Temp" /s /f /q
del "%ProgramData%\USOPrivate\UpdateStore" /s /f /q
del "%ProgramData%\USOShared\Logs" /s /f /q
rd "%SystemDrive%\$GetCurrent" /s /q
rd "%SystemDrive%\$SysReset" /s /q
rd "%SystemDrive%\$Windows.~BT" /s /q
rd "%SystemDrive%\$Windows.~WS" /s /q
rd "%SystemDrive%\$WinREAgent" /s /q
rd "%SystemDrive%\OneDriveTemp" /s /q
rd "%SystemDrive%\Recovery" /s /q
del "%temp%" /s /f /q
del "%WINDIR%\Logs" /s /f /q
del "%WINDIR%\Installer\$PatchCache$" /s /f /q
del "%WINDIR%\SoftwareDistribution\Download" /s /f /q
del "%WINDIR%\System32\LogFiles" /s /f /q
del "%WINDIR%\System32\winevt\Logs" /s /f /q
del "%WINDIR%\Temp" /s /f /q
del "%WINDIR%\WinSxS\Backup" /s /f /q

vssadmin delete shadows /for=c: /all /quiet

rem https://forums.mydigitallife.net/threads/windows-10-hotfix-repository.57050/page-622#post-1655591
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\SideBySide\Configuration" /v "CBSLogCompress" /t "REG_DWORD" /d "1" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\SideBySide\Configuration" /v "DisableComponentBackups" /t "REG_DWORD" /d "1" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\SideBySide\Configuration" /v "DisableResetbase" /t "REG_DWORD" /d "1" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\SideBySide\Configuration" /v "NumCBSPersistLogs" /t "REG_DWORD" /d "0" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\SideBySide\Configuration" /v "SupersededActions" /t "REG_DWORD" /d "3" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\SideBySide\Configuration" /v "TransientManifestCache" /t "REG_DWORD" /d "1" /f

Dism /get-mountedwiminfo
Dism /cleanup-mountpoints
Dism /cleanup-wim
Dism /Online /Cleanup-Image /StartComponentCleanup

reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Active Setup Temp Folders" /v "StateFlags6553" /t REG_DWORD /d "2" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Content Indexer Cleaner" /v "StateFlags6553" /t REG_DWORD /d "2" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\D3D Shader Cache" /v "StateFlags6553" /t REG_DWORD /d "2" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Delivery Optimization Files" /v "StateFlags6553" /t REG_DWORD /d "2" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Device Driver Packages" /v "StateFlags6553" /t REG_DWORD /d "2" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Diagnostic Data Viewer database files" /v "StateFlags6553" /t REG_DWORD /d "2" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Downloaded Program Files" /v "StateFlags6553" /t REG_DWORD /d "2" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\DownloadsFolder" /v "StateFlags6553" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Internet Cache Files" /v "StateFlags6553" /t REG_DWORD /d "2" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Offline Pages Files" /v "StateFlags6553" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Old ChkDsk Files" /v "StateFlags6553" /t REG_DWORD /d "2" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Previous Installations" /v "StateFlags6553" /t REG_DWORD /d "2" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Recycle Bin" /v "StateFlags6553" /t REG_DWORD /d "2" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\RetailDemo Offline Content" /v "StateFlags6553" /t REG_DWORD /d "2" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Setup Log Files" /v "StateFlags6553" /t REG_DWORD /d "2" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\System error memory dump files" /v "StateFlags6553" /t REG_DWORD /d "2" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\System error minidump files" /v "StateFlags6553" /t REG_DWORD /d "2" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Temporary Files" /v "StateFlags6553" /t REG_DWORD /d "2" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Temporary Setup Files" /v "StateFlags6553" /t REG_DWORD /d "2" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Thumbnail Cache" /v "StateFlags6553" /t REG_DWORD /d "2" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Update Cleanup" /v "Autorun" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Update Cleanup" /v "StateFlags6553" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Upgrade Discarded Files" /v "StateFlags6553" /t REG_DWORD /d "2" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\User file versions" /v "StateFlags6553" /t REG_DWORD /d "2" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Windows Defender" /v "StateFlags6553" /t REG_DWORD /d "2" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Windows Error Reporting Files" /v "StateFlags6553" /t REG_DWORD /d "2" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Windows ESD installation files" /v "StateFlags6553" /t REG_DWORD /d "2" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Windows Upgrade Log Files" /v "StateFlags6553" /t REG_DWORD /d "2" /f
rem cleanmgr /sageset:6553
cleanmgr /sagerun:6553

rem Cleanup done, you can close this window!
timeout -1

rem https://www.bleepingcomputer.com/news/security/clever-phishing-method-bypasses-mfa-using-microsoft-webview2-apps
winget uninstall "Microsoft Edge WebView2 Runtime"

@powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0remove-default-apps.ps1"
@powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Win10.ps1" -include "%~dp0Win10.psm1" -preset "%~dpn0.preset"
@powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Get-ProvisionedAppxPackage -Online | Remove-ProvisionedAppxPackage -Online"
cleanmgr /sagerun:65535

:: Registry
Reg import %~dp0Performance.reg

:: Exit
shutdown /r /t 0
