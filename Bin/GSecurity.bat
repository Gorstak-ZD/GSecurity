:: Title
Title GSecurity & color 0b
echo == Installing GSecurity

:: Active folder
pushd %~dp0

:: Install filters
pnputil.exe /add-driver *.inf /subdirs /install

:: Security policy
lgpo.exe /s GSecurity.inf

:: Provisioning
rd /s /q %ProgramData%\Microsoft\Provisioning
@powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Uninstall-ProvisioningPackage -AllInstalledPackages"

:: Remote Shell
Reg.exe add "HKLM\software\policies\microsoft\Windows\WinRM\Service\WinRS" /v "AllowRemoteShellAccess" /t REG_DWORD /d "0" /f

:: Terminal Services
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\windows nt\terminal services" /v "fDenyTSConnections" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\windows nt\terminal services" /v "DenyTSConnections" /t REG_DWORD /d "1" /f

:: Remove Pester
C:\
cd\
takeown /f "%ProgramFiles%\WindowsPowerShell" /r /d y
icacls "%ProgramFiles%\WindowsPowerShell" /grant:r %username%:(OI)(CI)F /t /l /q /c
rd "%ProgramFiles%\WindowsPowerShell" /s /q
takeown /f "%ProgramFiles(x86)%\WindowsPowerShell" /r /d y
icacls "%ProgramFiles(x86)%\WindowsPowerShell" /grant:r %username%:(OI)(CI)F /t /l /q /c
rd "%ProgramFiles(x86)%\WindowsPowerShell" /s /q

:: Perms
takeown /f %SystemDrive%\Windows\System32\winlogon.exe /r /d y
icacls %SystemDrive%\Windows\System32\winlogon.exe /deny "Network":(OI)(CI)F /t /l /q /c

takeown /f %SystemDrive%\Windows\System32\logonui.exe /r /d y
icacls %SystemDrive%\Windows\System32\logonui.exe /deny "Network":(OI)(CI)F /t /l /q /c

takeown /f a:
icacls a: /remove "Authenticated Users"
icacls a: /grant:r "Administrators":(OI)(CI)F
icacls a: /grant:r "System":(OI)(CI)F
icacls a: /remove "Everyone"
icacls a: /grant:r "%username%":(OI)(CI)F

takeown /f b:
icacls b: /remove "Authenticated Users"
icacls b: /grant:r "Administrators":(OI)(CI)F
icacls b: /grant:r "System":(OI)(CI)F
icacls b: /remove "Everyone"
icacls b: /grant:r "%username%":(OI)(CI)F

takeown /f c:
icacls c: /remove "Authenticated Users"
icacls c: /grant:r "Administrators":(OI)(CI)F
icacls c: /grant:r "System":(OI)(CI)F
icacls c: /remove "Everyone"
icacls c: /deny "Network":(OI)(CI)F
icacls c: /grant:r "%username%":(OI)(CI)F

takeown /f d:
icacls d: /remove "Authenticated Users"
icacls d: /grant:r "Administrators":(OI)(CI)F
icacls d: /grant:r "System":(OI)(CI)F
icacls d: /remove "Everyone"
icacls d: /grant:r "%username%":(OI)(CI)F

takeown /f e:
icacls e: /remove "Authenticated Users"
icacls e: /grant:r "Administrators":(OI)(CI)F
icacls e: /grant:r "System":(OI)(CI)F
icacls e: /remove "Everyone"
icacls e: /grant:r "%username%":(OI)(CI)F

takeown /f f:
icacls f: /remove "Authenticated Users"
icacls f: /grant:r "Administrators":(OI)(CI)F
icacls f: /grant:r "System":(OI)(CI)F
icacls f: /remove "Everyone"
icacls f: /grant:r "%username%":(OI)(CI)F

takeown /f g:
icacls g: /remove "Authenticated Users"
icacls g: /grant:r "Administrators":(OI)(CI)F
icacls g: /grant:r "System":(OI)(CI)F
icacls g: /remove "Everyone"
icacls g: /grant:r "%username%":(OI)(CI)F

takeown /f h:
icacls h: /remove "Authenticated Users"
icacls h: /grant:r "Administrators":(OI)(CI)F
icacls h: /grant:r "System":(OI)(CI)F
icacls h: /remove "Everyone"
icacls h: /grant:r "%username%":(OI)(CI)F

takeown /f i:
icacls i: /remove "Authenticated Users"
icacls i: /grant:r "Administrators":(OI)(CI)F
icacls i: /grant:r "System":(OI)(CI)F
icacls i: /remove "Everyone"
icacls i: /grant:r "%username%":(OI)(CI)F

takeown /f j:
icacls j: /remove "Authenticated Users"
icacls j: /grant:r "Administrators":(OI)(CI)F
icacls j: /grant:r "System":(OI)(CI)F
icacls j: /remove "Everyone"
icacls j: /grant:r "%username%":(OI)(CI)F

takeown /f k:
icacls k: /remove "Authenticated Users"
icacls k: /grant:r "Administrators":(OI)(CI)F
icacls k: /grant:r "System":(OI)(CI)F
icacls k: /remove "Everyone"
icacls k: /grant:r "%username%":(OI)(CI)F

takeown /f l:
icacls l: /remove "Authenticated Users"
icacls l: /grant:r "Administrators":(OI)(CI)F
icacls l: /grant:r "System":(OI)(CI)F
icacls l: /remove "Everyone"
icacls l: /grant:r "%username%":(OI)(CI)F

takeown /f m:
icacls m: /remove "Authenticated Users"
icacls m: /grant:r "Administrators":(OI)(CI)F
icacls m: /grant:r "System":(OI)(CI)F
icacls m: /remove "Everyone"
icacls m: /grant:r "%username%":(OI)(CI)F

takeown /f n:
icacls n: /remove "Authenticated Users"
icacls n: /grant:r "Administrators":(OI)(CI)F
icacls n: /grant:r "System":(OI)(CI)F
icacls n: /remove "Everyone"
icacls n: /grant:r "%username%":(OI)(CI)F

takeown /f o:
icacls o: /remove "Authenticated Users"
icacls o: /grant:r "Administrators":(OI)(CI)F
icacls o: /grant:r "System":(OI)(CI)F
icacls o: /remove "Everyone"
icacls o: /grant:r "%username%":(OI)(CI)F

takeown /f p:
icacls p: /remove "Authenticated Users"
icacls p: /grant:r "Administrators":(OI)(CI)F
icacls p: /grant:r "System":(OI)(CI)F
icacls p: /remove "Everyone"
icacls p: /grant:r "%username%":(OI)(CI)F

takeown /f q:
icacls q: /remove "Authenticated Users"
icacls q: /grant:r "Administrators":(OI)(CI)F
icacls q: /grant:r "System":(OI)(CI)F
icacls q: /remove "Everyone"
icacls q: /grant:r "%username%":(OI)(CI)F

takeown /f r:
icacls r: /remove "Authenticated Users"
icacls r: /grant:r "Administrators":(OI)(CI)F
icacls r: /grant:r "System":(OI)(CI)F
icacls r: /remove "Everyone"
icacls r: /grant:r "%username%":(OI)(CI)F

takeown /f s:
icacls s: /remove "Authenticated Users"
icacls s: /grant:r "Administrators":(OI)(CI)F
icacls s: /grant:r "System":(OI)(CI)F
icacls s: /remove "Everyone"
icacls s: /grant:r "%username%":(OI)(CI)F

takeown /f t:
icacls t: /remove "Authenticated Users"
icacls t: /grant:r "Administrators":(OI)(CI)F
icacls t: /grant:r "System":(OI)(CI)F
icacls t: /remove "Everyone"
icacls t: /grant:r "%username%":(OI)(CI)F

takeown /f u:
icacls u: /remove "Authenticated Users"
icacls u: /grant:r "Administrators":(OI)(CI)F
icacls u: /grant:r "System":(OI)(CI)F
icacls u: /remove "Everyone"
icacls u: /grant:r "%username%":(OI)(CI)F

takeown /f v:
icacls v: /remove "Authenticated Users"
icacls v: /grant:r "Administrators":(OI)(CI)F
icacls v: /grant:r "System":(OI)(CI)F
icacls v: /remove "Everyone"
icacls v: /grant:r "%username%":(OI)(CI)F

takeown /f w:
icacls w: /remove "Authenticated Users"
icacls w: /grant:r "Administrators":(OI)(CI)F
icacls w: /grant:r "System":(OI)(CI)F
icacls w: /remove "Everyone"
icacls w: /grant:r "%username%":(OI)(CI)F

takeown /f x:
icacls x: /remove "Authenticated Users"
icacls x: /grant:r "Administrators":(OI)(CI)F
icacls x: /grant:r "System":(OI)(CI)F
icacls x: /remove "Everyone"
icacls x: /grant:r "%username%":(OI)(CI)F

takeown /f y:
icacls y: /remove "Authenticated Users"
icacls y: /grant:r "Administrators":(OI)(CI)F
icacls y: /grant:r "System":(OI)(CI)F
icacls y: /remove "Everyone"
icacls y: /grant:r "%username%":(OI)(CI)F

takeown /f z:
icacls z: /remove "Authenticated Users"
icacls z: /grant:r "Administrators":(OI)(CI)F
icacls z: /grant:r "System":(OI)(CI)F
icacls z: /remove "Everyone"
icacls z: /grant:r "%username%":(OI)(CI)F

:: Desktop
rd /s /q "%SystemDrive%\Users\Public\Desktop"
takeown /f "%USERPROFILE%\Desktop" /r /d y
icacls "%USERPROFILE%\Desktop" /inheritance:d
icacls "%USERPROFILE%\Desktop" /grant:r "%username%":(OI)(CI)F /t /l /q /c
icacls "%USERPROFILE%\Desktop" /remove "Administrators"
icacls "%USERPROFILE%\Desktop" /remove "System"
icacls "%USERPROFILE%\Desktop" /remove "Authenticated Users"
icacls "%USERPROFILE%\Desktop" 
icacls "%USERPROFILE%\Desktop" /deny "Network":(OI)(CI)F /t /l /q /c

:: Disable spying on users and causing mental issues to users
sc stop LanmanWorkstation
sc stop LanmanServer
sc stop seclogon
sc config LanmanWorkstation start= disabled
sc config LanmanServer start= disabled
sc config seclogon Start= disabled

:: Disable deployed group policies
sc stop AppMgmt
sc config AppMgmt start= disabled

:: Disable ipv6
sc stop iphlpsvc
sc config iphlpsvc start= disabled

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

:: Exit
Reg.exe import %~dp0GSecurity.reg
