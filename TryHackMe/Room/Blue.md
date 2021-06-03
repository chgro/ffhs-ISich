# Basic Pentesting

IP = 10.10.178.14

# Scanning

### OS:

### Users / Passwords:


### Ports:


### WebServer:

### Connection:


### Exploration:



# Notes:

    kali@kali:~$ nmap -A -T5 --script vuln -oN rpnmap.nmap 10.10.178.14
    
    Starting Nmap 7.80 ( https://nmap.org ) at 2020-11-05 08:54 EST
    Nmap scan report for 10.10.178.14
    Host is up (0.044s latency).
    Not shown: 991 closed ports
    PORT      STATE SERVICE            VERSION
    135/tcp   open  msrpc              Microsoft Windows RPC
    |_clamav-exec: ERROR: Script execution failed (use -d to debug)
    139/tcp   open  netbios-ssn        Microsoft Windows netbios-ssn
    |_clamav-exec: ERROR: Script execution failed (use -d to debug)
    445/tcp   open  microsoft-ds       Microsoft Windows 7 - 10 microsoft-ds (workgroup: WORKGROUP)
    |_clamav-exec: ERROR: Script execution failed (use -d to debug)
    3389/tcp  open  ssl/ms-wbt-server?
    |_clamav-exec: ERROR: Script execution failed (use -d to debug)
    | rdp-vuln-ms12-020: 
    |   VULNERABLE:
    |   MS12-020 Remote Desktop Protocol Denial Of Service Vulnerability
    |     State: VULNERABLE
    |     IDs:  CVE:CVE-2012-0152
    |     Risk factor: Medium  CVSSv2: 4.3 (MEDIUM) (AV:N/AC:M/Au:N/C:N/I:N/A:P)
    |           Remote Desktop Protocol vulnerability that could allow remote attackers to cause a denial of service.
    |           
    |     Disclosure date: 2012-03-13
    |     References:
    |       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2012-0152
    |       http://technet.microsoft.com/en-us/security/bulletin/ms12-020
    |   
    |   MS12-020 Remote Desktop Protocol Remote Code Execution Vulnerability        
    |     State: VULNERABLE                                                           
    |     IDs:  CVE:CVE-2012-0002                                                       
    |     Risk factor: High  CVSSv2: 9.3 (HIGH) (AV:N/AC:M/Au:N/C:C/I:C/A:C)               
    |           Remote Desktop Protocol vulnerability that could allow remote attackers to execute arbitrary code on the tareted system.                                                                                  
    |                                                                                               
    |     Disclosure date: 2012-03-13                                                                   
    |     References:                                                                                   
    |       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2012-0002                                  
    |_      http://technet.microsoft.com/en-us/security/bulletin/ms12-020                                   
    |_sslv2-drown:                                                                                               
    49152/tcp open  msrpc              Microsoft Windows RPC                                                      
    |_clamav-exec: ERROR: Script execution failed (use -d to debug)                                                   
    49153/tcp open  msrpc              Microsoft Windows RPC                                                                
    |_clamav-exec: ERROR: Script execution failed (use -d to debug)
    49154/tcp open  msrpc              Microsoft Windows RPC
    |_clamav-exec: ERROR: Script execution failed (use -d to debug)
    49158/tcp open  msrpc              Microsoft Windows RPC
    |_clamav-exec: ERROR: Script execution failed (use -d to debug)
    49160/tcp open  msrpc              Microsoft Windows RPC
    |_clamav-exec: ERROR: Script execution failed (use -d to debug)
    Service Info: Host: JON-PC; OS: Windows; CPE: cpe:/o:microsoft:windows
    
    Host script results:
    |_samba-vuln-cve-2012-1182: NT_STATUS_ACCESS_DENIED
    |_smb-vuln-ms10-054: false
    |_smb-vuln-ms10-061: NT_STATUS_ACCESS_DENIED
    | smb-vuln-ms17-010: 
    |   VULNERABLE:
    |   Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)
    |     State: VULNERABLE
    |     IDs:  CVE:CVE-2017-0143
    |     Risk factor: HIGH
    |       A critical remote code execution vulnerability exists in Microsoft SMBv1
    |        servers (ms17-010).
    |           
    |     Disclosure date: 2017-03-14
    |     References:
    |       https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/
    |       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0143
    |_      https://technet.microsoft.com/en-us/library/security/ms17-010.aspx
    
    Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
    Nmap done: 1 IP address (1 host up) scanned in 102.38 seconds
