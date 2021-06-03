##Scanning:

###nMap

mkdir nmap

Connect Scan
- nmap -sT <ip>

SYN Scan 
- nmap -sS <ip>

This scan type is the most favourable method as Nmap can use all the information gathered throughout the handshake to determine port status based on the response that is given by the IP address that is being scanned:

    SYN/ACK = open
    RST = Closed
    Multiple attempts = filtered

Scan agressivität:

-T0 scans a Port every 5 Minutes

...

-T5 Bruteforce everything

|Flag   |Usage Example          |Description|
|---    |---                    |---|
|-A     |nmap -A x.x.x.x|	    Scan the host to identify services running by matching against Nmap's database with OS detection|
|-O     |nmap -O x.x.x.x|	    Scan the host to retrieve and perform OS detection|
|-p     |nmap -p 22 x.x.x.x|	Scan a specific port number on the host. A range of ports can also be provided (i.e. 10-100) by using the first and last value of the range like so: nmap -p 10-100 x.x.x.x|
|-p-    |nmap -p- x.x.x.x|	    Scan all ports (0-65535) on the host|
|-sV    |nmap -sV x.x.x.x|	    Scan the host using TCP and perform version fingerprinting|

Verwenden eines Scripts:

[nMap/scripts](https://nmap.org/nsedoc/scripts/)

nmap --script ftp-proftpd-backdoor -p 21 <ip_address>

nmap -sC -sV -oN nmap/[ExerciseName] [IP-Address]

subl nmap/[ExerciseName]

IP in Browser eingeben...


###DirBuster / gobuster:

gobuster dir  -u [InternetAddress] -w [DirPathWordlist]

dirb 

Einträge in Browser ausprobieren


enum4linux -a [IP-Address] | tee enum4linux.log

subl enum4linux.log