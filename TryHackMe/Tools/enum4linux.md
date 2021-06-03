#enum4linux

https://github.com/CiscoCXSecurity/enum4linux

Enum4linux is a tool used to enumerate SMB shares on both Windows and Linux systems. It is basically a wrapper around the tools in the Samba package and makes it easy to quickly extract information from the target pertaining to SMB. It's installed by default on Parrot and Kali, however if you need to install it, you can do so from the official github.

The syntax of Enum4Linux is nice and simple: "enum4linux [options] ip"

|TAG |FUNCTION|
|---|---|
|-U |get userlist|
|-M |get machine list|
|-N |get namelist dump (different from -U and-M)|
|-S |get sharelist|
|-P |get password policy information|
|-G |get group and member list|
|-A |all of the above (full basic enumeration)|

    enum4linux -A <IP>