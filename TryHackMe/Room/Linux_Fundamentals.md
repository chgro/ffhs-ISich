# Linux Fundamentals

## Part 1

- Introduction To Linux
- Executing Commands and Man Pages
- Basic File Operators

#####Man Pages:

    man 

    <command> -h

#####Output Commandline Input:

    echo
    
    echo -n <document>

Zu Dokument hinzufügen:

    echo hi >> <document>

#####List dir content:

    ls -a   

    ls -al

#####Output File:

    cat

#####Create Document:

    touch

#####Show Executable

    which

#####Running a Binary:

Relative Paths:

|Relative Path	|Meaning	|Absolute Path	|Relative Path	|Running a binary with a Relative Path	|Running A Binary with an Absolute Path|
|---|---|---|---|---|---|
|.	|Current Directory	|/tmp/aa 	|.	|./hello	|/tmp/aa/hello|
|..	|Directory before the current directory	|/tmp	|..	|../hello	|/tmp/hello|
|~	|The user's home directory	|/home/<current user>	|~	|~/hello	|/home/<user>/hello|

#####Switch User:

    su

man zu -s --> Es kann bestimmt werden welche Shell verwendet werden soll:

        -s, --shell SHELL
       The shell that will be invoked.

       The invoked shell is chosen from (highest priority first):

           The shell specified with --shell.

           If --preserve-environment is used, the shell specified by the $SHELL environment variable.

           The shell indicated in the /etc/passwd entry for the target user.

           /bin/sh if a shell could not be found by any above method.

       If the target user has a restricted shell (i.e. the shell field of this user's entry in
       /etc/passwd is not listed in /etc/shells), then the --shell option or the $SHELL environment
       variable won't be taken into account, unless su is called by root.

##Part 2

- Linux Operators
- Advanced File Operators

#####PuTTY

https://www.chiark.greenend.org.uk/~sgtatham/putty/latest.html

#####Operators

&&

    ls && echo hello

&

    & is a background operator, meaning say you run a command that takes 10 seconds to run, normally you wouldn't be able to run commands during that period; however, with & that command will still execute and you'll be able to run other commands.

$

    The $ is an unusually special operator, as it is used to denote environment variables. These are variables set by the computer(you can set them yourself but we'll get into that) that are used to affect different processes and how they work. Meaning that if you edit these variables you can change how certain processes work on your computer. For example your current user is always stored in an environment variable called $USER. You can view these variables with the echo command.

| <-- Pipe

    The pipe is unique because while operators like >> allow you to store the output of a command, the | operator allows you to take the output of a command and use it as input for a second command

    touch test.txt

    echo 12312314 >> test.txt && echo test >> test.txt && echo noot >> text.txt

    cat text.txt | grep noot

    cat text.txt | grep 123

;

    The ; operator works a lot like &&, however it does not require the first command to execute successfully.

.> <-- Redirection

    > is the operator for output redirection. Meaning that you can redirect the output of any command to a file. For example if I were to run echo hello > file, then instead of outputting hello to the console, it would save that output to a file called file.
    It is worth noting that if you were to use this operator on a file that already exists, it would completely erase the contents of that file and replace it with the output from your command

    echo twenty > test

.>> <-- Append

    >> does mainly the same thing as >, with one key difference. >> appends the output of a command to a file, instead of erasing it.

    echo hello >> test

#####Environment Variables

Set Variable:

    export <varname>=<value>

Show Variable:

    $HOME

    $USER

Show all Variables:

    printenv

###Advanced File Operations

#####Change owner and group

    ls -al

These attributes are the user, and group attributes resepectively. Recall that we can edit the permissions for these attributes, so it stands to reason that we can also change these attributes. That is done using the chown command, which allows us to change the user and group for any file. The syntax for this command is chown user:group file. For example if we wanted to change the owner of file to shiba2 as well as the group to shiba2, we could usechown shiba2:shiba2 file

    chown
    
    chown user:group
    
    chown user

    chown shiba2:shiba2 file

Change dir all files in dir at once:

    chown -R shiba2 /dirtest

#####Change file permission

chmod allows you to set the different permissions for a file, and control who can read it. The syntax of this command is typically chmod <permissions> <file> . 

The interesting part is how the permissions are set. They're set using a three digit number, where each digit controls a specific permission, meaning the first digit controls the permissions for a user, the second digit controls the permission for a group, the third digit controls permissions for everyone that's not a part of the user or group.

|Digit	|Meaning|
|---|---|
|1	|That file can be executed|
|2	|That file can be written to|
|3	|That file can be executed and written to|
|4	|That file can be read|
|5	|That file can be read and executed|
|6	|That file can be written to and read|
|7	|That file can be read, written to, and executed|

|Command:	|Meaning|
|---|---|
|chmod 341 file	|The file can be executed and written to by the user that owns the file. The file can be read by the group that owns the file. The file can be executed by everyone else.|
|chmod 777 file	|The file can be read, written to, and executed by the user that owns the file. The file can be read, written to, and executed by the group that owns the file. The file can be read, written to, and executed by everyone else.|
|chmod 455 file	|The file can be read by the user that owns the file. The file can be read and executed by the group that owns the file. The file can be read to and executed by everyone else.|

Note: It is possible to give someone no perms to a file, You can just put 0 as the digit. 770 Means that everyone that isnt a part of the user or group cant do anything to the file.

#####Remove

File:

    rm file

Dir:

    empty:
    rm -d /dirtest
    dir and files:
    rm -r /dirtest

#####Move files

    mv <file> <destination>

to home:

    mv file ~

Note: You can also use mv to change the name of file, mv file ~/ghfds will rename file to ghfds.

##Part 3

Copie:

cp does mainly the same thing as mv, except instead of moving the file it duplicates(copies) it

    cp <file> <destination>

    cp file ~/

    cp file ~/newfilename

Change current dir:

    cd <directory>
    
    cd /tmp

Create new dir:

    mkdir <directory name>

    mkdir ~/test

######Linking:

Hard Link source to desination:

One of those is what's known as "hard linking", which completely duplicates the file, and links the duplicate to the original copy. Meaning What ever is done to the created link, is also done to the original file.

    ln <source> <destination>

    ln /home/test/testfile /tmp/test

Symbolic Link source to destination:

The next form of linking is symbolic linking(symlink). While a hard linked file contains the data in the original file, a symbolic link is just a glorified reference. Meaning that the actual symbolic link has no data in it at all, it's just a reference to another file.
    
    ln -s <file> <destination>

    ln -s /home/test/testfile /tmp/test

Searching dir / files:

    find ~
    
    find /home

    find /var/www

list every file owned by a specific user

    find dir -user <username>

    find / -user paradox

list every file owned by a specific group.

    find dir -group <groupname>

EXAMPLES:

    find /tmp -name core -type f -print | xargs /bin/rm -f
    
        Find files named core in or below the directory /tmp and delete them.  Note that this will work incor‐
        rectly if there are any filenames containing newlines, single or double quotes, or spaces.
    
    find /tmp -name core -type f -print0 | xargs -0 /bin/rm -f
    
        Find files named core in or below the directory /tmp and delete them, processing filenames in  such  a
        way  that file or directory names containing single or double quotes, spaces or newlines are correctly
        handled.  The -name test comes before the -type test in order to avoid having to call stat(2) on every
        file.
    
    find . -type f -exec file '{}' \;
    
        Runs  `file'  on every file in or below the current directory.  Notice that the braces are enclosed in
        single quote marks to protect them from interpretation as shell script punctuation.  The semicolon  is
        similarly  protected by the use of a backslash, though single quotes could have been used in that case
        also.
    
    find / \( -perm -4000 -fprintf /root/suid.txt '%#m %u %p\n' \) , \
    \( -size +100M -fprintf /root/big.txt '%-10s %p\n' \)
    
        Traverse the filesystem just once, listing setuid files and directories into /root/suid.txt and  large
        files into /root/big.txt.
    
    find $HOME -mtime 0
    
        Search  for files in your home directory which have been modified in the last twenty-four hours.  This
        command works this way because the time since each file was last modified is divided by 24  hours  and
        any  remainder  is discarded.  That means that to match -mtime 0, a file will have to have a modifica‐
        tion in the past which is less than 24 hours ago.
    
    find /sbin /usr/sbin -executable \! -readable -print
    
        Search for files which are executable but not readable.
    
    find . -perm 664
    
        Search for files which have read and write permission for their owner,  and  group,  but  which  other
        users  can read but not write to.  Files which meet these criteria but have other permissions bits set
        (for example if someone can execute the file) will not be matched.
    
    find . -perm -664
    
        Search for files which have read and write permission for their owner and group, and which other users
        can  read,  without  regard  to  the presence of any extra permission bits (for example the executable
        bit).  This will match a file which has mode 0777, for example.
    
    find . -perm /222
    
        Search for files which are writable by somebody (their owner, or their group, or anybody else).
    
    find . -perm /220
    find . -perm /u+w,g+w
    find . -perm /u=w,g=w
    
        All three of these commands do the same thing, but the first one uses the octal representation of  the
        file  mode,  and  the  other two use the symbolic form.  These commands all search for files which are
        writable by either their owner or their group.  The files don't have to be writable by both the  owner
        and group to be matched; either will do.
    
    find . -perm -220
    find . -perm -g+w,u+w
    
        Both  these  commands  do  the same thing; search for files which are writable by both their owner and
        their group.
    
    find . -perm -444 -perm /222 \! -perm /111
    find . -perm -a+r -perm /a+w \! -perm /a+x
    
        These two commands both search for files that are readable for everybody ( -perm -444 or -perm  -a+r),
        have  at  least  one  write bit set ( -perm /222 or -perm /a+w) but are not executable for anybody ( !
        -perm /111 and ! -perm /a+x respectively).
    
    cd /source-dir
    find . -name .snapshot -prune -o \( \! -name '*~' -print0 \)|
    cpio -pmd0 /dest-dir
    
        This command copies the contents of /source-dir to /dest-dir, but omits files  and  directories  named
        .snapshot  (and  anything  in them).  It also omits files or directories whose name ends in ~, but not
        their contents.  The construct -prune -o \( ... -print0 \) is quite common.  The idea here is that the
        expression  before  -prune  matches  things which are to be pruned.  However, the -prune action itself
        returns true, so the following -o ensures that the right hand side is evaluated only for those  direc‐
        tories  which didn't get pruned (the contents of the pruned directories are not even visited, so their
        contents are irrelevant).  The expression on the right hand side of the -o is in parentheses only  for
        clarity.   It  emphasises  that the -print0 action takes place only for things that didn't have -prune
        applied to them.  Because the default `and' condition between tests binds more tightly than  -o,  this
        is the default anyway, but the parentheses help to show what is going on.
    
    find repo/ \( -exec test -d '{}'/.svn \; -or \
    -exec test -d {}/.git \; -or -exec test -d {}/CVS \; \) \
    -print -prune
    
        Given the following directory of projects and their associated SCM administrative directories, perform
        an efficient search for the projects' roots:
    
    repo/project1/CVS
    repo/gnu/project2/.svn
    repo/gnu/project3/.svn
    repo/gnu/project3/src/.svn
    repo/project4/.git
    
        In this example, -prune prevents unnecessary descent into directories that have already  been  discov‐
        ered  (for  example we do not search project3/src because we already found project3/.svn), but ensures
        sibling directories (project2 and project3) are found.
    
    find /tmp -type f,d,l
    
        Search for files, directories, and symbolic links in the directory  /tmp  passing  these  types  as  a
        comma-separated list (GNU extension), which is otherwise equivalent to the longer, yet more portable:

#####Find Data in Files:

    grep <string> <file>

    grep <regular expression> <file>

Note: You can search multiple files at the same time, meaning you can theoretically do

    grep <string> <file> <file2>

Find File on Filesystem:

    find /* | grep test1234

Find Data in File with Rownumber:

    grep hello test -n

###Weitere hilfreiche commands

Aktuellen User anzeigen:

    whoami

Aktuellen User und group anzeigen:

    id

Super Do:

    cat /etc/sudoers

    sudo <options> <command>

     -u user, --user=user
                 Run the command as a user other than the default target user (usually root).  The user may
                 be either a user name or a numeric user ID (UID) prefixed with the ‘#’ character (e.g.  #0
                 for UID 0).  When running commands as a UID, many shells require that the ‘#’ be escaped
                 with a backslash (‘\’).  Some security policies may restrict UIDs to those listed in the
                 password database.  The sudoers policy allows UIDs that are not in the password database as
                 long as the targetpw option is not set.  Other security policies may not support this.

    -l, --list  
                 If no command is specified, list the allowed (and forbidden) commands for the invoking user
                 (or the user specified by the -U option) on the current host.  A longer list format is used
                 if this option is specified multiple times and the security policy supports a verbose output
                 format.

                 If a command is specified and is permitted by the security policy, the fully-qualified path
                 to the command is displayed along with any command line arguments.  If command is specified
                 but not allowed, sudo will exit with a status value of 1.


EXAMPLES
     
Note: the following examples assume a properly configured security policy.

     To get a file listing of an unreadable directory:

           $ sudo ls /usr/local/protected

     To list the home directory of user yaz on a machine where the file system holding ~yaz is not exported
     as root:

           $ sudo -u yaz ls ~yaz

     To edit the index.html file as user www:

           $ sudoedit -u www ~www/htdocs/index.html

     To view system logs only accessible to root and users in the adm group:

           $ sudo -g adm more /var/log/syslog

     To run an editor as jim with a different primary group:

           $ sudoedit -u jim -g audio ~jim/sound.txt

     To shut down a machine:

           $ sudo shutdown -r +15 "quick reboot"

     To make a usage listing of the directories in the /home partition.  Note that this runs the commands in
     a sub-shell to make the cd and file redirection work.

           $ sudo sh -c "cd /home ; du -s * | sort -rn > USAGE"


Adding users and groups:

    sudo adduser username
    
    sudo addgroup groupname

    sudo usermod -a -G <groups seperated by commas> <user>

Write to a File:

    nano <file you want to write to>

    exit nano:
    
        ctrl+x
        
        y
        
        <ENTER>

Shell Scripting:

It is worth noting that the sh extension isn't technically needed if you provide a shebang(#!) , and then the path to the shell we want to use to run our command Ahttps://imgur.com/a5AX8U4.

    #!/bin/bash
    echo hallo
    echo whoami
    whoami

###Import Files and Directories

/etc/passwd - Stores user information - Often used to see all the users on a system

/etc/shadow - Has all the passwords of these users

/tmp - Every file inside it gets deleted upon shutdown - used for temporary files

/etc/sudoers - Used to control the sudo permissions of every user on the system -

/home - The directory where all your downloads, documents etc are. - The equivalent on Windows is C:\Users\<user>

/root - The root user's home directory - The equivilent on Windows is C:\Users\Administrator

/usr - Where all your software is installed 

/bin and /sbin - Used for system critical files - DO NOT DELETE

/var - The Linux miscellaneous directory, a myriad of processes store data in /var

$PATH - Stores all the binaries you're able to run - same as $PATH on Windows

     $PATH is an environment variable that contains all the binaries you're able to execute. 

It is worth noting that the paths in $PATH(hah!) are separated by colons. Every executable file that is in any of those paths you are able to run just by typing the name of the executable instead of the full path.


#####Installing packages (apt)

    sudo apt install package

#####Processes

User created processes:

    ps

To view a list of all system processes:

    ps -ef

Kill precess:

    kill <PID>

show most use of system resources:

    top

    Note: The top man page has descriptions for what every value means, and how they affect your system; I highly recommend reading it!

#Linux Challenge

There will be challenges that will involve you using the following commands and techniques:

- Using commands such as: ls, grep, cd, tail, head, curl, strings, tmux, find, locate, diff, tar, xxd
- Understanding cronjobs, MOTD's and system mounts
- SSH'ing to other users accounts using a password and private key
- Locating files on the system hidden in different directories
- Encoding methods (base64, hex)
- MySQL database interaction
- Using SCP to download a file
- Understanding Linux system paths and system variables
- Understanding file permissions
- Using RDP for a GUI


