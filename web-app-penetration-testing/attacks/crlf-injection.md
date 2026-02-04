# CRLF Injection

- This attack exploits improper validation of user input.
- The term CRLF consists of the names of the two control characters `Carriage Return (CR)` and `Line Feed (LF)` that mark the beginning of a new line. 
- CRLF injection thus refers to the injection of new lines in places where the beginning of a new line has a special semantic meaning and no proper sanitization is implemented.


### Log Injection

- Check if CRLF characters are logged without sanitizing.

```text
'%0d%0atest2
```

- We can inject malicious code to get RCE.

