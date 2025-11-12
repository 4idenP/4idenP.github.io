---
title: "CaptureTaFac 2025 - Blockparty"
subtitle: "*...*"
excerpt: "*...*"
date: 2025-03-08
categories: [crypto]
tags: [aes, ecb]
ctfs: [capturetafac]
author_profile: true
sidebar:
  nav: "docs"
header:
  overlay_color: "#000"
---

# Recon

We are given a *Python* script :

```python
from  Crypto.Cipher import AES
import Crypto.Util.Padding as pad
import json
import key
import socket
import threading

FLAG="fakeflag"

def crypt(text, key):
    cipher = AES.new(bytes(key,"utf-8"), AES.MODE_ECB)
    result = cipher.encrypt(text)
    result = result.hex()
    return result


def decrypt(text, key):
    text = bytes.fromhex(text)
    cipher = AES.new(bytes(key,"utf-8"), AES.MODE_ECB)
    result = cipher.decrypt(text)
    return result


def login(k):
    conn.sendall(b"Please enter your encrypted credentials:  ")
    encrypted = conn.recv(1024).decode('utf-8')
    encrypted = encrypted.strip()
    try:
        decrypted = decrypt(encrypted, k)
        decrypted = decrypt(encrypted, k)
        decrypted = pad.unpad(decrypted, 16)
        decrypted = json.loads(decrypted)
        username = decrypted["username"]
        perms = decrypted["perms"]
        if(username=="admin" and perms == "true"):
            conn.sendall(b"Welcome admin!")
            conn.sendall(b"Here is your flag: "+ FLAG.encode("utf-8") + b"\n\n")
        else:
            conn.sendall(b"Welcome "+username.encode("utf-8")+b" !\n")
            conn.sendall(b"You do not have permission to view the flag.\n\n")
    except Exception as e:
        conn.sendall(b"Your credentials are invalid be careful about the format and padding\n\n")
        print(e)
    return


def register(k):
    conn.sendall(b"Please enter your username:  ")
    username = conn.recv(1024).decode('utf-8')
    username = username[:-1]
    data_to_encrypt = '{"username": "' + username+ '","perms": "guest"}'
    for i in range(len(data_to_encrypt) // 16+1):
        print(data_to_encrypt[i*16:16*(i+1)])
    padded_data = pad.pad(bytes(data_to_encrypt,"utf-8"), 16)
    encrypted = crypt(padded_data, k)

    tmp = '{"username": "admin", "os" :"o","perms": "true"}'
    print(f"GOAL : {crypt(pad.pad(bytes(tmp,'utf-8'), 16), k)}")

    for i in range(32):
        l = b""
        for j in range(16):
            l+=i.to_bytes(1)
        d = crypt(l, k)
        print(f"{i} : {d}")

    conn.sendall(b"Your encrypted credentials are: \n" + encrypted.encode('utf-8')+b"\n\n\n")
    return

HOST = "0.0.0.0" 
PORT = 1337

# Création du socket
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind((HOST, PORT))
server_socket.listen(10)  

print(f"Serveur en attente de connexions sur {HOST}:{PORT}...")

# Fonction pour gérer chaque client
def handle_client(conn, addr):
    print(f"Connexion reçue de {addr}")
    
    #k=key.key()
    k="abcdefdcbea1adf2"
    while True:
        try:
            conn.sendall(b"""Welcome! Would you like to come to the block party? If yes, please register.
                   Type the number corresponding to your choice and press enter.
                   1: register
                   2: login
                   3: exit
               """)
            
            
            # Répondre au client
            data = conn.recv(1024)
            if(data == b"1\n"):
                register(k)
            if(data == b"2\n"):
                login(k)
            if(data == b"3\n"):
                conn.sendall(b"Goodbye! LOOSER!")
                break
           
            if not data:
                break
        except ConnectionResetError:
            break
    print(f"Connexion fermée avec {addr}")
    conn.close()

# Accepter plusieurs connexions
while True:
    conn, addr = server_socket.accept()
    client_thread = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
    client_thread.start()
``` 

This server offers to choices : 

- `register` : the users provides a username, the server returns an encrypted JSON object containing the username and a permission level (*true/guest*)
- `login` : the users provides its encrypted JSON object, the server decrypts it and compares the permission ; if the user has the *admin* username and the *true* permission level, the flag is returned.

So the goal seems to be able to have an encrypted object with the *admin* username and the *true* permission level.

# Investigations

We can see the encryption is done using **AES-ECB**, the cryptographic primitive is fine but the mode, **ECB**, isn't. 

This mode encrypts the provided data block-by-block independently, thus allowing to control and shuffle some blocks arbitrarily. 

Knowing the block size is 16-bytes for **AES**, we can craft an encrypted user object, given that the server inteprets the decrypted payload directly as JSON, we can abuse the syntax :


```python
import socket
import Crypto.Util.Padding as pad

# Connection to the server
host = "localhost"
port = 1337
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((host, port))

# Welcome message reception
sock.recv(1024)

# Registration
sock.sendall(b"1\n")
sock.recv(1024)

# We input an arbitrary 10-chars long block in order to align the total blocks to 3 16-bytes blocks (here 49 chars as the last character of the username is stripped)
# Thus giving the following object :
# {"username": "admin", "os" :"o","perms": "guest"}

username = "admin\", \"os\" :\"o" 
sock.sendall(username.encode('utf-8') + b"\n")

# We receive the encrypted object
encrypted_credentials = sock.recv(1024).decode('utf-8').split("Your encrypted  credentials are: \n")[1].strip()

# Now have to replace the last block by something with perms == true
# In order to do that, let's retrieve the corresponding encrypted block 

sock.recv(1024)
sock.sendall(b"1\n")
sock.recv(1024)
sock.sendall(b"ad\"perms\": \"true\"}" + b"\x10" * 16 +b"\n")
true_block = sock.recv(1024).decode('utf-8').split("Your encrypted credentials are: \n")[1].strip()

# We substitue the last block with the one containing the right permissions
modified_credentials = encrypted_credentials[:64] + true_block[32:96]

# We connect with the crafted informations
sock.recv(1024)
sock.sendall(b"2\n")
sock.recv(1024)

payload = bytes(modified_credentials, 'utf-8')

sock.sendall(payload)

# We retrieve the flag
sock.recv(1024) # "Welcome admin!"
flag = sock.recv(1024).decode('utf-8')
print(flag)

sock.close()
```

Using this exploit, the server sends us the flag back :

> *...*