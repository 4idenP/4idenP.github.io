---
title: "Platypwn 2025 - Key Conversation"
subtitle: "Someone managed to eavesdrop on some super secure communication and sold you the data. They told you there’s value in those bits and bytes. You just need to find the ones that are valuable."
excerpt: "Someone managed to eavesdrop on some super secure communication and sold you the data. They told you there’s value in those bits and bytes. You just need to find the ones that are valuable."
date: 2025-11-16
categories: [forensics]
tags: [wireshark, zstd]
ctfs: [platypwn25]
author_profile: true
sidebar:
  nav: "docs"
header:
  overlay_color: "#000"
---

# Recon

We get a `pcap` file with two objects extractable from the HTTP conversations : 

```
hello		788 bytes	text/plain
Conversation	38 kB		text/html
```

# Investigations

The two files appear to be *zstd* compressed : 

```
Conversation:                  Zstandard compressed data (v0.8+), Dictionary ID: None
hello:                         Zstandard compressed data (v0.8+), Dictionary ID: None
```

By decompressing `hello` we get the following text :

```
~# zstd -d hello -o hello.txt

Alice: It's past midnight, I think we are ready.
Bob: I hope noone EVEsdrops on this conversation.
Alice: Surely not, we are totally safe.
Bob: But are you really sure? Did you take all the precautions we talked about?
Alice: Yes yes, we got the best security by obscurity on our side. There's no way they're breaking our encryption.
Bob: Ok ok, fine. Then handover the flag, please.
Alice: Here you go: Cf7z9+sZxDpNX4XxtVqY3X1NH+s/WlE6hWdpwKgIVRr3SdLls1dmYF7TFS/s2vlUVLxFb47Qd0f5t7GcKacwwvao++I4pA1ZHv8=
Alice: Remember, its Base64 encoded and AES256GCM encrypted. The nonce is also Base64: 1hAHFOm7LXsF7SCj
Bob: Cool, and how do I get the key?
Alice: Shhht, that's the part that we are trying to keep secret. We cannot use this connection to
transmit it. I will mark it's location for you. Remember that AES256 keys are 32 bytes large, and
not larger. Once you have something that looks like the key, delete suspicious looking bytes until
you reach 32 bytes. Then you can use it to decrypt the flag.
Bob: Is this really necessary?
```

- So the challenge here seems to be able to retrieve the key in the second embedde file, `Conversation`, which is the HTML page of the "Conversation" Wikipedia page :

> https://en.wikipedia.org/wiki/Conversation

```
~# zstd -d Conversation -o Conversation.html
```

By looking for the word `key` on the page, we can find this strange sentence where text seem to be missing : `"" is the key, he wrote.`. Naturally, something seems to have been removed from the file during decompression. The *zstd* library offers the possibility to display informations on compressed files using the `-l` option : 

```
~# zstd -l Conversation

Frames  Skips  Compressed  Uncompressed  Ratio  Check  Filename
     3      1    37.3 KiB                        None  Conversation
```

We can see the "Skips" column is set to 1. Looking at the **RFC** for *zstd*, we learn there exists "skippable frames" : `Skippable frames allow the insertion of user-defined metadata into a flow of concatenated frames.`. So that's it, some metadata has been embedded into the compressed data and is thus missing after decompression.

> https://www.rfc-editor.org/rfc/rfc8878.html#name-skippable-frames

Still according to the **RFC**, skippable frames are identifyable by the following magic bytes : `0x184D2A5x` (with `0 <= x <= F`). 

So let's look for the magic bytes in order to extract the hidden frame : 

```
~# xxd -e Conversation | grep "184d2a5."
[...]
00004fb0: 01fd8dae 184d2a5d 00000030 72a700df
[...]
```

Here we see the magic bytes and the following 4 bytes representing the data length : `0x00000030`. So the frame content is `48` bytes long and starts right after. 

The offset being `0x4fb0` = `20400` and the "header" being 8-bytes long, let's extract the frame content starting at `offset=20412` and `count=48` : 

```
~# dd skip=20412 count=48 if=Conversation of=skippable_frame.bin bs=1 | xxd skippable_frame.bin
00000000: df00 a772 0092 6800 cf33 00eb ba00 0ccc  ...r..h..3......
00000010: 0072 b400 987c 00d0 c100 9256 00c1 4900  .r...|.....V..I.
00000020: 5801 00de aa00 f4b7 00da 9800 7175 00bb  X...........qu..
```

There is quite a few null bytes in here, according to the instruction Alice gave : `delete suspicious looking bytes until you reach 32 bytes`, let's delete the null bytes : 

```
~# tr < skippable_frame.bin -d '\000' > sanitized_skippable_frame.bin
```

Now the length of our data is 32-bytes, as advised by Alice : 

```
~# wc -c sanitized_skippable_frame.bin
32 sanitized_skippable_frame.bin
```

This should be our symmetric key, now we decrypt the intercepted ciphertext using the correct key and nonce : 

```python
import base64
from Crypto.Cipher import AES

ciphertext_bytes=base64.b64decode(b"Cf7z9+sZxDpNX4XxtVqY3X1NH+s/WlE6hWdpwKgIVRr3SdLls1dmYF7TFS/s2vlUVLxFb47Qd0f5t7GcKacwwvao++I4pA1ZHv8=")
nonce_bytes=base64.b64decode(b"1hAHFOm7LXsF7SCj")

with open("sanitized_skippable_frame.bin", "rb") as f:
    key_bytes=f.read()

# We take the tag/MAC into account (last 16 bytes of the ciphertext for AES-GCM)
ciphertext = ciphertext_bytes[:-16]
tag = ciphertext_bytes[-16:]

cipher = AES.new(key_bytes, AES.MODE_GCM, nonce=nonce_bytes)

# Decrypt the ciphertext and verify plaintext integrity
plaintext = cipher.decrypt_and_verify(ciphertext, tag)
print(plaintext.decode("utf-8"))
```

> PP{just-because-your-decompressor-tells-you-its-not-there}
