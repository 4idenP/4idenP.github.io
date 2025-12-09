---
title: "BackdoorCTF25 - Fractonacci"
subtitle: "Beautiful. Red. Fractonacci. What could this mean??"
excerpt: "Beautiful. Red. Fractonacci. What could this mean??"
date: 2025-12-07
categories: [steganography]
tags: [image, color channel]
ctfs: [backdoorctf25]
author_profile: true
sidebar:
  nav: "docs"
header:
  overlay_color: "#000"
---

# Investigations

We have an image representing a Newton fractal, with mostly red pixels. By looking in the red RGB channel, at the beginning of the image, we can notice artifacts that seem to follow an exponential progression regarding their coordinates.

Therefore, we guess we have to extract the red channel of specific pixels whose coordinates follow the *Fibonacci suite* : 

```python
from PIL import Image

img = Image.open("./challenge.png")
pixels = img.load()

# The first two values of the fibonacci suite are "1", here we only retrieve it once since it will produce the same value for both
numbers : list = [1]
extracted = []

idx = 0
coord = 0
while coord < img.width * img.height:

    if idx == len(numbers):
        numbers.append(numbers[idx-1]+numbers[idx-2])

    coord : int = numbers[idx]

    x = coord % img.width
    y = int(coord/img.height)

    if coord >= img.width * img.height:
        break

    extracted.append(pixels[x,y][0])

    idx+=1

print(''.join(chr(c) for c in extracted))
```

```
~# python script.py
lag{n3wt0n_fr4c74l5_4r3_b34u71ful}lp
```

We can deduce the full flag : 

> flag{n3wt0n_fr4c74l5_4r3_b34u71ful}
