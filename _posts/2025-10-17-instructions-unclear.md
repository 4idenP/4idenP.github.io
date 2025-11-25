---
title: "Hack.lu CTF 2025 - Instructions unclear"
subtitle: "bro is stuck installing this FLÄN ceiling fan. Instructions are unclear. Can you help 'em?"
excerpt: "bro is stuck installing this FLÄN ceiling fan. Instructions are unclear. Can you help 'em?"
date: 2025-10-17
categories: [rev]
tags: [asm]
ctfs: [hacklu25]
author_profile: true
sidebar:
  nav: "docs"
header:
  overlay_color: "#000"
---

# Investigations

We start with a single pdf file containing instrucitons on how to build a lamp, on a single page with images.

The pdf seems very big for such few content : 

```
-rw-r--r-- 1 root root 12851533 Oct 17 23:38 instructions.pdf
```
The first reflex is to parse the pdf using the `pdf-parser` *Python* module. We rapidly notice a strange object : 

```
obj 8 0
 Type: /XObject
 Referencing: 
 Contains stream

  <<
    /BitsPerComponent 8
    /ColorSpace /DeviceRGB
    /Filter [ /ASCII85Decode /FlateDecode ]
    /Height 200
    /Subtype /Image
    /Type /XObject
    /Width 440471
    /Length 10863939
  >>
```

It is a `440471x200` image, which is pretty unusual, furthermore because it is not visible on the pdf. Let's extract the object : 

```
~# sed -n '/^8 0 obj/,/^endobj/p' instructions.pdf > obj8.txt
```

Now let's convert it to the PNG format as is it currently pure RGB data : 

```python
from PIL import Image
import numpy as np

width = 440471
height = 200

data = open("obj8_decompressed.bin", "rb").read()
img = Image.frombytes("RGB", (width, height), data)
img.save("obj8.png")
```

By previewing the image, we notice it looks like a huuuuuge barcode, at least to big for classical barcode readers. Let's write our own, guessing the encoding is **Code128**, as there are no control characters at the beginning/end : 

> https://fr.wikipedia.org/wiki/Code_128

```python
from PIL import Image
import numpy as np

# Compute a 1D-array containing the barcode as binary data

im = Image.open("obj8.png").convert("L")
w, h = im.size
line = np.array(im)[h//2, :]
binary_line = (line < 128).astype(int)

runs = []
current_value = binary_line[0]
count = 1

# Count elements widths and store the data as tuples (color, width)
# We divide by two and round the result for each element width as the base unit seems to be 2 pixels for this barcode

for pixel in binary_line[1:]:
    if pixel == current_value:
        count += 1
    else:
        fixed = int(count/2)
        if fixed == 5: fixed = 4
        runs.append((int(current_value), fixed))
        current_value = pixel
        count = 1
runs.append((int(current_value), int(count/2)))
runs = runs[1:-1] # Remove padding pixels

# Group elements by 6 in order to retrieve the full list of characters composing the barcode

def chunk_runs(runs):
    chars = []
    i = 0
    while i + 5 < len(runs):
        char = runs[i:i+6]
        chars.append(char)
        i += 6
    return chars

characters = chunk_runs(runs)

# Added fixes into the table as some translations wheren't accurate because of the rounding, e.g. some 3 -> 4 or 4 -> 3 (intentional ?)

CODE128_TABLE = {
    (2,1,2,2,2,2): ' ',  (2,2,2,1,2,2): '!',  (2,2,2,2,2,1): '"',
    (1,2,1,2,2,3): '#',  (1,2,1,3,2,2): '$',  (1,3,1,2,2,2): '%',
    (1,2,2,2,1,3): '&',  (1,2,2,3,1,2): "'",  (1,3,2,2,1,2): '(',
    (2,2,1,2,1,3): ')',  (2,2,1,3,1,2): '*',  (2,3,1,2,1,2): '+',
    (1,1,2,2,3,2): ',',  (1,2,2,1,3,2): '-',  (1,2,2,2,3,1): '.',
    (1,1,3,2,2,2): '/',  (1,2,3,1,2,2): '0',  (1,2,3,2,2,1): '1',
    (2,2,3,2,1,1): '2',  (2,2,1,1,3,2): '3',  (2,2,1,2,3,1): '4',
    (2,1,3,2,1,2): '5',  (2,2,3,1,1,2): '6',  (3,1,2,1,3,1): '7',
    (3,1,1,2,2,2): '8',  (3,2,1,1,2,2): '9',  (3,2,1,2,2,1): ':',
    (3,1,2,2,1,2): ';',  (3,2,2,1,1,2): '<',  (3,2,2,2,1,1): '=',
    (2,1,2,1,2,3): '>',  (2,1,2,3,2,1): '?',  (2,3,2,1,2,1): '@',
    (1,1,1,3,2,3): 'A',  (1,3,1,1,2,3): 'B',  (1,3,1,3,2,1): 'C',
    (1,1,2,3,1,3): 'D',  (1,3,2,1,1,3): 'E',  (1,3,2,3,1,1): 'F',
    (2,1,1,3,1,3): 'G',  (2,3,1,1,1,3): 'H',  (2,3,1,3,1,1): 'I',
    (1,1,2,1,3,3): 'J',  (1,1,2,3,3,1): 'K',  (1,3,2,1,3,1): 'L',
    (1,1,3,1,2,3): 'M',  (1,1,3,3,2,1): 'N',  (1,3,3,1,2,1): 'O',
    (3,1,3,1,2,1): 'P',  (2,1,1,3,3,1): 'Q',  (2,3,1,1,3,1): 'R',
    (2,1,3,1,1,3): 'S',  (2,1,3,3,1,1): 'T',  (2,1,3,1,3,1): 'U',
    (3,1,1,1,2,3): 'V',  (3,1,1,3,2,1): 'W',  (3,3,1,1,2,1): 'X',
    (3,1,2,1,1,3): 'Y',  (3,1,2,3,1,1): 'Z',  (3,3,2,1,1,1): '[',
    (3,1,4,1,1,1): '\\', (2,2,1,4,1,1): ']',  (4,3,1,1,1,1): '^',
    (1,1,1,2,2,4): '_',  (1,1,1,4,2,2): '`',  (1,2,1,1,2,4): 'a',
    (1,2,1,4,2,1): 'b',  (1,4,1,1,2,2): 'c',  (1,4,1,2,2,1): 'd',
    (1,1,2,2,1,4): 'e',  (1,1,2,4,1,2): 'f',  (1,2,2,1,1,4): 'g',
    (1,2,2,4,1,1): 'h',  (1,4,2,1,1,2): 'i',  (1,4,2,2,1,1): '\n', # (1,4,2,2,1,1): 'j',
    (2,4,1,2,1,1): 'k',  (2,2,1,1,1,4): 'l',  (4,1,3,1,1,1): 'm',
    (2,4,1,1,1,2): 'n',  (1,3,4,1,1,1): 'o',  (1,1,1,2,4,2): 'p',
    (1,2,1,1,4,2): 'q',  (1,2,1,2,4,1): 'r',  (1,1,4,2,1,2): 's',
    (1,2,4,1,1,2): 't',  (1,2,4,2,1,1): 'u',  (4,1,1,2,1,2): 'v',
    (4,2,1,1,1,2): 'w',  (4,2,1,2,1,1): 'x',  (2,1,2,1,4,1): 'y',
    (2,1,4,1,2,1): 'z',  (4,1,2,1,2,1): '{',  (1,1,1,1,4,3): '|',
    (1,1,1,3,4,1): '}',  (1,3,1,1,4,1): '~',  (2,3,4,1,1,1): '\r',
    (1,1,4,1,3,1): '',   (4,1,1,3,1,1): '',   (2,1,1,2,1,4): '',   # FNC 4, SHIFT, Start Code B
    (3,1,1,1,4,1): '',   (3,3,2,1,1,1): '[',  (4,3,1,1,2,1): 'X',  # Code A - Fixes start here
    (1,1,2,2,3,2): ',',  (1,4,4,1,1,1): 'o',  (1,1,4,1,4,1): '',   # Code C
    (4,1,4,1,1,1): 'm',  (3,4,1,1,2,1): 'X',  (1,1,2,2,4,2): ',',
    (1,2,4,2,2,1): '1',  (1,3,1,4,2,1): 'C',  (1,1,3,4,2,1): 'N',
    (1,3,1,1,2,4): 'B',  (4,3,2,1,1,1): '[',  (4,1,1,1,4,1): '',
    (2,2,4,2,1,1): '2',  (4,2,1,2,2,1): ':',  (1,1,4,3,2,1): 'N',
    (2,4,1,3,1,1): 'I',  (1,2,4,1,2,2): '0',  (1,4,1,1,2,3): 'B',
    (1,1,2,4,3,1): 'K',  (3,1,2,1,4,1): '7',  (2,1,4,2,1,2): '5',
    (3,4,2,1,1,1): '[',  (2,1,4,1,1,3): 'S',  (1,1,1,4,2,3): 'A',
    (1,1,1,3,2,4): 'A',  (4,1,2,1,3,1): '7',  (2,1,3,1,1,4): 'S',
    (2,2,1,1,4,2): '3',  (4,1,3,1,2,1): 'P',  (1,1,2,3,4,1): 'K',
    (4,2,1,1,2,2): '9',  (4,1,1,2,2,2): '8',  (1,3,2,4,1,1): 'F',
    (1,1,4,1,2,3): 'M',  (1,1,2,3,1,4): 'D',  (1,1,3,1,2,4): 'M',
    (3,1,2,1,1,4): 'Y',  (2,2,1,2,4,1): '4',  (2,2,4,1,1,2): '6',
    (1,4,2,3,1,1): 'F',  (1,4,2,1,3,1): 'L',  (1,4,2,1,1,3): 'E',
    (3,1,4,1,2,1): 'P',  (1,1,2,4,1,3): 'D'
}

decoded = []
unknown = set()

# Translate the characters using the Code128 standard table (interpreting as Code B according to the "Start code B" control character) 

for char in characters:
    tup = []
    for i in char:
        tup.append(i[1])
    tup = tuple(tup)
    if tup in CODE128_TABLE:
        decoded.append(CODE128_TABLE[tup])
    else:
        unknown.add(tup)
        decoded.append(str(tup))

result = ''.join(decoded)
print(result)
```

**Code128** works by encoding a character with 6 elements (3 spaces + 3 bars), then the width of the bars/spaces defines which character is being encoded
> https://en.wikipedia.org/wiki/Code_128

Knowing this and adjusting a few errors in the encoding manually, we get this pseudo-assembly code : 

```
.section .ikea
FLEN:    db 65
paX:    db 23
BLKSZ:   db 12
b00ts: db 47
c5d: db 225,204,82,249,67,214,139,164,154,116,172,47,62,84,45,3,47,104,35,84,93,44,34,6,25,163,30,206,78,117,5,225,233,23,152,55,146,238,226,49,74,173,199,34,15,78,84,81,161,96,220,110,128,201,46,27,123,41,191,6,123,58,89,119,69
kallax: db 3,0,0,2,0,0,4,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,5,0,0,1,0,0
billy: db 166,241,180,132,190,47,251,88,10,46,127,195,92,216,151,226,103,173,3,218,0,14,199,119,228,111,214,104,131,252,134,152,225,52,39,60,56,179,4,144,24,203,233,156,167,91,146,254,73,27,187,123,113,40,83,41,1,81,22,202,201,176,100,158,87,50,128,182,84,209,55,240,20,62,51,184,75,220,175,192,12,172,5,204,61,186,30,154,255,101,213,208,67,145,23,36,170,141,108,212,181,193,82,37,74,211,109,155,168,221,138,207,121,130,198,9,188,164,124,249,217,157,110,139,210,229,8,116,93,6,178,29,70,2,129,53,183,197,99,95,38,244,65,125,85,49,194,94,11,219,148,215,115,223,26,140,44,245,19,15,248,86,7,205,253,171,160,169,246,105,191,54,243,239,238,79,13,242,143,72,68,25,227,97,34,31,161,196,32,147,126,78,71,57,159,137,114,42,230,250,117,106,59,17,133,98,16,177,136,90,232,174,80,206,185,234,107,76,35,162,237,58,200,163,89,77,222,142,102,21,189,122,48,224,165,69,64,247,149,66,18,236,153,135,96,33,28,235,231,150,120,118,112,63,45,43,177,88,7,134,38,179,127,126,41,20,25,233,37,141,82,124,215,206,128,237,239,19,227,180,83,248,249,165,57,228,232,161,94,6,192,142,64,200,77,42,132,4,221,153,65,48,238,135,89,27,70,122,13,210,16,155,160,119,17,240,242,188,251,51,107,22,208,162,197,230,39,229,146,157,168,76,67,105,49,213,96,241,109,104,87,125,68,44,66,140,26,136,143,203,245,211,183,10,193,43,100,172,171,28,85,98,226,151,73,236,91,40,198,110,219,114,117,111,23,60,101,244,62,0,47,186,175,174,191,167,52,148,189,173,61,194,250,231,130,54,50,187,93,185,9,218,255,214,149,106,32,145,71,31,209,202,29,154,118,190,201,56,12,204,84,5,115,246,58,14,166,103,235,170,147,247,53,196,2,99,3,92,199,150,97,46,30,131,35,176,81,78,222,133,59,18,178,253,79,182,123,75,217,163,137,113,223,95,21,252,63,195,158,121,36,34,205,184,224,129,102,11,8,243,225,159,254,33,181,112,90,74,216,138,120,80,24,1,220,156,139,72,55,207,164,86,69,234,169,144,108,15,212,152,116,45,58,14,250,180,0,171,247,215,46,166,50,118,73,231,33,7,223,79,242,113,61,88,177,2,147,202,18,15,167,152,101,27,183,220,158,30,224,128,153,198,187,6,178,22,34,232,210,5,191,219,110,226,244,9,117,45,248,245,8,71,161,124,205,105,69,92,241,132,246,81,51,142,20,37,172,208,160,75,62,53,42,13,236,193,80,144,181,151,155,235,170,141,59,189,41,148,87,233,197,109,123,253,206,19,86,126,188,254,195,182,133,100,130,55,116,201,4,112,131,225,96,125,114,60,176,194,149,21,211,156,200,134,216,240,111,28,243,140,68,255,237,3,102,10,64,207,238,12,67,32,29,99,239,162,164,174,120,115,90,190,230,184,89,228,78,221,36,107,52,157,95,17,108,74,234,145,185,54,154,229,76,251,94,23,218,137,204,26,136,70,222,186,165,91,39,179,173,163,85,66,24,168,150,72,47,199,139,119,217,169,122,82,40,214,213,175,252,56,209,146,63,57,11,138,127,104,31,1,159,97,83,249,196,106,48,43,227,143,98,16,212,135,121,84,44,35,203,129,93,38,25,192,103,77,65,49,255,148,204,174,252,10,233,164,253,76,113,9,187,33,51,20,87,196,59,193,27,221,116,40,107,37,69,38,172,129,56,72,194,119,142,203,168,224,120,133,156,247,195,166,143,70,241,126,118,90,191,186,235,234,104,100,210,34,207,152,246,208,229,109,64,57,190,160,44,140,132,139,28,62,79,92,182,167,19,202,238,60,111,228,213,163,189,237,14,135,13,58,15,150,81,48,42,226,93,211,236,21,157,217,250,231,24,185,68,7,198,225,138,219,192,249,171,105,242,26,106,77,197,95,200,245,180,201,179,43,88,244,136,147,6,121,39,153,223,36,146,232,144,89,161,251,218,178,181,215,12,78,22,230,176,159,169,99,80,17,206,35,114,66,212,173,85,53,52,222,127,31,125,103,82,243,71,8,155,83,29,0,108,254,18,154,84,177,115,94,214,101,46,188,102,73,1,170,97,5,151,134,98,45,4,131,91,65,54,32,16,205,141,49,220,158,137,124,112,23,2,209,130,67,199,122,227,41,11,184,96,47,183,149,239,110,25,175,145,123,50,30,240,165,74,55,3,216,128,117,63,248,162,86,75,61,144,192,167,72,80,203,160,78,18,82,208,212,222,235,228,84,161,12,5,73,132,239,89,252,56,21,233,102,187,231,36,2,74,246,39,85,1,130,110,0,97,226,240,156,254,151,47,31,205,137,150,224,64,79,206,123,75,159,202,111,214,183,193,220,67,140,55,3,182,93,136,200,135,127,117,145,17,8,204,34,38,115,100,255,114,26,43,249,68,46,25,186,44,19,91,210,42,32,185,81,7,52,165,90,71,178,147,27,195,98,124,134,216,163,177,45,103,62,170,173,108,139,146,232,10,229,121,131,16,191,94,237,190,181,245,171,230,57,172,247,122,107,154,168,169,213,217,209,238,241,201,194,225,95,158,20,133,86,40,128,125,179,50,157,242,142,243,129,174,218,223,116,54,37,175,118,99,24,13,104,23,164,120,184,119,66,180,87,77,253,244,251,101,88,83,215,29,248,152,59,198,166,92,69,48,4,143,138,76,30,176,250,65,49,211,199,221,109,227,22,162,113,41,11,219,148,96,58,197,149,61,15,196,141,70,35,9,188,153,105,33,6,234,207,155,126,51,28,236,189,112,106,63,60,53,14,133,211,196,173,138,240,254,105,34,251,116,151,242,225,122,106,127,120,33,36,40,56,130,156,252,207,29,219,227,100,149,46,186,176,70,51,200,101,230,136,109,67,243,21,234,134,93,50,150,64,74,19,24,141,155,168,241,25,18,16,171,175,121,201,245,255,187,115,82,3,226,107,43,154,124,42,145,52,32,182,91,157,62,237,76,75,220,1,45,85,218,193,54,2,35,253,90,163,58,113,28,203,167,98,4,162,152,189,87,217,146,123,49,89,0,41,192,13,214,61,9,47,205,222,147,38,231,246,199,174,39,129,232,114,135,92,83,55,14,185,238,224,102,161,78,53,216,159,190,65,131,165,139,80,158,81,212,63,140,79,30,26,143,233,248,71,249,22,247,77,180,166,179,197,236,223,244,66,6,125,183,170,137,213,160,86,250,195,119,27,12,208,210,37,177,169,97,48,228,215,112,110,84,59,5,209,221,10,229,144,103,11,153,72,198,164,118,69,7,191,132,104,23,172,148,96,17,202,194,184,88,20,188,126,73,235,204,108,60,31,15,8,178,128,94,44,206,111,95,68,239,181,142,117,99,57
.section .bss.shuffled
IN:      rb 65          CAND:    rb 65          BLK:     rb 12          RND:     rb 12          SA:      rb 97          SB:      rb 89          SP:      rb 97          KA:      rb 2           KB:      rb 2           PK:      rb 2           DUMMY:   rb 64          SF:      rb 61          PASS:    rb 1           
.section .text
        mov     PASS, 0
        mov     sumct, 0
        mov     term, 0
        mov     i, 0
precs_i:
        cmp     i, FLEN
        jl      tradfi
        jmp     tradfine
tradfi:
        load    t0, c5d[i]
        add     sumct, t0
        add     sumct, term
        add     term, paX
        add     i, 1
        jmp     precs_i
tradfine:
        mod     sumct, 256
        mov     chk, sumct
        xor     chk, b00ts
        cmp     0, chk
        jl      union_work
        jmp     checkin
union_work:
        mov     i, 0
fw_init:
        mov     t1, i
        mod     t1, 61
        store   SF[i], t1
        add     i, 1
        cmp     i, 61
        jl      fw_init
        mov     z, paX
        xor     z, paX           
        mov     i, 0
fw_i:
        cmp     i, 64
        jl      fw_do
        jmp     checkin
fw_do:
        load    d, DUMMY[i]
        xor     d, z
        store   DUMMY[i], d
        add     i, 1
        jmp     fw_i
checkin:
        mov     offset, 0
        mov     bidx, 0
blk_check:
        cmp     offset, FLEN
        jl      do_block
        jmp     compare
do_block:
        mov     lenb, 0
        mov     i, 0
drucker0:
        cmp     i, BLKSZ
        jl      cc_check_flen
        jmp     cc_done
cc_check_flen:
        mov     t1, offset
        add     t1, i
        cmp     t1, FLEN
        jl      cc_copy
        jmp     cc_done
cc_copy:
        add     lenb, 1
        add     i, 1
        jmp     drucker0
cc_done:
        mov     i, 0
blk_copy:
        cmp     i, lenb
        jl      blk_copy_do
        jmp     stackfault
blk_copy_do:
        mov     t1, offset
        add     t1, i
        load    t2, IN[t1]
        store   BLK[i], t2
        add     i, 1
        jmp     blk_copy
stackfault:
        mov     flags, paX
        mov     t3, bidx
        add     t3, bidx
        add     t3, bidx
        add     flags, t3
        add     flags, 0x5A
        mov     t4, flags
        mod     t4, 2
        mov     use_billy, t4
        mov     t5, flags
        mod     t5, 4
        mov     use_roll, 0
        cmp     1, t5
        jl      set_roll
        jmp     steuerfahndung
set_roll:
        mov     use_roll, 1
steuerfahndung:
        mov     billy_id, paX
        mov     t6, bidx
        add     t6, bidx
        add     t6, bidx
        add     billy_id, t6
        mod     billy_id, 32
        load    billy_idx, kallax[billy_id]
        mov     t0, 0
        mov     i7, 0
ka_i7:
        cmp     i7, 7
        jl      selfservice
        jmp     r8none7
selfservice:
        add     t0, bidx
        add     i7, 1
        jmp     ka_i7
r8none7:
        mov     t0b, paX
        add     t0b, t0
        add     t0b, 11
        store   KA[0], t0b
        mov     t1b, paX
        xor     t1b, 0xA5
        store   KA[1], t1b
        mov     t2b, 0
        mov     i9, 0
kb_i9:
        cmp     i9, 9
        jl      kb_add
        jmp     kb_done9
kb_add:
        add     t2b, bidx
        add     i9, 1
        jmp     kb_i9
kb_done9:
        mov     t2b2, paX
        add     t2b2, t2b
        add     t2b2, 23
        store   KB[0], t2b2
        mov     t3b, paX
        add     t3b, paX
        add     t3b, paX
        add     t3b, paX
        add     t3b, paX
        add     t3b, 0x3D
        store   KB[1], t3b
        mov     b13, 0
        mov     i13, 0
pk_i13:
        cmp     i13, 13
        jl      pk_add13
        jmp     pk_done13
pk_add13:
        add     b13, bidx
        add     i13, 1
        jmp     pk_i13
pk_done13:
        mov     pk0, paX
        add     pk0, b13
        add     pk0, 57
        store   PK[0], pk0
        mov     b17, 0
        mov     i17, 0
pk_i17:
        cmp     i17, 17
        jl      pk_add17
        jmp     pk_done17
pk_add17:
        add     b17, bidx
        add     i17, 1
        jmp     pk_i17
pk_done17:
        mov     pk1, paX
        add     pk1, b17
        add     pk1, 91
        store   PK[1], pk1
        mov     i, 0
init_SA:
        mov     t0, i
        store   SA[i], t0
        add     i, 1
        cmp     i, 97
        jl      init_SA
        mov     i, 0
        mov     j, 0
ksa_a:
        load    t0, SA[i]
        load    kbyte, KA[i]
        add     j, t0
        add     j, kbyte
        mod     j, 97
        load    t1, SA[j]
        store   SA[j], t0
        store   SA[i], t1
        add     i, 1
        cmp     i, 97
        jl      ksa_a
        mov     i, 0
init_SB:
        mov     t0, i
        store   SB[i], t0
        add     i, 1
        cmp     i, 89
        jl      init_SB
        mov     i, 0
        mov     j, 0
cult:
        load    t0, SB[i]
        load    kbyte, KB[i]
        add     j, t0
        add     j, kbyte
        mod     j, 89
        load    t1, SB[j]
        store   SB[j], t0
        store   SB[i], t1
        add     i, 1
        cmp     i, 89
        jl      cult
        mov     i, 0
        mov     jA, 0
        mov     iB, 0
        mov     jB, 0
        mov     k, 0
prga_mask:
        cmp     k, lenb
        jl      nackt
        jmp     stage_billy
nackt:
        add     i, 1
        mod     i, 97
        load    t0, SA[i]
        add     jA, t0
        mod     jA, 97
        load    t1, SA[jA]
        store   SA[jA], t0
        store   SA[i], t1
        load    t2, SA[i]
        load    t3, SA[A]
        add     t2, t3
        mod     t2, 97
        load    kAbyte, SA[t2]
        add     iB, 1
        mod     iB, 89
        load    u0, SB[iB]
        add     jB, u0
        mod     jB, 89
        load    u1, SB[jB]
        store   SB[jB], u0
        store   SB[iB], u1
        load    u2, SB[iB]
        load    u3, SB[jB]
        add     u2, u3
        mod     u2, 89
        load    kBbyte, SB[u2]
        load    x, BLK[k]
        xor     x, kAbyte
        xor     x, kBbyte
        store   BLK[k], x
        add     k, 1
        jmp     prga_mask
stage_billy:
        cmp     0, use_billy
        jl      do_billy
        jmp     tombola
do_billy:
        mov     base, 0
        mov     i, 0
knut:
        cmp     i, billy_idx
        jl      knut_add
        jmp     billy_i
knut_add:
        add     base, 256
        add     i, 1
        jmp     knut
billy_i:
        mov     i, 0
billy_do:
        cmp     i, lenb
        jl      billy_apply
        jmp     tombola
billy_apply:
        load    byte, BLK[i]
        mov     t0, base
        add     t0, byte
        load    t1, billy[t0]
        store   BLK[i], t1
        add     i, 1
        jmp     billy_do
tombola:
        cmp     0, use_roll
        jl      do_roll
        jmp     stage_perm
do_roll:
        mov     acc, paX
        mov     t0, bidx
        add     t0, bidx
        add     t0, bidx
        add     acc, t0
        add     acc, 17
        mov     step, paX
        mov     t5b, bidx
        add     t5b, bidx
        add     t5b, bidx
        add     t5b, bidx
        add     t5b, bidx
        add     step, t5b
        add     step, 1
        mov     i, 0
roll_i:
        cmp     i, lenb
        jl      imbus
        jmp     stage_perm
imbus:
        load    x, BLK[i]
        mov     y, x
        xor     y, acc
        store   BLK[i], y
        add     acc, x
        add     acc, step
        mod     acc, 256
        add     i, 1
        jmp     roll_i
stage_perm:
        mov     i, 0
init_SP:
        mov     t0, i
        store   SP[i], t0
        add     i, 1
        cmp     i, 97
        jl      init_SP
        mov     i, 0
        mov     j, 0
ksa_sp:
        load    t0, SP[i]
        load    kbyte, PK[i]
        add     j, t0
        add     j, kbyte
        mod     j, 97
        load    t1, SP[j]
        store   SP[j], t0
        store   SP[i], t1
        add     i, 1
        cmp     i, 97
        jl      ksa_sp
        mov     i, 0
        mov     j, 0
        mov     k, 0
prga_sp:
        cmp     k, lenb
        jl      prga_sp_do
        jmp     permute
prga_sp_do:
        add     i, 1
        mod     i, 97
        load    t0, SP[i]
        add     j, t0
        mod     j, 97
        load    t1, SP[j]
        store   SP[j], t0
        store   SP[i], t1
        load    t2, SP[i]
        load    t3, SP[j]
        add     t2, t3
        mod     t2, 97
        load    t4, SP[t2]
        store   RND[k], t4
        add     k, 1
        jmp     prga_sp
permute:
        mov     idx, lenb
perm_i:
        add     idx, -1
        cmp     0, idx
        jl      BADRING
        jmp     store_block
BADRING:
        load    t0, RND[idx]
        mov     t1, idx
        add     t1, 1
        mod     t0, t1
        load    a, BLK[idx]
        load    b, BLK[t0]
        store   BLK[idx], b
        store   BLK[t0], a
        jmp     perm_i
store_block:
        mov     i, 0
wb_i:
        cmp     i, lenb
        jl      wb_do
        jmp     hotdogs
wb_do:
        mov     t1, offset
        add     t1, i
        load    t2, BLK[i]
        store   CAND[t1], t2
        add     i, 1
        jmp     wb_i
hotdogs:
        add     offset, lenb
        add     bidx, 1
        jmp     blk_check
compare:
        mov     i, 0
cmp_i:
        cmp     i, FLEN
        jl      cmp_do
        jmp     ingrid
cmp_do:
        load    a, CAND[i]
        load    b, c5d[i]
        cmp     a, b
        jl      fail
        cmp     b, a
        jl      fail
        add     i, 1
        jmp     cmp_i
ingrid:
        mov     PASS, 1
        jmp     done
fail:
        mov     PASS, 0
        mov     z2, paX
        xor     z2, paX
        mov     pass2, 0
pn_outer:
        cmp     pass2, 2
        jl      pn_begin
        jmp     done
pn_begin:
        mov     i, 0
pn_i:
        cmp     i, FLEN
        jl      pn_do
        add     pass2, 1
        jmp     pn_outer
pn_do:
        load    v, CAND[i]
        xor     v, z2
        store   CAND[i], v
        add     i, 1
        jmp     pn_i
done:
        halt
```

By analyzing it, the pseudo-assembly extracted from the Code128 image implements a minimal virtual machine, structured into three stages:
- A pre-computation phase (`precs_i`)
- A fake conditional path (`union_work`)
- The real block-based verification (`checkin / blk_check`)

### Pre-computation and derivation of `chk`

The pre-computation iterates over a constant table `c5d` (65 bytes) and accumulates the sum of all bytes in the table, an arithmetic progression based on `paX = 23`, and then reduces the result mod 256 :

```
b00ts = 47
sumct = ( Σ c5d[i]  +  Σ_{i=0..64} (23 * i) ) mod 256
chk   = sumct XOR b00ts
```

Then : 

```
if chk < 0:
    jump union_work
else:
    jump checkin
```

Since `chk` is an unsigned byte, it can never be negative : `union_work` is a decoy path. The real execution flow always continues into `checkin`.

### Block-based verification

The verification logic uses three buffers :

```
IN    : user input (65 bytes)
CAND  : intermediate buffer (65 bytes)
BLKSZ : 12
```

The program splits IN into 12-byte blocks :

```
IN[0..11], IN[12..23], IN[24..35], ...
```

For each block, the block is linearly mixed into the corresponding portion of `CAND` and the transformed block is compared to a reference block inside `c5d`.

In pseudo-code : 

```
for block in blocks(IN, 12):
    mix = transform(block)
    if mix != c5d[block_index]:
        reject
accept
```

Thus, the transformation is fully reversible, to recover the correct input we just have to invert `transform()` on each constant block.

### Flag reconstruction

Inverting the transformation for each block yields :

```
flag = concat(
    inverse_transform(c5d[0..11]),
    inverse_transform(c5d[12..23]),
    ...
)
```

This way, we can rebuild the exact input used for this challenge, i.e. the flag :

> flag{br3_unsTuUc7-d4_c3LInG_f4N_y33t--br00_1nStRuCT10N5_n0W_Cl3R}
