---
title: "CYBERGAME-2025 {CRYPTOGRAPHY-CHALLENGES}"
subtitle: "⚡Here is where the Math enjoy cooking our brains,but its always cool to see it when no one can.⚡"
summary: "* Kenyan version organized by: Ministry of Information,Communications and the Digital Economy*"
date: 2025-06-11
cardimage: cybergame.png
featureimage: cybergame.png
caption: cybergame
authors:
  - Havoc: logo.png
---

--
### Advanced Decryption Standard - Codebook
## 📌 Overview

CyberGame CTF was an exciting individual packaged, hands-on competition packed with challenges across multiple categories including **Web**, **binary, **Reverse Engineering**, **Forensics**, and **Crypto**. This write-up covers the challenges I solved on crypto, throught the  process, and the steps i did them. Hope you enjoy the journey as much as I did!.it was fun 

---

1 **CRYPTOGRAPHY**
In this challenge, we were presented with an encrypted file and a cryptographic key. The goal was to decrypt the file and extract the flag, which should follow the format `SK-CERT{something}`. The key provided for AES decryption was given in hexadecimal format, and the encryption was specified to be in ECB (Electronic Codebook) mode.

### Given Information
- **Encryption**: AES in ECB mode
- **Key**: `00000000000000000000000000000000` (hex format)
- **Flag Format**: `SK-CERT{something}`
### Approach

1. **Understanding AES in ECB Mode**: 
   AES (Advanced Encryption Standard) is a symmetric key encryption algorithm. In ECB mode, the data is divided into fixed-size blocks, and each block is encrypted independently using the same key. 

2. **Decryption Process**:
   - First, we read the encrypted file (`ecb.dat`).
   - We then use the provided AES key in ECB mode to decrypt the file.
   - Finally, we unpad the decrypted data to remove any padding added during encryption.

**Description:**
>You know that feeling—waking up after a wild night of gambling, pockets full of keys you’re sure are yours, but somehow every single one feels wrong, and you can’t, for the life of you, remember which one fits where, or even what it’s supposed to unlock?
>Now imagine being a novice cryptographer after that same night. You’ve got the keys—sure—but absolutely no clue what they open, how they work, or why you even have them in the first place. Welcome to the hangover of cryptography.
You think this file should contain a flag encrypted using... AES? Also, the letters ECB come to mind although you don’t know what it is. The flag should be in the usual format SK-CERT{something}.
key (hex format): `00000000000000000000000000000000`

**Solution:**
`ecb.dat` is encrypted with just `0x00`. You can decrypt it using the following command:

```bash

r.ef ecb.dat | r.aes h:00000000000000000000000000000000

```

This will reveal the flag: `SK-CERT{f1r57_15_3cb}`
### Advanced Decryption Standard - Blockchain
**Description:**
>You can’t, for the life of you, remember why each flag ended up with a different chaining method. Must’ve been one heck of a night...
This file contains the flag encrypted using AES with mode CBC.
key (hex format): `00000000000000000000000000000000` iv (hex format): `01020304050607080102030405060708`

**Solution:**

`cbc.dat` is encrypted with just `0x00` and IV `01020304050607080102030405060708`. You can decrypt it using the following command:

```bash

r.ef cbc.dat | r.aes -i h:01020304050607080102030405060708 h:00000000000000000000000000000000

```

This will reveal the flag: `SK-CERT{cbc_m0d3_15_n3x7}`
### Advanced Decryption Standard - easy like counting up to three

**Description:**
>The math of this is beyond your comprehension, but you just know this file contains a third flag, encrypted using AES with CTR (counter) mode.
key (hex format): `11111111111111111111111111111111` iv (hex format): `99999999999999999999999999999999`

**Solution:**

`ctr.dat` is encrypted with just `11111111111111111111111111111111` and IV `99999999999999999999999999999999`. You can decrypt it using the following command:

```bash

r.ef ctr.dat | r.aes -m CTR -i h:99999999999999999999999999999999 h:11111111111111111111111111111111

```

This will reveal the flag: `SK-CERT{4nd_7h3_l457_15_c7r}`

# ***Next challenge on Adversary***
# Adversary

## Almost Classic

![classic](https://github.com/Daniel-wambua/blogz/blob/main/content/CTF/writeup8/images/adversary%20almost%20classic.png?raw=true)

`communication.txt`

```shell
X: Ovgh xlliwrmzgv gsv wilk klrmg.
Y: Ztivvw yfg dv szev gl yv xzivufo. Lfi xibkgltizksvih dzimvw fh zylfg gsrh nvgslw. Gsvb hzb rg dlmg slow uli olmt.
X: Dv wlmg szev grnv gl hvg fk zmbgsrmt yvggvi. Xlnv gl gsv fhfzo kozxv rm gsv Kvmgztlm, Hgzeyzihpz 42. Gsv yzigvmwvi droo trev blf gsv kzxpztv. 
Y: Urmv yfg ru dv tvg xlnkilnrhvw yvxzfhv lu gsv xrksvi blf szev gl wlfyov blfi hgzpvh. HP-XVIG{szev_blf_vevi_svziw_zylfg_z_yolxp_xrksvi???}
```

Solution

It was [Adbash cipher](https://www.dcode.fr/atbash-cipher).

```
SK-CERT{have_you_ever_heard_about_a_block_cipher???}
```

## 3AES

![](https://github.com/Daniel-wambua/blogz/blob/main/content/CTF/writeup8/images/adversary%203AES.png?raw=true)

`intercept.txt`

```shell
key1: h+NvKyaJFRhpn7lRWo0JGGcSk7TOd2ltibSSI1CGDCk=
key2: CznIYU0rBgmzSb7WyqYfj+WKyDSXbbnsa8Wp/IRvUOc=
key3: ihpLsXPURUTwH4ULO9/87rHRCQibQO6+V4/QKJL7Bgg=

Y: rOkz0hogqrrjVXe8KhfwPmTXqy0NI5BaaVRwg8g4490Gi//XIIYY6t7pMpw/0DN4V26tcdwmmOOne75oEt4/oQ==
X: t+WZSn6H1mA9XUQJrQ2xxt33nVh6orKFygb7Q+8xMe9JSk7XgMdZ8Fwq9rSMw9SuCZWoIJ8qYOSOKwmyyvMmW7/kkPDoWNEezfme08HmEWi3DrPAefIpNVVewbfVzt5j
Y: dNMxxcWRHkxNxHu17gw5g5IE/Jf6tNmxw4OfBHEXfRv0cx4pKVKYjZofSRAgFspLnWcdR5GGasKxCgpOANPyS4liypMrPFKlXy/pm2BG7bM=
X: k8JzsMNxiG5KPGSdM/YjGjW7y8dzgG8vsQ3RB062Kz1/EzwUaWz5Sr2UFNuq0jcWqDdj3Y9I0UKz0rYdZuTxMHZ+oKVEqI8Xv9CuvOmOzkdBoBgsjaWT9ke6+BPcMH9Kpwq/jgoYVQ7SfJDKx5GCAxzSLyyS6tXGIZRrUny6jiU=
```

*Solution*

Back in the day, [Triple DES](https://en.wikipedia.org/wiki/Triple_DES#Algorithm) decryption worked as follows:

plaintext=DK1(EK2(DK3(ciphertext)))

So we have to mimic that but with AES. I had to write `intercept.py`

```python
#!/usr/bin/env python3
import base64

from Crypto.Cipher import AES

KEY1 = base64.b64decode('h+NvKyaJFRhpn7lRWo0JGGcSk7TOd2ltibSSI1CGDCk=')
KEY2 = base64.b64decode('CznIYU0rBgmzSb7WyqYfj+WKyDSXbbnsa8Wp/IRvUOc=')
KEY3 = base64.b64decode('ihpLsXPURUTwH4ULO9/87rHRCQibQO6+V4/QKJL7Bgg=')

MESSAGES = [
    'rOkz0hogqrrjVXe8KhfwPmTXqy0NI5BaaVRwg8g4490Gi//XIIYY6t7pMpw/0DN4V26tcdwmmOOne75oEt4/oQ==',
    't+WZSn6H1mA9XUQJrQ2xxt33nVh6orKFygb7Q+8xMe9JSk7XgMdZ8Fwq9rSMw9SuCZWoIJ8qYOSOKwmyyvMmW7/kkPDoWNEezfme08HmEWi3DrPAefIpNVVewbfVzt5j',
    'dNMxxcWRHkxNxHu17gw5g5IE/Jf6tNmxw4OfBHEXfRv0cx4pKVKYjZofSRAgFspLnWcdR5GGasKxCgpOANPyS4liypMrPFKlXy/pm2BG7bM=',
    'k8JzsMNxiG5KPGSdM/YjGjW7y8dzgG8vsQ3RB062Kz1/EzwUaWz5Sr2UFNuq0jcWqDdj3Y9I0UKz0rYdZuTxMHZ+oKVEqI8Xv9CuvOmOzkdBoBgsjaWT9ke6+BPcMH9Kpwq/jgoYVQ7SfJDKx5GCAxzSLyyS6tXGIZRrUny6jiU='
]


def triple_decrypt_cbc(ciphertext, k1, k2, k3):
    cipher3 = AES.new(k3, AES.MODE_ECB)
    step1 = cipher3.decrypt(ciphertext)

    cipher2 = AES.new(k2, AES.MODE_ECB)
    step2 = cipher2.encrypt(step1)

    cipher1 = AES.new(k1, AES.MODE_ECB)
    plaintext = cipher1.decrypt(step2)

    return plaintext


def main():
    for message in MESSAGES:
        ciphertext = base64.b64decode(message.encode())
        print(f'ciphertext (len={len(ciphertext)}:', ciphertext)
        plaintext = triple_decrypt_cbc(ciphertext, KEY1, KEY2, KEY3)

        try:
            print("Decrypted text:")
            print(plaintext.decode('utf-8'))
        except UnicodeDecodeError:
            print("Raw decrypted bytes:")
            print(plaintext)

        print('\n' + '=' * 120 + '\n')


if __name__ == '__main__':
    main()
```

to experiment easier, and *BOOM*  i got the flag.
![3aes](https://github.com/Daniel-wambua/blogz/blob/main/content/CTF/writeup8/images/3aes%20solvepng.png?raw=true)

```shell
SK-CERT{1_w0nd3r_why_th3y_d0nt_us3_7h1s_1rl}
```

## Key exchange

![key](https://github.com/Daniel-wambua/blogz/blob/main/content/CTF/writeup8/images/adversary%20key%20exchange.png?raw=true)

`exchange.png`
[![Key exchange](https://github.com/lukaskuzmiak/cybergame.sk-2025-writeups/raw/main/Adversary/Key%20exchange/exchange.png)](https://github.com/lukaskuzmiak/cybergame.sk-2025-writeups/blob/main/Adversary/Key%20exchange/exchange.png)

`message.txt`
```shell
X: tL90zeX19A2CLF9PH9oMQEuAPURmv7rp+oQ/DWiXEwTTQ6Ry/yDBHgqBGAa+OCaoI5JfdGYqhM2SHCWQyVdKJPj8HTY3gkxG38JEaET+CgX7h3cPQrufwYG8UOH6scrk1+guWvLOIAb/VJZ7pbjnEeORtN9C91EvxhNAO7r9pSFczo2TCGyFSaNOsvzN6C88Gw+4eXMTtVw=

Y: mBpf0ZTjWUczik9rrfwdM4wgVrN4I+++PGQSctBkAliziynxXJxYT0KnWxf5q8f1utv9ERPaWsJ+e/fENymhCWELXAnXGFaF8LHLzl9N1TWxu4b1CPPsU2pi2Rar9pm9FLfN4x/yYfP7daqKD7Rvq67wRu9+jsrgQKFj7687mZA4I9s11NpQQ7TSrEVr8Xx0d8FIZsV4x9M=

X: R8BSLUs24ieC8nV22ER/HYDYE7ltrz548dNMJeC+SwsOrcXFmuTdYHlSCnor9NU28nSoDhCJ7DXMDL5gzEiPWsikIgeM30CNfyH2ny/A6H0eZrOyLiEK8ZOS79hoFDsbiA3IidA2KpB9EgbRz1vRzXoOsAhUTa27/Px3nlCOboZRhXnTruzsPnKpWYjvXRQLKKW/d4Y4BbI=

Y: xl24Q/q0QOTK0hl1zOrSLgOEfbg+pzUf2FLNfS4OJD8k+R5hviqHb+DFSO2m1gXzkNoQa2guDRSRtKmHqigFKB/azqdEahvEnbH/wUImMc5UeC1FjOwsc7MBrhELI2M+rpo0z2RvzX+2VF0fCQWGm8by5D7yyJL8VHsE6acQjGSvkz0L+kRNtAQXh4ywjAet3rxnSlyu1kO9N4BPjCpCYNtfuPbnccMUCWiePiyj+GXh838frFEDdzL9gVOA4CZSNIOOgIJ0Re1c3dPQBdxhqpeXXyoj4PUK1W1Q6ZjOr362SoD8PwUU55nQTPUW50cp

X: CuU+OFj7FoHmmT1Ppsfn+kbLwwQF9A9hvdLgE8sEIi6D6RyCr6b2E+YxQi2x9qkECPJkiuSeYypnDifjavlhvTez6hM2JbZV4WrrzmePjWd/a63ZBgTs/JR9j0XdO0xoXCi5Y0rPDjj0oJsfLilu34PXtO8t1Y2MnlPQ/aRvhn+xe3mKauDuDtPjI+N3Tood

Y: AYdjr4yUpFrQC23EKtj0+w5m6Qq5QnxHcCC8WeU9GUPH6rAig0auAEKMVyfGnj/qxHKXuFSnWX+9Z04hY3RYLw==
```

Solution

Just XOR M1 (message 1), M2 (message 2) and M3 (message 3). M1⊕M2 cancels out S1. M2⊕M3 cancels out S2. Therefore, M1⊕M2⊕M3 cancels out S1 and S2 and only leaves Key.

Then just use the previous code to decrypt Triple AES. Implemented in `exchange.py

```python
#!/usr/bin/env python3
import base64
from functools import reduce

from Crypto.Cipher import AES

MESSAGES = [
    'tL90zeX19A2CLF9PH9oMQEuAPURmv7rp+oQ/DWiXEwTTQ6Ry/yDBHgqBGAa+OCaoI5JfdGYqhM2SHCWQyVdKJPj8HTY3gkxG38JEaET+CgX7h3cPQrufwYG8UOH6scrk1+guWvLOIAb/VJZ7pbjnEeORtN9C91EvxhNAO7r9pSFczo2TCGyFSaNOsvzN6C88Gw+4eXMTtVw=',
    'mBpf0ZTjWUczik9rrfwdM4wgVrN4I+++PGQSctBkAliziynxXJxYT0KnWxf5q8f1utv9ERPaWsJ+e/fENymhCWELXAnXGFaF8LHLzl9N1TWxu4b1CPPsU2pi2Rar9pm9FLfN4x/yYfP7daqKD7Rvq67wRu9+jsrgQKFj7687mZA4I9s11NpQQ7TSrEVr8Xx0d8FIZsV4x9M=',
    'R8BSLUs24ieC8nV22ER/HYDYE7ltrz548dNMJeC+SwsOrcXFmuTdYHlSCnor9NU28nSoDhCJ7DXMDL5gzEiPWsikIgeM30CNfyH2ny/A6H0eZrOyLiEK8ZOS79hoFDsbiA3IidA2KpB9EgbRz1vRzXoOsAhUTa27/Px3nlCOboZRhXnTruzsPnKpWYjvXRQLKKW/d4Y4BbI=',
    'xl24Q/q0QOTK0hl1zOrSLgOEfbg+pzUf2FLNfS4OJD8k+R5hviqHb+DFSO2m1gXzkNoQa2guDRSRtKmHqigFKB/azqdEahvEnbH/wUImMc5UeC1FjOwsc7MBrhELI2M+rpo0z2RvzX+2VF0fCQWGm8by5D7yyJL8VHsE6acQjGSvkz0L+kRNtAQXh4ywjAet3rxnSlyu1kO9N4BPjCpCYNtfuPbnccMUCWiePiyj+GXh838frFEDdzL9gVOA4CZSNIOOgIJ0Re1c3dPQBdxhqpeXXyoj4PUK1W1Q6ZjOr362SoD8PwUU55nQTPUW50cp',
    'CuU+OFj7FoHmmT1Ppsfn+kbLwwQF9A9hvdLgE8sEIi6D6RyCr6b2E+YxQi2x9qkECPJkiuSeYypnDifjavlhvTez6hM2JbZV4WrrzmePjWd/a63ZBgTs/JR9j0XdO0xoXCi5Y0rPDjj0oJsfLilu34PXtO8t1Y2MnlPQ/aRvhn+xe3mKauDuDtPjI+N3Tood',
    'AYdjr4yUpFrQC23EKtj0+w5m6Qq5QnxHcCC8WeU9GUPH6rAig0auAEKMVyfGnj/qxHKXuFSnWX+9Z04hY3RYLw=='
]


def xor_bytes(*args):
    return bytes(reduce(lambda x, y: [a ^ b for a, b in zip(x, y)], args))


def triple_decrypt_cbc(ciphertext, k1, k2, k3):
    cipher3 = AES.new(k3, AES.MODE_ECB)
    step1 = cipher3.decrypt(ciphertext)

    cipher2 = AES.new(k2, AES.MODE_ECB)
    step2 = cipher2.encrypt(step1)

    cipher1 = AES.new(k1, AES.MODE_ECB)
    plaintext = cipher1.decrypt(step2)

    return plaintext


def main():
    m1 = base64.b64decode(MESSAGES[0])
    m2 = base64.b64decode(MESSAGES[1])
    m3 = base64.b64decode(MESSAGES[2])

    key = xor_bytes(m1, m2, m3)
    print("Recovered key (hex):", key)

    """
    Recovered key (hex): b'key1: Om3TeRjbnnGxxNs3k/73aZXMZWneHF9XD11tIklg4kk=\nkey2: kl426dwQSc8lEZNPRy94s7MTZBHdiycxLf/9ShBKR+0=\nkey3: eWYw7oB8h46tzNTJEHR75h/urZ94e5G1IDGCDkOh0Sw='
    """

    key1 = base64.b64decode('Om3TeRjbnnGxxNs3k/73aZXMZWneHF9XD11tIklg4kk=')
    key2 = base64.b64decode('kl426dwQSc8lEZNPRy94s7MTZBHdiycxLf/9ShBKR+0=')
    key3 = base64.b64decode('eWYw7oB8h46tzNTJEHR75h/urZ94e5G1IDGCDkOh0Sw=')

    for message in MESSAGES[3:]:
        ciphertext = base64.b64decode(message.encode())
        print(f'ciphertext (len={len(ciphertext)}:', ciphertext)
        plaintext = triple_decrypt_cbc(ciphertext, key1, key2, key3)

        try:
            print("Decrypted text:")
            print(plaintext.decode('utf-8'))
        except UnicodeDecodeError:
            print("Raw decrypted bytes:")
            print(plaintext)

        print('\n' + '=' * 120 + '\n')


if __name__ == '__main__':
    main()
```

the results are cool and juicy!!!!!

![diffie](https://github.com/Daniel-wambua/blogz/blob/main/content/CTF/writeup8/images/diffie.png?raw=true)

```
SK-CERT{d1ff13_h3llm4n_15_n07_7h47_51mpl3_l0l}
```

## Next challenge 

## [★☆☆] Ransomware
## Recovery 1

![ransomware](https://github.com/Daniel-wambua/blogz/blob/main/content/CTF/writeup8/images/ransomware%20recovery1.png?raw=true)

`recovery_1.zip`

*Solution*

Easy XOR - first 16 bytes of almost every PNG are the same, XOR those with the `slon.png.enc` to get key

```shell
r.ef Ransomware/files/inescapable_storyception_of_doom.txt.enc | r.xor h:8382D29E0559CF6F21BE0CB2F97E5955
```

```
SK-CERT{7r1v14l_r4n50mw4r3_f0r_7h3_574r7}
```

## Recovery 2
![recovery](https://github.com/Daniel-wambua/blogz/blob/main/content/CTF/writeup8/images/ransomware%20recovery2.png?raw=true)

`recovery_2.zip`

*Solution*

Use `gpt_key.py`

```python
#!/usr/bin/env python3
"""
Recover a 16-byte PNG encryption key using known plaintext blocks.
"""

import argparse


def rotate_right(b: int, bits: int) -> int:
    """
    Rotate an 8-bit value right by the given number of bits.
    """
    return ((b >> bits) & 0xFF) | ((b << (8 - bits)) & 0xFF)


# Known PNG header bytes 0–15 (IHDR chunk signature prefix)
PNG_HDR = bytes.fromhex("89504E470D0A1A0A0000000D49484452")


def recover_key(enc_path: str, orig_path: str) -> bytes:
    """
    Recover the 16-byte encryption key given:
      - enc_path: path to the encrypted PNG file (.enc)
      - orig_path: path to the original plaintext PNG file

    The algorithm:
      1. Read first 16 bytes of ciphertext (block 0) and use PNG_HDR
         to extract the top 7 bits of each key byte.
      2. Read next 16 bytes of ciphertext (block 1), undo the left
         rotation by 3, XOR with the known plaintext bytes from the
         original file, and extract each LSB of the rotated key.
      3. Combine the 7 bits from step 1 and the single LSB from step 2
         to reconstruct each full key byte.
    """
    # Read first 32 bytes of ciphertext
    with open(enc_path, "rb") as f:
        data = f.read(32)
    enc0 = data[0:16]
    enc1 = data[16:32]

    # Step 1: extract top 7 bits from block 0
    key_top7 = [(enc0[i] ^ PNG_HDR[i]) & 0xFE for i in range(16)]

    # Read plaintext block 1 from the original PNG
    with open(orig_path, "rb") as f:
        f.seek(16)
        plain1 = f.read(16)

    # Step 2: undo the rotate_left(…,3) on block 1 ciphertext
    unrot1 = [rotate_right(b, 3) for b in enc1]

    # XOR with plaintext to obtain the rotated key bytes
    rotated_key = bytes(u ^ p for u, p in zip(unrot1, plain1))

    # Step 3: extract each LSB from the rotated key and combine
    full_key = bytes(
        key_top7[i] | (rotated_key[(i - 1) % 16] & 1)
        for i in range(16)
    )
    return full_key


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Recover PNG encryption key using known plaintext."
    )
    parser.add_argument(
        "enc_path",
        help="Path to the encrypted .enc PNG file"
    )
    parser.add_argument(
        "orig_path",
        help="Path to the original plaintext PNG file"
    )
    args = parser.parse_args()

    key = recover_key(args.enc_path, args.orig_path)
    print(key.hex())
```

first, it recovers the key properly included the scrambled LSB bits. Then use this `dec.py` 

```python
def rotate_right(byte, bits):
    return ((byte >> bits) & 0xff) | ((byte << (8 - bits)) & 0xff)


def decrypt_file(encrypted_file, key):
    with open(encrypted_file, "rb") as f:
        data = f.read()

    decrypted = bytearray()
    block_size = len(key)
    num_blocks = (len(data) + block_size - 1) // block_size

    for i in range(num_blocks):
        block = data[i * block_size: (i + 1) * block_size]
        if i == 0:
            # First block: XOR with key, ignoring LSB
            dec_block = bytearray()
            for b, k in zip(block, key):
                # Clear LSB before XOR to get original byte
                dec_byte = (b & 0xFE) ^ k
                dec_block.append(dec_byte)
        else:
            # Other blocks: reverse the encryption steps
            # 1. First rotate key
            offset = i % block_size
            rotated_key = key[offset:] + key[:offset]
            # 2. Then rotate right by 3 to undo the left rotation
            rotated_block = bytes(rotate_right(b, 3) for b in block)
            # 3. Finally XOR with rotated key
            dec_block = bytes(b ^ k for b, k in zip(rotated_block, rotated_key))
        decrypted.extend(dec_block)

    return decrypted


def main():
    # Example usage
    # encrypted_file = "./files/slon.png.enc"
    # output_file = "./files/slon.png"

    encrypted_file = "./files/slopes_of_the_unknowable.txt.enc"
    output_file = "./files/slopes_of_the_unknowable.txt"

    # Decrypt the file
    decrypted_data = decrypt_file(encrypted_file, bytes.fromhex('a58b3283477d8470cba5c8f083634e2a'))

    # Write decrypted data
    with open(output_file, "wb") as f:
        f.write(decrypted_data)

    print(f"[+] Decrypted file written to {output_file}")


if __name__ == "__main__":
    main()
```

to decrypt the contents, first block (16 bytes) will have LSB wrong but , not needed for solving. then we get this cool response i mean text file after running the above codes.

```shell
Sireeehng!the!Rlopes of the Unknowable

It all started with Rick waking up from a hangover inside a snow globe.
“Morty, get the sledgehammer. I accidentally dimension-hopped into a Christmas ornament again.”

Five smashed snowmen later, they stood in front of the portal gun.

“Morty, we’re going skiing. But not just anywhere,” Rick slurred, calibrating the gun with one hand while pouring schnapps into his coffee with the other. “We’re going outside the Central Finite Curve.”

Morty blinked. “Wait, what? Isn't that where all the non-Rick-dominated realities are?”

“Exactly! Which means we might actually get decent ski lift service.”

They portaled into a parallel universe ski resort called Slippery Realities, where the laws of physics were suggestions and snowflakes screamed as they fell.

“W-what the hell is this place?” Morty yelled as he adjusted his ski goggles, which were alive and whispering ominous prophecies into his ears.

Rick adjusted his skis, which were shaped like interdimensional fish. “This is Universe -∞.9b. Snow here is made of crystallized existential dread. It's primo for shredding.”

As they hit the slopes, Rick started yelling, “Watch out for the Slope Moguls! They’re sentient!”

Morty screamed as a mogul jumped at him, yelling “DO A TRICK OR DIE!”

Halfway down the mountain, they hit a temporal avalanche. Time itself started rewinding. Rick turned into a baby. Morty turned into a failed tax auditor.

“Rick! I can’t audit powder! I don’t even know what a W-2 is in this universe!”

Rick, now a toddler with a lab coat diaper, screamed, “BABY RICK NEEDS A TIME NAP!”

Thankfully, a sentient snowboard named Chad rescued them by doing a backflip so gnarly it temporarily restored local causality.

At the bottom of the mountain was a ski lodge run by Nietzsche clones, where the hot chocolate tasted like despair and came with a complimentary crisis of identity.

“We should go,” Morty muttered, sipping his drink while weeping softly.

“Not until we beat the Downhill Boss,” Rick said, pointing to the ski hill’s final challenge: a 10,000-foot vertical drop guarded by a giant snow demon made of failed philosophies.

Morty screamed.

Rick screamed louder—but only because his marshmallow was too hot.

They escaped by skiing off the edge of the universe itself, launching into the meta-dimensional void where gravity was negotiable and ski poles argued about Kantian ethics.

Back home, covered in frost and trauma, Morty collapsed on the couch.

“Rick… why?”

Rick tossed him a t-shirt that read ‘I Skied Outside the Central Finite Curve and All I Got Was a Recursive Mental Breakdown’.

“Because, Morty. Skiing inside the curve is for posers.”

THE END.

(Or is it? Time is still reversing in three universes. Sorry, Chad.)
############################################################################################


			SK-CERT{r1ck_4nd_m0r7y_4dv3n7ur35}	


############################################################################################
```

the flag:

```
SK-CERT{r1ck_4nd_m0r7y_4dv3n7ur35}
```

## Recovery 3

![recovery](https://github.com/Daniel-wambua/blogz/blob/main/content/CTF/writeup8/images/ransomware%20recovery3.png?raw=true)

`recovery_3.zip`

*Solution*

The most important part is that the `PRNG` is initialized only once and it seems the `flag.txt` was encrypted first and then the `slonik.png`, meaning we have to backtrack that many blocks (size of `flag.txt` / 4) in the PRNG state to get to the beginning.

Implemented in `decrypt.py` 

```python
#!/usr/bin/env python3
"""
Recover the PRNG seed from the first 8 ciphertext bytes of an encrypted PNG,
then decrypt all .enc files in a folder.
"""

import argparse
import os
import struct


# PRNG definition (must match the one in main.py)
class PRNG:
    def __init__(self, x: int, y: int, counter: int = 0):
        self.x = x & 0xFFFFFFFF
        self.y = y & 0xFFFFFFFF
        self.counter = counter & 0xFFFFFFFF

    def rand(self) -> int:
        # exactly as in your encryptor
        t = (self.x ^ (self.x << 10)) & 0xFFFFFFFF
        self.x = self.y
        self.y = ((self.y ^ (self.y >> 10)) ^ (t ^ (t >> 13))) & 0xFFFFFFFF
        self.counter = (self.counter + 362437) & 0xFFFFFFFF
        return (self.y + self.counter) & 0xFFFFFFFF


# PNG’s first 8 bytes as big-endian u32 words
PNG_SIG0 = int.from_bytes(b'\x89PNG', byteorder='little')
PNG_SIG1 = int.from_bytes(b'\r\n\x1a\n', byteorder='little')


def invert_xor_right(v: int, shift: int) -> int:
    """Invert v = x ^ (x >> shift) for 32‑bit x."""
    x = 0
    for i in reversed(range(32)):
        if i + shift < 32:
            bit = ((v >> i) & 1) ^ ((x >> (i + shift)) & 1)
        else:
            bit = (v >> i) & 1
        x |= bit << i
    return x


def invert_xor_left(v: int, shift: int) -> int:
    """Invert v = x ^ (x << shift) for 32‑bit x."""
    x = 0
    for i in range(32):
        if i - shift >= 0:
            bit = ((v >> i) & 1) ^ ((x >> (i - shift)) & 1)
        else:
            bit = (v >> i) & 1
        x |= bit << i
    return x


def xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def recover_seed(enc_png: str, skip_blocks: int = 0):
    # read first 8 ciphertext bytes
    with open(enc_png, "rb") as f:
        data = f.read(8)
    c0 = struct.unpack("<I", data[0:4])[0]
    c1 = struct.unpack("<I", data[4:8])[0]

    # keystream words = ciphertext ^ plaintext
    k0 = c0 ^ PNG_SIG0
    k1 = c1 ^ PNG_SIG1

    # counter increments by 362437 each call; initial counter was 0
    C1 = ((skip_blocks + 1) * 362437) & 0xFFFFFFFF
    C2 = ((skip_blocks + 2) * 362437) & 0xFFFFFFFF

    # y1 and y2 are the PRNG’s y after call #1 and call #2
    y1 = (k0 - C1) & 0xFFFFFFFF
    y2 = (k1 - C2) & 0xFFFFFFFF
    print("y1: ", y1)
    print("y2: ", y2)

    # backtrack PRNG state skip_blocks times to align with initial outputs
    for _ in range(skip_blocks):
        A_bt = y2 ^ (y1 ^ (y1 >> 10))
        t_bt = invert_xor_right(A_bt, 13)
        y0_bt = invert_xor_left(t_bt, 10)
        y2, y1 = y1, y0_bt

    # Step A: recover y0 and x0
    # call #1: y1 = f(y0, t0), where t0 = x0 ^ (x0<<10)
    # so   A0 = y1 ^ (y0 ^ (y0>>10)) = t0 ^ (t0>>13)
    # invert that to get t0, then invert x^ (x<<10) to get x0
    # But we don’t yet know y0—so first recover y0 from the second step:
    # call #2: y2 = f(y1, t1) ⇒ A1 = y2 ^ (y1 ^ (y1>>10)) = t1 ^ (t1>>13)
    A1 = y2 ^ (y1 ^ (y1 >> 10))
    t1 = invert_xor_right(A1, 13)
    # t1 = x1 ^ (x1<<10), and x1 == y0 (because x was set to old y at each step)
    y0 = invert_xor_left(t1, 10)

    # now back‐solve x0:
    A0 = y1 ^ (y0 ^ (y0 >> 10))
    t0 = invert_xor_right(A0, 13)
    x0 = invert_xor_left(t0, 10)

    return x0, y0


def decrypt_folder(folder: str, x0: int, y0: int):
    prng = PRNG(x0, y0, counter=0)
    print('PAY ATTENTION THE SORT ORDER MIGHT BE WRONG AND THAT WILL MESS EVERYTHING UP!')
    for fn in sorted(os.listdir(folder)):
        if not fn.endswith(".enc"):
            continue
        inp = os.path.join(folder, fn)
        out = os.path.join(folder, fn[:-4])  # strip “.enc”
        with open(inp, "rb") as f_in, open(out, "wb") as f_out:
            while True:
                blk = f_in.read(4)
                if not blk:
                    break
                ks = prng.rand().to_bytes(4, "little")
                pt = bytes(b ^ k for b, k in zip(blk, ks))
                f_out.write(pt)
        print(f"→ Decrypted {fn} → {os.path.basename(out)}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Recover PRNG state from a PNG and decrypt all .enc files"
    )
    parser.add_argument("encrypted_png", help="One of your .enc PNGs")
    parser.add_argument("folder", help="Directory containing all .enc files")
    parser.add_argument(
        "--skip-bytes", type=int, default=0,
        help="Number of plaintext bytes encrypted before the PNG (to adjust PRNG offset)"
    )
    args = parser.parse_args()
    # compute how many 4-byte blocks to skip based on earlier plaintext
    skip_blocks = (args.skip_bytes + 3) // 4
    x0, y0 = recover_seed(args.encrypted_png, skip_blocks)
    print(f"Recovered PRNG seed: x0=0x{x0:08x} ({x0}), y0=0x{y0:08x} ({y0})")
    decrypt_folder(args.folder, x0, y0)
```

ChatGPT wrote the amazing code so dont worry about it, its cool though, was faster than doing it by hand, so everything is cool..

```shell
python3 decrypt.py --skip-bytes 3315 ./files/slonik.png.enc ./files 
```

![enc](https://github.com/Daniel-wambua/blogz/blob/main/content/CTF/writeup8/images/enc.png?raw=true)

```
SK-CERT{h4rd3r_x0r5h1f7_r3v3r53}
```


## The next challenge on crypptography
# Short Crypto Tales

## MorizOtis

*Description*

Moriz Otis, cryptographer and CERTcoin tycoon, sent coins to a phishing awareness hotline, a jar of entropy, and even himself. But when he tried one final mega-transfer and locked his flag with it, something went horribly wrong. Now the flag’s encrypted, Moriz is panicking, and it’s your job to fix the mess. the files are below *main.py* and *data.json*

`main.py`

```python
import hashlib
import json
from os import urandom
from Crypto.Cipher import AES

BYTE_MAX = 255
KEY_LEN = 32


class Moriz_OTS:
    def __init__(self):
        self.priv_key = []
        for _ in range(KEY_LEN):
            priv_seed = urandom(KEY_LEN)
            self.priv_key.append(priv_seed)
        self.gen_pubkey()

    def gen_pubkey(self):
        self.pub_key = []
        for i in range(KEY_LEN):
            pub_item = self.hash(self.priv_key[i])
            for _ in range(BYTE_MAX):
                pub_item = self.hash(pub_item)
            self.pub_key.append(pub_item)

    def hash(self, data):
        return hashlib.sha256(data).digest()

    def sign(self, data):
        data_hash = self.hash(data)
        data_hash_bytes = bytearray(data_hash)
        sig = []
        for i in range(KEY_LEN):
            sig_item = self.priv_key[i]
            int_val = data_hash_bytes[i]
            hash_iters = BYTE_MAX - int_val
            for _ in range(hash_iters):
                sig_item = self.hash(sig_item)
            sig.append(sig_item)
        return sig

    def verify(self, signature, data):
        data_hash = self.hash(data)
        data_hash_bytes = bytearray(data_hash)
        verify = []
        for i in range(KEY_LEN):
            verify_item = signature[i]
            hash_iters = data_hash_bytes[i] + 1
            for _ in range(hash_iters):
                verify_item = self.hash(verify_item)
            verify.append(verify_item)
        return self.pub_key == verify


if __name__ == "__main__":
    w = Moriz_OTS()

    output = {
        "signatures": []
    }

    for i in range(20):
        message = f"{w.pub_key[0].hex()} transfered {int.from_bytes(urandom(1), 'big')} CERTcoins to {urandom(32).hex()}".encode()
        signature = w.sign(message)
        assert w.verify(signature, message)
        output["signatures"].append({
            "message": message.decode(),
            "signature": [s.hex() for s in signature],
        })

    message2 = f"{w.pub_key[0].hex()} transfered 999999 CERTcoins to me".encode()
    signature2 = w.sign(message2)
    assert w.verify(signature2, message2)

    with open("flag.txt") as f:
        flag = f.read().strip().encode()
    aes_key = bytes([s[0] for s in signature2])
    aes_iv = urandom(16)
    cipher = AES.new(aes_key, AES.MODE_CBC, aes_iv)
    encrypted = cipher.encrypt(flag)

    with open("data.json", "w") as f:
        output["public_key"] = [s.hex() for s in w.pub_key]
        output["iv"] = aes_iv.hex()
        output["enc"] = encrypted.hex()

        f.write(json.dumps(output))
```

`data.json`

```shell
{"signatures": [{"message": "afd43c3e9c1c09118d051e9d31a678fa96b5b3182fa6a6628b0c79f0424ebdc0 transfered 183 CERTcoins to 58f2154c312704c90f07fca1746e523d8b908c4695944be23c8e2d7268ac788c", "signature": ["02ae85c74e18454f4043c23d94584a34e6eac2eb96f2e822fdcec258f64ad9a7", "7bfa3fb300bc8374b169b2f41b9576031b94892e198baebe4136766bc74c3264", "f383a64823f95b32bb7b091aca0334396992b421fb2f5d6f883755e0a1297065", "71ed5a665be2ed96423be4e6c69107d96578f5c5b3e4e0c30c98352814aada47", "9bbd12146edb3c127098229094587c272c1781ebdcba1d57594a09a648357bee", "7872d46eb99c447c65ebb0ca98c23c73c550974b39d2b58dbf84072d5454670d", "44f5e06a60f5f75b35676addb7073bce871c59098ebbf208462027680748cee4", "9a4e689885aa15a2093cbd2dc434eed8e7cb35160e0475ded5e2071a3ee4363f", "9d245d790047e2317e934748ab64d004f37ff331d34c6e31e989f1efcff4226e", "8edc1a9f5185404e53eb91b9bd9de375d8872501be7d7d53d06fbfc7a59d403e", "d90704bca4139f304452f63cd08b17c5255eb14682188d27ce5a4a80df338e3a", "757686bf7e3a36d5298cb9621f1eb2d1a2d3b35dbe8a3e7f8f16c124418881d9", "ac29c62354ef36178eddb03078f136806e556b556f62fddbfc9c0cb80e8990c1", "348c138488d0e6306f787307b24aae3c877b096369c9792a2eeb51260181f27a", "73a28f19902ade81f64febbfbf081ab6d8f4d24407c393cf4d12325450d88d5a", "34d98142f217fae880b369ea1d799f93f9ce3b846869567ac71c579328031e6f", "5769f0d117a49d932764c15db64f0262c1ada78879620d8b4914300b5cb3b4a5", "42addf9ec162f6b5bb91e65f443974374b0f6a8a7b5de839b02bc71a6be3d891", "1ecb998efd0d1e604085771cca8e8c791a5e358b42a0d577ec7c453c3c3bd289", "2c0fed1fb414f19357964c2d3a694bc9410785a8595272f5e51d19767f581ae1", "f75ff7b136dfc3501f4c12a7a1abd88fedb0605b2baaef9d00888913f9df8ea6", "f5a3b11cb1bb261263655024c8fa31b789273171a87bb0b457bee77ec17ed483", "aafe9b014385e20042d29487f69e1107a8a3b202c99111d102aa1bd222a54363", "8fe5a1c63df4c3c37a498229f3a511700289b38fbe70e05fc55e31435ccd423f", "4cbf0683e6cef532e49f25d1b2da2226d0c6713a50adb99eca0556b6d162698c", "d3af760c17c25923c9f68835ab944f00fbee221cc01cc5fc6bd1f86facd4de4e", "df45fa3bbc90d9047909fe8f3dbd66d0e8603195833bf42343b00e51516e9c88", "08e751423d7638ad1408f3323379a6f0cd6ff8e7ff7a32e2718f0e19b3a0c525", "50be7364fc13778c3492993acc05c6d126c7e40d05635a1916f334a7ccadb502", "94142589d24ef1a99598e10a7b2abd08e684d7c89003dda16bf4096e841c9afc", "aa9afee50233cd307b7b188484dbf39c1ace9fc984f40fddbacb751e6b93e4de", "58552658b4efb9161c60d093635285bfc7918ad19489604ce2c0d987de5ec293"]}, {"message": "afd43c3e9c1c09118d051e9d31a678fa96b5b3182fa6a6628b0c79f0424ebdc0 transfered 80 CERTcoins to b3902a40a72d999765e3997331945e112f817d71e1b491fb1f0811539e3d7d4c", "signature": ["2e24486d4e75c57bda5bb5c9f7983cfb7a0ea332b804e9fc4987854a692b7ae0", "6bbd28b07cbb787d71bc3cb9b48669dcd418879227fb3242b1e6f3706c24de38", "25c29dc69d85c92b34d905bc3902dbb02419cb662a4b5ce74b93b20eb79fed0d", "4651d9bad5c3bda9e66eeeae0d4ea198a0461cbbe2c9c5d3104d62038fca8344", "7ba1aa0d147824c49c012aa747cd269d50f554f626bf8ff15caeb8b007ea305a", "9402a2215cf332620ab63d17ba9b35701dd73e5fda466022e67303b16d1d1100", "130a4abe3adb74b80657d00e69360279e2fbc27014474957e0d1682c0770114a", "2d8a6346363be31355b3b13939038ff398841233b37fc84328dcf64a7feefff9", "b9c8076ab7428e502157f437b8a22dc1b7568786e8d33941f2410920bd442a54", "820b7c21dcac1140673545634f468bc950bbbb569dddd6ae5d226b9f12183806", "8574dad1c002e01a4fa74c534a4e274af98c397925c3a0e93e1013856687d610", "f16fe329518822e5a7501e51bf9b7ff3175bc646aa93246fe7a21db4dcd24654", "1ee48c1a430bc6da1e2ff56d9ecca851dc315933fbefb5bf1d9a22e04a5a1e8a", "b82facac10d141ac462e72981f3d70d542fd1952b574a64e7fb2440ef100fd79", "30715ae1b4bb0907cc0b2f2dcaa19d9a7d5b4d2f4e4408be4cf85c42024e2a87", "12f05af4cec2eed06e8c46072f0a4b2e62812cb9e83f175a9c95ed72d4529e69", "fdfd06e51eb612c5c61be7cb4562319e2381e7c2139adcd2eee89a0011c47055", "d65e613a86deb861d0552bd1b6a6d9b1b93062a8080640318a8f221671aff829", "a1b2296cb6dcebc076ad357a65d30581ad9978a72420b008791414d7a24e8867", "0ee89bf9e0baea2648703d688445488d9adc171c6636f1fc151f34170d7ef816", "b1fc791bb59a0dcb900e0b91f9e6be0b33b8d48d42ef75ee6840b90c21a46af1", "27fe5df1fb2fbc6166fd556658bcce6a3ed3157b7e1f12eda538af445d5dd61e", "f84a9b21e38da8576125f461b106d3ebd5af6666bdcd6b6308ac0be17bcb8767", "539c26c744a9b9c6b38df5fa56a53a1a1d2604eaeb06e93f9f207d4e663ed2a9", "4a15c3aedb34ff5d551551f81ced1187b513c7ce9534e81084df4bd0f162818c", "d5c3f206a06ee0718c5c310b5b3d7c184de00fa8c0c2142e2586580fc7612635", "d13f7da690dfa671e7cf9203ad1eb973cb9fba8db896f5b55e687caa954403ad", "5c917eef9aa93dee77ec9bd7a4d4538bd0b885f505e1b1a8863d67d1da5adb10", "fb46059205068c54a9753efd7e4bd9c08e19d3fa8f53d4990792e1b2e7db8ab8", "ef8886892e38bef1fb3a8ec4f239eb667310688cc53362f9f6199bc38eb93ab7", "1270d6918a4610e41578f0470944ec23ea06217a73141c00f43cd7db57ac9765", "9c724cb010521a386872ee3dc47fe0a8e5537574d06493d281191d93a1710d20"]}, {"message": "afd43c3e9c1c09118d051e9d31a678fa96b5b3182fa6a6628b0c79f0424ebdc0 transfered 36 CERTcoins to d636564e1c9a7c8deda4b82f299294e7f59b8c989a8fe19e8596c5e3b52a8312", "signature": ["498305447970b4b42d46083aa42b30a29396edc6a8a006e0678c8f882d3d4c77", "b8cb53d3562414cc1968f4e60c8c4076119fcce209c55a57560ea96e9974f9b4", "19e8e5171559bfacf625a6cf9199fc6c3a431fb0ff6d4d22eb3fb64ec2f632ed", "6b68ff3f383ce6abad29880ff88342456e1d2e7a3858b905745b8845eda0e0bc", "7566492344e7a097916a8e6e730d8d63e7fe2e21724306f3d3c17334015db502", "cf5256199f447f6debb90fdd39517cf61d52f129c183ab65b4060a267973a410", "b977e9bcc4100a75dd94d55bdd17ff1e0364054e1f889036bb8f3fa711152ca1", "12239414ce28fca5e0ed70f32d626b33723da6a3ec9515936b2a2565d2d066d9", "37168576873c5b8f5d43a2b4a0b58761d0df4ba6baec2ca868f991d48ef90e7f", "1b5ddf97249710938ae057b6dfdb89a1ec9c82d96e0bdb7e4a73041e4151e477", "7e11d584669fb16728104d793418247bdddb0eedea891121dc79ee6ba677836c", "4d91d7366de19f6b0bec5d26c99f947a1b6b699706d1e6019f39d76523b224bd", "87ee4b630d8499cdaae71af127f1154904eb4f67ed88344938dc04cd3682e753", "8f1fb263c317e603af35f6ca87102201b3aa02a0daf9b4da03e4de56c190f083", "c3e42b0a840cb7a2577e3419e9e416458e66ada4df57a8db9e32555a82fe4d14", "0bc73bc4df784e6eddcea9b4941a7d71ff066808098bfe35617e0488c70ffa53", "7fb326e0375210f0ba342389004b53bf1640fcac987b68fac69bf3b941a5dfc6", "78474d41ea330194e47825ee0d42c8b885a96d8c605708bd8cc5c842700d47a8", "5c5a09fdac2d5d9160f21712dc49e9f635e8da6cc213f76d3620589ab3716ecc", "6e38e760e4c4a42aff32c53a6967a69b74c20461f42c3158ff0ad6f5f85e81e6", "d8eac02b0077e33329145b6c8a459d4645cddcc75f3c85649e40c1cb365a0395", "f41c65fddd438e77af28a86ab5cff04de8a4f029a2468c66b314cd38031980f1", "027d2852aa8b69a7092b16993dded9ebf4fc510b241ee243e56f42151ee060c3", "d24a61dcd6440ea70ef0772bc858f6e6a31659b88d5d81253e45b38301698d79", "7fe58a47958eb07b6b9ae3bde936be58d7d44589c8083a4eb0738fbbb41d3d78", "de4c13ef55a4e6821b0a38a8707672297fc8ff1af2dc11b9387dccb381ff3f99", "58df6a05184ad44b819aabb5ccfb16e7615ae24653c879837da1081d315ee2cc", "3942ebef806d4fb6ff74a6ada36828c2baa572f0b2f314839602fb8b5a995dfa", "a352baa1cd3fff5ae2e17a2c25dcd0399f9e0c6b108326f65bf8b96413396824", "0593f2ac92d6d930f35b4593d294af24d7baf1327b7e4256ce3d7253e2ddca16", "65e6a8b2c28d27c16f393783bb1b28dd0a44bac53169a7523792cb326c56bf73", "6d7716987927aabbbb53cd0212e574bd2f55d998815576026f44213eea78446d"]}, {"message": "afd43c3e9c1c09118d051e9d31a678fa96b5b3182fa6a6628b0c79f0424ebdc0 transfered 90 CERTcoins to d1fda0f79ead0c7db20728edf7d6fa34b762042a8c8e12bc39e6c821ab83e10b", "signature": ["528b3b01bd5794b7d9e90419c501bb42db8163b109bbc2f8fb90e35f29441bd1", "0d595854abfeaae094c06b9e2fd43790471639410e6d65e6974e037b53938a97", "e5e7e8514000f92c52bea466f1a3bd86ca5a29a302ba87cf7f74afcf5cd0aba8", "321688087054c9e53cc39c7f5c920a1b088410315043ec7d54b20fe07813b7fe", "0360a933f46c875ce31765edbb3dff3210c0f558add6db4f5f7d8f254388f67a", "6707f07017ee45405c4fce56546516710866c0bc503aa34d38907254c0e93e5f", "b52d9a462d336f5e22d6f100b4887b81b36b3ef02f9919e0f92d6d327cf58a56", "18c2d47c52a227ffe9f0be2870875549f7b9e3947d07f586b8901ee79ea96cd7", "060601899a2b4ac8490c87a610b403615e69281d741ba736f49302e2e4e2b17f", "46407a93510290f3d926673280b6d00d7186b881f1c8b1208e42831d1ea89505", "fe3b6f3c1b88b01ecd3c12b8f26d2814f71cd72020a7551e11fb9614b1ae4f76", "252d570f874846a9f9e6759967dfe7b647b406c83557e9486e6d334d0456d6b5", "bdcaa626fce96d2b07d4d13af080142e9ab0337969b06c87070949dde20b8d0b", "83e4043c4e6122077df934d11d6d7084c4de87f95475fb5c21bdbc21a6c13991", "091de6c5ce5a5b2da94555e97d24b75e13eb2303fc2c2b609b8dbed272dc77f1", "3b84625d16c1ad3168bcb477d97bd9ee2eadd929704c9a7cd455c7a3f295f1af", "99174f18ee05cb41aee45166af151b5b5d4df5fb75de2e32bfa2a1b4fd120d01", "d49bbad08b9e62ec91cbdee0618b26adced623445a819d485d4f40cef7720595", "5a092a4ae57115e7483a5891c230bc27e8843ff2d1435065c77a121e60863cfd", "9b7ef85898caccc76d71b41404d09bfb202beca79372c473e602408c6f1b8cd4", "4df65a00f90b76cf3fa533d8e30c08eedcde51b56a0d0fd3e642ec73f272342f", "41f300700de228dd85281c1e52b171f605e3b14fcf72a9422e2fe15bc308935b", "0fed93cc9c8577fdebdfae5be285fd74f2a9fb29a5c86bbe54afba89cfbaf49d", "11af7ae50ab423b679d349ef0b27576f23227435a9f0acf158bc7afb188cd42f", "ea81da3aa12da0a11c47ad80768621b7459c0eac073bfaba353d15e59e907b98", "ba57c7062c4d7a7444f22b58ec1b181f99a44e5eb40303bb4a5d46cd86047088", "ecdd643e2306c1de22b705445c134d7ff5a1a6001ba7d767ea48bbe16d70673d", "735dd9afb0aa3f49b3f125c457e953307038a2a3284623ae5ec060608b57a79e", "f3c77ea71e27475ec7ed002c3a54040e2db01d61ec8c98a8abed79c6ebeb7280", "f88f715753af3c903bdfcdb76f31d9a29799ac7c6d522779e3658edb5d89bdc3", "aa9afee50233cd307b7b188484dbf39c1ace9fc984f40fddbacb751e6b93e4de", "6064199e327f4da81a8c943de372f5f8796d9cb18cc29f3062a74bada4240ed8"]}, {"message": "afd43c3e9c1c09118d051e9d31a678fa96b5b3182fa6a6628b0c79f0424ebdc0 transfered 131 CERTcoins to 2fffbab0644c4949b2ac160a9953b76b4fd94ccbd60394976258ce2f44876c39", "signature": ["555d8870b7ac963f42a6982968d3fb329bb5c5f43aed215a0e0998d558569977", "e3aa79d30725aa3e0e0845d013a4f827c337b42fde918b800b2e9de5e6bfbac4", "a4390da481491793d4699e34bd4c6dc688180603e9e97460ae4183cf36aa39c9", "efcd9a5622f3719c406cf3cad002e9e8a03c2ac1140dd8bab2255c01f6d2ad46", "2b7fb2c43f59d268d45559976d070289d434e4bfdd8a983d84c2c6f57cd7f45d", "6a96e1f58ae5005a8eecf6810c7b79c90353e8acec7d77f91dae22c1aa80a66f", "cd3cd2463b6c4bc3e999f2b5c1a94a57db2c473da814bdf84990258d18880643", "1a99580a75e4357d2bdcd9937bd9257b489e23fc390175392536496f920224e8", "d6b5b1781a7a53ee58032b0f5250aa5391631c6a84d2282ca340bc8d0cfaaac8", "178be6d2b7cc5263812381c9a25f1d39ae273f898df579b5454c4ab766c9d59c", "cb7ec428be1279cad1792a974622656cfde308db0001de13f33a08b4846c3b64", "88ae3518d12729788b5d0cc49b70bfeb591aeb5198c6814f8f304baa6ea92cb8", "d506c48b19d425d6cda7533c2601225ae87ae16bf50bc58d9fc164099b5890fa", "6d177b4371b2570f6e972557db01e52131efb4df1f402003ce7cd14613529836", "a31ffa498b6277f671e5d48de444c82ab4dd735797f8d4f37e6420a88632ee40", "86ef147be4b74e48d488c97ac810b6c4d2b0dd4820135f9a9b545d0c1b01a128", "36b0a998d3f1307bf5594c97ade1a4ba0035378447a2ffc7ecf1780adf08a1d0", "31f7da8c09007e3836931638ac71844691c4dc8f854b9762754611ac7b828dae", "40e414ce36afa63aeeda67b024988b0dfec297d82ccf53a0720f6286a4a8d777", "e6fc6aad38a76486cf47ba93fb946fcae1c0d9ef7b09296e1fdc372d66633b7d", "0fd8139926dd87074d58e956365960cb7f8c8277aa6ede46ed2b1a2f6e7fa186", "6908d4670411bcc38e44e6eebef3ed2e380d7218fcc60595afa9b39251f81ea5", "0adabfbaf93c50391a92b15af8fb7db14002b4fbbf01804177ac90bd026fe21f", "e93b45f8b5d349ed49d3c8fcbe6980547af7452ba07be8e2f4505501561f9533", "77e2037399afaf15bc03403966d98571d13cde8bef9336c069a754bf0731c09c", "e36ee8b7be6b74719bdbfb6be1978ae1a0d64e2f100b958faedb69ded34b120b", "f60505b64645cd1e486cd126f67edfdcbf2a62f809ba00082c49befb59505cb8", "91a168533c322ee2ac5bfbc51b82fd5ba455922442438c674a7796559814559f", "5e74a47362e4a9c385c6ddd2a3efb72be48ab98f0b3d221cd10f5420349ac12b", "08280f76cd1dcffb32539da93db25823f4e8e9cc351bba43ca15356450fd09ff", "aa9afee50233cd307b7b188484dbf39c1ace9fc984f40fddbacb751e6b93e4de", "45007eeafaa5ad774cbbe7af5bce475ad46c9a39c71b668af60bd7c0a92503f8"]}, {"message": "afd43c3e9c1c09118d051e9d31a678fa96b5b3182fa6a6628b0c79f0424ebdc0 transfered 62 CERTcoins to 9808dece9396cb3c7ea71291ad33b60cc94993692e030d67a5cfe0dfa1bf957c", "signature": ["ae195ba4aa7a831801fa5998cc34826505c452e4b3d2e52b15e44b86339809e8", "6dacd9c06a7d2c1fcaf03db74576e8bdcb189c6fd3626b3a395a270e86fcdbfc", "366424e4d296d16a580645c24a688a3479dd49a6a0d3b82792090e11dd2a8d38", "fcae70176589b7077da3a9c295d92a1a10242ff01b4c80c33ad76a7700c7fe42", "a61a7ca194324336557e5022d0879274f2caef6d365687fbedc6e36205bf6c88", "414c72308d77dee0fddc1704dbc5f4df7ac847f28135bace9a826ac91ef32220", "7da23233875ed3c1cbee1e2a291bbece7b3cb2f140b9882c6d620d6c021f428d", "1bf063109430144227f4d0374fda73dfb469effa9f5b77891b9a7b474cf4e6d1", "d6e419ec669e9d781f231ce5a036c8b3ef489fa799cc1293009a3f342cf19b7c", "ad7e7ff89f2ca411f882298928fb06e98b8d191a27079bfa28bb7b208bc003b1", "8f6451392a6ff9577f8c53fdc2a379d7faeb8c6a38c16e45811517d430dc339f", "aedf4841478f6d4533002aa0d2c262abef77df425e246227c588e75ea1453831", "f2a9f6d9c463e74248548fb7bc97acd2e26bd8a708c8738e35a5838c261b3b80", "d9c501fab7775220452438ed97d768214374a41a01efe7fd0e2522e5a88d56cb", "70086ccc1ee53f9ec3798e4ad96d85f716aada8c7da81ffee9d38281a18c98e7", "bce9e240dd98454b3555bc16362e2b83c9cb7d77a6c573a51631aec977bb5785", "0598e99874dbc65dd55924e301a384c205140ac87a1f74cbbcf507e407c1e6c8", "fef69f124a2667bd13c2de7d0d02583a3bdfe7f5ba41050abe52b2c3399a6916", "816af4f2bbf2d0002a8ccbd8da2aed2965909b913949ef01313345aa4ddd160c", "cf150893c705ac20093b764c45e6dfb468c8129a5b88cebae745efe6aadbd119", "6774c8b929715c6c97f03e90db7e248ccf3e4b5fe31aacf97e9640b201f808df", "ae2054eb1feee54cdae1b834f7694a2cf77aedab46640fcf215f69e64544f469", "75600f47ffaf6906e8c33255e00ac838a46f2efcc920e53817cc4ad0bc3f5865", "f58a933d0e048f1b03ddd83c738af1544f439bf3c535300832b05c6a0d4445eb", "5e60ef0787d866c6951cc6b9ce11cda3785fef1e2d287fe365e6002dff5eb8b5", "8d27ffa30fd7df3fa7360bdc866acc53d7ac0ab6f3da3c03424d367b5f76ea68", "212a4b3684c8e8649c70e29f5b09cdd220e483bd5cb1565888b304a18169f061", "7e264d5f23d97021911234bd47317e494b80abf68a0eeaa2294be5d23ad6603d", "172b367c878dd57c2432280f1371b22d066c5eed353b884da96caf46bc467593", "e7b7c8ad08289a0425445214dedcc7e0b976a70c5401caa6a1b1ef3f97de05f3", "498206950cb97c9b341022a1a358c63ee7ea4501ae323246270176caf0fe3afe", "cd6fd48307d02c329c144ccf49d0d70f98bc20c915203e4d92fc969a17cca1ba"]}, {"message": "afd43c3e9c1c09118d051e9d31a678fa96b5b3182fa6a6628b0c79f0424ebdc0 transfered 99 CERTcoins to 434a72d88767e455928e02b15b3e9db07680fe72b843c76285b86933ee0d8441", "signature": ["30492a80bd8f48d6cc10b1c49ea2463044f9a41148498486314749f6839739d4", "a242d2c9f2d66b6594e4530aa675095355ee23e0ee384fd1bcff80fe043c2b1a", "97b2fb1f3d9f5c506d22f982c860219d662afc349cc21f28d170d80ebbd7050b", "082da1e6fd7c19677fdcca1bdd23868eb7a49080bbf3e0ee7d106fd0ce2524c1", "54707d6d30bf851f69f9e376bcc361dbfa8ab55ed6767cea25df1c4f3c33663b", "2b09389f007b2a583444f3da5303010bd5953d724dd9c5fc7efc54d988eb0b2a", "04a33092c854f20176f6c403e43d195cf265f2e555cc5744833e2e7a3955120d", "5fc4002f5ad12313b9658750d87ddf13214c771f3c8a0011489053d56f25b206", "3767486e8ceaed029f8242f4102599fd00d327ef08914cb0e0d2641e52fc8acc", "f0d3ea5be3b47239d743a56e680fb6c808d4b4e195cc880f4583b933a0c9a038", "f14f5eada745f4f23c2527406319ea27ab797a5a02525d71f0becb37f0042665", "5dd6caf72e5c7416774b9f917d540433c075a2e582a06cc760cbf8b7e6cb9d2e", "f2a9f6d9c463e74248548fb7bc97acd2e26bd8a708c8738e35a5838c261b3b80", "01c060e9c0f738905e7766274e366514dc504b4e2b73e6836f6affa0da1d1104", "68f324bbe0310a11181974e9f565d22d7ce22a8ce4102ed8a13ff326933fe13a", "1356551a92b2b77fb30472b2032a6535c44c51343d5fccfa3a2a8c798767fdcb", "c36099fa6f04a38dc42de253f68b22986921327ff7ddfe1ff3b674d7d9f66627", "d236ea221207173b653f8a98da279b033c7adb47de48144c0fee52b9bdf8bde3", "a5d0c7dc012dabe25057917a90281cc89ddc0b3d560dc889a47bd6e98b9f8070", "75f8a187f410f610ac297e4c3c33dc9307cd3e7c52fa7b4b13a1d9c1e6e84016", "3fd90a5de122e658e5b8a2df1dc669e3bddbf4855075d18187b39453990389e5", "134e0600bdb3e207c9a469eb83e630ccc83578ae43a19f3e8210df1d895195fe", "13f769e890875ec4a26c0e88aa22a87b5184d3a02c8dfc901bd6df39a96efeb1", "906fefb6fb973219f14103810c282ef6b47e872a1aefe4905e974365012fd0b7", "da1db98e4d02d4a2485b3693364b00218fa936829d24996b7aa74fe106fada8f", "f6b4da47dda1793e6b225792d2e011adde362a4e5fd04a89687f688f264ab12d", "107adc35dd3a5e480564dcaeef2fcabf3329f1841adf6a7908da4c9b2d4e4049", "672de3f4e76176352cb74755cff8d580e427c6f870865d93e1abf58a4e9eb93f", "6eb58729572e24e5298e86cbad3fe99a299248be18ddd7779e3586f9b93a17c7", "329f9eb5b59d4f676f91f7a8cc60fb5aeda6fbf25c2a1fa6c490d78ceb023a3d", "33f68730f2b221eac8a74263782b29ce373b14319c1cefb2031fd2caed120dd8", "b282a1d4f5b2a1d27885102198ecb3df13d07aebdba176c09f1d64291dac805c"]}, {"message": "afd43c3e9c1c09118d051e9d31a678fa96b5b3182fa6a6628b0c79f0424ebdc0 transfered 106 CERTcoins to c020b7347a3553dfbe3709a388d7aac9f9b6afc0aa7fdd9c3ae54ffa505f8fea", "signature": ["2d34af78f1ed8969dfd554150ad87458c52245b90ce09020dd7620cc9264795e", "11e4bde97478b2d0ccd44d2fc7ee5c33c06972d817382c8ff4d5c408f35a7603", "8cb468ad6eaf8bf73074df57e72f68e0a6167b20bf714f460e8599842667e382", "28561fa8b70a8afd4afeebf609afd404cc4a9609fcf4e4332695eb4daaadc284", "5db997febc2d0460d9082fec2bc9a58fc876e7fea70c8770fe44c9472610b0f1", "4e72fc0736b36994b495939f5ed0fcf0db9898b240f1e590eae01906e5727b9e", "ef4dcd1d614772c389b8fee1b620c074964f171a0e251b2d6083c69876def753", "9a4acb93b32ff0a0d82a1d4fb2933d6237a9ad74956db6c5c0cb2d1045c781e8", "aaef64e002d2020031cdfeacaced2463bed310546e3f55c6897e4d3a91082416", "9dee0d53b751d465ec69cd2ade03670f434963a5af69f3e89fb113f36b19f98b", "5b357b122f5326caaf9155a2b935f870974a2279194613a7a71d324da5a6a331", "fe2b60a282e0fcd29e1ae506a1f06e4ce73e05543052d037a3910863e5bbc356", "96466077270df64c3fd6cc46ce3c012e46d72701adac38883f0e42a7974d0ffa", "bbd307549ac567544e1816b2bde550d5b878ed2dd0a7de3e1963fafbb78d676c", "d9782368fc5f6e692afc7a4f27a19c411725682c56da403cdc51ed99c716ffcd", "eba10a27116c9042bead06ea8c12c509839dfbf36f8f8610d2981201cfd46da2", "cb0097d94d3e055292a7f7748893ee9d17133df386b2167f75e72f5706e8f633", "6e2da1a18ea03c8defb81e192787073c148d1db71d63b34aa35c9f34aa328192", "1d285d61704f207ba7e31d657bd34d29817e6d5f784504749d87a7d68186019a", "9d339e00f42793ff9aa70ea74139158c9a576b029c81e0911ad7cfb025c66748", "28d7c22fb1edf2d27e419060308a5cf94ff2ebfc99e2419b28f804335abd20f4", "5c9d9b408d084374260516b998f5d219797e3235d577c0c12bf05a9f15bc9fbb", "71e48ab10c8f51a9ed2820e7db601fe5100ba0a5bb5df37476138065bbf9fdd3", "a10f82e6a86b3748c5ca29f3da75ddf11da796ac6bc3de2792738c1da27eb60d", "e1bb119d8ee7ad940f62f76274d43e114866c6f99f980a3b6b4196bb1ad25bb2", "48e95e19506e612716bcebb9840a12c25bbd9ee69188f62c830b5620419bb572", "f95b45c4d31f4da97473647260ab102fc7ac4771dbc380d22b8517b1c0201e34", "f24a5f02b428159ab55c6e3f72dfd583f012a3ff3e0cdec9346a11b7325e1fe1", "e43169955964ca4ff2b5e11aeddf4b630c32bd16e5f1c48f1239cceb3461fa6f", "c1f1d674ce9baf9b683cbc7d7722b29ae20f376ae76f35c284023118fdcff404", "f36619b7d137faa6468d7244ed9bdd33283e00cbf6aada97a245e98f47e2449e", "59aa18ac756fa7274528afd6d9958660ce7eb582cb835f8797fe7cd5297a697c"]}, {"message": "afd43c3e9c1c09118d051e9d31a678fa96b5b3182fa6a6628b0c79f0424ebdc0 transfered 182 CERTcoins to 2ee916ee4c74bff89f117097ae71af56283c19488a8cacec4a21aabf771646aa", "signature": ["b038b69c8fc16f498e5a8a196caf51b3bd6f6e49e91ee342eb90eb0ed95bc316", "2d9aa00843982da21d9fccb09bf6a2861448dc398882895697eb3ec2ba0e8a11", "5f08eb2f77feeff6f4357449a16169a92958cc77cf54f023b46d1dd750208c99", "1164b2c234f7115cd30764aaaf5be74beb1b0274ee0a4320738a3d179099b7f3", "885f8b9798224e10a460dd10d45bf867cdbc88fd3438c473f8845e99c5baa6dc", "e98da93b0157ce53d296395148f3af4e0b0ae29b727b43c556423bd09ebf34e1", "40376e7f6f005f338e87ea2c4881635b97ba870549b0ef27193cf36389ba0148", "b4189c719df058f481d52e30ad6c8aa13d7b42b816b3f9efed5370f5762e304d", "fea077a7d0dfa53d2ffe211c561b8140c581fff623178d13d00d1ac84d9b88e7", "e14c57f535f9e43011c4945d895ca9456a7e5e5f9320431487cdbf5e60f1df68", "95f38763212495b2cbb5015fb7ef29b2de52caad768856672b5569058a433108", "cad2d4d8c5ddf4bd5069fd53002b2fba996b4c17d38389ef461965de5b427867", "9999c67a77efc5f1aa69ecfab03d02b5f004ecf5f9323dfb67c817c1f491df69", "9f26513600966e075bfdb0df108724df8b17b0b39ede68776d4be7ffb16bdda0", "3c43b63243d1eb3ba1acfdb0c3d0e5f1da8d55f9c0e19de161612625ff1c4cab", "8bf5dc5ecf2835c621ec47833a43c0f5dccc774701d5ecb3072478f03bf76c48", "fb91c05d65b5eadc949f1b7229c247e069f53007012a231fe812b492bef0ebb3", "b56bb6448b25d9d9b12c857cb66f9bae0abb0e02d96b71bf37e51e86f09511c8", "0ac8cd2ff75e78eda1fb979e10175065b883b88af25d89403eb280fb534077e6", "0ee89bf9e0baea2648703d688445488d9adc171c6636f1fc151f34170d7ef816", "ab2f3c48ac88592e1ceb0ca64cbed88a6ff6929c33cf5b1c51bc43ebcf8e6bd3", "2ec7bac5ed35db4a1420d84034d5e99d319f0eb783520568821221bf4e05ebc5", "5ee9ff594f9370d335c2843d62b654670cc1a38bd1d2dacebdee5cdd377a1ade", "3703945bb9c8b9fff2d4793ad4543e64c9b22a27eb9f1ea9460c730ca51ba0ab", "b8c65dccbf50b5ba1f3434cf42b2102d0eff5f0f6f42763b1c9a9ce1cbbc9b05", "b9a401a0e680a06276e340c349eee60cf92666829db7c2bbcdfa3269dbb1529b", "e71d26b9bbe33c9c9b3ec347e9ad222188b75577a0259bbe43ef255a63f25f12", "386536e658ded687b361ca30cfe16a3124354940b18cf07230d50c5d24a900f0", "03952bdfb23ee6ab09604c72093f846c1585d01f96167f7b34edb654d5bf31b4", "216df6019cfaaccbf11eec13d65060a1c270ec25fab641a39a3b9459cc77acf2", "1fc783215e75b359ea007989affc06c606e9f282926f2dc9cf328f895fb50e59", "9c724cb010521a386872ee3dc47fe0a8e5537574d06493d281191d93a1710d20"]}, {"message": "afd43c3e9c1c09118d051e9d31a678fa96b5b3182fa6a6628b0c79f0424ebdc0 transfered 204 CERTcoins to b75bee90578734d7f3505b8f21f136a028532df54eff2be896f8a0ca90ae5a8b", "signature": ["680b08782b6d46e8e97bb4559ac4d10b8798f397149562ca7a5d6175c10529f8", "fcb5dfc0d6fa938aecf81d53b7791a49960c1140d4af24a48db6c0b20cc3ef78", "e64852576f705bb11dfb634c66a1adc11bacf18973e80332de90261215a7d92b", "fbb1afd18a8487ab7b6761c07277fdf7a4fc478f23a57f07329128fbc7c47570", "4f12d69ba93761c774f6e4bb0c1f472c751d6fa2b93675c964c5cbf87485d413", "b5c7687fb98a5417284fdc7dd9528a320d197c6bd9609dab9aa13aef9f60ebaf", "bd9037e2bd51b6658ebb69007ad3c27e0d8db926465674a1b06fa0dea18b3960", "b4275d9af39a23ef503f2c7e83e2c8bafec575d4bea97e5f3af3e84ea972ffd0", "38311f0c0d8cc1a994674137763476af2d883f73550f197ca6a870cb0ad813bf", "743b3a2bc3fd3e3e88528366a2ebc73592850c3b19a7fba1e833988ab941776a", "b466b9647d35c2c5277736b647cdfd0405e3b1124f7b084923c7294ade82b789", "56689a5472f9d4e77ebb76cdcd074445648eb6a09b651d3208af9cd6bfa643a2", "2c565bc99dbd554d398c7f8a877e264adf30b76e78747821025c36c4135a4164", "aa5cfd0e0ece5ac2758ac2a7c9efca39461c1913dd57e5dd63e8f131bec7a0f7", "9b83e1407f196f9a710627693100e6747e26f674452cd7dc23d571a30df55c4e", "4cee06b3af1aba3829b016685252badc151e82de9f6027fee3f1a60ebb2832ce", "564cfa7cf08d7f120e37e4c617c15d17954cc42eca4e8e8747112fa7243575be", "7bb92113822de0398617390a0d56e036a1bef614a2bead4bc42455dc5e74462b", "16e6925bf3b79221297bdc4a7eb27c89c17ca26bf808b3b09b079fa76f06cf55", "575ea380958ad9bc82e3fc48cca71d857e81cd3824743a555cfc6f104ccb25a2", "bdf99fc9d9b75fbfbb8b4bd81942d2265946b1d845b0bef7f253c48c7cf755c0", "1447f45ebae24b259bf67d87190800b762ecf727aefa56bb2566652e32090534", "0323b5ddf10d048b4bed2e184ec84d5c5a3e436454d0754660338a91a8ca87a2", "00aecdc73719b787cd6d2c955c130a024f28b9c4d99e0543ff09f233341255f4", "55a9659cd690d31a9effde0d71268e7a6081f2d3244765a75d420919c3263a48", "ea6ec59e59f161f6110777741cc490efa623586229652cdc7b963bfd875ea83e", "d9a13acb78f6b6b39b937044544e36c2ebb00964d4f1b4415ca00a86253ae33e", "e457d95cb1d229ccc5cc552b81e3e7878b9f0a57af79d4a19efc54a14b8448eb", "1b448a1735e3e93832c4ac3afa82d3dda00039b93fa2f11536f5bd6282c9ca11", "5169f893633fdb4f0158c9f6255c82f4942d5e2feb9830bcf01327cf87fc46f9", "1015b80d119186d17330f9cb1624b2b99c850f2678632da9842ab20727fd288d", "dd2131b6557c9c2e51370da31b2b4f2f403094e9e2ea900d59595175bfe3f78f"]}, {"message": "afd43c3e9c1c09118d051e9d31a678fa96b5b3182fa6a6628b0c79f0424ebdc0 transfered 43 CERTcoins to 35c605f586d3dfd63583d986a758845b469d0b87d6d646ed5c0714e67fbe7de8", "signature": ["c1315f070684de7c1f8232a2cae06fdadaa9d7313bf3f64c283d3e1356822157", "b16eaca743928ee951eeefdf92b51bd445a489b0b0a3f19ed2038f15af1a18a0", "4e3015cb0181f895e9fe2322c8b1dfeffb37b9103f8ec0125a53513279c2b838", "a8b6dd62e9b81ce44f221b7aaf106a3e8f89d9dc64244bad38f09372c9ca35aa", "5fa3fe671989a4ba69e2160d5b6904ea6b37a6b8177948295709fe48fea466f1", "3f0fe08650bd8eec2a1fe39e969ebfba24f71279219db4ce8983509aa00afa33", "3cd508db0dd1f6ef2b338df5a025e9658e13cd9ae1999bd0b9f73011714ca91f", "6bbd47bb3d57831ca41a8fce3db4db21a87333b3e7bf852963fd142e6c2ad65b", "dbb5870c3742217aee72dccab58c629233d9f138b71ac5e71c1a14b4cb1831e4", "18fbd5863ad9b1b9554f03cc218f4873e9a272fedcfb071ea8af41aab5900abd", "d4880810654aa4ba75bbcbf3961b78304813b5be92c3d3c453814aedd0edfe00", "d1ad6cdaa1d98b0774275212d5f7104f7c5effd584e140e5b5e1d5b520399cc7", "96466077270df64c3fd6cc46ce3c012e46d72701adac38883f0e42a7974d0ffa", "404cfc70ef2b9c3ff576c67e49a955993de4e2285d2b035390fb90aaacc6d693", "bd53b0d47c5615b1510433cda76bc3cccab276e0a1ccaa997e04917089e15a49", "80b0119bb69d5d6a49420a3701640037a517e6e144b93c2baeeaf53c373a1a68", "99e08eea5b2798f3d9d4eec289db1fd42f4450e7934d3d712e87737e62fa776d", "22879aa05ba483a0d56545822e7aa7a6486683855e778713bc6cf3685159d032", "def3f3d1de714243847e2661d8a4643634e906b936a74dd0b3fd324f9ebaa320", "4d499b6b59a71ed2bf7f6ec66e5f03cee5d7da345ca7342931db149db92fa399", "a575f16e207cbb19059ab467ac3b419d60765181f6eb1dac1e7b74f6cb0d00a0", "ad873380a0111e979ba8217dc6a5c5ebd71ad9dca7f1d4e8841f830353637912", "2dcab78f4a3f647aa53936c8e686aede20f44a9a5cbb3492c7193b58eb540f05", "a0a6e2677156f2712a4bcf9c56eb8628ce1268e63fadb14744dc8df8b280b7a9", "e782a84eccc89ae1337bb6e4ff047d5c883c6d5b81897e4e4d16dcd3e5faf6a5", "de0f9075be0648f63ac51689f387627ffffb6270439021e61ecea8e8a554ae2a", "33d9d3ab2ae89b1e3bf0f42759f83bf34d36b93a02302b32165fcfef3bbf0175", "6f9ff8d1aebb967c385a6f3b18fe564a2e8a7438c2aa6fc03a6653c7fdb9ce3e", "c9eb7bf6ea6154a1f717f1ae2ba910a147cf8eb5743856f7185ed481e9b7646d", "3a65b600e0927a3c2725657e797703535b1423c72bc0e696d95025518fe4acfc", "fd53d64d0fc57be9b6095f47a64c19a171f0fc19fff8269395cdd80b4e31412c", "88cb4e2e6f4478d6199141beb95e345551b2a0974e53bc5e23ea51bb5d466dc9"]}, {"message": "afd43c3e9c1c09118d051e9d31a678fa96b5b3182fa6a6628b0c79f0424ebdc0 transfered 164 CERTcoins to 6ba9ee34da770998a4a81e755ad4a73e6fcdfd1e53f59b271f483d7efe8f1d60", "signature": ["c1315f070684de7c1f8232a2cae06fdadaa9d7313bf3f64c283d3e1356822157", "fcc33bbef1b30187a8b14b7f036f189fc753172d042bd730723e89c790e89555", "ef52e0af68cc0a0e787ec2c5c2ba9a8d9a82c214a0943157d5462f654cbce549", "78a92acdb31388612f26faf6be6e7930c63c20631ea34caee5d2b3ea0915a4b3", "065dd3e56bec5707ee684c3e22f1a6f905ce7a18e578534eee1c510be5bc2f9d", "b888f4265bb8ef840a266417d60f650b6792126a500b67f0954c94e5b4a59485", "ec9962d0434ddffdf6c01a0d661776eb79a6627413a81a5876f90fb898c9a3df", "892a31aceef7f62371b4c2621de17cdc52d966528cf3f4cf5625157e5e4f5ddc", "dd0ba50292182e645bdf31182b8128b715463a9929139b8cac58c5303763433d", "dd0b5326c4a90e7d0673014c268ca1cee7e123b277ba43bda9102f8b08b889a9", "b5e97dfadcf06113292d4ee51f7d8717d1de072d910ff3415aed5bd42550c663", "391ef789d4ddd37da120316d673aa46f49dc88f395ca91b808077feeb3740e03", "0a386eb2c51d59a8363390f09149a4e59e6c4261580bcde9626af8a3f3e74154", "7bac8a5582993af1dcfa0cf319648dcef3009fa781f5059a4d73b1181843a59f", "b1c45724be6d67d8ee46560df2a7ff6281141f9323664831e0025ae64d40621d", "136d419b95f0d84985a0e1a1b0bd2a61ffd26524b0c9f342dc3d55b0ba54c032", "6d9e5cbee47c6430495f2b43058e4cbbeda20d1a3e2f469d2aabdfa921a4942d", "6d13410987840c088cc842452151b77baf1afef74b09355ca3bf86b7102d1674", "e17a4af715906e9e7bb819fb560cda8b388d8fa2907ea563e982e636dfee15f8", "87df90f1b465eda4269e7c8c1101a6bab23c64a3430af90fbe6872ac742ac915", "68ea8bc0af38f73ea0499cedfe4a8818e1d84d66f75e106e8f44164df8eb9b2f", "2001e9aaf4c43a231b20df38f1321e34d64cb0f334d7d4cf59d5bc11d15e68cb", "58ff48e65b63075db41b314fc210bdc349552e65f7ab90b6a9eba184b93786e7", "15bd4fc02bb170595d2d00020787a2f7fb01cf629c22bd81f0a5df90fc899909", "4a4f40281e89ad7691b79b69b36a14646528354993e09f9bb1f82b126162dae1", "c1a326a09d2fe9c2d60e04f247e77af7cd09cf14193c5d679bc9e5214fea5318", "8341a8afd7136c72bbb383ee5af492cc31d90da6a7ed0c2052f3853a0502e778", "ea377dd956ac4fdf31a2830e90c95c7143047b49177a97d2f9181da277c2628c", "15555ddfa92d2224feb93ebe4c19a984fa6ff93008e19c3d5f1315babe5b11d8", "e1b5be59c7d423b884f05ecf4fee72b483a45f63d1f137d8058382f78df1a5e6", "6d63dbefaf5137f458df30cdbcde2bdd6af8804480bb1d743ccfd98f4ba37478", "dae49a81b28784b9cec4c5820f82bfff8ee5ab1d3408a46db090962401f2c877"]}, {"message": "afd43c3e9c1c09118d051e9d31a678fa96b5b3182fa6a6628b0c79f0424ebdc0 transfered 6 CERTcoins to 13d93724f2aca310e1a55e8e0068776e7a95e8dc3dbde6c8a6f5678aab4fb292", "signature": ["48c9a01ff73ef376040d94490b2699864267fdb9673162f44dc6e10fde59cab1", "890cdf8fe2f45f9c45df09bb2b0a95210f9bbb1e382a417ed58da1be33279b4d", "483592a1ccdac96e012296419a63d7a6c2c2ed4f86e1ee3695582556ae9b6dfd", "e3320455bb88605c38aed042e2025165531d7e16cfe8ba393c209b01eb18a357", "8fd03a63aad747427a38f0480ff2cf2960c42be11a40b52482c81bb728c10ddb", "67e65a0b917321cd247d57c189009ed20174d8e9bdcf1aef08a771499d7658fb", "a860986abe3717b5e4575f4fb69317dbe803d6cb57cfd9309a228cb8eb261c2f", "bbdb7ba5f14cb777bd93ab2438e93d414634d3c5f7c65de82c213a5bcb959c20", "dbb5870c3742217aee72dccab58c629233d9f138b71ac5e71c1a14b4cb1831e4", "4590ab2207e4b74f2bcc241660a179bf813920d4d695642bd96965781b226e81", "3c1e9314985d5a2e08dc35b27f279a846a38f022305bc261a7157d65ec15e1f9", "56689a5472f9d4e77ebb76cdcd074445648eb6a09b651d3208af9cd6bfa643a2", "55b416e7a8089a7d5aa616f788876c05d8e9425238e07df434312c83034177a1", "97ad9b2be756de1b62ce8ecb2f99654060f1a95beb3f708deb3e428297219e2b", "e584562ce040968f3bd61cd9915995548202ac2c99f86732e1922e6231a82105", "a5b7308187caada4195e57ffa07e102889c3efc832523c82abc6cdbf627177ca", "d9e8b14d1d7d4f7200fdf1138a4a085a4eb295f46078db925c6c0aa3fc71db7d", "930ce7bfa40b700b784f6d36447e173db207524b5312bf3f3c7776261a9c9cdf", "1ecb998efd0d1e604085771cca8e8c791a5e358b42a0d577ec7c453c3c3bd289", "1ed962a1451811a581ebd416b997b561d04ff7b24b7dd08a9d7efce7843f9e82", "1b473e28243734b6bb4bb0b04c7db8f6d41b9723b0115f3024058d75654b3035", "1a5616910a900526403d6e700aa361636382927f8621dc7557c8d6879aed823b", "ed292f354e958ea2aa1d64abe3fe56056dddd82bf2be3b9c3d9847431aeda2a7", "0a680f2501e0289f65ec0cffcb6009e10c2615957b3c3ef844358800c3665638", "96ee7ca0d3000ad768b052c38820f77d9bb5c2afaf7c01cee1c0a46b754934ef", "21c44985155462e73991fe35850d744dcfb4eeab2bc9ec9cf3704716850f0817", "b2628126330908b5d2752f697ac8b4cda23b961c9d05fd606427207f190ca0f2", "08e751423d7638ad1408f3323379a6f0cd6ff8e7ff7a32e2718f0e19b3a0c525", "403e8acd2cd653b747955bd93015949cee23e2784917857a521646c620101977", "b6a484fe0cf89b44f3f00c44fae7e711869f8f1a4313711cfefc669d3f6f787e", "f36619b7d137faa6468d7244ed9bdd33283e00cbf6aada97a245e98f47e2449e", "88401e530f69bc58f223dcb97c85eaa35eaf0faff7de5cfc5f8975e30fa47c62"]}, {"message": "afd43c3e9c1c09118d051e9d31a678fa96b5b3182fa6a6628b0c79f0424ebdc0 transfered 117 CERTcoins to 7c7da32a5ac15c64a7efda8cb2bbd312e15df329019e94ceb72d6f247f9bac73", "signature": ["ce892f11c79c6882e6b4ae2ac49e0593a9efbdf99b0e850b19595dae200c0861", "1282a1389b592dbf4d51ef0ff3d6457d915300b6bf5a2384300d1486d2b90051", "5e7c5d278de74e451f51c78fa1777d4673dca922d5702d35980da59097033963", "bda8bb54b4cdceaab997c5c47539c88a3dca03aaf1ff6fda465cc71796b3a82e", "bd05c2d60a91cefbdb01b77b4b79c874a32f37304410faecbf66425d9cf17c91", "e83037f6f4b5280a361d2a5702c2d0d95ff81d3a799bd04dfe3c9156e831f4f2", "f011a16010528585d3455aff02aac8205c659dfa552b827b6c23fc74e26fa2ee", "8a2e2a0e3ad3fda168b3c950176aa308f400ecea759d911ab2afb8ec4185c7f6", "3e183d55d490a5397cdf2663a6c4d7c8a7b5210b6e2df239d37a931022675f34", "18fbd5863ad9b1b9554f03cc218f4873e9a272fedcfb071ea8af41aab5900abd", "89ff940cd5af0a78d403e88f023eb48aef2c78fb14ea0ed08820bdcc0016680e", "96a23855e366e842f10576f52c358ad30c790627acca21bd5d63890a82d61c34", "2f5d30162395a944326fac0c970b893acf63b3d99774621201803711feab9f7a", "ccbd5593ee20c8a24cef5c9256eb36dd3ecbc4bedfdddffcca8644a05246cec6", "a70be6717bc4145bed54255708c31489f54f8007f04757f76783f585eb30d449", "7ced86c89f0b3ed47f79dd52ae2ccb9c4568752f78e393fe0c8a9865794782d8", "e86e46e1d2b30535919bcee0f2fb55c359bb17991f4872310225fb625915b0af", "59297408bfad37316b43187e1fb56f027a90cd6a240df2272651c77468581b8c", "30e3c48e7072978c0784f7b8e11d83ef1ce4916efe9215eeb2bb20b08de2d171", "86cd8f881f99dc3a6aead7287fb50775fa792f34fdbd61cefd754fb28dc20edf", "38b3ad11672f5821d7b9bf66ec932fb7d48497e802fc22f9d4a3b81675bebb34", "75f22542c4adce174db5df194f24e66fa3cccab61299a04d4873fb3d9a7f8744", "6a9ac2ad221b5c8b81760e01ec2a261440b200dd3f001fd446ae083f46763069", "6605d61be8a3b95c20dce538359602ef78efcdeeff964a0b64b933bd8129e57b", "da37b2b3f1f533bcffcff46aad43e4146eb3dabb6a6a2524e82d79192dc27b1c", "8d27ffa30fd7df3fa7360bdc866acc53d7ac0ab6f3da3c03424d367b5f76ea68", "f627ec650121b4c9899df9961e604ea001e24ffeb4f036db3ea6d4056e46a1a6", "b9d20ff5f29e384bd527ccda950448259309c5f1c7349f2f41060502277203f9", "e0066d54663f97882566b75ddb9e3366071c0b17f94343107039df31f8283ced", "8f3b3c918ad46858361a22fde20fce4899cd949b7f4533dc4b82d690d0c4334a", "fc6bc52c8965ade246f26582a14f747eb78aa6785c767a3f72a59bd24b84b643", "2f794861d919ce2412d027aaa98ff040018401c70e4f305308cb5e2c1f562f17"]}, {"message": "afd43c3e9c1c09118d051e9d31a678fa96b5b3182fa6a6628b0c79f0424ebdc0 transfered 48 CERTcoins to d3af01a0301cdacb913b647337580a655083fe9d5765c98fa1f69c7d92ab8ae1", "signature": ["ba2b9efc603a96f99ca81ae19275a54edca7d08d649bb364b41cebcad6930c7c", "36a4fb063225d7000d58daee82280c0f3e0fba58ea0134eef5d0a5e87ead2364", "ed31ecaedada23216ac3755c63c244dffb9f651c98248e33d6bf644e88efbea3", "a88577a17f0e59443fdde5143fdbed79db1ee613bf050dd400686d688329668f", "fbb345afcc0c08826be55222a189d2a1daa8c83abda0b4ba3db0450004119ddf", "4e72fc0736b36994b495939f5ed0fcf0db9898b240f1e590eae01906e5727b9e", "88b0d1bf59b6001d4196768d950d855e2d97e655ca13616ec29706c1ba6491bc", "3229d90c185566795034ab98f3341a831a1f9e70e58e433b26a609150f187d68", "4f3568dbfbd80888108aaee5935690603bc44668ad669cceba0ca872d5bc6787", "2fd35bb94b6c4d8cda840bacf7aaafd209167ad0c8bde77ac69518cc92286cbb", "c3dc765ba12ca9e1511738f8bf3c467d65f725685ec8648ac85e0fa68c705462", "a3132d54d338819712d88c967fba2d3b29afbf74999903a22d414a65d85d77ee", "1ed0ef95689505b9dd68c0c6e369ddecafe20605509b1b165857c13b86e6a093", "679aabf16a720f11369563ab29732ae42732d47ecfd8e4bdfe3966113b43528d", "0e983faf9cf885a2e4445adf2c7871bf971fe6a2423221d5814ec9335dd429aa", "c8260ae82623c94eb92895a6d93661bd384e6dbf7682d7b538af5816e1504a3c", "f904ce7b9264c1e8ea689cf695de4660f21bd92716751e39d0a17a0702551d3a", "2ef2729723012a8171e962ff60cbd48ad9041f9fd0ca6050de4b54c12474e2d1", "49f658d7cb5344e151391cd260eac39d2763de8f6d430f352723c231a8dd21a8", "5c54c1a1681d3ea293aef43145a90bbea141ed4ed273ce4faa6c43c07b4c8eff", "2d3d6ea98f1b6b34b0fe43d409fe42fdc8d76668edcb6fa25759c6205fef7a23", "21eae65e213b2630d09ec5310d4ae4562b6572f9fafb1e9349a616ca4cef0180", "fe7b53f62ceddaba23246365e9ecd4f1104243d08c3aba94223207f95cddf4fb", "46f25f34af6140dae28940e2d39360fff9ed843339192545dc2fec8801765705", "16814307b9439730acb2076db498268bafa492457a6bc01898c92f4f49a5d13e", "92bce5806968ca9a0640b05d7bbe9ea058c954176fee69087ba473a0ae1c0830", "8e4431563aa838f6ce2ed488f1611eb5c61c645345c388510af7840c0a8cd936", "e622e4fa020f82b2d1929c385ab96adfee11f29f51d1f27e2351ea705b8bd8b4", "d1c524ba1d607ed791ac4b118b4e53bb9f13f3d189e13a41118a4bbdd0642350", "de08950b7364fea9bd8d019c10b0b002a5d078f0a6ded7df89a5edc7357bdd1a", "153fd61e1af1f10c56d0b61b1954da1654d1e0f3132b977b1de5797ba9982ea1", "bc3796bd8aacde5cb0224a6391ef7bbfa92a70e40b2c6904d1c30053020cf65c"]}, {"message": "afd43c3e9c1c09118d051e9d31a678fa96b5b3182fa6a6628b0c79f0424ebdc0 transfered 20 CERTcoins to e4f2da2a09be8081b947701e4c5dcad383cf1c6e54ae48b4b4773de4e61a1eb6", "signature": ["98024cc1c77f2fa6fedc423a2de540cff779b019c061bd75624c8919d913e436", "8bbc1439f5f114c9f6c389643319c7fadbb40cdc38896f21807fb93e8fe5b61e", "5a2d948f29411d8709c20a1977d1d1d156cb825017cda3f7cd7199ecc3344be5", "3647fe5ebcc8e030db748bbac923c2e808a5769ed2f0286e937ea02d2285c1ef", "d65019af9f55f02ebd177988960ed29d10507f472e0946542c098ffd4c9d1e57", "1d0f3ab46461a6cd84f08f7f03291cd0f35494b76e1db6294f9a00aa60b00566", "404652cbbd7d2fad63fa0e95977e402bba6c62ba5e8df153ecfa37d5e3ef8bb7", "eb5496e5cf30c6d5215e8b792a18285c2a7a7e359f17eaaebda21b657809730d", "58cd85ccf026f839fb2fe755da692d60b786d3412c42a1eb530faab14f873591", "4590ab2207e4b74f2bcc241660a179bf813920d4d695642bd96965781b226e81", "a7c6a5e99f3150f1462a8af754627580cb9f0c354c330639f24b81da786bde2a", "e6c89267a11000bc6191fc3feb2b34f9c466198e9df550eb74aed2ba4e82fe01", "084607124ee3d5fea019f4b7319feedfa36c61c70aeda395b86ee8d51b14435c", "c361c10ef9e0924e1c53680db55efc6c452382224b6cd8d3fbd334d95b76f0c3", "bca29cab44459cb78597031a1b2c90663334a7ad3864f62bfb4197ddd977deb0", "4fd4db9cb911f9896ac40524b63e407ec1263810293081c6380eff2dbd841a3c", "e2d1495a2f20df9c676154e54deed761fa08ce7a5de3ca4155ba67b6cf9f8b46", "2c65448c7c679f90d22b6397ea81b6fe2f3fb3c5961ff68d314195e237e6bcb0", "e9f7164840afe8548adcac1eb97cb7e28ae18a55aa2e402d58f4f997d793e89b", "6bb9502fe3eb7469bd2a295fd44a4837c2d784f2965ad8b75345aaa1bc4b084a", "ac3f67b805f26dad49c1bcc04a52e8153c41d2f508c3056b27615725f24a7230", "814720521a8eae5f6f0fe7527e2db10a383aded3acdede648a095bfd92e6b51f", "46aa2c963e472222f7bc17c3617681f3844b65e76f89dca926becfc6438561d1", "3eb08b110714412cb407994ae34671c5b3d22fc2a683c3fb49702e984adaf5f4", "677e68176daa708a237802c0d8dca79d95545eafa6d26bca5704141496a8920f", "c1b22c5321681023c68663d2f06da29fae4f3637574c421c1de13205b775fec4", "f836198506524013e7783128a4da09fbfe6b002b66dc3e08c6f663963dd9c6d1", "1da3c2e0222628545f73590f8d9f6733b74a4845d35afde77b55a02282cd29bb", "bef3b99601bb2367be195c762f44ca1391b0beed2654383c52dedc327911dd29", "d7f3e984487e7cc8400d73185bd57d45bdec64ad0dd3c7a4a8f5586e62c384e5", "bfc7e7e074811b8a9d9321897ca60d547f40fc35fe3a7f105bb1ba89c1f6dead", "82130fe1671e6b3bc47ffddc2f5196497f107e4b1641754e2ad7b29b3dcbee72"]}, {"message": "afd43c3e9c1c09118d051e9d31a678fa96b5b3182fa6a6628b0c79f0424ebdc0 transfered 156 CERTcoins to d70fe43067eb0545b3b1bc92b24f89717b8d05ebd2994fb5f6d244c0ccbbc195", "signature": ["a35fbc609916b6c40173cdf1a5f375ca33aed7013fc7e62f40ca3b9210cc1678", "95ad8302cbf78b598c8e7f37a5e7dcf6a65ca649b12d91716ba8b04dcd954e1d", "5fff7b8ea98fe3824aad673ba3999842cf279ee6674c7ead77a5c7fd680e04c1", "6b68ff3f383ce6abad29880ff88342456e1d2e7a3858b905745b8845eda0e0bc", "6aacb2149c92454cede25eb17cc9004612cf44daee077a2236043a07c8a34139", "ba4cc0f8b21610bee4308c065f8bf3098a4d4b9bed4674a4d226d5363e05531f", "951106a8bc6f6c34df924bf1b1b350c350a7289e110a38f780b2ef9b7a146813", "cdb200cd1ddbbdb12753cc3026cb383b04cb6764476c882f7c765aa70e8680da", "60355795a68906bdd280ce712676c0a4c47c0c183ac69ec19a3042951af26bf8", "6c4e6e29fe6e548e7a80c02180ad64d993a1e17ba7d6e07614e422179410637f", "9204943ed701add7a3f07cbbfac44fff75f3275d8ca0c461db1f5f490e4609b1", "d6c02bd21d796c1bad4cdea4bbadf4de3706840f72cae4e54eb1b4432211000b", "c56ab6bbb89bb1caf3ee4abe518b89988fd04b5fa4677790022f2cd7780a75c8", "b90fb819055d76834adda36a032c0c32fe9229634e34ae9bad78cd2bda8a22ca", "1f3ee7314b337115c9645c6ea3d2b345619786519c5bd3d61cfb7cfbbd5f9cb7", "88c5ee021d33d17548b007f612d4c8cb51d86941c87c0ad98167fa703b61b45b", "94d237906bc7df9aeb44b7df742928143fb142aa42d4d4545f2d24dbc8f2aa6b", "e3caf8a0dc9af33536d072e35664d5fdb4a32779893200e2e7c6a8b9959e54e0", "6ba5d804505b6312dc8697f9ea010125df779b560cfe32a26c482cb404d386e9", "514257237112bd6a9617abf7c2a6a5dc0893b478ab34c27367b17fc736536b78", "6fc109e66001e0464d67772f48227a2f8ec47a05169a9dd65e8c992d9949df80", "a45f2af851e708ca45628c1dd37784e3c43f0b50fe735ed73f0e9069df8e5780", "8e91f4d1c85548d1bb60c438ef2dd0708f232df1ba02fec44bf7f0f019e3c22d", "145a6d27a0b6f7ca774af16389f958c7f6acf1fd83573b75e9f75fc475776eb8", "7c5201b78765d6a5c61d65fe61c022e9212bf1be25df6c615c9da7c8c700773b", "8cbe60cb387d7ef8aebe021cd3b61e22f97f789f812325f61deb95d505d22d3f", "f1cd3fa711879360112693b5ef17bfb363a5f84710d5290f8295bd24597dfebd", "d1c83e1e01e9107d07b9d8d1941d5c94381c46ca0a57edb6f9163e8b810d773d", "e47b97c7564d7b308047751e92da65b7c63e015ffdccbaec15fdbfaaf117ef2c", "bfca7c8f1b4b2bd6e801e05a44aae73343139b8bde089a4808d972bb48bf7b16", "b2f2448886ea84ca80e40c85dc1781717025e927ed678ef805807a98bffdc5e1", "a108cca9152c19b05755e8b7ed58ba6aa6112da2a38a7d0af9de97e7cbd766fc"]}, {"message": "afd43c3e9c1c09118d051e9d31a678fa96b5b3182fa6a6628b0c79f0424ebdc0 transfered 156 CERTcoins to 7b31d9be63a1d475565a24eb25e3b2675264e6db2cfa99d393423aadcf2d47d7", "signature": ["a1e68899bae3e6da7fa0ac5fc0446599ed5302e4dbd6e671548c211200b73492", "a44aad7b01a8b52eda0fb5d636d77de079e24c8ba0d3d8318b29a738388b66b2", "325a3dd9b62c02588d3539ad4c8d118b6845ab6f3293f770d9f60f44c5ec85e6", "96b4f87f2b9828ab8ea8cdf480b4a8364df6590620ed161eb861a12a4542d546", "1ef20499f8dd4b89bec6ecc85690b9ed0db4c7f09f935fe456137b20dd36325d", "6a7f5c34466f3afb41e363dab3b52fb544becc049bb809c3a7eaae401e1c425e", "cbbc114b77b1e04198fa32801285ee0dda777953270df8eadd967c891edf57e0", "fbd341eb15eb2427c894286ce077a24debf7047e6342c1fb383bfc8fe0dccbed", "bedacf179c7226cd1400a037b7b2d895a267af8d83194c6d419520e0999c7744", "b80475c2e43b93780bbb6b5d6fb4c1190511d31ecd1c1b266a3faa127a185b21", "deb5840edee2452184f57b21e7345ca0c7f7b6b8228be56a9f21d3ed0f8d5000", "cd648ca2daccea442a4bda2971580f0f8d855f475e13f988da5f9e08f239fdfc", "2f67bc05e9cbace0028808585ba8d72acc2a4289f10e411ebb4821506e34a524", "842304cf9dcd43b47442eaa4e27c7d4ec08dadf08dc14a767fc196060b0e75a9", "e13012a858a93fef15a3a17554b7290543d5f9f68a1d7eefded309e8f37f9e79", "5857646b9bb5faca8f601232cba0e3e9c3c61d353ea7d950015118bfbe9123e4", "dbe977cfaccecd1f18785be5b3b2bffa022968cac3ef746ecb69a37b8446f04b", "2b69451a0cba01ce881d5dc740a93d2a55b9c07a5d0a20ccc28ff353fe80f3fe", "6ba5d804505b6312dc8697f9ea010125df779b560cfe32a26c482cb404d386e9", "369aed77f79c8392e3044d9c51d3bc9426eaffc7f6b7f7aa018109305b1d07f1", "55d98a9b5de8819569818318d9f56e981a8a27940979bf855731c0042f785a9f", "d20d61068b2b718102e45c882450105ae488fa9873e067ca0f70eccd3047c4c6", "9991eb0c9ad51248e9d5a62c31a1023ee1d7d0afcbf60b98ced8ae46985939ca", "867bc48d464b2f7f8abbf82b01f202b7ac8cfea5af175fddfee8a35d94d0ab37", "93d93a0c317c2671ee521acb0fefd4776a6333f3b4355aa828b29b0ed1dc3580", "9651e53418e0750abd99d67b445116b65b6f6049f7fcf04ae7e5f850d81347bb", "373d2e2a138cd7ecff40d03ee5ddbda92865c7c533523119d71b7ab91e3e868e", "413019a5160ca51d84881edf99d54bbef8ca39008c7258b50a05559357c28863", "5e74a47362e4a9c385c6ddd2a3efb72be48ab98f0b3d221cd10f5420349ac12b", "d0e23d68fc1679091524253cfd93817f29f689c1460d6f88a850399a426cd690", "b66b4b4efe1cc8d4af0ef51f41b67c84aeed0ee2f82e0647d9cd2dc46ea43927", "19280a813dcc2c47c081390e80f3cc09657d8ba3742a926ee1d26c1a83d23cb3"]}, {"message": "afd43c3e9c1c09118d051e9d31a678fa96b5b3182fa6a6628b0c79f0424ebdc0 transfered 160 CERTcoins to ae4b51845804f849f218f4a8f640b2d744a224092e178d71c275021d0ee95ad7", "signature": ["d5537682f89e272d4fb1a5f49a201573eb692e46750e2a76681b7e98579963a0", "2d9aa00843982da21d9fccb09bf6a2861448dc398882895697eb3ec2ba0e8a11", "9c869110a4a67bf5891b696b068dff5da260e066ad57d095133719039daf9511", "6f2d3d41823301cc632779099e7f2712ef8de73a433b1dce396a0c45f38b7175", "bbbe2b618b990447ab3345f538748fc334261de2d2119a62bafac3477f256e7f", "7f64b5b5e4eb044b54ad2596f20b7a3a41b9b3f95d61cb2dbc8cec2eedbb27c9", "2db983b083138e81d6d1babf0556e379275260c9c5ec9193de43e44cc085f208", "01cd515124a545a889312638b27f40d32d300463b404cb8ec5c4f80a8dc2c102", "66f891d0db5f906b05f0efa870b9bc765a3020218e8f36c60fb35c4dd5d8b92a", "dcb187256efae71cc92f0163d21d36304d9e45f5f8a9027f52048f3eff7dbb35", "700b18841f2ee6ce05435649a89e20998a16dd238272b258c0909877588b9648", "a810307a9f984f11b70350c38bcd798d592c803948d5d3c7a406057c770caba1", "a09b768d0ac4362ccdb0846b9ed48ca59f5fdafa06e4483b7edc341efff161f6", "6d9ec036deaaeddcffabddf798ad42b9f465a0d3193beb34913ee1e9251347fa", "05b6d7287e1761fe1eb0169a7cc1e83bb4b71c43333ff3cb0dd4b160ee1bef97", "969e5b6da2f122f9be4de22c7e9eba689e4c1a95458ecd4f476244dfec88b1f6", "e4d198fa15ee8e93e03b08f7a5a5061719a70bf78876d4449ffe222b2f9ae0a7", "6785093460686ee0ad3ae15b22b666bb0ec2e802608f142afd205f4686a4ef3c", "abcf28f0750de54e41e312736b56a6396aeb034cfe81335f2c8e99b08e0a87b9", "f63a9aa5f91e1afaad3cdc9ddc53ee96901a639e9b7204a3158835ad797872fd", "63621fa01018decc3e9ec5fd9434fece6af0333c08223475d4f7ae6a0ec2c925", "4f175c06ca7d66229647cf1092b68a9e4fc8f73bb043d765224cdc9ba1e540d2", "bffb3069853c31e308da20cdaab6604ebdb9e96b86eacbf2b9d108c1f72f7a39", "a65937267a10e8c133db318e80daf81d919c98d31da8aa38fc22cbe66ac05e7a", "8246dcfb5689dcd3081b90416b617b127a637616e0acdd843669882410604ecb", "3ac1f431ca18b45f4e6cb45de3edd5fed96c27da8dc0d765edb8abae84f4c176", "f9095cd582e54e691e0c3a587f1e19d08db5299adbc42e7e4a494cbd0b4302e4", "3490c0cb9ad1822e924a296bd08b3a97c5aaf8e62473ca67f0e953c22f614cb4", "9dc76861ca78f321018a46ddb53b6b7762ffbcddedae4de6c1a27251763a9c22", "8586c66c37794d4d71d8123b36e0a43286dccb079bf7b62335f97dfb40e7943f", "d417b86c178fdbcc753754d93b8b3dfee167e9497896020fff214ee6d6ae3f19", "99477ceaee7b0402e817154938122d7a7fc78426b0163573a0a7c0c3c7dc60ba"]}, {"message": "afd43c3e9c1c09118d051e9d31a678fa96b5b3182fa6a6628b0c79f0424ebdc0 transfered 189 CERTcoins to 0cf7246598bccfae50de41b33d76ebe69590eebaea342c7eb6d5b4a81f506de8", "signature": ["22a6caaeaa903ac429380dbf916fb1eba96ab6473ed48582ad43217332526d78", "2c5192f2cb8f9a67e048861cbdb0419a6037875763d15e6e96f6885192d00919", "f8acef254cf66de66ac454f7b6eefbbc7917eaed631058dbd9875dc27d5787cb", "d020416084e6b76b197913896b528beae4f4a4fc027795643487e27a0201b466", "50af4fd71dabd2e751d8b584cf01e69e6ec979a67906a85ec3a2c242f4cf8818", "caffd1f2cd5d350e0981fb5a1519321802077e14e6da948812fc770112d211b9", "7da23233875ed3c1cbee1e2a291bbece7b3cb2f140b9882c6d620d6c021f428d", "1bf063109430144227f4d0374fda73dfb469effa9f5b77891b9a7b474cf4e6d1", "34ed630db563be2d5304267b5b89d5df16d1345ca2f9173e6fb3dd3bfa670de6", "b38a30a19341c3b9a38f9f00c7958e74299dd015246945bd258347b8bace34e9", "e3c196a462fbe7f4b8720d31b751bab24a8e8656e1c3e321943025589043c8c2", "eebf5a1a885d75de0a21968e3df6c582f313b163e5bd1ea569a80fdd752481d8", "837e3739d24b18f96d44b947aaaf1df926f70abd2a6aedf1b846098c22bb58de", "7ebed9677ae10dca5c796960c9dede566c394b321838e7eb106d785989b4a987", "c09c629db29a25449ab8860685152b4632596268cf91aa4813cc1c4408310026", "032f1ff7e0a03f62ce13c9b16a47a38d1ae6c6d81d6b285c2ee3cb65192d3d37", "99e08eea5b2798f3d9d4eec289db1fd42f4450e7934d3d712e87737e62fa776d", "2a15ca62477501984e5c2f01fd69e4c4ab42dea1f5b0824e8510f99329db8321", "14ceeca7dbd52a31090169ac2796415367ce0272c493485df5896811a7e63d3e", "3d71451c8048c5e3663b620d5e5221a23ce86d950d709b3efa27160e3f796feb", "ee6a902d2b30396612de2bfe0a87748bb28007d3adc23cb9f0c5cc39bffee9a8", "ad873380a0111e979ba8217dc6a5c5ebd71ad9dca7f1d4e8841f830353637912", "10bd3769097ecf0f6f5170e7fa51211dd9d7bb1212af1a4838f0bf9270c9903b", "8fe5a1c63df4c3c37a498229f3a511700289b38fbe70e05fc55e31435ccd423f", "2177114192dd6d7ed9449feb4218c4b86117d71c7a5083402ffe191d3c16ea52", "9291c96eb78cba53a7f400492d8159551850744c3f404485fb0033ed50312179", "f5624b4b52effdd88c423940008a4dd4053af60063d3dcc544eeadedb25a9831", "7687f69b7a148d77100243b8cf7d913c500b09af667ab8fbafe0ffded0f91897", "03952bdfb23ee6ab09604c72093f846c1585d01f96167f7b34edb654d5bf31b4", "064556f0b762c878a1bdb9b3a017610136bed6cbb2b315dff389f431f1b2648c", "498206950cb97c9b341022a1a358c63ee7ea4501ae323246270176caf0fe3afe", "9ee5451006ea028ff3278edc4f030597066fdcd0b92b142a713579337e891192"]}], "public_key": ["afd43c3e9c1c09118d051e9d31a678fa96b5b3182fa6a6628b0c79f0424ebdc0", "713f29cda55908c55ef071da18157c80227c4a8587fa53a496bc7cc3451fadc4", "8b6dde9408eb90cc55a0f7e8bbf3a8c0c2c0e8a4c0a0da6373a0a30fa18c1892", "379f3894d39d3982562e9c5ccda397d09f61d8fbcaccbd7149f997848b475626", "3f5bcca389878576f21f7fe35160cfe2e0c330f9d0600b22fc92df9d76527320", "6e6c33389db39ef15488f5a523cc335bcb003f403e64a75383814a66d00e3eff", "0043d19eec3f08b5a0c7e8af8e144275dd83a4b4db17363073cfb7b8cd9801ff", "eb9fc2ce69b2d342953f72a35025783734c7f2f5b2909a9d4cc1a4b4801a708b", "6a427b92bb6b589585fb5ce14b55701b429da9ccd9f349c5fef5c1d8ea83ff14", "d103c4aec578fc0344bdd18d187b84a944dd1516656e2c27ee58cd0e23aa3b80", "f46a16130c23a5233e02e4af7787ed713c05321d277e4f1da9ec354800cc4b10", "e0d2b5ca91c97248defb90338abf43384dddf3b1444304254ae6af61cb884950", "d013e20cec79a20ee0409c718d88b3533913425950bc58ad03c9c5e4cc0fb43d", "f3accad50962e99fa7a6630ff93f262c1576f465dc9a975f4a157bf905aca686", "74a6afe6b7c458c8b73ac9c4e3cce14ae97cde8132945d88f5c8053fecfda073", "2c6f1fc31c918443e9e56e8d674e2def341f88f3df77eeb1cef21ea734d7faa5", "7f1634a7c9f6a9053c0d3b3eaea1e9ef6ee97b69b24cb1e391fc8fc11fb65a67", "902e9d50881969e785f3f92ecc3d51d1f91ed62994a492fa08f6a95ecfec082b", "1b5571e5a1ee23a2fc0a978af6aa9cbb457d63ca63a299ab78780099b044e30d", "e77f93dfa7f64f4b281ac7dc5a43c7713fc7e4dd346bfb898ce0bf5d3ab0ca28", "cadb672b394b5a9674765b27b65d60a54e5c1f554e3ada372b632bad80c6b3b3", "b3b72e1a42e597195bbab11cad77f671aab2b9769264335f9b9bb6eac4690d68", "4e3675fbf23ddd89152674d7a79fb7caddd107b0bf55f440302a69b0c089de7a", "b6697049d4c6f3e83bacef57c4bc14cc1c34b3be658a215decbbe55797d011d0", "55147d1c295227e6f654caa3307463bcf1dc7652d98abfd9338ab5f43bd90807", "58c99a316d367f92da25fba833fdb085ce386aac30f63d2fd37b33cbd12e0c5e", "7588fe6ed948be47448c44c2c6594958b316766f236b5bc50916ec8a04d413e2", "50c9c6041f25a26d9620fa820c647cf978b99fe9d6331d7585fdc9b5dbde31ac", "aede15ace5fdc783beeeb95f0ccd4863a56dd547652f6fe1117759cbd29eb558", "70b4bda072c75127f5ebbfdffa5c39b38b1ddbb211e86fea16fafd295962ad45", "102d740f015169e9af60d375fdae31a77272a2cee023508c75caac87eeeba49f", "04b5f4ed03fa6918f6e681af8c23027ff4323eba1d344d4e23a008e16aab5c4d"], "iv": "cb41722b75cf975e5222d4c23eb1d51a", "enc": "031ce82c5562f165ad0fde8649faf69bb68ccfc39e3c3ac1c7820a4e71fdc962"}
```
*Solution*
After careful analysis and research i came to conclusion that the vulnerability is one cool one where the script re‑uses the same one‑time signature (OTS) key pair to sign 20 different messages. That’s fatal for hash‑based OTS: by comparing the hash‑chain lengths between the provided signatures and the target message, you can “walk” one of the existing signatures forward (by hashing a few more times) to forge the signature on the challenge message.

### Forge the missing signature

- Compute `h2 = SHA256(target_message)` for the challenge message:
    
    ```
    "<public_key[0]> transfered 999999 CERTcoins to me"
    ```
    
- For each index i (0…31), find one of the 20 given signatures whose hash at position i (i.e. SHA256 of its message’s i‑th byte) is `≥ h2[i]`.
    
- The difference `d = h1[i] - h2[i]` tells you how many extra times to hash that signature piece to match the chain length required.
    
- Hash it forward `d` times to get the `i‑th` component of the new signature.
### Recover the AES key and decrypt

Once you’ve forged the full 32‑piece signature, the AES key is simply the array of first bytes of each signature piece. With the provided IV and ciphertext, decrypt with AES‑CBC to reveal the flag.

Implemented in `solve.py`

```python


import json
import hashlib
from Crypto.Cipher import AES

# Load the provided data
with open('../data.json', 'r') as f:
    data = json.load(f)

# Reconstruct the target message
pub0_hex = data['public_key'][0]
message2 = (pub0_hex + ' transfered 999999 CERTcoins to me').encode()

# Hash of the target message
h2 = hashlib.sha256(message2).digest()

# Parse the given signatures and their messages
signatures = data['signatures']
hashes = [hashlib.sha256(sig['message'].encode()).digest() for sig in signatures]

# Forge the missing signature by leveraging reused OTS keys
signature2 = []
for i in range(32):
    target_byte = h2[i]
    # Find a provided signature whose hash byte ≥ target_byte
    for j, h in enumerate(hashes):
        if h[i] >= target_byte:
            delta = h[i] - target_byte
            sig_piece = bytes.fromhex(signatures[j]['signature'][i])
            # Hash forward delta times to match the needed chain length
            for _ in range(delta):
                sig_piece = hashlib.sha256(sig_piece).digest()
            signature2.append(sig_piece)
            break
    else:
        raise ValueError(f"No suitable signature found for index {i}")

# Derive the AES key (first byte of each signature piece)
aes_key = bytes(piece[0] for piece in signature2)

# Decrypt the flag
iv = bytes.fromhex(data['iv'])
enc = bytes.fromhex(data['enc'])
cipher = AES.new(aes_key, AES.MODE_CBC, iv)
flag = cipher.decrypt(enc)

print(flag.decode())
```

and we get the FLAG as:

```
SK-CERT{h45h_0n3_71m3_51gn47ur3}
```


## Suibom

*Description*

While pruning timelines, Mobius met a bizarre variant obsessed with organizing numbers by divisibility. The variant handed him a dusty notebook titled The Table of Divine Divisors, muttering something about cosmic balance. Mobius, unimpressed, filed it under “N for Nonsense” — but kept a copy, just in case it had anything to do with jet skis or Lokis.

`main.py`
```python
import random
import json
import csv
from math import prod
from sympy import isprime, nextprime, divisors
from secret import flag

bits = 32
primes = []
while len(primes) < 12:
    candidate = random.getrandbits(bits) | (1 << (bits-1)) | 1
    if isprime(candidate):
        primes.append(int(candidate))

N = prod(primes)

offset = random.randint(2, 5000)
base = N*offset + 1
p = nextprime(base)

exp = (p - 1) // N
g = None
while g is None:
    a_candidate = random.randrange(2, p - 1)
    potential = pow(a_candidate, exp, p)
    if pow(potential, N, p) == 1:
        is_generator = True
        for q in primes:
            if pow(potential, N // q, p) == 1:
                is_generator = False
                break
        if is_generator:
            g = potential


flag = b"SK-CERT{REDACTED}"
x = int.from_bytes(flag, 'big')
assert x < N, "flag too large"


divs = divisors(N)
F = {}
for n in divs:
    total = 0
    for d in divs:
        if n % d == 0:
            total += pow(g, x * d, p)
    F[n] = total % p

with open('params.json', 'w') as file_1:
    json.dump({'p': str(p), 'g': str(g), 'N': str(N)}, file_1, indent=2)

with open('values.csv', 'w', newline='') as file_2:
    writer = csv.writer(file_2)
    writer.writerow(['n', 'F(n)'])
    for n in divs:
        writer.writerow([n, F[n]])
```

`params.json`
```shell
{
  "p": "24543926533640002647957367866857207914306117049983697556799269232027004353932658074554559267003250607939288726496967",
  "g": "2078132001926017604748032590856030624252738363341625757437676864936624505324989739084558861915765841155338265586523",
  "N": "314665724790256444204581639318682152747514321153637148164093195282397491717085359930186657269272443691529342647397"
}
```

`values.csv`


*Solution*

The challenge name hinted at Möbius inversion, ChatGPT implemented that in this  `solve.py`
```python
#!/usr/bin/env python3
import math
import json
import csv
import random
import argparse

def is_prime(n):
    if n < 2:
        return False
    for a in (2, 7, 61):
        if a >= n:
            continue
        if pow(a, n-1, n) != 1:
            return False
    return True

def pollards_rho(n):
    if n % 2 == 0:
        return 2
    if is_prime(n):
        return n
    while True:
        c = random.randrange(1, n)
        f = lambda x: (x*x + c) % n
        x = y = 2
        d = 1
        while d == 1:
            x = f(x)
            y = f(f(y))
            d = math.gcd(abs(x - y), n)
        if d != n:
            return d

def factor(n):
    if n == 1:
        return {}
    if is_prime(n):
        return {n: 1}
    d = pollards_rho(n)
    f1 = factor(d)
    f2 = factor(n // d)
    for pr, exp in f2.items():
        f1[pr] = f1.get(pr, 0) + exp
    return f1

def discrete_log(a, b, p, order):
    m = int(math.ceil(math.sqrt(order)))
    table = {}
    cur = 1
    for j in range(m):
        table.setdefault(cur, j)
        cur = (cur * a) % p
    inv_am = pow(a, -m, p)
    gamma = b
    for i in range(m):
        if gamma in table:
            return i * m + table[gamma]
        gamma = (gamma * inv_am) % p
    raise ValueError("Logarithm not found")

def crt(residues, moduli):
    x = 0
    M = math.prod(moduli)
    for ai, mi in zip(residues, moduli):
        Mi = M // mi
        inv = pow(Mi, -1, mi)
        x = (x + ai * Mi * inv) % M
    return x

def main():
    parser = argparse.ArgumentParser(description="Solve the Möbius inversion crypto challenge")
    parser.add_argument("--params", default="params.json", help="Path to params.json")
    parser.add_argument("--values", default="values.csv", help="Path to CSV of F(n) values")
    args = parser.parse_args()

    with open(args.params) as f:
        params = json.load(f)
    p = int(params["p"])
    g = int(params["g"])
    N = int(params["N"])

    F = {}
    with open(args.values) as f:
        reader = csv.reader(f)
        next(reader)
        for n_str, val_str in reader:
            F[int(n_str)] = int(val_str)

    gx = F[1]

    factors = factor(N)
    primes = list(factors.keys())

    residues = []
    moduli = []
    for qi in primes:
        gi = pow(g, N // qi, p)
        hi = pow(gx, N // qi, p)
        xi = discrete_log(gi, hi, p, qi)
        residues.append(xi)
        moduli.append(qi)

    x = crt(residues, moduli)
    flag_bytes = x.to_bytes((x.bit_length() + 7) // 8, 'big')
    print(flag_bytes.decode())

if __name__ == "__main__":
    main()
```
 
 and we get the flag as:
 
```
SK-CERT{m0b1u5_1nv3r710n_15_345y_f0r_3v3ryb0dy}
```


## **The next challenge**

## Simple curve definition

**Description**

I am using a very good and secure messaging system, but I found logs that are not from my communications. Because it is so secure, I need your help to decrypt the messages so I can find out what was going on.

*Solution*

### Recover k

First, we extract ECDH public points—these are the two public points represented as P=k⋅G and Q=k′⋅G. This is what is exchanged during the ECDH handshake.

Then, we compute subgroup order—we need the group order to ensure the discrete log operates correctly in that order. This involves using tools like Sage and some elliptic curve group math.

- The full elliptic‑curve group E(Fp) has some order N.
- Our base point G generates a cyclic subgroup of order r|N.
- Discrete‑log algorithms (like Pollard’s Rho) work modulo the subgroup order.
- Knowing r ensures that the discrete logarithm solution k is computed modulo the correct subgroup order, which defines the cyclic group where G and P reside.

Then, we recover server's private scalar:

- Elliptic‑Curve Discrete Logarithm Problem (ECDLP): find k such that k⋅G=P
- That k is exactly the server's private key used in the ECDH exchange.

This is it in SageMath:

```python
p = 298211241770542957242152607176537420651
a = p - 1
E = EllipticCurve(GF(p), [a, 0])

G = E(107989946880060598496111354154766727733,
      36482365930938266418306259893267327070)

P = E(72947667249607227642932393260968830921,
      261432642373021661017738970173175343657)

r = G.order()
assert r * P == E(0)  # sanity check

k = G.discrete_log(P)

assert k * G == P  # sanity check
print("Recovered k =", k)
```

```
Recovered k = 37041828426322252952359931953705367198
```

### Derive AES key and decrypt

This part is implemented in `decryptor.py`

```python
#!/usr/bin/env python3
import json

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

# — Curve parameters from main.py —
p = 298211241770542957242152607176537420651
a = p - 1
G = (
    107989946880060598496111354154766727733,
    36482365930938266418306259893267327070
)

# — Client’s public key from cache.jsonl —
client_pub = (
    291216048318375702409990419027018106946,
    219380392381458352976435257541531938506
)

# — Recovered server private scalar k —
k = 37041828426322252952359931953705367198


def modinv(x, m):
    """Modular inverse via extended GCD."""
    lm, hm = 1, 0
    low, high = x % m, m
    while low > 1:
        ratio = high // low
        nm = hm - lm * ratio
        new = high - low * ratio
        lm, low, hm, high = nm, new, lm, low
    return lm % m


def ec_add(P, Q):
    """Elliptic-curve point addition on y^2 = x^3 + a x over F_p."""
    if P is None:
        return Q
    if Q is None:
        return P
    x1, y1 = P
    x2, y2 = Q
    if x1 == x2 and y1 == y2:
        if y1 == 0:
            return None
        s = (3 * x1 * x1 + a) * modinv(2 * y1, p) % p
    else:
        if x1 == x2:
            return None
        s = (y2 - y1) * modinv(x2 - x1, p) % p
    x3 = (s * s - x1 - x2) % p
    y3 = (s * (x1 - x3) - y1) % p
    return (x3, y3)


def ec_scalar_mult(k, P):
    """Double‑and‑add scalar multiplication on the curve."""
    result = None
    addend = P
    while k:
        if k & 1:
            result = ec_add(result, addend)
        addend = ec_add(addend, addend)
        k >>= 1
    return result


def int_to_bytes(x):
    """Big-endian byte representation, at least one byte."""
    return x.to_bytes((x.bit_length() + 7) // 8 or 1, 'big')


# 1) Compute the shared EC point S = k * client_pub
S = ec_scalar_mult(k, client_pub)

# 2) Derive the 32-byte AES key from S.x
shared_key = int_to_bytes(S[0])[:32]


def decrypt_log(filename, field):
    """Decrypt and print each JSONL entry from `filename` using AES-CBC."""
    with open(filename, 'r') as f:
        for line in f:
            record = json.loads(line)
            blob = bytes.fromhex(record[field])
            iv, ct = blob[:16], blob[16:]
            cipher = AES.new(shared_key, AES.MODE_CBC, iv)
            pt = unpad(cipher.decrypt(ct), AES.block_size)
            print(pt.decode())


if __name__ == "__main__":
    print("== Decrypted received messages ==")
    decrypt_log("cache/cache_recv.jsonl", "recv")
    print("\n== Decrypted sent messages ==")
    decrypt_log("cache/cache_send.jsonl", "send")
```

First, we derive the shared AES key:

- Compute the shared point S=k⋅Q.
- Truncate the x‑coordinate of S to 32 bytes to form the AES‑CBC key.

```python
S = ec_scalar_mult(k, client_pub, a, p)
key = int_to_bytes(S[0])[:32]
```

Then we just AES-CBC decrypt the logs.

```
== Decrypted received messages ==
hi
how are you?
good, want secret?
SK-CERT{n33d_70_k33p_m0v1n6}
bye

== Decrypted sent messages ==
hi
good, u?
y
thx bye
```

the flag is clear

`SK-CERT{n33d_70_k33p_m0v1n6}`

---
> On this module i managed to solve those the others we a bit cold to me.but i will find the solutions and add them here.

---
