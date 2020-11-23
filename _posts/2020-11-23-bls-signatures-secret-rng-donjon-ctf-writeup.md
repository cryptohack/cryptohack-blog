---
layout: post
title: "BLS Signatures and Secret RNG Donjon CTF Writeup"
categories: CTF Writeup
permalink: bls-signatures-secret-rng-donjon-ctf-writeup
author: Robin Jadoul
meta: "BLS Signatures and Secret RNG Donjon CTF Writeup"
---

Following on from our [Fast Multisignatures and One Time-Based Signature](https://blog.cryptohack.org/multisignatures-donjon-ctf-writeup) writeups for Ledger Donjon CTF, here are two more for vulnerable signatures schemes from the pure cryptography category. Writeups by Robin_Jadoul.


## BoLoS BLS on BLS (100pts)

> This signature scheme sounds really good and efficient.

We're given a README and two files with Python code. The file `app.py` is just the web interface we can use to interact with the server and isn't really interesting otherwise, so we'll ignore that here. The README has a very brief explanation of how the BLS signature scheme works and how the challenge applies it and modifies it.

#### BLS elliptic curves

The letters BLS occur several times in the challenge name, and they do have different meanings. The first of these meanings that we'll investigate is Barreto-Lynn-Scott: the inventors of a *pairing-friendly* elliptic curve. We don't need to know a lot about pairing-friendly curves and pairings to be able to solve this challenge, but a bare minimum is definitely useful. A pairing-friendly elliptic curve is (as the name might clearly imply) an elliptic curve for which we know how to efficiently compute a pairing. A pairing is a bilinear map $$e : \mathbb{G}_1 \times \mathbb{G}_2 \rightarrow \mathbb{G}_T$$ where $\mathbb{G}_1$, $\mathbb{G}_2$, $\mathbb{G}_T$ are groups of the same order with respectively generators $g_1$, $g_2$ and $g_T$ such that $e([a]g_1, [b]g_2) = [ab]g_T$.

This means that we can use pairings to solve the Decisional Diffie–Hellman problem (DDH), or even more or less solve the DDH problem *once*. Note that because the groups don't necessarily coincide, we might not actually be able to solve the Computational Diffie–Hellman problem (CDH) outside of $\mathbb{G}_T$.

#### BLS signatures

The second occurrence of BLS refers to the Boneh–Lynn–Shacham signature scheme, that relies on pairing-friendly elliptic curves (so we can instantiate that curve with a BLS curve for example). The first thing we need for this is a function $H$ that maps (hashes) an arbitrary message $m$ onto the group $\mathbb{G}_1$. Our public keys will live in $\mathbb{G}_2$. We write the keypair $(sk, pk) = (sk, [sk]g_2)$.

Now to sign a message $m$, we compute $\sigma = [sk]H(m)$, and to verify the signature, we can check that $$e(\sigma, g_2) = e(H(m), pk)$$, since:

$$e(\sigma, g_2) = e([sk]H(m), g_2) = e(H(m), [sk]g_2) = e(H(m), pk)$$

by the bilinearity of the pairing.

#### Forgery ahead

The vulnerability in this challenge now comes from the choice of $H$:

$$H(m) = [SHA256(m)]g_1.$$

To see why this is a problem, we will show how transform a signature $\sigma$ for a message $m$ into a valid signature $\sigma'$ for an arbitrary message $m'$. Consider $\sigma = [sk][S]g_1 = [sk \cdot S]g_1$ where for convenience, we will write $S$ (resp. $S'$) to denote the SHA256 hash of $m$ (resp. $m'$). Similarly, we want to obtain the value $\sigma' = [sk][S']g_1 = [sk \cdot S']g_1$. Now it's fairly easy to see that, knowing both $S$ and $S'$, we can compute $\sigma' = \left[\frac{S'}{S}\right]\sigma$, where of course, the division is modular division $\mod \|g_1\|$.

Implementing it is equally as easy, when we use the same library as the challenge already used. One thing to pay attention to is not to forget to normalize the curve point of $\sigma'$ before sending it to the server, since we can only send the x and y coordinates of the projective representation.

```python
s1 = normalize(multiply(s0, (map_to_field(m1) * inverse(map_to_field(m0), curve_order)) % curve_order))
print(verify_signature(int(s1[0]).to_bytes(48, 'big').hex() + int(s1[1]).to_bytes(48,  'big').hex(), m1))
```

What was a bit confusing at this point, is that the local file tries to decode the signature as utf8 after it is validated, which will crash. When trying our signature on the server instead, however, we simply get the flag instead of this exception.

Flag: `CTF{How_did_you_get_here_and_where's_my_key!?}`


## Secret RNG (300pts)

> Our previous implementation was flawed!
> I don't want to use the crypto/rand generator, as it is probably not quantum resistant! Instead, I modified all the rngCooked values in the previous generator.
> There are so many values! It is impossible to retrieve them.

In this challenge, we're given the source code of a Golang application that uses the same one-time signature library as [before](https://blog.cryptohack.org/multisignatures-donjon-ctf-writeup#one-time-based-signature-100pts), but is now using a version of the Golang `math/rand` library where they replaced all the `rngCooked` array with their own values. We can get an arbitrary number of public keys, and if for any of those public keys we are able to sign the message `"Sign me if you can"`, we obtain the flag. If our attempted signature was incorrect, the server reveals the private key.
The seed used for the PRNG is based on the current time in nanosecond resolution, so we might have a bruteforce opportunity there.

#### PRNG(o)
Now let's have a look at what the default Golang PRNG is actually doing.

You can inspect the actual source code [here](https://github.com/golang/go/blob/master/src/math/rand/rng.go#L238), but for convenience, we will present it here in a simplified version, rewritten in python.

```python
import random

LEN = 607
TAP = 273
class Rng:
    def seed(self, s):
        # This is based on the rngCooked values that we don't know
        # So let's consider this as perfectly unknown and random for now
        self.vec = [random.getrandbits(64) for _ in range(LEN)]
        self.tap = 0
        self.feed = LEN - TAP

    def next(self):
        self.tap -= 1
        if self.tap < 0:
            self.tap = LEN - 1
        self.feed -= 1
        if self.feed < 0:
            self.feed = LEN - 1
        self.vec[self.feed] = (self.vec[self.feed] + self.vec[self.tap]) % (2**64)
        return self.vec[self.feed]
```

To summarize: there are two pointers (`feed` and `tap`) moving over `vec` in a circular fashion, at a fixed distance from each other. To obtain 64 bits of randomness, we take the value $\text{vec}[\text{feed}] \oplus \text{vec}[\text{tap}]$, which we then also store back into `vec[feed]`.
One other important thing to find in the Golang source code (the parts that are relevant to what the `wots` library uses, that is), is that of every 64 bits we obtain from our RNG, we only use [the lower 56 bits/7 bytes](https://github.com/golang/go/blob/master/src/math/rand/rand.go#L278). Observe that this doesn't impact us in any way since these unknown bits will only ever be XORed with other unknown bits.

This means that we can query enough keys to reconstruct the current value of `vec`, by each of the `vec[feed]` values that are present in the revealed private key. Once we have reconstructed the RNG state, it's only a matter of using it to construct the next private key, verify it matches the provided public key, sign the message and profit.

*Aside*: Given the length of `vec`, we need to recover 607 values, each 64 (or 56 in this case) bits to reconstruct the entire PRNG state. If we compare this to the classical weak PRNG, the MT19937 Mersenne Twister, we see that this amount to just a bit less than double the amount of bits we need there: 624 values of 32 bits each.

#### Imp(y)lementation

The code to reconstruct the PRNG state is presented here (courtesy of *esrever*):
```python
#!/usr/bin/python3
import socket

class Socket(socket.socket):
    def recvpred(self, pred):
        data = b''
        while not pred(data):
            try:
                buffer = self.recv(1)
                data += buffer
            except:
                print('\n'.join([
                    '[Error] In recvpred:',
                    '\texpected={}'.format(expected),
                    '\tpartial data={}'.format(data),
                ]))
                raise
        return data

    def recvuntil(self, expected):
        return self.recvpred(lambda s: expected in s)

    def recvn(self, n):
        return self.recvpred(lambda s: len(s) == n)

    def recvline(self):
        return self.recvuntil(b'\n')

    def sendafter(self, expected, msg):
        data = self.recvuntil(expected)
        self.sendall(msg)
        return data

    def interact(self):
        '''
        Use Telnet.interact().
        May break with non-printable characters, especially IAC (0xFF).

        Possible enhancement: adopt tube.interactive() in pwnlib.
        https://github.com/Gallopsled/pwntools/blob/dev/pwnlib/tubes/tube.py
        '''
        from telnetlib import Telnet

        def listener():
            '''
            Modified from Telnet.listener() so that it stops itself.
            '''
            from sys import stdout
            while not finished:
                try:
                    data = tn.read_eager()
                except EOFError:
                    print('*** Connection closed by remote host ***')
                    return
                if data:
                    stdout.write(data.decode('ascii'))
                else:
                    stdout.flush()

        print('*** Interact starts ***')
        finished = False
        tn = Telnet()
        tn.listener = listener
        tn.sock = self

        tn.interact()

        finished = True
        tn.sock = None
        print('*** Interact ends ***')

# ===== END OF TEMPLATE =====


import base64
import re


LEN = 607
TAP = 273
class Rng:
    def __init__(self):
        # Can't really know anything here without correlating different seeds
        self.vec = [0] * LEN
        self.tap = 0
        self.feed = LEN - TAP

        self.pos = 7
        self.val = 0

        self.set_count = 0

    def next(self):
        self.tap -= 1
        if self.tap < 0:
            self.tap = LEN - 1
        self.feed -= 1
        if self.feed < 0:
            self.feed = LEN - 1
        self.vec[self.feed] = (self.vec[self.feed] + self.vec[self.tap]) % (2**64)
        return self.vec[self.feed]

    def next_bytes(self, n):
        bs = bytearray(n)
        for i in range(n):
            if self.pos == 0:
                self.pos = 7
                self.val = self.next()
            bs[i] = self.val & 0xff
            self.val >>= 8
            self.pos -= 1
        return bytes(bs)

    def set_next(self, val):
        self.set_count += 1
        self.tap -= 1
        if self.tap < 0:
            self.tap = LEN - 1
        self.feed -= 1
        if self.feed < 0:
            self.feed = LEN - 1
        self.vec[self.feed] = val

    def set_next_bytes(self, bs):
        n = len(bs)
        for i in range(n):
            if self.pos == 0:
                self.pos = 7
                self.set_next(self.val)
                self.val = 0
            self.val = self.val | (bs[i] << (8 * (7 - self.pos)))
            self.pos -= 1

    def ready(self):
        return self.set_count >= LEN


def get_priv():
    line = conn.sendafter(b'Enter signature: ', b'\n')
    line = conn.recvline()
    priv_b64 = re.findall(r'You failed! Private key was: (.*)\n', line.decode())[0]
    priv = base64.b64decode(priv_b64)
    return priv


host = 'ots-sig.donjon-ctf.io'
port = 4001
conn = Socket()
conn.connect((host, port))

# Put your code here!
cnt = 0
rng = Rng()
while not rng.ready():
    rng.set_next_bytes(get_priv())
_ = rng.next_bytes(7)  # align feed

assert rng.next_bytes(1088) == get_priv()

print('next private key:', base64.b64encode(rng.next_bytes(1088)))
conn.interact()
```

To patch this together with the signing process, we copy-pasted the private key and signature between this code and the following quick-and-ugly go code.

```go
package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/dchest/wots"
	"math/rand" // The real one, not *really* used
)

func main() {
    var message = []byte("Sign me if you can")

    // Not *really* used, but too lazy to figure out how to generate
    // a new wots scheme without rng :)
    rng := rand.New(rand.NewSource(time.Now().UnixNano()))

    for {
        var ots = wots.NewScheme(sha256.New, rng)

        reader := bufio.NewReader(os.Stdin)
        fmt.Print("Enter privkey: ")
        text, err := reader.ReadString('\n')
        if err != nil {
            fmt.Println("Error occurred. Please try again later.")
	            return
        }

        text = strings.TrimSuffix(text, "\n")
        priv, err := base64.StdEncoding.DecodeString(text)
        if err != nil {
            return
        }

        sign, err := ots.Sign(priv, message);
        fmt.Print(base64.StdEncoding.EncodeToString(sign));
    }
}
```

All of this eventually coming together to grant us the flag: `CTF{m4th_RanD_1s_s0_pr3d1cT4bl3}`.

