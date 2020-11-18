---
layout: post
title: "Fast Multisignatures and One Time-Based Signature Ledger Donjon CTF Writeup"
categories: CTF Writeup
permalink: multisignatures-donjon-ctf-writeup
author: josephsurin
meta: "Fast Multisignatures and One Time-Based Signature Ledger Donjon CTF Writeup"
---

These two challenges in the Crypto category of [Ledger Donjon CTF](https://donjon.ledger.com/Capture-the-Fortress/) involved exploiting vulnerable signature schemes. Writeup by [josephsurin](https://www.josephsurin.me/).

## Fast Multisignatures (100pts)

> Distributing trust in signatures is hard...

We are given a README file that describes how the multisignature scheme works, and a `client.py` Python script that shows how to interact with the server.

The purpose of a multisignature scheme is to allow a group of signers (each with their own private/public key pair) to produce one signature for some message. The signature can be verified using the public keys of all of the signers.

The scheme in the challenge is based on [Schnorr signatures](https://en.wikipedia.org/wiki/Schnorr_signature) and can be summarised as follows:

### Signing

Suppose there are $n$ signers, labelled $1$ to $n$ and they want to sign a message $m$. For each signer, their private key, $x_i$, is a large integer and their corresponding public key is $P_i = x_i P$ where $P$ is the base point of the elliptic curve `secp256k1`. Each signer generates a random nonce $r_i$.

The aggregated nonce is given by $R = \sum_{i=1}^n r_iP$.

Individual signatures are computed as $s_i = r_i - x_i H(R, m)$ (where $H$ is the scheme's hash function, given in the README).

The aggregate signature is given by $\sigma = \sum_{i=1}^n s_i$.

The output signature is $(R, \sigma)$.

### Verifying

The aggregated public key is given by $Q = \sum_{i=1}^n P_i$.

If $\sigma P = R + H(R, m)Q$ then the signature is verified.

Note that

$$
\begin{aligned}
    \sigma P &= \left (\sum_{i=1}^n r_i + \sum_{i=1}^n x_i H(R, m) \right ) P \\
             &= \sum_{i=1}^n r_i P + H(R, m) \sum_{i=1}^n x_i P \\
             &= R + H(R, m)Q
\end{aligned}
$$

### Forging Signatures

This scheme is vulnerable to an attack described in [this paper](https://eprint.iacr.org/2018/068.pdf). If the last signer (which is us in the context of the challenge) publishes her public key as $x_n P - \sum_{i=1}^{n-1} x_i P$, then the aggregated public key will be just $x_n P$.

It is easy to see that the rogue attacker can forge a signature for any message $m$. To do this, she lets $r_n$ be any integer and computes $R = r_n P$ (the aggregated nonce). Then, she computes $\sigma = r_n - x_n H(R, m)$ and publishes $(R, \sigma)$ as the signature. Since the aggregated public key is $Q = x_n P$, then

$$
\begin{aligned}
    \sigma P &= (r_n  - x_n H(R, m))P \\
             &= r_n P - H(R, m)x_n P  \\
             &= R - H(R, m) Q
\end{aligned}
$$

so the signature verifies.

```python
import ecdsa
from ecdsa.ellipticcurve import Point
import hashlib
import requests

def H(R, m):
    h = hashlib.sha256()
    h.update(int(R.x()).to_bytes(32, 'big'))
    h.update(int(R.y()).to_bytes(32, 'big'))
    h.update(m)
    return int.from_bytes(h.digest(), 'big')

C = ecdsa.SECP256k1
P = C.generator

agg_pubkey = (0x576b0844ccb7d0690c686540c1afc77750561f3738675f788e60586f9beb518e, 0x797854561cb2bab977d472a7e187163196f2da3002049c4c1a10f8c7a0ed1932)
agg_pubkey_point = Point(C.curve, *agg_pubkey)

msg = b'We lost. Dissolving group now.'
x = 1337
r = 123456789

pubkey = x*P
px, py = pubkey.x(), pubkey.y()

public_pubkey = pubkey + (-1)*agg_pubkey_point
Px, Py = public_pubkey.x(), public_pubkey.y()
fmt_pubkey = f'{Px:064x}{Py:064x}'

nonce = r*P
rx, ry = nonce.x(), nonce.y()
fmt_nonce = f'{rx:064x}{ry:064x}'

s = (r - H(nonce, msg)*x) % C.order
fmt_sig = f'{s:064x}'

url = 'http://multisig.donjon-ctf.io:6000'
cmd = dict()
cmd['public_nonce'] = fmt_nonce
cmd['public_key'] = fmt_pubkey
cmd['signature'] = fmt_sig
res = requests.post(url, json=cmd)
print(res.text)
```

Flag: `CTF{Multi_means_several_right?}`

## One Time-Based Signature (100pts)

> We used a quantum-resistant signature algorithm. Will you be able to break it? Show us you can sign a message without knowing our private key!

We are given the source code of a Go program running on the server which uses [this implementation](https://github.com/dchest/wots) of the Winternitz one-time signature scheme. The server sends us its public key and challenges us to sign a specific message.

The randomness used to generate the private key is seeded by the current time, so we can easily bruteforce the seed. We can check if we've got the correct seed by checking if the generated public key is the same as the one given by the server. Once we've recovered the seed (and therefore the private key), all we need to do is sign the message and send it to the server:

```go
package main

import (
    "bufio"
    "crypto/sha256"
    "encoding/base64"
    "fmt"
    "math/rand"
    "strings"
    "time"
    "net"

    "github.com/dchest/wots"
)

func readline(reader *bufio.Reader) string {
    line, _ := reader.ReadString('\n')
    return strings.Trim(line, "\n")
}

func main() {
    message := []byte("Sign me if you can")

    curr_time := time.Now().UnixNano()/1e6
    conn, _ := net.Dial("tcp", "ots-sig.donjon-ctf.io:4000")
    reader := bufio.NewReader(conn)

    target_pubkey := strings.Split(readline(reader), "key: ")[1]

    for {
        wotssha256 := wots.NewScheme(sha256.New, rand.New(rand.NewSource(curr_time)))
        priv, pub, _ := wotssha256.GenerateKeyPair()
        P := base64.StdEncoding.EncodeToString(pub)
        if P == target_pubkey {
            signature, _ := wotssha256.Sign(priv, message)
            b := make([]byte, base64.StdEncoding.EncodedLen(len(signature)))
            base64.StdEncoding.Encode(b, signature)
            conn.Write(append(b, '\n'))
            fmt.Println(readline(reader))
            break
        }
        curr_time++
    }
}
```

Flag: `CTF{e4sY_brUt3f0Rc3}`



