---
layout: post
title: "Partial Redaction is not Redaction"
categories: Twitter CTF-Challenge
permalink: twitter-secrets
author:
- CryptoHackers
meta: "PEM"
tags: Twiter RSA PEM
excerpt_separator: <!--more-->
---

The [@CryptoHack__](https://twitter.com/cryptohack__) account was pinged today by ENOENT, with a CTF-like challenge found in the wild: [Source tweet](https://twitter.com/ENOENT_/status/1374679885101285376?s=20). Here's a write-up covering how given a partially redacted PEM, the whole private key can be recovered.
<!--more-->
The Twitter user, SAXX, shared a partially redacted private RSA key in a tweet about a penetration test where they had recovered a private key. Precisely, a screenshot of a PEM was shared online with 31 of 51 total lines of the file redacted.

As ENOENT correctly identified, the redaction they had offered wasn't sufficient, and from the shared screenshot, it was possible to totally recover the private key.

This was done as a bit of fun within the CryptoHack discord, but the take away should be:

**Do not share private information online. Partial redaction is not safe.**

Whether this image was shared for a CTF challenge, or because SAXX didn't realise how dangerous infomation leakage like this could be, this PEM is called private for a reason. Don't let people find yours with Google, and don't share snippets of them online!

## Timeline (GMT+0)

**11:09** - _jack_ shared the Tweet on CH discord -- [Discord message](https://discord.com/channels/692694094111309866/695239931790098434/824239899682930699) <br>

### Transcription

**12:02** - _Zeecka_ OCR completed (with some typos) -- [Discord message](https://discord.com/channels/692694094111309866/695239931790098434/824251721089810452)<br>
**12:15** - _\$in_ identified the parameters -- [Discord message](https://discord.com/channels/692694094111309866/695239931790098434/824255162889404436)

### Solving

**12:46** - _Drago_1729_ recovered $q$ by hand with $e=65537$ -- [Discord message](https://discord.com/channels/692694094111309866/695239931790098434/824262983223083058)<br>
**13:50** - _Mystiz_ proposed that it is $q$ and $dp$ instead of $dp$ and $dq$ we have in full -- [Discord message](https://discord.com/channels/692694094111309866/695239931790098434/824279036099559495)<br>
**13:58** - _joachim_ recovered the modulus $n$ -- [Discord message](https://discord.com/channels/692694094111309866/695239931790098434/824281068566872195)

## OCR

From ENOENT's tweet, the question was: given a partially redacted private key, could the full key be derived? To answer this question, the first step was to obtain the key, which meant transcribing it from the screenshot.

![Challenge image](https://pbs.twimg.com/media/ExPF9EnXIAEY8QU?format=png)

_Zeecka_ used OCR with manual tweaks to obtain an almost perfect transcription (typos would be spotted later when analysing the details). The transcription was found to be

```
-----BEGIN RSA PRIVATE KEY-----
MIIJKAIBAAKCAgEApRVJnlLaLVO7zNZPbqw4xYZtZpxPpQs3Io3JauefRg+UP5ye
INAZOwhZV7vmo0uidzItwjPXVNlRToWQ1Vzp72OxJ9FSWcBsxwWx9AhkBGyNtGYC
i3UDlfx9ut3vXIiZN1v3lk6KIOEwJmFNiVh5OyMpny44DUYYsjDUiiw1cJKWagn0
PGpEANxZMqGOBeR7uWI0iLtA4WqQG88wwzz08nW5V326Xh8Xn/oIASyV8JjRCPRb
3uBL6KE2q28lqBwk8k8l+HDhZptqOz5h41CmUpl3aiaDXJypLoG70LoHq7yy/jd3
9E3R9j1dze3p0991S4Yp1+deT8EH9CusR1uVZ7i4npUT691xWtL6W5IvYDIGzeUS
[                           Snipped!                           ]
[                           Snipped!                           ]
[                           Snipped!                           ]
[                           Snipped!                           ]
[                           Snipped!                           ]
[                           Snipped!                           ]
[                           Snipped!                           ]
[                           Snipped!                           ]
[                           Snipped!                           ]
[                           Snipped!                           ]
[                           Snipped!                           ]
[                           Snipped!                           ]
[                           Snipped!                           ]
[                           Snipped!                           ]
[                           Snipped!                           ]
[                           Snipped!                           ]
[                           Snipped!                           ]
[                           Snipped!                           ]
[                           Snipped!                           ]
[                           Snipped!                           ]
[                           Snipped!                           ]
d7bLAtXyoK6i+QKCAQEAwohx6HFAkOCjMye4isxX7vLrYDOsa8RPMbrqwzy8Amw+
i76eD3fI28C0v+0Cc/ZiHSS8Hv/AtsBkJ7iXWPbUM6Ar+ZbULh4nUHOKw7hbShh6
O8tBJNYilssO7KpbcPuEoSJUsJc3l6HlOCnsWfIiOOq3eyEWZPwvpoaJPdpDdWyJ
WVPlc/1Sqpu0HSIwYTXIEXSgAbMvVAfU9y2Axd4oUFQd5dVcGcH4F+6plN+lNLbZ
QbogSzBiJangbdsEj040UHVA+z8D7+swvdB2z6IrE1yQN8nhj+T6cM9hzqjAAunI
XlPB6qyTUELQBpcnDwW4p5doRpY8kz2t1ScifmxF4QKCAQEAh498G5sZsWk8E3Ew
XxlM0Ix3DI9ZdrLY4892mhEXCA1ukKEK752m61s0IZtx9MjlzeOp02lFrFB+5t/k
wUbnRY74P6Bl4wNuX78VWX6Xp7qToxEk2XwXfmjjitxMRYWEF6v4A0dF1rN4Khle
bdPPC+FPXZckeQDpqsOytaifM6P49x0n1nBAHKGF65yIZEt5heTZin2je//9tzfl
S24N4gBNDIxCX7FjgEMdfeQFQMAjRsmJkbdI67yKrHPdWN5vf/AKMC9ARwILbNkJ
j2umhplPXgQ+cYHt/FUuGLzkKzpCtj98y3cpt052oEAFXTlyeMuTkkDyNtCip5dX
unqfCQKCAQB9VtCdxaqmLja41RTwSS03Bkll2KV1Yizsi9SLKuywWvIJtC2/JZzD
[                           Snipped!                           ]
[                           Snipped!                           ]
[                           Snipped!                           ]
[                           Snipped!                           ]
[                           Snipped!                           ]
[                           Snipped!                           ]
[                           Snipped!                           ]
[                           Snipped!                           ]
[                           Snipped!                           ]
[                           Snipped!                           ]
-----END RSA PRIVATE KEY-----
```

Ironically, this was the hardest part of the challenge. It took the longest time of all the steps and was the easiest to make errors in.

From the size of the image, this seemed to fit with a 4096 bit RSA private key, which when new keys were generated also had 51 lines.

## Guessing which part of RSA is revealed

The private key is encoded in PEM (Privacy-Enhanced Mail) and the below parameters are encoded in order: $n$, $e$, $d$, $p$, $q$, $d\mod (p-1)$, $d\mod (q-1)$ and $q^{-1}\mod p$.

```
PrivateKeyInfo ::= SEQUENCE {
   version Version,
   privateKeyAlgorithm AlgorithmIdentifier {{PrivateKeyAlgorithms}},
   privateKey PrivateKey,
   attributes [0] Attributes OPTIONAL
}

RSAPrivateKey ::= SEQUENCE {
  version           Version,
  modulus           INTEGER,  -- n
  publicExponent    INTEGER,  -- e
  privateExponent   INTEGER,  -- d
  prime1            INTEGER,  -- p
  prime2            INTEGER,  -- q
  exponent1         INTEGER,  -- d mod (p-1)
  exponent2         INTEGER,  -- d mod (q-1)
  coefficient       INTEGER,  -- (inverse of q) mod p
  otherPrimeInfos   OtherPrimeInfos OPTIONAL
}
```

PEM encoding is actually the DER format base64 encoded and wrapped into header and footer. They are different encodings of the ASN.1 used to structure key files.

By first decoding the base64 data we have, we can visualize the raw data and try to understand the whole structure.


To understand what the windows of the PEM key related to, _Mystiz_ generated a dummy code and looked at where the data headers were. This allowed us to go through the known ordering and have a good idea of what data we could extract.

| Recovered PEM                        | Dummy PEM                            |
| ------------------------------------ | ------------------------------------ |
| ![](https://i.imgur.com/BuG8zNA.png) | ![](https://i.imgur.com/es6dshf.png) |

Here the ASN.1 header for the integers values are `02 82 01 01`, which is decomposed as follow:

- `02` for the data type, here Integer.
- `82` meaning that the length of the integer value will be encoded in the 2 following bytes.
- `0101`, the actual length, which integer value is 257, meaning that the integer value will be encoded in the following 257 bytes. Retrieving the 257 next bytes in Big Endian and taking their integer values yield the rsa values we are looking for.


Comparing these headers with the ordering of data given above, we determine that the exposed data relates to:

- The last bits of the prime `p`
- All of the the prime `q`
- All of `dp = d % (p-1)`
- The first bits of `dq = d % (p-1)`

Additionally, we have the first ~2000 bits of the public modulus (not shown in the screenshot).

**This is more than enough to fully recover the private key!**

## Decoding the PEM

From the above analysis, the partial PEM can be decoded and we find:

```python
N_upper_bits = 0xa515499e52da2d53bbccd64f6eac38c5866d669c4fa50b37228dc96ae79f460f943f9c9e20d0193b085957bbe6a34ba277322dc233d754d9514e8590d55ce9ef63b127d15259c06cc705b1f40864046c8db466028b750395fc7dbaddef5c8899375bf7964e8a20e13026614d8958793b23299f2e380d4618b230d48a2c357092966a09f43c6a4400dc5932a18e05e47bb9623488bb40e16a901bcf30c33cf4f275b9577dba5e1f179ffa08012c95f098d108f45bdee04be8a136ab6f25a81c24f24f25f870e1669b6a3b3e61e350a65299776a26835c9ca92e81bbd0ba07abbcb2fe3777f44dd1f63d5dcdede9d3df754b8629d7e75e4fc107f42bac475b9567b8b89e9513ebdd715ad2fa5b922f603206cde512
p_lower_bits = 0x77b6cb02d5f2a0aea2f9
q = 0xc28871e8714090e0a33327b88acc57eef2eb6033ac6bc44f31baeac33cbc026c3e8bbe9e0f77c8dbc0b4bfed0273f6621d24bc1effc0b6c06427b89758f6d433a02bf996d42e1e2750738ac3b85b4a187a3bcb4124d62296cb0eecaa5b70fb84a12254b0973797a1e53829ec59f22238eab77b211664fc2fa686893dda43756c895953e573fd52aa9bb41d22306135c81174a001b32f5407d4f72d80c5de2850541de5d55c19c1f817eea994dfa534b6d941ba204b306225a9e06ddb048f4e34507540fb3f03efeb30bdd076cfa22b135c9037c9e18fe4fa70cf61cea8c002e9c85e53c1eaac935042d00697270f05b8a7976846963c933dadd527227e6c45e1
dp = 0x878f7c1b9b19b1693c1371305f194cd08c770c8f5976b2d8e3cf769a1117080d6e90a10aef9da6eb5b34219b71f4c8e5cde3a9d36945ac507ee6dfe4c146e7458ef83fa065e3036e5fbf15597e97a7ba93a31124d97c177e68e38adc4c45858417abf8034745d6b3782a195e6dd3cf0be14f5d97247900e9aac3b2b5a89f33a3f8f71d27d670401ca185eb9c88644b7985e4d98a7da37bfffdb737e54b6e0de2004d0c8c425fb16380431d7de40540c02346c98991b748ebbc8aac73dd58de6f7ff00a302f4047020b6cd9098f6ba686994f5e043e7181edfc552e18bce42b3a42b63f7ccb7729b74e76a040055d397278cb939240f236d0a2a79757ba7a9f09
dq_upper_bits = 0x7d56d09dc5aaa62e36b8d514f0492d37064965d8a575622cec8bd48b2aecb05af209b42dbf259cc3
```

We see from the PEM we have one of the prime factors, a few bits of the other prime factor, about half of the public modulus and

$$
dp = d \pmod{p -1}
$$

Given this, we can recover $p$ with a quick brute search in the following way.

## Looking for p

> well, it's not too hard: `e*dp = kp * (p - 1) + 1` by definition <br>
> we just brute force `kp` <br>
> ~ joachim <br>

We know that:

$$
e*d = 1 \pmod \phi \qquad  \Rightarrow \qquad
e*dp = 1 \pmod {p-1}.
$$

Guessing that `e = 65537` (although we could iterate through to check all `e` if needed) we can recover `p` in the following way:

$$
e*dp = 1 + k_p (p - 1)
$$

for some integer $k_p$. As $e$ is fairly small, so will $k_p$. We can rearrange the above for:

$$
p = \frac{e*dp - 1}{k_p} + 1
$$

with the only unknown being $k_p$. Using python, we find a potential prime very quickly:

```python
e = 65537
q = 0xc28871e8714090e0a33327b88acc57eef2eb6033ac6bc44f31baeac33cbc026c3e8bbe9e0f77c8dbc0b4bfed0273f6621d24bc1effc0b6c06427b89758f6d433a02bf996d42e1e2750738ac3b85b4a187a3bcb4124d62296cb0eecaa5b70fb84a12254b0973797a1e53829ec59f22238eab77b211664fc2fa686893dda43756c895953e573fd52aa9bb41d22306135c81174a001b32f5407d4f72d80c5de2850541de5d55c19c1f817eea994dfa534b6d941ba204b306225a9e06ddb048f4e34507540fb3f03efeb30bdd076cfa22b135c9037c9e18fe4fa70cf61cea8c002e9c85e53c1eaac935042d00697270f05b8a7976846963c933dadd527227e6c45e1
dp = 0x878f7c1b9b19b1693c1371305f194cd08c770c8f5976b2d8e3cf769a1117080d6e90a10aef9da6eb5b34219b71f4c8e5cde3a9d36945ac507ee6dfe4c146e7458ef83fa065e3036e5fbf15597e97a7ba93a31124d97c177e68e38adc4c45858417abf8034745d6b3782a195e6dd3cf0be14f5d97247900e9aac3b2b5a89f33a3f8f71d27d670401ca185eb9c88644b7985e4d98a7da37bfffdb737e54b6e0de2004d0c8c425fb16380431d7de40540c02346c98991b748ebbc8aac73dd58de6f7ff00a302f4047020b6cd9098f6ba686994f5e043e7181edfc552e18bce42b3a42b63f7ccb7729b74e76a040055d397278cb939240f236d0a2a79757ba7a9f09

for kp in range(3, e):
    p_mul = dp * e - 1
    if p_mul % kp == 0:
        p = (p_mul // kp) + 1
        if isPrime(p):
            print(f"Possible p: {p}")

# Possible p: 27424620168275816399297809452044477898445869043083928305403190561848181247448557658593857562389973580360112343197758188112451321934751365149355739718827334237004580631677805658180827450425037486862624956571004133160660553447844660253489608830574578247130997606552780186884875956837105323963951273120671578260037968554324775219655391384842262185092080897722729583541520288238199378137937292821948537290086006515948412691425793388343550817692412524057095996025193588558531233775036475712447358021159753894894021532314644572789928387689536798350947404591354707156502434749956591501101436381621117178639848984726819742457
```

## Confirming primes

Taking the derived primes, we can compute the modulus and confirm the upper bits of `N` match those from the recovered `N_upper_bits`

```python
N_upper_bits = 30457427562244323579995437754324534042018777613280180532197676197118773628723461730749173890412017170754986992178083905899989046914120484395653402018748091340601512280164459651105248203554437109452956905174469553583658956325738170447166511238136068903957328423268890614035002257855819844002763618901877232360449508033171964723850088618508402484321650636524135174864151909497499848927402074808738379325859558320263545273590421575782466275984910813150564483189339584572087724451857125236851614481208797282465329307679185127704976887027977667331795205260510366606766510658771276256076154115655874640089815969499349881297639470105972704299290754862459964952937451349266

p = 27424620168275816399297809452044477898445869043083928305403190561848181247448557658593857562389973580360112343197758188112451321934751365149355739718827334237004580631677805658180827450425037486862624956571004133160660553447844660253489608830574578247130997606552780186884875956837105323963951273120671578260037968554324775219655391384842262185092080897722729583541520288238199378137937292821948537290086006515948412691425793388343550817692412524057095996025193588558531233775036475712447358021159753894894021532314644572789928387689536798350947404591354707156502434749956591501101436381621117178639848984726819742457
q = 24557514677450020709963903681375364460820310266225384291801637341521595342666253205336845264757421255260600704049154546684780792118829382331570439401486399561491019552699939934010000272140266285812605412789634489018971904144689626714670157946287893352873566395341167986917862250727568353619706271981868858422563892161248368282001614623019718319955556301526416891588398000135343850148192339727753574805943013572453864284921278971901324211911400447669171516029983339292676625790107076548171060714108275954116817388931089212370784359178408782912113219892536791605458546076478558167775258954035994791211659035962325616097
N = p*q

assert hex(N).startswith(hex(N_upper_bits))
```

We see that the primes we found share the same upper bits as the revealed public modulus.

## Solution

Putting this all together, we can check all parameters behave as we expect them to

```python
from Crypto.Util.number import isPrime

# Data recovered from the redacted PEM
N_upper_bits = 30457427562244323579995437754324534042018777613280180532197676197118773628723461730749173890412017170754986992178083905899989046914120484395653402018748091471325800581059219147254282405451408833890008151641508599927170303197870017651603982363161977846481534314039335805832251681230043116365831643123937810888714099430787872874844412743459707657688891322959172991748764808819027728030102198424238026738647991640843466422153686070659179149234970752534637975655271174952598523649705880170583334087935944873931196059355239581556699146426727615685871650650038514279491416779855152128644712117727535638228142315728117649806977113579344429317148886889408318502441937921298
e = 65537 # assumption
p_lower_bits = 0x77b6cb02d5f2a0aea2f9
q = 0xc28871e8714090e0a33327b88acc57eef2eb6033ac6bc44f31baeac33cbc026c3e8bbe9e0f77c8dbc0b4bfed0273f6621d24bc1effc0b6c06427b89758f6d433a02bf996d42e1e2750738ac3b85b4a187a3bcb4124d62296cb0eecaa5b70fb84a12254b0973797a1e53829ec59f22238eab77b211664fc2fa686893dda43756c895953e573fd52aa9bb41d22306135c81174a001b32f5407d4f72d80c5de2850541de5d55c19c1f817eea994dfa534b6d941ba204b306225a9e06ddb048f4e34507540fb3f03efeb30bdd076cfa22b135c9037c9e18fe4fa70cf61cea8c002e9c85e53c1eaac935042d00697270f05b8a7976846963c933dadd527227e6c45e1
dp = 0x878f7c1b9b19b1693c1371305f194cd08c770c8f5976b2d8e3cf769a1117080d6e90a10aef9da6eb5b34219b71f4c8e5cde3a9d36945ac507ee6dfe4c146e7458ef83fa065e3036e5fbf15597e97a7ba93a31124d97c177e68e38adc4c45858417abf8034745d6b3782a195e6dd3cf0be14f5d97247900e9aac3b2b5a89f33a3f8f71d27d670401ca185eb9c88644b7985e4d98a7da37bfffdb737e54b6e0de2004d0c8c425fb16380431d7de40540c02346c98991b748ebbc8aac73dd58de6f7ff00a302f4047020b6cd9098f6ba686994f5e043e7181edfc552e18bce42b3a42b63f7ccb7729b74e76a040055d397278cb939240f236d0a2a79757ba7a9f09
dq_upper_bits = 1045791941318134345061297955329583824686635584654238166561681444681117346937661337003083367292099

# derived info
N = 0xa515499e52da2d53bbccd64f6eac38c5866d669c4fa50b37228dc96ae79f460f943f9c9e20d0193b085957bbe6a34ba277322dc233d754d9514e8590d55ce9ef63b127d15259c06cc705b1f40864046c8db466028b750395fc7dbaddef5c8899375bf7964e8a20e13026614d8958793b23299f2e380d4618b230d48a2c357092966a09f43c6a4400dc5932a18e05e47bb9623488bb40e16a901bcf30c33cf4f275b9577dba5e1f179ffa08012c95f098d108f45bdee04be8a136ab6f25a81c24f24f25f870e1669b6a3b3e61e350a65299776a26835c9ca92e81bbd0ba07abbcb2fe3777f44dd1f63d5dcdede9d3df754b8629d7e75e4fc107f42bac475b9567b8b89e9513ebdd715ad2fa5b922f603206cde512918fed2e16518cdb2f561faab195867198f4c7cd1aec3e847e010a4f0366bddbdeed9cfaf970914e98bfab41bade40972ffa13a7ad1de473acf1bbaba9c79f2827de2221b990750025082452e4a180bf2f35261519a16dffb0dbd57e39f914e62936838470924aaf2135d39e7cb938976a6781ba0c2a8e57550853a1befd7f58e5fc2e66b15821ae48caa539d64ad56080c894dbe7b93006727e94f5461fbb68853e30c270fcc2d40864a48622cae9259976be9aa1d815152f8902fda533830312fa589aebde7ae44b4fc647fe7b76c470acc701f26f72a7639d4c52f29ee13af8436d58aeccc1839a7659d9
p = 0xd93eadbb861d5cbf29a399492c96635b5258cf51a9366b67c6692b62791c8f07a5b1cf9ba5159b3be0859791b27dae060a1cdb44658afc9a16f1e9f33fe49c269341ea21c021e97c45f85b72e02ce928b11dc88c8a199bf82a3aadd65db2936810fa31efe1e8c35170dec359ce65d45dc6aab3969211f984d70cbf89953932db56e03b499ba76013a431fc85b65364dd7c2b0a2e47e390ab886e28ee3fb5a3e4450752bbb42119de04d6269ae48b79e5586a32d86d20e6626d86c05565926ff144362c9c14e93bf746bfc50be72b0c9a51a11b929448a482053d981c102e6ca66d1d24285b851cc47017074bffdb88e252bb4978c6b177b6cb02d5f2a0aea2f9
phi = (p-1)*(q-1)
d = pow(e,-1,phi)

# We have found the two prime factors of the modulus
assert isPrime(p) and isPrime(q) and p*q == N

# Our private exponent matches that from dp recovered
assert d % (p-1) == dp

# The top bits of the Modulus match those recovered
assert hex(N).startswith(hex(N_upper_bits))

# The prime p matches the low bits
assert hex(p).endsswith(hex(p_lower_bits)[2:])

# The derived dq matches the recovered upper bits of dq
assert hex(d % (q-1)).startswith(hex(dq_upper_bits))
```

## Recovered PEM

With all our parameters recovered, the last step for total recovery means reconstructing the PEM

```python
from Crypto.PublicKey import RSA

key = RSA.construct((N,e,d,p,q))
pem = key.export_key('PEM')
print(pem.decode())
```

Which is found to be

```
-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----
```

Checking with a diff:

![](https://i.imgur.com/vBzZQoH.png)

## Conclusions

Whether it's a single bit leaking with Ladder Leak, or pieces of primes for a Coppersmith attack, partial infomation exposure of cryptographic private keys is often enough to totally break the crypto protocol.

If you find something private, keep it that way.
