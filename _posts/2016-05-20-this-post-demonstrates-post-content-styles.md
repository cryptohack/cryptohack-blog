---
layout: post
title: "ASIS Quals 2020"
categories: CTF Writeup
author:
- Jack4818
meta: "ASIS Quals 2020"
---

A handful of write ups from some of the crypto challenges from ASIS 2020 Quals. Thanks to Aurel, Hrpr and Hyperreality for the tips while solving these. Cr0wn came 16th overall, and I learnt that I really need to get to grips with multivariate polynomials because Tripolar was solved by a bunch of teams and I just couldn't crack it...


## Contents

| Challenge                         | Points |
| --------------------------------- | -----: |
| [Baby RSA](#baby-rsa)             |     60 |
| [Elliptic Curve](#elliptic-curve) |    125 |
| [Jazzy](#jazzy)                   |    122 |
| [Crazy](#crazy)                   |    154 |
| [Tripolar](#tripolar)             |    154 |



## Baby RSA

> All babies love [RSA](https://asisctf.com/tasks/baby_rsa_704000e3703726346fa621a91a9f8097a9307929.txz). How about you? 😂

#### Challenge

```python
#!/usr/bin/python

from Crypto.Util.number import *
import random
from flag import flag

nbit = 512
while True:
	p = getPrime(nbit)
	q = getPrime(nbit)
	e, n = 65537, p*q
	phi = (p-1)*(q-1)
	d = inverse(e, phi)
	r = random.randint(12, 19)
	if (d-1) % (1 << r) == 0:
		break

s, t = random.randint(1, min(p, q)), random.randint(1, min(p, q))
t_p = pow(s*p + 1, (d-1)/(1 << r), n)
t_q = pow(t*q + 4, (d-1)/(1 << r), n)

print 'n =', n
print 't_p =', t_p
print 't_q =', t_q
print 'enc =', pow(bytes_to_long(flag), e, n)
```



#### Solution

To solve this challenge, we use that for the RSA cryptosystem the public and private keys obey

$$
e\cdot d - 1 \equiv 0 \mod \phi(n), \qquad \Rightarrow  \qquad e\cdot d - 1 = k \cdot \phi(n), \quad k \in \mathbf{Z}
$$

and Euler's theorem, which states that

$$
\gcd(a,n) = 1 \qquad \Leftrightarrow \qquad a^{\phi(n)} \equiv 1\mod n
$$

We have the data $t_p, t_q, e, n$ which is suffient to solve for $p$. Using that

$$
t_p = (sp + 1)^{\frac{d-1}{2^r}}
$$

We can take `eth` power to find

$$
\begin{align}
t_p^e &= (sp + 1)^{\frac{ed-e}{2^r}} \mod n \\
&= (sp + 1)^{\frac{k\phi(n) + 1 -e}{2^r}} \mod n \\
&= (sp + 1)^{\frac{k\phi(n)}{2^r}} (sp + 1)^{\frac{1-e}{2^r}} \mod n
\end{align}
$$

From Euler's theorem we have

$$
(sp + 1)^{\frac{k\phi(n)}{2^r}} \equiv 1^{\frac{k}{2^r}} \equiv 1 \mod n
$$

The value of `r` is of small size `r = random.randint(12, 19)` and we also $e - 1 = 2^{16}$. We can understand $m = \frac{1-e}{2^r}$ as a power of two. The actual value of $m$ isn't needed, as we can simply expand out $t_p^e$ and write down

$$
\begin{align}
t_p^e - 1 = s p \cdot (s^{m-1} p^{m-1} + \ldots + m) \mod n \\
\end{align}
$$

We see that $N$ and $t_p^e$ share a common factor of $p$, and we can solve the challenge from

$$
\gcd(t_p^e - 1, n) = p
$$

**Note**: we can only treat $p$ as a true factor in the above line as $n = p\cdot q$,  so by nature of the CRT, this expression simplifies.

#### Implementation

```python
import math
from Crypto.Util.number import *

n = 10594734342063566757448883321293669290587889620265586736339477212834603215495912433611144868846006156969270740855007264519632640641698642134252272607634933572167074297087706060885814882562940246513589425206930711731882822983635474686630558630207534121750609979878270286275038737837128131581881266426871686835017263726047271960106044197708707310947840827099436585066447299264829120559315794262731576114771746189786467883424574016648249716997628251427198814515283524719060137118861718653529700994985114658591731819116128152893001811343820147174516271545881541496467750752863683867477159692651266291345654483269128390649
e = 65537
t_p = 4519048305944870673996667250268978888991017018344606790335970757895844518537213438462551754870798014432500599516098452334333141083371363892434537397146761661356351987492551545141544282333284496356154689853566589087098714992334239545021777497521910627396112225599188792518283722610007089616240235553136331948312118820778466109157166814076918897321333302212037091468294236737664634236652872694643742513694231865411343972158511561161110552791654692064067926570244885476257516034078495033460959374008589773105321047878659565315394819180209475120634087455397672140885519817817257776910144945634993354823069305663576529148
t_q = 4223555135826151977468024279774194480800715262404098289320039500346723919877497179817129350823600662852132753483649104908356177392498638581546631861434234853762982271617144142856310134474982641587194459504721444158968027785611189945247212188754878851655525470022211101581388965272172510931958506487803857506055606348311364630088719304677522811373637015860200879231944374131649311811899458517619132770984593620802230131001429508873143491237281184088018483168411150471501405713386021109286000921074215502701541654045498583231623256365217713761284163181132635382837375055449383413664576886036963978338681516186909796419
enc = 5548605244436176056181226780712792626658031554693210613227037883659685322461405771085980865371756818537836556724405699867834352918413810459894692455739712787293493925926704951363016528075548052788176859617001319579989667391737106534619373230550539705242471496840327096240228287029720859133747702679648464160040864448646353875953946451194177148020357408296263967558099653116183721335233575474288724063742809047676165474538954797346185329962114447585306058828989433687341976816521575673147671067412234404782485540629504019524293885245673723057009189296634321892220944915880530683285446919795527111871615036653620565630

p = math.gcd(n, pow(t_p, e, n) - 1)
q = n // p
phi = (p-1)*(q-1)
d = inverse(e, phi)
flag = pow(enc,d,n)
print(long_to_bytes(flag))
# b'ASIS{baby___RSA___f0r_W4rM_uP}'
```

#### Flag

`b'ASIS{baby___RSA___f0r_W4rM_uP}'`



## Elliptic Curve

### Challenge

> Are all elliptic curves smooth and projective?
>
> ```
> nc 76.74.178.201 9531
> ```

### Solution

The hard part of this challenge was dealing with boring bugs when sending data to the server while resolving the proof of work. One you connected to the server and passed the proof of work, we were given the prompt

```
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
+ hi! There are three integer points such that (x, y), (x+1, y), and +
+ (x+2, y) lies on the elliptic curve E. You are given one of them!! +
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
| One of such points is: P = (68363894779467582714652102427890913001389987838216664654831170787294073636806, 48221249755015813573951848125928690100802610633961853882377560135375755871325)
| Send the 37362287180362244417594168824436870719110262096489675495103813883375162938303 * P :
```

So the question is, given a single point $P$, together with the knowledge of the placement of three points, can we uniquely determine the curve?

If we assume the curve is over some finite field with prime characteristic, and that as standard this challenge uses a curve of Weierstrass form, we know we are looking for curves of the form

$$
y^2 = x^3 + Ax + B \mod p
$$

and from the knowledge of the three points we have

$$
x^3 + Ax + B = (x+ 1)^3 + A(x+1) + B = (x + 2)^3 + A(x + 2) + B \mod p
$$

We can then write down

$$
x^3 + Ax = (x+ 1)^3 + A(x+1), \quad \Rightarrow \quad A = -1 -3x - 3x^2
$$

and

$$
x^3 + Ax = (x+ 2)^3 + A(x+2), \quad \Rightarrow \quad A = -4 -6x - 3x^2
$$

as all three points are on the same curve, we have that

$$
3x^2 + 3x + 1 = 3x^2 +6x +4, \quad \Rightarrow \quad x = -1
$$

and from the above we have $x = -1 \Rightarrow A = -1$. The only thing left to do is to find $B$, which we can see is recovered from the general form of the curve.

$$
y^2 = (-1)^3 + (-1)^2 + B, \quad \Rightarrow \quad B = y^2
$$

Now we have recovered the inital point, we see that the triple of points we will be given is  $(-1, y)$, $(0, y)$ and $(1,y)$. The last two of these points would be trivial to spot and we can see this isn't what the server is sending us. We can then know for certain that the given point

```
(68363894779467582714652102427890913001389987838216664654831170787294073636806, 48221249755015813573951848125928690100802610633961853882377560135375755871325)
```

is the point $(x_0, y_0) = (-1, y)$ . We can now recover the characteristic from

$$
-1 \equiv x_0 \mod p, \quad \Rightarrow \quad p = x_0 + 1
$$

and we can quickly check that

```python
sage: x0 = 68363894779467582714652102427890913001389987838216664654831170787294073636806
sage: p = x0 + 1
sage: print(p.is_prime())
True
```

With everything now understood, we can take the point given by the server, together with the given scale factor, computer the scalar multiplication and send the new point back to the server

### Implmentation

```python
import os
os.environ["PWNLIB_NOTERM"] = "True"

import hashlib
import string
import random
from pwn import *

IP = "76.74.178.201"
PORT = 9531
r = remote(IP, PORT, level="debug")
POW = r.recvline().decode().split()
x_len = int(POW[-1])
suffix = POW[-5]
hash_type = POW[-7].split('(')[0]

"""
The server asks for a random length string, hashed with a random hash
function such that the last 3 bytes of the hash match a given prefix.
"""
while True:
	X = ''.join(random.choices(string.ascii_letters + string.digits, k=x_len))
	h = getattr(hashlib, hash_type)(X.encode()).hexdigest()
	if h.endswith(suffix):
		print(h)
		break

r.sendline(X)

header = r.recvuntil(b'One of such points')

points = r.recvline().split(b'P = (')[-1]
points = points.split(b', ')
px = Integer(points[0])
py = Integer(points[-1][:-2])

scale_data = r.recvline().split(b' ')
scale = Integer(scale_data[3])

p = px + 1
assert p.is_prime()
a = -1
b = (py^2 - px^3 - a*px) % p
E = EllipticCurve(GF(p), [a,b])
P = E(px,py)

Q = P*scale

"""
For some reason sending str(Q.xy()) to the server caused an error, so I
just switched to interactive and sent it myself. I'm sure it's a dumb
formatting bug, but with the annoying POW to deal with, I can't be bothered
to figure it out...
"""
# r.sendline(str(Q.xy()))
print(Q.xy())
r.interactive()
```

#### Flag

`ASIS{4n_Ellip71c_curve_iZ_A_pl4Ne_al9ebr4iC_cUrv3}`


## Jazzy

### Challenge

>Jazzy in the real world, but it's flashy and showy!

```
nc 76.74.178.201 31337
```

### Solution

Connecting to the server, we are given the following options:

```
------------------------------------------------------------------------
|          ..:: Jazzy semantically secure cryptosystem ::..            |
|           Try to break this cryptosystem and find the flag!          |
------------------------------------------------------------------------
| Options:                                                             |
|	[E]ncryption function                                          |
|	[F]lag (encrypted)!                                            |
|	[P]ublic key                                                   |
|	[D]ecryption oracle                                            |
|	[Q]uit                                                         |
|----------------------------------------------------------------------|
```

Calling `E` we are given the source of the encryption

```python
def encrypt(msg, pubkey):
	h = len(bin(len(bin(pubkey)[2:]))[2:]) - 1	# dirty log :/
	m = bytes_to_long(msg)
	if len(bin(m)[2:]) % h != 0:
		m = '0' * (h - len(bin(m)[2:]) % h) + bin(m)[2:]
	else:
		m = bin(m)[2:]
	t = len(m) // h
	M = [m[h*i:h*i+h] for i in range(t)]
	r = random.randint(1, pubkey)
	s_0 = pow(r, 2, pubkey)
	C = []
	for i in range(t):
		s_i = pow(s_0, 2, pubkey)
		k = bin(s_i)[2:][-h:]
		c = bin(int(M[i], 2) ^ int(k, 2))[2:].zfill(h)
		C.append(c)
		s_0 = s_i
	enc = int(''.join(C), 2)
	return (enc, pow(s_i, 2, pubkey))
```

I'll talk about this more later, but let's play with the server and see what it allows us to do first.



Sending the option `P` we get the `pubkey`

```
pubkey = 19386947523323881137657722758784550061106532690506305900249779841167576220076212135680639455022694670503210628255656646008011027142702455763327842867219209906085977668455830309111190774053501662218829125259002174637966634423791789251231110340244630214258655422173621444242489738175447333216354148711752466314530719614094724358835343148321688492410941279847726548532755612726470529315488889562870038948285553892644571111719902764495405902112917765163456381355663349414237105472911750206451801228088587783073435345892701332742065121188472147494459698861131293625595711112000070721340916959903684930522615446106875805793
```

Which for reasons below, I will now refer to as the modulus $n$. Sending the option `F`, we get the encryption of the flag, again with `pubkey` as a label, but from the encryption function, we know that this value is (or at least should be $s_{t+1} = s_t^2 \mod n$). Not sure why ASIS chose this confusing notation...

```
encrypt(flag, pubkey) = (513034390171324294434451277551689016606030017438707103869413492040051559571787250655384810990478248003042112532698503643742022419886333447600832984361864307529994477653561831340899157529404892382650382111633622198787716725365621822247147320745039924328861122790104611285962416151778910L, 1488429745298868766638479271207330114843847244232531062732057594917937561200978102167607190725732075771987314708915658110913826837267872416736589249787656499672811179741037216221767195188188763324278766203100220955272045310661887176873118511588238035347274102755393142846007358843931007832981307675991623888190387664964320071868166680149108371223039154927112978353227095505341351970335798938829053506618617396788719737045747877570660359923455754974907719535747353389095579477082285353626562184714935217407624849113205466008323762523449378494051510623802481835958533728111537252943447196357323856242125790983614239733L)
```

Lastly sending the option `D` we are given the prompt

```
| send an pair of integers, like (c, x), that you want to decrypt:
```

Being a wise guy, I tried sending the flag back to the server, but I was given the message

```
| this decryption is NOT allowed :P
```

Solving this challenge was easy after a bit of googling to try and see what this crypto system was. I noticed that the key stream was generated using a random number generator called [Blum Blum Shub](https://en.wikipedia.org/wiki/Blum_Blum_Shub). Looking for when this was used as a keystream, I stumbled upon the [Blum-Goldwasser Cryptosystem](https://en.wikipedia.org/wiki/Blum–Goldwasser_cryptosystem) and spending a little bit of time reading the Wikipedia page, I could tell that this was the right choice.

#### Adaptive chosen plaintext attack

Reading more closely, I spotted that the BG implementation is insecure against adaptive plaintext attacks when the attacker has access to a decryption oracle. This sounds great!!

The idea is that to decrypt some ciphertext $(\vec{c}, s)$, one can pick a generic ciphertext using the same seed $(\vec{a}, s)$ and then use the decryption oracle to find $m^\prime$. As the seed is the same, both $m^\prime$ and the flag $m$ have been encrypted with the same keystream and we can obtain the flag from $m = \vec{a} \oplus \vec{c} \oplus m^\prime$.

This sounds easy! Lets go back to the server and generate $m^\prime$:

```
| send an pair of integers, like (c, x), that you want to decrypt:
(513034390171324294434451277551689016606030017438707103869413492040051559571787250655384810990478248003042112532698503643742022419886333447600832984361864307529994477653561831340899157529404892382650382111633622198787716725365621822247147320745039924328861122790104611285962416151778910, 1488429745298868766638479271207330114843847244232531062732057594917937561200978102167607190725732075771987314708915658110913826837267872416736589249787656499672811179741037216221767195188188763324278766203100220955272045310661887176873118511588238035347274102755393142846007358843931007832981307675991623888190387664964320071868166680149108371223039154927112978353227095505341351970335798938829053506618617396788719737045747877570660359923455754974907719535747353389095579477082285353626562184714935217407624849113205466008323762523449378494051510623802481835958533728111537252943447196357323856242125790983614239733)
| this decryption is NOT allowed :P
```

Uh oh... it seems that the server checks the seed value and doesn't let us use this attack...

#### Just one more block

Okay, so if we can't use the same $s$ as the flag encryption, and we can't factor $n$ (waaaaaaay too big) what options do we have?

I dunno if this attack has a proper name, but I realised we could fool the server into decrypting the flag by adding a block to the end of the ciphertext. For every block that is encoded, the encryption protocol takes $s_i$ and calculates $s_{i+1} = s_i^2 \mod n$. As a result, if the ciphertext being decoded was exactly one block longer, then the seed value we would supply to the oracle wouldn't be $s$, but rather $s^2 \mod n$.

As we know `ct, s, n` we control enough data to solve the challenge, assuming that the server doesn't tell us off for sending $s^2 \mod n$...

So, this *should* bypass the seed check in the oracle and allow us to decrypt the flag. All we need to do is take the pair `(ct, s)` from the server, together with the modulus `n` , add `h` bits to the end of `ct` and square `s`. Sending this to the oracle will decrypt our ciphertext block by block, we can finally remove the last `h` bits (which will have decoded to garbage) and grab the flag.

To do this I wrote something quick and dirty

```python
n = 19386947523323881137657722758784550061106532690506305900249779841167576220076212135680639455022694670503210628255656646008011027142702455763327842867219209906085977668455830309111190774053501662218829125259002174637966634423791789251231110340244630214258655422173621444242489738175447333216354148711752466314530719614094724358835343148321688492410941279847726548532755612726470529315488889562870038948285553892644571111719902764495405902112917765163456381355663349414237105472911750206451801228088587783073435345892701332742065121188472147494459698861131293625595711112000070721340916959903684930522615446106875805793
h = len(bin(len(bin(n)[2:]))[2:]) - 1

flag_ct = 513034390171324294434451277551689016606030017438707103869413492040051559571787250655384810990478248003042112532698503643742022419886333447600832984361864307529994477653561831340899157529404892382650382111633622198787716725365621822247147320745039924328861122790104611285962416151778910
seed = 1488429745298868766638479271207330114843847244232531062732057594917937561200978102167607190725732075771987314708915658110913826837267872416736589249787656499672811179741037216221767195188188763324278766203100220955272045310661887176873118511588238035347274102755393142846007358843931007832981307675991623888190387664964320071868166680149108371223039154927112978353227095505341351970335798938829053506618617396788719737045747877570660359923455754974907719535747353389095579477082285353626562184714935217407624849113205466008323762523449378494051510623802481835958533728111537252943447196357323856242125790983614239733
seed_squared = pow(seed,2,n)
flag_extended = bin(flag_ct)[2:] + '1'*h
flag_extended = int(flag_extended, 2)

print(f"({flag_extended}, {seed_squared})")
```

Using the data collected above. Sending our slightly longer flag to the server gives us a decrypted message:

```
(1050694431070872155001756216425859106009149475714472148724558831698025594003020289342228092908499451910230246466966535462383661915927210900686505951973098101821428690234494630586161474620221219599667982564625658263117243853548793491962157712885841765025507579474134243913651028278843209727, 3216641374118298063210229377328115445643813442578456023987769065661762517695051834586452075939576983800791011462122765510295327568646398522659752628912802933208909111321539625480585977865621874640928715606628766855738533853630742505790835948213775188951805695531626048779789826277990208281243968206104294503971898862963118207505455918079294280929081526755227996190831742555093366364879064928874861060462753403017976763786404530509469825731935018035684983539175758425557263211403465858234005521025395515018046387350089113701767863479780051534190944394815574406100307489105693633714510667995574063150674428700480235811)
| the decrypted message is: 47771147116374265884489633343424974277884840496243413677482329815315049691915267634281287751924271959635398604756191897221446400520109091655450373658402419482516535670630080915290670126420548875478840451816545566711178369563850274167871301020132981380671014536902778264305709989256317962
```

Then we can simply grab the flag after chopping off 11 bits

```python
>>> from Crypto.Util.number import long_to_bytes
>>> flag_ext = 47771147116374265884489633343424974277884840496243413677482329815315049691915267634281287751924271959635398604756191897221446400520109091655450373658402419482516535670630080915290670126420548875478840451816545566711178369563850274167871301020132981380671014536902778264305709989256317962
>>> flag_bin = bin(flag_ext)[2:-11]
>>> flag_int = int(flag_bin, 2)
>>> flag = long_to_bytes(flag_int)
>>> print(flag)
b'((((......:::::: Great! the flag is: ASIS{BlUM_G0ldwaS53R_cryptOsySt3M_Iz_HI9hlY_vUlNEr4bl3_70_CCA!?} ::::::......))))'
```

No pwntools cracked out to do this one in a stylish way, but we still grab the flag!

#### Flag

`ASIS{BlUM_G0ldwaS53R_cryptOsySt3M_Iz_HI9hlY_vUlNEr4bl3_70_CCA!?}`

## Crazy

### Challenge

>Look at you kids with your vintage music
>
>Comin' through satellites while cruisin'
>
>You're part of the past, but now you're the future
>
>Signals crossing can get confusing
>
>It's enough just to make you feel crazy, crazy, crazy
>
>Sometimes, it's enough just to make you feel crazy

```python
#!/usr/bin/python

from Crypto.Util.number import *
from flag import flag
from secret import *

def encrypt(msg, pubkey, xorkey):
	h = len(bin(len(bin(pubkey)[2:]))[2:]) - 1	# dirty log :/
	m = bytes_to_long(msg)
	if len(bin(m)[2:]) % h != 0:
		m = '0' * (h - len(bin(m)[2:]) % h) + bin(m)[2:]
	else:
		m = bin(m)[2:]
	t = len(m) // h
	M = [m[h*i:h*i+h] for i in range(t)]
	r = random.randint(1, pubkey)
	s_0 = pow(r, 2, pubkey)
	C = []
	for i in range(t):
		s_i = pow(s_0, 2, pubkey)
		k = bin(s_i)[2:][-h:]
		c = bin(int(M[i], 2) ^ int(k, 2) & xorkey)[2:].zfill(h)
		C.append(c)
		s_0 = s_i
	enc = int(''.join(C), 2)
	return (enc, pow(s_i, 2, pubkey))

for keypair in KEYS:
	pubkey, privkey, xorkey = keypair
	enc = encrypt(flag, pubkey, xorkey)
	msg = decrypt(enc, privkey, xorkey)
	if msg == flag:
		print pubkey, enc
```

### Solution

After solving Jazzy there's not much to this challenge. We know that it is an implementation of Blum-Goldwasser (albeit with an additional xorkey). Blum-Goldwasser's security relies on the hardness of factoring $n = p\cdot q$ and so our best chance to solve this puzzle is to find the factors of the pubkey.

Looking at the challenge, we see we are given many many instances of the encryption. With all of these public keys, wouldn't it be a shame if some of them shared a factor?

Putting the data into an array, I checked for common factors using `gcd` in the following way:

```python
def find_factors(data):
	  data_length = len(data)
	  for i in range(data_length):
		  p = data[i][0]
		  for j in range(i+1,data_length):
		  	x = data[j][0]
		  	if math.gcd(p,x) != 1:
          			print(f'i = {i}')
        			print(f'j = {j}')
         			print(f'p = {math.gcd(p,x)}')
				return i, math.gcd(p,x)
```

Very quickly we get output:

```python
i = 0
j = 7
p = 114699564889863002119717546749303415014640174666510831598557661431094864991761656658454471662058404464073476167628817149960697375037558130201947795111687982132434309682025253703831106682712999472078751154844115223133651609962643428282001182462505433609132703623568072665114357116233526985586944694577610098899
```

and so with this, the whole encryption scheme is broken (ignoring the xorkey step of course).

With the factors of the pubkey, we can follow the dycryption algorithm on [Wikipedia](https://en.wikipedia.org/wiki/Blum–Goldwasser_cryptosystem#Decryption) to get

```python
def xgcd(a, b):
    """return (g, x, y) such that a*x + b*y = g = gcd(a, b)"""
    x0, x1, y0, y1 = 0, 1, 1, 0
    while a != 0:
        (q, a), b = divmod(b, a), a
        y0, y1 = y1, y0 - q * y1
        x0, x1 = x1, x0 - q * x1
    return b, x0, y0


def decrypt(c, pubkey, p, q, s):
	h = len(bin(len(bin(pubkey)[2:]))[2:]) - 1	# dirty log :/
	if len(bin(c)[2:]) % h != 0:
		c = '0' * (h - len(bin(c)[2:]) % h) + bin(c)[2:]
	else:
		c = bin(c)[2:]
	t = len(c) // h

	# Recover s0
	dp = (((p + 1) // 4)**(t + 1)) % (p - 1)
	dq = (((q + 1) // 4)**(t + 1)) % (q - 1)
	up = pow(s, dp, p)
	uq = pow(s, dq, q)
	_, rp, rq = xgcd(p,q)
	s_0 = (uq * rp * p + up * rq * q ) % pubkey

	C = [c[h*i:h*i+h] for i in range(t)]
	M = []
	for i in range(t):
		s_i = pow(s_0, 2, pubkey)
		k = bin(s_i)[2:][-h:]
		m = bin(int(C[i], 2) ^ int(k, 2))[2:].zfill(h)
		M.append(m)
		s_0 = s_i

	msg = long_to_bytes(int(''.join(M),2))
	return msg
```

With the crypto system all sorted out and checked against the encryption function (without the xorkey) we just need to find a way to do this last step. I started trying to think of a clever way to undo the xor with knowledge of several ct / msg pairs (many of the public keys share common factors) but then i realised that the block size is only 10 bits long and a brute force of `xorkey` would only mean guessing 1024 values.

So, i took the easy way and included a loop inside my decrypt trying all values for the `xorkey` and storing any decryptions that had the flag format: `ASIS{`. The script takes seconds and finds the flag.



### Implementation

```python
from Crypto.Util.number import *
import math

def find_factors(data):
	data_length = len(data)
	for i in range(data_length):
		p = data[i][0]
		for j in range(i+1,data_length):
			x = data[j][0]
			if math.gcd(p,x) != 1:
				return i, math.gcd(p,x)


def encrypt(msg, pubkey, xorkey):
	h = len(bin(len(bin(pubkey)[2:]))[2:]) - 1	# dirty log :/
	m = bytes_to_long(msg)
	if len(bin(m)[2:]) % h != 0:
		m = '0' * (h - len(bin(m)[2:]) % h) + bin(m)[2:]
	else:
		m = bin(m)[2:]
	t = len(m) // h
	M = [m[h*i:h*i+h] for i in range(t)]
	r = random.randint(1, pubkey)
	s_0 = pow(r, 2, pubkey)
	C = []
	for i in range(t):
		s_i = pow(s_0, 2, pubkey)
		k = bin(s_i)[2:][-h:]
		c = bin(int(M[i], 2) ^ int(k, 2) & xorkey)[2:].zfill(h)
		C.append(c)
		s_0 = s_i
	enc = int(''.join(C), 2)
	return (enc, pow(s_i, 2, pubkey))


def xgcd(a, b):
    """return (g, x, y) such that a*x + b*y = g = gcd(a, b)"""
    x0, x1, y0, y1 = 0, 1, 1, 0
    while a != 0:
        (q, a), b = divmod(b, a), a
        y0, y1 = y1, y0 - q * y1
        x0, x1 = x1, x0 - q * x1
    return b, x0, y0


def decrypt(c, pubkey, p, q, s):
	# Idiot checks
	assert p*q == pubkey
	assert isPrime(p) and isPrime(q)

	h = len(bin(len(bin(pubkey)[2:]))[2:]) - 1	# dirty log :/
	if len(bin(c)[2:]) % h != 0:
		c = '0' * (h - len(bin(c)[2:]) % h) + bin(c)[2:]
	else:
		c = bin(c)[2:]
	t = len(c) // h

	# Recover s0
	dp = (((p + 1) // 4)**(t + 1)) % (p - 1)
	dq = (((q + 1) // 4)**(t + 1)) % (q - 1)
	up = pow(s, dp, p)
	uq = pow(s, dq, q)
	_, rp, rq = xgcd(p,q)
	s0 = (uq * rp * p + up * rq * q ) % pubkey


	C = [c[h*i:h*i+h] for i in range(t)]

	# Brute xorkey (max size: 2**10 - 1)
	flags = []
	for X in range(1024):
		# Restore value for brute, and empty M
		s_0 = s0
		M = []

		for i in range(t):
			s_i = pow(s_0, 2, pubkey)
			k = bin(s_i)[2:][-h:]
			m = bin(int(C[i], 2) ^ int(k, 2) & X)[2:].zfill(h)
			M.append(m)
			s_0 = s_i

		fl = long_to_bytes(int(''.join(M),2))
		try:
			flag = fl.decode()
			if "ASIS{" in flag:
				flags.append(flag)
		except:
			pass
	return flags

# data from challenge.txt, truncated to only two values save space
data = [[12097881278174698631026228331130314850080947749821686944446636213641310652138488716240453597129801720504043924252478136044035819232933933717808745477909546176235871786148513645805314150829468800301698799525780070273753857243854268554322340900904051857831398492096742127894417784386491191471947863787022245824307084379225579368393254254088207494229400873467930160606087032014972366802086915193167585867760542665623158008113534159892785943512727008525032377162641992852773743617023163398493300810949683112862817889094615912113456275357250831609021007534115476194023075806921879501827098755262073621876526524581992383113, (238917053353586684315740899995117428310480789049456179039998548040503724437945996038505262855730406127564439624355248861040378761737917431951065125651177801663731449217955736133484999926924447066163260418501214626962823479203542542670429310307929651996028669399692119495087327652345, 2361624084930103837444679853087134813420441002241341446622609644025375866099233019653831282014136118204068405467230446591931324445417288447017795525046075282581037551835081365996994851977871855718435321568545719382569106432442084085157579504951352401314610314893848177952589894962335072249886688614676995039846245628481594015356555808852415257590789843672862086889766599032421071154614466932749223855909572291554620301269793104658552481172052104139007105875898227773975867750358642521359331140861015951930087364330158718293540721277710068251667789725792771210694545702423605041261814818477350926741922865054617709373)],[11618071445988286159614546200227554667389205281749443004629117264129957740203770615641847148204810865669191685874152730267573467338950993270113782537765608776375192263405546036787453939829561684834308717115775768421300006618296897365279937358126799904528083922552306565620644818855350306352024366076974759484150214528610355358152789696678410732699598714566977211903625075198935310947340456263339204820065134900427056843183640181066232714511087292771420839344635982165997540089604798288048766074061479118366637656581936395586923631199316711697776366024769039316868119838263452674798226118946060593631451490164411150841, (108436642448932709219121968294434475477600203743366957190466733100162456074942118592019300422638950272524217814290069806411298263273760197756252555274382639125596214182186934977255300451278487595744525177460939465622410473654789382565188319818335934171653755811872501026071194087051, 10240139028494174526454562399217609608280817984150287983207668274231906642607868694849967043415262875107269045985517134901896201464915880088854955991401353416951487254838341232922059441309704096261457984093029892511268213868493162068362288179130193503313930139616441614927005917140608739837772400963531761014330142192223670723732255263011157267423056439150678533763741625000032136535639171133174846473584929951274026212224887370702861958817381113058491861009468609746592170191042660753210307932264867242863839876056977399186229782377108228334204340285592604094505980554432810891123635608989340677684302928462277247999)]]

i, p = find_factors(data)
n = data[i][0]
c, s = data[i][1]
q = n // p

print(decrypt(c, n, p, q, s))
```

#### Flag

`ASIS{1N_h0nOr_oF__Lenore__C4r0l_Blum}`


## Tripolar

**Disclaimer** I didn't solve this challenge during the competition and it took me reading a [writeup](https://ctftime.org/writeup/22112) to understand how this challenge works. I'm writing it up to talk myself through the solution, and maybe someone else will read this and be surprised by the solution too.

After working through this, my take away is that my intuition for cube roots was way off! The key for solving this challenge is that given a polynomial of the form


$$
f(x, y, z) = x^3 + y^2 + z
$$


One can recover the value of $x$ from taking the cube root of $f(x,y,z)$.  Even after I read this, I couldn't believe there wasn't some loss of information of the LSB of $x$, but it seems like it holds, even for small positive integers

```python
>>> from Crypto.Util.number import *
>>> import gmpy2
>>> gmpy2.get_context().precision = 4096
>>> x, y, z = [getPrime(256) for _ in range(3)]
>>> f = x**3 + y**2 + z
>>> _x = gmpy2.iroot(f, 3)[0]
>>> x == _x
True
>>> x, y, z = [getPrime(5) for _ in range(3)]
>>> f = x**3 + y**2 + z
>>> _x = gmpy2.iroot(f, 3)[0]
>>> x == _x
True
```

The same is true for quadratic terms, by looking at the square root of $f - x^3$, but here there seems to be a bit less certainty and we find with small enough inputs, the square root approximation can be off by 1.

Anyway... with my display of ignorance out the way, lets look at the challenge!


### Challenge

```python
#!/usr/bin/python

from Crypto.Util.number import *
from hashlib import sha1
from flag import flag

def crow(x, y, z):
	return (x**3 + 3*(x + 2)*y**2 + y**3 + 3*(x + y + 1)*z**2 + z**3 + 6*x**2 + (3*x**2 + 12*x + 5)*y + (3*x**2 + 6*(x + 1)*y + 3*y**2 + 6*x + 2)*z + 11*x) // 6

def keygen(nbit):
	p, q, r = [getPrime(nbit) for _ in range(3)]
	pk = crow(p, q, r)
	return (p, q, r, pk)

def encrypt(msg, key):
	p, q, r, pk = key
	_msg = bytes_to_long(msg)
	assert _msg < p * q * r
	_hash = bytes_to_long(sha1(msg).digest())
	_enc = pow(_msg, 31337, p * q * r)
	return crow(_enc * pk, pk * _hash, _hash * _enc)

key = keygen(256)
enc = encrypt(flag, key)
f = open('flag.enc', 'w')
f.write(long_to_bytes(enc))
f.close()
```


Reading through the code, we see that the flag is encrypted RSA style using three primes $p,q,r$. The message is also hashed with `sha1` and the three primes used for encryption are fed into some fairly ugly polynomial named `crow` to produce another value `pk`.

The results of these computations are then all taken together, multiplied to and fed into the `crow` function again. The only output of the challenge is `enc`, which is the value of the second evaluation of the `crow` polynomial.

We then understand this challenge as learning how to find the integer solutions of `crow` so we can work backwards to finding the flag. Solving the first step will give us `_enc`, `_hash` and `pk` and solving `pk = crow(p,q,r)` we can grab the primes and reverse the encryption of `_enc`. But how to we solve `crow`?

During the competition I got toally sidetracked by the paper [A Strategy for Finding Roots of Multivariate Polynomials with New Applications in Attacking RSA Variants](http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.61.8061&rep=rep1&type=pdf) by Jochemsz and May, and decided the solution to this puzzle must be to implement the small integer roots algorithm that they give in 2.2 of the paper. This was hard to specialise to this polynomial and i failed. Potentially this method works, but I couldnt get it to. The closest I got was to notice that the bitsize of `_enc*pk` was larger than the other two elements of `crow` and so by taking the cube root, I could recover the MSB of `_enc*pk`. Typing this up now I see i was kind of close, but thinking totally wrong.

The real solution is much simplier and elegant and relies on the fact that we can find certain terms in the polynomial due to the various powers of certain terms (I've already explained this a little in the disclaimer). What we find is with a few steps of algebra and a resetting of my intuition of cube roots, this challenge has a nice solution.


### Solution

The first step to solving this challenge is simplifying the polynomial. I went down a rabbit hole of Legendre polynomials, taking the "dipole" hint way too seriously. Im not sure what the "Tripolar" hint was pointing towards... maybe some can enlighten me.

The crow polynomial is given to us in the form

$$
\begin{align}
C(x,y,x) &= \frac16 \big( x^3 + 3(x + 2)y^2 + y^3 + 3(x + y + 1)z^2 + z^3 + 6x^2\\
					&+ (3x^2 + 12x + 5)y + (3x^2 + 6(x + 1)y + 3y^2 + 6x + 2)z + 11x \big)
\end{align}
$$

This is a big mess, but we can notice that the coefficient for all cubic terms is $1$ (ignoring the overall factor of a sixth) and we can start to piece together simple parts of this expression until we obtain

$$
C(x,y,z) = \frac16 \left((x + y + z + 1 )^3 + 3(x + y + 1)^2 + 2(x + y + 1) - 6y - z - 6 \right)
$$

This is looking better, and by renaming a few pieces we get the polynomial into the form

$$
C(x,y,z) = \frac16 \left( f^3 + 3h^2 +2h -6y - z - 6 \right) \\
$$

Where we have defined

$$
f(x,y,z) = x + y + z + 1 \qquad h(x,y) = x + y + 1
$$


We now see how the disclaimer discussed above is going to help us. By taking the cube root of `enc`, we will recover the value for $f(x,y,z)$! Following this, we know that


$$
6 C - f^3 = 3h^2 + 2h - 6y - z - 6,
$$


and by the same approximation, the square root of the left hand side will be a good approximation for $h$. **Note** for the second time we solve `crow` with the smaller inputs of the three primes, we will find this approximation is off by one, which can be spotted by either making mistakes, or trying out this step with some known values of $p,q,r$.

With knowledge of both $f(x,y,z)$ and $h(x,y)$, we can recover the input values from the three expressions


$$
\begin{align}
z &= f - h \\
y &= -\frac16 \left( 6C - f^3 - 3h^2 - 2h + z + 6\right) \\
x &= h - y - 1
\end{align}
$$


With the triple $(x,y,z)$ from `crow` we can find the input parameters from the gcd of the inputs:

```python
import math

_enc = math.gcd(x,z)
pk = math.gcd(x,y)
_hash = math.gcd(y,z)
```

Solving `crow` from `pk` will give three primes $p,q,r$ and from that we can decrypt `_enc` from

```python
from Crypto.Util.number import *

N = p*q*r
phi = (p-1)*(q-1)*(r-1)
d = inverse(31337, phi)
m = pow(_enc, d, N)
print(long_to_bytes(m))
```



### Implementation


```python
import gmpy2
import math
from Crypto.Util.number import *
from hashlib import sha1
gmpy2.get_context().precision = 4096

def crow(x, y, z):
	return (x**3 + 3*(x + 2)*y**2 + y**3 + 3*(x + y + 1)*z**2 + z**3 + 6*x**2 + (3*x**2 + 12*x + 5)*y + (3*x**2 + 6*(x + 1)*y + 3*y**2 + 6*x + 2)*z + 11*x) // 6


def keygen(nbit):
	p, q, r = [getPrime(nbit) for _ in range(3)]
	pk = crow(p, q, r)
	return (p, q, r, pk)


def encrypt(msg, key):
	p, q, r, pk = key
	_msg = bytes_to_long(msg)
	assert _msg < p * q * r
	_hash = bytes_to_long(sha1(msg).digest())
	_enc = pow(_msg, 31337, p * q * r)
	return crow(_enc * pk, pk * _hash, _hash * _enc)


def alt_crow(x, y, z):
	return ((x + y + z + 1 )**3 + 3*(x + y + 1)**2 + 2*(x + y + 1) - 6*y - z - 6) // 6


def solve_crow(c, delta):
	"""
	Solve equation of the form:
	crow = [(x + y + z + 1 )**3 + 3*(x + y + 1)**2 + 2*(x + y + 1) - 6*y - z - 6] // 6
	     = [f^3 + 3h^3 + 2h - g] // 6
	f = x + y + z + 1
	h = x + y + 1
	g = 6y + z + 6
	"""
	f = gmpy2.iroot(6*c, 3)[0]
	h2 = (6*c - f**3) // 3
	"""
	For small values of inputs, the square root is off by one
	"""
	h = gmpy2.iroot(h2, 2)[0] + delta
	z = f - h
	y = -(6*c - f**3 - 3*h**2 - 2*h + z + 6) // 6
	x = h - y - 1
	assert crow(x, y, z) == c
	return x,y,z


def decrypt(ct):
	# Solve for arguments
	x, y, z = solve_crow(ct, 0)
	assert crow(x, y, z) == ct

	# Recover pieces
	_enc = math.gcd(x, z)
	pk = x // _enc
	_hash = z // _enc
	assert crow(_enc * pk, pk * _hash, _hash * _enc) == ct

	# Solve for primes
	p, q, r = solve_crow(pk, 1)
	assert crow(p, q, r) == pk

	# Solve encryption
	N = p*q*r
	phi = (p-1)*(q-1)*(r-1)
	d = inverse(31337, phi)
	m = pow(_enc, d, N)
	return long_to_bytes(m)

# Sanity test
p, q, r, pk = keygen(256)
# Check alt form is correct
assert alt_crow(p,q,r) == pk
# Check solver finds values
x, y, z = solve_crow(pk, 1)
assert x == p and y == q and z == r

ct = open('flag.enc', "rb").read()
ct = bytes_to_long(ct)
flag = decrypt(ct)
print(flag)
```


#### Flag

`ASIS{I7s__Fueter-PoLy4__c0nJ3c7UrE_iN_p4Ir1n9_FuNCT10n}`
