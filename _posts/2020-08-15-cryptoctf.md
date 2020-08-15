---
layout: post
title: "CryptoCTF 2020"
categories: CTF Writeup
permalink: cryptoctf2020
author:
- CryptoHackers
meta: "CryptoCTF 2020"
---

Here are our challenge writeups from the CryptoCTF 2020 competition. Members of the CryptoHack community played under the team "CryptoHackers" and came second overall, solving 18 of the 20 challenges during the 24 hour competition. This was the first time we all played a CTF together, and we will definitely be doing it again in the future. It was truly a pleasure to get so many cryptographic brains together in one chatroom and collaborate on cracking some mindbending puzzles.

![CTF Scoreboard](/assets/images/cryptoctf2020.png)

Thank you to everyone who played for the CryptoHackers, and to ASIS CTF for organising this enjoyable event. Congratulations to hellman for being an astonishingly quick one man army!

_We will be publishing more writeups here as soon as they are finished. If you spot a mistake or an improvement that could be made, please ping jack or hyperreality on CryptoHack Discord._

## Challenges

| Challenge Name  | Category | Solved By | Points |
| --------------- | -------- | --------- | -----: |
| [Trailing Bits](#trailing-bits)     | Bitshifting     | willwam845     | 30
| [Amsterdam](#amsterdam)     | Encoding    | rkm0959     | 55
| [Gambler](#gambler)     | PRNG     | Cryptanalyse, willwam845     | 87
| [Three Ravens](#three-ravens)     | RSA     | TheBlueFlame121     | 90
| [Model](#model)     | RSA     | TheBlueFlame121, rkm0959, joachim  | 112
| [One Line Crypto](#one-line-crypto) | Primes | UnblvR  | 146  |
| [Abbot](#abbot)     |     Maths		| rkm0959     | 194 |
| [Butterfly Effect](#butterfly-effect)     | PRNG     | rkm0959, Robin_Jadoul     | 209
| [Mad Hat](#mad-hat)     | Matrices     | rkm0959     | 217
| [Classic](#classic)     | Classical     | Tux, hyperreality | 226
| [Heaven](#heaven)     | LFSR     | Q7, Robin_Jadoul     | 226
| [Strip](#strip)     |    Primes  		| pcback, rkm0959     | 285 |
| [Complex to Hell](#complex-to-hell)     | Hill Cipher     | pcback, joseph, UnblvR  | 300
| [Fatima](#fatima)     |  Reversing | pcback  | 316
| [Namura](#namura)     | Knapsack     | Q7     | 375
| [Decent RSA](#decent-rsa)  |   RSA   | jack  | 423 |
| [Gengol](#gengol)   |    Boneh-Durfee   | pcback, hyperreality, UnblvR   | 450 |


## Trailing Bits

### Challenge

```
The text that includes the flag is transmitted while
unfortunately both of its head and tail bits are lost :(
```

We are given a file containing binary.

### Solution

From the challenge description, we can guess that the binary data provided has a couple bits removed from either end. Not to worry however, since the removed bits won't affect the rest of the data at all.

We know that some bits have been removed, so we can just replace those with some decoy bits, and then try decoding from binary until we get readable text.
```py
from Crypto.Util.number import *

flag = open('output.txt', 'r').read().strip()

i = 0
while True:
	data = long_to_bytes(int(flag,2)*2**i)
	if b'CCTF' in data:
		print(data)
		exit()
	i += 1
```

Output:

> basic unit of information in computing and digital communications. The name is a portmanteau of binary digit.[1] The bit represents a logical state with one of two possible values. These values are most commonly represented as either 0or1, but other representations such as true/false, yes/no, +/−, or on/off are common.
The flag is CCTF{it5_3n0u9h_jU5T_tO_sH1ft_M3}
The correspondence between these values and the physical states of the underlying storage or device is a matter of convention, and different assignments may be used even within the same device or program. It may be physically implemented with a two-st

### Flag

`CCTF{it5_3n0u9h_jU5T_tO_sH1ft_M3}`


---

## Amsterdam

### Challenge

> Is it normal to have such encoding?

```python
from Crypto.Util.number import *
from functools import reduce
import operator
from secret import flag, n, k

def comb(n, k):
	if k > n :
		return 0
	k = min(k, n - k)
	u = reduce(operator.mul, range(n, n - k, -1), 1)
	d = reduce(operator.mul, range(1, k + 1), 1)
	return u // d

def encrypt(msg, n, k):
	msg = bytes_to_long(msg.encode('utf-8'))
	if msg >= comb(n, k):
		return -1
	m = ['1'] + ['0' for i in range(n - 1)]
	for i in range(1, n + 1):
		if msg >= comb(n - i, k):
			m[i-1]= '1'
			msg -= comb(n - i, k)
			k -= 1
	m = int(''.join(m), 2)
	i, z = 0, [0 for i in range(n - 1)]
	c = 0
	while (m > 0):
		if m % 4 == 1:
			c += 3 ** i
			m -= 1
		elif m % 4 == 3:
			c += 2 * 3 ** i
			m += 1
		m //= 2
		i += 1
	return c

enc = encrypt(flag, n, k)
print('enc =', enc)

enc = 5550332817876280162274999855997378479609235817133438293571677699650886802393479724923012712512679874728166741238894341948016359931375508700911359897203801700186950730629587624939700035031277025534500760060328480444149259318830785583493
```

### Solution
We see that there are two steps into solving this problem. First, we have to retrieve the value of $m$ from the encryption result. Then, we calculate the plaintext from $m$.

The first part can be done with recursion. By dividing cases on $c \pmod 3$, we can find which 'if' statement we entered on the first 'while' iteration. This also gives our value of $m \pmod{4}$. We continue this until we have our original value of $c$.

```python
def recv(res):
    if res == 1:
        return 1
    if res % 3 == 0:
        return 2 * recv(res//3)
    if res % 3 == 1:
        return 1 + 2 * recv(res//3)
    if res % 3 == 2:
        return -1 + 2 * recv(res//3)

## computation result
m = 13037931070082386429043329808978789360911287214189289770230708339088698578551447560972351036453899271623903109387482345515668380476074788749548946464
```

Now we calculate the plaintext. Notice that $m$ was initially a bit string, which was then converted to an integer. Therefore, we start by changing $m$ into a bit string.

```python
s = []
while m > 0:
    s.append(m%2)
    m //= 2
s = s[::-1]
n = len(s)
```

It can be proved with induction that after a successful (one that does not return $-1$) call of encrypt(), the value of 'msg' must be $0$. The key idea is Pascal's Triangle.
If we know the value of $k$ at the end of encrypt(), we can reverse engineer the plaintext since we know the result $m$. Brute force all possibilities for $k$, and we are done.

### Implementation
```python
def comb(n, k):
    if k > n :
        return 0
    k = min(k, n - k)
    u = reduce(operator.mul, range(n, n - k, -1), 1)
    d = reduce(operator.mul, range(1, k + 1), 1)
    return u // d

def recv(res):
    if res == 1:
        return 1
    if res % 3 == 0:
        return 2 * recv(res//3)
    if res % 3 == 1:
        return 1 + 2 * recv(res//3)
    if res % 3 == 2:
        return -1 + 2 * recv(res//3)

## m = recv(enc)
m = 13037931070082386429043329808978789360911287214189289770230708339088698578551447560972351036453899271623903109387482345515668380476074788749548946464
s = []
while m > 0:
    s.append(m%2)
    m //= 2
s = s[::-1]
n = len(s)

ans = 0
for k in range(0, 400):
    ans = 0
    for i in range(0, n-1):
        if s[n-1-i] == 1:
            ans += comb(i, k)
            k = k + 1
    print(long_to_bytes(ans))
```

#### Flag

`CCTF{With_Re3p3ct_for_Sch4lkwijk_dec3nt_Encoding!}`

---


## Gambler

### Challenge

In this challenge, we have access to a server with the following options

```
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
+ Hi, there is a strong relation between philosophy and the gambling!  +
+ Gamble as an ancient philosopher and find the flag :)                +
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
| Options:
|    [C]ipher flag!
|    [E]ncryption function!
|    [T]ry the encryption
|    [Q]uit
```

Where the encrypttion function is given by:
```python
def encrypt(m, p, a, b):
    assert m < p and isPrime(p)
    return (m ** 3 + a * m + b) % p
```

### Solution

The goal is to decrypt the flag by recovering the hidden parameters $a,b,p$ and then solving the polynomial used in `encrypt`.

We can recover all parameters quite easily with the function to encrypt our own message.

We can obtain from the server the value of

$$
y(x) = x^3 + ax + b \mod p
$$

for any input $x$.

We can recover $b$ by encrypting 0 as

$$
y(0) = 0^3 + a*0 + b = b \mod p
$$

Where we are assuming that $a,b < p$.

With the value of $b$, we can calculate

$$
y(1) = 1 + a + b \mod p, \quad \Rightarrow \quad a = y(1) - 1 - b
$$


Finally, with both $a,b$ recovered, we need to find the modulus $p$. If we encrypt a fairly small message, such that $y(x) > p$ we can use that

$$
x^3 + ax + b = y(x) + kp, \quad \Rightarrow \quad kp = x^3 + ax + b - y(x)
$$

Since we know a and b, we can compute all the terms on the right hand side of this equation and recover $k p$. All that remains is solving for $k$, which is pretty fast as $k$ is so small.

With all parameters known, we can request the encrypted flag from the server and solve the cubic equation with Sage:
$$
x^3 + ax + b = c \mod p
$$



### Implementation

```py
import os
os.environ["PWNLIB_NOTERM"] = "True"
from pwn import *
from Crypto.Util.number import long_to_bytes

debug = False

r.sendline('C')
data = r.recvuntil(b'|\t[Q]uit\n')
enc = int(data.split()[3].decode().strip())

def encrypt_int(n):
    r.sendline('T')
    r.recvuntil(' your message to encrypt:\n')
    r.sendline(str(n))
    data = r.recvuntil(b'|\t[Q]uit\n')
    b = int(data.split()[3].decode().strip())
    return b

b = encrypt_int(0)
c = encrypt_int(1)
a = c - b - 1
enc_kp = encrypt_int(100)
kp = (2**3 + a*2 + b) - enc_kp

if debug:
    print(a)
    print(b)
    print(kp)

p = max(f[0] for f in factor(kp))
PR.<x> = PolynomialRing(GF(p))
f = x^3 + a * x + b - enc
rts = f.roots()
print(rts)

flag = rts[0][0]
print(long_to_bytes(flag))

r.interactive()
```

### Flag

`CCTF{__Gerolamo__Cardano_4N_itaLi4N_p0lYma7H}`

---

## Three Ravens

### Challenge

> There were three ravens sat on a tree, Downe a downe, hay downe, a downe, They were as black as they might be.

```python
#!/usr/bin/python

from Crypto.Util.number import *
from flag import flag

def keygen(nbit):
    while True:
        p, q, r = [getPrime(nbit) for _ in range(3)]
        if isPrime(p + q + r):
            pubkey = (p * q * r, p + q + r)
            privkey = (p, q, r)
            return pubkey, privkey

def encrypt(msg, pubkey):
    enc = pow(bytes_to_long(msg.encode('utf-8')), 0x10001, pubkey[0] * pubkey[1])
    return enc

nbit = 512
pubkey, _ = keygen(nbit)
print('pubkey =', pubkey)

enc = encrypt(flag, pubkey)
print('enc =', enc)
```

### Solution

The challenge encrypts the flag with a modulus

$$
N = (p*q*r)*(p+q+r)
$$

and gives the output $n = pqr$, $k = p+q+r$. To totally break the cryptosystem, we would want to find the totient of the modulus

$$
\phi(N) = (p-1)(q-1)(r-1)(p+q+r - 1)
$$

but we can simplify this when the encrypted message $m$ is small enough. If we have $m < k$, we can instead find $\phi(k) = k-1$, and find $e^{-1} \mod \phi(k)$, and solve!


### Implementation

```py
from Crypto.Util.number import *

k = 31678428119854378475039974072165136708037257624045332601158556362844808093636775192373992510841508137996049429030654845564354209680913299308777477807442821
c = 8218052282226011897229703907763521214054254785275511886476861328067117492183790700782505297513098158712472588720489709882417825444704582655690684754154241671286925464578318013917918101067812646322286246947457171618728341255012035871158497984838460855373774074443992317662217415756100649174050915168424995132578902663081333332801110559150194633626102240977726402690504746072115659275869737559251377608054255462124427296423897051386235407536790844019875359350402011464166599355173568372087784974017638074052120442860329810932290582796092736141970287892079554841717950791910180281001178448060567492540466675577782909214
e = 0x10001

phi = k-1
d = pow(e,-1,phi)

flag = pow(c,d,k)
print(long_to_bytes(flag))
```

### Flag

`CCTF{tH3_thr3E_r4V3n5_ThRe3_cR0w5}`

---

## Model

### Challenge

```py
def genkey(nbit):
    while True:
        p, q = getPrime(nbit), getPrime(nbit)
        if gcd((p-1) // 2, (q-1) // 2) == 1:
            P, Q = (q-1) // 2, (p-1) // 2
            r = inverse(Q, P)
            e = 2 * r * Q  - 1
            return(p, q, e)

def encrypt(msg, pubkey):
    e, n = pubkey
    return pow(bytes_to_long(msg), e, n)
```

### Solution

The key to solving this challenge is that

$$
e \equiv 2 Q^{-1}Q - 1 \equiv 2 - 1 \equiv 1 \pmod P
$$

So encrypting a message `m` we have, for some integer $k$,

$$
m^e \equiv m^{1 + \frac{k(q-1)}{2}} \equiv m \cdot \left( \frac{m}{q} \right)^k \equiv \pm m \pmod q
$$

Therefore, we can compute $q = \text{gcd}(m^e \pm m, n)$ to factorize $n$.

One last step that needs attention is that we recover $q$, not $p$, which matters for the recovery of $e$, as the primes are not interchangeable here.

### Implementation

```python
from Crypto.Util.number import *
import math

def derive_e(p,q):
	P, Q = (q-1) // 2, (p-1) // 2
	r = pow(Q, -1, P)
	e = 2 * r * Q  - 1
	return e

N = 17790613564907955318126717576181316624843451677921227941389832111093895513875496295594784102148835715126789396535470416868485674231839509486983792844881941097589192520877472968227711640216343330193184235164710328845507199362646489303138765492026284976828397217700058854699501312701069031398507487060508966602815218264215778115331187180105972920333780067280854048113094622799996118383376340217782122945586262887450863620856214375258659362300743471229410735400189992359220551961441580630740022857304514895745174813529758766758733506538696933950282130984955594881517339093338779101106466633380921338845195921235252323721
flag_enc = 8216344743331409189205831776342200252705923796193752552649425282859227400617284746437075756157249953578189229459392338128783031841882560801175367779263048253787547952450480816724222285583987363793884961526545550108790689158473753461378651141379053427506957702375732452598640804768960184186521954448243004125900395894265450073650101942224629389391631821735998886688813393717718376391743836798122485350719355567861201466641767009303179260141365766023680788250688524528992952859061172438083227729190577738108854783536925967748199734513738782142055609101950770816942854252284355975365351013803601963990179403849614198536

m = bytes_to_long(b'0')
ct = 8131881080215090371487466406674376044247120209816118806949066423689730735519795472927218783473464525260814227606067990363574576048132004742403517775620572793232598693334765641758830271460405790617624271060522834683042735967050146871067065889288923913486919193720360254923458500009885281654478144592942337767754315130844294762755237864506689552987776560881357285727629827190391683150994461127468196118126587159811046890420456603820675085450111755868116701855834309297184745623927049652098555126342100576188575279791066071616897443075423425299542959405192350563251777193668273523389978129359003036691597884885020756981

q = math.gcd(ct - m, N)
assert isPrime(q)
p = N // q
e = derive_e(p,q)
d = pow(e, -1, (p-1)*(q-1))
m = pow(flag_enc,d,N)
print(long_to_bytes(m))
```

### Flag

`CCTF{7He_mA1n_iD34_0f_pUb1iC_key_cryPto9raphy_iZ_tHa7_It_l3ts_y0u_puBli5h_4N_pUbL!c_k3y_wi7hOuT_c0mprOmi5InG_y0Ur_5ecr3T_keY}`

---

## One Line Crypto

### Challenge

> A profile, a look, a voice, can capture a heart ♥ in no time at all.”

We're given this very short snippet:
```python
#!/usr/bin/python

from Crypto.Util.number import *
from secret import m, n, x, y, flag

p, q = x**(m+1) - (x+1)**m, y**(n+1) - (y+1)**n
assert isPrime(p) and isPrime(q) and p < q < p << 3 and len(bin(p*q)[2:]) == 2048
enc = bytes_to_long(flag)
print(pow(enc, 0x10001, p*q))
```

and the output of the print function, which consists of just a single, giant number. This is typical RSA encryption, with a slight twist: `n` is not given!

### Solution

The prime selection for `p` and `q` is identical. Two secret numbers `x` and `m` are used, such that `x^(m+1) - (x+1)^m` is a prime. Calculating `q` uses differently named constants, but there's no cross-dependencies between the parameters.

Knowing that `p*q` contains 2048 bits, counting from the MSB, puts some rather strict bounds on the parameters. Just playing around with random numbers, it quickly becomes clear that `m`/`n` can't be very big.

The plan simply becomes:
1. Start off with a low bound like 500 or 1000
2. Brute-force all `m` and `x` less than the bound, such that `x^(m+1) - (x+1)^m` is max 2048 bits.
3. When we got ourselves a small pool of candidate values, pair up two and two random values from the pool
4. Check if their product is 2048 bits, and try to decrypt the ciphertext.

### Implementation

```python
#!/usr/bin/python3
from Crypto.Util.number import long_to_bytes
from gmpy2 import invert, is_prime
from tqdm import tqdm

primes = []

for xy in tqdm(range(500)):
    for mn in range(500):
        prime = xy**(mn+1) - (xy+1)**mn
        if prime.bit_length() > 2048: break
        if is_prime(prime):
            primes.append(prime)

c = 14608474132952352328897080717325464308438322623319847428447933943202421270837793998477083014291941466731019653023483491235062655934244065705032549531016125948268383108879698723118735440224501070612559381488973867339949208410120554358243554988690125725017934324313420395669218392736333195595568629468510362825066512708008360268113724800748727389663826686526781051838485024304995256341660882888351454147057956887890382690983135114799585596506505555357140161761871724188274546128208872045878153092716215744912986603891814964771125466939491888724521626291403272010814738087901173244711311698792435222513388474103420001421

for i in range(len(primes)):
    for j in range(i, len(primes)):
        pq = primes[i]*primes[j]
        if len(bin(pq)[2:]) == 2048:
            try:
                d = invert(0x10001, (primes[i]-1)*(primes[j]-1))
                dec = long_to_bytes(pow(c, d, pq))
                if b"CCTF" in dec:
                    print(dec)
            except ValueError:
                pass
```

### Flag

`CCTF{0N3_1!nE_CrYp7O_iN_202O}`

---

## Butterfly Effect

### Challenge

> Have you heard of the butterfly effect in chaos theory?
We have a very clear sample!

```py
def hq_prng(x, p, g):
    rng = 0
    for _ in range(getRandomNBitInteger(14)):
        x = pow(g, x, p)
    for i in range(nbit):
        x = pow(g, x, p)
        if x < (p-1) // 2:
            rng += 2**i - 1
        elif x > (p-1) // 2:
            rng -= 2**i + 1
        else:
            rng ^= 2**(i + 1)
    if rng <= 0:
        return -rng
    return rng

def keygen(p, g):
    r, s = hq_prng(getRandomNBitInteger(nbit), p, g), hq_prng(getRandomNBitInteger(nbit), p, g)
    u, v = gmpy2.next_prime(r**2 + s**2), gmpy2.next_prime(2*r*s)
    e, n = 0x10001, u * v
    return e, n

def encrypt(msg, e, n):
    return pow(bytes_to_long(msg.encode('utf-8')), e, n)

| encrypt(flag, e, n) = 117667582947026307482709850318214820165964980495414423711608614681075036546959172088083682928734150238100258554942348560628319669155021151214088627854571799267413754120136204715904365400299634909310436631535142237485014585244686834739846288478469145431250711508705770591654103989678439960043788163169606969942

| (p, g, n) = (68396932999729141946282927360590169590631231980913314894620521363257317833167L, 11148408907716636563689390048104567047599159688378384611325239859308138541650L, 174421003123810033381790236221837856515717326914686209725144085385038416771831243218121939343204739172142573392914539954561702192037384452671829208544052005809111211272767217997373349539621608610104198849289553199153550766664805075406312493730029215085806581713874721280621739864343621647737777392917211017939L)
```

### Solution

We start by realizing that the given value of $g$ is not actually a generator of $\mathbb{F}_p$.
In reality, $g$ generates a very small subgroup, having order of $31337$. This can be easily computed with Sage or brute force in Python.

This implies that there are at most $31337$ possible values for the outputs for the PRNG.
We calculate them all, then sort. Denote the result as $x_1 \le x_2 \le \cdots \le x_{31337}$.

We now want to find a pair $(i, j)$ such that $N = \text{nxt}(x_i^2 + x_j^2) \cdot \text{nxt}(2 x_ix_j)$, where $\text{nxt}(n)$ is the smallest prime larger than $n$. This gives a solution with approximately $31337^2/2$ calls to the $\text{nxt}$ function. This is too slow to solve the problem.

To optimize, we use two tricks. First, due to small prime gap, one may assume that

$$
(x_i^2+x_j^2) \cdot 2x_ix_j \le N \le (x_i^2+x_j^2+1000) \cdot (2x_ix_j+1000)
$$ holds true. This cuts the number of pairs to compute. Also, if we fix $x_i$, the values of $x_j$ that satisfy this inequality forms an interval. Therefore, one can use binary search to efficiently compute this interval. This is efficient enough for the task.

### Implementation

```python
from Crypto.Util.number import *

p = 68396932999729141946282927360590169590631231980913314894620521363257317833167
g = 11148408907716636563689390048104567047599159688378384611325239859308138541650
N = 174421003123810033381790236221837856515717326914686209725144085385038416771831243218121939343204739172142573392914539954561702192037384452671829208544052005809111211272767217997373349539621608610104198849289553199153550766664805075406312493730029215085806581713874721280621739864343621647737777392917211017939
c = 117667582947026307482709850318214820165964980495414423711608614681075036546959172088083682928734150238100258554942348560628319669155021151214088627854571799267413754120136204715904365400299634909310436631535142237485014585244686834739846288478469145431250711508705770591654103989678439960043788163169606969942
e = 0x10001

def hq_prng(x, p, g):
    global rsf;
    rng = 0
    for i in range(256):
        x = rsf[x]
        if x < (p-1) // 2:
            rng += 2**i - 1
        elif x > (p-1) // 2:
            rng -= 2**i + 1
        else:
            rng ^= 2**(i + 1)
        x = x % 31337
    if rng <= 0:
        return -rng
    return rng

rsf[0] = 1
for i in range(1, 31337):
    rsf[i] = (g * rsf[i-1]) % p
WOW = [0] * 31337
for i in range(0, 31337):
    WOW[i] = hq_prng(i, p, g)
WOW.sort()
for i in range(0, 31337):
    lef = i+1
    rig = 31336
    mid, best = 0, 0
    while lef <= rig:
        mid = (lef + rig) // 2
        if (WOW[i]*WOW[i] + WOW[mid] * WOW[mid]) * 2 * WOW[i] * WOW[mid] >= n:
            best = mid
            rig = mid -1
        else:
            lef = mid + 1
    if best == 0:
        continue
    for j in range(best-1, min(best+30, 31337)):
        u = WOW[i] * WOW[i] + WOW[j] * WOW[j]
        v = 2 * WOW[i] * WOW[j]
        if u * v <= n and n <= (u+1000) * (v+1000):
            u = nextprime(u)
            v = nextprime(v)
            if u * v == n:
                break

u = 13207168490744652956999406596846767472614127517045010655090178723910296606220559473477009696618646553552917605315941229263316963221556883007951846286507319
v = 13206540315287197799978983146788490475082830408392129019383447128092673850363700139125558344894148410716241976023782262109119063597770109472702331423302981

phi = (u-1)*(v-1)
d = inverse_mod(e,phi)
flag = pow(c,d,N)
print(long_to_bytes(flag))
```

### Flag

`CCTF{r341Ly_v3ryYyyyYY_s3cUrE___PRNG___}`

---

## Abbot

### Challenge
> It isn't the big troubles in life that require character. Anybody can rise to a crisis and face a crushing tragedy with courage, but to meet the petty hazards of the day with a laugh.

```python
import string
import random
from fractions import Fraction as frac
from secret import flag


def me(msg):
	if len(msg) == 1 :
		return ord(msg)
	msg = msg[::-1]
	reducer = len(msg) - 1
	resultNum, resultDen = frac(ord(msg[0]), reducer).denominator, frac(ord(msg[0]), reducer).numerator
	reducer -= 1
	for i in range(1, len(msg)-1):
		result =  ord(msg[i]) +  frac(resultNum, resultDen)
		resultDen, resultNum  = result.denominator, result.numerator
		resultDen, resultNum =  resultNum, reducer * resultDen
		reducer -= 1
	result = ord(msg[-1]) + frac(resultNum, resultDen)
	resultDen, resultNum  = result.denominator, result.numerator
	return (resultNum, resultDen)

def you(msg):
	if len(msg) == 1 :
		return ord(msg)
	msg = msg[::-1]
	reducer = (-1) ** len(msg)
	result = frac(ord(msg[0]), reducer)
	resultNum, resultDen = result.denominator, result.numerator
	reducer *= -1
	for i in range(1, len(msg)-1):
		result =  ord(msg[i]) +  frac(resultNum, resultDen)
		resultDen, resultNum  = result.denominator, result.numerator
		resultDen, resultNum =  resultNum, reducer * resultDen
		reducer *= -1

	result = ord(msg[-1]) + frac(resultNum, resultDen)
	resultDen, resultNum  = result.denominator, result.numerator
	return (resultNum, resultDen)

def us(msg):
	if len(msg) == 1 :
		return ord(msg)
	msg = msg[::-1]
	reducer = (-1) ** int(frac(len(msg), len(msg)**2))
	result = frac(ord(msg[0]), reducer)
	resultNum, resultDen = result.denominator, result.numerator
	reducer **= -1
	reducer = int(reducer)
	for i in range(1, len(msg)-1):
		result =  ord(msg[i]) +  frac(resultNum, resultDen)
		resultDen, resultNum  = result.denominator, result.numerator
		resultDen, resultNum =  resultNum, reducer * resultDen
		reducer **= -1
		reducer = int(reducer)
	result = ord(msg[-1]) + frac(resultNum, resultDen)
	resultDen, resultNum  = result.denominator, result.numerator
	return (resultNum, resultDen)

dict_encrypt = {
	1: me,
	2: you,
	3: us,
	4: you,
	5: me
}
cipher = [[] for _ in range(5)]
S = list(range(1,6))
random.shuffle(S)
print("enc = [")
for i in range(4):
	cipher[i] = dict_encrypt[S[i]](flag[int(i * len(flag) // 5) : int(i * len(flag) // 5 + len(flag) // 5)])
	print(cipher[i])
	print(", ")
i += 1
cipher[i] = dict_encrypt[S[i]](flag[int(i * len(flag) // 5) : int(i * len(flag) // 5 + len(flag) // 5)])
print(cipher[i])
print( " ]")

enc = [(4874974328610108385835995981839358584964018454799387862L, 72744608672130404216404640268150609115102538654479393L),(39640220997840521464725453281273913920171987264976009809L, 366968282179507143583456804992018400453304099650742276L),(145338791483840102508854650881795321139259790204977L, 1529712573230983998328149700664285268430918011078L),(84704403065477663839636886654846156888046890191627L, 717773708720775877427974283328022404459326394028L),(287605888305597385307725138275886061497915866633976011L, 8712550395581704680675139804565590824398265004367939L)]
```

### Solution
The code breaks the flag to five pieces, applies three types of encryption function to them, then combines them into an array. Therefore, it suffices to write codes that reverse these encryptions. Then, we can try to reverse each ciphertext with all types of encryption function, and see what strings it gives us.

We'll start with the `me` encryption function and work from there.
The key intuition is that the value of `resultNum` / `resultDen` is kept between 0 and 1 at the end of each iteration. If this holds, this implies that we can calculate each character of the plaintext by simply taking the integer part of the fraction and using `chr()` function. Why would this be true? Well, we can guess that the length of the each broken message is less than, say, 30. Since each character of the string is readable, the ASCII value of them will be at least 33. With this idea in hand, one can prove the claim by induction. Reversing is also straightforward. Take the integer part, change it into character, take the remaining fractional part and reverse it accordingly.

`you` encryption is a bit trickier since negative values appear. By inspection, we can see that `resultNum` / `resultDen` changes its sign every iteration. The absolute value is kept between 0 and 1. The key idea remains the same, but we need to be careful.

`us` encryption is easy, since the value of `reducer` equals `1` the entire time. Noting this, the code remains very similar to the one of `me` encryption.


### Implementation
```python
def me(resultNum, resultDen, dg):
	st = ""
	if resultNum == 0 or resultDen == 0:
		return ""
	if dg == 0:
		TT = resultNum // resultDen
		if TT < 0 or TT > 256:
			return ""
		st = chr(TT)
		resultNum = resultNum - TT * resultDen
		st += me(resultNum, resultDen, dg+1)
		return st
	acnum = resultDen * dg
	acden = resultNum
	if acden == 0:
		return ""
	TT = acnum // acden
	if TT < 0 or TT > 256:
		return ""
	st = chr(TT)
	acnum = acnum - TT * acden
	st += me(acnum, acden, dg+1)
	return st

def you(resultNum, resultDen, dg, cv):
	st = ""
	if resultNum == 0 or resultDen == 0:
		return ""
	if cv == 0:
		TT = resultNum // resultDen
		if TT < 0 or TT > 256:
			return ""
		st = chr(TT)
		resultNum %= resultDen
		st += you(resultNum, resultDen, dg, cv+1)
		return st
	acnum = resultDen
	acden = resultNum * dg
	if acden < 0:
		acden = -acden
		acnum = acnum
	if acden == 0:
		return ""
	if cv % 2 == 0:
		TT = acnum // acden
		if TT < 0 or TT > 256:
			return ""
		st = chr(TT)
		acnum %= acden
		st += you(acnum, acden, dg*-1, cv+1)
		return st
	else:
		TT = (acnum + acden - 1) // acden
		if TT < 0 or TT > 256:
			return ""
		st = chr(TT)
		acnum = acnum - TT * acden
		st += you(acnum, acden, dg*-1, cv+1)
		return st

def us(resultNum, resultDen, dg):
	st = ""
	if resultNum == 0 or resultDen == 0:
		return ""
	if dg == 0:
		TT = resultNum // resultDen
		if TT < 0 or TT > 256:
			return ""
		st = chr(TT)
		resultNum %= resultDen
		st += us(resultNum, resultDen, dg+1)
		return st
	acnum = resultDen
	acden = resultNum // dg
	if acden == 0:
		return ""
	TT = acnum // acden
	if TT < 0 or TT > 256:
		return ""
	st = chr(TT)
	acnum %= acden
	st += us(acnum, acden, dg)
	return st

for i in range(0, 5):
	print(me(enc[i][0], enc[i][1], 0))
	print(you(enc[i][0], enc[i][1], -1, 0))
	print(us(enc[i][0], enc[i][1], 0))

```

### Flag
` CCTF{This_13_n0t_Arthur_Who_l0ves_Short_st0ries_This_IS___ASIS___Crypto_CTF____with_very_m0d3rn_arthur_Enc0d1ng!!_D0_you_Enj0y_IT_as_w311??} `

---

## Mad Hat

### Challenge
> A dream is not reality, but who's to say which is which?

```python
import random
from secret import p, flag

def transpose(x):
	result = [[x[j][i] for j in range(len(x))] for i in range(len(x[0]))]
	return result

def multiply(A, B):
	if len(A[0]) != len(B):
		return None
	result = []
	for i in range(len(A)):
		r = []
		for j in range(len(B[0])):
			r.append(0)
		result.append(r)
	for i in range(len(A)):
		for j in range(len(B[0])):
			for k in range(len(B)):
				result[i][j] += A[i][k] * B[k][j]
	return result

def sum_matrix(A, B):
	result = []
	for i in range(len(A)):
		r = []
		for j in range(len(A[0])):
			r.append(A[i][j]+B[i][j])
		result.append(r)
	return result

def keygen(p):
	d = random.randint(1, 2**64)
	if p % 4 == 1:
		Q = []
		for i in range(p):
			q = []
			for j in range(p):
				if i == j:
					q.append(0)
				elif pow((i-j), int ((p-1) // 2), p) == 1:
					q.append(1)
				else:
					q.append(-1)
			Q.append(q)
		Q_t = transpose(Q)
		H = []
		r = []
		r.append(0)
		r.extend([1 for i in range(p)])
		H.append(r)
		for i in range(1, p + 1):
			r = []
			for j in range(p + 1):
				if j == 0:
					r.append(1)
				else:
					r.append(Q[i-1][j-1])
			H.append(r)

		H2 = [[0 for j in range(2*(p+1))] for i in range(2*(p+1))]
		for i in range(0, p+1):
			for j in range(0, p+1):
				if H[i][j] == 0:
					H2[i*2][j*2] = 1
					H2[i*2][j*2+1] = -1
					H2[i*2+1][j*2] = -1
					H2[i*2+1][j*2+1] = -1
				elif H[i][j] == 1:
					H2[i*2][j*2] = 1
					H2[i*2][j*2+1] = 1
					H2[i*2+1][j*2] = 1
					H2[i*2+1][j*2+1] = -1
				else:
					H2[i*2][j*2] = -1
					H2[i*2][j*2+1] = -1
					H2[i*2+1][j*2] = -1
					H2[i*2+1][j*2+1] = +1
		ID = [[(-1)**d if i == j else 0 for i in range(len(H2))] for j in range(len(H2))]
		H2 = multiply(ID, H2)
		return(H2, d)
	else:
		Q = []
		for i in range(p):
			q = []
			for j in range(p):
				if i == j:
					q.append(0)
				elif pow( (i-j), int ((p-1) // 2), p) == 1:
					q.append(1)
				else:
					q.append(-1)
			Q.append(q)
		Q_t = transpose(Q)
		Q_Q_t = multiply(Q, Q_t)
		H1 = []
		H1.append([1 for i in range(p+1)])
		for i in range(1, p +1):
			r = []
			for j in range(p +1):
				if j == 0:
					r.append(-1)
				elif i == j:
					r.append(1 + Q[i-1][j-1])
				else:
					r.append(Q[i-1][j-1])
			H1.append(r)
		ID = [[(-1)**d if i == j else 0 for i in range(len(H1))] for j in range(len(H1))]
		H1 = multiply(ID, H1)
		return(H1, d)

def encrypt(msg, key):
	matrix = key[0]
	d = key[1]
	m = [[ord(char) for char in msg ]]
	de = [[-d for i in range(len(msg))]]
	C = multiply(m, matrix)
	cipher = sum_matrix(C, de)
	return cipher

key = keygen(p)
flag = flag + (len(key[0][0]) - len(flag)) * flag[-1]
cipher = encrypt(flag, key)
print('cipher =', cipher)
```

### Solution

By analyzing the dimensions of the ciphertext, it's straightforward to find $p=37$.
Since the matrix part of the secret key is only determined by $p$ and the parity of $d$, we have two possible matrices to consider. Also, if we fix $d$, we can compute the plaintext by solving a system of linear equations. We proceed this way.

If we iterate over $d$ simply as integers, the solution of the equation may contain rational, non-integer numbers. This is slow and prone to floating-point errors, (unless we take proper care) so we will use another trick.

Since all the ordinal values in the plaintext are between $0$ and $256$, we will take this entire problem into $\mathbb{F}_{257}$. This way, we can try $257$ different values of $d$, solve the system without worrying about floating error, and retrieve our answer.

### Implementation

```python
## keygen(d) : simply keygen with p=37, d's parity

MAT0 = keygen(0)
MAT1 = keygen(1)
MM0 = Matrix(GF(257), MAT0)
MM1 = Matrix(GF(257), MAT1)
adv = [1]*76
adv = vector(GF(257), adv)
AD0 = MM0.solve_right(adv)
AD1 = MM1.solve_right(adv)
cipher = [-3459749918754130611, -3459749918754138177, -3459749918754137803, -3459749918754138385, -3459749918754138025, -3459749918754138097, -3459749918754138073, -3459749918754138245, -3459749918754138183, -3459749918754138445, -3459749918754137991, -3459749918754138597, -3459749918754138309, -3459749918754138309, -3459749918754138279, -3459749918754138771, -3459749918754138327, -3459749918754138485, -3459749918754138233, -3459749918754138389, -3459749918754138207, -3459749918754138555, -3459749918754138141, -3459749918754138501, -3459749918754138677, -3459749918754138297, -3459749918754138563, -3459749918754138439, -3459749918754138429, -3459749918754138041, -3459749918754138611, -3459749918754138469, -3459749918754138217, -3459749918754138585, -3459749918754138403, -3459749918754138177, -3459749918754137777, -3459749918754138587, -3459749918754138231, -3459749918754138677, -3459749918754138127, -3459749918754138679, -3459749918754137789, -3459749918754138305, -3459749918754138025, -3459749918754138301, -3459749918754137941, -3459749918754138489, -3459749918754137583, -3459749918754138297, -3459749918754137949, -3459749918754138475, -3459749918754137879, -3459749918754138813, -3459749918754137981, -3459749918754138395, -3459749918754138201, -3459749918754138459, -3459749918754138195, -3459749918754138617, -3459749918754138003, -3459749918754138557, -3459749918754138429, -3459749918754138499, -3459749918754137951, -3459749918754138673, -3459749918754137975, -3459749918754138341, -3459749918754138121, -3459749918754138375, -3459749918754137869, -3459749918754138459, -3459749918754137739, -3459749918754138405, -3459749918754137921, -3459749918754138775]
res = vector(GF(257), cipher)
XX = MM0.solve_right(res)
YY = MM1.solve_right(res)
for i in range(0, 257):
    stX = ""
    stY = ""
    for j in range(0, 76):
        XX[j] += AD0[j]
        YY[j] += AD1[j]
    for j in range(0, len(XX)):
        if (int)(XX[j]) <= 255:
            stX = stX + chr((int)(XX[j]))
    for j in range(0, len(YY)):
        if (int)(YY[j]) <= 255:
            stY = stY + chr((int)(YY[j]))
    if "CCTF" in stX:
        print(stX)
    if "CCTF" in stY:
        print(stY)
```

### Flag
`CCTF{TH13_i3_Hadamard_rip_y0ung_&_bri11iant_Paley!}`

---

## Classic

### Challenge

> Classic is Easy but Essential!

```
b7UkM iK2L0 PUVnZ Ho79I tDAf0 PUvfQ G5jHo 7GwLG wL9It vfQHo 7G5j0 PUvfQ 9Ithd JkMiK 2LU2b 0PUkM B8Nih dJK2L GwL0P UHo7U 2bK2L
...
```


### Solution

Taking trigrams from the ciphertext (i.e. splitting it up into groups of three characters), this becomes a classic monoalphabetic substitution cipher. See the script for inline comments about the solving methodology we used on this more open-ended challenge.


### Implementation

```python
import string
from collections import Counter
from cipher_solver.simple import SimpleSolver

with open('enc.txt') as f:
    ctext = f.read().strip().replace(' ', '')

def chunks(l, n):
    n = max(1, n)
    return [l[i:i+n] for i in range(0, len(l), n)]

# 1. We suspect that groupings of 5 are there to confuse us.
# Let's break chars into groups of different sizes and look at
# the size of the set
for i in range(1,10):
    unique = len(set(chunks(ctext, i)))
    print(f"{unique} unique groups when split into groups of length {i}")

# 2. Breaking into groups of 3 (trigrams) gives much less unique chars
chunked = chunks(ctext, 3)
freq = Counter(chunked).most_common()
print(freq)

# 3. Build a substitution table for each trigram to a different letter
# only important thing is that the most frequent trigram corresponds to a space
subs = {}
alphabet = " " + string.ascii_lowercase + string.ascii_uppercase
cur = 0
for trigram in freq:
    subs[trigram[0]] = alphabet[cur]
    cur += 1
print(subs)

# 4. Make the substitutions
substituted = "".join([subs[c] for c in chunked])
print(substituted)

# 5. Use any algorithm for solving substitution ciphers (quipqiup also works)
s = SimpleSolver(substituted)
s.solve()

# 6. It's readable and the flag is visible after a couple of manual
# substitutions
ptext = s.plaintext()
ptext = ptext.replace('z', 'T')
ptext = ptext.replace('q', '_')
print(ptext)
```

### Flag

`CCTF{The_main_classical_cipher_types_are_substitution_ciphers}`

---

## Heaven

### Challenge

```python
from bitstring import BitArray
from heaven import seventh_seal, oh, no, new_testament

def matthew_effect(shire, rohan):
    gandalf = ''
    for every, hobbit in enumerate(shire):
        gandalf += oh if ord(hobbit) ^ ord(rohan[every]) == 0 else no
    return gandalf

def born_to_die(isengard):
    luke = 0
    for book in new_testament:
        luke ^= ord(isengard[book])
    lizzy_grant = oh + isengard[:-1] if luke == 0 else no + isengard[:-1]
    return lizzy_grant

david = len(seventh_seal)
elf = seventh_seal
lord = BitArray(bytes=bytes(open('flag.jpg', 'rb').read())).bin
bilbo = len(lord)
matthew = 0
princess_leia = ''
destiny = bilbo // david
apocalypse = bilbo % david
for i in range(32):
    elf = born_to_die(elf)
while matthew < destiny:
    princess_leia += matthew_effect(elf, lord[matthew * david : (matthew + 1) * david])
    elf = born_to_die(elf)
    matthew += 1
princess_leia += matthew_effect(elf[:apocalypse], lord[matthew * david :])
res = open('flag.enc', 'wb')
res.write(bytes(int(princess_leia[i : i + 8], 2) for i in range(0, bilbo, 8)))
```
### Solution
After some renaming and minor reverse engineering of the challenge logic, we see that a JPEG image has been xor'ed with a keystream generated from an LFSR. Each time a key-sized block is xored, and the key is forwarded one step in the LFSR.

Xor the encrypted file with a JFIF jpg file header to try to recover the current state of the LFSR.
```python
from bitstring import BitArray

pt = BitArray(bytes=bytes.fromhex('FFD8FFE000104A4649460001')).bin
with open('flag.enc', 'rb') as f:
    content = f.read()
ct = BitArray(bytes=content).bin

key = ''

for i, j in zip(pt, ct):
    key += str(int(i) ^ int(j))
print(key)
```
Then we can get
```python
1100011100101011000
0110001110010101100
0011000111001010110
0001100011100101011
1000110001110010101
0
```

Since we know from the source code that encryptions under consecutive keys share almost the entire key (`x...xa` and `bx...x`), we can recover the length of the key from this. We can observe this rotation already in the above listing of the bits, thanks to our insertion of newlines in the right positions.

Finally we can brute force the polynomial to recover the original image file.

### Implementation
```python
from bitstring import BitArray
key = '1100011100101011000'
seventh_seal = key
oh = '0'
no = '1'


def matthew_effect(shire, rohan):
    gandalf = ''
    for every, hobbit in enumerate(shire):
        gandalf += oh if ord(hobbit) ^ ord(rohan[every]) == 0 else no
    return gandalf


new_testament = []


def born_to_die(isengard):
    luke = 0
    for book in new_testament:
        luke ^= ord(isengard[book])
    lizzy_grant = oh + isengard[:-1] if luke == 0 else no + isengard[:-1]
    return lizzy_grant


a = b'1100011100101011000'
b = b'0110001110010101100'
c = b'0011000111001010110'
d = b'0001100011100101011'
e = b'1000110001110010101'

for i in range(19):
    for j in range(i+1, 19):
        for k in range(j+1, 19):
            for l in range(k+1, 19):
                if a[i] ^ a[j] ^ a[k] ^ a[l] == \
                    b[i] ^ b[j] ^ b[k] ^ b[l] == \
                    c[i] ^ c[j] ^ c[k] ^ c[l] == \
                        e[i] ^ e[j] ^ c[k] ^ c[l] == 0:
                    if d[i] ^ d[j] ^ d[k] ^ d[l] == 1:
                        print(i, j, k, l)
                        seventh_seal = '1100011100101011000'
                        new_testament = [i, j, k, l]

                        david = len(seventh_seal)
                        elf = seventh_seal
                        lord = BitArray(bytes=bytes(open('flag.enc', 'rb').read())).bin
                        bilbo = len(lord)
                        matthew = 0
                        princess_leia = ''
                        destiny = bilbo // david
                        apocalypse = bilbo % david
                        # for i in range(32):
                        #     elf = born_to_die(elf)
                        while matthew < destiny:
                            princess_leia += matthew_effect(elf, lord[matthew * david: (matthew + 1) * david])
                            elf = born_to_die(elf)
                            matthew += 1
                        princess_leia += matthew_effect(elf[:apocalypse], lord[matthew * david:])
                        res = open(f'flag_{i}-{j}-{k}-{l}.jpg', 'wb')
                        res.write(bytes(int(princess_leia[i: i + 8], 2) for i in range(0, bilbo, 8)))
                        res.close()

```

### Flag

`CCTF{0Ne_k3y_t0_rU1e_7hem_A11_4Nd_7o_d3crYp7_th3_fl4g!}`

---

## Strip

No writeup yet

---

## Complex to Hell

### Challenge

> I Already Know I'm Going to Hell
>
> At This Point, It's Really Go Big Or Go Home!

```python
import math 
import string
import random
from secret import flag, key

mapstr = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!{}_"

def multiply(A ,B): 
	ac,ar,bc,br = len(A[0]), len(A), len(B[0]), len(B)
	if ac != br:
		return None
	result = []
	for i in range(ar):
		r = []
		for j in range(bc):
			r.append(0)
		result.append(r)
	for i in range(ar): 
		for j in range(bc): 
			for k in range(br): 
				result[i][j] += A[i][k] * B[k][j] 	
	return result


def comple_congruent (z):
	a = z.real % len(mapstr)
	b = z.imag % len(mapstr) 
	return a + b * 1j

def plain_to_matrix(msg ,n): 
	p = int(math.ceil(len(msg) // (2 * n))) + 1

	matrix_row_size = n
	matrix_col_size = p
	index = 0
	matrix_plain = []
	for i in range(matrix_row_size):
		col = []
		for j in range(matrix_col_size):
			if index >= len(msg):
				col.append(0 + 0.j)
			elif index == len(msg)-1:
				col.append(mapstr.index(msg[index]) + 0.j)
				index += 1
			else:
				col.append(mapstr.index(msg[index]) + mapstr.index(msg[index+1]) * 1.j)
				index += 2
		matrix_plain.append(col)
	return matrix_plain


def encrypt(flag ,key):
	n = len(key)
	p = int(math.ceil(len(flag) // (2 * n))) + 1
	matrix_plain = plain_to_matrix(flag, n)
	key_congruent = []
	for i in range(n):
		r = []
		for j in range(n):
			r.append(comple_congruent(key[i][j]))
		key_congruent.append(r)
	cipher = multiply (key_congruent, matrix_plain)
	result = []
	for i in range(n):
		r = []
		for j in range(p):
			r.append(comple_congruent(cipher[i][j]))
		result.append(r)
	return result

cipher = encrypt(flag, key)
print("cipher = ", cipher)
```

### Solution

tldr;
- Use flag format to set up system of equations.
- Bruteforce the first two entries on the 2nd row.
- Many keys allow decryption of the first row.
- Use last entries in first row, with knowledge of padding to bruteforce the full, correct key.

`plain_to_matrix(msg, n)` takes a message string as input and a row count `n`, and returns a matrix with `n` rows that has the characters of `msg` as complex numbers as entries (one complex number represents two characters). If the message doesn't fill the matrix completely, it is padded with `0`s.

`encrypt(msg, key)` encrypts the given message by left multiplying the message (as a matrix) by the $2 \times 2$ key. The size of the key space is $66^8$ which is infeasible to bruteforce.

We can use the flag format to reduce the amount of bruteforce required. Let the key be

$$
K = \begin{bmatrix}
    a+bi & c+di \\
    e+fi & g+hi
\end{bmatrix}$$

where $a,b,c,d,e,f,g \in \mathbb{Z}/66\mathbb{Z}$

Write the plaintext flag matrix as

$$M = \begin{bmatrix}
    m_0 + m_1i & m_2 + m_3 i & \cdots & m_{32} + m_{33} i \\
    m_{34} + m_{35} i & m_{36} + m_{37} i & \cdots & m_{66} + m_{67} i
\end{bmatrix}$$

and the ciphertext matrix as

$$C = \begin{bmatrix}
    c_0 + c_1i & c_2 + c_3 i & \cdots & c_{32} + c_{33} i \\
    c_{34} + c_{35} i & c_{36} + c_{37} i & \cdots & c_{66} + c_{67} i
\end{bmatrix}$$

(all coefficients in $\mathbb{Z}/66\mathbb{Z}$).

So $C = KM$.

From this we get the equations

$$\begin{aligned}
    c_0 + c_1 i &= (a + bi)(m_0 + m_1 i) + (c + d_i)(m_{34} + m_{35} i) \\
    c_2 + c_3 i &= (a + bi)(m_2 + m_3 i) + (c + d_i)(m_{36} + m_{37} i) \\
    c_{34} + c_{35} i &= (e + fi)(m_0 + m_1 i) + (g + hi)(m_{34} + m_{35} i) \\
    c_{36} + c_{37} i &= (e + fi)(m_2 + m_3 i) + (g + hi)(m_{36} + m_{37} i)
\end{aligned}$$

so

$$\begin{aligned}
    c_0    &= am_0 - bm_1 + cm_{34} - dm_{35} \\
    c_1    &= am_1 + bm_0 + cm_{35} + dm_{34} \\
    c_2    &= am_2 - bm_3 + cm_{36} - dm_{37} \\
    c_3    &= am_3 + bm_2 + cm_{37} + dm_{36} \\
    c_{34} &= em_0 - fm_1 + gm_{34} - hm_{35} \\
    c_{35} &= em_1 + fm_0 + gm_{35} + hm_{34} \\
    c_{36} &= em_2 - fm_3 + gm_{36} - hm_{37} \\
    c_{37} &= em_3 + fm_2 + gm_{37} + hm_{36}
\end{aligned}$$

We'll bruteforce $66^4$ values for $m_{34}, m_{35}, m_{36}$ and $m_{37}$ and solve for the 8 key values with the 8 equations. We already know $m_0, m_1, m_2$ and $m_3$ from the flag format.

Doing this quickly reveals the first row of the plaintext: `CCTF{This_0n3_Is_State_0f_th3_4rt_`.

With this, we can reduce the bruteforce amount to at most $66^3$. Fortunately for us, it turns out that the last 4 characters of the plaintext are `}000`, so we have enough information to enumerate possible keys with minimal bruteforce. We can use the exact same setup as above, except instead of bruteforcing $m_{34}, m_{35}, m_{36}$ and $m_{37}$, we take them to be `}000`. Solving the system will give us a vector $\mathbf{k} = (a,b,c,d,e,f,g,h)$, but this might not be the correct key.

Any vector of the form $\mathbf{k} + \mathbf{t}$ where $\mathbf{t}$ is in the kernel of the coefficients matrix, $A$, will satisfy the system. We can find all vectors in the kernel of $A$ by finding a basis for the kernel modulo each of the prime factors of $66$, and then combining them with the Chinese Remainder Theorem. In this case, the nullity of $A$ in $\mathbb{F}_3$ and $\mathbb{F}_{11}$ is $0$, and the nullity of $A$ in $\mathbb{F}_2$ is $4$. This means we'll need to enumerate at most $2^4$ possible keys.

Note on `inv(key)`: I couldn't find a way to use Sage's built-ins to find the inverse of a matrix with complex entries so I just used the following theory:

Suppose $K^{-1}$ exists. Write

$$K^{-1} = \begin{bmatrix}
    a' + b'i & c' + d'i \\
    e' + f'i & g' + h'i
\end{bmatrix}$$

Then, by definition

$$\begin{bmatrix}
    a + bi & c + di \\
    e + fi & g + hi
\end{bmatrix}
\begin{bmatrix}
    a' + b'i & c' + d'i \\
    e' + f'i & g' + h'i
\end{bmatrix} =
\begin{bmatrix}
    1 & 0 \\
    0 & 1
\end{bmatrix}
$$

so

$$\begin{aligned}
    aa' - bb' + ce' - df' &= 1 \\
    ab' + ba' + cf' + de' &= 0 \\
    ac' - bd' + cg' - dh' &= 0 \\
    ad' + bc' + ch' + dg' &= 0 \\
    ea' - fb' + ge' - hf' &= 0 \\
    eb' + fa' + gf' + he' &= 0 \\
    ec' - fd' + gg' - hh' &= 1 \\
    ed' + fc' + gh' + hg' &= 0
\end{aligned}$$

which is a system of 8 equations in 8 unknowns that can be easily solved.

### Implementation

```python
from itertools import product

mapstr = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!{}_"
cipher =  [ [(24+36j), (41+47j), (3+27j), (36+41j), (57+58j), (11+24j), (33+7j), (52+64j), (26+23j), (30+35j), (64+39j), (52+19j), (39+45j), (33+31j), (3+17j), (21+32j), (15+55j)], [(33+44j), (15+39j), (64+50j), (44+41j), (39+20j), 42j, (16+12j), (63+27j), (9+52j), (39+64j), (5+18j), (53+25j), (47+31j), (5+49j), (24+8j), (57+9j), (38+16j)] ]

F = IntegerModRing(66)

def multiply(A ,B): 
    ac,ar,bc,br = len(A[0]), len(A), len(B[0]), len(B)
    if ac != br:
        return None
    result = []
    for i in range(ar):
        r = []
        for j in range(bc):
            r.append(0)
        result.append(r)
    for i in range(ar): 
        for j in range(bc): 
            for k in range(br): 
                result[i][j] += A[i][k] * B[k][j]     
    return result

def inv(key):
    a,b,c,d,e,f,g,h = key
    M = [[a,-b,0,0,c,-d,0,0],
         [b,a,0,0,d,c,0,0],
         [0,0,a,-b,0,0,c,-d],
         [0,0,b,a,0,0,d,c],
         [e,-f,0,0,g,-h,0,0],
         [f,e,0,0,h,g,0,0,],
         [0,0,e,-f,0,0,g,-h],
         [0,0,f,e,0,0,h,g]]
    M = Matrix(F,M)
    t = vector(F,[1,0,0,0,0,0,1,0])
    i = M.solve_right(t)
    a,b,c,d,e,f,g,h = map(ZZ, i)
    I = [[a+b*1j, c+d*1j],[e+f*1j, g+h*1j]]
    return I

def cong(z):
    a = z.real() % 66
    b = z.imag() % 66
    return a + b*1j

def decrypt(key):
    Kinv = inv(key)
    key = [[cong(Kinv[i][j]) for j in range(2)] for i in range(2)]
    M = multiply(key, cipher)
    res = []
    flag = ''
    for i in range(2):
        for j in range(17):
            a = cong(M[i][j]).real()
            b = cong(M[i][j]).imag()
            flag += mapstr[int(a)] + mapstr[int(b)]
    return flag

# first round, bruteforce m34,m35,m36,m37
# c0, c1, c2, c3 = 24, 36, 41, 17
# c34, c35, c36, c37 = 33, 44, 15, 19
# m0, m1, m2, m3 = 38, 38, 55, 41
# RECOVERS first row: CCTF{This_0n3_Is_State_0f_th3_4rt_

c0, c1, c2, c3 = 21, 32, 15, 55
c34, c35, c36, c37 = 57, 9, 38, 16
m0, m1, m2, m3 = 4, 27, 29, 65
m34, m35, m36, m37 = 64, 0, 0, 0

A = [[m0,-m1,m34,-m35,0,0,0,0],
     [m1, m0, m35, m34,0,0,0,0],
     [m2, -m3,m36,-m37,0,0,0,0],
     [m3,m2,m37,m36,0,0,0,0],
     [0,0,0,0,m0,-m1,m34,-m35],
     [0,0,0,0,m1,m0,m35,m34],
     [0,0,0,0,m2,-m3,m36,-m37],
     [0,0,0,0,m3,m2,m37,m36]]
v = [c0,c1,c2,c3,c34,c35,c36,c37]
A = Matrix(F, A)
v = vector(F, v)
x = A.solve_right(v)
A2 = Matrix(GF(2), A)
A2K = Matrix(F, A2.right_kernel_matrix())
# A3 and A11 have 0 nullity

for lc in product(range(2), repeat=A2.right_nullity()):
    try:
        t2 = A2K.linear_combination_of_rows(lc)
        t = vector([crt([int(a2), 0, 0], [2, 3, 11]) for a2 in t2])
        key = x + t
        flag = decrypt(key)
        print(flag)
    except ValueError:
        pass
    except KeyboardInterrupt:
        exit()
```

### Flag
`CCTF{This_0n3_Is_State_0f_th3_4rt_and_C0mplex_is_Truly_compl3x!!}`

---

## Fatima

No writeup yet

---

## Namura

### Challenge

```python
def encrypt(pubkey, msg):
	C = 0
	for i in range(n):
		C += pubkey[i] * int(msg[i])
	return C

flag = flag.lstrip('CCTF{').rstrip('}')
bflag = bin(bytes_to_long(flag.encode('utf-8')))[2:]
n = len(bflag)
u = n - 30

pubkey = keygen((n+1) // 3, n, u)

print('pubkey =', pubkey)
enc = encrypt(pubkey, bflag)
print('enc =', enc)
```

### Solution

This looks like a knapsack cryptosystem, which are usually solved by lattice reduction algorithms modelling a Shortest Vector Problem (SVP). We noticed that the title of the challenge "Namura" hints at the paper describing this algorithm, Naskao and Murakami's [Knapsack Public-Key Cryptosystem Using Chinese Remainder Theorem](https://eprint.iacr.org/2007/107.pdf). Section 4.2 describes a lattice that can solve low density subset sum problems, and the public key in this challenge has a very low density:

```python
d = len(pubkey) / log(max(pubkey), 2)
print(CDF(d))
0.5625
```

Since the flag can be assumed to be printable ASCII chars, we can reduce the dimension of the pubkey by removing the corresponding number to the MSB of each character in the plaintext.

```python
new = []
pubkey = [0] + pubkey
for i in range(len(pubkey)):
    if i % 8 == 0:
        continue
    new.append(pubkey[i])
print('pubkey =', new)
```

Then we can just solve this like other knapsack problems by bruteforcing the permutation and using the BKZ lattice reduction algorithm to find the SVP.


### Implementation
```python
import re
import random
import multiprocessing as mp
from functools import partial

def check(sol, A, s):
    """Check whether *sol* is a solution to the subset-sum problem.
    """
    return sum(x*a for x, a in zip(sol, A)) == s

def solve(a, s, ID=None):
    rand = random.Random(x=ID)

    mat = []
    for idx,val in enumerate(a):
        mat.append([0]*idx + [1] + [0]*(len(a)-idx-1)+[val])
    mat.append([0]*len(a)+[-s])

    # main loop
    itr = 0
    start_time = cputime()
    while True:
        itr += 1

        # 2. Randomly shuffle
        l = mat[::]
        shuffle(l, random=rand.random)

        # 3. BKZ!!!
        m = matrix(l)
        t_BKZ = cputime()
        l_sol = m.BKZ(block_size=25)
        print(f"{itr} runs. BKZ running time: {cputime(t_BKZ):.3f}s")

        for line in l_sol:
            if all([x >= 0 for x in line[:-1]]):
                print(line)
                print(check(line,a,s))
                print(f"After {itr} runs. FIND SVP!!! {line}\n"
                      f"Single core time used: {cputime(start_time):.3f}s")
                return True

            
enc = 154657917005376465967753276253676484467260782425419406781078357515
pubkey = [636730424634282684150787505024636846878192530834301373045417941, 443443736056701854821550045409138156747702906153207509789193893, 4044894679347221866903041471393250783970070284064844489844729640, 2438178506188801348411667154785222321653401060527584288473058029, 1900607069477409243358471897897077706622577630696771143373974126, 4396893130381899655054557551793492148977658211100513328122993482, 2601912276825314189427819328705612999759768062840709690416685851, 849578696430489144601066711846105434868737506048858961510584478, 867634152731852110202428052792503837522496305953184128350918090, 2141949199052254673518707523413310868963934449025085556791898943, 1317724781892829476727276429613649391725697391917627197350586077, 846616203254169113248714620324777288157484807522832537271896727, 1889890413622399357217368964385384275068207071755568870885142697, 4345106754542111105556800435292359436746763182165461814839878219, 1844751943408649439970784234819027788878268101086942786334241578, 4635151867785248653584925319820032342108353583278365090165351369, 1891260029110631153447767958167471428147295737587261835048395769, 3273672699905851794278838098554938393037792687468962414002119644, 4759683391852904086863354069372064775438697384972606618058259428, 2277479715112568474291874878404028785747567257268529120464806983, 712281270914494089486011482407537474741428127403029959878626851, 4663860235979475414650446442104011820603148660069426522253772670, 3570757581386148492619721379754470899316095256123109990599128391, 4609713244848853151872498160877375734335329160891300656414838786, 1431248994688391495017629590719567118297228062918817671705412012, 2225618736576399852718197161416790353023368081178287753385225648, 4782768885432039605448539230699045953181097923357764740448690485, 1025808412433473089433862844337525335386046496037581875356716631, 2850703152833612251035169162871614900872662336925683266673455769, 4686484042664673737330267137247259184248980902553457550045106744, 3316117133062845045327521738264790714934051828005331038083037906, 1411496297445655314847983724570982636448577335114241954690062680, 2542720351620819402979547749565244924618621495731029455602801063, 4197157173419472170084161918188987699514176876278506629655813541, 775178221793495085043576729609381220589053240944436598437451103, 1341597796943613200200560889564801116846969301604051962802959921, 4724275587384586890632093268426638078191399337509178017491641396, 2254966368661541088781913210011063323766242664855534020654216185, 1559111672805843337464695743725374999443380244436636784823457268, 263060461355351726244024949311923372968467484234342136010504498, 4218489168395358789072676527116792449437414059225489587311420630, 2251347608406477583876276692162280889042972229705782250944073182, 1048197300230894759772482326800601949486880189444304544917201349, 4594309375612539584017914006965726879737368434732989117961461158, 1233526648681303204756491942769500757542366936959132748188681389, 3016611933554222534504704995395833948561521013355966057174149640, 685431642960387458833365483769661272653394129002170162343687962, 1252350578439116321952733140441764993245772656606639708501799071, 2004856906093670950398190666612521156885201358615487450361722687, 1725528220657822102510144312466698156124143365979935333948441423, 3301536380780212554033742823735941195638359575128262344444357806, 3361176781081176991336986769591969284375994647164396417238879397, 2555688594908398218735938381172552745926292876995621798813594216, 2149199142659861721027875250011594210747138266017264150889296633, 4654853318545885657451422703700711659405223637471250014707272999, 1783827755250002883819223478577480687561868815037598618999110299, 3876452588731221361888242546888347728419654382142841199604124779, 2283317070521561115970687892255141823986922119608171153201553969, 3015343638915794545630411225203386258523748035633382700837350107, 1308963799032621611684027617168973833892399982687941479751647735, 3363298156592318867171609036073104624481755649616128282937579774, 3543718722328215918394832245155182570535205536855659505934745836, 2955555006922666284454361589146164283232856958998231643765012061, 4193238914021395832431998242809775488323071053203281739810565939, 4863715450542324142694503897491361069694288484386266524822426647, 3583711168144466683911674650704848504341023445180872465082660398, 1433492863048866856968843544774985957106873111077658213115876127, 3622680772935480479302879234497984985614630209532096422962674742, 3887543917518693741822422553185837022122830870466259214366790339, 3010960827639423613523800853443011766752449479334524527050675334, 1675955542074383948970870230135814936799951109866034174734491734, 2568984843336400124353481960719548494069287783874504372170058935, 680042408260630675242336818143271325154353883745350135887078713, 1896768391347692167859873865813768792359296006947445277687988097, 537513148597668578568712785471862479586342936485511258184103046, 4338318157572996055378474172251186724034148657838505626251846209, 4509359887372553408550688030273180923282246069532844476087185588, 1961425576962957081785371096529881351777256192797473186708183898, 4562726127192998241808421239521775685020063730950933119470565151, 3197416476037069116835447572914275965582808251383336065711778098, 4509743379431751154130020063323115916220642219739358425391068150, 1737231313740527925458531852974418083735884963087687882655818328, 4723771434844173636187013002792278070911838005170476297565209636, 4021068815924596682472342770957679146819658388809493963529859273, 4786593367935490268774249574977281762592209022792374805751998882, 1706847947841349067687051586871379604391823960780007506398289654, 2092911436130136930529034363620771320336826052044341129920779847, 2386542753409262049262444109479898339116742017285966198413932291, 2575514997936878781309794857665223684996125674280321049577858392, 2526059212864002845504783002187945419965243527858703947395965701, 2077055376963690862993188737229202782309424513798741527458096967, 1947721666793448806619506886745665574368753315129031773531178573, 2321982120042809240576670901783025887795295409352093643395133004, 4191930348600938505176612143361132888157091847500134549846473180, 1279873852200144323116032749112043797286486924653552312015287694, 3934811009597203954835516432740855968621865146569217009553064951, 804570958275502176779582603101955727481164663345322968855176622, 4755601230261360181533138175300662604366870408130917516343576381, 2016264908613514961521473342929083040444069560476054659007958347, 3857121931198808981033402131835999166260880661479936388701406991, 4787908501772479625441292392638080593307265124479164945134226910, 403228266126326263488043524077179619385866145325037513940941892, 4080757802977772396554968304371742747141072297333640725823656444, 248086288384249359079536769334310714884272887049336400711180125, 1607777042247987295060365154963999272145526955355524894746933487]
solve_n = partial(solve, pubkey, enc)
CPU_CORE_NUM = 8
with mp.Pool(CPU_CORE_NUM) as pool:
    reslist = pool.imap_unordered(solve_n, range(CPU_CORE_NUM))
    # terminate all processes once one process returns
    for res in reslist:
        if res:
            pool.terminate()
            break
```

Output: 

> After 19 runs. FIND SVP!!! (1, 0, 0, 1, 1, 0, 1, 1, 1, 1, 0, 1, 0, 1, 1, 0, 1, 0, 0, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 1, 0, 1, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 0, 1, 1, 0, 1, 0, 1, 1, 0, 0, 0, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 0, 1, 0, 0, 0, 0, 0, 1, 0, 1, 1, 0, 1, 0, 1, 0, 1, 1, 0, 1, 0, 0, 1, 0, 0, 1, 0, 1, 1, 0, 1, 1, 0, 0, 0, 0, 0)
Single core time used: 643.215s

```python
flag = ''
svp = (1, 0, 0, 1, 1, 0, 1, 1, 1, 1, 0, 1, 0, 1, 1, 0, 1, 0, 0, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 1, 0, 1, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 0, 1, 1, 0, 1, 0, 1, 1,
       0, 0, 0, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 0, 1, 0, 0, 0, 0, 0, 1, 0, 1, 1, 0, 1, 0, 1, 0, 1, 1, 0, 1, 0, 0, 1, 0, 0, 1, 0, 1, 1, 0, 1, 1, 0, 0, 0, 0)
for i in range(0, len(svp), 7):
    flag += '0' + ''.join(map(str, svp[i:i+7]))
print(b'CCTF{'+long_to_bytes(int(flag, 2))+b'}')
```

### Flag

`CCTF{MuR4kam1_nA54K0}`

---

## Decent RSA

### Challenge

> RSA can be decent as well!

> **Note** Although this task is very decent and solvable with focusing on the module number, you may use any tools, guessing, or whatever you know to solve it!


### Solution

TD;DR

- See that when written in base 11, the modulus is mainly zeros
- Write the modulus as a polynomial in base 11 and factor the polynomial
- Solve RSA

All we are given is a RSA public key
```
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA/Ug8rlEPci1UXMsT+UDo
y8DfxbTHX/3BK2oU+FPWiJf+EiUBM2x4ep04qZ1SO9Pmqj/WH9skMrF1J/LXuY3l
fjvJCh0DXa9VUyX2dAJidja9Ior7GpFwwjYdKh+OETNV+2/CcX4RiPvj+8ApmedW
gn4Fxaeivki+f/UwDa+ws1fTUzmI325v8yvcryHhbgeUWiF85EP6HFAavTsVPlxb
LikVMAB1fuzDbqqJvW2u138w6b2FH3WrezYF6tbAyZej2HX46phwDm9C7MXYJ/sU
oS+E8P7S1jMTCWjfwMCOKU3SFGrkWtXuTaoMZ2nZ+HVfJV8xJOjWez1OxQ5P3F1w
GQIDAQAB
-----END PUBLIC KEY-----
```
and some encrypted data.

From the `.pem` we get
```
Algo RSA
Format X.509
ASN1 Dump
RSA Public Key [21:5d:61:5d:7e:ef:d0:58:12:d0:dc:14:bd:7c:e1:69:eb:77:01:f0]
modulus: fd483cae510f722d545ccb13f940e8cbc0dfc5b4c75ffdc12b6a14f853d68897fe122501336c787a9d38a99d523bd3e6aa3fd61fdb2432b17527f2d7b98de57e3bc90a1d035daf555325f67402627636bd228afb1a9170c2361d2a1f8e113355fb6fc2717e1188fbe3fbc02999e756827e05c5a7a2be48be7ff5300dafb0b357d3533988df6e6ff32bdcaf21e16e07945a217ce443fa1c501abd3b153e5c5b2e29153000757eecc36eaa89bd6daed77f30e9bd851f75ab7b3605ead6c0c997a3d875f8ea98700e6f42ecc5d827fb14a12f84f0fed2d633130968dfc0c08e294dd2146ae45ad5ee4daa0c6769d9f8755f255f3124e8d67b3d4ec50e4fdc5d7019
public exponent: 10001
```
where the modulus is some `2048` bit integer. As we are given a `X.509` key, esrever suggested looking at a database of [predictable RSA keys](https://github.com/g0tmi1k/debian-ssh), which contains 30k public keys which were insecure. We downloaded these and looked for a common factor between our common modulus and one of these known, weak keys. We didnt have any luck though.

Another idea was that maybe this would be solved with Fermat factorisation, with "Decent RSA" being a pun for the infinite decent method. I let the algorithm run for a while but eventually killed it.

The solution came from looking at the modulus in various bases. My initial hope was that the primes might be Mersenne primes, which would be exposed by looking at the modulus in base 2, but it turns our the right base for the solve is base 11.

```py
sage: N.str(base=11)
'10010000000000000000000000000000020000000000010000000000000000000000000000000000000000000002002000002000000000000000020020004000000000002000000000004040000000000020000000002000000000000000000400000000000000000000000004000000000000000000000800000000000000000000000408000000000000000200000004000000600200000000000000000000000000000400000000000200000000000000000000000000000040000000000000080000000040400000000000000800000000000000000000000000000080000000000000000000000040000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004000000000000008'
```

We can then write `N` as a polynomial in the following way

```
sage: poly = sum(e * x^i for i,e in enumerate(N.digits(11)))
sage: poly
x^592 + x^589 + 2*x^559 + x^547 + 2*x^501 + 2*x^498 + 2*x^492 + 2*x^475 + 2*x^472 + 4*x^468 + 2*x^456 + 4*x^444 + 4*x^442 + 2*x^430 + 2*x^420 + 4*x^401 + 4*x^375 + 8*x^353 + 4*x^329 + 8*x^327 + 2*x^311 + 4*x^303 + 6*x^296 + 2*x^293 + 4*x^263 + 2*x^251 + 4*x^220 + 8*x^205 + 4*x^196 + 4*x^194 + 8*x^179 + 8*x^148 + 4*x^124 + 4*x^15 + 8
```

Which sage very quickly can factor

```
sage: poly.factor()
(x^296 + x^293 + 2*x^263 + x^251 + 2*x^196 + 4*x^148 + 2*x^124 + 2*x^15 + 4)*(x^296 + 2*x^205 + 2*x^179 + 2)
```

Setting `x = 11` will return the primes `p*q = N`, solving the challenge.


### Implementation

```py
from Crypto.PublicKey import RSA
from Crypto.Util.number import long_to_bytes, bytes_to_long

flag = bytes_to_long(open("flag.enc","rb").read())
key = RSA.import_key(open("mykey.pem").read())
n = Integer(key.n)

poly = sum(e * x^i for i,e in enumerate(Integer(key.n).digits(11)))
(p, _), (q, _) = poly.factor_list()
p, q = p(x=11), q(x=11)
assert p*q == n

d = inverse_mod(key.e, (p-1)*(q-1))
print(long_to_bytes(pow(flag, d, n)))
```

### Flag

`CCTF{___RSA___1n_D3cEn7_W0rLd_cRyPtO5!!!}`

---

## Gengol

No writeup yet
