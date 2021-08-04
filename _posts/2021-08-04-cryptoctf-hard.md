---
layout: post
title: "CryptoCTF 2021 - Hard Challenges"
categories: CTF Writeup
permalink: cryptoctf2021-hard
author:
- CryptoHackers
meta: "CryptoCTF 2021"
tags: Writeup CryptoCTF
---

Last week, CryptoHackers got together to play CryptoCTF for the second time as a team. We solved 26/29 of the challenges during the 24 hour window and came third overall. First and second places went to Super Guessers (Rkm and Rbtree are very friendly faces from CryptoHack) and a Vietnamese team working together to support the spirt of Ho Chi Minh city and nearby provinces. Congratulations to them both.

![CTF Scoreboard](/assets/images/cryptoctf-2021.png)

Not only was it a lot of fun for us all to play together, but it was amazing to see how many CryptoHack friends played the CTF either solo or in small teams and who were able to get a top 15 spot. We're honoured to have so many talented people in our Discord, chatting with us about maths and cryptography. We even have a guest writeups from [rkm0959](https://rkm0959.tistory.com) talking about the solutions of [DoRSA](#dorsa) and [Polish](#polish)

Here are the write-ups for the hardest challenges in the CTF. We'll be writing further blog posts detailing the solutions to all the other challenges very soon! 

Thank you to everyone who played for the CryptoHackers, and to ASIS CTF for organising this enjoyable event. Congratulations again to Super Guessers for being the ultimate crypto heros!

_We will be publishing more writeups here as soon as they are finished. If you spot a mistake or an improvement that could be made, please ping jack or hyperreality on CryptoHack Discord._

## Challenges


| Challenge Name                   | Category          | Solved By                         | Points  |
|----------------------------------|-------------------|-----------------------------------|--------:|
| [Tiny ECC](#tiny-ecc)            | Elliptic Curves   | Jack                              | 217     |
| [Elegant Curve](#elegant-curve)  | Elliptic Curves   | Jack                              | 217     |
| [Double Miff](#double-miff)      | Elliptic Curves   | NeketmanX                         | 217     |
| [Ecchimera](#ecchimera)          | Elliptic Curves   | Vishiswoz, Kubie, NeketmanX       | 271     |
| [RoHaLd](#rohald)                | Elliptic Curves   | Jack, Esrever, Vishiswoz, UnblvR  | 180     |
| [Robert](#robert)                | Carmichael Lambda | Robin, DD                         | 194     |
| [Trunc](#trunc)                  | Signature forgery | NeketmanX                         | 334     |
| [My Sieve](#my-sieve)            | RSA               | Solved after end                  | 477     |
| [DoRSA](#dorsa)                  | RSA               | Super Guesser (Guest Post)        | 450     |
| [Polish](#polish)                | RSA               | Super Guesser (Guest Post)        | 477     |


## Tiny ECC
### Challenge

> Being Smart will mean completely different if you can use [special numbers](https://cr.yp.toc.tf/tasks/tiny_ecc_f6ba20693ddf6ba78f1537889d2c46a17b7a4d8b.txz)!
>
> `nc 01.cr.yp.toc.tf 29010`

```python
#!/usr/bin/env python3

from mini_ecdsa import *
from Crypto.Util.number import *
from flag import flag

def tonelli_shanks(n, p):
    if pow(n, int((p-1)//2), p) == 1:
            s = 1
            q = int((p-1)//2)
            while True:
                if q % 2 == 0:
                    q = q // 2
                    s += 1
                else:
                    break
            if s == 1:
                r1 = pow(n, int((p+1)//4), p)
                r2 = p - r1
                return r1, r2
            else:
                z = 2
                while True:
                    if pow(z, int((p-1)//2), p) == p - 1:
                        c = pow(z, q, p)
                        break
                    else:
                        z += 1
                r = pow(n, int((q+1)//2), p)
                t = pow(n, q, p)
                m = s
                while True:
                    if t == 1:
                        r1 = r
                        r2 = p - r1
                        return r1, r2
                    else:
                        i = 1
                        while True:
                            if pow(t, 2**i, p) == 1:
                                break
                            else:
                                i += 1
                        b = pow(c, 2**(m-i-1), p)
                        r = r * b % p
                        t = t * b ** 2 % p
                        c = b ** 2 % p
                        m = i
    else:
        return False

def random_point(p, a, b):
    while True:
        gx = getRandomRange(1, p-1)
        n = (gx**3 + a*gx + b) % p
        gy = tonelli_shanks(n, p)
        if gy == False:
            continue
        else:
            return (gx, gy[0])

def die(*args):
    pr(*args)
    quit()

def pr(*args):
    s = " ".join(map(str, args))
    sys.stdout.write(s + "\n")
    sys.stdout.flush()

def sc():
    return sys.stdin.readline().strip()

def main():
    border = "+"
    pr(border*72)
    pr(border, "  Dual ECC means two elliptic curve with same coefficients over the ", border)
    pr(border, "  different fields or ring! You should calculate the discrete log   ", border)
    pr(border, "  in dual ECCs. So be smart in choosing the first parameters! Enjoy!", border)
    pr(border*72)

    bool_coef, bool_prime, nbit = False, False, 128
    while True:
        pr(f"| Options: \n|\t[C]hoose the {nbit}-bit prime p \n|\t[A]ssign the coefficients \n|\t[S]olve DLP \n|\t[Q]uit")
        ans = sc().lower()
        if ans == 'a':
            pr('| send the coefficients a and b separated by comma: ')
            COEFS = sc()
            try:
                a, b = [int(_) for _ in COEFS.split(',')]
            except:
                die('| your coefficients are not valid, Bye!!')
            if a*b == 0:
                die('| Kidding me?!! a*b should not be zero!!')
            else:
                bool_coef = True
        elif ans == 'c':
            pr('| send your prime: ')
            p = sc()
            try:
                p = int(p)
            except:
                die('| your input is not valid :(')
            if isPrime(p) and p.bit_length() == nbit and isPrime(2*p + 1):
                q = 2*p + 1
                bool_prime = True
            else:
                die(f'| your integer p is not {nbit}-bit prime or 2p + 1 is not prime, bye!!')
        elif ans == 's':
            if bool_coef == False:
                pr('| please assign the coefficients.')
            if bool_prime == False:
                pr('| please choose your prime first.')
            if bool_prime and bool_coef:
                Ep = CurveOverFp(0, a, b, p)
                Eq = CurveOverFp(0, a, b, q)

                xp, yp = random_point(p, a, b)
                P = Point(xp, yp)

                xq, yq = random_point(q, a, b)
                Q = Point(xq, yq)

                k = getRandomRange(1, p >> 1)
                kP = Ep.mult(P, k)

                l = getRandomRange(1, q >> 1)
                lQ = Eq.mult(Q, l)
                pr('| We know that: ')
                pr(f'| P = {P}')
                pr(f'| k*P = {kP}')
                pr(f'| Q = {Q}')
                pr(f'| l*Q = {lQ}')
                pr('| send the k and l separated by comma: ')
                PRIVS = sc()
                try:
                    priv, qriv = [int(s) for s in PRIVS.split(',')]
                except:
                    die('| your input is not valid, Bye!!')
                if priv == k and qriv == l:
                    die(f'| Congrats, you got the flag: {flag}')
                else:
                    die('| sorry, your keys are not correct! Bye!!!')
        elif ans == 'q':
            die("Quitting ...")
        else:
            die("Bye ...")

if __name__ == '__main__':
    main()
```

The challenge is to supply $a,b,p,q=2p+1$ to generate two curves

$$
E_p: y^2 = x^3 + ax + b \pmod p \\ 
E_q: y^2 = x^3 + ax + b \pmod q
$$

The goal of the challenge is to solve the discrete log for a pair of points on each of these curves. Submitting the correct private keys gives you the flag.

### Solution

I solved this challenge in a fairly ugly and inelegant way. So I'll go through it quickly, then discuss what seems to be the intended solution after.

My idea was to generate a curve $E_p$  with $\\#E_p = p$. This is an anomalous curve, and using Smart's attack, the discrete log problem can be moved to solving the discrete log on $F_p^+$ , which is just division! Then after making one curve easy, I would keep generating primes $p$ until I found a $(q,a,b)$ where $E_q$ had a smooth order, allowing us to solve the discrete log easily.

#### Generating anomalous curves

I refered to [Generating Anomalous Elliptic Curves](http://www.monnerat.info/publications/anomalous.pdf) to generate anomalous curves, and iterated through all primes $p$ where $E_p$   was anomalous. If $q = 2p + 1$ was prime, then I stored the tuple $(p,a,b)$ in a list. I did this until I had plenty of curves to look through.

```python
# http://www.monnerat.info/publications/anomalous.pdf
D = 19
j = -2^15*3^3

def anon_prime(m):
    while True:
        p = (19*m*(m + 1)) + 5
        if is_prime(p):
            return m, p
        m += 1

curves = []
def anom_curve():
    m = 2**61 + 2**60 # chosen so the curves have bit length 128
    while True:
        m, p = anon_prime(m)
        a = (-3*j * inverse_mod((j - 1728), p)) % p
        b = (2*j * inverse_mod((j - 1728), p)) % p
        E = EllipticCurve(GF(p), [a,b])
        
        if E.order() == p:
            G = E.gens()[0]
            print(f'Found an anomalous prime of bit length: {p.nbits()}')
            if is_prime(2*p + 1):
                print(f'Found an anomalous prime with safe prime q = 2p+1. p={p}')
                if p.nbits() != 128:
                    exit()
                curves.append([p,a,b])
                print(curves)
        m += 1
```

Going through curves, I then looked to find $E_q$ of smooth order:

```python
for param in curves:
    p, a, b = param
    q = 2*p + 1

    print(p,a,b)
    exit()
    E1 = EllipticCurve(GF(p), [a,b])
    E2 = EllipticCurve(GF(q), [a,b])
    assert E1.order() == p
    print(factor(E2.order()))
```

Pretty quickly, I found a curve (I think the 15th one?) with order:

```python
E2.order() = 2 * 11 * 29 * 269 * 809 * 1153 * 5527 * 1739687 * 272437559 * 1084044811
```

This is more than smooth enough to solve the dlog (about 10 seconds). 

Sending the parameters to the server:

```python
p = 227297987279223760839521045903912023553
q = 2*p + 1
a = 120959747616429018926294825597988269841 
b = 146658155534937748221991162171919843659
```

I can solve this discrete log using Smart's attack, and the inbuilt discrete log on $E_q$ as it has smooth order.

```python
def SmartAttack(P,Q,p):
    E = P.curve()
    Eqp = EllipticCurve(Qp(p, 2), [ ZZ(t) + randint(0,p)*p for t in E.a_invariants() ])

    P_Qps = Eqp.lift_x(ZZ(P.xy()[0]), all=True)
    for P_Qp in P_Qps:
        if GF(p)(P_Qp.xy()[1]) == P.xy()[1]:
            break

    Q_Qps = Eqp.lift_x(ZZ(Q.xy()[0]), all=True)
    for Q_Qp in Q_Qps:
        if GF(p)(Q_Qp.xy()[1]) == Q.xy()[1]:
            break

    p_times_P = p*P_Qp
    p_times_Q = p*Q_Qp

    x_P,y_P = p_times_P.xy()
    x_Q,y_Q = p_times_Q.xy()

    phi_P = -(x_P/y_P)
    phi_Q = -(x_Q/y_Q)
    k = phi_Q/phi_P
    return ZZ(k)

p = 227297987279223760839521045903912023553
q = 2*p + 1
a = 120959747616429018926294825597988269841 
b = 146658155534937748221991162171919843659

Ep = EllipticCurve(GF(p), [a,b])
G = Ep(97161828186858857945099901434400040095,76112161730436240110429589963792144699)
rG = Ep(194119107523766318610516779439078452539,111570625156450061932127850545534033820)

print(SmartAttack(G,rG,p))

Eq = EllipticCurve(GF(q), [a,b])
H = Eq(229869041108862357437180702478501205702,238550780537940464808919616209960416466)
sH = Eq(18599290990046241788386470878953668775,281648589325596060237553465951876240185)

print(H.discrete_log(sH))
```

##### Flag

`CCTF{ECC_With_Special_Prime5}`

### Intended Solution?

Thanks to Ariana for suggeting this solution to me after the CTF ended. 

The challenge checks for $a * b \neq 0$ , but it does not do this modulo the primes, so if we pick any two primes $p, q = 2p+1$  we can send

```python
p = 227297987279223760839521045903912023553
q = 2*p + 1
a = p*(2*p + 1)
b = p*(2*p + 1)
```

Such that the two curves are given by

$$
E_p: y^2 = x^3 + pq x  + pq \pmod p = x^3 \\
E_q: y^2 = x^3 + pq x  + pq \pmod p = x^3 \\ 
$$

Which are singular curves (in particular, these singular curves with triple zeros, known as cusps). We can translate the discrete log over these curves to solving in the additive group of $F_p$   and so the discrete log is division, and trivial. See this [link](https://crypto.stackexchange.com/questions/61302/how-to-solve-this-ecdlp) for an example.

We solve this discrete log in the following way

```python
p = 227297987279223760839521045903912023553
q = 2*p + 1

Fp = GF(p)
Fq = GF(q)

Px, Py = (171267639996301888897655876215740853691,17515108248008333086755597522577521623)
kPx, kPy = (188895340186764942633236645126076288341,83479740999426843193232746079655679683)
k = Fp(Fp(kPx) / Fp(kPy)) / Fp(Fp(Px) / Fp(Py))

Qx, Qy = (297852081644256946433151544727117912742,290511976119282973548634325709079145116)
lQx, lQy = (83612230453021831094477443040279571268,430089842202788608377537684275601116540)
l = Fq(Fq(lQx) / Fq(lQy)) / Fq(Fq(Qx) / Fq(Qy))

print(f'{k}, {l}')
```

However, these primes aren't special, so maybe this also isn't intended?

## ELEGANT CURVE
### Challenge
> Playing with [Fire](https://cr.yp.toc.tf/tasks/elegant_curve_ae8c3f188723d2852c9f939ba87d930398720a62.txz)!
>
> `nc 07.cr.yp.toc.tf 10010`

```python
#!/usr/bin/env python3

from Crypto.Util.number import *
import sys
from flag import flag

def tonelli_shanks(n, p):
    if pow(n, int((p-1)//2), p) == 1:
            s = 1
            q = int((p-1)//2)
            while True:
                if q % 2 == 0:
                    q = q // 2
                    s += 1
                else:
                    break
            if s == 1:
                r1 = pow(n, int((p+1)//4), p)
                r2 = p - r1
                return r1, r2
            else:
                z = 2
                while True:
                    if pow(z, int((p-1)//2), p) == p - 1:
                        c = pow(z, q, p)
                        break
                    else:
                        z += 1
                r = pow(n, int((q+1)//2), p)
                t = pow(n, q, p)
                m = s
                while True:
                    if t == 1:
                        r1 = r
                        r2 = p - r1
                        return r1, r2
                    else:
                        i = 1
                        while True:
                            if pow(t, 2**i, p) == 1:
                                break
                            else:
                                i += 1
                        b = pow(c, 2**(m-i-1), p)
                        r = r * b % p
                        t = t * b ** 2 % p
                        c = b ** 2 % p
                        m = i
    else:
        return False

def add(A, B, p):
    if A == 0:
        return B
    if B == 0:
        return A
    l = ((B[1] - A[1]) * inverse(B[0] - A[0], p)) % p
    x = (l*l - A[0] - B[0]) % p
    y = (l*(A[0] - x) - A[1]) % p
    return (int(x), int(y))

def double(G, a, p):
    if G == 0:
        return G
    l = ((3*G[0]*G[0] + a) * inverse(2*G[1], p)) % p
    x = (l*l - 2*G[0]) % p
    y = (l*(G[0] - x) - G[1]) % p
    return (int(x), int(y))

def multiply(point, exponent, a, p):
    r0 = 0
    r1 = point
    for i in bin(exponent)[2:]:
        if i == '0':
            r1 = add(r0, r1, p)
            r0 = double(r0, a, p)
        else:
            r0 = add(r0, r1, p)
            r1 = double(r1, a, p)
    return r0

def random_point(a, b, p):
    while True:
        x = getRandomRange(1, p-1)
        try:
            y, _ = tonelli_shanks((x**3 + a*x + b) % p, p)
            return (x, y)
        except:
            continue

def die(*args):
    pr(*args)
    quit()

def pr(*args):
    s = " ".join(map(str, args))
    sys.stdout.write(s + "\n")
    sys.stdout.flush()

def sc():
    return sys.stdin.readline().strip()

def main():
    border = "+"
    pr(border*72)
    pr(border, " hi talented cryptographers, the mission is decrypt a secret message", border)
    pr(border, " with given parameters for two elliptic curve, so be genius and send", border)
    pr(border, " suitable parameters, now try to get the flag!                      ", border)
    pr(border*72)

    nbit = 160

    while True:
        pr("| Options: \n|\t[S]end ECC parameters and solve the task \n|\t[Q]uit")
        ans = sc().lower()
        if ans == 's':
            pr("| Send the parameters of first ECC y^2 = x^3 + ax + b like: a, b, p ")
            params = sc()
            try:
                a, b, p = params.split(',')
                a, b, p = int(a), int(b), int(p)
            except:
                die("| your parameters are not valid!!")
            if isPrime(p) and 0 < a < p and 0 < b < p and p.bit_length() == nbit:
                pr("| Send the parameters of second ECC y^2 = x^3 + cx + d like: c, d, q ")
                pr("| such that 0 < q - p <= 2022")
                params = sc()
                try:
                    c, d, q = params.split(',')
                    c, d, q = int(c), int(d), int(q)
                except:
                    die("| your parameters are not valid!!")
                if isPrime(q) and 0 < c < q and 0 < d < q and 0 < q - p <= 2022 and q.bit_length() == nbit:
                    G, H = random_point(a, b, p), random_point(c, d, q)
                    r, s = [getRandomRange(1, p-1) for _ in range(2)]
                    pr(f"| G is on first  ECC and G =", {G})
                    pr(f"| H is on second ECC and H =", {H})
                    U = multiply(G, r, a, p)
                    V = multiply(H, s, c, q)
                    pr(f"| r * G =", {U})
                    pr(f"| s * H =", {V})
                    pr("| Send r, s to get the flag: ")
                    rs = sc()
                    try:
                        u, v = rs.split(',')
                        u, v = int(u), int(v)
                    except:
                        die("| invalid input, bye!")
                    if u == r and v == s:
                        die("| You got the flag:", flag)
                    else:
                        die("| the answer is not correct, bye!")
                else:
                    die("| invalid parameters, bye!")
            else:
                die("| invalid parameters, bye!")
        elif ans == 'q':
            die("Quitting ...")
        else:
            die("Bye ...")

if __name__ == '__main__':
    main()
```

The challenge is to supply two elliptic curves

$$
E_p: y^2 = x^3 + ax + b \pmod p \\
E_p: y^2 = x^3 + cx + d \pmod q
$$

Where $0 < q - p < 2023$ and $0 < a,b < p$, $0 < c,d < q$. 

Supplying these curves, you are given two pairs of points and the challenge is to solve this discrete log for both pairs. Supplying the two private keys to the server gives the flag.

### Solution

This challenge I solved in an identical way to Tiny ECC. I generated an anomalpus curve $E_p$  and then used `q= next_prime(p)`. I then searched for a pair $(c,d)$  where $\\#E_q$  was smooth. I think the intended solution was to generate two singular elliptic curves with smooth primes $p,q$  so you could solve the discrete log in $F_p^{\star}$ , but seeing as the last solution worked, this was already in my mind.

First I needed an anomalous curve with 160 bit prime. Luckily, this is in the paper [Generating Anomalous Elliptic Curves](http://www.monnerat.info/publications/anomalous.pdf) as an example, so I can use their $m$  value. 

Iterating over $c,d$ I found a curve

```python
q = 730750818665451459112596905638433048232067472077
aq = 3
bq = 481
Eq = EllipticCurve(GF(q), [aq,bq])

factor(Eq.order())                                                                                                
2^2 * 3 * 167 * 193 * 4129 * 882433 * 2826107 * 51725111 * 332577589 * 10666075363
```

Which is smooth, with a 34 bit integer as the largest factor.

Sending to the server:

```python
p = 730750818665451459112596905638433048232067471723 
ap = 425706413842211054102700238164133538302169176474 
bp = 203362936548826936673264444982866339953265530166
q = 730750818665451459112596905638433048232067472077
aq = 3
bq = 481
```

I get my two pairs of points I can easily solve the dlog for

```python
from random import getrandbits

# params from http://www.monnerat.info/publications/anomalous.pdf
D = 11
j = -2**15

def anom_curve():
    m = 257743850762632419871495
    p = (11*m*(m + 1)) + 3
    a = (-3*j * inverse_mod((j - 1728), p)) % p
    b = (2*j * inverse_mod((j - 1728), p)) % p
    E = EllipticCurve(GF(p), [a,b])
    G = E.gens()[0]
    return p, a, b, E, G

def SmartAttack(P,Q,p):
    E = P.curve()
    Eqp = EllipticCurve(Qp(p, 2), [ ZZ(t) + randint(0,p)*p for t in E.a_invariants() ])

    P_Qps = Eqp.lift_x(ZZ(P.xy()[0]), all=True)
    for P_Qp in P_Qps:
        if GF(p)(P_Qp.xy()[1]) == P.xy()[1]:
            break

    Q_Qps = Eqp.lift_x(ZZ(Q.xy()[0]), all=True)
    for Q_Qp in Q_Qps:
        if GF(p)(Q_Qp.xy()[1]) == Q.xy()[1]:
            break

    p_times_P = p*P_Qp
    p_times_Q = p*Q_Qp

    x_P,y_P = p_times_P.xy()
    x_Q,y_Q = p_times_Q.xy()

    phi_P = -(x_P/y_P)
    phi_Q = -(x_Q/y_Q)
    k = phi_Q/phi_P
    return ZZ(k)


p = 730750818665451459112596905638433048232067471723 
ap = 425706413842211054102700238164133538302169176474 
bp = 203362936548826936673264444982866339953265530166

Ep = EllipticCurve(GF(p), [ap,bp])
G = Ep(126552689249226752349356206494226396414163660811, 559777835342379827315577715664975494598512818777)
rG = Ep(190128385937465835164338802317889165657442536853, 604514027124204305317929024826237325074492980218)

print(SmartAttack(G,rG,p))

q = 730750818665451459112596905638433048232067472077
aq = 3
bq = 481
Eq = EllipticCurve(GF(q), [aq,bq])

H = Eq(284866865619833057500909264169831974815120720320, 612322665682105897045018564282609259776516527853)
sH = Eq(673590124165798818844330235458561515292416807353, 258709088293250578320930080839442511989120686226)

print(H.discrete_log(sH))
```

Sending the two keys, I get the flag

##### Flag

`CCTF{Pl4yIn9_Wi7H_ECC_1Z_liK3_pLAiNg_wiTh_Fir3!!}`


## Double Miff
### Challenge
>A new approach, a new attack. Can you attack this curve?
[double_miff.txz](https://cr.yp.toc.tf/tasks/double_miff_58336b2ad5ed82754ac8e9b3bdcc8f25623c909c.txz)

```python
#!/usr/bin/env python3

from Crypto.Util.number import *
from secret import a, b, p, P, Q
from flag import flag

def onmiff(a, b, p, G):
    x, y = G
    return (a*x*(y**2 - 1) - b*y*(x**2 - 1)) % p == 0

def addmiff(X, Y):
    x_1, y_1 = X
    x_2, y_2 = Y
    x_3 = (x_1 + x_2) * (1 + y_1*y_2) * inverse((1 + x_1*x_2) * (1 - y_1*y_2), p) % p
    y_3 = (y_1 + y_2) * (1 + x_1*x_2) * inverse((1 + y_1*y_2) * (1 - x_1*x_2), p) % p
    return (x_3, y_3)


l = len(flag) // 2
m1, m2 = bytes_to_long(flag[:l]), bytes_to_long(flag[l:])

assert m1 < (p // 2) and m2 < (p // 2)
assert onmiff(a, b, p, P) and onmiff(a, b, p, Q)
assert P[0] == m1 and Q[0] == m2

print(f'P + Q = {addmiff(P, Q)}')
print(f'Q + Q = {addmiff(Q, Q)}')
print(f'P + P = {addmiff(P, P)}')
```

```python
P + Q = (540660810777215925744546848899656347269220877882, 102385886258464739091823423239617164469644309399)
Q + Q = (814107817937473043563607662608397956822280643025, 961531436304505096581595159128436662629537620355)
P + P = (5565164868721370436896101492497307801898270333, 496921328106062528508026412328171886461223562143)
```

### Solution
We have a curve equation $ax(y^2 - 1) \equiv by(x^2 - 1) \mod p$ with unknown $a$, $b$, $p$; $P$ and $Q$ are some points on it, and we have $P + Q$, $Q + Q$ and $P + P$.

We need to recover $x$-coordinates of $P$ and $Q$, since they contain parts of the flag.
Addition here is commutative and associative, so we have $(P + P) + (Q + Q) = P + P + Q + Q = P + Q + P + Q = (P + Q) + (P + Q)$.

We have 2 ways of representing $x$- and $y$-coordinates of $P + P + Q + Q$. Set $P + Q = (x_1, y_1)$, $Q + Q = (x_2, y_2)$, $P + P = (x_3, y_3)$, $P + P + Q + Q = (x_0, y_0)$. Then from addition formulas for $x$ we have $x0 \equiv \frac{(x_2+x_3)(1+y_2y_3)}{(1+x_2x_3)(1-y_2y_3)} \mod p$ and $x0 \equiv \frac{2x_1(1+y_1^2)}{(1+x_1^2)(1-y_1^2)} \mod p$, from where we get this:

$$
p|((1+x_1^2)(1-y_1^2)(x_2+x_3)(1+y_2y_3) - 2x_1(1+y_1^2)(1+x_2x_3)(1-y_2y_3))
$$

Analogously from addition formulas for y we get 

$$
p|((1+y_1^2)(1-x_1^2)(y_2+y_3)(1+x_2x_3)-2y_1(1+x_1^2)(1+y_2y_3)(1-x_2x_3))
$$

We can compute gcd of 2 numbers above to get a small multiple of $p$ ($8p$ in this case), and from there we get $p = 1141623079614587900848768080393294899678477852887$.

Recall that for any point on the curve we have $ax(y^2-1) \equiv by(x^2-1) \mod p$, from where we can compute $k \equiv \frac{a}{b} \equiv \frac{y(x^2 - 1)}{x(y^2-1)} \mod p$ by using any known point. 

Note that we also have $\frac{y}{y^2-1} \equiv k\frac{x}{x^2-1} \mod p$.

Set $P = (x_4, y_4)$, and from addition formulas we get:

$$
x_3 \equiv \frac{2x_4(1+y_4^2)}{(1+x_4^2)(1-y_4^2)} \mod p \\
y_3 \equiv \frac{2y_4(1+x_4^2)}{(1+y_4^2)(1-x_4^2)} \mod p
$$

from where we get 

$$
x_3y_3 \equiv \frac{4x_4y_4}{(x_4^2-1)(y_4^2-1)} \equiv 4k(\frac{x_4}{x_4^2 - 1})^2 \mod p
$$

and then $(\frac{x_4^2-1}{x_4})^2 \equiv \frac{4k}{x_3y_3} \mod p$.

We have $\frac{x_4^2-1}{x_4} \equiv \pm l \mod p$, where $l \equiv (\frac{4k}{x_3y_3})^{\frac{p+1}{4}} \mod p$, since $p \equiv 3 \mod 4$.

From here we get $x_4^2 \mp lx_4 - 1 \equiv 0 \mod p$. Discriminant in both cases is equal to $D \equiv l^2 + 4 \mod p$, and we get roots of both equations with $\frac{\pm l \pm \sqrt{D}}{2} \mod p$. Check each one of them, the one that results into printable text gives us the first half of the flag. Analogously we can recover $x$-coordinate of $Q$ and get second half of the flag. By concatenating them, we will have the full flag. Judging by the flag, though, this may be an unintended solution.

# Implementation
```python
#!/usr/bin/env python3
from Crypto.Util.number import isPrime, long_to_bytes
from math import gcd

x1, y1 = (540660810777215925744546848899656347269220877882, 102385886258464739091823423239617164469644309399)
x2, y2 = (814107817937473043563607662608397956822280643025, 961531436304505096581595159128436662629537620355)
x3, y3 = (5565164868721370436896101492497307801898270333, 496921328106062528508026412328171886461223562143)
num1 = (1 + x1 ** 2) * (1 - y1 ** 2) * (x2 + x3) * (1 + y2 * y3) - 2 * x1 * (1 + y1 ** 2) * (1 + x2 * x3) * (1 - y2 * y3)
num2 = (1 + y1 ** 2) * (1 - x1 ** 2) * (y2 + y3) * (1 + x2 * x3) - 2 * y1 * (1 + x1 ** 2) * (1 + y2 * y3) * (1 - x2 * x3)
pmult = gcd(num1, num2)
for i in range(2, 10):
    while pmult % i == 0:
        pmult //= i
    if isPrime(pmult):
        p = pmult
        break


def recover_half(x, y):
    k = y * (x ** 2 - 1) * pow(x * (y ** 2 - 1), -1, p) % p
    l = pow(4 * k * pow(x * y, -1, p), (p + 1) // 4, p)
    D = (l ** 2 + 4) % p
    sqrtD = pow(D, (p + 1) // 4, p)
    for i in range(-1, 2, 2):
        for j in range(-1, 2, 2):
            num = (i * l + j * sqrtD) * pow(2, -1, p) % p
            text = long_to_bytes(num)
            if b'CCTF{' in text or b'}' in text:
                return text

first_half = recover_half(x3, y3)
second_half = recover_half(x2, y2)
flag = (first_half + second_half).decode()
print(flag)
```

##### Flag
`CCTF{D39enEr47E_ECC_4TtaCk!_iN_Huffs?}`


## Ecchimera
##### Points: 271
### Challenge
> The [mixed](https://cryp.toc.tf/tasks/ecchimera_da57494454cba7683105130b6161f4f65c41306f.txz) version is a hard version!

```python
#!/usr/bin/env python3

from sage.all import *
from flag import flag


n = 43216667049953267964807040003094883441902922285265979216983383601881964164181
U = 18230294945466842193029464818176109628473414458693455272527849780121431872221
V = 13100009444194791894141652184719316024656527520759416974806280188465496030062
W = 5543957019331266247602346710470760261172306141315670694208966786894467019982

flag = flag.lstrip(b'CCTF{').rstrip(b'}')
s = int(flag.hex(), 16)
assert s < n

E = EllipticCurve(Zmod(n), [0, U, 0, V, W])
G = E(6907136022576092896571634972837671088049787669883537619895520267229978111036, 35183770197918519490131925119869132666355991678945374923783026655753112300226)

print(f'G = {G}')
print(f's * G = {s * G}')
```

We have an elliptic curve defined over the ring of integers modulo n, or $Z_n$. Generally elliptic curves are defined over a field with a prime $p$, or $F_p$, but in this case we working with the ring $Z_n$. 

The rest of the question is a typical ECDLP (Elliptic Curve Discrete Log Problem) problem, where we're given a generator point $G$ on the curve and the point $s * G$, where $s$ is our flag and the value we need to solve for.

Because $n$ isn't prime, we need to take a different approach to solve the discrete log problem. If we use [factordb](http://factordb.com/index.php?query=43216667049953267964807040003094883441902922285265979216983383601881964164181), we can factor $n$ into 2 primes $p$ and $q$. 

According to this link https://link.springer.com/content/pdf/10.1007%2FBFb0054116.pdf (pg. 4), the number of points on the elliptic curve ($\#E_{Z_n}$) is equivalent to the product of the order of the curve defined over $F_p$ and $F_q$. In other words,

$$\#E_{Z_n} = \#E_{F_p} * \#E_{F_q}$$

Now because $p$ and $q$ are prime, it's very simple to figure out $\#E_{F_p}$ and $\#E_{F_q}$, we can do it directly in Sage

```python
#!/usr/bin/env python3

n = 43216667049953267964807040003094883441902922285265979216983383601881964164181
U = 18230294945466842193029464818176109628473414458693455272527849780121431872221
V = 13100009444194791894141652184719316024656527520759416974806280188465496030062
W = 5543957019331266247602346710470760261172306141315670694208966786894467019982

E = EllipticCurve(Zmod(n), [0, U, 0, V, W])
G = E(6907136022576092896571634972837671088049787669883537619895520267229978111036, 35183770197918519490131925119869132666355991678945374923783026655753112300226)
sG = E(14307615146512108428634858855432876073550684773654843931813155864728883306026, 4017273397399838235912099970694615152686460424982458188724369340441833733921)

p = 190116434441822299465355144611018694747
q = 227316839687407660649258155239617355023

assert p * q == n

# P and Q curves
Ep = EllipticCurve(GF(p), [0, ZZ(U % p), 0, ZZ(V % p), ZZ(W % p)])
Eq = EllipticCurve(GF(q), [0, ZZ(U % q), 0, ZZ(V % q), ZZ(W % q)])

kp = Ep.order()
kq = Eq.order()
```

Now in order to solve the discrete log on the curve over the ring $Z_n$, what we can do instead is solve the discrete log on the curve over the field $F_p$ and $F_q$ and then combine the results using the Chinese remainder theorem (from pg.11 of the same paper linked above). Another explanation is given here: https://crypto.stackexchange.com/questions/72613/elliptic-curve-discrete-log-in-a-composite-ring.

If we look at the order of the curve over $F_p$ and $F_q$ we notice a few things.

$$\#E_{F_p} = p = 190116434441822299465355144611018694747\\
\#E_{F_q} = 2^4 * 3 * 13 * 233 * 4253 * 49555349 * 7418313402470596923151
$$

If the order of a curve defined over a field $F_p$ is equal to $p$, then that means the curve is anomalous, and there's an attack (called Smart's attack) that we can apply to solve the discrete log easily. So we can apply this to the curve defined over $F_p$. This also implies that every point generated by the curve also has an order of $p$.

For the other curve defined over $F_q$, notice that the order is somewhat smooth, meaning that the number can be decomposed into small-ish primes. Other than the last prime factor, the other numbers are fairly small primes. This kind of smooth order implies the Pohlig Hellman attack, where we solve the discrete log problem by solving the discrete log over the subgroups of the group generated by the point $G$.

To summarize, we have a elliptic curve defined over $Z_n$ and we need to solve the discrete log problem to find a value $s$ given $G$ and $sG$. We can split the curve into 2 curves defined over $F_p$ and $F_q$. Then we solve the discrete log over these 2 curves for $s_p$ and $s_q$ such that
$$
s_p \equiv s \mod \#E_{F_p} \\
s_q \equiv s \mod \#E_{F_q}
$$

Using the Chinese remainder theorem we combine these results to find

$$
s \mod \#E_{Z_n}
$$

because

$$
\#E_{Z_n} = \#E_{F_p} * \#E_{F_q}
$$

### Pohlig Hellman

We'll start with the curve defined over $F_q$. First we find the order of the point $G$ defined on the curve:

```python
#!/usr/bin/env python3
from Crypto.Util.number import *

n = 43216667049953267964807040003094883441902922285265979216983383601881964164181
U = 18230294945466842193029464818176109628473414458693455272527849780121431872221
V = 13100009444194791894141652184719316024656527520759416974806280188465496030062
W = 5543957019331266247602346710470760261172306141315670694208966786894467019982

E = EllipticCurve(Zmod(n), [0, U, 0, V, W])
G = E(6907136022576092896571634972837671088049787669883537619895520267229978111036, 35183770197918519490131925119869132666355991678945374923783026655753112300226)
sG = E(14307615146512108428634858855432876073550684773654843931813155864728883306026, 4017273397399838235912099970694615152686460424982458188724369340441833733921)

p = 190116434441822299465355144611018694747
q = 227316839687407660649258155239617355023

assert p * q == n

# P curve
Eq = EllipticCurve(GF(q), [0, ZZ(U % q), 0, ZZ(V % q), ZZ(W % q)])

kq = Eq.order()
Gq = Eq(6907136022576092896571634972837671088049787669883537619895520267229978111036, 35183770197918519490131925119869132666355991678945374923783026655753112300226)
sGq = Eq(14307615146512108428634858855432876073550684773654843931813155864728883306026, 4017273397399838235912099970694615152686460424982458188724369340441833733921)

print(Gq.order())
```

Output is

$$
75772279895802553549752718413205785008 = 2^4 * 13 * 233 * 4253 * 49555349 * 7418313402470596923151
$$

Other than the last factor, the number is fairly smooth. Also notice that the order of $G$ isn't equal to the order of the curve $\#E_{F_q}$ (there's a factor of 3 missing).

We will run the Pohlig Hellman algorithm using every factor except the last one, because solving the discrete log in that prime-order subgroup will take too long. If $s_q$ is small enough, we don't have use the last prime and we will still find the correct value.

Code below is to find $s_q$

```python
primes = [2^4, 13, 233, 4253, 49555349, 7418313402470596923151] #don't use 3 and last one
dlogs = []

for fac in primes[:-1]:
    t = int(Gq.order()) // int(fac)
    dlog = (t*Gq).discrete_log(t*sGq) #discrete_log(t*sGq, t*Gq, operation="+")
    dlogs += [dlog]
    #print("factor: "+str(fac)+", Discrete Log: "+str(dlog)) #calculates discrete logarithm for each prime order

q_secret = crt(dlogs, primes[:-1])
```
Running this we get $s_q = 9092500866606561$.

### Smart's attack

Onto the other curve. We know the order of the curve equals the prime $p$ (anomalous curve), so we can apply Smart's attack to solve the discrete log quickly.

Code to apply this attack and solve for $s_p$ is below:
```python
n = 43216667049953267964807040003094883441902922285265979216983383601881964164181
U = 18230294945466842193029464818176109628473414458693455272527849780121431872221
V = 13100009444194791894141652184719316024656527520759416974806280188465496030062
W = 5543957019331266247602346710470760261172306141315670694208966786894467019982

E = EllipticCurve(Zmod(n), [0, U, 0, V, W])
G = E(6907136022576092896571634972837671088049787669883537619895520267229978111036, 35183770197918519490131925119869132666355991678945374923783026655753112300226)
sG = E(14307615146512108428634858855432876073550684773654843931813155864728883306026, 4017273397399838235912099970694615152686460424982458188724369340441833733921)

p = 190116434441822299465355144611018694747
q = 227316839687407660649258155239617355023

assert p * q == n

# P curve
Ep = EllipticCurve(GF(p), [0, ZZ(U % p), 0, ZZ(V % p), ZZ(W % p)])

kp = Ep.order()
Gp = Ep(6907136022576092896571634972837671088049787669883537619895520267229978111036, 35183770197918519490131925119869132666355991678945374923783026655753112300226)
sGp = Ep(14307615146512108428634858855432876073550684773654843931813155864728883306026, 4017273397399838235912099970694615152686460424982458188724369340441833733921)

print(Gp.order())

def SmartAttack(P,Q,p):
    E = P.curve()
    Eqp = EllipticCurve(Qp(p, 2), [ ZZ(t) + randint(0,p)*p for t in E.a_invariants() ])

    P_Qps = Eqp.lift_x(ZZ(P.xy()[0]), all=True)
    for P_Qp in P_Qps:
        if GF(p)(P_Qp.xy()[1]) == P.xy()[1]:
            break

    Q_Qps = Eqp.lift_x(ZZ(Q.xy()[0]), all=True)
    for Q_Qp in Q_Qps:
        if GF(p)(Q_Qp.xy()[1]) == Q.xy()[1]:
            break

    p_times_P = p*P_Qp
    p_times_Q = p*Q_Qp

    x_P,y_P = p_times_P.xy()
    x_Q,y_Q = p_times_Q.xy()

    phi_P = -(x_P/y_P)
    phi_Q = -(x_Q/y_Q)
    k = phi_Q/phi_P
    return ZZ(k)

p_secret = SmartAttack(Gp,sGp,p)
```

Running that code we get $s_p = 35886536999264548257653961517736633452$

### CRT

All that's left is to combine our 2 answers with CRT and solve for the flag.
Let the order of $G$ on $E_{F_p}$ be $n_p$ and the order of $G$ on $E_{F_q}$ be $n_q$. 

Also note that:
$$\#E_{F_p} = n_p\\
\#E_{F_q} = n_q \cdot 3 \cdot 7418313402470596923151$$

We have the following equations:
$$
s_p \equiv s \mod n_p\\
s_q \equiv s \mod n_q
$$

If the $s$ is small enough, CRT will be able to recover the flag.

```python
flag = long_to_bytes(int(crt([p_secret, q_secret], [Gp.order(), Gq.order() // 7418313402470596923151])))
print(flag)
```

### Solution
Full solution code below

```python
#!/usr/bin/env python3
from Crypto.Util.number import *

n = 43216667049953267964807040003094883441902922285265979216983383601881964164181
U = 18230294945466842193029464818176109628473414458693455272527849780121431872221
V = 13100009444194791894141652184719316024656527520759416974806280188465496030062
W = 5543957019331266247602346710470760261172306141315670694208966786894467019982

E = EllipticCurve(Zmod(n), [0, U, 0, V, W])
G = E(6907136022576092896571634972837671088049787669883537619895520267229978111036, 35183770197918519490131925119869132666355991678945374923783026655753112300226)
sG = E(14307615146512108428634858855432876073550684773654843931813155864728883306026, 4017273397399838235912099970694615152686460424982458188724369340441833733921)

p = 190116434441822299465355144611018694747
q = 227316839687407660649258155239617355023

assert p * q == n

# P curve
Ep = EllipticCurve(GF(p), [0, ZZ(U % p), 0, ZZ(V % p), ZZ(W % p)])
Eq = EllipticCurve(GF(q), [0, ZZ(U % q), 0, ZZ(V % q), ZZ(W % q)])

kp = Ep.order()
kq = Eq.order()

Gp = Ep(6907136022576092896571634972837671088049787669883537619895520267229978111036, 35183770197918519490131925119869132666355991678945374923783026655753112300226)
Gq = Eq(6907136022576092896571634972837671088049787669883537619895520267229978111036, 35183770197918519490131925119869132666355991678945374923783026655753112300226)

sGp = Ep(14307615146512108428634858855432876073550684773654843931813155864728883306026, 4017273397399838235912099970694615152686460424982458188724369340441833733921)
sGq = Eq(14307615146512108428634858855432876073550684773654843931813155864728883306026, 4017273397399838235912099970694615152686460424982458188724369340441833733921)

print(Gp.order())
print(Gq.order())

def SmartAttack(P,Q,p):
    E = P.curve()
    Eqp = EllipticCurve(Qp(p, 2), [ ZZ(t) + randint(0,p)*p for t in E.a_invariants() ])

    P_Qps = Eqp.lift_x(ZZ(P.xy()[0]), all=True)
    for P_Qp in P_Qps:
        if GF(p)(P_Qp.xy()[1]) == P.xy()[1]:
            break

    Q_Qps = Eqp.lift_x(ZZ(Q.xy()[0]), all=True)
    for Q_Qp in Q_Qps:
        if GF(p)(Q_Qp.xy()[1]) == Q.xy()[1]:
            break

    p_times_P = p*P_Qp
    p_times_Q = p*Q_Qp

    x_P,y_P = p_times_P.xy()
    x_Q,y_Q = p_times_Q.xy()

    phi_P = -(x_P/y_P)
    phi_Q = -(x_Q/y_Q)
    k = phi_Q/phi_P
    return ZZ(k)

primes = [2^4, 13, 233, 4253, 49555349, 7418313402470596923151] #don't use 3 and last one
dlogs = []

for fac in primes[:-1]:
    t = int(Gq.order()) // int(fac)
    dlog = (t*Gq).discrete_log(t*sGq) #discrete_log(t*sGq, t*Gq, operation="+")
    dlogs += [dlog]
    #print("factor: "+str(fac)+", Discrete Log: "+str(dlog)) #calculates discrete logarithm for each prime order


p_secret = SmartAttack(Gp,sGp,p)
q_secret = crt(dlogs, primes[:-1]) #Gq.discrete_log(sGq) #9092500866606561 #discrete_log(sGq, Gq, ord=Gq.order(), bounds=2^4 * 3 * 13 * 233 * 4253 * 49555349, operation="+")

print(p_secret, q_secret)
flag = long_to_bytes(int(crt([p_secret, q_secret], [Gp.order(), Gq.order() // 7418313402470596923151])))
print(flag)
```
##### Flag
`CCTF{m1X3d_VeR5!0n_oF_3Cc!}`

## RoHaLd
### Challenge

> There is always a [starting point](https://cr.yp.toc.tf/tasks/Rohald_86da9506b23e29e88d8c8f44965e9c2949a3dc41.txz), isn't it?

`RoHaLd_ECC.py`

```python
#!/usr/bin/env sage

from Crypto.Util.number import *
from secret import flag, Curve

def ison(C, P):
    c, d, p = C
    u, v = P
    return (u**2 + v**2 - c**2 * (1 + d * u**2*v**2)) % p == 0

def teal(C, P, Q):
    c, d, p = C
    u1, v1 = P
    u2, v2 = Q
    assert ison(C, P) and ison(C, Q)
    u3 = (u1 * v2 + v1 * u2) * inverse(c * (1 + d * u1 * u2 * v1 * v2), p) % p
    v3 = (v1 * v2 - u1 * u2) * inverse(c * (1 - d * u1 * u2 * v1 * v2), p) % p
    return (int(u3), int(v3))

def peam(C, P, m):
    assert ison(C, P)
    c, d, p = C
    B = bin(m)[2:]
    l = len(B)
    u, v = P
    PP = (-u, v)
    O = teal(C, P, PP)
    Q = O
    if m == 0:
        return O
    elif m == 1:
        return P
    else:
        for _ in range(l-1):
            P = teal(C, P, P)
        m = m - 2**(l-1)
        Q, P = P, (u, v)
        return teal(C, Q, peam(C, P, m))

c, d, p = Curve

flag = flag.lstrip(b'CCTF{').rstrip(b'}')
l = len(flag)
lflag, rflag = flag[:l // 2], flag[l // 2:]

s, t = bytes_to_long(lflag), bytes_to_long(rflag)
assert s < p and t < p

P = (398011447251267732058427934569710020713094, 548950454294712661054528329798266699762662)
Q = (139255151342889674616838168412769112246165, 649791718379009629228240558980851356197207)

print(f'ison(C, P) = {ison(Curve, P)}')
print(f'ison(C, Q) = {ison(Curve, Q)}')

print(f'P = {P}')
print(f'Q = {Q}')

print(f's * P = {peam(Curve, P, s)}')
print(f't * Q = {peam(Curve, Q, t)}')
```

`output.txt`

```python
ison(C, P) = True
ison(C, Q) = True
P = (398011447251267732058427934569710020713094, 548950454294712661054528329798266699762662)
Q = (139255151342889674616838168412769112246165, 649791718379009629228240558980851356197207)
s * P = (730393937659426993430595540476247076383331, 461597565155009635099537158476419433012710)
t * Q = (500532897653416664117493978883484252869079, 620853965501593867437705135137758828401933)
```

The challenge is to solve the discrete log problem twice, given two pairs of points on the curve. However, before we can do this, we need to recover the curve parameters $(c,d,p)$. The writeup is broken into two pieces: first the recovery of the paramters, then the mapping of the Edwards curve to Weierstrass form to easily solve the dlog using Sage.

### Solution

#### Recovering Curve Parameters

Our goal in this section is to recover $(c,d,p)$ so we can reconstruct the curve and solve the discrete log. We will obtain $p$ first, which will allow us to take inversions mod $p$, needed to recover $c, d$. 

We have the curve equation: 
$$
E_{c,d} : x^2 + y^2  = c^2 (1 + d x^2 y^2) \pmod p
$$
and so we know for any point $(x_0,y_0)$  we have
$$
x_0^2 + y_0^2  - c^2 (1 + d x_0^2 y_0^2) = k_0 p \equiv 0\pmod p
$$
for some integer $k_0$   . 

Taking two points on the curve, we can isolate $cd^2$  using:
$$
X_1 = x_1^2 + y_1^2  - c^2 (1 + d x_1^2 y_1^2) = k_1 p \\
X_2 = x_2^2 + y_2^2  - c^2 (1 + d x_2^2 y_2^2) = k_2 p
$$
The goal is to use two points to write something which is a multiple of $p$, and to do this twice. We can then recover $p$ from the gcd of the pair of points.

Taking the difference $X_1 - X_2$ elliminates the constant $c^2$ term:
$$
X_1 - X_2 = (x_1^2 - x_2^2 + y_1^2 - y_2^2) - c^2d (x_1^2 y_1^2 - x_2^2 y_2^2) \equiv 0 \pmod p
$$
Collecting the multiples of $p$ we can isolate $c^2 d$ , where we use the notation:
$$
A_{ij} = x_i^2 - x_j^2 + y_i^2 - y_j^2, \qquad B_{ij} = x_i^2 y_i^2 - x_j^2 y_j^2
$$
to write down:
$$
\frac{A_{12}}{B_{12}} \equiv c^2 d \pmod p
$$
Doing this with the other pair of points gives another expression for $c^2 d$ and the difference of these two expressions will be a multiple of $p$
$$
\frac{A_{12}}{B_{12}}  -  \frac{A_{34}}{B_{34}}  = k \cdot p
$$
There's one more problem: we can't divide without knowing $p$, so first let's remove the denominator:
$$
A_{12} B_{34} - A_{34} B_{12} = B_{12}B_{34}kp = \tilde{k} p
$$
Finally, we can obtain $p$ from taking another combination of points and taking the $\gcd$
$$
\begin{aligned}
Y_{1234} &= A_{12} B_{34} - A_{34} B_{12} = B_{12}B_{34} \\
Y_{1324} &= A_{13} B_{24} - A_{24} B_{13} = B_{13}B_{24} \\
p &\simeq \gcd(Y_{1234}, Y_{1324})
\end{aligned}
$$
Note, we may not get exactly $p$ , but some multiple of $p$, however, it's easy to factor this and find $p$  precisely.

Returning to the above expression with the knowledge of $p$, we can compute $c^2d$
$$
c^2 d = \frac{x_1^2 - x_2^2 + y_1^2 - y_2^2 }{x_1^2 y_1^2 - x_2^2 y_2^2} \pmod p
$$
and with this known, we can so back to any point on a curve and write
$$
c^2 = x_0^2 + y_0^2 - c^2 d x_0^2 y_0^2 \pmod p
$$
and $c$   is then found with a square root and $d$ can be found from $c^2 d$. With all curve parameters known, we can continue to solve the discrete log.

```python
from math import gcd

def ison(C, P):
    """
    Verification points are on the curve
    """
    c, d, p = C
    u, v = P
    return (u**2 + v**2 - cc * (1 + d * u**2*v**2)) % p == 0

def a_and_b(u1,u2,v1,v2):
    """
    Helper function used to simplify calculations
    """
    a12 = u1**2 - u2**2 + v1**2 - v2**2
    b12 = u1**2 * v1**2 - u2**2 * v2**2
    return a12, b12

def find_modulus(u1,u2,u3,u4,v1,v2,v3,v4):
    """
    Compute the modulus from four points
    """
    a12, b12 = a_and_b(u1,u2,v1,v2)
    a13, b13 = a_and_b(u1,u3,v1,v3)
    a23, b23 = a_and_b(u2,u3,v2,v3)
    a24, b24 = a_and_b(u2,u4,v2,v4)

    p_almost = gcd(a12*b13 - a13*b12, a23*b24 - a24*b23)

    for i in range(2,1000):
        if p_almost % i == 0:
            p_almost = p_almost // i

    return p_almost

def c_sq_d(u1,u2,v1,v2,p):
    """
    Helper function to computer c^2 d
    """
    a1,b1 = a_and_b(u1,u2,v1,v2)
    return a1 * pow(b1,-1,p) % p

def c(u1,u2,v1,v2,p):
    """
    Compute c^2, d from two points and known modulus
    """
    ccd = c_sq_d(u1,u2,v1,v2,p)
    cc = (u1**2 + v1**2 - ccd*u1**2*v1**2) % p
    d = ccd * pow(cc, -1, p) % p
    return cc, d


P = (398011447251267732058427934569710020713094, 548950454294712661054528329798266699762662)
Q = (139255151342889674616838168412769112246165, 649791718379009629228240558980851356197207)
sP = (730393937659426993430595540476247076383331, 461597565155009635099537158476419433012710)
tQ = (500532897653416664117493978883484252869079, 620853965501593867437705135137758828401933)

u1, v1 = P
u2, v2 = Q
u3, v3 = sP
u4, v4 = tQ

p = find_modulus(u1,u2,u3,u4,v1,v2,v3,v4)
cc, d = c(u1,u2,v1,v2,p)

C = cc, d, p
assert ison(C, P)
assert ison(C, Q)
assert ison(C, sP)
assert ison(C, tQ)

print(f'Found curve parameters')
print(f'p = {p}')
print(f'c^2 = {cc}')
print(f'd = {d}')

# Found curve
# p = 903968861315877429495243431349919213155709
# cc = 495368774702871559312404847312353912297284
# d = 540431316779988345188678880301417602675534
```

#### Converting to Weierstrass Form

With the curve known, all we have to do is solve the discrete log problem on the Edwards curve. This could be done by using Pohlih-Hellman and BSGS using the functions defined in the file, but instead we map the Edwards curve into Weierstrass form and use sage in built dlog to solve. Potentially there is a smarter way to do this conversion, here I used known mappings to go from Edwards to Montgomery form, then Montgomery form to Weierstrass form. Please let me know if there's a smarter way to do this!

We begin with the Edwards curve:
$$
E_{c,d} : x^2 + y^2  = c^2 (1 + d x^2 y^2) \pmod p
$$
This is in the less usual form, with the factor $c$, so before continuing, we scale $(x,y,d)$ to remove $c$:
$$
x \to \frac{x}{c}, \; \; y \to \frac{y}{c}, \;\; d \to c^4 d
$$
 To obtain the more familiar Edwards curve:
$$
E_{c} : x^2 + y^2  = (1 + d x^2 y^2) \pmod p
$$
Note: I am refering to $(x,y,d)$ using the same labels, I hope this doesnt confuse people.

In this more familiar form, I referred to  https://safecurves.cr.yp.to/equation.html to map the curve to the Montgomery curve
$$
E_{A,B}: B v^2 =  u^3 + Au^2 + u \pmod p
$$
With the factor $B$ here, I dont know how to create this curve using Sage, maybe this is possible? This mapping is done by the coordinate transformation
$$
u = \frac{1 + y}{1 - y}, \qquad v = \frac{2(1 + y)}{ x(1 - y)} = \frac{2u}{x}
$$
and the curve parameters are related by
$$
A = \frac{4}{1 - d } - 2 \qquad B = \frac{1}{1 - d }
$$
Finally, we can convert this curve to short Weierstrass form (equations are taken from https://en.wikipedia.org/wiki/Montgomery_curve)
$$
E_{a,b}: Y^2 = X^3 + aX^2 + b \pmod p
$$
My making the coordinate transformations
$$
X = \frac{u}{B} + \frac{A}{3B}, \qquad Y = \frac{v}{B}
$$
and the curve parameters are related by
$$
a = \frac{3 - A^2}{3B^2} \qquad  b = \frac{2A^3 - 9A}{27B^3}
$$
In this form, we can plug the points into the curve using Sage and solve the discrete log. Implementation is given below

#### Grabbing the flag

```python
from Crypto.Util.number import *

# Recovered from previous section
p = 903968861315877429495243431349919213155709
F = GF(p)
cc = 495368774702871559312404847312353912297284
c = F(cc).sqrt()
d = 540431316779988345188678880301417602675534

# Point data from challenge
P = (398011447251267732058427934569710020713094, 548950454294712661054528329798266699762662)
Q = (139255151342889674616838168412769112246165, 649791718379009629228240558980851356197207)
sP = (730393937659426993430595540476247076383331, 461597565155009635099537158476419433012710)
tQ = (500532897653416664117493978883484252869079, 620853965501593867437705135137758828401933)

x1, y1 = P
x2, y2 = Q
x3, y3 = sP
x4, y4 = tQ

R.<x,y> = PolynomialRing(F)
g = (x^2 + y^2 - cc * (1 + d * x^2*y^2))

# Check the mapping worked!
assert g(x=x1, y=y1) == 0
assert g(x=x2, y=y2) == 0
assert g(x=x3, y=y3) == 0
assert g(x=x4, y=y4) == 0

# Scale: x,y,d to remove c:
# x^2 + y^2 = c^2 * (1 + d * x^2*y^2)
# to:
# x^2 + y^2 = (1 + d * x^2*y^2)

d = F(d) * F(cc)^2
x1, y1 = F(x1) / F(c),  F(y1) / F(c)
x2, y2 = F(x2) / F(c),  F(y2) / F(c)
x3, y3 = F(x3) / F(c),  F(y3) / F(c)
x4, y4 = F(x4) / F(c),  F(y4) / F(c)

h = (x^2 + y^2 - (1 + d * x^2*y^2))

# Check the mapping worked!
assert h(x=x1, y=y1) == 0
assert h(x=x2, y=y2) == 0
assert h(x=x3, y=y3) == 0
assert h(x=x4, y=y4) == 0

# Convert from Edwards to Mont. 
# https://safecurves.cr.yp.to/equation.html
def ed_to_mont(x,y):
    u = F(1 + y) / F(1 - y)
    v = 2*F(1 + y) / F(x*(1 - y))
    return u,v

u1, v1 = ed_to_mont(x1, y1)
u2, v2 = ed_to_mont(x2, y2)
u3, v3 = ed_to_mont(x3, y3)
u4, v4 = ed_to_mont(x4, y4)

e_curve = 1 - F(d)
A = (4/e_curve - 2)
B = (1/e_curve)

# Mont. curve: Bv^2 = u^3 + Au^2 + u
R.<u,v> = PolynomialRing(ZZ)
f = B*v^2 - u^3 - A* u^2 - u

# Check the mapping worked!
assert f(u=u1, v=v1) == 0
assert f(u=u2, v=v2) == 0
assert f(u=u3, v=v3) == 0
assert f(u=u4, v=v4) == 0

# Convert from Mont. to Weierstrass
# https://en.wikipedia.org/wiki/Montgomery_curve
a = F(3 - A^2) / F(3*B^2)
b = (2*A^3 - 9*A) / F(27*B^3)
E = EllipticCurve(F, [a,b])

# https://en.wikipedia.org/wiki/Montgomery_curve
def mont_to_wei(u,v):
    t = (F(u) / F(B)) + (F(A) / F(3*B))
    s = (F(v) / F(B))
    return t,s

X1, Y1 = mont_to_wei(u1, v1)
X2, Y2 = mont_to_wei(u2, v2)
X3, Y3 = mont_to_wei(u3, v3)
X4, Y4 = mont_to_wei(u4, v4)

P = E(X1, Y1)
Q = E(X2, Y2)
sP = E(X3, Y3)
tQ = E(X4, Y4)

# Finally we can solve the dlog
s = P.discrete_log(sP)
t = Q.discrete_log(tQ)

# This should be the flag, but s is broken
print(long_to_bytes(s))
print(long_to_bytes(t))

# b'\x05\x9e\x92\xbfO\xdf1\x16\xb0>s\x93\xc6\xc7\xe7\xa3\x80\xf0'
# b'Ds_3LlipT!c_CURv3'

# No idea why we need to do this... 
print(long_to_bytes(s % Q.order()))
print(long_to_bytes(t))

# b'nOt_50_3a5Y_Edw4r'
# b'Ds_3LlipT!c_CURv3'
```

##### Flag

`CCTF{nOt_50_3a5Y_Edw4rDs_3LlipT!c_CURv3}`


## Robert
##### 194 pts (19/444 solves)
### Challenge

> Oh, Robert, you can always handle everything!
`nc 07.cr.yp.toc.tf 10101`

Upon connection, we see
```
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
+   hi all, all cryptographers know that fast calculation is not easy! +
+   In each stage for given integer m, find number n such that:        +
+   carmichael_lambda(n) = m, e.g. carmichael_lambda(2021) = 966       +
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
| send an integer n such that carmichael_lambda(n) = 52: 
```
where we can of course assume we will need to pass a certain number of rounds, and the numbers will grow.

### Solution

Early on, we find [this math stackexchange post](https://math.stackexchange.com/questions/41061/what-is-the-inverse-of-the-carmichael-function), where we already make the comment

> looks hard

as, in general, this problem appears to be at least as hard as factoring $m$.
We consider the possibility of factoring $m$ and applying a dynamic programming based approach to group the prime factors of $m$ among the prime factors of what would be $n$.
In the end, this did not get implemented, as our intermediate attempts at cheesy solutions converge towards a simpler approach that solves the challenge.
The first of these cheesy attempts comes from 3m4 -- while setting the basis for further server communication scripts -- where we simply cross our fingers and hope that $m + 1$ is prime, leading to $n = m + 1$ and $\lambda(n) = m$.
While this clears up to 6 rounds on numerous occasions, it appears we'd need to either hammer the server really hard, or find something better.
Somewhere during this period of running our cheesy script full of hope, dd suggests that we might be in a situations where $m$ is known to be derived from a semiprime originally, i.e. $m = \lambda(pq)$.
Alongside this idea, an attempted solution exploiting that property is proposed, that unfortunately has several flaws and doesn't work against the server.

Basing ourselves on this idea, we can however write the dumbest sage script imaginable for this problem:
- Let $D$ be the set of divisors of $m$
- Enumerate all $(a, b) \in D^2$
- If $a + 1$ is prime, $b + 1$ is prime, *and* $\mathsf{lcm}(a, b) = m$: reply with $n = (a + 1)(b + 1)$

Clearly, *if* our assumed property that $m = \lambda(pq)$ holds, and $m$ does not grow too large to enumerate $D^2$, this should give us a correct solution.

Without all too much hope, we run the following sage script (with the `DEBUG` command line argument for pwntools, so that we can observe the flag should it get sent at the end):

```python
import os
os.environ["PWNLIB_NOTERM"] = "true"

from pwn import remote
io = remote("07.cr.yp.toc.tf", 10101)


io.recvuntil(b"++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
io.recvuntil(b"++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++")

proof.arithmetic(False)
def reverse_lambda(n):
    for x in divisors(n):
        for y in divisors(n):
            if lcm(x, y) == n and is_prime(x + 1) and is_prime(y + 1):
                return (x + 1) * (y + 1)
        
try:
    while True:
        io.recvuntil(b"carmichael_lambda(n) = ")
        integer = ZZ(io.recvuntil(b":")[:-1])
        print(f"[*] Reversed: {integer} ->", end=" ", flush=True)
        rev = reverse_lambda(integer)
        print(f"{rev}")
        io.sendline(str(rev).encode())
except EOFError:
    print("EOF")
```

Against our initial expectations, we easily clear more than 10 rounds.
Slowing down on an occasional $m$ that might have been hard to factor or have a lot of different divisors, the script happily chugs along without the server closing the connection on it, eventually getting the flag after 20 rounds.

##### Flag
`CCTF{Carmichael_numbers_are_Fermat_pseudo_primes}`


## Trunc

### Challenge
> I wish I could say more, but I don't want to!
`nc 02.cr.yp.toc.tf 23010`

- [TRUNC.txz](https://cr.yp.toc.tf/tasks/TRUNC_dd1e2d91b790125fdfc7596f0076fa476446d2fb.txz)

```python
#!/usr/bin/env python3

from Crypto.Util.number import *
from hashlib import sha256
import ecdsa
from flag import FLAG

E = ecdsa.SECP256k1
G, n = E.generator, E.order

cryptonym = b'Persian Gulf'

def keygen(n, G):
    privkey = getRandomRange(1, n-1)
    pubkey = privkey * G
    return (pubkey, privkey)

def sign(msg, keypair):
    nbit, dbit = 256, 25
    pubkey, privkey = keypair
    privkey_bytes = long_to_bytes(privkey)
    x = int(sha256(privkey_bytes).hexdigest(), 16) % 2**dbit
    while True:
        k, l = [(getRandomNBitInteger(nbit) << dbit) + x for _ in '01']
        u, v = (k * G).x(), (l * G).y()
        if u + v > 0:
            break
    h = int(sha256(msg).hexdigest(), 16)
    s = inverse(k, n) * (h * u - v * privkey) % n
    return (int(u), int(v), int(s))

def verify(msg, pubkey, sig):
    if any(x < 1 or x >= n for x in sig):
        return False
    u, v, s = sig
    h = int(sha256(msg).hexdigest(), 16)
    k, l = h * u * inverse(s, n), v * inverse(s, n)
    X = (k * G + (n - l) * pubkey).x()
    return (X - u) % n == 0

def die(*args):
    pr(*args)
    quit()

def pr(*args):
    s = " ".join(map(str, args))
    sys.stdout.write(s + "\n")
    sys.stdout.flush()

def sc():
    return sys.stdin.readline().strip()

def main():
    border = "+"
    pr(border*72)
    pr(border, " hi all, welcome to the high secure elliptic curve signature oracle!", border)
    pr(border, " Your mission is to sign the out cryptonym, try your best :)        ", border)
    pr(border*72)

    keypair = keygen(n, G)
    pubkey, privkey = keypair

    while True:
        pr("| Options: \n|\t[P]rint the pubkey \n|\t[S]ign \n|\t[V]erify \n|\t[Q]uit")
        ans = sc().lower()
        if ans == 'p':
            pr("| pubkey =", pubkey.x(), pubkey.y())
        elif ans == 's':
            pr("| send your hex message to sign: ")
            msg = sc()
            try:
                msg = bytes.fromhex(msg)
            except:
                die("| your message is not valid! Bye!!")
            if msg == cryptonym:
                die('| Kidding me? Bye')
            msg = msg[:14]
            sig = sign(msg, keypair)
            pr("| sign =", sig)
        elif ans == 'v':
            pr("| send your hex message to verify: ")
            msg = sc()
            try:
                msg = bytes.fromhex(msg)
            except:
                die("| your message is not valid! Bye!!")
            pr("| send the signature separated with comma: ")
            sig = sc()
            try:
                sig = [int(s) for s in sig.split(',')]
            except:
                die("| your signature is not valid! Bye!!")
            if verify(msg, pubkey, sig):
                if msg == cryptonym:
                    die("| Good job! Congrats, the flag is:", FLAG)
                else:
                    pr("| your message is verified!!")
            else:
                die("| your signature is not valid! Bye!!")
        elif ans == 'q':
            die("Quitting ...")
        else:
            die("Bye ...")

if __name__ == '__main__':
    main()
```

### Solution
Here we have a ECDSA-like signature scheme: nonces $k$ and $l$ are generated in such a way, that they always have their 25 LSBs dependent only on private key, thus always the same, then $u$ and $v$ are obtained as $x$-coordinates of $k * G$ and $l * G$ respectively, where $G$ is a generator on the curve `secp256k1`, then $h$ = `sha256(msg)` and $s \equiv k^{-1}*(hu - vd) \mod n$ are computed, where $d$ is the private key and $n$ is the order of the curve. $(u, v, s)$ is a signature for $h$.
Verification works as follows: again, $h$ = `sha256(msg)` is computed, then $k \equiv hus^{-1} \mod n$ and $l \equiv vs^{-1} \mod n$ are computed, after that $X$ is derived as $x$-coordinate of $k * G - l * P$, where $P = G * d$ is the public key. Signature verifies iff $X \equiv u \mod n$.
During interaction with the service we can obtain the public key by sending `p`, sign any message (except `Persian Gulf`) by sending `s`, verify a signature for a message with `v`, and if the signature for `Persian Gulf` verifies, we are given the flag, and quit with `q`.
This is an unintended solution, which doesn't exploit odd nonce generation during signature creation.
If $h_1$ is a hash of some message $m$, and $h_2$ is the hash for `Persian Gulf`, we can write $h_2 \equiv m*h_1 \mod n$, and if $(u_1, v_1, s_1)$ is a valid signature for $h_1$, then $(u_1, v_1m, s_1m)$ is a valid signature for $h_2$.
Proof: during verification of $h_1$ we have $k \equiv h_1u_1s_1^{-1} \mod n$ and $l \equiv v_1s_1^{-1} \mod n$. During verification of $h_2$ we have $k \equiv h_1mu_1(ms_1)^{-1} \equiv h_1mu_1m^{-1}s_1^{-1} \equiv h_1u_1s_1^{-1}\mod n$ and $l \equiv v_1m(s_1m)^{-1} \equiv v_1ms_1^{-1}m^{-1} \equiv v_1s_1^{-1}\mod n$, so $k, l$ are the same, thus $X$ is the same. And since $u$ is also the same, this signature will also verify.

#### Implementation

```python
#!/usr/bin/env python3
from pwn import remote
from ecdsa import SECP256k1
from hashlib import sha256

n = SECP256k1.order
m1 = b'lol' # any other message is fine
m2 = b'Persian Gulf'
h1 = int(sha256(m1).hexdigest(), 16)
h2 = int(sha256(m2).hexdigest(), 16)
m = h2 * pow(h1, -1, n) % n
r = remote("02.cr.yp.toc.tf", 23010)
for _ in range(9):
    r.recvline()
r.sendline('s')
r.recvline()
r.sendline(m1.hex())
u1, v1, w1 = eval(r.recvline()[8:])
u2, v2, w2 = u1, v1 * m % n, w1 * m % n
for _ in range(5):
    r.recvline()
r.sendline('v')
r.recvline()
r.sendline(m2.hex())
r.recvline()
r.sendline(','.join(map(str, [u2, v2, w2])))
print(r.recvline().decode().strip().split()[-1])
r.close()
```
##### Flag

`CCTF{__ECC_Bi4seD_N0nCE_53ns3_LLL!!!}`


## My Sieve
### Challenge
> We have captured one of the most brilliant spies who successfully broke a private key! All the [information](https://cr.yp.toc.tf/tasks/recovered_54f706f7fb8fc9718a4600d0000987ea4bcb03d8.txz) gathered and we believe they are enough to reconstruct the way he used to break the key. Now, can you help us to find the secret message?

We are given the encrypted flag:

```
enc = 17774316754182701043637765672766475504513144507864625935518462040899856505354546178499264702656639970102754546327338873353871389580967004810214134215521924626871944954513679198245322915573598165643628084858678915415521536126034275104881281802618561405075363713125886815998055449593678564456363170087233864817
```

A corrupted pem file:

```
-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCB*QKBgQCkRgRCyTcSwlBKmERQV/BHkurS
5QnYz7Rm18OjxuuWT3A*Ueqzq7fHISey2NEEtral/*E7v2Dy59DYHoRAAouWQd03
ZYWnvU5mWoYRcpNmHIj8q*+FOtBWcCGzMZ8uxOxaV74vqqerjxyRI14rXZ+QOcNM
/TMM84h0rl/IKqqWsQIDAQAB
-----END PUBLIC KEY-----
```

and a `msieve.dat` file, which is a file outputted while using msieve https://github.com/radii/msieve.

### Solution

#### Msieve

Looking at the data file, we see that a `~350` bit number

```
0x1dabd3bb8e99101030cd7094eb15dd525cb0f02065694604071c2a8b10228f30cc12d08fc9caa8d97c65ff481
```

 was factored. We can recover the factors using the command:

```
./msieve 17012713766362055606937340593828012836774345940104644978558327325254454345526470012917476548051189037528193
```

where we must ensure the data file is in the correct directory. Looking into the log file we find:

```
Fri Jul 30 19:34:05 2021  Msieve v. 1.46
Fri Jul 30 19:34:05 2021  random seeds: 98cfb443 69ab82cc
Fri Jul 30 19:34:05 2021  factoring 17012713766362055606937340593828012836774345940104644978558327325254454345526470012917476548051189037528193 (107 digits)
Fri Jul 30 19:34:06 2021  no P-1/P+1/ECM available, skipping
Fri Jul 30 19:34:06 2021  commencing quadratic sieve (106-digit input)
Fri Jul 30 19:34:06 2021  using multiplier of 11
Fri Jul 30 19:34:06 2021  using generic 32kb sieve core
Fri Jul 30 19:34:06 2021  sieve interval: 39 blocks of size 32768
Fri Jul 30 19:34:06 2021  processing polynomials in batches of 6
Fri Jul 30 19:34:06 2021  using a sieve bound of 4223251 (149333 primes)
Fri Jul 30 19:34:06 2021  using large prime bound of 633487650 (29 bits)
Fri Jul 30 19:34:06 2021  using double large prime bound of 6968329308179250 (45-53 bits)
Fri Jul 30 19:34:06 2021  using trial factoring cutoff of 53 bits
Fri Jul 30 19:34:06 2021  polynomial 'A' values have 14 factors
Fri Jul 30 19:34:06 2021  restarting with 35905 full and 2217078 partial relations
Fri Jul 30 19:34:06 2021  149536 relations (35905 full + 113631 combined from 2217078 partial), need 149429
Fri Jul 30 19:34:07 2021  begin with 2252983 relations
Fri Jul 30 19:34:07 2021  reduce to 393304 relations in 11 passes
Fri Jul 30 19:34:07 2021  attempting to read 393304 relations
Fri Jul 30 19:34:08 2021  recovered 393304 relations
Fri Jul 30 19:34:08 2021  recovered 385553 polynomials
Fri Jul 30 19:34:08 2021  attempting to build 149536 cycles
Fri Jul 30 19:34:08 2021  found 149535 cycles in 5 passes
Fri Jul 30 19:34:08 2021  distribution of cycle lengths:
Fri Jul 30 19:34:08 2021     length 1 : 35905
Fri Jul 30 19:34:08 2021     length 2 : 25563
Fri Jul 30 19:34:08 2021     length 3 : 24612
Fri Jul 30 19:34:08 2021     length 4 : 20585
Fri Jul 30 19:34:08 2021     length 5 : 15651
Fri Jul 30 19:34:08 2021     length 6 : 10638
Fri Jul 30 19:34:08 2021     length 7 : 6982
Fri Jul 30 19:34:08 2021     length 9+: 9599
Fri Jul 30 19:34:08 2021  largest cycle: 19 relations
Fri Jul 30 19:34:08 2021  matrix is 149333 x 149535 (43.3 MB) with weight 10166647 (67.99/col)
Fri Jul 30 19:34:08 2021  sparse part has weight 10166647 (67.99/col)
Fri Jul 30 19:34:09 2021  filtering completed in 3 passes
Fri Jul 30 19:34:09 2021  matrix is 143467 x 143531 (41.8 MB) with weight 9815366 (68.38/col)
Fri Jul 30 19:34:09 2021  sparse part has weight 9815366 (68.38/col)
Fri Jul 30 19:34:09 2021  saving the first 48 matrix rows for later
Fri Jul 30 19:34:09 2021  matrix is 143419 x 143531 (24.4 MB) with weight 7565741 (52.71/col)
Fri Jul 30 19:34:09 2021  sparse part has weight 4961307 (34.57/col)
Fri Jul 30 19:34:09 2021  matrix includes 64 packed rows
Fri Jul 30 19:34:09 2021  using block size 57412 for processor cache size 65536 kB
Fri Jul 30 19:34:09 2021  commencing Lanczos iteration
Fri Jul 30 19:34:09 2021  memory use: 24.2 MB
Fri Jul 30 19:34:10 2021  linear algebra at 4.2%, ETA 0h 0m
Fri Jul 30 19:34:34 2021  lanczos halted after 2270 iterations (dim = 143416)
Fri Jul 30 19:34:34 2021  recovered 16 nontrivial dependencies
Fri Jul 30 19:34:35 2021  p2 factor: 11
Fri Jul 30 19:34:35 2021  prp53 factor: 37517726695590864161261967849116722975727713562769161
Fri Jul 30 19:34:35 2021  prp53 factor: 41223455646589331474862018682296591762663841134030283
Fri Jul 30 19:34:35 2021  elapsed time 00:00:30
```

and so we have the three factors of the number:

```
Fri Jul 30 19:34:35 2021  p2 factor: 11
Fri Jul 30 19:34:35 2021  prp53 factor: 37517726695590864161261967849116722975727713562769161
Fri Jul 30 19:34:35 2021  prp53 factor: 41223455646589331474862018682296591762663841134030283
```

Now the question was, how does this 350 bit integer relate to the corrupted public key?

#### Corrupted Key

Looking at the corrupted key, we see 4 `*` though the file. This means naively we have `64**4` different `N` which are valid. The assumption was that one of these `N` would share factors the factored number from msieve.

Looking into the pem format, we actually find the first character must be `i` and so only three chr remain to be searched through. To try and find the correct `N` we looked for `gcd(X,N)!=0` for all possible keys:

```python
from math import gcd

corrupt_N = 0xa4460442c93712c2504a98445057f04792ead2e509d8cfb466d7c3a3c6eb964f700051eab3abb7c72127b2d8d104b6b6a5fc013bbf60f2e7d0d81e8440028b9641dd376585a7bd4e665a86117293661c88fca80f853ad0567021b3319f2ec4ec5a57be2faaa7ab8f1c91235e2b5d9f9039c34cfd330cf38874ae5fc82aaa96b1
X = 0x1dabd3bb8e99101030cd7094eb15dd525cb0f02065694604071c2a8b10228f30cc12d08fc9caa8d97c65ff481
offsets = [356, 620, 752]

for a in range(64):
    for b in range(64):
        for c in range(64):
            N = corrupt_N | (a<<offsets[0]) | (b<<offsets[1]) | (c<<offsets[2])
            if gcd(N, X) > 2**32:
                print("w00t")
                print(a, b, c)
                print(N)
                print(gcd(N, X))
```

However, running this script we found no values of `N` which had `X`, or a factor of `X` as a common divisor. The rest of the CTF we tried guessing other things, but nothing worked out.

During the CTF, this was solved once, by HXP, who solved it by using `X//11` as the public key:

```python
from Crypto.Util.number import *                                                                                  
p = 37517726695590864161261967849116722975727713562769161
q = 41223455646589331474862018682296591762663841134030283
N = p*q
phi = (p-1)*(q-1)
e = 0x10001
d = pow(e,-1,phi)
enc = 17774316754182701043637765672766475504513144507864625935518462040899856505354546178499264702656639970102754546327338873353871389580967004810214134215521924626871944954513679198245322915573598165643628084858678915415521536126034275104881281802618561405075363713125886815998055449593678564456363170087233864817                            
flag = long_to_bytes(pow(enc,d,N))
print(flag)           
# b'CCTF{l34Rn_WorK_bY__Msieve__A5aP}'
```

This was an unintended solution, and worked as the flag was small enough. Seeing this, it's dissapointing that we didnt try this guess, but we were so sure the .pem was needed for the solve, I guess this didnt occur to any of us.

### True Solution

After the CTF ended, the real pem was released. 

```
$ cat pubkey.pem 
-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCkRgRCyTcSwlBKmERQV/BHkurT
5QnYz7Rm18OjxuuWT3AhUeqzq7fHISey2NEEtral/jE7v2Dy59DYHoRAAouWQd02
ZYWnvU5mWoYRcpNmHIj8qk+FOtBWcCGzMZ8uxOxaV74vqqerjxyRI14rXZ+QOcNL
/TMM84h0rl/IKqqWsQIDAQAB
-----END PUBLIC KEY-----

$ cat pubkey_corrupted.pem 
-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCB*QKBgQCkRgRCyTcSwlBKmERQV/BHkurS
5QnYz7Rm18OjxuuWT3A*Ueqzq7fHISey2NEEtral/*E7v2Dy59DYHoRAAouWQd03
ZYWnvU5mWoYRcpNmHIj8q*+FOtBWcCGzMZ8uxOxaV74vqqerjxyRI14rXZ+QOcNM
/TMM84h0rl/IKqqWsQIDAQAB
-----END PUBLIC KEY-----
```

It turns out that `N` was corrupted not only in the four `*` throughout the file, but additionally the chracaters at the end of the first three lines were also modified... Using the correct pem we find:

```python
x = 17012713766362055606937340593828012836774345940104644978558327325254454345526470012917476548051189037528193
n = 115356776450250827754686976763822189563265178727141719602571509315861796708491086355344129261506721466097001689191320289269213116060519988849918021824941560396659801251826221296538423055226122464968459205865316769204109964482429845998764457962631301677585992875791654646257335269595789163018282966936558671537
print(gcd(x, n))
# 1546610342396550509721576417620728439706758721827694998050757029568586758684224546628861504368289912502563
```

and so our idea was right, but we didnt not understand all the changes. Essentially after factoring `X` with msieve, the challenge was to replace all `*` and also know to modify the end of each line. If you have any intuition on why this is the case, I would love to know.

##### Flag

`CCTF{l34Rn_WorK_bY__Msieve__A5aP}`


## DoRSA
### Challenge

> Fun with RSA, this time [two times](https://cr.yp.toc.tf/tasks/DoRSA_17cab1318229a0207b1648615db1edc6497f8b62.txz)!

```python
#!/usr/bin/env python3

from Crypto.Util.number import *
from math import gcd
from flag import FLAG

def keygen(nbit, dbit):
    assert 2*dbit < nbit
    while True:
        u, v = getRandomNBitInteger(dbit), getRandomNBitInteger(nbit // 2 - dbit)
        p = u * v + 1
        if isPrime(p):
            while True:
                x, y = getRandomNBitInteger(dbit), getRandomNBitInteger(nbit // 2 - dbit)
                q = u * y + 1
                r = x * y + 1
                if isPrime(q) and isPrime(r):
                    while True:
                        e = getRandomNBitInteger(dbit)
                        if gcd(e, u * v * x * y) == 1:
                            phi = (p - 1) * (r - 1)
                            d = inverse(e, phi)
                            k = (e * d - 1) // phi
                            s = k * v + 1
                            if isPrime(s):
                                n_1, n_2 = p * r, q * s
                                return (e, n_1, n_2)

def encrypt(msg, pubkey):
    e, n = pubkey
    return pow(msg, e, n)

nbit, dbit = 1024, 256

e, n_1, n_2 = keygen(nbit, dbit)

FLAG = int(FLAG.encode("utf-8").hex(), 16)

c_1 = encrypt(FLAG, (e, n_1))
c_2 = encrypt(FLAG, (e, n_2))

print('e =', e)
print('n_1 =', n_1)
print('n_2 =', n_2)

print('enc_1 =', c_1)
print('enc_2 =', c_2)
```

```
e = 93546309251892226642049894791252717018125687269405277037147228107955818581561
n_1 = 36029694445217181240393229507657783589129565545215936055029374536597763899498239088343814109348783168014524786101104703066635008905663623795923908443470553241615761261684865762093341375627893251064284854550683090289244326428531870185742069661263695374185944997371146406463061296320874619629222702687248540071
n_2 = 29134539279166202870481433991757912690660276008269248696385264141132377632327390980628416297352239920763325399042209616477793917805265376055304289306413455729727703925501462290572634062308443398552450358737592917313872419229567573520052505381346160569747085965505651160232449527272950276802013654376796886259
enc_1 = 4813040476692112428960203236505134262932847510883271236506625270058300562795805807782456070685691385308836073520689109428865518252680199235110968732898751775587988437458034082901889466177544997152415874520654011643506344411457385571604433702808353149867689652828145581610443408094349456455069225005453663702
enc_2 = 2343495138227787186038297737188675404905958193034177306901338927852369293111504476511643406288086128052687530514221084370875813121224208277081997620232397406702129186720714924945365815390097094777447898550641598266559194167236350546060073098778187884380074317656022294673766005856076112637129916520217379601
```

Basically, we have $$ p = uv + 1, \quad q = uy + 1, \quad r = xy + 1, \quad s = kv + 1$$
where $p, q, r, s$ are all primes. Also, $\phi = (p-1)(r-1) = uvxy$ and $ed \equiv 1 \pmod \phi$. 
$k$ is calculated by $k = (ed - 1)/\phi$. It is notable that $e$ is $256$ bits. 

Our goal is to decrypt RSA-encrypted messages, so we need to find one of $\phi(n_1)$ or $\phi(n_2)$. 

### Solution

Not so long after starting this problem, rbtree suggested using continued fractions with $$ n_2 / n_1 \approx k / x $$ Indeed, we see that $$ \frac{n_2}{n_1} = \frac{qs}{pr} = \frac{(uy+1)(kv+1)}{(uv+1)(xy+1)} \approx \frac{uykv}{uvxy} = \frac{k}{x}$$ and their difference is quite small, as $$ \frac{n_2}{n_1} - \frac{k}{x} = \frac{(uy+1)(kv+1)x - (uv+1)(xy+1)k}{x(uv+1)(xy+1)} $$ and the numerator is around $256 \times 3$ bits, and the denominator is around $256 \times 5$ bits. 

Note that $k/x$ has denominator around 256 bits, and it approximates $n_2/n_1$ with difference around $2^{-512}$. If you know the proof for Wiener's Attack (highly recommend you study it!) you know that this implies that $k/x$ must be one of the continued fractions of $n_2/n_1$. Now, we can get small number of candidates for $k/x$. We also further assumed $\gcd(k, x) = 1$. If we want to remove this assumption, it is still safe to assume that $\gcd(k, x)$ is a small integer, and brute force all possible $\gcd(k, x)$ as well. Now we have a small number of candidates for $(k, x)$. 

I finished the challenge by noticing the following three properties.

First, $k \phi + 1 \equiv 0 \pmod{e}$, so that gives $256$ bit information on $e$. 

Second, $\phi \equiv 0 \pmod x$, so that gives another $256$ bit information on $x$. 

Finally, $|\phi - n_1| = |(p-1)(r-1) - pr| \approx p + r \le 2^{513}$. 

Therefore, we can use the first two facts to find $\phi \pmod{ex}$.
Since $ex$ is around $512$ bits, we can get a small number of candidates for $\phi$ using the known bound for $\phi$. If we know $\phi$, we can easily decrypt $c_1$ to find the flag.



```python
from Crypto.Cipher import AES, PKCS1_OAEP, PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Util.number import inverse, long_to_bytes, bytes_to_long, isPrime, getPrime, GCD
from tqdm import tqdm
from pwn import *
from sage.all import *
import itertools, sys, json, hashlib, os, math, time, base64, binascii, string, re, struct, datetime, subprocess
import numpy as np
import random as rand
import multiprocessing as mp
from base64 import b64encode, b64decode
from sage.modules.free_module_integer import IntegerLattice
from ecdsa import ecdsa

def inthroot(a, n):
    if a < 0:
        return 0
    return a.nth_root(n, truncate_mode=True)[0]

def solve(n, phi):
    tot = n - phi + 1
    dif = inthroot(Integer(tot * tot - 4 * n), 2)
    dif = int(dif)
    p = (tot + dif) // 2
    q = (tot - dif) // 2
    if p * q == n:
        return p, q
    return None, None

e = 93546309251892226642049894791252717018125687269405277037147228107955818581561
n_1 = 36029694445217181240393229507657783589129565545215936055029374536597763899498239088343814109348783168014524786101104703066635008905663623795923908443470553241615761261684865762093341375627893251064284854550683090289244326428531870185742069661263695374185944997371146406463061296320874619629222702687248540071
n_2 = 29134539279166202870481433991757912690660276008269248696385264141132377632327390980628416297352239920763325399042209616477793917805265376055304289306413455729727703925501462290572634062308443398552450358737592917313872419229567573520052505381346160569747085965505651160232449527272950276802013654376796886259
enc_1 = 4813040476692112428960203236505134262932847510883271236506625270058300562795805807782456070685691385308836073520689109428865518252680199235110968732898751775587988437458034082901889466177544997152415874520654011643506344411457385571604433702808353149867689652828145581610443408094349456455069225005453663702
enc_2 = 2343495138227787186038297737188675404905958193034177306901338927852369293111504476511643406288086128052687530514221084370875813121224208277081997620232397406702129186720714924945365815390097094777447898550641598266559194167236350546060073098778187884380074317656022294673766005856076112637129916520217379601

c = continued_fraction(Integer(n_2) / Integer(n_1))

for i in tqdm(range(1, 150)):
    k = c.numerator(i)
    x = c.denominator(i)
    if GCD(e, k) != 1:
        continue
    res = inverse(e - k, e)
    cc = crt(res, 0, e, x)
    md = e * x // GCD(e, x)

    st = cc + (n_1 // md) * md - 100 * md
    for j in range(200):
        if GCD(e, st) != 1:
            st += md
            continue 
        d_1 = inverse(e, st)
        flag = long_to_bytes(pow(enc_1, d_1, n_1))
        if b"CCTF" in flag:
            print(flag)
        st += md
```

##### Flag

`CCTF{__Lattice-Based_atT4cK_on_RSA_V4R1aN75!!!}`


## Polish
### Challenge

> Maybe this time we should focus on important parts of [RSA](https://cr.yp.toc.tf/tasks/polish_attack_de0955bc42af9591300a30c39dc74aaceea2451d.txz)!

```python
m = bytes_to_long(flag)

e = 65537

n = p * q
  = 40246250034008312612597372763167482121403594640959033279625274444300931999548988739160328671767018778652394885185401059130887869211330599272113849088780129624581674441314938139267245340401649784020787977993123159165051168187958742107

d = 0b1[REDACTED]00001101110000010101000000101110000111101011011101111111000011110101111000100001011100001111011000010101010010111100000011000101000001110001111100001011001100010001100000011100001101101100011101000001010001100000101000001

c = pow(x**2 + m + y, e, n)
  = 28505561807082805875299833176536442119874596699006698476186799206821274572541984841039970225569714867243464764627070206533293573878039612127495688810559746369298640670292301881186317254368892594525084237214035763200412059090430060075

x**2 * (y - 146700196613209180651680280746469710064760660116352037627587109421827052580531) + y**2 * (x - 146700196613209180651680280746469710064760660116352037627587109421827052580531) = 27617741006445293346871979669264566397938197906017433294384347969002810245774095080855953181508639433683134768646569379922750075630984038851158577517435997971553106764846655038664493024213691627948571214899362078353364358736447296943
```

We have $n$ which we probably need to factor, along with $221$ LSBs of $d$. We also have a diophantine to solve in order to get $x, y$. If we factorize $n$ and find $x, y$, we can compute the flag. 

### Factorization of $n$

It's known that with lower $1/4$ bits of $d$, we can factorize $n$ in polynomial time of $e$. To learn how, check out Theorem 9 on [Twenty Years of Attacks on the RSA Cryptosystem](https://crypto.stanford.edu/~dabo/papers/RSA-survey.pdf). 
Basically, we can compute $\mathcal{O}(e \log_2 e)$ candidates for the lower half bits of $p$ by solving some quadratic congruences, which we can apply Coppersmith afterwards to factorize $n$. 

TODO : it would be great if someone could write about how to solve the quadratic congruences

### Solving the Diophantine

We start by writing the equation as $$x^2(y-a) + y^2(x-a) = b$$ To solve this, we substitute $$u = x+y, \quad v = xy$$ and rewrite our equation as $$xy(x+y) - a(x^2+y^2) = b$$ $$uv - a(u^2 - 2v) = b$$ $$(u+2a) v = au^2 + b$$ $$v = \frac{au^2 + b}{u + 2a}$$

Performing long division, we see that $$v = au - 2a^2 + \frac{4a^3 + b}{u + 2a}$$ This shows that $u + 2a$ is a factor of $4a^3 + b$. 
Therefore, it makes sense to try and factorize $4a^3 + b$ to compute the possible values for $u$. 

Surprisingly, it turns out that $$ 4a^3 + b = n$$

Now we see that factorization of $n$ solves the problem. Since $n = pq$ has four divisors, we have a small number of candidates for $u+2a$. For each candidate, we can compute $u$, then compute $v$. From $u, v$, we can solve a quadratic to find $x, y$. Then, we can compute the flag. 

### Back to Factorization of $n$ 

rbtree was writing the program to find the factorization of $n$. At first, we $n = pq$ would split evenly, i.e. both $p, q$ would have around $387$ bits.

In this case, after we compute (a candidate of) $221$ LSBs of $p$, we have to find the remaining $166$ MSBs of $p$. To utilize Coppersmith attack, we used SageMath's small_roots with $\beta = 0.5$ and $\epsilon$ that $$2^{166} \le \frac{1}{2} n^{\beta^2 - \epsilon}$$ We decided to use $\epsilon = 0.034$ and run the algorithm. 

However, while running this algorithm, I suggested that $n = pq$ will not split evenly. 

The logic is that one of the factors of $n$ would be $u + 2a$. If we guess that $x$ and $y$ have similar size, we would have something like $x \sim y \sim M$ where $M$ is the value such that $$2 M^2(M-a) = b$$ Since $b \sim a^3$ we would also have $M \sim a$ which implies $u + 2a \sim a$ as well. Here, $A \sim B$ when $A, B$ have a similar size, i.e. $\max(A, B) / \min(A, B)$ is a small value. 

Since $a$ has around $256$ bits, what this means is that $u + 2a$ also has around $256$ bits, i.e. one of $p, q$ has around $256$ bits. Therefore, if our guess is correct, then $n$, which is $773$ bits, is composed of something like $258$ bit $p$ and $515$ bit $q$. This changes how we have to choose $\beta$ and $\epsilon$. 

In the end, we have chosen $\beta = 0.33$ and $\epsilon = 0.05$ in the end and ran the algorithm with 20 cores.


```python
# Part 1 : Factorization of n, written by rbtree
# Also, multiprocess the code below with multiple cores for shorter computation time

e = 65537
n = 40246250034008312612597372763167482121403594640959033279625274444300931999548988739160328671767018778652394885185401059130887869211330599272113849088780129624581674441314938139267245340401649784020787977993123159165051168187958742107

mod = 2^221
d_low = 0b00001101110000010101000000101110000111101011011101111111000011110101111000100001011100001111011000010101010010111100000011000101000001110001111100001011001100010001100000011100001101101100011101000001010001100000101000001

def get_p(p_low):
    F.<z> = PolynomialRing(Zmod(n))

    f = mod * z + p_low
    f = f.monic()
    res = f.small_roots(beta=0.33, epsilon=0.05)

    if len(res) > 0:
        return 1
    return None

R.<x> = PolynomialRing(ZZ)
for k in range(1, e + 1):
    cands = [1]
    f = k * x^2 + (e*d_low - k*n - k - 1) * x + k * n
    for i in range(1, 221):
        new_cands = []
        for v in cands:
            if f(v) % 2^(i+1) == 0:
                new_cands.append(v)
            if f(v + 2^i) % 2^(i+1) == 0:
                new_cands.append(v + 2^i)
        
        cands = new_cands
        if len(new_cands) == 0:
            print("break", i)
            break

    print(k)
    print(cands)

    ret = None
    for v1 in cands:
        for v2 in cands:
            if v1 * v2 % mod != n % mod:
                continue
            ret = get_p(v1)
            break
        if ret is not None:
            break
    
    print(ret)
    if ret:
        break
```

```python
# Part 2 : Calculating the Flag

def inthroot(a, n):
    return a.nth_root(n, truncate_mode=True)[0]

n = 40246250034008312612597372763167482121403594640959033279625274444300931999548988739160328671767018778652394885185401059130887869211330599272113849088780129624581674441314938139267245340401649784020787977993123159165051168187958742107

a = 146700196613209180651680280746469710064760660116352037627587109421827052580531
b = 27617741006445293346871979669264566397938197906017433294384347969002810245774095080855953181508639433683134768646569379922750075630984038851158577517435997971553106764846655038664493024213691627948571214899362078353364358736447296943

assert n == 4 * a * a * a + b

# from rbtree's code with partial exposure attack on d
p = 893797203302975694226187727100454198719976283557332511256329145998133198406753
q = n // p

u = p - 2 * a
v = (a * u * u + b) // (u + 2 * a)
dif = inthroot(Integer(u * u - 4 * v), 2)

x = (u + dif) // 2
y = (u - dif) // 2

e = 65537 

c = 28505561807082805875299833176536442119874596699006698476186799206821274572541984841039970225569714867243464764627070206533293573878039612127495688810559746369298640670292301881186317254368892594525084237214035763200412059090430060075

d = inverse(e, (p-1) * (q-1))

res = pow(c, d, n)

print(long_to_bytes(res - x * x - y))
print(long_to_bytes(res - y * y - x))
```

##### Flag

`CCTF{Par7ial_K3y_Exp0sure_At7ack_0n_L0w_3xP_RSA}`