---
layout: post
title: "Finite Groups, Gaussian Integers & TetCTF 2021"
categories: CTF Write-up
permalink: tetctf-2021
meta: "Finite Groups, Gaussian Integers & TetCTF 2021"
author: Jack
tags: Finite-Fields, Gaussian-Integers, Writeup
---


Last weekend [TetCTF](https://ctf.hackemall.live/) held their new year CTF competition. I felt particularly nostalgic playing this, as it was the TetCTF 2020 CTF where Hyper and I played the crypto challenges and soon after decided to make CryptoHack together. Something about Ndh's crypto challenges really make me want to keep learning.

There are already very good write-ups from [rkm0959](https://rkm0959.tistory.com/192), [Mystify](https://mystiz.hk/posts/2021-01-03-tetctf-unevaluated/) and [TheBlueFlame](https://hackmd.io/@TheBlueFlame121/HJPbMVk0v) offering discussion of the cryptography challenges that Ndh created. This blog post sums up a few days of conversation in the [CryptoHack discord](https://discord.gg/eJaJ3xC), where several of us spent time trying to break these challenges into their fundamental pieces. I think the quality of the conversation about these challenges is testament to the beauty of Ndh's challenges as well as the impressive knowledge of the community.

The challenges implemented public-key crypto using Gaussian integers (more on these later). The first challenge  `Unimplemented` required writing the decrypt function for an RSA-like system. The second challenge `Unevaluated` required solving the discrete logarithm problem for Gaussian integers.  

In this blog post I'm aiming to cover the background behind finite groups and Gaussian integers which I think then allows for the solutions of these challenges to feel elegant. Note that a lot of what I cover here was first discussed in the Discord so many points were put forward first by other members of the community. 

The blog post got much longer than I anticipated. I hope it's entertaining / educational enough to carry through to the end, as I think these challenges are really worth understanding.

## Finite groups

Finite groups are an expansive topic, so this section won't act as as a total overview. There are CryptoHack challenges that cover parts of this, and maybe some more in the future. However, there are a few important concepts we will need.

In particular, I want to spend a small amount of time talking about the order (or size) of a finite group and the order of an element (or the size of the subgroup it generates). Understanding this is the key to being able to solve these challenges and Ndh's challenges give us a chance to think about these fundamental concepts in a new group, causing us to think carefully about exactly what we're computing when we're solving a challenge.

Let us continue this discussion with examples. Consider the field

$$
\mathbf{F}_p = \mathbb{Z} / p  \mathbb{Z} = \{ 0, 1, 2, \ldots p-1 \},
$$

which is the set of integers modulo some prime $p$.  Sometimes you will also see the field $\mathbf{F}\_p$ represented as $GF(p)$ and if you want to build this using Sage, you can call

```python
sage: p = 11
sage: F = GF(p)
sage: F
Finite Field of size 11
```

 A field is a ring with the additional property that every element has an additive and multiplicative (excluding zero) inverse. When compared to a group, a field is a set of elements which obey the group law axioms for two specific binary operations: addition and multiplication. To introduce the notion of the order of a group, let us consider these two operators $(+, \times)$ separately. 

#### Recap on groups

For a set $G$ to be considered as a group we require a binary operator $\circ$ such that the following properties hold

- **Closure**: For all $a,b \in G$,  the composition $a \circ b = c \in G$
- **Associativity**: $a \circ (b \circ c) = (a \circ b) \circ c$  for $a,b,c \in G$
- **Identity**: there exists an element $e$ such that $e \circ a = a \circ e = a$ for all $a \in G$
- **Inverse**: for every element $a \in G$ there is an element $b \in G$ such that $a \circ b = e$  

**Note**: when we discuss rings or fields we only consider the binary operation of addition and multiplication (and their inverses subtraction and division to use conventional terms). For groups, the composition law can be any operation which obeys these properties. As an example, consider a symmetry group of rotations which can be represented by matrices and the binary operation is matrix multiplication.

- **Commutative**: this is not a required property, but when a group has a binary operation such that $a \circ b = b \circ a$ we say the group is commutative. In my more familiar physics language, we refer to these groups as Abelian groups after the Norwegian mathematician Niels Abel.

### An introduction to orders

Let us first consider the group of integers $F_p^+ = (\mathbf{F}_p, +)$ which are the integers modulo $p$ with the group operation of addition. We know that addition is associative, and the identity element in addition is the number which when added "does nothing": $a + 0 = 0 + a = a$ for all $a \in F_p^+$. 

To verify the existence of an inverse for each element, we need elements such that $a + b = 0$ in the group, or more precisely $a + b \equiv 0 \mod p$. Put this way, the inverse is fairly obvious, and we understand $b = p - a$ such that 

$$
a + b = a + p - a = p \equiv 0 \mod p .
$$

Having recovered both the identity and inverse for this set of integers, we can understand $F_p^+$ as a group.

We say that the **order** of a group $(G, \circ)$ is the number of elements in $G$, which we denote $\|G\|$. For the example above there are $p$ elements in the group $F_p^+$, which are simply the integers from $\\{0,\ldots p-1\\}$, as such we know that $\|F_p^+\| = p$.

We say that the order of an element $a \in G$ is the smallest positive integer $k \in \mathbb{N}$ such that

$$
a^k = e, \quad a,e \in G.
$$


We use the notation of exponentiation for $k$ repeated operations of $\circ$. For the example above this may feel more conventional when written as

$$
\underbrace{(a + a + \ldots + a)}_{k-\text{times}} = k \times a = e.
$$

When the order of an element is equal to the order of the group, this element is called a *generator* of the group in the sense that repeated operation of the element on itself will generate the whole group. For our current example, a generator of the group is $1$ as 

$$
\underbrace{(1 + 1 + \ldots + 1)}_{p-\text{times}} = p \times 1 = p \equiv 0 \mod p.
$$

Not every element of $a \in G$ will be a generator, but will instead generate a subgroup with $k$ elements in. As a trivial example, consider the order of the element $e \in G$ which will always have order $k = 1$ as $e^1 = e$. [Lagrange's theorem](https://en.wikipedia.org/wiki/Lagrange%27s_theorem_(group_theory)) states that for any subgroup $H$ of a finite field $G$, the order of $H$ divides the order of $G$. An element of order $k$ is a generator for the subgroup $H$ with $k$ elements.

### Multiplicative groups

The additive example above is a nice way to cover what we mean when we talk about orders, but for the challenges we wish to solve we'll be working in multiplicative groups. Let us return to $\mathbf{F}_p$ and consider the group of integers modulo $p$ with the binary operation of multiplication. To match our previous discussion we denote this $F_p^\times = (F_p^\star, \times)$. 

Like addition, multiplication is associative and closure for multiplication modulo $p$ should feel natural. The identity element is now no longer $0$, but rather the unit: $1 \times a = a \times 1 = a$. The final piece we must check is that every element $a \in F_p^\times$ has an inverse. 

Notice that unlike the above example, we are considering $F_p^\star$ and not $\mathbf{F}_p$. The difference arises as to work with a group, **every element** must have an inverse. In $\mathbf{F}_p$, we have the element $0$, which was our identity in the additive group. However, under multiplication we have the issue of then needing to find an element $0 \times b \equiv 1 \mod p$ which we know is impossible as $0 \times a = 0$ $\forall a \in \mathbb{\mathbf{F}_p}$. We remedy this issue by instead considering the following set of integers modulo $p$

$$
F_p^\star = (\mathbb{Z} / p\mathbb{Z})^\star = \{1,2,\ldots, p-1\},
$$

where the superscript ${}^\star$ denotes that we have removed $0$ from out set. Sometimes this is written as $F_p^\star = F_p / \\{ 0\\}$. All that remains is that we ensure that every element $a \in F_p^\times$ has an inverse $b \in F_p^\times$ such that $a \times b \equiv 1 \mod p$. We are guaranteed a solution to  $a \times b \equiv 1 \mod p$ if and only if $\gcd(a,p) = 1$. In other words, $a,p$ must be coprime (share no common factors).

As $p$ is itself prime and all $a \in F_p^\times$ obey $a < p$, we are guaranteed that $\gcd(a,p) = 1$ and so every element has an inverse! We will come back to this soon when we consider $(\mathbb{Z} / n\mathbb{Z})^\star$ where $n$ is a composite integer.

The order of $F_p^\times$ is therefore $\|F_p^\times\| = (p-1)$ and we know that the elements of $a \in F_p^\times$ will have an order $k \| (p -1)$ from Lagrange's theorem. In multiplicative groups, we have that an element of order $k$ obeys 

$$
a^k \equiv 1 \mod p.
$$

You may already be aware of Fermat's little theorem that states

$$
a^{p-1} \equiv 1 \mod p.
$$

A generator of $F_p^\times$ has order $k = p-1$ and so in this case, we are simply talking of Fermat's little theorem. For elements with $k < (p-1)$ we can write $(p - 1) = k \times d$ for some integer $d \in \mathbb{N}$. We know that

$$
a^{(p-1)} = a^{kd} = (a^k)^d \equiv (1)^d \equiv 1 \mod p.
$$

This may appear as obvious, but it's worth understanding that taking an element to the power of the order of the group will necessarily return the identity of the group, even if the element itself has a different order.

This will come up again when we want to obtain

$$
a^f \equiv 1 \mod p,
$$

for an element $a \in (\mathbb{Z}[i] / n \mathbb{Z}[i])^\times$ when the order of $a$ is unknown (the element $a$ is itself unknown!) and we use that it is enough to use an $f$ which is a multiple of the element's order. The order of the group is the most natural choice. 

**Note**: For those who are already familiar with Diffie-Hellman key exchange, this discussion of elements in subgroups dividing the order might give you additional insight into why we call primes of the form $p = (2q + 1)$ *safe primes*, where $q$ itself is prime. The multiplicative group will have order $2q$ and so elements in the group will only ever have order $2$ or order $q$. This allows us to avoid small sub-group attacks, providing we don't use the element of order two as the generator!  

### Multiplicative group of integers modulo n 

The last example we consider is the set of integers modulo $n$, where $n \in \mathbb{N}$. The set of these integers is 

$$
\mathbb{Z} / n \mathbb{Z} = \{0,1,\ldots, n-1 \}.
$$

As before, multiplication modulo $p$ is associative and closed and our identity element is $1$. To work with a group though, we must ensure that every element in our set has an inverse. We know that this is only the case when

$$
\gcd(a, n) = 1, \qquad a \in \mathbb{Z} / n \mathbb{Z}, \;\; n \in \mathbb{N}.
$$

Taking this into account, we denote the multiplicative group as

$$
F_n^\times =  \{a  \in \mathbb{Z} / n \mathbb{Z} \;\;  | \;\; \gcd(a,n) = 1\}.
$$

The order of $F_n^\times$ is the number of integers $a < n$ which are coprime to $n$, which is computed by Euler's totient function $\phi(n)$.

#### Euler's totient function and RSA

Euler's totient function $\phi(n)$ counts the number of positive integers up to $n$ which are also coprime to $n$. In the special case when $n = p$ is prime, $\phi(p) = p-1$.

The totient function obeys a few interesting identities which will be of use to us

$$
\phi(mn) = \phi(m) \phi(n) \cdot \frac{d}{\phi(d)}, \qquad d = \gcd(m,n).
$$

In the special case when $\gcd(m,n) = 1$, this simplifies to

$$
\phi(mn) = \phi(m) \phi(n).
$$

When $n = m^k$ the totient simplifies as 

$$
\phi(n) = \phi(m^k) = m^{k-1} \phi(m).
$$

Using the totient $\phi(n)$, Fermat's little theorem can be generalised to composite modulus

$$
a^{\phi(n)} \equiv 1 \mod n \iff \gcd(a,n) = 1,
$$

which is known as Euler's theorem.

If you've solved an RSA challenge you're already familiar with this group! Here, the modulus $n = pq$ is a composite number made from two large primes and the message $m$ that we encode as our message is some $m \in F_n^\times$. 

To decrypt an RSA message 

$$
c = m^e \mod n,
$$

we commonly say that this is done by "factorising $n$". However what's really happening is all down to the derivation of the totient function. We know that

$$
m^{\phi(n)} \equiv 1 \mod n,
$$

from Euler's theorem. To decrypt this cryptosystem we need

$$
c^d = (m^e)^d \equiv m \mod n.
$$

We see that we can do this when $ed \equiv 1 \mod \phi(n)$. To solve the solution we simply need to compute

$$
d = e^{-1} \mod \phi(n),
$$

and this is easy to compute given that:

- $\gcd(e, \phi(n)) = 1$
- We know the value of $\phi(n)$

The first condition *should* be checked on encryption, the second condition is what keeps RSA secure. 

From the above relations, we have that $\phi(n) = \phi(p)\phi(q) = (p-1)(q-1)$. Now we see that given $\\{p,q,e,c\\}$ we can compute $\\{\phi(n), d\\}$ and from this obtain $m$. This is what we mean when we say to decrypt a message we must factor $n$ when solving an RSA challenge. The hardness of RSA comes from the hardness to compute $\phi(n)$ which is believed to be as hard as computing the prime factorisation of $n$. 

**Note**: I know this discussion covers things which seem simple, or off-topic, but it recapped something fundamental which I think is often overlooked when you're racing to solve an RSA challenge:

- Solving RSA requires finding a solution to $e d \mod \phi(n) \equiv 1$ and this is true for other multiplicative groups, the case we consider next being the Gaussian integers.

- We don't even need $\phi(n)$, all we really need is the order of the message $m$ as if we have

  $$
  m^k = 1 \mod n
  $$

  then we could solve $e d \mod k = 1$ and still decrypt the message. It just turns out $\phi(n)$ is what we use as given the prime factorisation of the modulus, this is very easy to compute (without the prime factorisation finding either $k$ or $\phi(n)$ is believed to be hard classically).

- Following this, the famous quantum algorithm developed by [Shor](https://en.wikipedia.org/wiki/Shor%27s_algorithm) doesn't factor $n$, but rather computes the order of the element in $F_n^\times$. From this we could derive the factors, but by that point we don't need to as we would only use the factors to then compute $\phi(n)$.

## Gaussian Integers

The common feature for the two challenges we're going to discuss is that instead of working with integers $a \in \mathbb{Z}$, we consider complex numbers with integer coefficients

$$
\mathbb{Z}[i] = \{a + i b \;\; | \;\;  a,b \in \mathbb{Z} \}, \qquad i^2 = -1.
$$

Complex numbers with integer coefficients are interesting enough that they get their own name, and are called Gaussian integers. 

The Gaussian integers are closed under both addition and multiplication and so form a commutative (Abelian) ring and can be considered as a subring of the field of complex numbers $\mathbb{C}$.

As with complex numbers, we say that the complex conjugate of $z = a + ib$ is $z^\star = a - ib$. The norm of a Gaussian integer is given by

$$
N(z) = z z^\star = a^2 -iab + iba - i^2 b^2 = a^2 + b^2.
$$

**Note**: there is a difference here between the norm and the absolute value of a complex number $\|z\| = \sqrt{a^2 + b^2}$ which may be more familiar to those of you who have studied complex numbers. If you're used to thinking in this way, we can think of $N(z) = \|z\|^2$.

We will return to the norm map shortly, as it will be vital in part of our solution for the second challenge.

### Wait where were we?

This post is already getting long, so let's try and refocus back onto the challenges we are interested in. For both problems, we consider the ring

$$
\mathbf{K} = \frac{\mathbb{Z}[i]}{n \mathbb{Z}[i]}, \qquad n \in \mathbb{N}.
$$

#### Unimplemented

Recover the message $m$ from

$$
c = m^e \mod n, \qquad {m,c \in \mathbf{K}}, \;\; {e,n} \in \mathbb{N},
$$

where $n = p^2 q^2$ and $p,q$ are large primes. The solution of this challenge requires finding the number of elements in multiplicative group formed from the elements of $\mathbf{K}$. We will solve this by computing the Euler totient $\phi(n)$ where we must find the number of relatively coprime Gaussian integers to $n$. 

#### Unevaluated

Recover the secret $k$ from

$$
P = G^k \mod n, \qquad P,G \in \mathbf{K}, \;\; k,n \in \mathbb{N},
$$

where $k$ is a 256 bit integer, and $n = p^2$ for $p$ a Gaussian prime of 128 bits. This requires solving the discrete logarithm problem. Like most challenges which require this, there are some tricks we can perform to make this computationally viable. Naively, the discrete logarithm problem for Gaussian integers modulo a Gaussian prime $p$ is the same as computing the discrete log in $GF(p^2)$.

Before jumping into the solutions for these problems, let's look at Gaussian integers in a bit more detail, focusing on the tools we'll need to solve the problems. In particular, what do we mean by Gaussian prime and how can we compute $\phi(n)$? What tricks can we use to offload computational difficulty of the DLP?

### Gaussian Primes

The Gaussian integers form a unique factorisation domain: any Gaussian integer can be unique factored into its Gaussian primes. This is in direct analogy with the  [fundamental theorem of arithmetic](https://en.wikipedia.org/wiki/Fundamental_theorem_of_arithmetic) for integers $n \in \mathbb{Z}$. In this section we overview the form of Gaussian primes in analogy to the integer primes.

Prime integers $p$ can be organised in the following way:

- $p = 2$
- $p \equiv 1 \mod 4$
- $p \equiv 3 \mod 4$

A prime integer $p$ is additionally a Gaussian prime if and only if $p \equiv 3 \mod 4$. The remaining prime integers are composite Gaussian integers are are uniquely decomposed into two Gaussian primes which are each other's conjugates.

The Gaussian primes $\pi = a + ib$ are in one of two forms:

- Either $a$ or $b$ is zero and $N(\pi) = p^2$ and $p$ is a prime integer of the form  $p \equiv 3 \mod 4$.
- Both $a$ and $b$ are non zero and $N(\pi) = p$ is an integer prime with **either** $p = 2$ or $p \equiv 1 \mod 4$.

#### Examples

The prime $p = 11 \equiv 3 \mod 4$ is a integer prime and a Gaussian prime. For the integers we have the units $u = \\{1, -1\\}$ and understand the prime factors $\\{11, -11\\}$ as identified when they differ only by a unit element. For Gaussian integers there are four units $u = \\{1,-1,i,-i\\}$ and so we identify the four prime factors $\\{11, -11, 11i, -11i\\}$.

The prime $p = 5 \equiv 1 \mod 4$ is a Gaussian integer which can be decomposed into two Gaussian primes $(1 + 2i)(1 - 2i)$. 

**Note**: another way of thinking about this is when we have some integer prime $p \not\equiv 3 \mod 4$ we can write $p = a^2 + b^2$ for $a,b \in \mathbb{N}$. 

As these two Gaussian integers are not related by multiplication of the units, we understand them as distinct Gaussian primes

$$
(1 + 2i) \equiv -(1 + 2i) \equiv (-2 + i) \equiv (2 - i), \\
(1 - 2i) \equiv -(1 - 2i) \equiv (-2 - i) \equiv (2 + i).
$$

When we consider $p = 2$, we have the Gaussian factorisation $2 = (1 + i)(1 - i) = i(1 - i)^2$. This is the only integer prime which can be represented as a square of a Gaussian prime. This is because $(1 + i)$ and $(1 - i)$ differ only by a unit: $i(1 - i) = (i - i^2) = (1 + i).$

**Note**: another way people talk about this is with the language of algebraic number theory. The Gaussian primes which are integer primes are said to be inert. The prime integers with $p \equiv 1 \mod 4$ are said to split. Finally, $p = 2$ is the unique prime integer for the Gaussian integers which ramifies. As it appears as a square, we say the *ramification index* is $e = 2$. For more information on the splitting of prime ideals, this Wikipedia page has an example with the [Gaussian integers](https://en.wikipedia.org/wiki/Splitting_of_prime_ideals_in_Galois_extensions#Example_—_the_Gaussian_integers).

#### Factorisation

Understanding the structure of the Gaussian primes, we can represent any Gaussian integer uniquely in the following form

$$
z = i^k \pi_1^{e_1} \ldots \pi_n^{e_n},
$$

where $\pi_i$ are Gaussian primes and $e_i$ are positive integers. Just like we can compute $\phi(n)$ with the prime factors of $n$, we can compute $\phi(z)$ with the prime factorisation of $z$. We will return to this when we consider the group of Gaussian integers mod $n$, which is the set of Gaussian integers with multiplicative inverses modulo $n$, whose order is counted by $\phi(n)$.

### The Norm Map

Above we mentioned that the norm of a Gaussian integer $z = a + i b$ is given by $N(z) = a^2 + b^2$. The [field norm](https://en.wikipedia.org/wiki/Field_norm) is a special map which is a group homomorphism

$$
N(zw) = N(z)N(w) \quad \forall z,w \in \mathbb{Z}[i].
$$

A [group homomorphism](https://en.wikipedia.org/wiki/Group_homomorphism) has some interesting and useful properties. In particular, the norm map will map the identity of one group to the other:

$$
N(z) = N(e \circ z) = N(e) \circ N(z) = N(z).
$$

In a similar argument, it also maps inverses to inverses

$$
N(e) = N(a \circ a^{-1}) = N(a) \circ N(a^{-1}) = e.
$$

Of particular interest to us is the discrete logarithm problem, where we are interested in solving for $k$ when given $G, P$

$$
P  = G^k \mod n.
$$

As the norm map is a group homomorphism, we can transfer the problem of solving the discrete log for Gaussian integers to that of their norms:

$$
N(P) = N(G^k) = \underbrace{N(G)\ldots N(G)}_{k-\text{times}} = N(G)^k \mod n.
$$

If me just telling you that the norm map is a group homomorphism feels ugly, then we can look at:

$$
\begin{aligned}
N((a + ib)(c + id)) &= N(ac - bd + i(ad + bc)) \\
&= (ac - bd)^2 + (ad + bc)^2 \\
&= a^2 c^2 + b^2 c^2 + a^2 d^2 + b^2 d^2 \\
&= (a^2 + b^2) (c^2 + d^2) \\
&= N(a + ib) N(c + id).
\end{aligned}
$$

Which is ugly too, but in a different way!

#### Computing the GCD

For any unique factorisation domain we say that the greatest common divisor or $\gcd(z,w)$ is the largest element $d$ which divides both $z$ and $w$. 

As with the integers, we say that for $z,w \in \mathbb{Z}[i]$, $z \| w$ (said "$z$ divides $w$ "), if there if $z d = w$ for $d = (a + ib) \in \mathbb{Z}[i]$. If the only divisor that satisfies this relation is a unit in $u$, then we say these two Gaussian integers are relatively prime.

**Note**: just like for the integers, we can prove that when $gcd(z,w) = 1$ then the Gaussian integer $z$ is invertible modulo $w$ in $\mathbb{Z}
[i]$.

Additionally, two relatively prime Gaussian integers $z,w \in \mathbb{Z}[i]$ satisfy the relation

$$
1 = a z + b w \qquad \text{for } \;  a,b \in \mathbb{Z}[i].
$$

The greatest common divisor then has the same meaning as for the integers, where $\gcd(z,w) = d$ is the largest Gaussian integer such that $d \| z$ and $d \| w$. However, as there are multiple units in $\mathbb{Z}[i]$, the greatest common divisors are not unique. This is to say that for $\gcd(z,w) = d = (a + ib)$ we have the set of greatest common divisors which all have the same norm

$$
\{(a + ib), - (a + ib), (-b + ia), (b - ia)\}.
$$

There are a few ways to compute the gcd of two Gaussian integers, but a particularly nice one is that for $z,w \in \mathbb{Z}[i]$ we find that $\gcd(z,w) = \gcd(N(w), N(w), N(z + w))$. As we wont directly need this for our solutions, we don't say much more on this. I enjoyed [this example](https://math.stackexchange.com/questions/82350/how-to-calculate-gcd-of-gaussian-integers) showing the Euclidean algorithm for Gaussian integers and recommend it, if you're interested.

### Congruences and Residue classes

These challenges don't consider the Gaussian integers, but rather the quotient ring formed by looking at the Gaussian integers modulo some composite integer. We are therefore interested in the ring 

$$
\mathbf{K} = \frac{\mathbb{Z}[i]}{n \mathbb{Z}[i]} = \{z \mod n \;\; | \;\; z \in \mathbb{Z}[i]  \}, \qquad n \in \mathbb{N}.
$$

As with the integers, we say that $z \equiv w \mod n$ when $n \| (z - w)$. In words: $z$ is congruent to $w$ modulo $n$ when the difference between $z$ and $w$ is a multiple of $n$.

We wish to compute the order of the multiplicative group of a subset of these Gaussian integers just as we did for our integers before: we want to have the collection of Gaussian integers which are coprime to the modulus:

$$
(\mathbb{Z[i]} / n\mathbb{Z[i]})^\times = \{z \in \mathbf{K} \;\; | \;\;\gcd(z,n) = 1\},
$$

guaranteeing every element of our set is invertible modulo $n$. To compute the order of this group, we wish to generalise Euler's totient function for Gaussian integers. This is the group we work with in both of the following challenges.

#### Computing Euler's totient

Euler's totient computes the number of invertible elements of a set of Gaussian integers modulo a Gaussian integer. We will denote this $\phi(z)$. 

By definition, a Gaussian prime has no non-unit divisors. In the set $(\mathbb{Z[i]} / p \mathbb{Z[i]})$, we will have $N(p)$ elements. However, this includes the zero element which we know we must remove by hand to form a multiplicative group. Therefore, in the case when $p$ is a Gaussian prime, we have

$$
\phi(p) = N(p) - 1,
$$

elements in the group $(\mathbb{Z[i]} / p\mathbb{Z[i]})^\times$, all of which are invertible as $\gcd(z,p) = 1$ for all $z \in (\mathbb{Z[i]} / p\mathbb{Z[i]})^\times$.

As with the integers, we can show that when $\gcd(z,w) = 1$ we can split apart Euler's totient in the following way

$$
\phi(zw) = \phi(z) \phi(w).
$$

This means that when given the prime factorisation of a Gaussian integer, we have the formula for the totient as

$$
\phi(z) = \prod_{i, \; e_i > 0} N(p_i^{e_i}) \left(1 - \frac{1}{N(p_i))} \right).
$$

When we have $z = p^k$ we can simplify this expression to

$$
\phi(p^k) = N(p^{k-1}) (N(p) - 1).
$$

Most importantly, just like as for the integers, Euler's theorem can be generalised

$$
a^{\phi(z)} \equiv 1 \mod z \iff \gcd(a,z) = 1.
$$


### Wrapping up

So this write up got a bit out of hand, but I hope that this background is useful to those who took part in TetCTF, or any other CTF and wanted to gain some intuition on some of the results we use to solve CTF challenges. What is so beautiful about this set of problems is that they challenge your fundamental understanding of the core components of public key crypto and present them in challenging and engaging ways.

For the remainder of the write up, my tone will be closer to standard write ups where I will be drawing from ideas discussed above to present solutions, together with their Sage implementations.



## Unimplemented 

##### 60 Solves, 100 points

> A new public key encryption algorithm is being invented, but the author is not quite sure how to implement the decryption routine correctly. Can you help him?

#### Challenge Source

```python
from collections import namedtuple
from Crypto.Util.number import getPrime
import random
 
Complex = namedtuple("Complex", ["re", "im"])
 
 
def complex_mult(c1, c2, modulus):
    return Complex(
        (c1.re * c2.re - c1.im * c2.im) % modulus,  # real part
        (c1.re * c2.im + c1.im * c2.re) % modulus,  # image part
    )
 
 
def complex_pow(c, exp, modulus):
    result = Complex(1, 0)
    while exp > 0:
        if exp & 1:
            result = complex_mult(result, c, modulus)
        c = complex_mult(c, c, modulus)
        exp >>= 1
    return result
 
 
def generate_key_pair(nbits):
    while True:
        p = getPrime((nbits + 3) // 4)
        q = getPrime((nbits + 3) // 4)
        n = (p ** 2) * (q ** 2)
        if n.bit_length() == nbits:
            return (p, q), n
 
 
def pad(data, length):
    assert len(data) < length
    pad_length = length - len(data) - 1
    pad_data = bytes(random.choices(range(1, 256), k=pad_length))
    sep = b'\x00'
    return pad_data + sep + data
 
 
def unpad(data):
    assert b"\x00" in data, "incorrect padding"
    return data.split(b"\x00", 1)[1]
 
 
def encrypt(public_key, plaintext):
    n = public_key
    plaintext = pad(plaintext, 2 * ((n.bit_length() - 1) // 8))
    m = Complex(
        int.from_bytes(plaintext[:len(plaintext) // 2], "big"),
        int.from_bytes(plaintext[len(plaintext) // 2:], "big")
    )
    c = complex_pow(m, 65537, n)
    return (c.re.to_bytes((n.bit_length() + 7) // 8, "big")
            + c.im.to_bytes((n.bit_length() + 7) // 8, "big"))
 
 
def decrypt(private_key, ciphertext):
    # TODO
    raise Exception("unimplemented")
 
 
def main():
    private_key, public_key = generate_key_pair(2021)
    from secret import flag
 
    print("private_key =", private_key)
    print("public_key =", public_key)
    print("ciphertext =", encrypt(public_key, flag))
 
 
if __name__ == '__main__':
    main()
 
# Output:
# private_key = (128329415694646850105527417663220454989310213490980740842294900866469518550360977403743209328130516433033852724185671092403884337579882897537139175073013,
#                119773890850600188123646882522766760423725010264224559311769920026142724028924588464361802945459257237815241227422748585976629359167921441645714382651911)
# public_key = 236252683050532196983825794701514768601125614979892312308283919527619033977486749228418695923608569040825653688303374445536392159719426640289893369552258923597180869981053519695297428186215135878525530974780390951763007339139013157234202093279764459949020588291928614938201565110828675907781512603972957429701280916745719458738970910789383870206038035515777549907045905872280803964436193687072794878040018900969772972761081589529671158140590712503582004892067155769362463889653489918914397872964087471457070748108694165412065471040954221707557816986272311750297566993468288899523479556822418109112211944932649
# ciphertext = b'\x00h\xbe\x94\x8c\xcd\xdd\x04\x80\xf4\x9d\t\xd8\x8dO\x08\xf1\xd1\xc4\xb9\xa06\xe7\xe3\xb6\xc3\x01+\xa9\xf2\xb9\xe8\x8d\xe6\xc9\x0c_#\x93\x11\xad\x0f\x90\xd3\x0b6\xb0n\x13\xea~"V6\xdbA&\x87\xfe\xa3C\xcb\x16\xae\xd9\x83\xdbU\xc6\x06\xcd\x9a\x94\xa9\xce\x15{d\x95s\xc2\xfb\x90q\xe7\x02\xa2\x081:_C\xc68\x00y\x7fj4@\xd2\xcdE\x06\x943\xbe\xbcC3\xca\x91\xb4\x0e}C\xab\xff?X\xc30u\x069:Dc\xb5\xdc\x9b0%\x98\xbd\xd9\x13\xc0\x02w\xc5\xe5:\xca\xcf\x0c\xab\xc2\x9b}\xab\xd0\xcc\xbc\x0f\x9e9\t\xf7M\xb3\xed\x86\xb5E\x8b\xbc4\xfaH\x9b4\x1c\xc4\xab\xc0\xaf\x8a5XcX\x19K\xed\x19\xe1\x1c\xd0\x1e\x97c\x9fF:L\x9d\x90p\x99\xb8\xde\xcblM\xb3\x80sSL\xe1\xa4\xd6,\x81\xd6\x9c\xf1\xbb\x9c)\xf03\x155\xc0\xd5v\x13\xd6#\xb7\x19\xdea%\xce<\x1c\xf7\xf2!;\xc1\xd7w\xd1\xc8\x8d/\xaew\xa1\x1d\xc5(\xc8\x9d\x82v\xf6j\x90A,e\xbd\xa7]\x10\x8f\xe5\xe7\x93}:\xdf1~\xec\xd0-o`\r\x96\xe4\x03\xb9E\x9fdF\xc3\xf8L\xa0\xda\xf0E[\xf7\x02\xef|*\x08\x8a5pI&\xa9i\x0fZ\xa8\xb3H\xed\xe8v\xc4H\xff\xdb\xcb\x00\xf1\xae\x9bO\x18\xd5\xd8&p\xf5\xf6\xe9\xf1\x1brs\xc2\r\xceZ\xd0\xb24\x97+\x98b\x0e\xbb\xb8.\x8dT\xe4"\xad\xe4\xa3f\xd0M\xbf\xafX\xbb"[\x99\xdap\xa5\xcfT2Wx\x87M\x7f\x99!>B[Q\x04\xf6\x03\xbc\x84\xf4\xdfj\xdd1^I\x1a\x05\x81\x91\xde9Mf*\x8e\x8d\xe64\xf8\x93\x99&yP\xcd\x00!\x82\xab\xbcy\xed\xf1\x13\xd3\x81\xeaz\xbbP>\x9a2\x8c\x08\x0es\xbc\xa9\xf6\xa3\x8c\xb0\xb9t\xd9?\x06@\xc9\x90\xb7\xa7<\x85\xeb\x1a\x88#\x1c\xc3 \xec\xc7\x94d\x99\xd6\x8e>\x06\xf8Y\xf4\x19\xcaI/hy\x18\x8e\x0e8\xf8\r\xbb\xf6\x11\xb9\x8dCWB6 '
```

### Solution

This challenge implements an RSA-like public key cryptosystem where the message (and therefore ciphertext) are encoded as Gaussian integers.

We are given the ciphertext `ciphertext` as a bytestring formed by the concatenation of the `encrypted = Complex(a, b)` such that `ciphertext = long_to_bytes(a) + long_to_bytes(b)`. We are additionally given

- The public key $(e, n)$
- The prime factors of $n = p^2 q^2$

To solve this challenge, we are required to write the decrypt function. The key to solving this is that given the prime factorisation of the modulus, compute the totient function $\phi(n)$ to recover the order of $\mathbb{Z}[i] / n\mathbb{Z}[i]$.

From the formula discussed above this requires knowing the Gaussian prime factors of $n$. Looking at the primes, we find:

- `private_key = (p,q)`
- $p \equiv 1 \mod 4 $
- $q \equiv 3 \mod 4 $

This means that $q$ can be considered as a Gaussian prime with $N(q) = q^2$ and $p$ is a Gaussian integer which factors into two Gaussian primes $ p = \pi \pi^\star $ where $ N(\pi) = N(\pi^\star) = p$. 

As such, the prime factorisation of the modulus is $n = q^2 \pi^2 \pi^{\star 2}$. We can compute the totient for $n$ in the following way

$$
\begin{aligned}
\phi(n) &= \phi(p^2 q^2) =  \phi(\pi^2 \pi^{\star 2} q^2) \\
 &= \phi(\pi^2) \phi(\pi^{\star 2}) \phi(q^2) \\
&= N(\pi) \phi(\pi) \cdot N(\pi^\star) \phi(\pi^\star) \cdot N(q) \phi(q)  \\
&= [N(\pi)(N(\pi) - 1)]^2 \cdot N(q)(N(q) - 1) \\
&= [p(p-1)]^2 \cdot q^2 (q^2 - 1).
\end{aligned}
$$

With Euler's totient computed, the rest of the challenge is simply like any other RSA challenge. Roughly we would compute

```python
c_re = int.from_bytes(ciphertext[:len(ciphertext) // 2], "big")
c_im = int.from_bytes(ciphertext[len(ciphertext) // 2:], "big")
c = Complex(c_re, c_im)

e = 65537
p,q = private_key
n = p**2 * q**2
phi = (p*(p-1))*(q**2)*(q**2 - 1)
d = pow(e,-1,phi) # This was introduced in python 3.8
m = complex_pow(c, d, n)

flag = (m.re.to_bytes((n.bit_length() + 7) // 8, "big")
          + m.im.to_bytes((n.bit_length() + 7) // 8, "big"))
```

A full implementation and generalised formula for `phi` is given below. 

#### A note on the element's order

Here we solve the challenge using Euler's totient, but it's actually overkill. What we're really looking for is the maximum order of the element. For the integers, there's usually not a big difference between these numbers but here we find you can remove factors of the prime.

In rkm's writeup, they use

$$
\lambda(p^2) = p(p^2 - 1) \;\; \Rightarrow \;\; \lambda(n) = pq(p^2 - 1)(q^2 - 1).
$$

Discussing this difference in the CryptoHack discord, [Drago_1729](https://twitter.com/Drago1729) found a paper: [The Euler φ-Function in the Gaussian Integers](https://www.jstor.org/stable/2322785?origin=JSTOR-pdf&seq=1) which mentioned that for Gaussian integers modulo $p^k$ have $\phi(p^k) = N(p^{k-1}) (N(p)^2 - 1)$ but that the maximum order of an element is $\lambda(p^k) = N(p^{k-1})^{\frac{1}{2}} (N(p)^2 - 1)$ which matches with what rkm found.

Furthermore, Ariana then did some heavy lifting and derived in this [blog post](https://ariana1729.github.io/2021/01/06/QuoUnitGrp.html) a generalised expression for the maximal order of an element in the unit group of quotients. Ariana then shows that in the case of $n = p^2q^2$, $p\equiv 1 \mod 4$, $q\equiv3 \mod 4$, we have the maximal multiplicative order 

$$
\lambda(n) = \frac{1}{4} pq (p-1)(q^2 - 1) | \text{lcm} \left(p^2-p,p^2-p,q^2-1,q \right),
$$

which further simplifies the result that rkm used in his solution. Note that:

$$
m_1 * \lambda_{\text{Ariana}}(n)  = m_2 * \lambda_{\text{Rkm}}(n)= \phi(n),
$$

so as Ariana's result divides Rkm's result which both divide $\phi(n)$ we can appreciate why all of these solutions were consistent.

### Implementation

```python
from collections import namedtuple
Complex = namedtuple("Complex", ["re", "im"])
 
 
def complex_mult(c1, c2, modulus):
    return Complex(
        (c1.re * c2.re - c1.im * c2.im) % modulus,  # real part
        (c1.re * c2.im + c1.im * c2.re) % modulus,  # image part
    )


def complex_pow(c, exp, modulus):
    result = Complex(1, 0)
    while exp > 0:
        if exp & 1:
            result = complex_mult(result, c, modulus)
        c = complex_mult(c, c, modulus)
        exp >>= 1
    return result


def totient(factors):
    phi = 1
    for (p, e) in factors:
        # Integer prime of this form is a Gaussian prime with norm(p) = p^2
        if p % 4 == 3:
            phi *= (p**(e-1))**2 * (p**2 - 1)
        # Integer prime of this form is factored into two Gaussian primes with norm(P) = p
        elif p % 4 == 1:
            phi *= (p**(e-1) * (p - 1))**2
    return phi


def decrypt(private_key, ciphertext):
    # Convert bytes to Gaussian integer
    c_re = int.from_bytes(ciphertext[:len(ciphertext) // 2], "big")
    c_im = int.from_bytes(ciphertext[len(ciphertext) // 2:], "big")
    c = Complex(c_re, c_im)

    # RSA pieces
    e = 65537
    p,q = private_key
    n = p**2 * q**2

    # Solution given factorisation
    factors = [(p,2), (q,2)]
    phi = totient(factors)
    d = pow(e,-1,phi)
    m = complex_pow(c, d, n)

    return (m.re.to_bytes((n.bit_length() + 7) // 8, "big")
          + m.im.to_bytes((n.bit_length() + 7) // 8, "big"))

def main():
    private_key = (128329415694646850105527417663220454989310213490980740842294900866469518550360977403743209328130516433033852724185671092403884337579882897537139175073013,
                119773890850600188123646882522766760423725010264224559311769920026142724028924588464361802945459257237815241227422748585976629359167921441645714382651911)
    public_key = 236252683050532196983825794701514768601125614979892312308283919527619033977486749228418695923608569040825653688303374445536392159719426640289893369552258923597180869981053519695297428186215135878525530974780390951763007339139013157234202093279764459949020588291928614938201565110828675907781512603972957429701280916745719458738970910789383870206038035515777549907045905872280803964436193687072794878040018900969772972761081589529671158140590712503582004892067155769362463889653489918914397872964087471457070748108694165412065471040954221707557816986272311750297566993468288899523479556822418109112211944932649
    ciphertext = b'\x00h\xbe\x94\x8c\xcd\xdd\x04\x80\xf4\x9d\t\xd8\x8dO\x08\xf1\xd1\xc4\xb9\xa06\xe7\xe3\xb6\xc3\x01+\xa9\xf2\xb9\xe8\x8d\xe6\xc9\x0c_#\x93\x11\xad\x0f\x90\xd3\x0b6\xb0n\x13\xea~"V6\xdbA&\x87\xfe\xa3C\xcb\x16\xae\xd9\x83\xdbU\xc6\x06\xcd\x9a\x94\xa9\xce\x15{d\x95s\xc2\xfb\x90q\xe7\x02\xa2\x081:_C\xc68\x00y\x7fj4@\xd2\xcdE\x06\x943\xbe\xbcC3\xca\x91\xb4\x0e}C\xab\xff?X\xc30u\x069:Dc\xb5\xdc\x9b0%\x98\xbd\xd9\x13\xc0\x02w\xc5\xe5:\xca\xcf\x0c\xab\xc2\x9b}\xab\xd0\xcc\xbc\x0f\x9e9\t\xf7M\xb3\xed\x86\xb5E\x8b\xbc4\xfaH\x9b4\x1c\xc4\xab\xc0\xaf\x8a5XcX\x19K\xed\x19\xe1\x1c\xd0\x1e\x97c\x9fF:L\x9d\x90p\x99\xb8\xde\xcblM\xb3\x80sSL\xe1\xa4\xd6,\x81\xd6\x9c\xf1\xbb\x9c)\xf03\x155\xc0\xd5v\x13\xd6#\xb7\x19\xdea%\xce<\x1c\xf7\xf2!;\xc1\xd7w\xd1\xc8\x8d/\xaew\xa1\x1d\xc5(\xc8\x9d\x82v\xf6j\x90A,e\xbd\xa7]\x10\x8f\xe5\xe7\x93}:\xdf1~\xec\xd0-o`\r\x96\xe4\x03\xb9E\x9fdF\xc3\xf8L\xa0\xda\xf0E[\xf7\x02\xef|*\x08\x8a5pI&\xa9i\x0fZ\xa8\xb3H\xed\xe8v\xc4H\xff\xdb\xcb\x00\xf1\xae\x9bO\x18\xd5\xd8&p\xf5\xf6\xe9\xf1\x1brs\xc2\r\xceZ\xd0\xb24\x97+\x98b\x0e\xbb\xb8.\x8dT\xe4"\xad\xe4\xa3f\xd0M\xbf\xafX\xbb"[\x99\xdap\xa5\xcfT2Wx\x87M\x7f\x99!>B[Q\x04\xf6\x03\xbc\x84\xf4\xdfj\xdd1^I\x1a\x05\x81\x91\xde9Mf*\x8e\x8d\xe64\xf8\x93\x99&yP\xcd\x00!\x82\xab\xbcy\xed\xf1\x13\xd3\x81\xeaz\xbbP>\x9a2\x8c\x08\x0es\xbc\xa9\xf6\xa3\x8c\xb0\xb9t\xd9?\x06@\xc9\x90\xb7\xa7<\x85\xeb\x1a\x88#\x1c\xc3 \xec\xc7\x94d\x99\xd6\x8e>\x06\xf8Y\xf4\x19\xcaI/hy\x18\x8e\x0e8\xf8\r\xbb\xf6\x11\xb9\x8dCWB6 '
    flag = decrypt(private_key, ciphertext)
    print(flag.split(b'\x00')[-1])

if __name__ == '__main__':
  main()
  
# b'TetCTF{c0unt1ng_1s_n0t_4lw4ys_34sy-vina:*100*48012023578024#}'

```



## Unevaluated

##### 3 Solves, 998 points

> We're about to launch a new public key cryptosystem, but its security has not been carefully reviewed yet. Can you help us?

#### Challenge Source

```python
from collections import namedtuple
from Crypto.Util.number import getPrime, isPrime, getRandomRange
 
Complex = namedtuple("Complex", ["re", "im"])
 
 
def complex_mult(c1, c2, modulus):
    return Complex(
        (c1.re * c2.re - c1.im * c2.im) % modulus,  # real part
        (c1.re * c2.im + c1.im * c2.re) % modulus,  # image part
    )
 
 
def complex_pow(c, exp, modulus):
    result = Complex(1, 0)
    while exp > 0:
        if exp & 1:
            result = complex_mult(result, c, modulus)
        c = complex_mult(c, c, modulus)
        exp >>= 1
    return result
 
 
class ComplexDiffieHellman:
    @staticmethod
    def generate_params(prime_length):
        # Warning: this may take some time :)
        while True:
            p = getPrime(prime_length)
            if p % 4 == 3:
                if p % 3 == 2:
                    q = (p - 1) // 2
                    r = (p + 1) // 12
                    if isPrime(q) and isPrime(r):
                        break
                else:
                    q = (p - 1) // 6
                    r = (p + 1) // 4
                    if isPrime(q) and isPrime(r):
                        break
        n = p ** 2
        order = p * q * r
        while True:
            re = getRandomRange(1, n)
            im = getRandomRange(1, n)
            g = complex_pow(Complex(re, im), 24, n)
            if (
                    complex_pow(g, order, n) == Complex(1, 0)
                    and complex_pow(g, order // p, n) != Complex(1, 0)
                    and complex_pow(g, order // q, n) != Complex(1, 0)
                    and complex_pow(g, order // r, n) != Complex(1, 0)
            ):
                return g, order, n
 
    def __init__(self, params=None, prime_length=128, debug=False):
        if not debug:
            raise Exception("security unevaluated")
        if params is None:
            params = ComplexDiffieHellman.generate_params(prime_length)
        self.g, self.order, self.n = params
 
    def get_public_key(self, private_key):
        return complex_pow(self.g, private_key, self.n)
 
    def get_shared_secret(self, private_key, other_public_key):
        return complex_pow(other_public_key, private_key, self.n)
 
 
def main():
    from os import urandom
    private_key = urandom(32)
    k = int.from_bytes(private_key, "big")
 
    cdh = ComplexDiffieHellman(debug=True)
    print("g =", cdh.g)
    print("order =", cdh.order)
    print("n =", cdh.n)
    print("public_key =", cdh.get_public_key(k))
 
    # Solve the discrete logarithm problem if you want the flag :)
    from secret import flag
    from Crypto.Cipher import AES
    if len(flag) % 16 != 0:
        flag += b"\x00" * (16 - len(flag) % 16)
    print("encrypted_flag = ",
          AES.new(private_key, AES.MODE_ECB).encrypt(flag))
 
 
if __name__ == "__main__":
    main()
 
# Output:
# g = Complex(re=20878314020629522511110696411629430299663617500650083274468525283663940214962,
#             im=16739915489749335460111660035712237713219278122190661324570170645550234520364)
# order = 364822540633315669941067187619936391080373745485429146147669403317263780363306505857156064209602926535333071909491
# n = 42481052689091692859661163257336968116308378645346086679008747728668973847769
# public_key = Complex(re=11048898386036746197306883207419421777457078734258168057000593553461884996107,
#                      im=34230477038891719323025391618998268890391645779869016241994899690290519616973)
# encrypted_flag = b'\'{\xda\xec\xe9\xa4\xc1b\x96\x9a\x8b\x92\x85\xb6&p\xe6W\x8axC)\xa7\x0f(N\xa1\x0b\x05\x19@<T>L9!\xb7\x9e3\xbc\x99\xf0\x8f\xb3\xacZ:\xb3\x1c\xb9\xb7;\xc7\x8a:\xb7\x10\xbd\x07"\xad\xc5\x84'
```

### Solution

As mentioned in the introduction, [rkm0959](https://rkm0959.tistory.com/192), [Mystify](https://mystiz.hk/posts/2021-01-03-tetctf-unevaluated/) and [TheBlueFlame](https://hackmd.io/@TheBlueFlame121/HJPbMVk0v) have offered detailed write-ups on how they solved this puzzle, including some very smart simplifications of the problem using the Chinese remainder theorem and knowledge of the [Paillier](https://en.wikipedia.org/wiki/Paillier_cryptosystem) cryptosystem.

However, despite the low number of solves this challenge can be computed in a reasonable time with only a couple of pieces of information

- The norm is a group homomorphism (see above)
- The `private_key` has only 256 bits, rather than being of the size of the order of $\|G\|$ which has 378 bits
- This means solving the discrete log after taking the norm map will recover *most* of the `private_key`
- Pari has an implementation for solving the discrete log much faster than `discrete_log` offered by default from Sage for $n = p^k$.

Let's discuss the solution, and then look at the implementation

We are given the following problem

$$
P = G^k \mod n, \qquad P,G \in (\mathbb{Z}[i] / n\mathbb{Z}[i])^\times, \quad n = p^2, \quad p \equiv 3 \mod 4.
$$

Using the norm map, we can convert this into the problem of solving

$$
N(P) = N(G)^k \mod n,
$$

and now rather than working with Gaussian integers, we're simply solving the discrete log for $(\mathbb{Z} / n \mathbb{Z})^\times$ which we're already familiar with!

Traditionally, the private key has the same bit length as the generator in the key exchange. This is important as it prevents the norm map being a suitable reduction of the DLP. Solving the discrete log for Gaussian integers, we would obtain

$$
k = \log_G (P) \mod |G|.
$$

From the challenge source we know that $k$ has 256 bits, while $\|G\|$ has 378 bits. Solving this problem would recover the whole of $k$, but this means solving the DLP in $GF(p^2)$ and $p$ is too large to make this feasible.

Using the norm map, we find

$$
k = \log_{N(G)} (N(P)) \mod |N(G)|.
$$

However, the order of $(\mathbb{Z} / n \mathbb{Z})^\times$ is $p(p-1)$, and so the order of $N(G) \mod n$ is going to be some divisor of this. Looking at our challenge, $p(p-1)$ has 255 bits, therefore the secret we recover will be slightly truncated. As it's very close in size, this is no problem, but solving using the norm map would be infeasible if $k$ had 378 bits.

We can obtain the full secret from the expression

$$
k_{\text{all}} = k + m \times |N(G)|,
$$

for some $m \in \mathbb{N}$. Luckily the order of $N(G)$ is very easy to compute in Sage

```python
R = Integers(n)
Rg = R(N(G))
order = Rg.multiplicative_order()
# order = p(p-1) // 2
```

and so we can take the result $k$ and iteratively add $\|N(G)\|$ until we have a valid AES key. This is shown in the implementation below.

#### Making SageMath do all the work

The one shame of this puzzle is the way you have to fight Sage to find the solution. If I had coded this without talking to CryptoHack people, my guess would have been

```python
from collections import namedtuple

Complex = namedtuple("Complex", ["re", "im"])

def N(z):
	return z.re^2 + z.im^2

G = Complex(re=20878314020629522511110696411629430299663617500650083274468525283663940214962,
	            im=16739915489749335460111660035712237713219278122190661324570170645550234520364)
P = Complex(re=11048898386036746197306883207419421777457078734258168057000593553461884996107,
	            im=34230477038891719323025391618998268890391645779869016241994899690290519616973)
n = 42481052689091692859661163257336968116308378645346086679008747728668973847769

R = Integers(n)
Rg = R(N(G))
Rp = R(N(P))

k = discrete_log(Rp, Rg)
```

Running this, nothing happens (or rather my RAM is silently eaten until sage crashes). The primes are too strong for this to be a reasonable solution.

If I had googled a bit, I would have read that there's another function `Rp.log(Rg)` which is implemented by Pari and is much faster that `discrete_log` but that **sage only tries the super fast function when the modulus is prime**. 

**Note**: here I've used lazy language with "fast" and "slow". `znlog` is a pari implementation of the linear sieve index calculus method and is sub-exponential. The default methods from `discrete_log` are Pohlig-Hellman with Pollard rho and baby-step-giant-step which run with $\mathcal{O}(\sqrt{q})$ for prime factors $q$. [Here](https://pari.math.u-bordeaux.fr/dochtml/html/Arithmetic_functions.html) it is explained that `znlog` is good for $N < 10^{50}$, while `discrete_log` for $N < 10^{30}$. 

The trick is that Pari, which lives somewhere inside Sage, will also run ``Rp.log(Rg)`` when the modulus is a prime power, but getting Sage to do this is hard work. It wasn't until Ndh came into the discord and showed us this one liner:

```python
k = int(pari(f"znlog({N(P)}, Mod({N(G)}, {n}))"))
```

did any of us understand how to solve this discrete log problem in Sage. The method of rkm0959, hellman and pcback all solved this challenge another way, using CRT and some clever tricks. Rather than attempt to summarise, I refer to the write ups in the intro, and this little code snippet from [Hellman](https://discord.com/channels/692694094111309866/744261335826563145/795223030992338955)

```python
c = complex_pow(g, q*r, p**2)
lg = (c.re - 1) // p
c = complex_pow(v, q*r, p**2)
lv = (c.re - 1) // p
solp = lv * inverse_mod(lg, p) % p

lg = complex_pow(g, p*r, p**2)
lv = complex_pow(v, p*r, p**2)
solq = GF(p)(lv.re).log(GF(p)(lg.re))

sec = crt([solp, solq], [p, q])
```

Which is a really concise solution. If this appears as magic, check out [rkm0959's full solution](https://rkm0959.tistory.com/192).

Armed with the theoretical knolwedge on how to solve this, together with our Pari one-liner, let's grab the flag.

### Implementation 

```python
from collections import namedtuple
from Crypto.Cipher import AES

Complex = namedtuple("Complex", ["re", "im"])


def complex_mult(c1, c2, modulus):
    return Complex(
        (c1.re * c2.re - c1.im * c2.im) % modulus,  # real part
        (c1.re * c2.im + c1.im * c2.re) % modulus,  # image part
    )


def complex_pow(c, exp, modulus):
    result = Complex(1, 0)
    while exp > 0:
        if exp & 1:
            result = complex_mult(result, c, modulus)
        c = complex_mult(c, c, modulus)
        exp >>= 1
    return result


def N(z):
	return z.re^2 + z.im^2


def main():
	encrypted_flag = b'\'{\xda\xec\xe9\xa4\xc1b\x96\x9a\x8b\x92\x85\xb6&p\xe6W\x8axC)\xa7\x0f(N\xa1\x0b\x05\x19@<T>L9!\xb7\x9e3\xbc\x99\xf0\x8f\xb3\xacZ:\xb3\x1c\xb9\xb7;\xc7\x8a:\xb7\x10\xbd\x07"\xad\xc5\x84'
	G = Complex(re=20878314020629522511110696411629430299663617500650083274468525283663940214962,
	            im=16739915489749335460111660035712237713219278122190661324570170645550234520364)
	P = Complex(re=11048898386036746197306883207419421777457078734258168057000593553461884996107,
	            im=34230477038891719323025391618998268890391645779869016241994899690290519616973)
	n = 42481052689091692859661163257336968116308378645346086679008747728668973847769
	
	# Multiplicative order is needed as secret = k + i*G_order 
	# for some non-negative integer i
	G_order = Integers(n)(N(G)).multiplicative_order()

	# Clever Sage method takes about 3 mins for me
	k = int(pari(f"znlog({N(P)}, Mod({N(G)}, {n}))")) # 15208121869682279508410349753961596563525285197548874227988093797553755490107

	while True:
		key = k.to_bytes((k.bit_length() + 7) // 8, 'big')
		flag = AES.new(key, AES.MODE_ECB).decrypt(encrypted_flag)
		if b'TetCTF' in flag:
			print(f'Secret: {k}')
			print(f'Flag: {flag}')
			break
		k += int(G_order)

if __name__ == '__main__':
	main()
  
# Secret: 36448648214228125938240931382630080621576419859132411658551075951915466230810
# Flag: b'TetCTF{h0m0m0rph1sm_1s_0ur_fr13nd-mobi:*100*231199111007#}\x00\x00\x00\x00\x00\x00'
```