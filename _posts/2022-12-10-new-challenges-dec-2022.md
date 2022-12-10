---
layout: post
title: "New Challenges 12/2022"
categories: New Challenges
permalink: new-challenges-dec-2022
author: hyperreality
meta: "CryptoHack New Challenges December 2022"
tags: Announcement CryptoHack
---

Hello CryptoHackers! It's been a quieter Autumn/Fall for CryptoHack, but we've still had a few things going on. And here's an exciting challenge release.

#### Applied Crypto Study Group

Chuck Bartowski has been running a reading group for ["A Graduate Course in Applied Cryptography"](https://toc.cryptobook.us/). The study group's goal is to learn the basics of applied cryptography, with a focus on better understanding of how to argue cryptographic security with proofs. If you're interested, you can join in on Discord ([channel link](https://discord.com/channels/692694094111309866/1028962150380732487)).

#### Backend Improvements

We have been doing some housekeeping on the backend. The CryptoHack platform was forked from [IceCTF's ColdCore](https://github.com/IceCTF/ColdCore) two years ago. IceCTF was only designed for a single CTF, and the data model was not perfect. One of the problems was that usernames were not case-insensitive, which we fixed within a few months of launching.

A worse problem with the data model is that email addresses were not required to be unique. Therefore, thousands of accounts on CH have been registered under duplicate email addresses. In almost all cases these are because people forgot their usernames and registered a new account. The problem is that this meant we couldn't implement "login by email address" or "reset password by entering email address" features.

Anyway, we finally fixed the problem, and will soon offer those features, which will hopefully put an end to the large number of users who forget their usernames and need admin help. For existing accounts that shared email addresses, we found the most recently active / highest score account and removed the others. In ambiguous cases, we sent an email asking how the player wanted it resolved. Overall this was a lot of work that could have been prevented by getting things right in the first place - a common engineering lesson.

### New Challenge Descriptions

These new challenges will be released on Thursday:

- **RSA vs RNG** (RSA): A fun challenge combining RSA and a bad RNG, as you might have guessed from the title. _Contributed by jschnei_
- **Digestive** (Elliptic Curves): A simple challenge showing a potential pitfall in ECDSA implementation.
- **Megalomaniac** (Crypto On The Web): A fantastic set of challenges showcasing the recent MEGA attacks. _Contributed by $in_
- **TLS Part 1** (Crypto On The Web): This rounds out the TLS Part 1 section teaching the cryptographic fundamentals of the TLS protocol.
- **Learning With Errors** (Post-Quantum): This kicks off a new Post-Quantum category helping you to understand the Kyber and Dilithium algorithms recently selected by NIST.  _Contributed by the entire country of ireland_

### Current Scoreboard

![CryptoHack Scoreboard 2022/12](/assets/images/scoreboard_202212.png)

Congratulations to Neobeo, ndh, and someone12469 for solving the last set of challenges the fastest.

