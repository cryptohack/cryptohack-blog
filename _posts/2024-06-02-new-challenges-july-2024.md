---
layout: post
title: "New Challenges 07/2024"
categories: New Challenges
permalink: new-challenges-july-2024
author: hyperreality
meta: "CryptoHack New Challenges July 2024"
tags: Announcement CryptoHack
---

Hello CryptoHackers! It's been ages since our last challenge release. However, we hope to make it up to you by delivering an enormous release with almost 50 fresh challenges.

#### Platform Improvements

We have a new career posting for a company called Aztec that is working on blockchain privacy and looking for crypto hackers (<a href="https://cryptohack.org/careers/aztec/">https://cryptohack.org/careers/aztec/</a>). 

Due to popular request, it will be possible to view the flags of challenges you've previously solved. Thanks to Robin for adding the code for this.

A line of code will be added to all interactive challenges so that they can easily be run locally when placed in the same directory as utils.listener, see <a href="https://cryptohack.org/faq/#netcat">the FAQ</a>.

We've rewritten challenges to fully promote the use of Pwntools, as telnetlib is getting removed from Python 3.13 (previously our starting challenges used telnetlib to make TCP socket connections because it was part of the Python standard library).

### New Challenge Descriptions

A major feature of this challenge release will be a whole new category on Zero-Knowledge Proofs contributed by Ectario and Killerdog. We're really excited to be adding this to the platform, which fills a much-needed gap on the site by teaching ZKP in a similar style to the existing CryptoHack categories.

Additionally, resident isogeny expert Jack has created a whole category on Isogenies, giving the CTF community a proper introduction to this fascinating topic.

Aloof has contributed a set of ECC challenges that dive deep into properties of elliptic curves.

$in has also contributed an ECC challenge based around exploiting ECDH key exchange.

Eli Sohl has contributed a set of challenges to the symmetric ciphers section, filling a padding oracle shaped hole in the platform.

deuterium has contributed a challenge on bounded noise to the LWE section.

Finally, a small section on hash-based cryptography will be added to the Hashes category.

This is a huge release full of challenges about some of the hottest topics in crypto at the moment so we're really excited.

### Current Scoreboard

![CryptoHack Scoreboard 2024/06](/assets/images/scoreboard_202406.png)

Congratulations to y011d4, someone12469, and ndh for solving the last set of challenges the fastest.

