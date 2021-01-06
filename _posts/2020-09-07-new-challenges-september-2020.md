---
layout: post
title: "New Challenges 09/2020"
categories: New Challenges
permalink: new-challenges-sept-2020
author: hyperreality
meta: "CryptoHack New Challenges September 2020"
tags: Announcement CryptoHack
---

As CryptoHack has grown, we've released more and more challenges submitted by the community. We love receiving new challenges especially in those areas which are currently not well-covered on the site.

We ask that submitted challenges follow the same coding style as existing ones, and that the solution can be calculated in less than 5 minutes. We also ask for an accompanying solution script. Our favourite challenges are relatively easy ones that explain complex concepts in creative ways.

However those are just general suggestions and we are happy to make exceptions. Finally, please don’t be upset if we decide not to release your challenge. We have received some excellent challenges that would be popular in CTFs, but don’t necessarily fit into the site at the moment.

Due to the number of people competing in [GoogleCTF](https://ctftime.org/event/1041), we decided to release the new challenges in two separate batches which are summarised below.

The other thing that we announced recently is a [Patreon](https://www.patreon.com/cryptohack) to support server costs and continued development of the site. We are very grateful to the 4 generous patrons so far.

## 20/08/2020

The general theme of these challenges is abusing signing flaws.

- **Let's Decrypt** (RSA Signing): given a message and a valid signature on that message, can you create a public key which validates the same signature under a different message? This scenario has come up in the real-world before and is bound to appear in some interesting places again.
- **Ellipse Curve Cryptography** (Mathematical Brainteasers): what happens when you try to do cryptography over a slightly different shape than your typical elliptic curve?
- **PriMeD5** (Hashing): here's a service which signs prime numbers and will reveal parts of the flag if you can break one of its assumptions. There are two inventive solutions to this puzzle. _Contributed by randomdude999_
- **No Random, No Bias** (Elliptic Curve Signing): can you exploit three ECDSA signatures to obtain the private key point on the curve? This is another attack that's had serious world consequences. _Contributed by aloof_

Congratulations to pcback and ndh from Vietnam and aloof from France for solving these challenges the fastest.


## 10/09/2020

This set of challenges includes sequels to previous popular challenges, and deep dives into the workings of hash functions which is currently not an area covered by CryptoHack.

- **Transparency** (Data Formats): this challenge supplements the section on PEM and DER formats by discussing the certificate authority system for TLS certificates and its weaknesses.
- **Let's Decrypt Again** (RSA Signing): Let's Decrypt has a nice solution, but those parameters might get blocked in practice. Can you get creative and achieve the same result in a more restricted situation? _Contributed by Robin Jadoul and Thunderlord_
- **No Difference** (Hashing): here's a custom hash function for which you need to find a collision; this may involve getting your hands dirty by exploiting an S-Box. _Contributed by VincBreaker_
- **Invariant** (Hashing): custom cryptographic hash functions are being designed for maximal efficiency in embedded device situations. Can you find a flaw in such a function to break its preimage resistance? _Contributed by Cryptanalyse_
- **Twin Keys** (Hashing): Jack and hyperreality have lost both their keys to their MD5-powered safe and Jack can only remember part of one of the keys. This puzzle reveals another dimension to the existing hashing challenges based on MD5. _Contributed by ciphr_
- **Trust Games** (PRNGs): here's a game powered by an LCG similar to Lo-Hi Card Game, but this time breaking it may require a more powerful technique. _Contributed by $in_
- **Edwards goes Degenerate** (Elliptic Curves): our first challenge based on Edwards Elliptic curves. This variant may protect against side channel attacks, but you've got to make sure you've got everything working just right. _Contributed by aloof_

