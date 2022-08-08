---
layout: post
title: "Cryptography CTF Archive"
categories: New Challenges
permalink: cryptography-ctf-archive
author: hyperreality
title: "Cryptography CTF Archive"
tags: Announcement CryptoHack News
---

Jack and I met up this weekend to build a feature which a lot of players have requested: a [cryptography CTF archive](https://cryptohack.org/challenges/ctf-archive/).

There are so many CTFs these days and lots of them feature excellent cryptography challenges. We think it's a shame that so many of these challenges only get hosted and played for a weekend. After the CTF ends, the CTF server usually goes offline, and the original source code may be lost. It's great when there is a writeup available, but it is often hard to understand the writeup without playing the challenge yourself.

Our objective is to host the best cryptography CTF challenges on our platform forever, or at least as long as economically feasible! A beautiful challenge can be the fastest way to learn a difficult concept and we think archived challenges will complement the rest of the CryptoHack site.

There's a few considerations we took when implementing this:
 - Since the challenges already appeared in CTFs, there may be public writeups for them.
 - Therefore, we need to remove the competitive aspect. Archive challenges are worth 0 points, and don't record first bloods.
 - It's helpful to have writeups adjacent to the challenges, so the normal CryptoHack solution functionality is available.

The other advantage is that this makes it easier to contribute challenges to be hosted on CryptoHack. In fact, we're quite proud of how smooth the submission process is:
 1. Read the [README](https://github.com/cryptohack/ctf_archive/blob/main/README.md) in the [ctf_archive GitHub repo](https://github.com/cryptohack/ctf_archive), which explains how to submit challenges.
 1. The easiest way is to copy one of the existing challenges in the repo, then make your changes:
   - Challenge metadata such as name, original CTF, the flag and the flag format is contained in `description.yml`
   - All files in `release_files` will be available to the players
   - The files in `server_files` will be what runs on the server for dynamic challenges. The server-side is built using a Dockerfile and always listens on port 1337
 1. `docker_deploy.py` does the magic of templating a `docker-compose.yml` file which gives all the dynamic challenges a unique port, adds the flag as an environment variable, and launches them.
 1. Open a pull request against the repo. Once it gets approved and merged by a CryptoHack admin, the challenge will be automatically deployed on CryptoHack.

### Post-Quantum Footer

Meanwhile, there has been exciting news in post-quantum cryptography as the Supersingular Isogeny Diffie–Hellman protocol (SIDH), one of the candidates in the NIST post-quantum standardisation competition, has been [completely broken](https://eprint.iacr.org/2022/975.pdf). The researchers' attack implementation uses the closed-source Magma tool, but Jack and a few others have implemented a [faster Sage version](https://github.com/jack4818/Castryck-Decru-SageMath). More news on this to come!

Behind the scenes top members of the community have been writing post-quantum challenges, especially challenges for understanding Learning With Errors (LWE) cryptosystems which have become the most promising candidates for standardisation. We are looking forward to releasing these soon. 
