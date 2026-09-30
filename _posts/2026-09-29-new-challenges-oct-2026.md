---
layout: post
title: "New Challenges 10/2026"
categories: New Challenges
permalink: new-challenges-oct-2026
author: hyperreality
meta: "CryptoHack New Challenges October 2026"
tags: Announcement CryptoHack
---

Hello CryptoHackers! It's been awhile since our last announcement, but we're back with fresh challenges and several site updates.

### A sea change in the CTF scene

We have always intended CryptoHack to be fundamentally an educational and not a competitive site. We recognise that competition can be a great motivator and the site has several "gamification" aspects like levels and trophies.

Alas, LLMs have transformed the competitive CTF landscape over the last year. When points and a race to flag first is involved, it is tempting to get an LLM do the hard work. This can lead to a fast solve, but the understanding that comes with researching and grinding against a problem is lost.

Therefore, with the mandate of the CryptoHack community, we have made some updates to further focus CryptoHack on learning and away from the race for points.

### Platform changes

#### Tied places on the scoreboard

Players with the same score now share the same placing - so everyone with max points is #1, rather than whoever solved first. The ordering within each placing is randomly shuffled every 24 hours.

#### Hall of Fame

To preserve the achievements of the players who climbed the rankings the hard way, we've added a [Hall of Fame](https://cryptohack.org/scoreboard/hall-of-fame/) that locks in the pre-2026 top 100 scoreboard.

#### Sharing solutions

We are relaxing our policy on publishing solutions outside of the CryptoHack platform. If you want to write a blog about how you solved some challenge, please feel free to.

### New Challenge Descriptions

These challenges address some clear missing areas on the platform:

- **Key Derivation** (Hashes): A new section on password-based key derivation functions:
  - **Seventy-Two**: involving bcrypt
  - **Long Story Short**: involving PBKDF2-HMAC-SHA256
- **Rhetorical Oracle** and **Rhetorical Oracle 2** (Symmetric Ciphers): two new additions to the padding attacks section _Contributed by versusdkp_
- **Bad Temper** and **Bad Temper 2** (Misc - PRNG): finally, some cool challenges based on the famous Mersenne Twister _Contributed by versusdkp_
- **Common Ground** (Mathematics - Brainteasers): involving a quirk of GCD math _Contributed by r4sti_

Thanks as always to our contributors, and if you have a challenge you'd like to share, please message one of us on Discord.

### Future challenges

As the cryptography world marches on, we are particularly interested in adding:
 * Challenges on post-quantum schemes in the NIST process: LWE, ML-KEM, SLH-DSA etc.
 * More practical/protocol stuff beyond TLS like Signal/X3DH/Double Ratchet, PAKE etc.
 * Modern AEADs like Salsa20, Poly1305 and ChaCha20-Poly1305
 * Differential cryptanalysis
 * More signature schemes especially Schnorr and Ed25519

### Other updates

**Solution runtime:** We've added [an FAQ entry](https://cryptohack.org/faq/#runtime) clarifying that the vast majority of solutions should run in under a minute on a modern PC. If a challenge is expected to take longer, the description will say so.

**Username change and reset progress:** You can now change your username or reset all your solves from the user settings page.

**Discord bot:** The [CryptoHacker bot](https://github.com/cryptohack/cryptohacker-discord-bot) has been updated to comply with stricter Discord policies. The main user-facing change is that you should now use [slash commands](https://support-apps.discord.com/hc/en-us/articles/26501837786775-Slash-Commands-FAQ) to communicate with the bot.

**Zellic:** We have a [career posting](https://cryptohack.org/careers/) from [Zellic](https://www.zellic.io/), who are hiring cryptographers and zero-knowledge experts.
