---
layout: post
title: "Announcing Matrix Bridge For CryptoHack Discord Chat"
categories: CryptoHack
permalink: announcing-matrix-bridge-for-cryptohack-discord-chat
author: hyperreality
meta: "Announcing Matrix Bridge For CryptoHack Discord Chat"
tags: Announcement CryptoHack
---

CryptoHack chat is based on [Discord](https://discord.gg/h9E7cna5pV), which has worked well for us so far. Discord is free, has a great UI, and has enabled the creation of the awesome [CryptoHacker bot](https://github.com/cryptohack/cryptohacker-discord-bot) which links CryptoHack accounts to Discord profiles.

However, there have been some concerns about the use of Discord as our only chat platform. Scams and abuse are rife on Discord, as we documented in a [previous post](https://blog.cryptohack.org/crypto-spambots-discord). We have combated this by enforcing a registration challenge, however this doesn't stop all spam: real users who have passed the challenge sometimes get their authentication tokens phished, leading to their accounts themselves attempting to phish in as many chat channels and DMs as they can before they get banned.

On a deeper level, many people within the cryptography, privacy, and free software space are against using Discord. It's a centralised platform that doesn't have add end-to-end encryption, and is increasingly under pressure to monetise its successful product - probably by selling data to third party advertising companies. CryptoHack chat is public, carefully moderated, and never tends to stray far from engaging technical and academic discussion. We're not too concerned about Discord for now, but we understand people who would rather avoid it. And apparently Discord now blocks Tor users completely, so those who route their traffic through it can no longer chat.

![Screenshot of Element Chat](/assets/images/element-chat.png)

As such, we have been looking at alternatives so that people can participate in CryptoHack chat through a different medium. For now we've setup a self-hosted [Matrix](https://matrix.org/) Synapse server which bridges from our Discord. This can be accessed via the Element chat client.

Currently, we are just testing this, and have not yet setup either federation or user registration. We don't want to make it easy for anonymous accounts on Matrix to abuse the chat, given the amount of effort we've put into preventing abuse on Discord. For now this is a trial and we'll see how it goes.

So those who want to test Matrix will have to email us (or contact by some other means) and we'll provision you an account. From there, the best way to get started is:
 1. Go to [https://app.element.io/](https://app.element.io/)
 1. Click "Sign In", edit homeserver to "matrix.cryptohack.org". Login using your credentials.
 1. You can now explore and send messages to rooms which have been bridged from Discord.
