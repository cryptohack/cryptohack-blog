---
layout: post
title: "Crypto Spammers Are Attacking Our Discord Community"
categories: CryptoHack
permalink: crypto-spambots-discord
author:
- hyperreality
meta: "spambots"
tags: Discord CryptoHack
excerpt_separator: <!--more-->
---

Recently our Discord community has come under attack by spammers advertising "cryptocurrency giveaways". We have taken several steps to try to prevent spam but they have not been effective. This post explores how we think the spammers are automatically obtaining the member list and bypassing the verification and anti-abuse protections on Discord. At the end we consider some possible solutions.

<!--more-->

## Unsolicited DMs

On 17th May and several previous occasions, members of the CryptoHack Discord received suspicious direct messages (DMs):

![Discord DM Spam](assets/images/discord-spam/attentive.png)

These messages originated from hundreds of different accounts, and appeared to target almost every one of our 5000 members who was online.

This was obviously annoying to our members, especially since our community was clearly the "mutual server" which the spammers had used to find them.

We initially suspected that our community was being targeted because of the "crypto" in our name (obligatory: [crypto is not cryptocurrency, it refers to cryptography](http://www.cryptoisnotcryptocurrency.com/)). But a [quick](https://support.discord.com/hc/en-us/community/posts/360055275992-Need-way-to-hide-list-of-members-) [browse](https://support.discord.com/hc/en-us/community/posts/360043274731-New-Permission-Allowing-users-not-to-see-the-memberlist-) of the Discord support forums shows that this has been happening to many large communities for years. So it's also likely that spammers are crawling the internet for all public invites to Discord servers rather than specifically targeting our relatively small server.

## Account Verification

The thing that confused us is that we have previously taken several steps to try and stop bots and unverified accounts:
 1. We set Discord's Moderation feature to the "Highest" level to require verified phone numbers.
 1. We have our own verification process that requires answering a trivia question before full membership is granted.

We thought these protections would be more than adequate. In fact they have even turned away many potential members who cannot be bothered to complete them. But somehow the bots were still discovering our entire member list and messaging them all.

Let's first look at Discord's Moderation feature:

![Discord DM Spam](assets/images/discord-spam/phone-verification.png)

Theoretically, when set to "Highest" level this looks like a strong safeguard against abuse. Accounts must have verified phone numbers before they can send messages or DMs to anyone. Phone numbers are not trivial to freely obtain, so you would expect this to prevent widespread spam.

The explanation must be either that the bots can circumvent the requirement somehow (but we tried and could not), or they have automated the process of getting verified phone numbers. The latter would imply that the profit from the scam is higher than the cost of constantly creating new accounts with new verified phone numbers as the old ones get banned.

Now let's look at our own verification process. When a user first joins, they are dumped in a '#how-to-join' channel with no access to anything else. No server members can be seen on the sidebar except others who have also not yet verified themselves, plus admins:

![Discord Verification Channel](assets/images/discord-spam/verification-channel.png)

To verify, users must answer a cryptography trivia question. A correct answer triggers our server bot to give the user a role, which allows them to see the rest of the channels.

We added this verification after a previous wave of spam. It's a common technique used on Discord servers, and we implement it using the [CryptoHacker](https://github.com/cryptohack/cryptohacker-discord-bot) bot developed by Robin. We were sure this would stop the spam, but nope! This was added months ago and it did not stop the May 17th spam.

## Bypassing verification

Our first thought was that the spammers might be using the Discord API to fetch the member list for our guild ("guild" just means "server" in API terms). The spammers would not be able to add a Discord bot account to the server without our permission, however they could "self-bot". Self-botting is calling the Discord API programmatically from a normal user account, which is [against Discord's Terms of Service](https://support.discord.com/hc/en-us/articles/115002192352-Automated-user-accounts-self-bots-) but spammers don't tend to care about such things!

However we tried to reproduce this and quickly realised that normal users don't have access to call the API method `Guild.fetch_members()`. The Members intent must be set, but even then Discord will return a 403 permission denied error unless the account has a privileged role. This makes sense; typical accounts shouldn't have default access to powerful APIs.

Since it didn't seem possible to acquire the member list through automation alone, our next thought was that the spammers were manually verifying with one human account first. The human would scrape the member list, then feed that to the bots. But looking through the audit logs we could not find any evidence of this.

## User Enumeration

Ariana pointed out something curious. Even an unverified user who is stuck in the '#how-to-join' channel is still able to enumerate members from the guild by typing in the search bar:

![Finding Users via the Search Box](assets/images/discord-spam/search.png)

Enumeration is easy. First you type "a" and three members whose name start with "a" show up. Next you type "aa" and two members whose names start with "aa" come up. Since less than three members were returned, next you try "ab". Following this simple algorithm you will soon have collected the entire member list.

Opening the WebSocket section of the Network pane of Developer Tools while searching, you can see the JSON search queries being sent and responded to in a binary format. Fortunately, there is no need to reverse engineer this protocol. Reading through the discord.py docs, a function that replicates the searching behaviour is [Guild.query_members()](https://discordpy.readthedocs.io/en/latest/api.html#discord.Guild.query_members). And this can fetch up to 100 members at once, and doesn't require any special privileges to run!

We quickly wrote a proof-of-concept script that was able to fetch 3500 of our 5000 members in two minutes using an unverified user account that had just joined our guild. From there, automating sending out the DMs is just one extra step.

## Stopping The Spam

So now we know the method that the spammers are using to bypass verification, how can we actually stop the spam?

Individual users can protect themselves by turning off the ability for non-friends to DM them, but it's not the default setting, and it can make other use-cases for Discord annoying. So it's not a reasonable suggestion for us to make to all our members.

The ideal solution for server admins would be for Discord to add a way to turn off the ability for certain roles to access any member data. This should include disabling users not in your channels from appearing in search results (or in the output of `Guild.query_members()`). Greater control over visibility of member lists was suggested in [a support thread](https://support.discord.com/hc/en-us/community/posts/360055275992-Need-way-to-hide-list-of-members-), but the thread is already 2 years old without an official response. Having more control over whether members who are on our server can DM each other would also help.

We could set up a whole different Discord server to do the verification, then give the user an invite to the actual server. This would work but the UI would be bad especially for people who have never used Discord before.

A recent post on the support thread suggested that we set up [membership screening](https://support.discord.com/hc/en-us/articles/1500000466882-Rules-Screening-FAQ). This is a relatively new feature which means new users must accept rules before they can interact with the server and DM other members:

![Finding Users via the Search Box](assets/images/discord-spam/screening.png)

We are hoping enabling this will work for now, but it seems like only a matter of time before the spammers automate accepting the rules too.

## Conclusion

Spam is a problem almost as old as the internet. Apparently it still doesn't have an easy solution in one of the most cutting-edge chat clients. We hope Discord will throw some resources at this problem, and improve the permissions on the backend to enforce more of a "least privilege" model.
 
And for those who say, "it's just spam, get over it"... it's actually a bigger problem than you think. A lot of people have it set so a DM sends a notification to their device. Further, out of the thousands or even millions of people who get spammed, some actually will fall for the scam. Preventing these unsolicited messages is important to stop interruptions and criminal activity from leeching off the great communities we are trying to build. If there is no defence, it threatens getting out of control and people will have to move to other chat platforms.

In the meantime, if you have any ideas about how we could stop the spammers ourselves (apart from changing our server name so it doesn't have "crypto" and "hack" in it) please let us know.
