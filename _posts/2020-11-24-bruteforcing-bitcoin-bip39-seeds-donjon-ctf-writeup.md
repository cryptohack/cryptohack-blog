---
layout: post
title: "Bruteforcing Bitcoin BIP39 Seeds: Scissors Secret Sharing Ledger Donjon CTF Writeup"
categories: CTF Writeup
permalink: bruteforcing-bitcoin-bip39-seeds-donjon-ctf-writeup
author: joachim
meta: "Bruteforcing Bitcoin BIP39 Seeds: Scissors Secret Sharing Ledger Donjon CTF Writeup"
---

This challenge was one of the most straightforward to understand in the [Ledger Donjon CTF](https://donjon.ledger.com/Capture-the-Fortress/). It involved bruteforcing a 12-word Bitcoin seed passphrase by starting off with partial information about it. Writeup by joachim. 

## Scissors Secret Sharing (100pts)

> A company found a clever way to split its seed used to access their Bitcoin account: it has converted its seed phrase in 12 words with BIP39, and gave one word of the mnemonic to 12 employees.
> Alice entered the manager's office and was given the first word on a piece of paper. Then Bob got the second word. Eve entered, and when she opened the door, a draft made all the papers fell on the floor. They are now totally mixed up.
> The company is trying to access its funds at address 1EHiMwCPzcvMdeGowsowVF2X2PgLo67Qj7, without success yet. Can you help it?
> Flag is CTF{<4th word>\_<9th word>\_<11th word>\_<10th word>}.
> For example, is mnemonic is "satoshi security lonely cupboard magic grow cup buddy cancel desert jar face", address and flag will be: 1J5ryMwcUmb7XiuDPqYjxSywJNf37FNdmA and CTF{cupboard\_cancel\_jar\_desert}.

We were given a mnemonic.txt file which contains the following contents:
```
Alice  since
Bob    desk
???    zone
???    leaf
???    luggage
???    hobby
???    depart
???    thrive
???    practice
???    carbon
???    prison
???    ivory

Bitcoin address: 1EHiMwCPzcvMdeGowsowVF2X2PgLo67Qj7
```

We know 12 words would have $12! = 479001600$ permutations, far too much to brute-force. However, if the two first words are fixed, we only have to brute-force $10! = 3628800$ permutations, which is a bit more reasonable. The easiest way to do this is just generating all permutations of the last 10 words, and computing the address associated with the mnemonic.

Looking at the description, BIP39 (Bitcoin Improvement Proposal 39) is used for the mnemonic. This means the 11 first words of the mnemonic are data words, and the 12th word is a checksum word. We can use this to improve the performance of the brute-force even more, and exit before calculating the address if the checksum does not verify.

Finally, there are a lot of different ways to convert a mnemonic to an address. If we put the provided example in [https://iancoleman.io/bip39/](https://iancoleman.io/bip39/) and play around with some of the settings, we can see that the BIP44 derived address with index 0 is the one to target (no hardened addresses).

To implement this, we used the [Python BIP utility library](https://github.com/ebellocchia/bip_utils), which also has a handy example for key derivation.

```python
from bip_utils import Bip39SeedGenerator, Bip39MnemonicValidator
from bip_utils import Bip44, Bip44Coins, Bip44Changes
import itertools

address = "1EHiMwCPzcvMdeGowsowVF2X2PgLo67Qj7"
words_prefix = ['since', 'desk']
words = ['zone', 'leaf', 'luggage', 'hobby', 'depart', 'thrive', 'practice', 'carbon', 'prison', 'ivory']


def generate_address(words):
    mnemonic = " ".join(words)
    # Early exit if the checksum word is wrong.
    if not Bip39MnemonicValidator(mnemonic).Validate():
        return False

    # Derive the seed bytes from the mnemonic.
    seed_bytes = Bip39SeedGenerator(mnemonic).Generate()
    # Derive the master BIP44 key from the seed bytes.
    bip44_mst = Bip44.FromSeed(seed_bytes, Bip44Coins.BITCOIN)
    # Derive account 0 for Bitcoin: m/44'/0'/0'.
    bip44_acc = bip44_mst.Purpose().Coin().Account(0)
    # Derive the external chain: m/44'/0'/0'/0
    bip44_change = bip44_acc.Change(Bip44Changes.CHAIN_EXT)
    # Derive the first address of the external chain: m/44'/0'/0'/0/0
    bip44_addr = bip44_change.AddressIndex(0)
    return bip44_addr.PublicKey().ToAddress() == address


for perm in itertools.permutations(words):
    if generate_address(words_prefix + list(perm)):
        print(words_prefix + list(perm))
        exit()
```

After running for some time, this program outputs `['since', 'desk', 'thrive', 'carbon', 'zone', 'prison', 'leaf', 'depart', 'hobby', 'practice', 'ivory', 'luggage']`.
This results in the flag `CTF{carbon_hobby_ivory_practice}`.



