---
layout: post
title: "Hardware Wallet Sudoku: Elliptic Relations Ledger Donjon CTF Writeup"
categories: CTF Writeup
permalink: hardware-wallet-sudoku-elliptic-relations-donjon-ctf-writeup
author: rbtree
meta: "Hardware Wallet Sudoku: Elliptic Relations Ledger Donjon CTF Writeup"
---

This challenge was the only one in the reverse engineering category of [Ledger Donjon CTF](https://donjon.ledger.com/Capture-the-Fortress/). Writeup by [rbtree](http://rb-tree.xyz/).

## Elliptic Relations (300pts)

>We found this binary, which seems to come from a well known hardware wallet.
>We were told it contains a secret. Can you retrieve it?

First looking at this, there are too many syscalls (`SVC 1`) which are unknown. After searching, we found out that there's an emulator for Ledger wallets called [speculos](https://github.com/LedgerHQ/speculos), and it was able to figure out how those syscalls work.

For example, look at this syscall function:
```
.text:C0D012C0 cx_rng_ID_IN                            ; CODE XREF: sub_C0D01020+8A↑p
.text:C0D012C0
.text:C0D012C0 var_18          = -0x18
.text:C0D012C0 var_14          = -0x14
.text:C0D012C0
.text:C0D012C0                 PUSH    {R3-R7,LR}
.text:C0D012C2                 STR     R0, [SP,#0x18+var_18]
.text:C0D012C4                 STR     R1, [SP,#0x18+var_14]
.text:C0D012C6                 LDR     R0, =0x6000052C
.text:C0D012C8                 MOV     R1, SP
.text:C0D012CA                 BL      call_svc_1
.text:C0D012CE                 LDR     R0, [SP,#0x18+var_14]
.text:C0D012D0                 ADD     SP, SP, #0x10
.text:C0D012D2                 POP     {R7,PC}
```

It set `R0 = 0x600052C`, and `R1 = arguments`. If you look at `bolos_syscalls_1.6.h` in speculos, you can find out that this function is `cx_rng_ID_IN`, and also figure out how the syscall works by searching `cx_rng`.

```c
// bolos_syscalls_1.6.h
...
#define SYSCALL_cx_rng_u32_ID_IN  0x600089ecUL
#define SYSCALL_cx_rng_u32_ID_OUT  0x900089d4UL
#define SYSCALL_cx_rng_ID_IN  0x6000052cUL
#define SYSCALL_cx_rng_ID_OUT  0x90000567UL
#define SYSCALL_cx_hash_ID_IN  0x6000073bUL
...
```

```c
// emu_cx.c
/* not secure, but this is clearly not the goal of this emulator */
unsigned long sys_cx_rng(uint8_t *buffer, unsigned int length)
{
  unsigned int i;

  if (!initialized) {
    srand(get_rng_seed_from_env("RNG_SEED"));
    initialized = true;
  }

  for (i = 0; i < length; i++) {
    buffer[i] = rand() & 0xff;
  }

  return 0;
}
```

After renaming all the syscall functions, we found a suspicious function:
```c
int __fastcall sub_C0D000D4(int a1)
{
  char *v2; // r7
  int v3; // r1
  int i; // r5
  int v5; // r0
  int v6; // r6
  int v7; // r0
  int v9; // [sp+8h] [bp-98h]
  cx_ecfp_256_public_key_s pub_key; // [sp+18h] [bp-88h] BYREF
  cx_ecfp_256_private_key_s priv_key; // [sp+64h] [bp-3Ch] BYREF

  v2 = &byte_C0D02C29[1];
  v3 = 0;
  while ( v3 != 27 )
  {
    v9 = v3;
    cx_ecfp_init_private_key_ID_IN(CX_CURVE_SECP256K1, a1 + byte_C0D02C29[9 * v3], 1, (int)&priv_key);
    cx_ecfp_generate_pair_ID_IN(CX_CURVE_SECP256K1, (int)&pub_key, (int)&priv_key, 1);
    if ( !pub_key.W_len )
      return 0;
    for ( i = 0; i != 8; ++i )
    {
      v5 = v2[i];
      if ( !*(_BYTE *)(a1 + v5) )
        return 0;
      cx_ecfp_scalar_mult_ID_IN(LOBYTE(pub_key.curve), (int)pub_key.W, pub_key.W_len, a1 + v5, 1);
    }
    v6 = 0;
    if ( pub_key.W_len == 65 )
    {
      v7 = sub_C0D02A80(pub_key.W, dword_C0D02D1C, 65);
      v2 += 9;
      v3 = v9 + 1;
      if ( !v7 )
        continue;
    }
    return v6;
  }
  return 1;
}
```

It calculates `(a1 + byte_C0D02C29[9 * i + 0]) * ... * (a1 + byte_C0D02C29[9 * i + 8]) * G` for each `i = 0..26`, and then compare with the point `dword_C0D02D1C`. `a1` is `byte_20001800`, which is 81-bytes. It seems like Sudoku, doesn't it?

Next, let's see the setter of `byte_20001800`.
```c
int __fastcall set_byte_20001800(unsigned int idx, char value)
{
  int v2; // r4
  int v6; // [sp+4h] [bp-1Ch] BYREF
  _BYTE v7[24]; // [sp+8h] [bp-18h] BYREF

  v2 = -1;
  if ( idx <= 0x50 && !byte_20001800[idx] )
  {
    LOBYTE(v6) = 64;
    v7[0] = value;
    if ( cx_math_is_prime_ID_IN((int)v7, 1) )
    {
      if ( cx_math_cmp_ID_IN(v7, &v6, 1) < 0 )
      {
        byte_20001800[idx] = value;
        v2 = 0;
      }
    }
  }
  return v2;
}
```

Okay, every value should be a prime number less than 64.
From this, we can brute-force to get `a` that `dword_C0D02D1C = a * G`.

```python
from ecdsa import VerifyingKey, SECP256k1
from ecdsa.ellipticcurve import Point
from ecdsa.util import sigencode_string
from ecdsa.numbertheory import inverse_mod

with open('elliptic_relations.elf', 'rb') as f:
    data = f.read()

byte_C0D02C29 = data[0x12C29:0x12C29 + 9 * 27]
dword_C0D02D1C = data[0x12D1C:0x12D1C + 65]
dword_C0D02C14 = data[0x12C14:0x12C14 + 21]

# primes under 64
primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61]
assert max(byte_C0D02C29) == 80

arr = dword_C0D02C14 + b'\x01' * 60

x = 1
unknown = []
for v in byte_C0D02C29[18:27]:
    if v <= 20:
        print(arr[v])
        x *= arr[v]
    else:
        unknown.append(v)

import itertools

for x1, x2, x3, x4, x5 in itertools.product(primes, repeat=5):
    print(x1, x2, x3, x4, x5)
    y = x * x1 * x2 * x3 * x4 * x5

    point = SECP256k1.generator * y
    if dword_C0D02D1C == bytes.fromhex("04{:064x}{:064x}".format(point.x(), point.y())):
        print("WOW")
        break
```

After running the script, we got `dword_C0D02D1C = 5 * 11 * 13 * 19 * 23 * 31 * 37 * 43 * 53 * G`. Nine different primes. So, Sudoku confirmed.

Flag-printing logic is here (run after `sub_C0D000D4`):
```c
int sub_C0D00180()
{
  int i; // r0
  char v2[124]; // [sp+Ch] [bp-7Ch] BYREF

  cx_sha256_init_ID_IN(v2);
  cx_hash_ID_IN((int)v2, 1, (int)load_sth, 81, (int)byte_20001A6C, 32);
  for ( i = 0; i != 26; ++i )
    byte_20001A6C[i] ^= *((_BYTE *)dword_C0D02EFC + i);
  return sub_C0D001D0(26, 1);
}
```

Finally, here is the solver that uses z3 to solve the Sudoku puzzle:
```python
from ecdsa import VerifyingKey, SECP256k1
from ecdsa.ellipticcurve import Point
from ecdsa.util import sigencode_string
from ecdsa.numbertheory import inverse_mod

with open('elliptic_relations.elf', 'rb') as f:
    data = f.read()

byte_C0D02C29 = data[0x12C29:0x12C29 + 9 * 27]
assert max(byte_C0D02C29) == 80
dword_C0D02D1C = data[0x12D1C:0x12D1C + 65]
dword_C0D02C14 = data[0x12C14:0x12C14 + 21]
dword_C0D02EFC = data[0x12EFC:0x12EFC + 26]

from z3 import *

primes_to_int = {5: 1, 11: 2, 13: 3, 19: 4, 23: 5, 31: 6, 37: 7, 43: 8, 53: 9}
int_to_primes = [0, 5, 11, 13, 19, 23, 31, 37, 43, 53]

arr = [Int('Arr{}'.format(i)) for i in range(81)]
s = Solver()

for i in range(21):
    s.add(primes_to_int[dword_C0D02C14[i]] == arr[i])
for i in range(81):
    s.add(And(1 <= arr[i], arr[i] <= 9))

for v3 in range(27):
    s.add(Distinct([arr[v] for v in byte_C0D02C29[9 * v3:9 * v3 + 9]]))

if s.check() == unsat:
    exit(0)

m = s.model()
ans = bytes(int_to_primes[m[v].as_long()] for v in arr)

import hashlib

hasher = hashlib.sha256()
hasher.update(ans)
hsh = bytearray(hasher.digest())

for i in range(26):
    hsh[i] ^= dword_C0D02EFC[i]

print(hsh)
```

The flag is `CTF{r4nD0m1Z3d_sUD0ku_FTW}`.
