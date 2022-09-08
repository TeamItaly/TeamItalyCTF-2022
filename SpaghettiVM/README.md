# TeamItaly CTF 2022

## Spaghetti VM (8 solves)

`Spaghetti VM` is a custom Javascript VM that runs very simple instructions with only a stack available (no registers).

The input comes from the first command line argument (`sys.argv[2]`) and is checked 4 characters
at a time (after checking the length).
It is possible to bruteforce the flag one char at a time and for this reason some counter-measures
against dynamic analysis have been added: the program will check itself by running another VM for some instructions
searching for newline characters.

### Solution

Both dynamic and static analysis are feasible.

_Dynamic analysis_ can be achieved by disabling the self check removing
the VMs inside the instructions, this can be achieved by simply deleting the for loop that is the core of the VM.

At this point the program can be run nicely formatted allowing to dump all instructions being called and the stack.
Note that the same is possible by editing the formatted file and then uglifying it again.

As the flag check is done char by char one can identify `===` instructions that fail and slowly reconstruct the flag,
be careful as the chars are checked in random order in groups of four.

_Static analysis_ is probably slower but can be performed by manually identifying the instructions called from the big
instructions array (each number is an index into that array) and map out the program. The only instruction that takes
an argument is the `LOAD` one, the argument is the index of the number to be loaded from the data array.
The original source for the challenge is ~900 lines as some operations need to be repeated, for this reason writing some
script to parse the program to identify repeating patterns is advised.

The flag is checked by xoring each character with a key that is generated piece by piece, the JS code for generating
the keys is:

```ts
const makeKey = (
  length: number,
  magic1: number,
  magic2: number
): { key: number[]; magics1: number[]; magics2: number[] } => {
  const key = [],
    magics1 = [],
    magics2 = [];
  for (let i = 0; i < Math.ceil(length / 4); i++) {
    magics1.push(magic1);
    magics2.push(magic2);

    const base = magic1 + magic2;
    key.push(base & 255);
    key.push((base >> 8) & 255);
    key.push((base >> 16) & 255);
    key.push((base >> 24) & 255);

    magic1 = magic2 ^ magic1 ^ ((magic1 << 26) | (magic1 >> 6)) ^ ((magic2 ^ magic1) << 9);
    magic2 = ((magic2 ^ magic1) << 13) | ((magic2 ^ magic1) >> 19);
  }

  return { key, magics1, magics2 };
};
```

Where `magic1` and `magic2` are hardcoded inside the program and loaded from 4 8-bits integers.
There is no JS code for the checking portion as it has been written directly in the VM "language", but here's the snippet:

```ts
const encryptFlag = (flag: string): { enc: number[]; magics1: number[]; magics2: number[] } => {
  const { key, magics1, magics2 } = makeKey(
    flag.length,
    randomInt(0xffffffff),
    randomInt(0xffffffff)
  );
  return {
    enc: key.map((x, i) => x ^ flag.charCodeAt(i)),
    magics1,
    magics2
  };
};

// Encrypt flag and compute all magics
const { enc, magics1, magics2 } = encryptFlag(flag);

// Compute order of checks
const shuffleList = (() => {
  const list = [];
  for (let i = 0; i < 4; i++) list.push(i);
  list.sort(() => 0.5 - Math.random());
  return list;
})();

const builder = new ChallengeBuilder();

// Get first argument
builder.loadFlag();

// Check we have the first argument
builder.dup().printNoIfFalse();

// Check the flag has the correct length
builder.len().load(flag.length).eeq().printNoIfFalse();

// Check flag 4 chars at a time
for (let i = 0; i < Math.ceil(flag.length / 4); i++) {
  builder.loadMagic(magics1[i]).loadMagic(magics2[i]).add();

  // Check 4 chars in pre-computed random order
  for (let j = 0; j < shuffleList.length; j++) {
    if (j < shuffleList.length - 1) builder.dup();

    switch (shuffleList[j]) {
      case 0:
        builder
          .load(255)
          .and()
          .loadFlag()
          .load(i * 4)
          .char()
          .xor()
          .load(enc[i * 4])
          .eeq()
          .printNoIfFalse();
        break;
      case 1:
        builder
          .rsh(8)
          .load(255)
          .and()
          .loadFlag()
          .load(i * 4 + 1)
          .char()
          .xor()
          .load(enc[i * 4 + 1])
          .eeq()
          .printNoIfFalse();
        break;
      case 2:
        builder
          .rsh(16)
          .load(255)
          .and()
          .loadFlag()
          .load(i * 4 + 2)
          .char()
          .xor()
          .load(enc[i * 4 + 2])
          .eeq()
          .printNoIfFalse();
        break;
      case 3:
        builder
          .rsh(24)
          .load(255)
          .and()
          .loadFlag()
          .load(i * 4 + 3)
          .char()
          .xor()
          .load(enc[i * 4 + 3])
          .eeq()
          .printNoIfFalse();
        break;
    }
  }
}

builder.loadString('ok!!').print();
```
