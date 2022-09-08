import { randomInt } from 'crypto';

// JavaScript bitwise operations work on 32-bit,
// translating this to other languages is not trivial.
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

export const encryptFlag = (
  flag: string
): { enc: number[]; magics1: number[]; magics2: number[] } => {
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
