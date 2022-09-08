import { encryptFlag } from './key';
import Builder from '../builder';
import { writeFileSync } from 'fs';

class ChallengeBuilder extends Builder {
  loadMagic(num: number): this {
    return this.load(num & 255)
      .load((num >> 8) & 255)
      .lsh(8)
      .or()
      .load((num >> 16) & 255)
      .lsh(16)
      .or()
      .load((num >> 24) & 255)
      .lsh(24)
      .or();
  }

  loadFlag(): this {
    return this.argv(2);
  }

  printNoIfFalse(): this {
    this.jumpIfTrue(7);

    const idx = this.index;
    this.loadString('no').print().exit();
    if (this.index - idx != 6) throw new Error('Bad jump!');

    return this;
  }
}

const run = (flag: string): string => {
  if (!flag) throw new Error('No flag given');

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

  return builder.build();
};

writeFileSync('gen/chall.txt', run(process.env.FLAG || ''));
