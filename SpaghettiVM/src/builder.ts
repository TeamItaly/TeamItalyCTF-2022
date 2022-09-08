import { InstructionType } from './instructions';

export default class Builder {
  #program: string[];
  #data: number[];

  constructor() {
    this.#program = [];
    this.#data = [];
  }

  #emit(instr: InstructionType, ...args: number[]) {
    let data = `${instr}`;
    if (args.length > 0) {
      data += ' ';
      data += args.join(' ');
    }
    this.#program.push(data);
  }

  get index(): number {
    return this.#program.length;
  }

  add(): this {
    this.#emit(InstructionType.ADD);
    return this;
  }

  and(): this {
    this.#emit(InstructionType.AND);
    return this;
  }

  or(): this {
    this.#emit(InstructionType.OR);
    return this;
  }

  char(): this {
    this.#emit(InstructionType.CHAR);
    return this;
  }

  lsh(count: number): this {
    this.load(count);
    this.#emit(InstructionType.LSH);
    return this;
  }

  rsh(count: number): this {
    this.load(count);
    this.#emit(InstructionType.RSH);
    return this;
  }

  xor(): this {
    this.#emit(InstructionType.XOR);
    return this;
  }

  len(): this {
    this.#emit(InstructionType.LEN);
    return this;
  }

  eeq(): this {
    this.#emit(InstructionType.EEQ);
    return this;
  }

  print(): this {
    this.#emit(InstructionType.PRINT);
    return this;
  }

  exit(): this {
    this.#emit(InstructionType.EXIT);
    return this;
  }

  jump(offset: number): this {
    this.load(offset);
    this.#emit(InstructionType.JMP);
    return this;
  }

  jumpIfTrue(offset: number): this {
    this.load(offset);
    this.#emit(InstructionType.JMP_IF_TRUE);
    return this;
  }

  loadString(str: string): this {
    for (let i = 0; i < str.length; i++) {
      this.load(str.charCodeAt(i));
    }
    this.str(str.length);
    return this;
  }

  load(num: number): this {
    let index = this.#data.indexOf(Math.abs(num));
    if (index === -1) {
      this.#data.push(Math.abs(num));
      index = this.#data.length - 1;
    }

    this.#emit(InstructionType.LOAD, index);

    if (num < 0) this.#emit(InstructionType.NEG);

    return this;
  }

  str(len: number): this {
    this.load(len);
    this.#emit(InstructionType.STR);
    return this;
  }

  argv(index: number): this {
    this.load(index);
    this.#emit(InstructionType.ARGV);
    return this;
  }

  swap(): this {
    this.#emit(InstructionType.SWAP);
    return this;
  }

  not(): this {
    this.#emit(InstructionType.NOT);
    return this;
  }

  dup(): this {
    this.#emit(InstructionType.DUP);
    return this;
  }

  loadGlobal(name: string): this {
    this.loadString(name);
    this.#emit(InstructionType.EVAL);
    return this;
  }

  toStr(): this {
    this.#emit(InstructionType.TO_STR);
    return this;
  }

  build(exit = true): string {
    let out = '';
    if (this.#data.length > 0) out += `DATA ${this.#data.join(' ')}\n\n`;

    out += this.#program.join('\n');

    if (exit) out += '\nEXIT';

    return out;
  }
}
