import { Instruction, InstructionType } from './instructions';

const asInteger = (arg: string): number => {
  const num = Number.parseInt(arg);
  if (Number.isNaN(num)) throw new Error('Invalid arguments, not an integer');

  if (num < 0) throw new Error('Invalid arguments, integer must be non-negative');

  return num;
};

export const parse = (content: string): Instruction[] => {
  const lines = content
    .split('\n')
    .map((x) => x.trim())
    .filter((x) => x.length > 0 && !x.startsWith('#'));

  const out = [];
  for (const line of lines) {
    const args = line.split(/\s+/);
    const instr = args.shift() as InstructionType;

    switch (instr as InstructionType) {
      case InstructionType.LOAD:
        if (args.length !== 1) throw new Error('Invalid arguments for instruction LOAD');

        out.push({ type: InstructionType.LOAD, args: [asInteger(args[0])] });
        break;
      case InstructionType.DATA:
        if (args.length === 0) throw new Error('No bytes provided for instruction DATA');

        out.push({ type: InstructionType.DATA, args: args.map((x) => asInteger(x)) });
        break;
      default:
        if (args.length !== 0) throw new Error(`Invalid arguments for instruction ${instr}`);

        out.push({ type: instr, args: [] });
        break;
    }
  }

  return out;
};
