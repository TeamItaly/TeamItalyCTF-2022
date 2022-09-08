import generate from '@babel/generator';
import {
  arrayExpression,
  assignmentExpression,
  binaryExpression,
  blockStatement,
  callExpression,
  expressionStatement,
  forStatement,
  functionExpression,
  identifier,
  ifStatement,
  memberExpression,
  numericLiteral,
  program,
  Statement,
  stringLiteral,
  throwStatement,
  updateExpression,
  variableDeclaration,
  variableDeclarator
} from '@babel/types';
import { readFileSync, writeFileSync } from 'fs';
import { generateInstruction, Instruction, InstructionType } from './instructions';
import { parse } from './parser';
import IdHelper from './id-helper';
import Builder from './builder';

const MAIN_FUNC_NAME = 'svm';

const buildSelfCheckVmSource = (): string => {
  class SelfCheckVmBuilder extends Builder {
    loadSelfStr(): this {
      return this.loadGlobal(MAIN_FUNC_NAME).toStr();
    }

    printNoIfTrue(): this {
      builder.not().jumpIfTrue(25);

      const idx = builder.index;
      builder.loadString('do not change me pls').print().exit();
      if (builder.index - idx != 24) throw new Error('Bad jump!');

      return this;
    }
  }

  const builder = new SelfCheckVmBuilder();

  builder.load(0);

  const idx = builder.index;
  builder.dup().loadSelfStr().swap();
  builder.char().load(10).eeq();
  builder.printNoIfTrue();
  builder
    .load(1)
    .add()
    .dup()
    .loadSelfStr()
    .len()
    .eeq()
    .not()
    .jumpIfTrue(idx - builder.index - 2);

  return builder.build(false);
};

const generateInstructionsArray = (
  id: IdHelper,
  used: InstructionType[],
  debug: boolean,
  selfCheck: boolean
): Statement => {
  const elems = [];
  for (const instr of used) {
    const func = generateInstruction(id, instr, debug);

    if (selfCheck && Math.random() > 0.75) {
      const selfCheckVm = buildVm(buildSelfCheckVmSource(), new IdHelper(debug), debug, false);

      // Mix the two arrays without changing orders
      const ratio = selfCheckVm.length / (selfCheckVm.length + func.body.body.length);
      const mixedBody: Statement[] = [];
      while (func.body.body.length > 0 || selfCheckVm.length > 0) {
        let item;
        if (Math.random() > ratio) item = func.body.body.shift();
        else item = selfCheckVm.shift();

        if (!!item) mixedBody.push(item);
      }

      func.body.body = mixedBody;
    }

    elems.push(func);
  }

  return variableDeclaration('const', [
    variableDeclarator(id.identifier('instructions'), arrayExpression(elems))
  ]);
};

const generateDataBlock = (id: IdHelper, data: number[]): Statement => {
  return variableDeclaration('const', [
    variableDeclarator(id.identifier('data'), arrayExpression(data.map((x) => numericLiteral(x))))
  ]);
};

const generateProgramArgs = (id: IdHelper, instructions: Instruction[]): Statement => {
  return variableDeclaration('const', [
    variableDeclarator(
      id.identifier('args'),
      arrayExpression(
        instructions.map((x) => arrayExpression(x.args.map((x) => numericLiteral(x))))
      )
    )
  ]);
};

const generateProgram = (
  id: IdHelper,
  instructions: Instruction[],
  usedInstructions: InstructionType[]
): Statement => {
  return variableDeclaration('const', [
    variableDeclarator(
      id.identifier('program'),
      arrayExpression(instructions.map((x) => numericLiteral(usedInstructions.indexOf(x.type))))
    )
  ]);
};

const generateExecutionBlock = (id: IdHelper, withJumps: boolean, debug: boolean): Statement[] => {
  const forBody: Statement[] = [];
  if (withJumps) {
    forBody.push(
      variableDeclaration('const', [
        variableDeclarator(
          id.identifier('jmp'),
          callExpression(
            memberExpression(
              id.identifier('instructions'),
              memberExpression(id.identifier('program'), id.identifier('i'), true),
              true
            ),
            [
              id.identifier('stack'),
              memberExpression(id.identifier('args'), id.identifier('i'), true)
            ]
          )
        )
      ])
    );
    forBody.push(
      ifStatement(
        binaryExpression('!==', id.identifier('jmp'), identifier('undefined')),
        expressionStatement(
          assignmentExpression(
            '+=',
            id.identifier('i'),
            binaryExpression('-', id.identifier('jmp'), numericLiteral(1))
          )
        )
      )
    );
  } else {
    forBody.push(
      expressionStatement(
        callExpression(
          memberExpression(
            id.identifier('instructions'),
            memberExpression(id.identifier('program'), id.identifier('i'), true),
            true
          ),
          [
            id.identifier('stack'),
            memberExpression(id.identifier('args'), id.identifier('i'), true)
          ]
        )
      )
    );
  }

  const out: Statement[] = [
    variableDeclaration('const', [variableDeclarator(id.identifier('stack'), arrayExpression([]))]),
    forStatement(
      variableDeclaration('let', [variableDeclarator(id.identifier('i'), numericLiteral(0))]),
      binaryExpression(
        '<',
        id.identifier('i'),
        memberExpression(id.identifier('program'), identifier('length'))
      ),
      updateExpression('++', id.identifier('i')),
      blockStatement(forBody)
    )
  ];

  if (debug) {
    out.push(
      ifStatement(
        binaryExpression(
          '!==',
          memberExpression(id.identifier('stack'), identifier('length')),
          numericLiteral(0)
        ),
        throwStatement(stringLiteral('Stack is not empty'))
      )
    );
  }

  return out;
};

const buildVm = (source: string, id: IdHelper, debug: boolean, selfCheck: boolean): Statement[] => {
  const parsedInstructions = parse(source);

  const dataBlock: number[] = [];
  const usedInstructionTypes: InstructionType[] = [];

  let hasJumps = false;
  for (let i = parsedInstructions.length - 1; i >= 0; i--) {
    const instr = parsedInstructions[i];
    if (instr.type === InstructionType.DATA) {
      dataBlock.push(...instr.args);
      parsedInstructions.splice(i, 1);
      continue;
    }

    if (usedInstructionTypes.indexOf(instr.type) === -1) usedInstructionTypes.push(instr.type);

    if (instr.type === InstructionType.JMP || instr.type === InstructionType.JMP_IF_TRUE)
      hasJumps = true;
  }

  // This isn't a good way, but good enough for this.
  usedInstructionTypes.sort(() => 0.5 - Math.random());

  const body = [];
  body.push(generateDataBlock(id, dataBlock));
  body.push(generateInstructionsArray(id, usedInstructionTypes, debug, selfCheck));
  body.push(generateProgramArgs(id, parsedInstructions));
  body.push(generateProgram(id, parsedInstructions, usedInstructionTypes));
  body.push(...generateExecutionBlock(id, hasJumps, debug));
  return body;
};

const run = (source: string, debug = false): string => {
  const id = new IdHelper(debug);

  return generate(
    program([
      expressionStatement(
        callExpression(
          functionExpression(
            identifier(MAIN_FUNC_NAME),
            [],
            blockStatement(buildVm(source, id, debug, true))
          ),
          []
        )
      )
    ]),
    { minified: !debug }
  ).code;
};

writeFileSync('gen/index.js', run(readFileSync(process.argv[2]).toString(), false));
