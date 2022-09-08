import {
  assignmentExpression,
  binaryExpression,
  blockStatement,
  callExpression,
  Expression,
  ExpressionStatement,
  expressionStatement,
  FunctionExpression,
  functionExpression,
  Identifier,
  identifier,
  ifStatement,
  MemberExpression,
  memberExpression,
  numericLiteral,
  returnStatement,
  spreadElement,
  Statement,
  stringLiteral,
  unaryExpression,
  variableDeclaration,
  variableDeclarator
} from '@babel/types';
import IdHelper from './id-helper';

export enum InstructionType {
  ADD = 'ADD',
  AND = 'AND',
  ARGV = 'ARGV',
  CHAR = 'CHAR',
  DATA = 'DATA',
  DUP = 'DUP',
  EEQ = 'EEQ',
  EVAL = 'EVAL',
  EXIT = 'EXIT',
  JMP = 'JMP',
  JMP_IF_TRUE = 'JMP_IF_TRUE',
  LEN = 'LEN',
  LOAD = 'LOAD',
  LSH = 'LSH',
  NEG = 'NEG',
  NOT = 'NOT',
  OR = 'OR',
  PRINT = 'PRINT',
  RSH = 'RSH',
  STR = 'STR',
  SWAP = 'SWAP',
  TO_STR = 'TO_STR',
  XOR = 'XOR'
}

export type Instruction = {
  type: InstructionType;
  args: number[];
};

const shrinkStack = (ctx: Identifier, count: number | Expression): ExpressionStatement => {
  return expressionStatement(
    assignmentExpression(
      '-=',
      memberExpression(ctx, identifier('length')),
      typeof count === 'number' ? numericLiteral(count) : count
    )
  );
};

const accessStack = (ctx: Identifier, index: number | Expression): MemberExpression => {
  return memberExpression(
    ctx,
    binaryExpression(
      '-',
      memberExpression(ctx, identifier('length')),
      typeof index === 'number' ? numericLiteral(index) : index
    ),
    true
  );
};

const assignStack = (
  ctx: Identifier,
  index: number | Expression,
  expr: Expression
): ExpressionStatement => {
  return expressionStatement(assignmentExpression('=', accessStack(ctx, index), expr));
};

const generateBinaryInstruction = (
  ctx: Identifier,
  op:
    | '+'
    | '-'
    | '/'
    | '%'
    | '*'
    | '**'
    | '&'
    | '|'
    | '>>'
    | '>>>'
    | '<<'
    | '^'
    | '=='
    | '==='
    | '!='
    | '!=='
    | 'in'
    | 'instanceof'
    | '>'
    | '<'
    | '>='
    | '<='
    | '|>'
): Statement[] => {
  return [
    assignStack(ctx, 2, binaryExpression(op, accessStack(ctx, 2), accessStack(ctx, 1))),
    shrinkStack(ctx, 1)
  ];
};

const generateUnaryInstruction = (
  ctx: Identifier,
  op: 'void' | 'throw' | 'delete' | '!' | '+' | '-' | '~' | 'typeof'
): Statement[] => {
  return [assignStack(ctx, 1, unaryExpression(op, accessStack(ctx, 1)))];
};

export const generateInstruction = (
  id: IdHelper,
  instr: InstructionType,
  debug: boolean
): FunctionExpression => {
  const ctxIdentifier = identifier(`${debug ? 'ctx' : ''}_${Math.round(Math.random() * 100000)}`);
  const argsIdentifier = identifier(`${debug ? 'args' : ''}_${Math.round(Math.random() * 100000)}`);

  if (instr === InstructionType.LOAD) {
    const block = [
      assignStack(
        ctxIdentifier,
        0,
        memberExpression(
          id.identifier('data'),
          memberExpression(argsIdentifier, numericLiteral(0), true),
          true
        )
      )
    ];

    if (debug) {
      block.unshift(
        expressionStatement(
          callExpression(memberExpression(identifier('console'), identifier('debug')), [
            stringLiteral(instr.toString()),
            spreadElement(identifier('arguments'))
          ])
        )
      );
    }

    return functionExpression(null, [ctxIdentifier, argsIdentifier], blockStatement(block));
  }

  const block = (() => {
    switch (instr) {
      case InstructionType.DATA:
        throw new Error('Instruction DATA cannot be generated');
      case InstructionType.DUP:
        return [assignStack(ctxIdentifier, 0, accessStack(ctxIdentifier, 1))];
      case InstructionType.NOT:
        return generateUnaryInstruction(ctxIdentifier, '!');
      case InstructionType.EEQ:
        return generateBinaryInstruction(ctxIdentifier, '===');
      case InstructionType.ADD:
        return generateBinaryInstruction(ctxIdentifier, '+');
      case InstructionType.OR:
        return generateBinaryInstruction(ctxIdentifier, '|');
      case InstructionType.RSH:
        return generateBinaryInstruction(ctxIdentifier, '>>');
      case InstructionType.LSH:
        return generateBinaryInstruction(ctxIdentifier, '<<');
      case InstructionType.XOR:
        return generateBinaryInstruction(ctxIdentifier, '^');
      case InstructionType.AND:
        return generateBinaryInstruction(ctxIdentifier, '&');
      case InstructionType.NEG:
        return generateUnaryInstruction(ctxIdentifier, '-');
      case InstructionType.CHAR:
        return [
          assignStack(
            ctxIdentifier,
            2,
            callExpression(
              memberExpression(accessStack(ctxIdentifier, 2), identifier('charCodeAt')),
              [accessStack(ctxIdentifier, 1)]
            )
          ),
          shrinkStack(ctxIdentifier, 1)
        ];
      case InstructionType.LEN:
        return [
          assignStack(
            ctxIdentifier,
            1,
            memberExpression(accessStack(ctxIdentifier, 1), identifier('length'))
          )
        ];
      case InstructionType.EXIT:
        return [
          expressionStatement(
            callExpression(memberExpression(identifier('process'), identifier('exit')), [])
          )
        ];
      case InstructionType.STR:
        return [
          assignStack(
            ctxIdentifier,
            binaryExpression('+', accessStack(ctxIdentifier, 1), numericLiteral(1)),
            callExpression(memberExpression(identifier('String'), identifier('fromCharCode')), [
              spreadElement(
                callExpression(memberExpression(ctxIdentifier, identifier('slice')), [
                  binaryExpression(
                    '-',
                    unaryExpression('-', accessStack(ctxIdentifier, 1)),
                    numericLiteral(1)
                  ),
                  numericLiteral(-1)
                ])
              )
            ])
          ),
          shrinkStack(ctxIdentifier, accessStack(ctxIdentifier, 1))
        ];
      case InstructionType.PRINT:
        return [
          expressionStatement(
            callExpression(memberExpression(identifier('console'), identifier('log')), [
              accessStack(ctxIdentifier, 1)
            ])
          ),
          shrinkStack(ctxIdentifier, 1)
        ];
      case InstructionType.ARGV:
        return [
          assignStack(
            ctxIdentifier,
            1,
            memberExpression(
              memberExpression(identifier('process'), identifier('argv')),
              accessStack(ctxIdentifier, 1),
              true
            )
          )
        ];
      case InstructionType.JMP:
        return [
          variableDeclaration('const', [
            variableDeclarator(identifier('loc'), accessStack(ctxIdentifier, 1))
          ]),
          shrinkStack(ctxIdentifier, 1),
          returnStatement(identifier('loc'))
        ];
      case InstructionType.JMP_IF_TRUE:
        return [
          ifStatement(
            accessStack(ctxIdentifier, 2),
            blockStatement([
              variableDeclaration('const', [
                variableDeclarator(identifier('loc'), accessStack(ctxIdentifier, 1))
              ]),
              shrinkStack(ctxIdentifier, 2),
              returnStatement(identifier('loc'))
            ]),
            shrinkStack(ctxIdentifier, 2)
          )
        ];
      case InstructionType.EVAL:
        return [
          assignStack(
            ctxIdentifier,
            1,
            callExpression(identifier('eval'), [accessStack(ctxIdentifier, 1)])
          )
        ];
      case InstructionType.TO_STR:
        return [
          assignStack(
            ctxIdentifier,
            1,
            callExpression(
              memberExpression(accessStack(ctxIdentifier, 1), identifier('toString')),
              []
            )
          )
        ];
      case InstructionType.SWAP:
        return [
          variableDeclaration('const', [
            variableDeclarator(id.identifier('swap'), accessStack(ctxIdentifier, 1))
          ]),
          assignStack(ctxIdentifier, 1, accessStack(ctxIdentifier, 2)),
          assignStack(ctxIdentifier, 2, id.identifier('swap'))
        ];
      default:
        throw new Error(`Unknown instruction: ${instr}`);
    }
  })();

  if (debug) {
    block.unshift(
      expressionStatement(
        callExpression(memberExpression(identifier('console'), identifier('debug')), [
          stringLiteral(instr.toString()),
          spreadElement(identifier('arguments'))
        ])
      )
    );
  }

  return functionExpression(null, [ctxIdentifier], blockStatement(block));
};
