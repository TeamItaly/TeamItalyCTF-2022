import Builder from '../builder';

const builder = new Builder();
builder
  .loadString('Hello world!')
  .print()
  .jump(-builder.index - 2);
console.log(builder.build());
