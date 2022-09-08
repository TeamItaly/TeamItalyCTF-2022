import Builder from '../builder';

const builder = new Builder();
builder.load(0);
builder.dup().loadString(' - Hello world!').add().print();
builder
  .load(1)
  .add()
  .dup()
  .load(1337)
  .eeq()
  .not()
  .jumpIfTrue(-builder.index - 1);
console.log(builder.build());
