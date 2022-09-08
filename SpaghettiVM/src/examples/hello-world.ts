import Builder from '../builder';

const builder = new Builder();
builder.loadString('Hello world!').print();
console.log(builder.build());
