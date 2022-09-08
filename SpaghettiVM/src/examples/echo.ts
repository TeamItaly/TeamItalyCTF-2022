import Builder from '../builder';

const builder = new Builder();
builder.argv(2).print();
console.log(builder.build());
