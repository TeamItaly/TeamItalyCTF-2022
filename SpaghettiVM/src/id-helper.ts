import { identifier, Identifier } from '@babel/types';

export default class IdHelper {
  readonly #globals: { [name: string]: Identifier };
  readonly #debug: boolean;

  constructor(debug: boolean) {
    this.#debug = debug;
    this.#globals = {};
  }

  identifier(name: string): Identifier {
    if (name in this.#globals) return this.#globals[name];

    if (this.#debug) {
      const id = identifier(`${name}_${Math.round(Math.random() * 100000)}`);
      this.#globals[name] = id;
      return id;
    } else {
      const id = identifier(`_${Math.round(Math.random() * 100000)}`);
      this.#globals[name] = id;
      return id;
    }
  }
}
