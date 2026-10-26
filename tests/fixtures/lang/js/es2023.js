export class Cache {
  static #count = 0;
  #data = new Map();
  items = [];
  static { Cache.#count = 1; }
  get size() { return this.#data.size; }
  set(k, v) { this.#data.set(k, v); return this; }
  last() { return this.items.findLast((x) => x > 1) ?? null; }
}

export const sorted = (xs) => xs.toSorted();
const cache = new Cache();
cache.set("a", 1);
const { promise, resolve } = Promise.withResolvers();
export default cache;
