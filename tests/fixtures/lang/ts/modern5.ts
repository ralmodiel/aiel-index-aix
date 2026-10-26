import { readFile } from "node:fs/promises";

function logged(target: any, ctx: ClassMethodDecoratorContext) {
  return target;
}

export class Store<const T extends readonly string[]> {
  #items: T;
  accessor count = 0;
  constructor(items: T) {
    this.#items = items;
  }
  @logged
  list(): T {
    return this.#items;
  }
  static {
    Store.prototype.touch = () => 1;
  }
}

type Config = { port: number; host: string };
const cfg = { port: 80, host: "h" } satisfies Config;

export async function run(path: string) {
  await using h = await open(path);
  const text = await readFile(path, "utf8");
  return new Store(["a", "b"] as const).list().length + text.length;
}

declare function open(p: string): Promise<AsyncDisposable>;
export enum Mode { A = "a", B = "b" }
export function useIt<T>(x: NoInfer<T>): T { return x; }
