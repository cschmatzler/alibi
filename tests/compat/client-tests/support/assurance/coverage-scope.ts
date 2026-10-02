import { AsyncLocalStorage } from "node:async_hooks";

/** A delayed task from a previous request must not credit the next scenario. */
export class CoverageScope {
  active: string | null = null;
  private resetting = false;
  private readonly context = new AsyncLocalStorage<string | null>();

  run<T>(work: () => T): T {
    return this.context.run(this.active, work);
  }
  accepts(): boolean {
    return this.resetting || (this.active !== null && this.context.getStore() === this.active);
  }
  reset(work: () => void) {
    this.resetting = true;
    try {
      work();
    } finally {
      this.resetting = false;
    }
  }
  counters<T extends object>(value: T): T {
    return new Proxy(value, {
      set: (target, key, next) => {
        if (this.accepts()) Reflect.set(target, key, next);
        return true;
      },
    });
  }
}
