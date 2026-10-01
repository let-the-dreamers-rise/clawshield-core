/**
 * Per-key serialisation: one decision at a time per agent.
 *
 * A decision reads the agent's ledger, awaits the policy provider (a network round trip when
 * sealed), then writes the ledger back. Two of those interleaved for the same agent would both
 * read the same spend and both be allowed. Queuing them per agent removes the race inside the
 * process; the ledger's version check in the store refuses anything that slips past it.
 *
 * The queue per key is bounded, so a client cannot park unbounded work behind a slow decision.
 */

export class QueueFullError extends Error {
  constructor(key: string) {
    super(`Too many decisions already queued for ${key}`);
    this.name = "QueueFullError";
  }
}

export function createKeyedMutex(maxPending = 16) {
  const tails = new Map<string, { readonly tail: Promise<void>; readonly pending: number }>();

  async function run<T>(key: string, fn: () => Promise<T>): Promise<T> {
    const prior = tails.get(key);
    if (prior && prior.pending >= maxPending) throw new QueueFullError(key);

    let release: () => void = () => {};
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const previous = prior?.tail ?? Promise.resolve();
    const tail = previous.then(() => gate);
    tails.set(key, { tail, pending: (prior?.pending ?? 0) + 1 });

    await previous;
    try {
      return await fn();
    } finally {
      release();
      const current = tails.get(key);
      if (current?.tail === tail) tails.delete(key);
      else if (current) tails.set(key, { tail: current.tail, pending: current.pending - 1 });
    }
  }

  return Object.freeze({ run, size: () => tails.size });
}
