/**
 * Per-client token buckets.
 *
 * In memory and per process: enough to keep one abusive client from monopolising a verifier
 * instance. A fleet behind a load balancer would move this to shared storage; the interface
 * here is the seam for that.
 */

export interface RateLimitConfig {
  /** Burst size: requests a fresh client may make at once. */
  readonly capacity: number;
  /** Sustained rate. Zero disables refill, which is only useful in tests. */
  readonly refillPerSecond: number;
  /** Clients tracked before the oldest are evicted, bounding memory under address churn. */
  readonly maxClients?: number;
}

export interface RateDecision {
  readonly allowed: boolean;
  /** Seconds until a token is available, when not allowed. */
  readonly retryAfterSeconds: number;
}

interface Bucket {
  readonly tokens: number;
  readonly updatedAt: number;
}

export function createRateLimiter(config: RateLimitConfig, now: () => number = () => Date.now()) {
  const maxClients = config.maxClients ?? 10_000;
  const buckets = new Map<string, Bucket>();

  function take(client: string): RateDecision {
    const t = now();
    const prior = buckets.get(client) ?? { tokens: config.capacity, updatedAt: t };
    const refilled = Math.min(
      config.capacity,
      prior.tokens + ((t - prior.updatedAt) / 1000) * config.refillPerSecond,
    );
    const allowed = refilled >= 1;
    const next: Bucket = { tokens: allowed ? refilled - 1 : refilled, updatedAt: t };

    buckets.delete(client);
    buckets.set(client, next);
    if (buckets.size > maxClients) {
      const oldest = buckets.keys().next().value;
      if (oldest !== undefined) buckets.delete(oldest);
    }

    const deficit = 1 - next.tokens;
    const retryAfterSeconds =
      allowed ? 0 : config.refillPerSecond > 0 ? Math.max(1, Math.ceil(deficit / config.refillPerSecond)) : 60;
    return { allowed, retryAfterSeconds };
  }

  return Object.freeze({ take });
}
