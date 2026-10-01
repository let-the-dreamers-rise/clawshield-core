/**
 * Small, strict validators for data that crossed a trust boundary.
 *
 * Each takes the value and the path it was found at, and either returns the value narrowed to
 * its type or throws a SchemaError naming that path. Objects are closed: an unknown key is an
 * error, because a receipt field the parser does not know about is still covered by the
 * signature, and silently dropping it would verify something other than what was signed.
 */

export class SchemaError extends Error {
  readonly path: string;

  constructor(path: string, message: string) {
    super(`${path || "(root)"}: ${message}`);
    this.name = "SchemaError";
    this.path = path;
  }
}

export type Obj = Readonly<Record<string, unknown>>;

export const at = (path: string, key: string | number): string =>
  typeof key === "number" ? `${path}[${key}]` : path ? `${path}.${key}` : key;

export function record(v: unknown, path: string, required: readonly string[], optional: readonly string[] = []): Obj {
  if (typeof v !== "object" || v === null || Array.isArray(v)) throw new SchemaError(path, "expected an object");
  const o = v as Obj;
  const known = new Set([...required, ...optional]);
  for (const key of Object.keys(o)) {
    if (!known.has(key)) throw new SchemaError(at(path, key), "unknown field");
  }
  for (const key of required) {
    if (!Object.hasOwn(o, key) || o[key] === undefined) throw new SchemaError(at(path, key), "required");
  }
  return o;
}

export function str(v: unknown, path: string, opts: { nonEmpty?: boolean; max?: number } = {}): string {
  if (typeof v !== "string") throw new SchemaError(path, "expected a string");
  if (opts.nonEmpty && v.length === 0) throw new SchemaError(path, "must not be empty");
  if (v.length > (opts.max ?? 4096)) throw new SchemaError(path, "too long");
  return v;
}

export function hex64(v: unknown, path: string): string {
  const s = str(v, path);
  if (!/^[0-9a-f]{64}$/.test(s)) throw new SchemaError(path, "expected 64 lowercase hex characters");
  return s;
}

export function int(v: unknown, path: string, min = Number.MIN_SAFE_INTEGER): number {
  if (typeof v !== "number" || !Number.isSafeInteger(v) || v < min) {
    throw new SchemaError(path, `expected an integer >= ${min}`);
  }
  return v;
}

export function finite(v: unknown, path: string): number {
  if (typeof v !== "number" || !Number.isFinite(v)) throw new SchemaError(path, "expected a finite number");
  return v;
}

export function big(v: unknown, path: string): bigint {
  if (typeof v !== "bigint") throw new SchemaError(path, 'expected a bigint ({"$bigint":"..."})');
  return v;
}

export function bool(v: unknown, path: string): boolean {
  if (typeof v !== "boolean") throw new SchemaError(path, "expected a boolean");
  return v;
}

export function oneOf<T extends string>(v: unknown, path: string, values: readonly T[]): T {
  if (typeof v !== "string" || !(values as readonly string[]).includes(v)) {
    throw new SchemaError(path, `expected one of ${values.join(", ")}`);
  }
  return v as T;
}

export function array<T>(v: unknown, path: string, item: (x: unknown, p: string) => T, max = 10_000): readonly T[] {
  if (!Array.isArray(v)) throw new SchemaError(path, "expected an array");
  if (v.length > max) throw new SchemaError(path, `at most ${max} entries`);
  return v.map((x, i) => item(x, at(path, i)));
}

export const strings = (v: unknown, path: string): readonly string[] => array(v, path, (x, p) => str(x, p));

/** Optional field: undefined stays undefined, anything else must parse. */
export function opt<T>(o: Obj, key: string, path: string, parse: (x: unknown, p: string) => T): T | undefined {
  return o[key] === undefined ? undefined : parse(o[key], at(path, key));
}

/** Drop undefined-valued keys, matching canonical form. */
export function compact<T extends object>(o: T): T {
  return Object.fromEntries(Object.entries(o).filter(([, v]) => v !== undefined)) as T;
}
