/**
 * Deterministic serialisation.
 *
 * Signatures are worthless if two parties can serialise the same object into different bytes.
 * JSON.stringify does not guarantee key order for us here, and it cannot represent bigint at
 * all, so we define our own canonical form:
 *
 *   - object keys sorted lexicographically by UTF-16 code unit
 *   - bigint encoded as a decimal string with a type tag, so 1n and "1" never collide
 *   - undefined-valued keys omitted entirely
 *   - no insignificant whitespace
 */

export type Canonicalisable =
  | string
  | number
  | boolean
  | bigint
  | null
  | undefined
  | readonly Canonicalisable[]
  | { readonly [k: string]: Canonicalisable };

export const BIGINT_TAG = "$bigint";

export function canonicalise(value: Canonicalisable): string {
  if (value === null) return "null";
  if (value === undefined) return "null";

  switch (typeof value) {
    case "string":
      return JSON.stringify(value);
    case "boolean":
      return value ? "true" : "false";
    case "bigint":
      return `{"$bigint":"${value.toString(10)}"}`;
    case "number":
      if (!Number.isFinite(value)) {
        throw new TypeError("Cannot canonicalise a non-finite number");
      }
      return JSON.stringify(value);
  }

  if (Array.isArray(value)) {
    return `[${value.map((v) => canonicalise(v as Canonicalisable)).join(",")}]`;
  }

  const obj = value as { readonly [k: string]: Canonicalisable };
  // Reserved: {"$bigint": ...} is how a bigint is written. An object carrying that key would
  // canonicalise to the same bytes as a bigint, and one signature would cover two meanings.
  if (Object.hasOwn(obj, BIGINT_TAG)) {
    throw new TypeError(`The key "${BIGINT_TAG}" is reserved for bigint encoding`);
  }
  const keys = Object.keys(obj)
    .filter((k) => obj[k] !== undefined)
    .sort();

  const body = keys.map((k) => `${JSON.stringify(k)}:${canonicalise(obj[k])}`).join(",");
  return `{${body}}`;
}

export function canonicalBytes(value: Canonicalisable): Uint8Array {
  return new TextEncoder().encode(canonicalise(value));
}
