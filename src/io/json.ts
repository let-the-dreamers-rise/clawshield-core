/**
 * JSON with exact bigints.
 *
 * Uses the same tag as canonical form - {"$bigint":"123"} - so a receipt written by toJson
 * and a receipt canonicalised for signing agree on what every amount is. Parsing is strict: a
 * tag must be the only key and must hold a decimal integer, and anything else that looks like a
 * tag is an error rather than an ordinary object.
 */

import { BIGINT_TAG, type Canonicalisable } from "../receipt/canonical.ts";

const DECIMAL = /^-?(0|[1-9]\d*)$/;

export function toJson(value: Canonicalisable, indent?: number): string {
  return JSON.stringify(
    value,
    function replacer(_key, v: unknown) {
      if (typeof v === "bigint") return { [BIGINT_TAG]: v.toString(10) };
      if (typeof v === "object" && v !== null && !Array.isArray(v) && Object.hasOwn(v, BIGINT_TAG)) {
        throw new TypeError(`The key "${BIGINT_TAG}" is reserved for bigint encoding`);
      }
      return v;
    },
    indent,
  );
}

export function fromJson(text: string): unknown {
  return JSON.parse(text, (_key, v: unknown) => {
    if (typeof v !== "object" || v === null || Array.isArray(v) || !Object.hasOwn(v, BIGINT_TAG)) return v;
    const record = v as Record<string, unknown>;
    const digits = record[BIGINT_TAG];
    if (Object.keys(record).length !== 1 || typeof digits !== "string" || !DECIMAL.test(digits)) {
      throw new SyntaxError(`Malformed bigint tag: ${JSON.stringify(record)}`);
    }
    return BigInt(digits);
  });
}
