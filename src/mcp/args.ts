/**
 * Tool arguments, read the way a model sends them. Every error starts with the argument's name
 * and says what was expected, so the model can correct its call; nothing invalid reaches the
 * gateway.
 */

import { decodePubkey } from "../solana/base58.ts";
import { AmountError, toMinorUnits } from "../solana/units.ts";
import { ToolError, type JsonObject } from "./protocol.ts";

const SOL_DECIMALS = 9;
const REQUEST_ID = /^[\x21-\x7e][\x20-\x7e]{0,254}$/;

/** Models send null for an optional argument they mean to leave out. */
const absent = (args: JsonObject, key: string): boolean => args[key] === undefined || args[key] === null;

export function onlyKnown(args: JsonObject, known: readonly string[]): void {
  const unknown = Object.keys(args).filter((k) => !known.includes(k));
  if (unknown.length === 0) return;
  const names = unknown.map((k) => k.slice(0, 64)).join(", ");
  throw new ToolError(`unknown argument: ${names}. This tool takes ${known.length === 0 ? "no arguments" : known.join(", ")}`);
}

export function text(args: JsonObject, key: string, max: number): string {
  const v = args[key];
  if (typeof v !== "string" || v.trim() === "" || v.length > max) {
    throw new ToolError(`${key}: expected a non-empty string of at most ${max} characters`);
  }
  return v;
}

export function address(args: JsonObject, key: string): string {
  const v = text(args, key, 44);
  try {
    decodePubkey(v);
  } catch {
    throw new ToolError(`${key}: not a Solana address. Expected a base58 public key of 32 bytes`);
  }
  return v;
}

export const optionalAddress = (args: JsonObject, key: string): string | undefined => (absent(args, key) ? undefined : address(args, key));

export function requestId(args: JsonObject): string {
  const v = args["request_id"];
  if (typeof v !== "string" || !REQUEST_ID.test(v)) {
    throw new ToolError("request_id: expected 1 to 255 printable ASCII characters naming this payment, such as an invoice number");
  }
  return v;
}

/** SOL always has 9 decimals. A token's decimals belong to its mint, so the caller must say. */
export function decimals(args: JsonObject, token: string | undefined): number {
  const v = args["decimals"];
  if (token === undefined) {
    if (absent(args, "decimals") || v === SOL_DECIMALS) return SOL_DECIMALS;
    throw new ToolError("decimals: SOL has 9 decimal places; leave decimals out for SOL");
  }
  if (typeof v !== "number" || !Number.isInteger(v) || v < 0 || v > 18) {
    throw new ToolError("decimals: required for an SPL token, an integer from 0 to 18: its mint's decimal places, for example 6 for USDC");
  }
  return v;
}

/** Whole tokens as a decimal string, to minor units. A float could round a payment. */
export function amount(args: JsonObject, places: number): bigint {
  const v = args["amount"];
  if (typeof v !== "string") throw new ToolError('amount: expected a decimal string such as "0.015", not a number, so no rounding can change it');
  let units: bigint;
  try {
    units = toMinorUnits(v, places);
  } catch (err) {
    if (err instanceof AmountError) throw new ToolError(err.message);
    throw err;
  }
  if (units === 0n) throw new ToolError("amount: must be greater than zero");
  return units;
}
