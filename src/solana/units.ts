/**
 * Amounts as people write them ("0.015") and as the chain counts them (15000000 lamports).
 *
 * The conversion is string arithmetic on bigints. Through a float, 0.015 SOL can come out as
 * 14999999 lamports, and a payment cannot be approximately right.
 */

const DECIMAL = /^(\d+)(?:\.(\d+))?$/;
const U64_MAX = (1n << 64n) - 1n;

export class AmountError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "AmountError";
  }
}

/** "0.015" at 9 decimals is 15000000n: exactly, or an error that says what is wrong. */
export function toMinorUnits(amount: string, decimals: number): bigint {
  if (!Number.isInteger(decimals) || decimals < 0 || decimals > 18) throw new AmountError("decimals: expected an integer from 0 to 18");
  const match = DECIMAL.exec(amount);
  if (!match) throw new AmountError(`amount: expected a decimal number such as "0.015", got ${JSON.stringify(amount)}`);
  const whole = match[1] ?? "";
  const fraction = match[2] ?? "";
  if (fraction.length > decimals) {
    throw new AmountError(`amount: ${amount} has more than ${decimals} decimal places, finer than the token's smallest unit`);
  }
  const units = BigInt(whole + fraction.padEnd(decimals, "0"));
  if (units > U64_MAX) throw new AmountError(`amount: ${amount} is more than a token amount can hold`);
  return units;
}
