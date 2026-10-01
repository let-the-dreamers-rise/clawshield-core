/**
 * Base58, as Solana uses it (the Bitcoin alphabet).
 *
 * Written here rather than imported for the same reason the signing code uses node:crypto: an
 * address codec sits directly on the path between a policy decision and a signed transfer. A
 * compromised or subtly wrong dependency at this point would sign a transfer to an address
 * other than the one the policy evaluated.
 *
 * Decoding is strict. A character outside the alphabet is an error, never skipped, because a
 * lenient decoder turns a typo into a different, valid-looking address.
 */

const ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const INDEX: ReadonlyMap<string, number> = new Map([...ALPHABET].map((c, i) => [c, i]));

export class Base58Error extends Error {
  constructor(message: string) {
    super(message);
    this.name = "Base58Error";
  }
}

export function encodeBase58(bytes: Uint8Array): string {
  let zeros = 0;
  while (zeros < bytes.length && bytes[zeros] === 0) zeros++;

  let value = 0n;
  for (const b of bytes) value = (value << 8n) | BigInt(b);

  let digits = "";
  while (value > 0n) {
    digits = ALPHABET[Number(value % 58n)] + digits;
    value /= 58n;
  }
  return "1".repeat(zeros) + digits;
}

export function decodeBase58(text: string): Uint8Array {
  let zeros = 0;
  while (zeros < text.length && text[zeros] === "1") zeros++;

  let value = 0n;
  for (const c of text) {
    const digit = INDEX.get(c);
    if (digit === undefined) {
      throw new Base58Error(`Character ${JSON.stringify(c)} is not in the base58 alphabet`);
    }
    value = value * 58n + BigInt(digit);
  }

  const body: number[] = [];
  while (value > 0n) {
    body.unshift(Number(value & 0xffn));
    value >>= 8n;
  }
  return Uint8Array.from([...new Array<number>(zeros).fill(0), ...body]);
}

/** Decode a public key, which must be exactly 32 bytes. Anything else is refused. */
export function decodePubkey(text: string): Uint8Array {
  const bytes = decodeBase58(text);
  if (bytes.length !== 32) {
    throw new Base58Error(`A public key is 32 bytes; ${JSON.stringify(text)} decodes to ${bytes.length}`);
  }
  return bytes;
}
