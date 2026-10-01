/**
 * Is a 32-byte string a point on the Ed25519 curve?
 *
 * Needed for exactly one reason: a program-derived address is only valid if it is NOT on the
 * curve, which guarantees no private key exists for it. Getting this wrong derives the wrong
 * associated token account, and a transfer to the wrong token account is a transfer to an
 * account nobody controls.
 *
 * Semantics match curve25519-dalek's CompressedEdwardsY::decompress, which is what the Solana
 * runtime uses: the sign bit is ignored for validity, y is reduced mod p, and the point is on
 * the curve exactly when (y^2 - 1) / (d*y^2 + 1) is a square mod p.
 *
 * Not constant time, and it does not need to be: every input here is a public key or a hash of
 * public data.
 */

const P = (1n << 255n) - 19n;
const D = mod(-121665n * inverse(121666n));

function mod(a: bigint): bigint {
  const r = a % P;
  return r >= 0n ? r : r + P;
}

function pow(base: bigint, exponent: bigint): bigint {
  let result = 1n;
  let b = mod(base);
  let e = exponent;
  while (e > 0n) {
    if (e & 1n) result = (result * b) % P;
    b = (b * b) % P;
    e >>= 1n;
  }
  return result;
}

function inverse(a: bigint): bigint {
  return pow(a, P - 2n);
}

export function isOnCurve(bytes: Uint8Array): boolean {
  if (bytes.length !== 32) return false;

  let y = 0n;
  for (let i = 31; i >= 0; i--) {
    const byte = i === 31 ? (bytes[i] ?? 0) & 0x7f : (bytes[i] ?? 0);
    y = (y << 8n) | BigInt(byte);
  }
  y = mod(y);

  const y2 = (y * y) % P;
  const u = mod(y2 - 1n);
  const v = mod(D * y2 + 1n);
  const x2 = (u * inverse(v)) % P;

  // Euler's criterion. Zero is a square (x = 0), which dalek accepts.
  return x2 === 0n || pow(x2, (P - 1n) / 2n) === 1n;
}
