/**
 * node:crypto for the browser verifier, limited to what verification uses.
 *
 * The core verifies with node:crypto on purpose (no third-party code on the signing path). A
 * browser has no synchronous SHA-256 or Ed25519, so the browser bundle substitutes audited
 * implementations from @noble/hashes and @noble/curves behind the same function names. The
 * verifier code itself is unchanged: the bundle runs the exact checks the CLI runs.
 *
 * Nothing here can sign or create a private key. Those names exist only so the modules that
 * import them load; calling one throws.
 *
 * Ed25519 is verified with zip215 off, i.e. RFC 8032 strict encoding, which matches what Node
 * (OpenSSL) accepts for every signature this system produces.
 */

import { ed25519 } from "@noble/curves/ed25519.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { Buffer } from "buffer";

/** RFC 8410 SubjectPublicKeyInfo prefix for a 32-byte Ed25519 public key. */
const SPKI_PREFIX = Uint8Array.from([0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00]);

// The buffer package has no base64url encoding, so JWK keys are converted by hand.
const toBase64url = (bytes: Uint8Array): string =>
  Buffer.from(bytes).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

function fromBase64url(text: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]*$/.test(text)) throw new TypeError("Not base64url");
  return new Uint8Array(Buffer.from(text.replace(/-/g, "+").replace(/_/g, "/"), "base64"));
}

export class KeyObject {
  readonly type = "public";
  readonly asymmetricKeyType = "ed25519";
  readonly raw: Uint8Array;

  constructor(raw: Uint8Array) {
    if (raw.length !== 32) throw new TypeError("An Ed25519 public key is 32 bytes");
    this.raw = raw;
  }

  export(options: { readonly format: string; readonly type?: string }): unknown {
    if (options.format === "jwk") return { kty: "OKP", crv: "Ed25519", x: toBase64url(this.raw) };
    if (options.format === "der" && options.type === "spki") return Buffer.concat([SPKI_PREFIX, this.raw]);
    throw new TypeError(`Unsupported key export ${options.type ?? ""}/${options.format}`);
  }
}

interface KeyInput {
  readonly key: Uint8Array | { readonly kty?: string; readonly crv?: string; readonly x?: string };
  readonly format: string;
  readonly type?: string;
}

export function createPublicKey(input: KeyInput | KeyObject): KeyObject {
  if (input instanceof KeyObject) return input;
  if (input.format === "der" && input.type === "spki" && input.key instanceof Uint8Array) {
    const der = input.key;
    if (der.length !== SPKI_PREFIX.length + 32 || !SPKI_PREFIX.every((b, i) => der[i] === b)) {
      throw new TypeError("Not an Ed25519 SubjectPublicKeyInfo");
    }
    return new KeyObject(der.slice(SPKI_PREFIX.length));
  }
  if (input.format === "jwk" && !(input.key instanceof Uint8Array)) {
    const jwk = input.key;
    if (jwk.kty !== "OKP" || jwk.crv !== "Ed25519" || typeof jwk.x !== "string") throw new TypeError("Not an Ed25519 JWK");
    return new KeyObject(fromBase64url(jwk.x));
  }
  throw new TypeError("Unsupported public key input");
}

export function verify(algorithm: null | undefined, data: Uint8Array, key: KeyObject, signature: Uint8Array): boolean {
  if (algorithm !== null && algorithm !== undefined) throw new TypeError("Ed25519 takes no digest algorithm");
  if (signature.length !== 64) return false;
  try {
    return ed25519.verify(new Uint8Array(signature), new Uint8Array(data), key.raw, { zip215: false });
  } catch {
    return false;
  }
}

class Sha256 {
  private readonly state = sha256.create();

  update(data: string | Uint8Array, _encoding?: string): this {
    this.state.update(typeof data === "string" ? new TextEncoder().encode(data) : new Uint8Array(data));
    return this;
  }

  digest(): Buffer;
  digest(encoding: "hex"): string;
  digest(encoding?: "hex"): Buffer | string {
    const out = Buffer.from(this.state.digest());
    return encoding === "hex" ? out.toString("hex") : out;
  }
}

export function createHash(algorithm: string): Sha256 {
  if (algorithm !== "sha256") throw new TypeError(`Only sha256 is available in the browser verifier, not ${algorithm}`);
  return new Sha256();
}

export function randomBytes(size: number): Buffer {
  const out = new Uint8Array(size);
  globalThis.crypto.getRandomValues(out);
  return Buffer.from(out);
}

export function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) throw new RangeError("Inputs must have the same length");
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= (a[i] as number) ^ (b[i] as number);
  return diff === 0;
}

const unavailable = (name: string) => (): never => {
  throw new Error(`${name} is not available in the browser verifier: it verifies, it never signs`);
};

export const createPrivateKey = unavailable("createPrivateKey");
export const generateKeyPairSync = unavailable("generateKeyPairSync");
export const sign = unavailable("sign");
