/**
 * File helpers for the CLI. Secret files are created exclusively (never overwritten) with
 * owner-only permissions; an existing key file is far more likely to be valuable than stale.
 */

import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import { fromJson, toJson } from "../io/json.ts";
import type { Canonicalisable } from "../receipt/canonical.ts";

export class UsageError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "UsageError";
  }
}

export function readJsonFile(path: string): unknown {
  let text: string;
  try {
    text = readFileSync(path, "utf8");
  } catch (err) {
    throw new UsageError(`Cannot read ${path}: ${(err as NodeJS.ErrnoException).code ?? String(err)}`);
  }
  try {
    return fromJson(text);
  } catch (err) {
    throw new UsageError(`${path} is not valid JSON: ${(err as Error).message}`);
  }
}

export function writeJsonFile(path: string, value: unknown): void {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, `${toJson(value as Canonicalisable, 2)}\n`);
}

export function writeSecretFile(path: string, text: string): void {
  mkdirSync(dirname(path), { recursive: true });
  try {
    writeFileSync(path, text, { flag: "wx", mode: 0o600 });
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "EEXIST") {
      throw new UsageError(`${path} already exists; refusing to overwrite a secret file`);
    }
    throw err;
  }
}
