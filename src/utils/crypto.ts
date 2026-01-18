import crypto from "crypto";
import { sha256 as sha256lib } from "js-sha256";

export function sha256(input: string) {
  return sha256lib(input);
}

// Cryptographically secure random token [web:723]
export function randomToken64() {
  return crypto.randomBytes(32).toString("hex");
}
