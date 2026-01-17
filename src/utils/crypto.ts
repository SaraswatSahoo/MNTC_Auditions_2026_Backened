import { sha256 as sha256lib } from "js-sha256";

export function generateOtp6() {
  return String(Math.floor(100000 + Math.random() * 900000));
}

export function sha256(input: string) {
  return sha256lib(input);
}
