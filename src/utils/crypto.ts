import crypto from "crypto";
import { sha256 as sha256lib } from "js-sha256";
import jwt from "jsonwebtoken";

export function sha256(input: string) {
  return sha256lib(input);
}

export function randomToken64() {
  return crypto.randomBytes(32).toString("hex");
}

// Google-verified email proof token (short-lived)
const EMAIL_TOKEN_TTL_SECONDS = 15 * 60; // 15 minutes

export function signEmailVerificationToken(email: string) {
  const secret = process.env.JWT_SECRET;
  if (!secret) throw new Error("Missing JWT_SECRET");

  return jwt.sign(
    { typ: "EMAIL_VERIFY", email: email.toLowerCase() },
    secret,
    { expiresIn: EMAIL_TOKEN_TTL_SECONDS }
  );
}

export function verifyEmailVerificationToken(token: string): { email: string } {
  const secret = process.env.JWT_SECRET;
  if (!secret) throw new Error("Missing JWT_SECRET");

  const decoded = jwt.verify(token, secret) as any;

  if (!decoded || decoded.typ !== "EMAIL_VERIFY" || !decoded.email) {
    const err: any = new Error("Invalid/expired email verification token");
    err.status = 401;
    throw err;
  }

  return { email: String(decoded.email).toLowerCase() };
}
