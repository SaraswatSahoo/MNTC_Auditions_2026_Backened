import { Request, Response, NextFunction } from "express";
import { prisma } from "../prisma";
import { sha256 } from "../utils/crypto";

declare global {
  namespace Express {
    interface Request {
      studentId?: string;
    }
  }
}

export async function requireParticipation(req: Request, res: Response, next: NextFunction) {
  const token = req.header("x-participation-token");
  if (!token) return res.status(401).json({ error: "Missing participation token" });

  const tokenHash = sha256(token);
  const now = new Date();

  const dbToken = await prisma.authToken.findFirst({
    where: {
      type: "PARTICIPATION_SESSION",
      tokenHash,
      expiresAt: { gt: now },
      consumedAt: null,
    },
  });

  if (!dbToken) return res.status(401).json({ error: "Invalid/expired token" });

  req.studentId = dbToken.studentId;
  return next();
}
