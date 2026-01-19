import "dotenv/config";

import express, { Request, Response, NextFunction } from "express";
import cors from "cors";
import cookieParser from "cookie-parser";
import { z, ZodError } from "zod";
import bcrypt from "bcryptjs";

import passport from "./auth/google";
import { prisma } from "./prisma";
import { ensureQuestionsExist } from "./bootstrap/questions";

import {
  sha256,
  randomToken64,
  signEmailVerificationToken,
  verifyEmailVerificationToken,
} from "./utils/crypto";

import { requireParticipation } from "./middleware/requireParticipation";

const app = express();

// CORS
app.use(
  cors({
    origin: process.env.FRONTEND_URL,
    credentials: true,
    methods: ["GET", "POST", "OPTIONS"],
    allowedHeaders: ["Content-Type", "x-participation-token"],
  })
);
app.options(/.*/, cors());

app.use(express.json());
app.use(cookieParser());
app.use(passport.initialize());

const SESSION_TTL_HOURS = 6;
const PASSWORD_COST = 12;

const asyncHandler =
  (fn: (req: Request, res: Response, next: NextFunction) => Promise<any>) =>
  (req: Request, res: Response, next: NextFunction) =>
    Promise.resolve(fn(req, res, next)).catch(next);

/**
 * Your Prisma schema has @@unique([studentId, type]) on AuthToken,
 * so create() on every login can fail. Use upsert() by (studentId,type).
 */
async function issueParticipationSession(studentId: string) {
  const sessionRaw = randomToken64();
  const sessionHash = sha256(sessionRaw);
  const sessionExp = new Date(Date.now() + SESSION_TTL_HOURS * 60 * 60 * 1000);

  await prisma.authToken.upsert({
    where: {
      studentId_type: {
        studentId,
        type: "PARTICIPATION_SESSION",
      },
    },
    update: {
      tokenHash: sessionHash,
      expiresAt: sessionExp,
      consumedAt: null,
    },
    create: {
      studentId,
      type: "PARTICIPATION_SESSION",
      tokenHash: sessionHash,
      expiresAt: sessionExp,
    },
  });

  return { sessionRaw, sessionExp };
}

// ============= GOOGLE OAUTH (EMAIL VERIFICATION ONLY) =============

app.get(
  "/auth/google",
  passport.authenticate("google", {
    scope: ["profile", "email"],
    session: false,
    prompt: "select_account",
  })
);

app.get(
  "/auth/google/callback",
  (req, res, next) => {
    passport.authenticate("google", { session: false }, (err, user, info) => {
      if (err) return next(err);

      if (!user) {
        const msg = encodeURIComponent(info?.message || "Google sign-in failed");
        return res.redirect(`${process.env.FRONTEND_URL}/?oauthError=${msg}`);
      }

      (req as any).user = user;
      return next();
    })(req, res, next);
  },
  asyncHandler(async (req: any, res) => {
    const u = req.user as { email: string; displayName: string; googleSub: string };
    const email = u.email.toLowerCase();

    const exists = await prisma.student.findUnique({
      where: { collegeEmail: email },
      select: { id: true },
    });

    const emailToken = signEmailVerificationToken(email);
    const targetPath = exists ? "/login" : "/register";

    const redirectUrl =
      `${process.env.FRONTEND_URL}${targetPath}` +
      `?verifiedEmail=${encodeURIComponent(email)}` +
      `&emailToken=${encodeURIComponent(emailToken)}`;

    return res.redirect(redirectUrl);
  })
);

// ============= REGISTER (requires Google emailToken + password) =============

app.post(
  "/api/register",
  asyncHandler(async (req, res) => {
    const Body = z.object({
      email: z.string().email(),
      emailToken: z.string().min(1, "Google verification required"),

      name: z.string().min(2),
      rollNumber: z.string().min(1),
      registrationNumber: z.string().min(1),
      department: z.string().min(1),
      year: z.number().int().min(1).max(6),
      phoneNumber: z.string().min(10).max(10),
      preferredCells: z
        .array(z.enum(["MANAGEMENT", "DESIGN", "DEVELOPMENT", "FINANCE"]))
        .min(1),

      password: z
        .string()
        .min(8, "Password must be at least 8 characters")
        .regex(/[A-Z]/, "Must contain uppercase letter")
        .regex(/[a-z]/, "Must contain lowercase letter")
        .regex(/\d/, "Must contain number"),
    });

    const data = Body.parse(req.body);

    const verified = verifyEmailVerificationToken(data.emailToken);
    const email = data.email.toLowerCase();

    if (verified.email !== email) {
      return res.status(400).json({ error: "Email does not match Google verified email" });
    }

    const exists = await prisma.student.findUnique({
      where: { collegeEmail: email },
      select: { id: true },
    });

    if (exists) {
      return res.status(409).json({ error: "Already registered. Please login." });
    }

    const passwordHash = await bcrypt.hash(data.password, PASSWORD_COST);

    const student = await prisma.student.create({
      data: {
        name: data.name,
        rollNumber: data.rollNumber,
        registrationNumber: data.registrationNumber,
        department: data.department,
        year: data.year,
        collegeEmail: email, // stores personal email now
        preferredCells: data.preferredCells,
        phoneNumber: data.phoneNumber,
        passwordHash,
      },
      select: { id: true },
    });

    const { sessionRaw, sessionExp } = await issueParticipationSession(student.id);

    return res.json({
      ok: true,
      participationToken: sessionRaw,
      expiresAt: sessionExp.toISOString(),
    });
  })
);

// ============= LOGIN (requires Google emailToken + password) =============

app.post(
  "/api/login",
  asyncHandler(async (req, res) => {
    const Body = z.object({
      email: z.string().email(),
      emailToken: z.string().min(1, "Google verification required"),
      password: z.string().min(1),
    });

    const data = Body.parse(req.body);

    const verified = verifyEmailVerificationToken(data.emailToken);
    const email = data.email.toLowerCase();

    if (verified.email !== email) {
      return res.status(400).json({ error: "Email does not match Google verified email" });
    }

    const student = await prisma.student.findUnique({
      where: { collegeEmail: email },
      select: { id: true, passwordHash: true, hasSubmitted: true },
    });

    if (!student) {
      return res.status(404).json({ error: "Not registered" });
    }

    const ok = await bcrypt.compare(data.password, student.passwordHash);
    if (!ok) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const { sessionRaw, sessionExp } = await issueParticipationSession(student.id);

    return res.json({
      ok: true,
      participationToken: sessionRaw,
      expiresAt: sessionExp.toISOString(),
      hasSubmitted: student.hasSubmitted,
    });
  })
);

// ============= SESSION & STATUS =============

app.get(
  "/api/me",
  requireParticipation,
  asyncHandler(async (req: any, res) => {
    const studentId = req.studentId as string;

    const student = await prisma.student.findUnique({
      where: { id: studentId },
      select: {
        collegeEmail: true,
        name: true,
        hasSubmitted: true,
      },
    });

    if (!student) return res.status(401).json({ error: "Invalid session" });
    return res.json({ ok: true, student });
  })
);

app.post(
  "/api/logout",
  requireParticipation,
  asyncHandler(async (req: any, res) => {
    const token = req.header("x-participation-token");
    if (!token) return res.status(400).json({ error: "Missing token" });

    const tokenHash = sha256(token);

    await prisma.authToken.updateMany({
      where: { tokenHash, type: "PARTICIPATION_SESSION" },
      data: { consumedAt: new Date() },
    });

    return res.json({ ok: true });
  })
);

// ============= QUESTIONS & ANSWERS =============

app.get(
  "/api/questions",
  requireParticipation,
  asyncHandler(async (_req, res) => {
    const questions = await prisma.question.findMany({
      where: { isActive: true },
      orderBy: { order: "asc" },
      select: { id: true, order: true, text: true },
    });

    return res.json({ questions });
  })
);

app.post(
  "/api/answers",
  requireParticipation,
  asyncHandler(async (req: any, res) => {
    const studentId = req.studentId as string;

    const Body = z.object({
      answers: z
        .array(
          z.object({
            questionId: z.string().min(1),
            answer: z.string().min(1).max(5000),
          })
        )
        .length(6),
    });

    const { answers } = Body.parse(req.body);

    const student = await prisma.student.findUnique({
      where: { id: studentId },
      select: { hasSubmitted: true },
    });

    if (!student) return res.status(401).json({ error: "Invalid session" });
    if (student.hasSubmitted) return res.status(409).json({ error: "You have already answered" });

    await prisma.$transaction([
      ...answers.map((a) =>
        prisma.answer.upsert({
          where: { studentId_questionId: { studentId, questionId: a.questionId } },
          update: { answer: a.answer },
          create: { studentId, questionId: a.questionId, answer: a.answer },
        })
      ),
      prisma.student.update({
        where: { id: studentId },
        data: { hasSubmitted: true },
      }),
    ]);

    return res.json({ ok: true });
  })
);

// ============= HEALTH & 404 =============

app.get("/health", (_req, res) => res.status(200).send("ok"));

app.use((_req, res) => {
  res.status(404).json({ error: "Not found" });
});

// ============= ERROR HANDLER =============

app.use((err: any, _req: Request, res: Response, _next: NextFunction) => {
  console.error("UNHANDLED_ERROR:", err);

  if (err instanceof ZodError) {
    const msg = err.issues?.[0]?.message || "Invalid request";
    return res.status(400).json({ error: msg });
  }

  const status = typeof err?.status === "number" ? err.status : 500;
  const message = err?.message || "Internal server error";
  return res.status(status).json({ error: message });
});

// ============= START SERVER =============

async function start() {
  await ensureQuestionsExist();

  app.listen(process.env.PORT || 4000, () => {
    console.log(`Server running on port ${process.env.PORT || 4000}`);
  });
}

start().catch((err) => {
  console.error("Failed to start server:", err);
  process.exit(1);
});
