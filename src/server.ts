import "dotenv/config";

import express, { Request, Response, NextFunction } from "express";
import cors from "cors";
import cookieParser from "cookie-parser";
import { z, ZodError } from "zod";
import bcrypt from "bcryptjs";

import passport from "./auth/google";
import { prisma } from "./prisma";
import { ensureQuestionsExist } from "./bootstrap/questions";
import { sha256, randomToken64 } from "./utils/crypto";
import { requireParticipation } from "./middleware/requireParticipation";

const app = express();

/**
 * CORS Configuration
 * - origin: must be explicit (no "*" when credentials: true)
 * - credentials: true allows cookies + custom headers
 * - allowedHeaders: includes x-participation-token for auth
 */
app.use(
  cors({
    origin: process.env.FRONTEND_URL,
    credentials: true,
    methods: ["GET", "POST", "OPTIONS"],
    allowedHeaders: ["Content-Type", "x-participation-token"],
  })
);

// Express v5: safe wildcard preflight
app.options(/.*/, cors());

app.use(express.json());
app.use(cookieParser());
app.use(passport.initialize());

// Constants
const SESSION_TTL_HOURS = 6;
const PASSWORD_COST = 12;

/**
 * asyncHandler wrapper ensures all thrown errors reach error middleware [web:723]
 */
const asyncHandler =
  (fn: (req: Request, res: Response, next: NextFunction) => Promise<any>) =>
  (req: Request, res: Response, next: NextFunction) =>
    Promise.resolve(fn(req, res, next)).catch(next);

// Helper: enforce college email
function requireNitdgpEmail(email: string) {
  const normalized = email.toLowerCase();
  if (!normalized.endsWith("@nitdgp.ac.in")) {
    const err: any = new Error("Use your college email (@nitdgp.ac.in)");
    err.status = 400;
    throw err;
  }
  return normalized;
}

// Helper: issue participation session token [web:723]
async function issueParticipationSession(studentId: string) {
  const sessionRaw = randomToken64(); // crypto.randomBytes, not Math.random
  const sessionHash = sha256(sessionRaw);
  const sessionExp = new Date(Date.now() + SESSION_TTL_HOURS * 60 * 60 * 1000);

  await prisma.authToken.create({
    data: {
      studentId,
      type: "PARTICIPATION_SESSION",
      tokenHash: sessionHash,
      expiresAt: sessionExp,
    },
  });

  return { sessionRaw, sessionExp };
}

// ============= GOOGLE OAUTH ROUTES =============

/**
 * Step 1: Initiate Google OAuth
 * hd=nitdgp.ac.in is a UX hint (not security); enforcement happens in strategy callback [web:742]
 */
app.get(
  "/auth/google",
  passport.authenticate("google", {
    scope: ["profile", "email"],
    session: false,
    accessType: "offline",
    prompt: "select_account",
  })
);

/**
 * Step 2: Google callback handler
 * After user approves, Google redirects here with authorization code.
 * Passport exchanges it for profile info.
 * Flow:
 *   - Create/update Student (upsert by collegeEmail)
 *   - Issue participation session
 *   - Redirect to frontend with token
 */
app.get(
  "/auth/google/callback",
  passport.authenticate("google", {
    session: false,
    failureRedirect: "/",
  }),
  asyncHandler(async (req: any, res) => {
    const user = req.user as {
      googleSub: string;
      displayName: string;
      email: string;
    };

    const email = user.email.toLowerCase();

    // Upsert: if first login, create; if returning, update fields
    const student = await prisma.student.upsert({
      where: { collegeEmail: email },
      update: {
        name: user.displayName,
      },
      create: {
        name: user.displayName,
        collegeEmail: email,
        rollNumber: "TBD",
        registrationNumber: "TBD",
        department: "TBD",
        year: 1,
        preferredCells: [],
        passwordHash: "", // Google login, no local password (or set a placeholder)
      },
      select: { id: true, hasSubmitted: true },
    });

    // Issue session
    const { sessionRaw, sessionExp } = await issueParticipationSession(student.id);

    // Redirect to frontend with token
    // Frontend stores token in localStorage, then calls /api/questions
    const redirectUrl = `${process.env.FRONTEND_URL}/participate?token=${sessionRaw}&hasSubmitted=${student.hasSubmitted}`;
    return res.redirect(redirectUrl);
  })
);

// ============= PASSWORD-BASED REGISTRATION =============

/**
 * POST /api/register
 * New users create account with email + password
 * Password must be 8+ chars with complexity [web:723]
 */
app.post(
  "/api/register",
  asyncHandler(async (req, res) => {
    const Body = z.object({
      name: z.string().min(2),
      rollNumber: z.string().min(1),
      registrationNumber: z.string().min(1),
      department: z.string().min(1),
      year: z.number().int().min(1).max(6),
      collegeEmail: z.string().email(),
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
    const email = requireNitdgpEmail(data.collegeEmail);

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
        collegeEmail: email,
        preferredCells: data.preferredCells,
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

// ============= PASSWORD-BASED LOGIN =============

/**
 * POST /api/login
 * Existing users log in with email + password
 */
app.post(
  "/api/login",
  asyncHandler(async (req, res) => {
    const Body = z.object({
      email: z.string().email(),
      password: z.string().min(1),
    });

    const { email, password } = Body.parse(req.body);
    const normalizedEmail = requireNitdgpEmail(email);

    const student = await prisma.student.findUnique({
      where: { collegeEmail: normalizedEmail },
      select: { id: true, passwordHash: true, hasSubmitted: true },
    });

    if (!student) {
      return res.status(404).json({ error: "Not registered" });
    }

    const ok = await bcrypt.compare(password, student.passwordHash);
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

/**
 * GET /api/me
 * Get current student status (for frontend to check hasSubmitted, etc)
 */
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

    if (!student) {
      return res.status(401).json({ error: "Invalid session" });
    }

    return res.json({ ok: true, student });
  })
);

/**
 * POST /api/logout
 * Invalidate current session token
 */
app.post(
  "/api/logout",
  requireParticipation,
  asyncHandler(async (req: any, res) => {
    const token = req.header("x-participation-token");
    if (!token) {
      return res.status(400).json({ error: "Missing token" });
    }

    const tokenHash = sha256(token);
    await prisma.authToken.updateMany({
      where: { tokenHash },
      data: { consumedAt: new Date() },
    });

    return res.json({ ok: true });
  })
);

// ============= QUESTIONS & ANSWERS =============

/**
 * GET /api/questions
 * Fetch all active questions (requires valid session)
 */
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

/**
 * POST /api/answers
 * Submit all 6 answers (one-time, then hasSubmitted = true)
 */
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

    if (!student) {
      return res.status(401).json({ error: "Invalid session" });
    }

    // BLOCK: already answered
    if (student.hasSubmitted) {
      return res.status(409).json({ error: "You have already answered" });
    }

    // Upsert answers + mark submitted (atomic transaction)
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

// ============= ERROR HANDLER (MUST BE LAST) =============

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
