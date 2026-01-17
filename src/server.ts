import "dotenv/config";

import express from "express";
import cors from "cors";
import cookieParser from "cookie-parser";
import jwt from "jsonwebtoken";
import { z } from "zod";

import passport from "./auth/google";
import { prisma } from "./prisma";
import { ensureQuestionsExist } from "./bootstrap/questions";
import { generateOtp6, sha256 } from "./utils/crypto";
import { sendOtpEmail } from "./utils/mailer";
import { requireParticipation } from "./middleware/requireParticipation";

const app = express();

app.use(cors({ origin: process.env.FRONTEND_URL, credentials: true }));
app.use(express.json());
app.use(cookieParser());
app.use(passport.initialize());

const OTP_TTL_MIN = 10;
const OTP_COOLDOWN_SEC = 60; // resend cooldown per email
const OTP_MAX_PER_DAY = 10;  // optional daily cap (can set 0/Infinity to disable)
const SESSION_TTL_HOURS = 6;

const EMAIL_VERIFIED_TTL_MIN = 15;
const OTP_VERIFY_MAX_ATTEMPTS_PER_10MIN = 20; // optional brute-force protection

const OTP_VERIFY_WINDOW_MIN = 10;
const OTP_VERIFY_MAX_ATTEMPTS = 20;

// --- helper: issue short-lived "registration JWT" after Google callback
function signRegisterJwt(payload: { googleSub: string }) {
  return jwt.sign(payload, process.env.REGISTER_JWT_SECRET!, { expiresIn: "15m" });
}

function verifyRegisterJwt(token: string) {
  return jwt.verify(token, process.env.REGISTER_JWT_SECRET!) as {
    googleSub: string;
    iat: number;
    exp: number;
  };
}

// --- helper: random session token (no Node crypto)
function randomToken32() {
  // Not cryptographically strong, but OK for a short-lived session token if you also store hash+expiry.
  // If you want cryptographically strong tokens without node:crypto, use WebCrypto in Node 20+.
  const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  let out = "";
  for (let i = 0; i < 64; i++) out += alphabet[Math.floor(Math.random() * alphabet.length)];
  return out;
}

async function enforceOtpLimits(email: string) {
  const now = new Date();
  const cooldownSince = new Date(now.getTime() - OTP_COOLDOWN_SEC * 1000);
  const daySince = new Date(now.getTime() - 24 * 60 * 60 * 1000);

  // Cooldown: if OTP was created recently, block
  const recent = await prisma.authToken.findFirst({
    where: {
      email,
      type: "EMAIL_OTP",
      createdAt: { gt: cooldownSince },
    },
    orderBy: { createdAt: "desc" },
    select: { createdAt: true },
  });

  if (recent) {
    const waitMs =
      OTP_COOLDOWN_SEC * 1000 - (now.getTime() - recent.createdAt.getTime());
    const waitSec = Math.max(1, Math.ceil(waitMs / 1000));
    return {
      ok: false as const,
      error: `Please wait ${waitSec}s before requesting another OTP.`,
    };
  }

  // Daily cap (optional)
  if (OTP_MAX_PER_DAY > 0) {
    const count = await prisma.authToken.count({
      where: {
        email,
        type: "EMAIL_OTP",
        createdAt: { gt: daySince },
      },
    });

    if (count >= OTP_MAX_PER_DAY) {
      return {
        ok: false as const,
        error: "OTP request limit reached. Try again tomorrow.",
      };
    }
  }

  return { ok: true as const };
}

async function issueParticipationSession(studentId: string) {
  const sessionRaw = randomToken32();
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

async function enforceOtpVerifyAttempts(email: string) {
  const now = new Date();
  const since = new Date(now.getTime() - OTP_VERIFY_WINDOW_MIN * 60 * 1000);

  const attempts = await prisma.authToken.count({
    where: { email, type: "EMAIL_OTP", createdAt: { gt: since } },
  });

  if (attempts > OTP_MAX_PER_DAY + OTP_VERIFY_MAX_ATTEMPTS) {
    // rough guard; better: make a separate table for verify attempts
    return { ok: false as const, error: "Too many attempts. Try later." };
  }
  return { ok: true as const };
}

// --- 1) Google OAuth start
app.get(
  "/auth/google",
  passport.authenticate("google", { scope: ["profile", "email"], session: false })
);

// --- 2) Google OAuth callback -> sets cookie with register token and redirects to frontend
app.get(
  "/auth/google/callback",
  passport.authenticate("google", { session: false, failureRedirect: "/" }),
  (req, res) => {
    const user = req.user as any; // { googleSub, displayName, email }
    const regToken = signRegisterJwt({ googleSub: user.googleSub });

    // NOTE: For Vercel(frontend) + Render(backend), cross-site cookies usually need SameSite=None; Secure.
    const isProd = process.env.NODE_ENV === "production";

    res.cookie("reg_token", regToken, {
      httpOnly: true,
      secure: isProd,
      sameSite: isProd ? "none" : "lax",
      maxAge: 15 * 60 * 1000,
    });

    res.redirect(`${process.env.FRONTEND_URL}/register`);
  }
);

// --- A) Email-only OTP: request code before full registration
app.post("/api/email/request-otp", async (req, res) => {
  const Body = z.object({
    email: z.string().email(),
    mode: z.enum(["REGISTER", "PARTICIPATE"]),
  });

  const { email, mode } = Body.parse(req.body);
  const normalizedEmail = email.toLowerCase();

  if (!normalizedEmail.endsWith("@nitdgp.ac.in")) {
    return res.status(400).json({ error: "Use your college email (@nitdgp.ac.in)" });
  }

  // If mode is PARTICIPATE, email must already be registered
  if (mode === "PARTICIPATE") {
    const student = await prisma.student.findUnique({
      where: { collegeEmail: normalizedEmail },
      select: { id: true },
    });
    if (!student) return res.status(404).json({ error: "Not registered" });
  }

  const limit = await enforceOtpLimits(normalizedEmail);
  if (!limit.ok) return res.status(429).json({ error: limit.error });

  const otp = generateOtp6();
  const otpHash = sha256(otp);
  const expiresAt = new Date(Date.now() + OTP_TTL_MIN * 60 * 1000);

  await prisma.authToken.updateMany({
    where: { email: normalizedEmail, type: "EMAIL_OTP", consumedAt: null },
    data: { consumedAt: new Date() },
  });

  await prisma.authToken.create({
    data: {
      email: normalizedEmail,
      type: "EMAIL_OTP",
      tokenHash: otpHash,
      expiresAt,
    },
  });

  await sendOtpEmail(normalizedEmail, otp);
  return res.json({ ok: true });
});

// --- B) Email-only OTP verify (marks email as verified in token table)

app.post("/api/email/verify-otp", async (req, res) => {
  const Body = z.object({
    email: z.string().email(),
    otp: z.string().length(6),
    mode: z.enum(["REGISTER", "PARTICIPATE"]),
  });

  const { email, otp, mode } = Body.parse(req.body);
  const normalizedEmail = email.toLowerCase();

  const now = new Date();
  const tokenHash = sha256(otp);

  const dbOtp = await prisma.authToken.findFirst({
    where: {
      email: normalizedEmail,
      type: "EMAIL_OTP",
      tokenHash,
      expiresAt: { gt: now },
      consumedAt: null,
    },
    orderBy: { createdAt: "desc" },
  });

  if (!dbOtp) return res.status(400).json({ error: "Invalid/expired OTP" });

  await prisma.authToken.update({
    where: { id: dbOtp.id },
    data: { consumedAt: now },
  });

  // REGISTER: create EMAIL_VERIFIED proof, don't create session yet
  if (mode === "REGISTER") {
    const verifiedExp = new Date(Date.now() + EMAIL_VERIFIED_TTL_MIN * 60 * 1000);

    await prisma.$transaction([
      prisma.authToken.updateMany({
        where: { email: normalizedEmail, type: "EMAIL_VERIFIED", consumedAt: null },
        data: { consumedAt: now },
      }),
      prisma.authToken.create({
        data: {
          email: normalizedEmail,
          type: "EMAIL_VERIFIED",
          tokenHash: sha256(randomToken32()), // random internal hash
          expiresAt: verifiedExp,
        },
      }),
    ]);

    return res.json({ ok: true });
  }

  // PARTICIPATE: must exist in DB, then issue session token
  const student = await prisma.student.findUnique({
    where: { collegeEmail: normalizedEmail },
    select: { id: true, isEmailVerified: true },
  });

  if (!student) return res.status(404).json({ error: "Not registered" });

  // optionally mark verified true (safe)
  if (!student.isEmailVerified) {
    await prisma.student.update({
      where: { id: student.id },
      data: { isEmailVerified: true },
    });
  }

  const { sessionRaw, sessionExp } = await issueParticipationSession(student.id);

  return res.json({
    ok: true,
    participationToken: sessionRaw,
    expiresAt: sessionExp.toISOString(),
  });
});

// --- 3) Create/update registration (requires Google login cookie)
app.post("/api/register", async (req, res) => {
  const Body = z.object({
    name: z.string().min(2),
    rollNumber: z.string().min(1),
    registrationNumber: z.string().min(1),
    department: z.string().min(1),
    year: z.number().int().min(1).max(6),
    collegeEmail: z.string().email(),
    preferredCells: z.array(z.enum(["MANAGEMENT", "DESIGN", "DEVELOPMENT", "FINANCE"])).min(1),
  });

  const data = Body.parse(req.body);
  const normalizedEmail = data.collegeEmail.toLowerCase();
  const now = new Date();

  if (!normalizedEmail.endsWith("@nitdgp.ac.in")) {
    return res.status(400).json({ error: "Use your college email (@nitdgp.ac.in)" });
  }

  // Require EMAIL_VERIFIED proof created by /api/email/verify-otp (REGISTER mode)
  const proof = await prisma.authToken.findFirst({
    where: {
      email: normalizedEmail,
      type: "EMAIL_VERIFIED",
      expiresAt: { gt: now },
      consumedAt: null,
    },
    orderBy: { createdAt: "desc" },
    select: { id: true },
  });

  if (!proof) {
    return res.status(403).json({ error: "Email not verified. Verify OTP first." });
  }

  // consume proof (one-time)
  await prisma.authToken.update({
    where: { id: proof.id },
    data: { consumedAt: now },
  });

  const student = await prisma.student.upsert({
    where: { collegeEmail: normalizedEmail },
    update: {
      name: data.name,
      rollNumber: data.rollNumber,
      registrationNumber: data.registrationNumber,
      department: data.department,
      year: data.year,
      preferredCells: data.preferredCells,
      isEmailVerified: true,
    },
    create: {
      // IMPORTANT: do NOT set googleSub: "" (empty string breaks unique in Postgres)
      name: data.name,
      rollNumber: data.rollNumber,
      registrationNumber: data.registrationNumber,
      department: data.department,
      year: data.year,
      collegeEmail: normalizedEmail,
      preferredCells: data.preferredCells,
      isEmailVerified: true,
    },
  });

  // Direct to participate page => issue participation token now
  const { sessionRaw, sessionExp } = await issueParticipationSession(student.id);

  return res.json({
    ok: true,
    participationToken: sessionRaw,
    expiresAt: sessionExp.toISOString(),
  });
});

// --- 6) Get questions (only after participation session verified)
app.get("/api/questions", requireParticipation, async (_req, res) => {
  const questions = await prisma.question.findMany({
    where: { isActive: true },
    orderBy: { order: "asc" },
    select: { id: true, order: true, text: true },
  });

  return res.json({ questions });
});

// --- 7) Submit answers (only after participation session verified)
app.post("/api/answers", requireParticipation, async (req, res) => {
  const studentId = req.studentId!;

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

  const student = await prisma.student.findUnique({ where: { id: studentId } });
  if (!student) return res.status(401).json({ error: "Invalid session" });
  if (!student.isEmailVerified) return res.status(403).json({ error: "Email not verified" });

  await prisma.$transaction(
    answers.map((a) =>
      prisma.answer.upsert({
        where: { studentId_questionId: { studentId, questionId: a.questionId } },
        update: { answer: a.answer },
        create: { studentId, questionId: a.questionId, answer: a.answer },
      })
    )
  );

  return res.json({ ok: true });
});

app.get("/health", (_req, res) => res.status(200).send("ok"));

async function start() {
  await ensureQuestionsExist();
  app.listen(process.env.PORT || 4000, () => console.log("Server running"));
}

start().catch((err) => {
  console.error(err);
  process.exit(1);
});
