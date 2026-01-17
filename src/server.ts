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
const SESSION_TTL_HOURS = 6;

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

// --- 3) Create/update registration (requires Google login cookie)
app.post("/api/register", async (req, res) => {
  const regToken = req.cookies.reg_token;
  if (!regToken) return res.status(401).json({ error: "Login with Google first" });

  const { googleSub } = verifyRegisterJwt(regToken);

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
  });

  const data = Body.parse(req.body);

  const student = await prisma.student.upsert({
    where: { googleSub },
    update: {
      name: data.name,
      rollNumber: data.rollNumber,
      registrationNumber: data.registrationNumber,
      department: data.department,
      year: data.year,
      collegeEmail: data.collegeEmail.toLowerCase(),
      preferredCells: data.preferredCells,
    },
    create: {
      googleSub,
      name: data.name,
      rollNumber: data.rollNumber,
      registrationNumber: data.registrationNumber,
      department: data.department,
      year: data.year,
      collegeEmail: data.collegeEmail.toLowerCase(),
      preferredCells: data.preferredCells,
      isEmailVerified: false,
    },
  });

  const otp = generateOtp6();
  const otpHash = sha256(otp);
  const expiresAt = new Date(Date.now() + OTP_TTL_MIN * 60 * 1000);

  // invalidate previous OTPs
  await prisma.authToken.updateMany({
    where: { studentId: student.id, type: "EMAIL_OTP", consumedAt: null },
    data: { consumedAt: new Date() },
  });

  await prisma.authToken.create({
    data: {
      studentId: student.id,
      type: "EMAIL_OTP",
      tokenHash: otpHash,
      expiresAt,
    },
  });

  await sendOtpEmail(student.collegeEmail, otp);

  return res.json({ ok: true, message: "OTP sent to email" });
});

// --- 4) Verify OTP (used both after registration and for “participate later”)
app.post("/api/verify-email-otp", async (req, res) => {
  const Body = z.object({
    email: z.string().email(),
    otp: z.string().length(6),
  });

  const { email, otp } = Body.parse(req.body);

  const student = await prisma.student.findUnique({
    where: { collegeEmail: email.toLowerCase() },
  });
  if (!student) return res.status(404).json({ error: "Email not registered" });

  const tokenHash = sha256(otp);
  const now = new Date();

  const dbOtp = await prisma.authToken.findFirst({
    where: {
      studentId: student.id,
      type: "EMAIL_OTP",
      tokenHash,
      expiresAt: { gt: now },
      consumedAt: null,
    },
  });

  if (!dbOtp) return res.status(400).json({ error: "Invalid/expired OTP" });

  await prisma.$transaction([
    prisma.authToken.update({ where: { id: dbOtp.id }, data: { consumedAt: now } }),
    prisma.student.update({ where: { id: student.id }, data: { isEmailVerified: true } }),
  ]);

  const sessionRaw = randomToken32();
  const sessionHash = sha256(sessionRaw);
  const sessionExp = new Date(Date.now() + SESSION_TTL_HOURS * 60 * 60 * 1000);

  await prisma.authToken.create({
    data: {
      studentId: student.id,
      type: "PARTICIPATION_SESSION",
      tokenHash: sessionHash,
      expiresAt: sessionExp,
    },
  });

  return res.json({
    ok: true,
    participationToken: sessionRaw,
    expiresAt: sessionExp.toISOString(),
  });
});

// --- 5) Participate later: request OTP (enter email -> if registered send code)
app.post("/api/participate/request-otp", async (req, res) => {
  const Body = z.object({ email: z.string().email() });
  const { email } = Body.parse(req.body);

  const student = await prisma.student.findUnique({
    where: { collegeEmail: email.toLowerCase() },
  });
  if (!student) return res.status(404).json({ error: "Not registered" });

  const otp = generateOtp6();
  const otpHash = sha256(otp);
  const expiresAt = new Date(Date.now() + OTP_TTL_MIN * 60 * 1000);

  await prisma.authToken.updateMany({
    where: { studentId: student.id, type: "EMAIL_OTP", consumedAt: null },
    data: { consumedAt: new Date() },
  });

  await prisma.authToken.create({
    data: {
      studentId: student.id,
      type: "EMAIL_OTP",
      tokenHash: otpHash,
      expiresAt,
    },
  });

  await sendOtpEmail(student.collegeEmail, otp);

  return res.json({ ok: true, message: "OTP sent" });
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

async function start() {
  await ensureQuestionsExist();
  app.listen(process.env.PORT || 4000, () => console.log("Server running"));
}

start().catch((err) => {
  console.error(err);
  process.exit(1);
});
