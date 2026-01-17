"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
require("dotenv/config");
const express_1 = __importDefault(require("express"));
const cors_1 = __importDefault(require("cors"));
const cookie_parser_1 = __importDefault(require("cookie-parser"));
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
const zod_1 = require("zod");
const google_1 = __importDefault(require("./auth/google"));
const prisma_1 = require("./prisma");
const questions_1 = require("./bootstrap/questions");
const crypto_1 = require("./utils/crypto");
const mailer_1 = require("./utils/mailer");
const requireParticipation_1 = require("./middleware/requireParticipation");
const app = (0, express_1.default)();
app.use((0, cors_1.default)({ origin: process.env.FRONTEND_URL, credentials: true }));
app.use(express_1.default.json());
app.use((0, cookie_parser_1.default)());
app.use(google_1.default.initialize());
const OTP_TTL_MIN = 10;
const SESSION_TTL_HOURS = 6;
// --- helper: issue short-lived "registration JWT" after Google callback
function signRegisterJwt(payload) {
    return jsonwebtoken_1.default.sign(payload, process.env.REGISTER_JWT_SECRET, { expiresIn: "15m" });
}
function verifyRegisterJwt(token) {
    return jsonwebtoken_1.default.verify(token, process.env.REGISTER_JWT_SECRET);
}
// --- helper: random session token (no Node crypto)
function randomToken32() {
    // Not cryptographically strong, but OK for a short-lived session token if you also store hash+expiry.
    // If you want cryptographically strong tokens without node:crypto, use WebCrypto in Node 20+.
    const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let out = "";
    for (let i = 0; i < 64; i++)
        out += alphabet[Math.floor(Math.random() * alphabet.length)];
    return out;
}
// --- 1) Google OAuth start
app.get("/auth/google", google_1.default.authenticate("google", { scope: ["profile", "email"], session: false }));
// --- 2) Google OAuth callback -> sets cookie with register token and redirects to frontend
app.get("/auth/google/callback", google_1.default.authenticate("google", { session: false, failureRedirect: "/" }), (req, res) => {
    const user = req.user; // { googleSub, displayName, email }
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
});
// --- 3) Create/update registration (requires Google login cookie)
app.post("/api/register", (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    const regToken = req.cookies.reg_token;
    if (!regToken)
        return res.status(401).json({ error: "Login with Google first" });
    const { googleSub } = verifyRegisterJwt(regToken);
    const Body = zod_1.z.object({
        name: zod_1.z.string().min(2),
        rollNumber: zod_1.z.string().min(1),
        registrationNumber: zod_1.z.string().min(1),
        department: zod_1.z.string().min(1),
        year: zod_1.z.number().int().min(1).max(6),
        collegeEmail: zod_1.z.string().email(),
        preferredCells: zod_1.z
            .array(zod_1.z.enum(["MANAGEMENT", "DESIGN", "DEVELOPMENT", "FINANCE"]))
            .min(1),
    });
    const data = Body.parse(req.body);
    const student = yield prisma_1.prisma.student.upsert({
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
    const otp = (0, crypto_1.generateOtp6)();
    const otpHash = (0, crypto_1.sha256)(otp);
    const expiresAt = new Date(Date.now() + OTP_TTL_MIN * 60 * 1000);
    // invalidate previous OTPs
    yield prisma_1.prisma.authToken.updateMany({
        where: { studentId: student.id, type: "EMAIL_OTP", consumedAt: null },
        data: { consumedAt: new Date() },
    });
    yield prisma_1.prisma.authToken.create({
        data: {
            studentId: student.id,
            type: "EMAIL_OTP",
            tokenHash: otpHash,
            expiresAt,
        },
    });
    yield (0, mailer_1.sendOtpEmail)(student.collegeEmail, otp);
    return res.json({ ok: true, message: "OTP sent to email" });
}));
// --- 4) Verify OTP (used both after registration and for “participate later”)
app.post("/api/verify-email-otp", (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    const Body = zod_1.z.object({
        email: zod_1.z.string().email(),
        otp: zod_1.z.string().length(6),
    });
    const { email, otp } = Body.parse(req.body);
    const student = yield prisma_1.prisma.student.findUnique({
        where: { collegeEmail: email.toLowerCase() },
    });
    if (!student)
        return res.status(404).json({ error: "Email not registered" });
    const tokenHash = (0, crypto_1.sha256)(otp);
    const now = new Date();
    const dbOtp = yield prisma_1.prisma.authToken.findFirst({
        where: {
            studentId: student.id,
            type: "EMAIL_OTP",
            tokenHash,
            expiresAt: { gt: now },
            consumedAt: null,
        },
    });
    if (!dbOtp)
        return res.status(400).json({ error: "Invalid/expired OTP" });
    yield prisma_1.prisma.$transaction([
        prisma_1.prisma.authToken.update({ where: { id: dbOtp.id }, data: { consumedAt: now } }),
        prisma_1.prisma.student.update({ where: { id: student.id }, data: { isEmailVerified: true } }),
    ]);
    const sessionRaw = randomToken32();
    const sessionHash = (0, crypto_1.sha256)(sessionRaw);
    const sessionExp = new Date(Date.now() + SESSION_TTL_HOURS * 60 * 60 * 1000);
    yield prisma_1.prisma.authToken.create({
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
}));
// --- 5) Participate later: request OTP (enter email -> if registered send code)
app.post("/api/participate/request-otp", (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    const Body = zod_1.z.object({ email: zod_1.z.string().email() });
    const { email } = Body.parse(req.body);
    const student = yield prisma_1.prisma.student.findUnique({
        where: { collegeEmail: email.toLowerCase() },
    });
    if (!student)
        return res.status(404).json({ error: "Not registered" });
    const otp = (0, crypto_1.generateOtp6)();
    const otpHash = (0, crypto_1.sha256)(otp);
    const expiresAt = new Date(Date.now() + OTP_TTL_MIN * 60 * 1000);
    yield prisma_1.prisma.authToken.updateMany({
        where: { studentId: student.id, type: "EMAIL_OTP", consumedAt: null },
        data: { consumedAt: new Date() },
    });
    yield prisma_1.prisma.authToken.create({
        data: {
            studentId: student.id,
            type: "EMAIL_OTP",
            tokenHash: otpHash,
            expiresAt,
        },
    });
    yield (0, mailer_1.sendOtpEmail)(student.collegeEmail, otp);
    return res.json({ ok: true, message: "OTP sent" });
}));
// --- 6) Get questions (only after participation session verified)
app.get("/api/questions", requireParticipation_1.requireParticipation, (_req, res) => __awaiter(void 0, void 0, void 0, function* () {
    const questions = yield prisma_1.prisma.question.findMany({
        where: { isActive: true },
        orderBy: { order: "asc" },
        select: { id: true, order: true, text: true },
    });
    return res.json({ questions });
}));
// --- 7) Submit answers (only after participation session verified)
app.post("/api/answers", requireParticipation_1.requireParticipation, (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    const studentId = req.studentId;
    const Body = zod_1.z.object({
        answers: zod_1.z
            .array(zod_1.z.object({
            questionId: zod_1.z.string().min(1),
            answer: zod_1.z.string().min(1).max(5000),
        }))
            .length(6),
    });
    const { answers } = Body.parse(req.body);
    const student = yield prisma_1.prisma.student.findUnique({ where: { id: studentId } });
    if (!student)
        return res.status(401).json({ error: "Invalid session" });
    if (!student.isEmailVerified)
        return res.status(403).json({ error: "Email not verified" });
    yield prisma_1.prisma.$transaction(answers.map((a) => prisma_1.prisma.answer.upsert({
        where: { studentId_questionId: { studentId, questionId: a.questionId } },
        update: { answer: a.answer },
        create: { studentId, questionId: a.questionId, answer: a.answer },
    })));
    return res.json({ ok: true });
}));
function start() {
    return __awaiter(this, void 0, void 0, function* () {
        yield (0, questions_1.ensureQuestionsExist)();
        app.listen(process.env.PORT || 4000, () => console.log("Server running"));
    });
}
start().catch((err) => {
    console.error(err);
    process.exit(1);
});
