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
const zod_1 = require("zod");
const bcryptjs_1 = __importDefault(require("bcryptjs"));
const google_1 = __importDefault(require("./auth/google"));
const prisma_1 = require("./prisma");
const questions_1 = require("./bootstrap/questions");
const crypto_1 = require("./utils/crypto");
const requireParticipation_1 = require("./middleware/requireParticipation");
const app = (0, express_1.default)();
/**
 * CORS Configuration
 * - origin: must be explicit (no "*" when credentials: true)
 * - credentials: true allows cookies + custom headers
 * - allowedHeaders: includes x-participation-token for auth
 */
app.use((0, cors_1.default)({
    origin: process.env.FRONTEND_URL,
    credentials: true,
    methods: ["GET", "POST", "OPTIONS"],
    allowedHeaders: ["Content-Type", "x-participation-token"],
}));
// Express v5: safe wildcard preflight
app.options(/.*/, (0, cors_1.default)());
app.use(express_1.default.json());
app.use((0, cookie_parser_1.default)());
app.use(google_1.default.initialize());
// Constants
const SESSION_TTL_HOURS = 6;
const PASSWORD_COST = 12;
/**
 * asyncHandler wrapper ensures all thrown errors reach error middleware [web:723]
 */
const asyncHandler = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
// Helper: enforce college email
function requireNitdgpEmail(email) {
    const normalized = email.toLowerCase();
    if (!normalized.endsWith("@nitdgp.ac.in")) {
        const err = new Error("Use your college email (@nitdgp.ac.in)");
        err.status = 400;
        throw err;
    }
    return normalized;
}
// Helper: issue participation session token [web:723]
function issueParticipationSession(studentId) {
    return __awaiter(this, void 0, void 0, function* () {
        const sessionRaw = (0, crypto_1.randomToken64)(); // crypto.randomBytes, not Math.random
        const sessionHash = (0, crypto_1.sha256)(sessionRaw);
        const sessionExp = new Date(Date.now() + SESSION_TTL_HOURS * 60 * 60 * 1000);
        yield prisma_1.prisma.authToken.create({
            data: {
                studentId,
                type: "PARTICIPATION_SESSION",
                tokenHash: sessionHash,
                expiresAt: sessionExp,
            },
        });
        return { sessionRaw, sessionExp };
    });
}
// ============= GOOGLE OAUTH ROUTES =============
/**
 * Step 1: Initiate Google OAuth
 * hd=nitdgp.ac.in is a UX hint (not security); enforcement happens in strategy callback [web:742]
 */
app.get("/auth/google", google_1.default.authenticate("google", {
    scope: ["profile", "email"],
    session: false,
    accessType: "offline",
    prompt: "select_account",
}));
/**
 * Step 2: Google callback handler
 * After user approves, Google redirects here with authorization code.
 * Passport exchanges it for profile info.
 * Flow:
 *   - Create/update Student (upsert by collegeEmail)
 *   - Issue participation session
 *   - Redirect to frontend with token
 */
app.get("/auth/google/callback", google_1.default.authenticate("google", {
    session: false,
    failureRedirect: "/",
}), asyncHandler((req, res) => __awaiter(void 0, void 0, void 0, function* () {
    const user = req.user;
    const email = user.email.toLowerCase();
    // Upsert: if first login, create; if returning, update fields
    const student = yield prisma_1.prisma.student.upsert({
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
    const { sessionRaw, sessionExp } = yield issueParticipationSession(student.id);
    // Redirect to frontend with token
    // Frontend stores token in localStorage, then calls /api/questions
    const redirectUrl = `${process.env.FRONTEND_URL}/participate?token=${sessionRaw}&hasSubmitted=${student.hasSubmitted}`;
    return res.redirect(redirectUrl);
})));
// ============= PASSWORD-BASED REGISTRATION =============
/**
 * POST /api/register
 * New users create account with email + password
 * Password must be 8+ chars with complexity [web:723]
 */
app.post("/api/register", asyncHandler((req, res) => __awaiter(void 0, void 0, void 0, function* () {
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
        password: zod_1.z
            .string()
            .min(8, "Password must be at least 8 characters")
            .regex(/[A-Z]/, "Must contain uppercase letter")
            .regex(/[a-z]/, "Must contain lowercase letter")
            .regex(/\d/, "Must contain number"),
    });
    const data = Body.parse(req.body);
    const email = requireNitdgpEmail(data.collegeEmail);
    const exists = yield prisma_1.prisma.student.findUnique({
        where: { collegeEmail: email },
        select: { id: true },
    });
    if (exists) {
        return res.status(409).json({ error: "Already registered. Please login." });
    }
    const passwordHash = yield bcryptjs_1.default.hash(data.password, PASSWORD_COST);
    const student = yield prisma_1.prisma.student.create({
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
    const { sessionRaw, sessionExp } = yield issueParticipationSession(student.id);
    return res.json({
        ok: true,
        participationToken: sessionRaw,
        expiresAt: sessionExp.toISOString(),
    });
})));
// ============= PASSWORD-BASED LOGIN =============
/**
 * POST /api/login
 * Existing users log in with email + password
 */
app.post("/api/login", asyncHandler((req, res) => __awaiter(void 0, void 0, void 0, function* () {
    const Body = zod_1.z.object({
        email: zod_1.z.string().email(),
        password: zod_1.z.string().min(1),
    });
    const { email, password } = Body.parse(req.body);
    const normalizedEmail = requireNitdgpEmail(email);
    const student = yield prisma_1.prisma.student.findUnique({
        where: { collegeEmail: normalizedEmail },
        select: { id: true, passwordHash: true, hasSubmitted: true },
    });
    if (!student) {
        return res.status(404).json({ error: "Not registered" });
    }
    const ok = yield bcryptjs_1.default.compare(password, student.passwordHash);
    if (!ok) {
        return res.status(401).json({ error: "Invalid credentials" });
    }
    const { sessionRaw, sessionExp } = yield issueParticipationSession(student.id);
    return res.json({
        ok: true,
        participationToken: sessionRaw,
        expiresAt: sessionExp.toISOString(),
        hasSubmitted: student.hasSubmitted,
    });
})));
// ============= SESSION & STATUS =============
/**
 * GET /api/me
 * Get current student status (for frontend to check hasSubmitted, etc)
 */
app.get("/api/me", requireParticipation_1.requireParticipation, asyncHandler((req, res) => __awaiter(void 0, void 0, void 0, function* () {
    const studentId = req.studentId;
    const student = yield prisma_1.prisma.student.findUnique({
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
})));
/**
 * POST /api/logout
 * Invalidate current session token
 */
app.post("/api/logout", requireParticipation_1.requireParticipation, asyncHandler((req, res) => __awaiter(void 0, void 0, void 0, function* () {
    const token = req.header("x-participation-token");
    if (!token) {
        return res.status(400).json({ error: "Missing token" });
    }
    const tokenHash = (0, crypto_1.sha256)(token);
    yield prisma_1.prisma.authToken.updateMany({
        where: { tokenHash },
        data: { consumedAt: new Date() },
    });
    return res.json({ ok: true });
})));
// ============= QUESTIONS & ANSWERS =============
/**
 * GET /api/questions
 * Fetch all active questions (requires valid session)
 */
app.get("/api/questions", requireParticipation_1.requireParticipation, asyncHandler((_req, res) => __awaiter(void 0, void 0, void 0, function* () {
    const questions = yield prisma_1.prisma.question.findMany({
        where: { isActive: true },
        orderBy: { order: "asc" },
        select: { id: true, order: true, text: true },
    });
    return res.json({ questions });
})));
/**
 * POST /api/answers
 * Submit all 6 answers (one-time, then hasSubmitted = true)
 */
app.post("/api/answers", requireParticipation_1.requireParticipation, asyncHandler((req, res) => __awaiter(void 0, void 0, void 0, function* () {
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
    const student = yield prisma_1.prisma.student.findUnique({
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
    yield prisma_1.prisma.$transaction([
        ...answers.map((a) => prisma_1.prisma.answer.upsert({
            where: { studentId_questionId: { studentId, questionId: a.questionId } },
            update: { answer: a.answer },
            create: { studentId, questionId: a.questionId, answer: a.answer },
        })),
        prisma_1.prisma.student.update({
            where: { id: studentId },
            data: { hasSubmitted: true },
        }),
    ]);
    return res.json({ ok: true });
})));
// ============= HEALTH & 404 =============
app.get("/health", (_req, res) => res.status(200).send("ok"));
app.use((_req, res) => {
    res.status(404).json({ error: "Not found" });
});
// ============= ERROR HANDLER (MUST BE LAST) =============
app.use((err, _req, res, _next) => {
    var _a, _b;
    console.error("UNHANDLED_ERROR:", err);
    if (err instanceof zod_1.ZodError) {
        const msg = ((_b = (_a = err.issues) === null || _a === void 0 ? void 0 : _a[0]) === null || _b === void 0 ? void 0 : _b.message) || "Invalid request";
        return res.status(400).json({ error: msg });
    }
    const status = typeof (err === null || err === void 0 ? void 0 : err.status) === "number" ? err.status : 500;
    const message = (err === null || err === void 0 ? void 0 : err.message) || "Internal server error";
    return res.status(status).json({ error: message });
});
// ============= START SERVER =============
function start() {
    return __awaiter(this, void 0, void 0, function* () {
        yield (0, questions_1.ensureQuestionsExist)();
        app.listen(process.env.PORT || 4000, () => {
            console.log(`Server running on port ${process.env.PORT || 4000}`);
        });
    });
}
start().catch((err) => {
    console.error("Failed to start server:", err);
    process.exit(1);
});
