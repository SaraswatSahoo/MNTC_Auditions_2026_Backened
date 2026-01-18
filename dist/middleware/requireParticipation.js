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
Object.defineProperty(exports, "__esModule", { value: true });
exports.requireParticipation = requireParticipation;
const prisma_1 = require("../prisma");
const crypto_1 = require("../utils/crypto");
function requireParticipation(req, res, next) {
    return __awaiter(this, void 0, void 0, function* () {
        const token = req.header("x-participation-token");
        if (!token) {
            return res.status(401).json({ error: "Missing participation token" });
        }
        const tokenHash = (0, crypto_1.sha256)(token);
        const now = new Date();
        const dbToken = yield prisma_1.prisma.authToken.findFirst({
            where: {
                type: "PARTICIPATION_SESSION",
                tokenHash,
                expiresAt: { gt: now },
                consumedAt: null,
            },
        });
        if (!dbToken) {
            return res.status(401).json({ error: "Invalid/expired token" });
        }
        if (!dbToken.studentId) {
            return res.status(401).json({ error: "Invalid session token" });
        }
        req.studentId = dbToken.studentId;
        return next();
    });
}
