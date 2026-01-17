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
exports.sendOtpEmail = sendOtpEmail;
const resend_1 = require("resend");
const resend = new resend_1.Resend(process.env.RESEND_API_KEY);
function sendOtpEmail(to, otp) {
    return __awaiter(this, void 0, void 0, function* () {
        const { error } = yield resend.emails.send({
            from: process.env.EMAIL_FROM, // e.g. "MNTC Auditions <onboarding@resend.dev>"
            to: [to],
            subject: "Your audition verification code",
            text: `Your verification code is: ${otp}\nThis code expires in 10 minutes.`,
        });
        if (error)
            throw error;
    });
}
