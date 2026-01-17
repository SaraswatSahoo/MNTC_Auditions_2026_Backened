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
exports.ensureQuestionsExist = ensureQuestionsExist;
const prisma_1 = require("../prisma");
const QUESTIONS = [
    { order: 1, text: "Why do you want to join MNTC?" },
    { order: 2, text: "Why should MNTC choose you?" },
    { order: 3, text: "Do you have any special quality or skill?" },
    { order: 4, text: "Do you have any prior experience to showcase?" },
    { order: 5, text: "What is your biggest plus point?" },
    { order: 6, text: "Any additional notes or links (GitHub/Portfolio)?" },
];
function ensureQuestionsExist() {
    return __awaiter(this, void 0, void 0, function* () {
        for (const q of QUESTIONS) {
            yield prisma_1.prisma.question.upsert({
                where: { order: q.order },
                update: { text: q.text, isActive: true },
                create: { order: q.order, text: q.text, isActive: true },
            });
        }
    });
}
