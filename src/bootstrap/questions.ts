import { prisma } from "../prisma";

const QUESTIONS = [
    { order: 1, text: "Why do you want to join MNTC?" },
    { order: 2, text: "Why should MNTC choose you?" },
    { order: 3, text: "Do you have any special quality or skill?" },
    { order: 4, text: "What is your biggest plus point?" },
    { order: 5, text: "What is one drawback you have, and how are you working on it?" },
    { order: 6, text: "Any additional notes or links (GitHub/Portfolio)?" },
] as const;

export async function ensureQuestionsExist() {
  for (const q of QUESTIONS) {
    await prisma.question.upsert({
      where: { order: q.order },
      update: { text: q.text, isActive: true },
      create: { order: q.order, text: q.text, isActive: true },
    });
  }
}
