import { prisma } from "../prisma";

const QUESTIONS = [
    { order: 1, text: "Why do you want to join MNTC?" },
    { order: 2, text: "What unique skills or talents can you bring to MNTC?" },
    { order: 3, text: "What does leadership mean to you?" },
    { order: 4, text: "Share an idea or event which  you think MNTC should conduct." },
    { order: 5, text: "How would you handle a disagreement within the team?" },
    { order: 6, text: "What are your club preferences?" },
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
