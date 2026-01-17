-- CreateEnum
CREATE TYPE "PreferredCell" AS ENUM ('MANAGEMENT', 'DESIGN', 'DEVELOPMENT', 'FINANCE');

-- CreateEnum
CREATE TYPE "TokenType" AS ENUM ('EMAIL_OTP', 'PARTICIPATION_SESSION');

-- CreateTable
CREATE TABLE "Student" (
    "id" TEXT NOT NULL,
    "googleSub" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "rollNumber" TEXT NOT NULL,
    "registrationNumber" TEXT NOT NULL,
    "department" TEXT NOT NULL,
    "year" INTEGER NOT NULL,
    "collegeEmail" TEXT NOT NULL,
    "preferredCells" "PreferredCell"[],
    "isEmailVerified" BOOLEAN NOT NULL DEFAULT false,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "Student_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Question" (
    "id" TEXT NOT NULL,
    "text" TEXT NOT NULL,
    "order" INTEGER NOT NULL,
    "isActive" BOOLEAN NOT NULL DEFAULT true,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "Question_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Answer" (
    "id" TEXT NOT NULL,
    "studentId" TEXT NOT NULL,
    "questionId" TEXT NOT NULL,
    "answer" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "Answer_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "AuthToken" (
    "id" TEXT NOT NULL,
    "studentId" TEXT NOT NULL,
    "type" "TokenType" NOT NULL,
    "tokenHash" TEXT NOT NULL,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "consumedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "AuthToken_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "Student_googleSub_key" ON "Student"("googleSub");

-- CreateIndex
CREATE UNIQUE INDEX "Student_collegeEmail_key" ON "Student"("collegeEmail");

-- CreateIndex
CREATE UNIQUE INDEX "Question_order_key" ON "Question"("order");

-- CreateIndex
CREATE UNIQUE INDEX "Answer_studentId_questionId_key" ON "Answer"("studentId", "questionId");

-- CreateIndex
CREATE INDEX "AuthToken_studentId_type_idx" ON "AuthToken"("studentId", "type");

-- AddForeignKey
ALTER TABLE "Answer" ADD CONSTRAINT "Answer_studentId_fkey" FOREIGN KEY ("studentId") REFERENCES "Student"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Answer" ADD CONSTRAINT "Answer_questionId_fkey" FOREIGN KEY ("questionId") REFERENCES "Question"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "AuthToken" ADD CONSTRAINT "AuthToken_studentId_fkey" FOREIGN KEY ("studentId") REFERENCES "Student"("id") ON DELETE CASCADE ON UPDATE CASCADE;
