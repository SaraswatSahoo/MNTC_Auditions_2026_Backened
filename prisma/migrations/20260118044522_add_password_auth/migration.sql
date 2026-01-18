/*
  Warnings:

  - You are about to drop the column `email` on the `AuthToken` table. All the data in the column will be lost.
  - You are about to drop the column `googleSub` on the `Student` table. All the data in the column will be lost.
  - You are about to drop the column `isEmailVerified` on the `Student` table. All the data in the column will be lost.
  - A unique constraint covering the columns `[studentId,type]` on the table `AuthToken` will be added. If there are existing duplicate values, this will fail.
  - Made the column `studentId` on table `AuthToken` required. This step will fail if there are existing NULL values in that column.

*/
-- DropIndex
DROP INDEX "AuthToken_email_type_idx";

-- DropIndex
DROP INDEX "Student_googleSub_key";

-- AlterTable
ALTER TABLE "AuthToken" DROP COLUMN "email",
ALTER COLUMN "studentId" SET NOT NULL;

-- AlterTable
ALTER TABLE "Student" DROP COLUMN "googleSub",
DROP COLUMN "isEmailVerified";

-- CreateIndex
CREATE UNIQUE INDEX "AuthToken_studentId_type_key" ON "AuthToken"("studentId", "type");
