-- DropIndex
DROP INDEX "AuthToken_studentId_type_idx";

-- AlterTable
ALTER TABLE "AuthToken" ADD COLUMN     "email" TEXT,
ALTER COLUMN "studentId" DROP NOT NULL;

-- CreateIndex
CREATE INDEX "AuthToken_type_idx" ON "AuthToken"("type");

-- CreateIndex
CREATE INDEX "AuthToken_email_type_idx" ON "AuthToken"("email", "type");
