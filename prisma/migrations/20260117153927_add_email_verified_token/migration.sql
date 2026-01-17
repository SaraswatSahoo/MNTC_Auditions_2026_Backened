-- AlterEnum
ALTER TYPE "TokenType" ADD VALUE 'EMAIL_VERIFIED';

-- AlterTable
ALTER TABLE "Student" ALTER COLUMN "googleSub" DROP NOT NULL;
