/*
  Warnings:

  - The values [EMAIL_OTP,EMAIL_VERIFIED] on the enum `TokenType` will be removed. If these variants are still used in the database, this will fail.
  - Added the required column `passwordHash` to the `Student` table without a default value. This is not possible if the table is not empty.

*/
-- AlterEnum
BEGIN;
CREATE TYPE "TokenType_new" AS ENUM ('PARTICIPATION_SESSION');
ALTER TABLE "AuthToken" ALTER COLUMN "type" TYPE "TokenType_new" USING ("type"::text::"TokenType_new");
ALTER TYPE "TokenType" RENAME TO "TokenType_old";
ALTER TYPE "TokenType_new" RENAME TO "TokenType";
DROP TYPE "public"."TokenType_old";
COMMIT;

-- AlterTable
ALTER TABLE "Student" ADD COLUMN     "hasSubmitted" BOOLEAN NOT NULL DEFAULT false,
ADD COLUMN     "passwordHash" TEXT NOT NULL,
ALTER COLUMN "isEmailVerified" SET DEFAULT true;
