import { Resend } from "resend";

const resend = new Resend(process.env.RESEND_API_KEY!);

export async function sendOtpEmail(to: string, otp: string) {
  const { error } = await resend.emails.send({
    from: process.env.EMAIL_FROM!, // e.g. "MNTC Auditions <onboarding@resend.dev>"
    to: [to],
    subject: "Your audition verification code",
    text: `Your verification code is: ${otp}\nThis code expires in 10 minutes.`,
  });

  if (error) throw error;
}
