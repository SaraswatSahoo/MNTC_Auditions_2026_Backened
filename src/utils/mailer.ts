import nodemailer from "nodemailer";

const transporter = nodemailer.createTransport({
  host: "smtp.gmail.com",
  port: 465,
  secure: true,
  auth: {
    user: process.env.GMAIL_USER!,      // mntc.auditions.2026@gmail.com
    pass: process.env.GMAIL_APP_PASS!,  // 16-char app password
  },
});

export async function sendOtpEmail(to: string, otp: string) {
  await transporter.sendMail({
    from: `MNTC Auditions <${process.env.GMAIL_USER!}>`,
    to,
    subject: "Your audition verification code",
    text: `Your verification code is: ${otp}\nThis code expires in 10 minutes.`,
  });
}
