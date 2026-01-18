import nodemailer from "nodemailer";

const transporter = nodemailer.createTransport({
  host: "smtp.gmail.com",
  port: 465,
  secure: true,
  auth: {
    user: process.env.GMAIL_USER!,
    pass: process.env.GMAIL_APP_PASS!,
  },
});

// For future use: send notification emails
export async function sendNotificationEmail(to: string, subject: string, text: string) {
  await transporter.sendMail({
    from: `MNTC Auditions <${process.env.GMAIL_USER!}>`,
    to,
    subject,
    text,
  });
}
