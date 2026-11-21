import nodemailer from "nodemailer";

const transport = nodemailer.createTransport({ host: process.env.SMTP_HOST, auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS } });

export async function sendMail(to: string, subject: string, text: string) {
  await transport.sendMail({ from: "team@example.com", to, subject, text });
}
