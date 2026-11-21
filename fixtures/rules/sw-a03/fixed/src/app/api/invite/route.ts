import { sendMail } from "@/lib/mail";

export async function POST(request: Request) {
  const { email } = await request.json();
  await sendMail(email, "You are invited", "Join us at https://app.example.com");
  return Response.json({ ok: true });
}
